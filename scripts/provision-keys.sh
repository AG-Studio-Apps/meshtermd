#!/usr/bin/env bash
#
# provision-keys.sh — generate the meshtermd release-signing key roster.
#
# What this does (once, on your workstation):
#   1. Generates a PRIMARY minisign keypair (used by CI for every signed release).
#   2. Generates an EMERGENCY minisign keypair (kept offline; iOS trusts it as a fallback).
#   3. Encrypts both private halves with age + a single passphrase you choose.
#   4. Pushes the encrypted private halves + plaintext public halves to
#      AG-Studio-Apps/meshterm_keys (private repo, encrypted backup).
#   5. Sets MINISIGN_KEY and MINISIGN_PASSWORD as Actions secrets on
#      AG-Studio-Apps/meshtermd so release CI can sign without you.
#   6. Shreds the unencrypted private files from your workstation.
#   7. Prints the two PUBLIC keys in the exact base64 form to embed in iOS.
#
# You will be prompted for passphrases several times during the run.
# READ the on-screen instructions for each prompt — minisign -G asks for
# its passphrase twice (generate + confirm), and the script needs the
# same passphrase a third time to upload it to GitHub Secrets.
#
# Public keys printed at the end are NOT secrets — paste them into the
# conversation so they can be committed into iOS source.

set -euo pipefail
umask 077

# ---------- config ----------
KEYS_REPO_DIR="${KEYS_REPO_DIR:-$HOME/appfactory/meshterm_keys}"
MESHTERMD_REPO="AG-Studio-Apps/meshtermd"
KEYS_REPO="AG-Studio-Apps/meshterm_keys"

# ---------- helpers ----------
red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n'  "$*"; }
die()   { red "✘ $*"; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1 (install it and retry)"
}

# ---------- pre-flight ----------
bold "▸ Pre-flight"

require minisign
require age
require gh
require git

gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run \`gh auth login\`)"

[ -d "$KEYS_REPO_DIR/.git" ] || die "keys repo not cloned at $KEYS_REPO_DIR — clone it first"

for f in primary.minipk primary.minisk.age emergency.minipk emergency.minisk.age; do
    [ -e "$KEYS_REPO_DIR/$f" ] && die "refusing to clobber existing $KEYS_REPO_DIR/$f (delete it first if rotating)"
done

# Sanity-check we can talk to both target repos.
gh repo view "$MESHTERMD_REPO" >/dev/null 2>&1 || die "cannot access $MESHTERMD_REPO via gh"
gh repo view "$KEYS_REPO"      >/dev/null 2>&1 || die "cannot access $KEYS_REPO via gh"

green "✓ tools, auth, and target repos look good"

# ---------- prompts ----------
TODAY="$(date +%F)"
bold ""
bold "▸ This run will create:"
echo "    • primary.minisk        (private — uploaded to GH secret + shredded locally)"
echo "    • primary.minipk        (public  — committed to $KEYS_REPO)"
echo "    • primary.minisk.age    (private, age-encrypted — committed to $KEYS_REPO)"
echo "    • emergency.minisk      (private — encrypted then shredded; NOT uploaded to GH)"
echo "    • emergency.minipk      (public  — committed to $KEYS_REPO)"
echo "    • emergency.minisk.age  (private, age-encrypted — committed to $KEYS_REPO)"
echo ""
read -rp "Trusted comment for PRIMARY key   [meshtermd primary $TODAY]: " PRIMARY_COMMENT
PRIMARY_COMMENT="${PRIMARY_COMMENT:-meshtermd primary $TODAY}"
read -rp "Trusted comment for EMERGENCY key [meshtermd emergency $TODAY]: " EMERGENCY_COMMENT
EMERGENCY_COMMENT="${EMERGENCY_COMMENT:-meshtermd emergency $TODAY}"

# ---------- workspace ----------
WORK_DIR="$(mktemp -d -t mtkeys.XXXXXX)"
cleanup() {
    # If anything plaintext survived (early exit), wipe it.
    for f in "$WORK_DIR"/*.minisk; do
        [ -f "$f" ] || continue
        if command -v shred >/dev/null 2>&1; then
            shred -u "$f" 2>/dev/null || rm -f "$f"
        else
            rm -P "$f" 2>/dev/null || rm -f "$f"
        fi
    done
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
cd "$WORK_DIR"

# ---------- generate keypairs ----------
bold ""
bold "▸ Generating PRIMARY minisign keypair"
echo "  minisign will prompt for a passphrase (twice). Use a strong one — it"
echo "  protects the CI signing key. Save it in your password manager AS"
echo "  YOU TYPE IT — you'll need to enter it a third time below."
echo ""
minisign -G -c "$PRIMARY_COMMENT" -p primary.minipk -s primary.minisk

bold ""
bold "▸ Generating EMERGENCY minisign keypair"
echo "  Use a DIFFERENT strong passphrase. Save it separately."
echo ""
minisign -G -c "$EMERGENCY_COMMENT" -p emergency.minipk -s emergency.minisk

# ---------- encrypt private halves ----------
bold ""
bold "▸ Encrypting private keys with age (one shared passphrase for both backups)"
echo "  age will prompt for the same passphrase twice."
echo ""
age -p -o primary.minisk.age   primary.minisk
echo ""
echo "  Same passphrase again for the emergency key backup."
echo ""
age -p -o emergency.minisk.age emergency.minisk

# ---------- upload primary to GH Actions secrets ----------
bold ""
bold "▸ Uploading PRIMARY private key to $MESHTERMD_REPO secret MINISIGN_KEY"
gh secret set MINISIGN_KEY --repo "$MESHTERMD_REPO" < primary.minisk

bold ""
bold "▸ Uploading PRIMARY passphrase to $MESHTERMD_REPO secret MINISIGN_PASSWORD"
echo "  Re-enter the PRIMARY minisign passphrase you just used (won't echo):"
read -rsp "  PRIMARY passphrase: " PRIMARY_PASS
echo
# `gh secret set --body` would put it on the argv; pipe via stdin instead.
printf '%s' "$PRIMARY_PASS" | gh secret set MINISIGN_PASSWORD --repo "$MESHTERMD_REPO"
unset PRIMARY_PASS
green "✓ secrets uploaded"

# ---------- commit encrypted backups + public keys to keys repo ----------
bold ""
bold "▸ Committing encrypted backups + public keys to $KEYS_REPO"
cp primary.minisk.age   emergency.minisk.age \
   primary.minipk       emergency.minipk \
   "$KEYS_REPO_DIR/"

cd "$KEYS_REPO_DIR"
git add primary.minisk.age emergency.minisk.age primary.minipk emergency.minipk
git -c user.name="$(git config user.name || echo "$USER")" \
    -c user.email="$(git config user.email || echo "$USER@$(hostname)")" \
    commit -m "Add primary + emergency minisign keys ($TODAY)"
git push
cd - >/dev/null

# ---------- shred plaintext privates ----------
bold ""
bold "▸ Shredding plaintext private keys from workspace"
for f in primary.minisk emergency.minisk; do
    [ -f "$WORK_DIR/$f" ] || continue
    if command -v shred >/dev/null 2>&1; then
        shred -u "$WORK_DIR/$f"
    else
        rm -P "$WORK_DIR/$f" 2>/dev/null || rm -f "$WORK_DIR/$f"
    fi
done
green "✓ plaintext private material removed"

# ---------- emit public-key payload for iOS ----------
# A minisign public-key file has the shape:
#   untrusted comment: minisign public key <hex key id>
#   <base64 payload>
# The base64 payload (line 2) is what we embed in iOS as `trustedMinisignKeys`.
# It decodes to: "Ed" (2 bytes) || key_id (8 bytes) || ed25519 pubkey (32 bytes) = 42 bytes.
# iOS strips the first 10 bytes before passing the 32-byte pubkey to CryptoKit.

extract_payload() { tail -n 1 "$KEYS_REPO_DIR/$1" | tr -d '[:space:]'; }
key_id_hex() {
    # Decode the base64 payload, take bytes 3..10 (key id), reverse for big-endian display.
    extract_payload "$1" | base64 -d | tail -c +3 | head -c 8 | xxd -p | tr -d '\n' | tr '[:lower:]' '[:upper:]'
}

PRIMARY_PAYLOAD="$(extract_payload primary.minipk)"
EMERGENCY_PAYLOAD="$(extract_payload emergency.minipk)"
PRIMARY_KEY_ID="$(key_id_hex primary.minipk)"
EMERGENCY_KEY_ID="$(key_id_hex emergency.minipk)"

bold ""
green "═══════════════════════════════════════════════════════════════════"
green "  PROVISIONING COMPLETE"
green "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Paste the two PUBLIC keys below into the conversation. They are NOT"
echo "secrets — they will be embedded in iOS so the app can verify daemon"
echo "release signatures. Either signature will satisfy verification."
echo ""
echo "PRIMARY:"
echo "  key id (hex): $PRIMARY_KEY_ID"
echo "  base64:       $PRIMARY_PAYLOAD"
echo ""
echo "EMERGENCY:"
echo "  key id (hex): $EMERGENCY_KEY_ID"
echo "  base64:       $EMERGENCY_PAYLOAD"
echo ""
echo "Encrypted backups committed to: https://github.com/$KEYS_REPO"
echo "Actions secrets set on:         https://github.com/$MESHTERMD_REPO/settings/secrets/actions"
echo ""
echo "Next:"
echo "  • Save both minisign passphrases + the age passphrase in your password manager."
echo "  • Paste the two base64 strings above back to Claude."
