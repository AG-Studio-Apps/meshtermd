package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// attachBootstrap is the parsed MTRM_QUIC bootstrap line. The
// daemon's `meshtermd connect` emits it on stdout after reserving
// an attach slot; mtctl receives it via SSH and feeds it into the
// QUIC dial.
type attachBootstrap struct {
	version         uint32
	port            uint16
	sessionID       []byte // 16 bytes
	certFingerprint []byte // 32 bytes (SHA-256)
	attachToken     []byte // 16 bytes
}

// bootstrapForAttach translates the user's selector into the right
// `meshtermd connect` invocation, runs it over SSH, parses the
// MTRM_QUIC line on stdout.
//
// Selector semantics:
//
//	"new"                       → --session new (+ --name from flag)
//	32 lowercase hex chars      → --session <hex> (reattach by ID)
//	anything else               → --session new --name <selector>
//	                              (daemon's create-if-missing flow)
//
// The `createName` arg only applies when selector == "new"; in the
// hex-id and create-if-missing paths the name on the wire is fixed
// by the selector or ignored.
func bootstrapForAttach(
	target, selector, createName, shell string,
	idleTimeout, deadline time.Duration,
	persist *bool,
) (*attachBootstrap, error) {
	var sessionArg string
	var nameArg string

	switch {
	case selector == "new":
		sessionArg = "new"
		nameArg = createName
	case isHexSessionID(selector):
		sessionArg = selector
		nameArg = "" // reattach by ID; daemon ignores Name
	default:
		// Treat as a name. Daemon's create-if-missing means existing
		// sessions of this name will attach rather than re-spawn.
		sessionArg = "new"
		nameArg = selector
	}

	cmd := "meshtermd connect --session " + shellQuote(sessionArg)
	if nameArg != "" {
		cmd += " --name " + shellQuote(nameArg)
	}
	if shell != "" {
		cmd += " --shell " + shellQuote(shell)
	}
	if idleTimeout > 0 {
		cmd += fmt.Sprintf(" --idle-timeout %ds", int(idleTimeout.Seconds()))
	}
	// --persist / --no-persist only matter for fresh spawn (reattach
	// inherits the existing session's persist bit). bootstrapForAttach
	// passes the flag through unconditionally — the daemon ignores it
	// when reattaching by hex ID.
	if persist != nil {
		if *persist {
			cmd += " --persist"
		} else {
			cmd += " --no-persist"
		}
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, cmd, deadline)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("`meshtermd connect` exited %d: %s",
			code, strings.TrimSpace(stderr))
	}

	line, err := pickMTRMLine(stdout)
	if err != nil {
		return nil, err
	}
	return parseMTRMLine(line)
}

// pickMTRMLine finds the `MTRM_QUIC …` line on stdout. Tolerates
// preceding noise (login banner, $PS1 echoes) — the daemon's CLI
// emits exactly one bootstrap line then exits.
func pickMTRMLine(stdout string) (string, error) {
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "MTRM_QUIC ") {
			return line, nil
		}
	}
	return "", fmt.Errorf("no MTRM_QUIC line on stdout (got %d bytes)", len(stdout))
}

// parseMTRMLine implements the strict-grammar parser from
// roam-protocol.md § 4.2:
//
//	MTRM_QUIC <version> <port> <sid_hex_32> <fp_hex_64> <tok_hex_32>
//
// Exactly 6 space-separated fields. No trailing whitespace, no
// extra fields. Same posture as iOS's RoamBootstrapInfo.parse.
func parseMTRMLine(line string) (*attachBootstrap, error) {
	parts := strings.Split(line, " ")
	if len(parts) != 6 {
		return nil, fmt.Errorf("MTRM_QUIC line has %d fields, want 6", len(parts))
	}
	if parts[0] != "MTRM_QUIC" {
		return nil, fmt.Errorf("missing MTRM_QUIC sentinel")
	}
	ver64, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("bad version: %w", err)
	}
	port64, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil || port64 == 0 {
		return nil, fmt.Errorf("bad port: %v", err)
	}
	sid, err := decodeHexExact(parts[3], 32, 16)
	if err != nil {
		return nil, fmt.Errorf("bad session_id: %w", err)
	}
	fp, err := decodeHexExact(parts[4], 64, 32)
	if err != nil {
		return nil, fmt.Errorf("bad cert_fp: %w", err)
	}
	tok, err := decodeHexExact(parts[5], 32, 16)
	if err != nil {
		return nil, fmt.Errorf("bad attach_token: %w", err)
	}
	return &attachBootstrap{
		version:         uint32(ver64),
		port:            uint16(port64),
		sessionID:       sid,
		certFingerprint: fp,
		attachToken:     tok,
	}, nil
}

// decodeHexExact decodes a hex string and asserts both the input
// length and the decoded byte count. Reject everything else — the
// bootstrap line's format is strict by design.
func decodeHexExact(s string, hexChars, wantBytes int) ([]byte, error) {
	if len(s) != hexChars {
		return nil, fmt.Errorf("need %d hex chars, got %d", hexChars, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != wantBytes {
		return nil, fmt.Errorf("need %d bytes, got %d", wantBytes, len(b))
	}
	return b, nil
}

// hexSessionIDPattern matches the 32-lowercase-hex shape of a
// SessionID. Uppercase is rejected because the bootstrap line emits
// lowercase only — accepting uppercase here would create a parsing
// asymmetry between mtctl and the iOS / daemon CLIs.
var hexSessionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func isHexSessionID(s string) bool {
	return hexSessionIDPattern.MatchString(s)
}
