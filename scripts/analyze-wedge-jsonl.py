#!/usr/bin/env python3
"""
Analyse the wedge-events.jsonl file produced by meshtermd's per-session
wedge watcher. Cross-references the user's manual classifications in
wedge-observations.log (timestamp-tagged true/false-positive entries).

Use during the data-collection phase (`MESHTERMD_WEDGE_CAPTURE_BYTES=1`)
to:
  * surface the distribution of `ms_since_resize` and `cud_observed`
  * decode the post-resize PTY byte stream and look for the
    "full re-init" discriminator pattern (mouse-mode setup + clear-
    screen + home) that empirically tags healthy multi-frame renders
    as false-positives
  * cross-reference user-tagged events so we can see the true / false
    positive split in one view

Run:
  python3 scripts/analyze-wedge-jsonl.py
  python3 scripts/analyze-wedge-jsonl.py --since 2026-05-18T11:00:00Z

The script is read-only; it never writes to either source file.
"""

import argparse
import base64
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

DEFAULT_JSONL = Path.home() / ".local/share/meshtermd/wedge-events.jsonl"
DEFAULT_OBSERVATIONS = Path.home() / ".local/share/meshtermd/wedge-observations.log"

# Empirically observed false-positive signature: Claude's full
# re-initialisation emits mouse-tracking-mode enable + clear-screen +
# home within the first ~200 bytes of the post-resize stream. A real
# wedge keeps drawing on the old frame and wouldn't emit `\x1b[2J`.
FULL_REINIT_RE = re.compile(rb"\x1b\[2J\x1b\[H")
MOUSE_MODES_RE = re.compile(rb"\x1b\[\?100[0236]h")


def load_events(jsonl_path: Path, since: str | None) -> list[dict]:
    if not jsonl_path.exists():
        return []
    out = []
    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since and e.get("ts", "") < since:
                continue
            out.append(e)
    return out


def load_observations(obs_path: Path) -> dict[str, list[dict]]:
    """Returns a mapping from jsonl timestamp → list of user annotations."""
    if not obs_path.exists():
        return {}
    by_ts: dict[str, list[dict]] = {}
    with obs_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = rec.get("tags_jsonl_ts")
            if ts:
                by_ts.setdefault(ts, []).append(rec)
    return by_ts


def classify(e: dict) -> str:
    """Heuristic label using the full-reinit byte-stream pattern."""
    b64 = e.get("recent_output_b64", "")
    if not b64:
        return "no-capture"
    raw = base64.b64decode(b64)
    head = raw[:200]
    if FULL_REINIT_RE.search(head):
        return "full-reinit (likely false-positive)"
    if MOUSE_MODES_RE.search(head):
        return "mouse-mode-setup (likely false-positive)"
    return "no-reinit signature"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--jsonl", type=Path, default=DEFAULT_JSONL)
    p.add_argument("--observations", type=Path, default=DEFAULT_OBSERVATIONS)
    p.add_argument("--since", type=str, default=None,
                   help="ISO8601 timestamp; events older than this are skipped")
    p.add_argument("--show-bytes", action="store_true",
                   help="For each capture-mode event, print head + tail of the byte stream")
    args = p.parse_args()

    events = load_events(args.jsonl, args.since)
    obs = load_observations(args.observations)

    if not events:
        print("No events in JSONL (path: %s)" % args.jsonl, file=sys.stderr)
        return 1

    print(f"Loaded {len(events)} events from {args.jsonl}")
    print(f"User annotations: {sum(len(v) for v in obs.values())} entries across {len(obs)} timestamps")
    print()

    # Wedge-type breakdown.
    by_type = Counter(e.get("wedge_type", "?") for e in events)
    print("Wedge-type counts:")
    for t, n in by_type.most_common():
        print(f"  {t:<16} {n}")
    print()

    # Capture coverage.
    captured = [e for e in events if e.get("recent_output_b64")]
    print(f"Byte-capture coverage: {len(captured)} / {len(events)}")
    print()

    # ms_since_resize distribution (vertical_walk only; silent doesn't have it).
    vw = [e for e in events if e.get("wedge_type") == "vertical_walk" and "ms_since_resize" in e]
    if vw:
        ms_vals = sorted(e["ms_since_resize"] for e in vw)
        print("vertical_walk ms_since_resize distribution:")
        print(f"  min={ms_vals[0]} max={ms_vals[-1]} median={ms_vals[len(ms_vals) // 2]}")
        print(f"  <100ms: {sum(1 for m in ms_vals if m < 100)}")
        print(f"  100-500ms: {sum(1 for m in ms_vals if 100 <= m < 500)}")
        print(f"  500+ms: {sum(1 for m in ms_vals if m >= 500)}")
        print()

        cud_vals = sorted(e["cud_observed"] for e in vw)
        print("vertical_walk cud_observed distribution:")
        print(f"  min={cud_vals[0]} max={cud_vals[-1]} median={cud_vals[len(cud_vals) // 2]}")
        print()

    # Per-event view, captured-only, with classification + user annotation.
    if captured:
        print("=" * 78)
        print(f"{'timestamp':<22} {'type':<14} {'cud':>4} {'ms':>5}  classification    user")
        print("-" * 78)
        for e in captured:
            ts = e.get("ts", "?")
            kind = e.get("wedge_type", "?")
            cud = e.get("cud_observed", "")
            ms = e.get("ms_since_resize", "")
            cls = classify(e)
            user_tags = obs.get(ts, [])
            user_class = ",".join(t.get("classification", "?") for t in user_tags) if user_tags else "-"
            print(f"{ts:<22} {kind:<14} {str(cud):>4} {str(ms):>5}  {cls:<35} {user_class}")
        print()

    # Optional: dump byte streams for inspection.
    if args.show_bytes:
        print("=" * 78)
        print("Byte streams (head + tail):")
        for e in captured:
            raw = base64.b64decode(e["recent_output_b64"])
            print(f"\n--- {e['ts']} ({len(raw)}B) ---")
            print(f"head 80: {raw[:80]!r}")
            print(f"tail 80: {raw[-80:]!r}")

    print()
    print("Discriminator hypothesis:")
    print("  False-positive (full-reinit) byte streams begin with mouse-mode")
    print("  enables (`\\x1b[?1000h` etc) and `\\x1b[2J\\x1b[H` within the first")
    print("  ~200 bytes. Real wedges keep drawing on the stale frame and")
    print("  shouldn't emit clear-screen.")
    print()
    print("  Once we have at least one user-confirmed TRUE positive captured")
    print("  with bytes, compare its head against the false-positives here")
    print("  to validate / invalidate the discriminator before changing the")
    print("  detector.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
