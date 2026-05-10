package session

import "io"

// QueryFilter intercepts terminal-query escape sequences in PTY
// output. For known queries (Device Attributes, Device Status
// Report) it writes a synthetic response back to the PTY input so
// the querying app gets its answer, and strips the query bytes from
// the output stream so the eventual client never sees them. This is
// the mosh "wrapper terminal" pattern.
//
// Why on the daemon and not the client: client-side filtering
// (either replay-window gating or content-shape detection) is
// inherently a band-aid — it either has timing races or breaks
// legitimate live capability negotiation. Synthesising responses on
// the daemon makes apps work normally during live operation AND
// keeps queries out of the ring buffer, so replays on reattach are
// pollution-free.
//
// Coverage: Device Attributes Primary (DA, `\x1b[c` / `\x1b[0c`),
// Device Attributes Secondary (`\x1b[>c` / `\x1b[>0c`), Device
// Status Report (`\x1b[5n`). Cursor Position Report (`\x1b[6n`)
// is stripped without a synthetic response — answering it correctly
// would require the daemon to maintain its own terminal-state
// model to track cursor position, which is out of scope. Apps that
// depend on CPR will time out or fall back; in interactive shell
// usage that's exceedingly rare.
//
// The filter is stateful: an escape sequence split across two PTY
// reads is held in `pending` until the next chunk completes it.
// Without that, we'd occasionally pass through partial query
// fragments and the response logic would miss them.
type QueryFilter struct {
	// pending holds the tail bytes of an unfinished escape sequence
	// from the previous read. Always empty at the end of a clean
	// process() call when no partial sequence is in flight.
	pending []byte

	// pty is the writer the filter uses to inject synthetic
	// responses into the child shell's stdin. In production this is
	// the PTY master (same handle the daemon uses to send user
	// keystrokes). Tests can pass a *bytes.Buffer or nil.
	pty io.Writer
}

// NewQueryFilter constructs a QueryFilter that synthesises responses
// to PTY queries by writing them to `pty`. Pass nil for `pty` to
// strip queries without responding (used by tests).
func NewQueryFilter(pty io.Writer) *QueryFilter {
	return &QueryFilter{pty: pty}
}

// Process scans `chunk` for query escape sequences, writes synthetic
// responses to the PTY for any queries it recognises, and returns
// the chunk with those queries removed. Bytes that aren't part of a
// recognised query pass through unchanged. Sequences split across
// chunks are buffered in `pending` and re-evaluated on the next call.
//
// Allocation: returns a fresh slice owned by the caller. Worst case
// it's the same length as `chunk`, but typically shorter when
// queries are stripped. Callers must not mutate the returned slice.
func (q *QueryFilter) Process(chunk []byte) []byte {
	// Carry over any partial sequence from the previous chunk.
	if len(q.pending) > 0 {
		merged := make([]byte, 0, len(q.pending)+len(chunk))
		merged = append(merged, q.pending...)
		merged = append(merged, chunk...)
		chunk = merged
		q.pending = nil
	}

	out := make([]byte, 0, len(chunk))
	idx := 0
	for idx < len(chunk) {
		if chunk[idx] != 0x1B {
			out = append(out, chunk[idx])
			idx++
			continue
		}

		// `\x1b` start. We handle two introducers:
		//   `\x1b[` — CSI (DA, DSR, CPR, …)
		//   `\x1b]` — OSC (palette / fg / bg / cursor colour queries)
		// Other escapes (DCS `\x1bP`, plain ESC keystrokes, etc.)
		// pass through.
		if idx+1 >= len(chunk) {
			// ESC at end of chunk; might be a partial introducer.
			q.pending = chunk[idx:]
			return out
		}
		if chunk[idx+1] == 0x5D /* ] */ {
			consumed, oscOut, isQuery := q.processOSC(chunk[idx:])
			if consumed == 0 {
				// Need more bytes — partial OSC (no terminator yet).
				q.pending = chunk[idx:]
				return out
			}
			if !isQuery {
				out = append(out, oscOut...)
			}
			idx += consumed
			continue
		}
		if chunk[idx+1] != 0x5B /* [ */ {
			out = append(out, chunk[idx])
			idx++
			continue
		}

		// Locate the final byte of the CSI sequence. CSI grammar:
		//   ESC [ <private?> <params> <intermediate?> <final>
		// where:
		//   private:      one of `?`, `>`, `=` (zero or one)
		//   params:       digits and `;` separators (any count)
		//   intermediate: bytes 0x20..0x2F (we don't see these for
		//                 the queries we care about, so we don't
		//                 enumerate them here)
		//   final:        byte 0x40..0x7E
		end := idx + 2
		// Optional private prefix.
		if end < len(chunk) {
			if chunk[end] == '?' || chunk[end] == '>' || chunk[end] == '=' {
				end++
			}
		}
		// Params.
		for end < len(chunk) && (isDigit(chunk[end]) || chunk[end] == ';') {
			end++
		}
		// We need at least one more byte for the final.
		if end >= len(chunk) {
			// Sequence runs off the end of this chunk; hold for next
			// read so we evaluate it as a complete unit.
			q.pending = chunk[idx:]
			return out
		}
		final := chunk[end]
		// CSI final bytes are in 0x40..0x7E; anything outside means
		// we mis-parsed (probably hit a non-CSI escape that just
		// happened to look CSI-ish). Pass through ESC and continue.
		if final < 0x40 || final > 0x7E {
			out = append(out, chunk[idx])
			idx++
			continue
		}

		seq := chunk[idx : end+1]
		response, isQuery := q.matchQuery(seq)
		if isQuery {
			if len(response) > 0 && q.pty != nil {
				// Best-effort write. If the PTY is closing we'll
				// just drop the response; the app will time out and
				// continue. Returning the error here would also
				// break the buffer-write path for non-query bytes.
				_, _ = q.pty.Write(response)
			}
			// Strip the query from the output regardless of whether
			// we wrote a response (CPR with no cursor info still gets
			// stripped — better silence than a wrong answer).
			idx = end + 1
			continue
		}

		// Not a query we handle — pass the whole sequence through.
		out = append(out, seq...)
		idx = end + 1
	}
	return out
}

// matchQuery returns the synthetic response bytes if `seq` is a
// query the filter recognises, or `(nil, true)` if `seq` is a
// recognised query that has no response (e.g., CPR — strip without
// answering). Returns `(nil, false)` for sequences that should pass
// through to the client (cursor positioning, colour, etc.).
//
// Static-tabled responses match xterm's defaults closely enough that
// vim/htop/etc. enable the optional features they probe for and stay
// happy. We don't bother with feature negotiation specific to the
// real underlying terminal — we ARE the terminal from the app's
// perspective, and we promise xterm-class capabilities.
func (q *QueryFilter) matchQuery(seq []byte) ([]byte, bool) {
	if len(seq) < 3 || seq[0] != 0x1B || seq[1] != '[' {
		return nil, false
	}
	final := seq[len(seq)-1]
	params := string(seq[2 : len(seq)-1])

	switch final {
	case 'c':
		// Device Attributes.
		switch params {
		case "", "0":
			// Primary DA query. Respond as xterm class 65 with the
			// capability list iOS Network.framework's terminal also
			// reports — vim/etc. detect them identically across the
			// two endpoints.
			return []byte("\x1b[?65;4;1;2;6;21;22;17;28c"), true
		case ">", ">0":
			// Secondary DA query. Respond as xterm version 276 (the
			// version string xterm itself uses for its 276-patch
			// release; widely accepted by terminfo databases).
			return []byte("\x1b[>0;276;0c"), true
		case "=", "=0":
			// Tertiary DA query (DECRPTUI). Almost no app actually
			// queries this — strip silently.
			return nil, true
		}
	case 'n':
		// Device Status Report.
		switch params {
		case "5":
			// "Are you OK?" → "Yes."
			return []byte("\x1b[0n"), true
		case "6", "?6":
			// Cursor Position Report. We don't track cursor state
			// on the daemon, so we can't answer correctly. Strip
			// without responding — apps that need CPR fall back or
			// time out, but that's vastly rarer than the DA case.
			return nil, true
		}
	}

	// Anything else: pass through. Includes cursor-forward
	// (`\x1b[<n>c`), colour codes, mode sets, etc.
	return nil, false
}

// processOSC scans `data` starting with `\x1b]` for an OSC sequence.
// Returns:
//   - consumed: bytes consumed (0 if no terminator yet — caller
//     should buffer in pending and retry)
//   - body: the full OSC sequence bytes (only set when consumed > 0
//     and isQuery is false — caller forwards these to the buffer)
//   - isQuery: true when the OSC contains a `?` value placeholder,
//     i.e. it's a query like `\x1b]10;?\x07` asking the terminal
//     to report its default foreground colour. We strip these
//     because the iOS-side terminal would otherwise auto-respond
//     and pollute the shell with the response bytes. We don't
//     synthesise replies because the daemon doesn't track terminal
//     palette state — apps that need real colour values fall back
//     to the TERM env var's terminfo entries.
//
// OSC grammar: `\x1b ] <params> <terminator>`
// where terminator is BEL (0x07) or ST (0x1b 0x5c). We accept both.
//
// Strip-on-query coverage:
//   * `\x1b]4;<n>;?` — palette colour query
//   * `\x1b]10;?`    — default fg query
//   * `\x1b]11;?`    — default bg query
//   * `\x1b]12;?`    — cursor colour query
//   * `\x1b]17;?`    — highlight bg query (rarer)
// ... and any other OSC with a `?` value placeholder. The `?` test
// is what distinguishes a query from a SET (`\x1b]10;#ff0000\x07`
// which sets the colour and elicits no response — passes through).
func (q *QueryFilter) processOSC(data []byte) (consumed int, body []byte, isQuery bool) {
	// Scan from after `\x1b]` (data[2]) to find the terminator.
	idx := 2
	for idx < len(data) {
		if data[idx] == 0x07 /* BEL */ {
			body = data[:idx+1]
			return idx + 1, body, oscBodyIsQuery(body)
		}
		if data[idx] == 0x1B /* ESC */ {
			// ST = ESC \\
			if idx+1 < len(data) && data[idx+1] == 0x5C /* \\ */ {
				body = data[:idx+2]
				return idx + 2, body, oscBodyIsQuery(body)
			}
			// ESC followed by something else — terminator not yet
			// complete. Need more bytes.
			return 0, nil, false
		}
		idx++
	}
	// No terminator in the chunk — partial OSC.
	return 0, nil, false
}

// oscBodyIsQuery reports whether the OSC sequence is a value query
// — distinguished from a SET — by the presence of `?` in the
// parameter portion (between the ` ] ` introducer and the
// terminator). Sets use literal values; queries use `?` as the
// placeholder. The check is pessimistic: any `?` in the body is
// treated as a query, which catches all real query shapes and
// occasionally over-strips a SET that includes a literal `?` in a
// label, which is harmless.
func oscBodyIsQuery(body []byte) bool {
	// Skip the `\x1b]` introducer; the trailing terminator (BEL or
	// ST) doesn't contain `?`, so a single byte scan over the body
	// is sufficient.
	for _, byte_ := range body[2:] {
		if byte_ == '?' {
			return true
		}
	}
	return false
}

func isDigit(byte_ byte) bool {
	return byte_ >= '0' && byte_ <= '9'
}
