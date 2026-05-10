package protocol

import (
	"bytes"
	"testing"
)

// Fuzz targets cover the parser surface that runs against
// untrusted bytes off the QUIC wire. The bar is "no panic, no
// goroutine leak, no infinite loop" on any input — silent error
// returns are fine. We've already wired StrictDecMode (max array
// size, max map pairs, max nested levels) so a CBOR depth bomb
// can't OOM us; these tests just continuously poke at edge cases
// CI's table tests don't.
//
// Run via:
//   go test ./internal/protocol/ -fuzz=FuzzReadFrame -run=^$ -fuzztime=30s
//   go test ./internal/protocol/ -fuzz=FuzzReadTaggedFrame -run=^$ -fuzztime=30s
//   go test ./internal/protocol/ -fuzz=FuzzPeekType -run=^$ -fuzztime=30s
//   go test ./internal/protocol/ -fuzz=FuzzAttachDecode -run=^$ -fuzztime=30s
//   go test ./internal/protocol/ -fuzz=FuzzAttachAckDecode -run=^$ -fuzztime=30s
//   go test ./internal/protocol/ -fuzz=FuzzDecodeStdoutBody -run=^$ -fuzztime=30s

// FuzzReadFrame: arbitrary bytes through the length-prefixed CBOR
// frame reader. Should never panic; should reject oversized
// length prefixes without ever calling make() on an attacker-
// chosen size.
func FuzzReadFrame(f *testing.F) {
	// Seed corpus: a few "normal" frames to anchor the fuzzer.
	f.Add([]byte{0, 0, 0, 0})                          // zero-length frame
	f.Add([]byte{0, 0, 0, 1, 0xa0})                    // 1 byte, valid empty CBOR map
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})              // huge length prefix (must reject)
	f.Add([]byte{})                                    // empty
	f.Add([]byte{0, 0, 0, 5, 0xa1, 0x61, 't', 0x60})   // {"t":""}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadFrame(bytes.NewReader(data))
	})
}

// FuzzReadTaggedFrame: same shape but with the type-tag prefix.
// Body of a stdout frame can be anything; control body has to be
// CBOR but we don't validate that here, just the framing parser.
func FuzzReadTaggedFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0})                       // type=0, zero-length
	f.Add([]byte{2, 0, 0, 0, 1, 0xa0})                 // type=stdout, 1 byte
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff})        // huge len, garbage type
	f.Add([]byte{0, 0, 0, 0})                          // truncated header
	f.Add([]byte{})                                    // empty
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadTaggedFrame(bytes.NewReader(data))
	})
}

// FuzzPeekType: the type-discriminator extractor reads a single
// CBOR map key. Malformed CBOR must surface as an error, not a
// panic.
func FuzzPeekType(f *testing.F) {
	f.Add([]byte{})                            // empty
	f.Add([]byte{0xa0})                        // empty map
	f.Add([]byte{0xa1, 0x61, 't', 0x60})       // {"t":""}
	f.Add([]byte{0xa1, 0x61, 't', 0x65, 'h', 'e', 'l', 'l', 'o'}) // {"t":"hello"}
	f.Add([]byte{0xff})                        // CBOR break code
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = PeekType(data)
	})
}

// FuzzAttachDecode: body of a control frame typed as "Attach"
// goes through StrictDecMode.Unmarshal into the Attach struct.
// CBOR depth bombs / oversized arrays must be rejected by the
// strict mode.
func FuzzAttachDecode(f *testing.F) {
	good, _ := MarshalAttach(Attach{
		V: 1, Token: bytes.Repeat([]byte{0xab}, 16),
		SessionID: bytes.Repeat([]byte{0xcd}, 16),
		AckSeq:    42, Rows: 24, Cols: 80,
	})
	f.Add(good)
	f.Add([]byte{0xa0})                       // empty map
	f.Add([]byte{0xa1, 0x61, 't', 0x66, 'A', 't', 't', 'a', 'c', 'h'}) // {"t":"Attach"}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a Attach
		_ = StrictDecMode.Unmarshal(data, &a)
	})
}

// FuzzAttachAckDecode: server-side response decoder. Same
// approach.
func FuzzAttachAckDecode(f *testing.F) {
	good, _ := MarshalAttachAck(AttachAck{
		V: 1, OK: true, Start: 100, BufSeq: 200, Trunc: false,
		Mode: AttachModeExclusive, Peers: []string{"readonly"},
	})
	f.Add(good)
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var a AttachAck
		_ = StrictDecMode.Unmarshal(data, &a)
	})
}

// FuzzDecodeStdoutBody: stdout-frame body splits into [u64 BE
// seq][raw bytes]. Truncated bodies, empty payload, and
// pathological lengths shouldn't panic.
func FuzzDecodeStdoutBody(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})             // seq=0, no payload
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 'a'})        // seq=1, "a"
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7})                // truncated seq prefix
	f.Add([]byte{})                                   // empty
	f.Add(bytes.Repeat([]byte{0xff}, 10))             // garbage
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeStdoutBody(data)
	})
}

// FuzzControlMessageDispatch: fed valid Attach Marshal output
// with arbitrary type-discriminator values and tweaked field
// shapes. Exercises the "PeekType says X but body is Y" mismatch
// path that the dispatcher in transport/pumps.go relies on.
func FuzzControlMessageDispatch(f *testing.F) {
	good, _ := MarshalAttach(Attach{V: 1, Rows: 24, Cols: 80})
	f.Add(good)
	pong, _ := MarshalPong(Pong{Nonce: 42})
	f.Add(pong)
	gb, _ := MarshalGoodbye(Goodbye{Reason: ReasonClientClose})
	f.Add(gb)
	f.Fuzz(func(t *testing.T, data []byte) {
		// Discover type via the same path the daemon uses.
		mt, err := PeekType(data)
		if err != nil {
			return
		}
		// Try every typed decode; none should panic regardless of
		// the actual contents.
		switch mt {
		case TypeAttach:
			var a Attach
			_ = StrictDecMode.Unmarshal(data, &a)
		case TypeAttachAck:
			var a AttachAck
			_ = StrictDecMode.Unmarshal(data, &a)
		case TypePing:
			var p Ping
			_ = StrictDecMode.Unmarshal(data, &p)
		case TypePong:
			var p Pong
			_ = StrictDecMode.Unmarshal(data, &p)
		case TypeAck:
			var a Ack
			_ = StrictDecMode.Unmarshal(data, &a)
		case TypeResize:
			var r Resize
			_ = StrictDecMode.Unmarshal(data, &r)
		case TypeGoodbye:
			var g Goodbye
			_ = StrictDecMode.Unmarshal(data, &g)
		}
	})
}
