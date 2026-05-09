package protocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestALPNMatchesSpec(t *testing.T) {
	t.Parallel()
	if ALPN != "meshterm/0" {
		t.Errorf("ALPN drifted: %q. Wire-format change requires bumping ALPN epoch and updating docs/roam-protocol.md.", ALPN)
	}
}

func TestMarshalSetsTypeDiscriminator(t *testing.T) {
	t.Parallel()
	b, err := MarshalAttach(Attach{V: 1, Token: []byte("tok"), SessionID: []byte("sid"), Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	got, err := PeekType(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != TypeAttach {
		t.Errorf("PeekType = %q, want %q", got, TypeAttach)
	}
}

func TestEachMarshalStampsItsType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fn   func() ([]byte, error)
		want string
	}{
		{"Attach", func() ([]byte, error) { return MarshalAttach(Attach{}) }, TypeAttach},
		{"AttachAck", func() ([]byte, error) { return MarshalAttachAck(AttachAck{}) }, TypeAttachAck},
		{"Ack", func() ([]byte, error) { return MarshalAck(Ack{}) }, TypeAck},
		{"Resize", func() ([]byte, error) { return MarshalResize(Resize{}) }, TypeResize},
		{"Ping", func() ([]byte, error) { return MarshalPing(Ping{}) }, TypePing},
		{"Pong", func() ([]byte, error) { return MarshalPong(Pong{}) }, TypePong},
		{"Goodbye", func() ([]byte, error) { return MarshalGoodbye(Goodbye{}) }, TypeGoodbye},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			b, err := c.fn()
			if err != nil {
				t.Fatal(err)
			}
			got, err := PeekType(b)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("PeekType = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAttachRoundTrip(t *testing.T) {
	t.Parallel()
	original := Attach{
		V:         1,
		Token:     []byte{0x01, 0x02, 0x03},
		SessionID: []byte{0xaa, 0xbb, 0xcc, 0xdd},
		AckSeq:    42,
		Rows:      40,
		Cols:      120,
	}
	b, err := MarshalAttach(original)
	if err != nil {
		t.Fatal(err)
	}
	var got Attach
	if err := cbor.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.T != TypeAttach {
		t.Errorf("T = %q, want %q", got.T, TypeAttach)
	}
	if got.V != original.V || got.AckSeq != original.AckSeq || got.Rows != original.Rows || got.Cols != original.Cols {
		t.Errorf("scalar fields lost: got %+v want %+v", got, original)
	}
	if !bytes.Equal(got.Token, original.Token) {
		t.Errorf("Token round-trip lost data")
	}
	if !bytes.Equal(got.SessionID, original.SessionID) {
		t.Errorf("SessionID round-trip lost data")
	}
}

func TestPeekTypeRejectsMissingT(t *testing.T) {
	t.Parallel()
	// CBOR for an empty map ({}) — valid CBOR, but no t.
	b, _ := cbor.Marshal(map[string]int{"x": 1})
	if _, err := PeekType(b); err == nil {
		t.Error("PeekType accepted a map with no t field")
	}
}

func TestPeekTypeRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := PeekType([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Error("PeekType accepted invalid CBOR")
	}
}

func TestWriteReadFrameRoundTrip(t *testing.T) {
	t.Parallel()
	body := []byte("hello, frame")
	var buf bytes.Buffer
	if err := WriteFrame(&buf, body); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("round-trip data mismatch: got %q want %q", got, body)
	}
}

func TestWriteFrameRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte{0xa}, MaxControlFrameBytes+1)
	if err := WriteFrame(io.Discard, body); err == nil {
		t.Error("WriteFrame accepted body exceeding limit")
	}
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	t.Parallel()
	// Craft a header that claims a body bigger than the limit.
	// Length = MaxControlFrameBytes + 1 in big-endian.
	hdr := []byte{0, 1, 0, 1} // 65537 = 0x00010001 — bigger than 65536
	r := bytes.NewReader(hdr)
	if _, err := ReadFrame(r); err == nil {
		t.Error("ReadFrame accepted oversized length header")
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	t.Parallel()
	// Three bytes, truncated header.
	r := bytes.NewReader([]byte{0, 0, 0})
	_, err := ReadFrame(r)
	if err == nil {
		t.Error("ReadFrame accepted truncated header")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Errorf("ReadFrame error = %v, want io.EOF or io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameTruncatedBody(t *testing.T) {
	t.Parallel()
	// Header says 10 bytes; supply 4.
	r := bytes.NewReader(append([]byte{0, 0, 0, 10}, []byte("abcd")...))
	if _, err := ReadFrame(r); err == nil {
		t.Error("ReadFrame accepted truncated body")
	}
}

func TestReadFrameAtEOF(t *testing.T) {
	t.Parallel()
	r := bytes.NewReader(nil)
	if _, err := ReadFrame(r); !errors.Is(err, io.EOF) {
		t.Errorf("ReadFrame at EOF = %v, want io.EOF", err)
	}
}

func TestOutputFrameRoundTrip(t *testing.T) {
	t.Parallel()
	payload := []byte("some pty bytes")
	var buf bytes.Buffer
	if err := EncodeOutputFrame(&buf, 12345, payload); err != nil {
		t.Fatal(err)
	}
	seq, got, err := DecodeOutputFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 12345 {
		t.Errorf("seq = %d, want 12345", seq)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload round-trip lost data")
	}
}

func TestOutputFrameRejectsOversizedPayload(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte{0xa}, MaxOutputFramePayload+1)
	if err := EncodeOutputFrame(io.Discard, 0, big); err == nil {
		t.Error("EncodeOutputFrame accepted payload exceeding limit")
	}
}

func TestOutputFrameDecodeRejectsOversizedHeader(t *testing.T) {
	t.Parallel()
	// 8 bytes of seq (any), then 4 bytes of length too big.
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0x10, 0, 1} // length = 0x00100001 = 1048577 bytes
	r := bytes.NewReader(hdr)
	if _, _, err := DecodeOutputFrame(r); err == nil {
		t.Error("DecodeOutputFrame accepted oversized payload header")
	}
}

func TestCanonicalEncodingIsStable(t *testing.T) {
	t.Parallel()
	// CTAP2 canonical encoding sorts map keys deterministically.
	// Re-marshalling the same struct should produce identical bytes.
	a := Attach{V: 1, Token: []byte("t"), SessionID: []byte("s"), AckSeq: 5, Rows: 24, Cols: 80}
	b1, err := MarshalAttach(a)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := MarshalAttach(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Error("two marshals of the same struct produced different bytes — encoding not deterministic")
	}
}

func TestErrorCodeConstants(t *testing.T) {
	t.Parallel()
	// Lock the wire-level numeric values so future refactors don't
	// silently break the protocol contract.
	checks := map[uint64]string{
		1001: "ErrOversizedFrame",
		1002: "ErrBadFrame",
		1003: "ErrProtocolViolation",
		1004: "ErrBadToken",
		1005: "ErrStreamWrongOrder",
		1006: "ErrOversizedDatagram",
		2000: "ErrInternal",
	}
	if int(ErrOversizedFrame) != 1001 ||
		int(ErrBadFrame) != 1002 ||
		int(ErrProtocolViolation) != 1003 ||
		int(ErrBadToken) != 1004 ||
		int(ErrStreamWrongOrder) != 1005 ||
		int(ErrOversizedDatagram) != 1006 ||
		int(ErrInternal) != 2000 {
		t.Errorf("error code drifted from spec; constants must match docs/roam-protocol.md § 13: %v", checks)
	}
}

func TestSpecConstantsHaveExpectedNames(t *testing.T) {
	t.Parallel()
	// Sanity: our Reason* and AttachErr* string values should match
	// the spec's named codes. Lock them down so refactors don't
	// rename them silently.
	wantReasons := []string{"client_close", "session_ended", "shutdown", "error", "replaced"}
	gotReasons := []string{ReasonClientClose, ReasonSessionEnded, ReasonShutdown, ReasonError, ReasonReplaced}
	for i, w := range wantReasons {
		if gotReasons[i] != w {
			t.Errorf("Reason[%d] = %q, want %q", i, gotReasons[i], w)
		}
	}
	wantErrs := []string{"unknown_session", "bad_token", "version_unsupported", "capacity", "replaced"}
	gotErrs := []string{AttachErrUnknownSession, AttachErrBadToken, AttachErrVersionUnsupported, AttachErrCapacity, AttachErrReplaced}
	for i, w := range wantErrs {
		if gotErrs[i] != w {
			t.Errorf("AttachErr[%d] = %q, want %q", i, gotErrs[i], w)
		}
	}
	// Sanity: all Reason* codes should be lowercase snake_case.
	for _, r := range gotReasons {
		if r != strings.ToLower(r) || strings.Contains(r, " ") {
			t.Errorf("Reason %q must be lowercase snake_case", r)
		}
	}
}
