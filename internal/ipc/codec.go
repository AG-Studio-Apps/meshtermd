package ipc

import (
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// IPC frames are framed with `protocol.WriteFrame` / `ReadFrame`,
// which inherits `protocol.MaxControlFrameBytes` (64 KiB). We
// previously declared a separate `MaxFrameBytes = 256 KiB` here
// but it was never wired in; audit F-E (v0.0.2 review) flagged the
// dead constant as a future-reviewer trap and we removed it.

// EncodeRequest CBOR-encodes a typed request struct (with its `t`
// discriminator stamped) and writes it as a length-prefixed frame.
// Mirrors the control stream's encoding so we have one
// understanding of "frame on a wire" throughout the codebase.
func EncodeRequest(w io.Writer, req any) error {
	b, err := cborMarshal(req)
	if err != nil {
		return fmt.Errorf("encode ipc request: %w", err)
	}
	return protocol.WriteFrame(w, b)
}

// EncodeResponse mirrors EncodeRequest for response types.
func EncodeResponse(w io.Writer, resp any) error {
	b, err := cborMarshal(resp)
	if err != nil {
		return fmt.Errorf("encode ipc response: %w", err)
	}
	return protocol.WriteFrame(w, b)
}

// ReadFrame reads one length-prefixed CBOR frame and returns its
// raw body. Caller dispatches on the `t` discriminator via
// PeekType / typed unmarshal.
func ReadFrame(r io.Reader) ([]byte, error) {
	return protocol.ReadFrame(r)
}

// PeekType extracts the `t` discriminator from a frame body.
func PeekType(body []byte) (string, error) {
	return protocol.PeekType(body)
}

// DecodeAllocateRequest decodes a frame body as an AllocateRequest.
// Returns an error if the body's `t` discriminator doesn't match
// TypeAllocate or the CBOR is malformed.
func DecodeAllocateRequest(body []byte) (AllocateRequest, error) {
	t, err := PeekType(body)
	if err != nil {
		return AllocateRequest{}, err
	}
	if t != TypeAllocate {
		return AllocateRequest{}, fmt.Errorf("expected Allocate frame, got %q", t)
	}
	var req AllocateRequest
	if err := protocol.StrictDecMode.Unmarshal(body, &req); err != nil {
		return AllocateRequest{}, err
	}
	return req, nil
}

// DecodeAllocateResponse mirrors DecodeAllocateRequest.
func DecodeAllocateResponse(body []byte) (AllocateResponse, error) {
	t, err := PeekType(body)
	if err != nil {
		return AllocateResponse{}, err
	}
	if t != TypeAllocate {
		return AllocateResponse{}, fmt.Errorf("expected Allocate response, got %q", t)
	}
	var resp AllocateResponse
	if err := protocol.StrictDecMode.Unmarshal(body, &resp); err != nil {
		return AllocateResponse{}, err
	}
	return resp, nil
}

// DecodePingRequest decodes a frame body as a PingRequest.
func DecodePingRequest(body []byte) (PingRequest, error) {
	t, err := PeekType(body)
	if err != nil {
		return PingRequest{}, err
	}
	if t != TypePing {
		return PingRequest{}, fmt.Errorf("expected Ping frame, got %q", t)
	}
	var req PingRequest
	if err := protocol.StrictDecMode.Unmarshal(body, &req); err != nil {
		return PingRequest{}, err
	}
	return req, nil
}

// DecodePingResponse mirrors DecodePingRequest.
func DecodePingResponse(body []byte) (PingResponse, error) {
	t, err := PeekType(body)
	if err != nil {
		return PingResponse{}, err
	}
	if t != TypePing {
		return PingResponse{}, fmt.Errorf("expected Ping response, got %q", t)
	}
	var resp PingResponse
	if err := protocol.StrictDecMode.Unmarshal(body, &resp); err != nil {
		return PingResponse{}, err
	}
	return resp, nil
}

func cborMarshal(v any) ([]byte, error) {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(v)
}

