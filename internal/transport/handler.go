package transport

import (
	"context"
	"log/slog"

	"github.com/quic-go/quic-go"
)

// LoggingHandler is the v0.0.x placeholder Handler. It logs each
// accepted connection's remote address + ALPN, then closes with a
// "not implemented" application error. Replaced in a later commit
// by the real protocol handler that drives Attach / replay / stream
// demux.
type LoggingHandler struct {
	Logger *slog.Logger
}

// HandleConnection implements Handler.
func (h *LoggingHandler) HandleConnection(ctx context.Context, conn *quic.Conn) {
	state := conn.ConnectionState()
	logger := h.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "accepted connection",
		"remote", conn.RemoteAddr().String(),
		"alpn", state.TLS.NegotiatedProtocol,
	)
	_ = conn.CloseWithError(0, "not implemented yet")
}
