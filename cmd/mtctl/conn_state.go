package main

import (
	"sync/atomic"
	"time"
)

// connStats holds shared mutable connection metadata between the
// attach pumps and downstream consumers — the prediction engine
// (for `--predict=adaptive` threshold decisions) and the `~?` info
// command (for human-readable RTT display).
//
// Updated by the stdout pump on:
//   - Initial AttachAck decode → seed RTTNanos from the AttachAck.RTTNanos
//     field, which the daemon populates from quic-go's smoothed-RTT
//     estimator at attach time.
//   - Periodic RTTNotify control frames (every ~5s while attached).
//
// Read by:
//   - The prediction engine when deciding whether to render predictions
//     underlined in adaptive mode.
//   - The `~?` escape-watcher info dump (C2 in the v0.7.0 plan).
//
// Atomic so concurrent readers don't need a mutex; the pumps and the
// consumers run in independent goroutines.
type connStats struct {
	rttNanos atomic.Int64
}

// SetRTT records the latest smoothed-RTT estimate. ns ≤ 0 is a no-op
// — the daemon's emitter suppresses zero values (handshake not
// settled yet), so a leftover zero from an earlier seed wouldn't
// pollute the cache.
func (cs *connStats) SetRTT(ns int64) {
	if ns <= 0 {
		return
	}
	cs.rttNanos.Store(ns)
}

// RTT returns the latest smoothed-RTT as a time.Duration. Zero
// duration means "not measured yet" — consumers should treat that as
// "fall back to conservative defaults" (e.g. don't underline
// predictions until we have a reading).
func (cs *connStats) RTT() time.Duration {
	return time.Duration(cs.rttNanos.Load())
}
