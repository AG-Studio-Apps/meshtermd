package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// migrationPollInterval is how often the local-interface signature is
// re-sampled. 2 seconds is the right trade for client-driven QUIC
// path migration: shorter wastes syscalls on a stable laptop; longer
// extends the user-visible "frozen" window after a real WiFi → cell
// handoff. quic-go's 30s idle timeout gives a wide enough net for
// 2-second detection to land before the connection dies.
const migrationPollInterval = 2 * time.Second

// migrationProbeTimeout caps the time we wait for PATH_CHALLENGE /
// PATH_RESPONSE validation on a new path. 5 seconds matches mosh-ish
// expectations for "WiFi switch should feel instant" while leaving
// enough headroom for a slow cellular handshake.
const migrationProbeTimeout = 5 * time.Second

// migrationLoop watches the local network-interface set and, on any
// change, performs a QUIC path migration so the existing meshtermd
// session survives the IP rebind. Runs until ctx is cancelled.
//
// The trigger model is "any change to the set of up, non-loopback
// interface addresses": adding a VPN, dropping WiFi, getting a new
// DHCP lease — all are observable as a different sorted address set
// from one poll to the next. We don't try to predict which path the
// kernel will route via; quic-go's AddPath workflow validates
// whichever route the new UDP socket lands on.
//
// Failure modes are non-fatal — a migration attempt that doesn't
// validate just leaves the connection on the prior path; quic-go's
// own idle timer eventually surfaces the broken connection if the
// kernel can't route packets either way. Errors are logged to stderr
// (so a `mtctl attach` user sees "[mtctl: migration failed: …]" on
// the way out of a glitchy moment) but never propagated to the pump
// caller.
func migrationLoop(ctx context.Context, conn *quic.Conn) {
	prev := ifaceSignature()
	t := time.NewTicker(migrationPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := ifaceSignature()
			if cur == prev {
				continue
			}
			fmt.Fprintf(os.Stderr,
				"\r\n[mtctl: network change detected; migrating QUIC path]\r\n")
			if err := tryMigrate(ctx, conn); err != nil {
				fmt.Fprintf(os.Stderr,
					"\r\n[mtctl: migration failed: %v]\r\n", err)
			} else {
				fmt.Fprintf(os.Stderr,
					"\r\n[mtctl: migrated to new path]\r\n")
			}
			prev = cur
		}
	}
}

// tryMigrate opens a fresh UDP socket (kernel picks the new source
// IP), wraps it in a quic.Transport, asks the existing connection to
// add the new path, probes it via PATH_CHALLENGE/PATH_RESPONSE, and
// switches the connection over. The new Transport is intentionally
// not closed on success — quic-go retains a reference through the
// active path and tearing it down would kill the connection.
func tryMigrate(ctx context.Context, conn *quic.Conn) error {
	pkt, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("listen new udp socket: %w", err)
	}
	udp, ok := pkt.(*net.UDPConn)
	if !ok {
		_ = pkt.Close()
		return fmt.Errorf("listen returned %T, want *net.UDPConn", pkt)
	}
	tr := &quic.Transport{Conn: udp}
	path, err := conn.AddPath(tr)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("AddPath: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, migrationProbeTimeout)
	defer cancel()
	if err := path.Probe(probeCtx); err != nil {
		_ = path.Close()
		_ = udp.Close()
		return fmt.Errorf("Probe: %w", err)
	}
	if err := path.Switch(); err != nil {
		// Don't close path or socket here — Switch may have partially
		// succeeded; let quic-go own the lifecycle from this point.
		return fmt.Errorf("Switch: %w", err)
	}
	return nil
}

// ifaceSignature computes a deterministic string identifying the
// current set of up, non-loopback network-interface addresses. The
// migration loop polls this every migrationPollInterval and triggers
// when the signature changes between samples.
//
// Filters:
//   - Skip interfaces that aren't FlagUp (down nics shouldn't trigger).
//   - Skip loopback (real networks only — a 127.0.0.2 alias shouldn't
//     trigger production migrations).
//
// The "name:addr" pair is included for each address so a same-name
// interface that swaps IPs (DHCP reissue) still triggers. Addresses
// are sorted so iteration order doesn't matter.
func ifaceSignature() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			parts = append(parts, ifc.Name+":"+a.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

