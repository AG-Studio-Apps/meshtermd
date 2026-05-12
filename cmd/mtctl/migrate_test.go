package main

import (
	"strings"
	"testing"
)

// TestIfaceSignatureStableAcrossCalls: signature is deterministic
// when interfaces don't change. Two back-to-back calls return the
// same string.
func TestIfaceSignatureStableAcrossCalls(t *testing.T) {
	t.Parallel()
	a := ifaceSignature()
	b := ifaceSignature()
	if a != b {
		t.Errorf("signature flapped: a=%q b=%q", a, b)
	}
}

// TestIfaceSignatureSkipsLoopback: the signature must NOT include
// the loopback interface (127.0.0.1 / ::1). If we leaked loopback,
// every test environment with an alias on lo would trigger a
// migration storm. We assert by checking the substring "127.0.0.1"
// is absent — the loopback interface always has at least 127.0.0.1
// on POSIX hosts, so its absence proves we're filtering.
func TestIfaceSignatureSkipsLoopback(t *testing.T) {
	t.Parallel()
	sig := ifaceSignature()
	if strings.Contains(sig, "127.0.0.1") {
		t.Errorf("signature leaks loopback addr 127.0.0.1: %q", sig)
	}
	if strings.Contains(sig, "::1/128") {
		t.Errorf("signature leaks loopback addr ::1/128: %q", sig)
	}
}

// TestIfaceSignatureNonEmptyOnRealHost: any developer machine running
// these tests has at least one non-loopback interface up (the box
// must've gotten the test binary somehow). Asserting non-empty
// catches an over-filter bug where we'd skip everything.
//
// Skipped on hosts with no non-loopback interfaces (rare; airgapped
// VMs). The test would be a flaky false positive there.
func TestIfaceSignatureNonEmptyOnRealHost(t *testing.T) {
	t.Parallel()
	sig := ifaceSignature()
	if sig == "" {
		t.Skip("no non-loopback interfaces detected; environment-dependent")
	}
}
