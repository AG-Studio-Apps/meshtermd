package session

import "testing"

func TestNameHashLengthAndStability(t *testing.T) {
	t.Parallel()
	sid, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}

	first := NameHash(sid, "demo")
	if len(first) != 8 {
		t.Fatalf("NameHash length: want 8 hex chars, got %d (%q)", len(first), first)
	}
	second := NameHash(sid, "demo")
	if first != second {
		t.Fatalf("NameHash not deterministic: %q vs %q", first, second)
	}
}

func TestNameHashSeparatorPreventsTrivialCollision(t *testing.T) {
	t.Parallel()
	// Two SessionIDs that differ in the last byte must produce
	// distinct hashes regardless of the name.
	var sidA, sidB SessionID
	for i := range sidA {
		sidA[i] = byte(i)
		sidB[i] = byte(i)
	}
	sidB[len(sidB)-1] ^= 0x01

	a := NameHash(sidA, "x")
	b := NameHash(sidB, "x")
	if a == b {
		t.Fatalf("expected distinct hashes for differing sids, got %q == %q", a, b)
	}
}

func TestNameHashDistinguishesSidAndName(t *testing.T) {
	t.Parallel()
	sid, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	// Rename produces a new hash, by design.
	first := NameHash(sid, "demo")
	second := NameHash(sid, "Demo")
	if first == second {
		t.Fatalf("expected rename to produce a new hash, got %q == %q", first, second)
	}
}
