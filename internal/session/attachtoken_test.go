package session

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAttachTokenStringRoundTrip(t *testing.T) {
	t.Parallel()
	var tok AttachToken
	for i := range tok {
		tok[i] = byte(i)
	}
	s := tok.String()
	if len(s) != AttachTokenLen*2 {
		t.Errorf("String length = %d, want %d", len(s), AttachTokenLen*2)
	}
	if s != strings.ToLower(s) {
		t.Error("String is not lowercase")
	}
	parsed, err := ParseAttachToken(s)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != tok {
		t.Error("round-trip lost data")
	}
}

func TestParseAttachTokenRejectsBad(t *testing.T) {
	t.Parallel()
	bad := []string{"", "abc", "zz" + strings.Repeat("0", 30)}
	for _, s := range bad {
		if _, err := ParseAttachToken(s); err == nil {
			t.Errorf("ParseAttachToken(%q) accepted invalid input", s)
		}
	}
}

func TestIssueAttachTokenRequiresSessionInRegistry(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	id, _ := NewSessionID()
	if _, err := r.IssueAttachToken(id); !errors.Is(err, ErrUnknownSession) {
		t.Errorf("IssueAttachToken on unknown session = %v, want ErrUnknownSession", err)
	}
}

func TestIssueThenConsumeRoundTrip(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	s := mustNewSession(t)
	if err := r.Add(s); err != nil {
		t.Fatal(err)
	}

	tok, err := r.IssueAttachToken(s.ID())
	if err != nil {
		t.Fatal(err)
	}
	if r.PendingTokenCount() != 1 {
		t.Errorf("PendingTokenCount = %d, want 1", r.PendingTokenCount())
	}

	got, err := r.ConsumeAttachToken(tok)
	if err != nil {
		t.Fatalf("ConsumeAttachToken: %v", err)
	}
	if got.ID() != s.ID() {
		t.Error("ConsumeAttachToken returned a different session")
	}
	if r.PendingTokenCount() != 0 {
		t.Errorf("PendingTokenCount after consume = %d, want 0", r.PendingTokenCount())
	}
}

func TestConsumeAttachTokenIsSingleUse(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	s := mustNewSession(t)
	r.Add(s)
	tok, _ := r.IssueAttachToken(s.ID())

	if _, err := r.ConsumeAttachToken(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConsumeAttachToken(tok); !errors.Is(err, ErrAttachTokenInvalid) {
		t.Errorf("second consume = %v, want ErrAttachTokenInvalid", err)
	}
}

func TestConsumeAttachTokenRejectsExpired(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	s := mustNewSession(t)
	r.Add(s)

	// Inject an already-expired token directly so we don't have to
	// wait 30s in tests. The public API only allows AttachTokenTTL,
	// but the registry's storage takes any expiresAt.
	r.mu.Lock()
	var expired AttachToken
	for i := range expired {
		expired[i] = 0xAA
	}
	r.tokens[expired] = pendingAttach{
		sessionID: s.ID(),
		expiresAt: time.Now().Add(-time.Second),
	}
	r.mu.Unlock()

	if _, err := r.ConsumeAttachToken(expired); !errors.Is(err, ErrAttachTokenInvalid) {
		t.Errorf("ConsumeAttachToken expired = %v, want ErrAttachTokenInvalid", err)
	}
	// Even though it was invalid, the entry should have been deleted.
	if r.PendingTokenCount() != 0 {
		t.Errorf("expired token not cleaned up; PendingTokenCount = %d", r.PendingTokenCount())
	}
}

func TestConsumeAttachTokenRejectsUnknown(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	var unused AttachToken
	if _, err := r.ConsumeAttachToken(unused); !errors.Is(err, ErrAttachTokenInvalid) {
		t.Errorf("ConsumeAttachToken unknown = %v, want ErrAttachTokenInvalid", err)
	}
}

func TestSweepAttachTokensRemovesExpired(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	s := mustNewSession(t)
	r.Add(s)

	// Plant two tokens: one fresh, one expired.
	r.mu.Lock()
	fresh := AttachToken{0xBB}
	expired := AttachToken{0xCC}
	r.tokens[fresh] = pendingAttach{sessionID: s.ID(), expiresAt: time.Now().Add(time.Hour)}
	r.tokens[expired] = pendingAttach{sessionID: s.ID(), expiresAt: time.Now().Add(-time.Second)}
	r.mu.Unlock()

	if got := r.SweepAttachTokens(); got != 1 {
		t.Errorf("SweepAttachTokens = %d, want 1", got)
	}
	if r.PendingTokenCount() != 1 {
		t.Errorf("PendingTokenCount after sweep = %d, want 1", r.PendingTokenCount())
	}
}

func TestIssuedTokensAreUnpredictable(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	s := mustNewSession(t)
	r.Add(s)

	const N = 100
	seen := make(map[AttachToken]struct{}, N)
	for i := 0; i < N; i++ {
		tok, err := r.IssueAttachToken(s.ID())
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token at iteration %d (CSPRNG broken or test miswired)", i)
		}
		seen[tok] = struct{}{}
	}
}
