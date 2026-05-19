package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"dev", `'dev'`},
		{"with space", `'with space'`},
		{"", `''`},
		// POSIX single-quote escape: close, escaped quote, reopen.
		{"can't", `'can'\''t'`},
		{`a'b'c`, `'a'\''b'\''c'`},
		// Shell metacharacters survive intact inside single quotes.
		{"$HOME; rm -rf /", `'$HOME; rm -rf /'`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := shellQuote(tc.in); got != tc.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveHostPrecedence(t *testing.T) {
	// 1. Explicit flag wins over env + config file.
	t.Setenv("MTCTL_HOST", "env@host")
	if got, err := resolveHost("flag@host"); err != nil || got != "flag@host" {
		t.Errorf("flag override: got %q, %v; want flag@host, nil", got, err)
	}

	// 2. Env wins over config file when flag empty.
	if got, err := resolveHost(""); err != nil || got != "env@host" {
		t.Errorf("env precedence: got %q, %v; want env@host, nil", got, err)
	}

	// 3. Config file is the last fallback.
	tmp := t.TempDir()
	mtctlDir := filepath.Join(tmp, ".config", "mtctl")
	if err := os.MkdirAll(mtctlDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(mtctlDir, "host")
	if err := os.WriteFile(hostFile, []byte("file@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", tmp)
	t.Setenv("MTCTL_HOST", "")
	if got, err := resolveHost(""); err != nil || got != "file@host" {
		t.Errorf("file fallback: got %q, %v; want file@host, nil", got, err)
	}
}

func TestResolveHostErrorsWhenUnset(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("MTCTL_HOST", "")
	_, err := resolveHost("")
	if err == nil {
		t.Fatal("resolveHost with nothing set returned nil error")
	}
	if !strings.Contains(err.Error(), "no SSH host configured") {
		t.Errorf("error message missing guidance: %v", err)
	}
}

// TestValidateSSHHostRejectsOptionInjection guards against the Codex
// audit 2026-05-19 MEDIUM finding: a host beginning with `-` could
// otherwise be parsed by OpenSSH as an option element, e.g.
// `-oProxyCommand=evil-script` → local-command execution.
func TestValidateSSHHostRejectsOptionInjection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"normal user@host", "alice@example.com", false},
		{"bare host", "example.com", false},
		{"host with port (.ssh/config style)", "myserver", false},
		{"empty", "", true},
		{"leading dash short opt", "-l alice", true},
		{"leading dash long opt", "-oProxyCommand=evil-script", true},
		{"leading dash F config", "-F /attacker.cfg", true},
		{"just a dash", "-", true},
		{"double dash literal", "--", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSSHHost(tc.host)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.host)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.host, err)
			}
		})
	}
}
