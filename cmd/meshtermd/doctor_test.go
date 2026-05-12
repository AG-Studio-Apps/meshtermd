package main

import (
	"testing"
)

func TestUnitHasKillModeProcess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "standard form",
			body: "[Service]\nKillMode=process\nExecStart=/usr/bin/x\n",
			want: true,
		},
		{
			name: "spaces around equals",
			body: "[Service]\nKillMode = process\n",
			want: true,
		},
		{
			name: "case insensitive key",
			body: "[Service]\nkillmode=Process\n",
			want: true,
		},
		{
			name: "quoted value",
			body: "[Service]\nKillMode=\"process\"\n",
			want: true,
		},
		{
			name: "single-quoted value",
			body: "[Service]\nKillMode='process'\n",
			want: true,
		},
		{
			name: "missing entirely",
			body: "[Service]\nExecStart=/usr/bin/x\n",
			want: false,
		},
		{
			name: "wrong value",
			body: "[Service]\nKillMode=mixed\n",
			want: false,
		},
		{
			name: "commented out",
			body: "[Service]\n#KillMode=process\nExecStart=/usr/bin/x\n",
			want: false,
		},
		{
			name: "semicolon comment",
			body: "[Service]\n; KillMode=process\n",
			want: false,
		},
		{
			name: "empty file",
			body: "",
			want: false,
		},
		{
			name: "key prefix but not the key",
			body: "[Service]\nKillModeFoo=process\n",
			want: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := unitHasKillModeProcess([]byte(tc.body))
			if got != tc.want {
				t.Errorf("unitHasKillModeProcess(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestBuildDoctorReportNoDaemon(t *testing.T) {
	t.Parallel()
	// No daemon listening at a bogus socket — buildDoctorReport must
	// still return a usable report with the contact_error recorded
	// and a corresponding warning. Used by the doctor's promise that
	// "if your daemon is down, doctor still tells you why."
	report := buildDoctorReport("/tmp/no-such-meshtermd-sock", 50)
	if report.Daemon.Running {
		t.Errorf("Daemon.Running = true, want false for bogus socket")
	}
	if report.Daemon.ContactError == "" {
		t.Errorf("Daemon.ContactError empty; want a description of the failure")
	}
	// Supervisor section must still be filled.
	if report.Supervisor.Backend == "" {
		t.Errorf("Supervisor.Backend empty; expected svcmgr.Detect() result")
	}
	// At least one warning explaining the daemon-down condition.
	if len(report.Warnings) == 0 {
		t.Errorf("Warnings empty; want at least one entry about the unreachable daemon")
	}
}
