// Package completions is the single source of truth for the
// subcommand and flag inventory of `meshtermd` and `mtctl`, used by
// the cmd/gen-completions generator to emit bash/zsh/fish completion
// scripts. Keep this file in lockstep with the actual CLIs — adding a
// subcommand without updating this spec means it won't be tab-
// completable until someone notices.
//
// Scope: subcommand-level completion plus the long-flag names per
// subcommand. Flag *value* completion (e.g. tab-completing existing
// session IDs by querying the daemon) is deliberately out for v1 —
// it requires running the CLI to populate, which is fragile when
// $MTCTL_HOST is unreachable.
package completions

// Flag is a long-form flag name plus its one-line help. Short flags
// are accepted by the CLIs but completion only offers the long form;
// users tab-complete `--<TAB>` and pick from there.
type Flag struct {
	Long string
	Help string
}

// Subcommand pairs a subcommand name with its one-line description
// and any flags it accepts (in addition to the always-accepted
// --help / -h).
type Subcommand struct {
	Name  string
	Help  string
	Flags []Flag
}

// Binary is one of the two shipped CLIs.
type Binary struct {
	Name        string
	Subcommands []Subcommand
}

// hostFlag is reused across mtctl subcommands that need an SSH target.
var hostFlag = Flag{Long: "--host", Help: "SSH target running meshtermd (default: $MTCTL_HOST)"}

// jsonFlag is reused across subcommands that emit a machine output.
var jsonFlag = Flag{Long: "--json", Help: "emit machine-readable JSON"}

// updateFlags are the shared flags on `update` for both binaries.
var updateFlags = []Flag{
	{Long: "--check", Help: "print current vs available version and exit"},
	{Long: "--yes", Help: "skip the confirmation prompt"},
	{Long: "--tag", Help: "update to a specific tag instead of the latest"},
	{Long: "--allow-downgrade", Help: "permit installing a tag older than the running version"},
}

// Mtctl is the laptop CLI spec. Mirrors cmd/mtctl/main.go's switch
// table — when adding a subcommand there, add it here.
var Mtctl = Binary{
	Name: "mtctl",
	Subcommands: []Subcommand{
		{Name: "version", Help: "print build identifier"},
		{Name: "list", Help: "enumerate sessions on the remote daemon",
			Flags: []Flag{hostFlag, jsonFlag,
				{Long: "--timeout", Help: "SSH dial / command timeout (e.g. 5s, 2m)"}}},
		{Name: "session-info", Help: "print one session's detail",
			Flags: []Flag{hostFlag, jsonFlag}},
		{Name: "status", Help: "print the remote daemon's operational snapshot",
			Flags: []Flag{hostFlag, jsonFlag}},
		{Name: "new", Help: "create a new named session (does not attach)",
			Flags: []Flag{hostFlag,
				{Long: "--name", Help: "user-visible session name"},
				{Long: "--idle-timeout", Help: "per-session idle GC timeout (e.g. 1h, 7d)"}}},
		{Name: "attach", Help: "attach to a session as your local terminal",
			Flags: []Flag{hostFlag,
				{Long: "--mode", Help: "attach mode: exclusive (default) or readonly"}}},
		{Name: "kill", Help: "reap a session by id or name",
			Flags: []Flag{hostFlag,
				{Long: "--all", Help: "kill every session on the daemon"}}},
		{Name: "rename", Help: "rename a session",
			Flags: []Flag{hostFlag}},
		{Name: "update", Help: "check for / apply a signed self-update", Flags: updateFlags},
		{Name: "uninstall", Help: "remove the mtctl binary",
			Flags: []Flag{{Long: "--yes", Help: "skip the confirmation prompt"}}},
		{Name: "help", Help: "print top-level usage"},
	},
}

// Meshtermd is the daemon CLI spec. Mirrors cmd/meshtermd/main.go.
var Meshtermd = Binary{
	Name: "meshtermd",
	Subcommands: []Subcommand{
		{Name: "version", Help: "print build identifier"},
		{Name: "serve", Help: "run the long-lived daemon",
			Flags: []Flag{
				{Long: "--addr", Help: "QUIC listen address (default 127.0.0.1:0)"},
				{Long: "--max-sessions", Help: "cap on concurrent sessions"},
				{Long: "--max-idle-timeout", Help: "ceiling for per-session idle timeouts"}}},
		{Name: "connect", Help: "SSH-side bootstrap helper (invoked by the iOS app)"},
		{Name: "list", Help: "enumerate live sessions on this daemon",
			Flags: []Flag{jsonFlag}},
		{Name: "session-info", Help: "print one session's detail",
			Flags: []Flag{jsonFlag}},
		{Name: "status", Help: "print the daemon's operational snapshot",
			Flags: []Flag{jsonFlag}},
		{Name: "kill", Help: "reap a session by id or name",
			Flags: []Flag{{Long: "--all", Help: "kill every session"}}},
		{Name: "rename", Help: "rename a session"},
		{Name: "update", Help: "check for / apply a signed self-update", Flags: updateFlags},
		{Name: "uninstall", Help: "remove the daemon, supervisor unit, and (optionally) state",
			Flags: []Flag{
				{Long: "--yes", Help: "skip the confirmation prompt"},
				{Long: "--purge", Help: "also wipe ~/.local/share/meshtermd/"}}},
		{Name: "help", Help: "print top-level usage"},
	},
}

// All returns every shipped binary, used by the generator's batch
// mode (one invocation, both binaries emitted).
func All() []Binary {
	return []Binary{Mtctl, Meshtermd}
}
