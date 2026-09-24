package agent

// harnesspath.go makes a harness that was installed for a *user* visible to a
// process supervised by a *service manager* (Task 20336).
//
// # The gap this closes, which is the whole reason auto-install needed it
//
// Claude Code's official installer is deliberately not a system package. It
// needs no root and it writes no system path: the binary lands in
// ~/.local/share/claude/versions/ with a launcher symlinked at
// ~/.local/bin/claude. That is the right default for a person at a terminal,
// whose shell profile has long since put ~/.local/bin on PATH.
//
// A systemd unit has no profile. Its PATH is whatever the unit or the manager's
// default says, which on every distribution means /usr/bin and friends and
// nothing under a home directory. So the install genuinely succeeds and
// exec.LookPath("claude") genuinely keeps failing — and the failure arrives
// looking exactly like the one auto-install was added to remove.
//
// That makes this file load-bearing rather than tidying. Without it the feature
// would install a harness, advertise it, and then fail the run with
// "executable file not found in $PATH" — the precise outcome Task 20332 existed
// to stop, now with a successful install in front of it to make it confusing.
//
// # Why detection and execution are fixed together
//
// It would be easy to teach Detect to look in ~/.local/bin and stop there. The
// device would then advertise the harness, the hub would place work on it, and
// the payload — which resolves the binary by name, through its own PATH —
// would still not find it. Capabilities would have become a lie, which is the
// failure mode this codebase's drivers already refuse elsewhere: an advertised
// capability has to be one the device can actually deliver.
//
// So both halves are here and both are applied together:
//
//   - the agent's own PATH gains these directories, which is what makes
//     LookPath in Detect true and what a nil Spec.Env inherits; and
//   - a Spec carrying an *explicit* environment gets them prepended to its
//     PATH, because cmd.Env replaces rather than adds and a leased credential
//     always produces an explicit environment (see withRunnableEnv in
//     pkg/executor/localprocess).
//
// Miss either and the bug is back for half the projects on the fleet — the
// half distinguished by whether they hold a secret grant, which is not a
// distinction anyone would think to test against.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// nativeHarnessSubdirs are the per-user directories a harness installer writes
// to, relative to the home directory.
//
// The list mirrors findClaude in pkg/provider/claudecode, which solved the same
// problem for the hub's in-process provider and found the same two locations:
// ~/.local/bin for the native installer, ~/.npm-global/bin for a global npm
// install by a user who redirected npm's prefix to avoid sudo. Kept in step
// with it deliberately — a harness the hub's own provider can find and a
// remote device cannot would be a difference with no principle behind it.
var nativeHarnessSubdirs = []string{
	filepath.Join(".local", "bin"),
	filepath.Join(".npm-global", "bin"),
}

// NativeHarnessDirs returns the absolute per-user harness directories for this
// device, skipping any that do not exist.
//
// Non-existent directories are dropped rather than returned hopefully: these
// values are prepended to PATH, and a PATH full of entries that resolve to
// nothing costs every exec on the device a failed stat for the life of the
// process.
func NativeHarnessDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return nil
	}
	var dirs []string
	for _, sub := range nativeHarnessSubdirs {
		dir := filepath.Join(home, sub)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// pathFixup serialises the read-modify-write of the process PATH. Installs run
// on their own goroutine and the agent refreshes the PATH at startup, so two
// of these can genuinely overlap; os.Setenv is safe on its own but a
// Getenv-then-Setenv pair is not.
var pathFixup sync.Mutex

// EnsureHarnessPath prepends this device's per-user harness directories to the
// agent process's own PATH, and reports the directories it added.
//
// Idempotent: a directory already on PATH is not added again, so calling this
// at startup and again after every install cannot grow the variable without
// bound over a long-lived agent.
//
// Mutating the process environment is a blunt instrument and worth justifying.
// The alternative is to thread a resolved absolute path from detection through
// to every exec, and that fails for the case that matters most — the harness is
// not run by this process, it is run by `cloop run` *inside* the payload, which
// resolves "claude" by name through whatever PATH it inherited. The only place
// to intervene for that is the environment the payload starts with, and the
// agent's own environment is its parent.
func EnsureHarnessPath() []string {
	dirs := NativeHarnessDirs()
	if len(dirs) == 0 {
		return nil
	}

	pathFixup.Lock()
	defer pathFixup.Unlock()

	current := os.Getenv("PATH")
	added := missingDirs(current, dirs)
	if len(added) == 0 {
		return nil
	}
	if err := os.Setenv("PATH", prependDirs(current, added)); err != nil {
		// A PATH that cannot be set leaves the device exactly where it was:
		// the harness stays undetected and the dispatch refusal explains it.
		// Nothing here is worth failing an agent over.
		return nil
	}
	return added
}

// withHarnessPath returns env with dirs prepended to its PATH entry.
//
// A nil env is returned unchanged, and that is the correct answer rather than
// an omission: nil means "inherit this process's environment", and this
// process's PATH has already been fixed by EnsureHarnessPath. Materialising the
// full inherited environment here just to edit one variable would convert an
// inheriting Spec into an explicit one and hand the payload every variable the
// agent holds — the agent's enrollment credential among them.
func withHarnessPath(env []string, dirs []string) []string {
	if len(env) == 0 || len(dirs) == 0 {
		return env
	}
	out := make([]string, len(env))
	copy(out, env)
	for i, kv := range out {
		value, ok := strings.CutPrefix(kv, "PATH=")
		if !ok {
			continue
		}
		add := missingDirs(value, dirs)
		if len(add) == 0 {
			return out
		}
		out[i] = "PATH=" + prependDirs(value, add)
		return out
	}
	// An explicit environment with no PATH at all. Left alone on purpose:
	// localprocess.withRunnableEnv inserts its default PATH for exactly this
	// case, and adding a PATH here would pre-empt that and leave the payload
	// with the harness directories and nothing else — no /bin, no /usr/bin.
	return out
}

// missingDirs returns the entries of dirs that are not already in the
// colon-separated path list.
func missingDirs(path string, dirs []string) []string {
	present := make(map[string]struct{}, 8)
	for _, p := range strings.Split(path, string(os.PathListSeparator)) {
		if p = strings.TrimSpace(p); p != "" {
			present[p] = struct{}{}
		}
	}
	var out []string
	for _, d := range dirs {
		if _, ok := present[d]; ok {
			continue
		}
		// Guard against the same directory appearing twice in dirs, which
		// would otherwise be added twice in one call.
		present[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// prependDirs puts dirs in front of a colon-separated path list.
//
// In front rather than behind, so that a harness a user installed for
// themselves wins over a stale copy left in a system directory by an earlier
// packaging attempt. That is the same precedence a login shell would give it,
// which is the behaviour an operator predicts.
func prependDirs(path string, dirs []string) string {
	sep := string(os.PathListSeparator)
	joined := strings.Join(dirs, sep)
	if strings.TrimSpace(path) == "" {
		return joined
	}
	return joined + sep + path
}
