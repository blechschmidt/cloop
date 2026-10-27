// Package copilotauth keeps one person's GitHub Copilot CLI apart from every
// other person's on a hub with single sign-on (Task 20449).
//
// The Copilot CLI signs in with the first credential it finds: a token in
// COPILOT_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN, the account `copilot login`
// stored under its home, then the GitHub CLI's. It keeps its session state and
// its logs — which hold the conversation — in that home: COPILOT_HOME, else
// ~/.copilot. A run on the hub's own host inherits the hub's environment and
// HOME, so before this package every person's copilot run on a hub with single
// sign-on, every dashboard model call on a copilot project and every resume of
// one signed in as whoever the hub's environment named — its operator's
// `copilot login`, or a GH_TOKEN the service holds for something else — and
// wrote everybody's conversations into one directory. Tasks 20241, 20442 and
// 20443 closed the same hole for Claude.
//
// The package has two halves.
//
// Homes. A person's Copilot home is the copilot directory inside their identity
// home, the directory claudecodeauth.HomeFor keeps for their Claude login. One
// tree on purpose: everything that removes that directory removes this one with
// it — an offboarding on every hub member, the hourly sweep of denied
// identities' homes, a deletion at the identity provider — and a legal hold
// that keeps the one keeps the other. It holds the CLI's sessions and logs, and
// no credential: the person's Copilot credential is a personal secret in the
// broker, sealed there, which a lease delivers to their own runs only.
//
// The environment. The hub knows whom a dispatch acts for; the provider spawns
// the CLI, possibly in another process — a `cloop run` on the hub's host. They
// meet in the environment:
//
//   - HubBlanks is what the hub appends to the environment such a dispatch
//     inherits, before its lease: every Copilot variable the hub holds,
//     blanked, so that the Copilot credential left in the run is what the
//     lease delivers — the person's own grant, or one an administrator shared
//     with the project. They are read by the Copilot CLI and nothing else, so
//     blanking them costs no other tool anything; the GitHub tokens and host
//     the CLI would also read stay for the tools that use them, and the
//     provider takes them from the CLI.
//   - Pin names the person's home in EnvHome, appended after everything else,
//     so no grant can point a run at somebody else's.
//   - ChildEnv is the provider's half: when the environment it inherits names
//     a home, the CLI gets that home, the credential the lease delivered and
//     nothing else of the hub's — no COPILOT_* setting, no GitHub token, no
//     host to send one to, and a GitHub CLI configuration of its own, so
//     neither the CLI's stored login nor gh's can stand in for a missing
//     credential.
//
// Without EnvHome nothing changes: a hub without single sign-on has one
// operator, whose sign-in is the one meant, and a `cloop run` started from a
// shell runs with that shell's.
package copilotauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
)

// EnvHome is the variable the hub pins a run's Copilot CLI to one person's home
// with. Its presence is what puts the provider in the per-person mode.
const EnvHome = "CLOOP_COPILOT_HOME"

// homeDirName is a person's Copilot home inside their identity home.
const homeDirName = "copilot"

// unattributedDirName is the Copilot home of dispatches that act for no one —
// the static admin token, a service token minted on nobody's behalf — beside
// the identity homes. Such a dispatch runs only on a credential an
// administrator shared with the project; this keeps its sessions out of the
// hub user's own ~/.copilot, which may hold the hub's `copilot login`.
const unattributedDirName = "copilot-unattributed"

// ghConfigDirName is the GitHub CLI configuration directory inside a Copilot
// home: empty, so `gh auth token` — the CLI's last resort — finds no login,
// and gh in the agent's shell is not the hub user's.
const ghConfigDirName = "gh"

// ErrNoIdentity is returned for a home requested for an empty owner key: a
// dispatch acting for no one has UnattributedHome, never a person's.
var ErrNoIdentity = errors.New("copilotauth: no identity")

// HomePath returns where ownerKey's Copilot home is, or would be, without
// creating anything: what an automatic dispatch acting for them — a resume, a
// failover — finds or does not, as it finds their Claude home.
func HomePath(ownerKey string) (string, error) {
	if strings.TrimSpace(ownerKey) == "" {
		return "", ErrNoIdentity
	}
	base, err := claudecodeauth.HomePath(ownerKey)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, homeDirName), nil
}

// HomeFor returns ownerKey's Copilot home, creating it — and the identity home
// around it — 0700 if absent. Called when the person starts something.
func HomeFor(ownerKey string) (string, error) {
	if strings.TrimSpace(ownerKey) == "" {
		return "", ErrNoIdentity
	}
	base, err := claudecodeauth.HomeFor(ownerKey)
	if err != nil {
		return "", err
	}
	return ensureDir(filepath.Join(base, homeDirName))
}

// ErrUnknown is returned by HomeIfKnown for an identity this hub keeps no
// identity home for: offboarded, or never here.
var ErrUnknown = errors.New("copilotauth: no identity home on this hub — offboarded, or never signed in here")

// HomeIfKnown returns ownerKey's Copilot home, making that directory if need
// be, only where their identity home exists already: what a dispatch the hub
// makes by itself acting for them — a resume, a failover — uses. It never makes
// the identity home, which offboarding removes and which is their Claude login
// home too: making it here would hand the next automatic Claude dispatch an
// empty login where it should find none.
func HomeIfKnown(ownerKey string) (string, error) {
	if strings.TrimSpace(ownerKey) == "" {
		return "", ErrNoIdentity
	}
	base, err := claudecodeauth.HomePath(ownerKey)
	if err != nil {
		return "", err
	}
	if fi, err := os.Lstat(base); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%w (%s)", ErrUnknown, base)
	}
	return ensureDir(filepath.Join(base, homeDirName))
}

// UnattributedHome returns the Copilot home of dispatches that act for no one,
// creating it 0700 if absent.
func UnattributedHome() (string, error) {
	root, err := claudecodeauth.HomeRoot()
	if err != nil {
		return "", err
	}
	return ensureDir(filepath.Join(root, unattributedDirName))
}

// ensureDir makes dir a private directory, refusing a symbolic link where it
// belongs: the hub did not make it, and whatever it points at — another
// person's home, the hub user's own ~/.copilot — is not this person's.
func ensureDir(dir string) (string, error) {
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("copilotauth: %s is a symbolic link, not a Copilot home this hub made", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create Copilot home %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("restrict Copilot home %s: %w", dir, err)
	}
	return dir, nil
}

// Own reports whether key is one of the Copilot CLI's own variables: every
// COPILOT_* and GITHUB_COPILOT_* variable. The CLI reads tokens, an API URL, a
// provider and a command that prints a key from them, and no other program
// reads them at all.
func Own(key string) bool {
	return strings.HasPrefix(key, "COPILOT_") || strings.HasPrefix(key, "GITHUB_COPILOT_")
}

// Ambient reports whether key is a variable through which the Copilot CLI could
// sign in, or be sent somewhere to, other than with the credential a person's
// run is given: its own variables (Own), and GitHub's tokens and the host the
// CLI sends them to.
func Ambient(key string) bool {
	switch key {
	case "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN":
		return true
	}
	return Own(key)
}

// CredentialVars are the variables a run's own Copilot credential arrives in,
// from its lease: a GitHub token for a Copilot seat, or a model provider of the
// project's own (bring your own key) with what travels beside its URL. They are
// the only Ambient variables the CLI gets in the per-person mode. Not
// COPILOT_PROVIDER_API_KEY_COMMAND, which runs a command, nor
// COPILOT_PROVIDER_GHES_HOST, COPILOT_GH_HOST or COPILOT_API_URL, which say
// where to send a credential.
var CredentialVars = []string{
	"COPILOT_GITHUB_TOKEN",
	"COPILOT_PROVIDER_BASE_URL",
	"COPILOT_PROVIDER_API_KEY",
	"COPILOT_PROVIDER_BEARER_TOKEN",
	"COPILOT_PROVIDER_TYPE",
	"COPILOT_PROVIDER_MODEL_ID",
	"COPILOT_PROVIDER_WIRE_API",
	"COPILOT_PROVIDER_WIRE_MODEL",
	"COPILOT_PROVIDER_AZURE_API_VERSION",
	"COPILOT_PROVIDER_MAX_PROMPT_TOKENS",
	"COPILOT_PROVIDER_MAX_OUTPUT_TOKENS",
	"COPILOT_PROVIDER_TRANSPORT",
	"COPILOT_PROVIDER_HEADERS",
	"COPILOT_OFFLINE",
}

// signInVars are the credential variables that sign the CLI in on their own:
// a token for a seat, or a provider's URL. The rest only qualify one of them.
var signInVars = []string{"COPILOT_GITHUB_TOKEN", "COPILOT_PROVIDER_BASE_URL"}

// HubBlanks returns, for env — the environment a dispatch acting for a person
// on the hub's host inherits, which is the hub's own — an empty assignment of
// every one of the Copilot CLI's own variables (Own) set in it. Appended to env
// before the lease, they leave only what the lease delivers: exec keeps the
// last assignment of a key, and the CLI reads an empty one as unset. The GitHub
// variables are not blanked here — other tools of the run read them — and
// ChildEnv removes them from the CLI's environment instead.
func HubBlanks(env []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || seen[k] || !Own(k) {
			continue
		}
		seen[k] = true
		out = append(out, k+"=")
	}
	return out
}

// Pin is the assignment that pins a run to home: appended after everything
// else the dispatch puts in its environment, the lease's grants included.
func Pin(home string) string { return EnvHome + "=" + home }

// ChildEnv builds the Copilot CLI's environment from defaults (the provider's
// own), inherited (its process's) and explicit (what the caller adds for one
// call), in that order, exec keeping the last assignment of a key. pinned
// reports whether the result names a person's home (EnvHome): then the CLI gets
// that home as COPILOT_HOME, a GitHub CLI configuration inside it, the
// non-empty CredentialVars, and no other Ambient variable at all. Otherwise the
// layers are returned as they are.
func ChildEnv(defaults, inherited, explicit []string) (env []string, pinned bool) {
	all := make([]string, 0, len(defaults)+len(inherited)+len(explicit))
	all = append(append(append(all, defaults...), inherited...), explicit...)
	last := lastValues(all)
	home := strings.TrimSpace(last[EnvHome])
	if home == "" {
		return all, false
	}
	out := make([]string, 0, len(all)+len(CredentialVars)+3)
	for _, kv := range all {
		k, _, _ := strings.Cut(kv, "=")
		if k == EnvHome || k == "GH_CONFIG_DIR" || Ambient(k) {
			continue
		}
		out = append(out, kv)
	}
	for _, k := range CredentialVars {
		if v := last[k]; strings.TrimSpace(v) != "" {
			out = append(out, k+"="+v)
		}
	}
	out = append(out,
		"COPILOT_HOME="+home,
		"GH_CONFIG_DIR="+filepath.Join(home, ghConfigDirName),
		// The provider's default, which the loop above dropped with the
		// rest of COPILOT_*: a pinned run installs no newer CLI either.
		"COPILOT_AUTO_UPDATE=false",
	)
	return out, true
}

// HasCredential reports whether env signs the CLI in on its own: a non-empty
// token for a seat, or a model provider's URL.
func HasCredential(env []string) bool {
	last := lastValues(env)
	for _, k := range signInVars {
		if strings.TrimSpace(last[k]) != "" {
			return true
		}
	}
	return false
}

// HomeOf returns the Copilot home env pins its CLI to, or "".
func HomeOf(env []string) string {
	return strings.TrimSpace(lastValues(env)[EnvHome])
}

// lastValues maps each key in env to the value its last assignment gives it.
func lastValues(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}
