package copilotauth

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
)

// The hub's own environment, as a service holding Copilot and GitHub
// credentials for something else would have it.
var hubEnv = []string{
	"PATH=/usr/bin",
	"HOME=/root",
	"COPILOT_GITHUB_TOKEN=host-copilot-token",
	"GH_TOKEN=host-gh-token",
	"GITHUB_TOKEN=host-github-token",
	"GH_HOST=ghe.example.com",
	"GH_ENTERPRISE_TOKEN=host-ghe-token",
	"GITHUB_ENTERPRISE_TOKEN=host-ghe-token-2",
	"COPILOT_API_URL=https://collector.example.com",
	"COPILOT_PROVIDER_API_KEY_COMMAND=cat /root/.secret",
	"COPILOT_HOME=/root/.copilot",
	"GITHUB_COPILOT_GITHUB_TOKEN=host-agent-token",
	"GH_CONFIG_DIR=/root/.config/gh",
	"GITHUB_TOKEN=host-github-token",
}

func values(env []string) map[string]string { return lastValues(env) }

func TestHomesNestInTheIdentityHome(t *testing.T) {
	const who = "alice@example.com"
	path, err := HomePath(who)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("HomePath created %s (stat: %v); looking must leave no trace", path, err)
	}
	home, err := HomeFor(who)
	if err != nil {
		t.Fatal(err)
	}
	if home != path {
		t.Errorf("HomeFor = %s, HomePath = %s", home, path)
	}
	identity, err := claudecodeauth.HomePath(who)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(home) != identity {
		t.Errorf("the Copilot home %s is not inside the identity home %s, which offboarding removes", home, identity)
	}
	fi, err := os.Stat(home)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the Copilot home is %v (%v), want a 0700 directory", fi, err)
	}

	// Removing the identity home — what an offboarding and the denied
	// identities' sweep do — removes the Copilot home with it.
	if err := claudecodeauth.ForgetHome(who); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("the Copilot home survived its identity home's removal: %v", err)
	}

	other, err := HomeFor("bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if other == home {
		t.Error("two people got one Copilot home")
	}
	if _, err := HomeFor(" "); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("HomeFor(blank) = %v, want ErrNoIdentity", err)
	}
	if _, err := HomePath(""); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("HomePath(\"\") = %v, want ErrNoIdentity", err)
	}
	nobody, err := UnattributedHome()
	if err != nil {
		t.Fatal(err)
	}
	if nobody == home || nobody == other || strings.HasPrefix(nobody, filepath.Dir(other)) {
		t.Errorf("the unattributed home %s is a person's", nobody)
	}
}

// A symbolic link where a home belongs is refused, not followed into whatever
// it names.
func TestASymlinkedHomeIsRefused(t *testing.T) {
	const who = "mallory@example.com"
	identity, err := claudecodeauth.HomeFor(who)
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(identity, homeDirName)); err != nil {
		t.Fatal(err)
	}
	if home, err := HomeFor(who); err == nil {
		t.Fatalf("HomeFor followed a symbolic link to %s", home)
	}
}

func TestHubBlanksEveryCopilotVariableTheHubHolds(t *testing.T) {
	blanks := HubBlanks(hubEnv)
	for _, kv := range blanks {
		if !strings.HasSuffix(kv, "=") {
			t.Errorf("HubBlanks carries a value: %q", kv)
		}
	}
	got := values(append(append([]string{}, hubEnv...), blanks...))
	for _, k := range []string{"COPILOT_GITHUB_TOKEN", "COPILOT_API_URL", "COPILOT_PROVIDER_API_KEY_COMMAND",
		"COPILOT_HOME", "GITHUB_COPILOT_GITHUB_TOKEN"} {
		if got[k] != "" {
			t.Errorf("after the blanks %s = %q, want it empty", k, got[k])
		}
	}
	// What other tools of the run read is theirs: the GitHub tokens and host
	// stay, and ChildEnv takes them from the Copilot CLI alone.
	for k, want := range map[string]string{"PATH": "/usr/bin", "HOME": "/root", "GH_TOKEN": "host-gh-token",
		"GITHUB_TOKEN": "host-github-token", "GH_HOST": "ghe.example.com", "GH_CONFIG_DIR": "/root/.config/gh"} {
		if got[k] != want {
			t.Errorf("HubBlanks touched %s: %q", k, got[k])
		}
	}
	if HubBlanks([]string{"PATH=/bin", "GH_TOKEN=x"}) != nil {
		t.Error("an environment with no Copilot variable got blanks")
	}
	twice := HubBlanks([]string{"COPILOT_MODEL=a", "COPILOT_MODEL=b"})
	if len(twice) != 1 || twice[0] != "COPILOT_MODEL=" {
		t.Errorf("a variable set twice was blanked as %v; want once", twice)
	}
}

// What a `cloop run` the hub dispatched for a person inherits: the hub's
// environment, the blanks, the lease's grants — the person's own token, and a
// repository grant's GitHub token — and the pin.
func runEnv(home string) []string {
	env := append([]string{}, hubEnv...)
	env = append(env, HubBlanks(hubEnv)...)
	env = append(env, "COPILOT_GITHUB_TOKEN=alice-token", "GH_TOKEN=repo-grant-token", "GITHUB_TOKEN=repo-grant-token")
	return append(env, Pin(home))
}

func TestChildEnvPinsThePersonsHomeAndCredential(t *testing.T) {
	home := "/hub/identities/alice/copilot"
	env, pinned := ChildEnv([]string{"COPILOT_AUTO_UPDATE=false", "NO_COLOR=1"}, runEnv(home),
		[]string{"GIT_CONFIG_COUNT=1"})
	if !pinned {
		t.Fatal("a run naming a home was not pinned")
	}
	got := values(env)
	want := map[string]string{
		"COPILOT_GITHUB_TOKEN": "alice-token",
		"COPILOT_HOME":         home,
		"GH_CONFIG_DIR":        filepath.Join(home, "gh"),
		"COPILOT_AUTO_UPDATE":  "false",
		"NO_COLOR":             "1",
		"PATH":                 "/usr/bin",
		"GIT_CONFIG_COUNT":     "1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
		"COPILOT_API_URL", "COPILOT_PROVIDER_API_KEY_COMMAND", "GITHUB_COPILOT_GITHUB_TOKEN", EnvHome} {
		if _, ok := got[k]; ok {
			t.Errorf("the pinned CLI inherits %s=%q", k, got[k])
		}
	}
	// Removed, not merely overridden: no assignment of a stripped key is left
	// for a reader that takes the first.
	for _, kv := range env {
		for _, bad := range []string{"host-", "repo-grant-token", "/root/.copilot", "/root/.config/gh"} {
			if strings.Contains(kv, bad) {
				t.Errorf("the pinned CLI's environment carries %q", kv)
			}
		}
	}
	if !HasCredential(env) {
		t.Error("HasCredential = false for the person's token")
	}
}

// The model call the hub makes in its own process passes the person's
// environment as the call's own, over the hub's.
func TestChildEnvPinsAnInlineCall(t *testing.T) {
	home := "/hub/identities/bob/copilot"
	explicit := append(HubBlanks(hubEnv), "COPILOT_PROVIDER_BASE_URL=https://models.example.com/v1",
		"COPILOT_PROVIDER_API_KEY=bob-key", "COPILOT_OFFLINE=true", Pin(home))
	env, pinned := ChildEnv(nil, hubEnv, explicit)
	if !pinned {
		t.Fatal("not pinned")
	}
	got := values(env)
	if got["COPILOT_PROVIDER_API_KEY"] != "bob-key" || got["COPILOT_OFFLINE"] != "true" ||
		got["COPILOT_PROVIDER_BASE_URL"] != "https://models.example.com/v1" {
		t.Errorf("bob's own provider did not reach the CLI: %v", got)
	}
	if _, ok := got["COPILOT_GITHUB_TOKEN"]; ok {
		t.Errorf("the hub's COPILOT_GITHUB_TOKEN reached bob's call: %q", got["COPILOT_GITHUB_TOKEN"])
	}
	if got["COPILOT_HOME"] != home {
		t.Errorf("COPILOT_HOME = %q", got["COPILOT_HOME"])
	}
	if !HasCredential(env) {
		t.Error("a provider's URL is a credential of its own")
	}
}

// The pin is the last word: a grant that names a home — another person's —
// comes before it and loses.
func TestThePinOutranksAGrantNamingAHome(t *testing.T) {
	env := append(append([]string{}, hubEnv...), EnvHome+"=/hub/identities/victim/copilot",
		"COPILOT_GITHUB_TOKEN=mallory-token", Pin("/hub/identities/mallory/copilot"))
	got, _ := ChildEnv(nil, env, nil)
	if v := values(got)["COPILOT_HOME"]; v != "/hub/identities/mallory/copilot" {
		t.Errorf("COPILOT_HOME = %q, want mallory's own", v)
	}
}

func TestNoCredentialLeftIsNoCredential(t *testing.T) {
	env := append(append([]string{}, hubEnv...), HubBlanks(hubEnv)...)
	env = append(env, Pin("/hub/identities/carol/copilot"))
	got, pinned := ChildEnv(nil, env, nil)
	if !pinned || HasCredential(got) {
		t.Errorf("pinned %v, credential %v: a person with no grant has no credential, not the hub's", pinned,
			HasCredential(got))
	}
	for _, kv := range got {
		if k, _, _ := strings.Cut(kv, "="); slices.Contains(CredentialVars, k) {
			t.Errorf("an empty credential was passed on: %q", kv)
		}
	}
}

// Without a pin nothing changes: the layers in order, the last word winning.
func TestChildEnvWithoutAPinIsTheLayers(t *testing.T) {
	env, pinned := ChildEnv([]string{"COPILOT_AUTO_UPDATE=false"}, hubEnv, []string{"CLOOP_HOLD=1"})
	if pinned {
		t.Fatal("pinned without a home")
	}
	want := append(append([]string{"COPILOT_AUTO_UPDATE=false"}, hubEnv...), "CLOOP_HOLD=1")
	if !slices.Equal(env, want) {
		t.Errorf("ChildEnv rewrote an unpinned environment:\n got %v\nwant %v", env, want)
	}
	if HomeOf(env) != "" || HomeOf(append(env, Pin(" /x "))) != "/x" {
		t.Error("HomeOf misread the pin")
	}
}

func TestOwnAndAmbient(t *testing.T) {
	for k, want := range map[string]bool{
		"COPILOT_GITHUB_TOKEN": true, "GITHUB_COPILOT_AGENT_GITHUB_TOKEN": true, "GH_TOKEN": false,
		"GITHUB_TOKEN": false, "GH_HOST": false, "PATH": false, EnvHome: false,
	} {
		if Own(k) != want {
			t.Errorf("Own(%s) = %v, want %v", k, !want, want)
		}
	}

	for k, want := range map[string]bool{
		"COPILOT_GITHUB_TOKEN": true, "COPILOT_HOME": true, "COPILOT_MODEL": true, "GH_TOKEN": true,
		"GITHUB_TOKEN": true, "GH_HOST": true, "GITHUB_COPILOT_AGENT_GITHUB_TOKEN": true,
		"PATH": false, "HOME": false, "GH_CONFIG_DIR": false, "GITHUB_ACTIONS": false, EnvHome: false,
	} {
		if Ambient(k) != want {
			t.Errorf("Ambient(%s) = %v, want %v", k, !want, want)
		}
	}
	for _, k := range CredentialVars {
		if !Own(k) {
			t.Errorf("credential variable %s is not one of the CLI's own, so the hub would not blank its own", k)
		}
	}
}
