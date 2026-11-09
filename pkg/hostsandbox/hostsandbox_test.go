package hostsandbox

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	InstallTestHelper()
	if len(os.Args) == 4 && os.Args[1] == byHandleArg {
		// Started inside a sandbox by TestAFileOutsideTheGrantsCannotBeOpenedByItsHandle,
		// by its arguments rather than its environment, which the sandbox
		// filters: this binary must never reach m.Run there.
		os.Exit(openByHandle(os.Args[2], os.Args[3]))
	}
	os.Exit(m.Run())
}

// byHandleArg makes this test binary try to open a file by its handle.
const byHandleArg = "__hostsandbox-test-by-handle"

func TestPolicyRoundTripsThroughItsEnvironmentValue(t *testing.T) {
	p := Policy{
		Argv:       []string{"cloop", "run"},
		Dir:        "/srv/projects/a",
		ReadWrite:  []string{"/srv/projects/a"},
		ReadOnly:   []string{"/usr"},
		Devices:    []string{"/dev/null"},
		Namespaces: true,
		Tmp:        "/tmp/cloop-sandbox-1/tmp",
	}
	enc, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("round trip changed the policy:\n got %+v\nwant %+v", got, p)
	}
}

func TestValidateRefusesWhatTheHelperCouldNotHonour(t *testing.T) {
	for name, p := range map[string]Policy{
		"no program":         {},
		"relative grant":     {Argv: []string{"x"}, ReadWrite: []string{"proj"}},
		"relative read":      {Argv: []string{"x"}, ReadOnly: []string{"usr"}},
		"relative directory": {Argv: []string{"x"}, Dir: "proj"},
		"relative temporary": {Argv: []string{"x"}, Tmp: "tmp"},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, p)
		}
	}
}

func TestIsInvocationIsExact(t *testing.T) {
	if !IsInvocation([]string{"/usr/local/bin/cloop", Arg}) {
		t.Fatal("the helper invocation was not recognised")
	}
	for _, args := range [][]string{
		{"cloop"}, {"cloop", "run"}, {"cloop", Arg, "run"}, {"cloop", "run", Arg},
	} {
		if IsInvocation(args) {
			t.Errorf("IsInvocation(%q) = true", args)
		}
	}
}

func TestHubCredentialsAreScrubbedUnlessALeaseDeliveredThem(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"CLOOP_SECRET_KEY=root-of-every-secret",
		"CLOOP_SECRET_KEY_PREVIOUS=older-root",
		"CLOOP_SECRET_KEY_FILE=/etc/cloop/key",
		"CREDENTIALS_DIRECTORY=/run/credentials/cloop.service",
		"CLOOP_UI_TOKEN=static-admin",
		"CLOOP_NOTIFY_SLACK=https://hooks.example/abc",
		"CLOOP_TASK_ID=7",
		"GITHUB_TOKEN=from-a-lease",
	}
	got := WithoutHubCredentials(env, map[string]bool{"CLOOP_UI_TOKEN": true})
	want := []string{"PATH=/usr/bin", "CLOOP_UI_TOKEN=static-admin", "CLOOP_TASK_ID=7", "GITHUB_TOKEN=from-a-lease"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WithoutHubCredentials:\n got %q\nwant %q", got, want)
	}
}

func TestEnvironmentLeavesTheHubUsersHomeAndSessionBehind(t *testing.T) {
	env := []string{
		"PATH=/root/.local/bin:/usr/bin",
		"HOME=/root",
		"TMPDIR=/tmp",
		"GOPATH=/root/go",
		"GOFLAGS=-mod=mod",
		"NPM_CONFIG_PREFIX=/opt/npm:/root/.npm-global",
		"SSH_AUTH_SOCK=/tmp/ssh-x/agent.1",
		"XDG_CONFIG_HOME=/root/.config",
		"DOCKER_HOST=unix:///run/docker.sock",
		"LANG=C.UTF-8",
		"ROOTED=/rootfs/keep",
		"CLAUDE_CONFIG_DIR=/root/.config/cloop/claude-identities/alice",
		"CLOOP_OTHER_HOME=/root/.config/cloop/claude-identities/bob",
		EnvPolicy + "=stale",
	}
	got := Environment(env, "/srv/homes/alice", "/tmp/cloop-sandbox-1/tmp", "/root",
		[]string{"/root/.config/cloop/claude-identities/alice"})
	want := []string{
		"PATH=/root/.local/bin:/usr/bin",
		"GOFLAGS=-mod=mod",
		"LANG=C.UTF-8",
		"ROOTED=/rootfs/keep",
		"CLAUDE_CONFIG_DIR=/root/.config/cloop/claude-identities/alice",
		"HOME=/srv/homes/alice",
		"TMPDIR=/tmp/cloop-sandbox-1/tmp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Environment:\n got %q\nwant %q", got, want)
	}
}

func TestEtcAllowListLeavesOutTheHostsSecrets(t *testing.T) {
	for _, secret := range []string{
		"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh", "/etc/ssl/private",
		"/etc/credstore", "/etc/systemd", "/etc/letsencrypt", "/etc/cloop", "/etc",
	} {
		for _, granted := range append(append([]string{}, EtcReadOnly...), SystemReadOnly...) {
			if granted == secret || strings.HasPrefix(secret+"/", granted+"/") {
				t.Errorf("%s is granted to every sandboxed workload by %s", secret, granted)
			}
		}
	}
}

func TestOnlyHarmlessSettingsAreInheritedByDefault(t *testing.T) {
	for _, name := range []string{"PATH", "LANG", "LC_ALL", "HTTPS_PROXY", "no_proxy", "SSL_CERT_FILE",
		"GOPROXY", "GOFLAGS", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK", "DISABLE_TELEMETRY"} {
		if !Inheritable(name) {
			t.Errorf("%s is not inherited", name)
		}
	}
	for _, name := range []string{"OPENAI_API_KEY", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "SLACK_WEBHOOK_URL",
		"DATABASE_URL", "AWS_SECRET_ACCESS_KEY", "NPM_TOKEN", "KUBECONFIG", "CLOOP_SECRET_KEY", "GROQ_API_KEY",
		"VAULT_ADDR", "PGPASSWORD", "SOME_DEPLOY_KEY"} {
		if Inheritable(name) {
			t.Errorf("%s is inherited", name)
		}
	}
}
