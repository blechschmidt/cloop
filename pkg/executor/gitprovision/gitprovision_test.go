// Tests for the half of the credential circuit that carries a leased token
// *into* a sandbox.
//
// The package had no test file at all, which is the wrong state for the code
// that decides whether a brokered GitHub credential ends up in a log, on a
// disk, or in the hands of a host the grant never covered. A leak here is
// invisible until it matters: the fetch still works, the transcript still looks
// right, and the token is simply also somewhere else.
//
// So almost nothing here is asserted by reading a string. The remote is a real
// git-http-backend over real TLS on loopback (see pkg/executor/internal/
// gitforge), the client is the real git binary, and the questions are asked of
// artefacts rather than of intentions:
//
//   - did the forge receive a request at all, or was the refusal made before
//     the network — the difference between a policy that holds and one that
//     relies on the remote saying no;
//   - does any byte of the credential appear in the returned error, the emitted
//     log, or any file under the workspace or the home directory — asked
//     through pkg/redact, so a test agrees with the production redactor about
//     what a match is;
//   - did a setting from the host's environment reach git — asked by putting a
//     hostile value in the environment and observing that the fetch behaves as
//     though it were not there.
package gitprovision_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// The fixture repository. The owner/name shape is load-bearing: that is what
// executor.Workspace.RepoPath matches a grant's allowlist against.
const (
	owner = "acme"
	repo  = "tool"

	// The leased credential. It must be longer than redact.MinLen or the
	// redactor would decline to match it and every leak assertion here would
	// pass for the wrong reason — gitforge.NoSecretIn fails loudly on an empty
	// Set precisely so that cannot happen quietly.
	credUser  = "x-access-token"
	credToken = "cloop-test-lease-DO-NOT-LOG-7Kq2Vx9m"
)

// --- fixture -----------------------------------------------------------------

type fixture struct {
	t     *testing.T
	forge *gitforge.Forge
	// dir is the provisioning target.
	dir string
	// home is an isolated HOME for fixture git, and a second place a leaked
	// credential would plausibly land.
	home string
	ws   executor.Workspace
	cred executor.GitCredential
	// set is the production redactor over this fixture's credential.
	set *redact.Set

	emitted strings.Builder
}

// newFixture brings up a forge holding one seeded repository and a workspace
// pointed at it, with the forge's CA trusted through the one host setting
// gitprovision forwards.
func newFixture(t *testing.T, opt gitforge.Options) *fixture {
	t.Helper()
	if opt.User == "" && opt.Password == "" {
		opt.User, opt.Password = credUser, credToken
	}
	f := &fixture{
		t:     t,
		forge: gitforge.Start(t, opt),
		dir:   filepath.Join(t.TempDir(), "workspace"),
		home:  t.TempDir(),
	}
	f.forge.Create(t, owner, repo)
	f.forge.Trust(t)

	f.ws = executor.Workspace{
		Kind:  executor.WorkspaceGit,
		Repo:  f.forge.RepoURL(owner, repo),
		Ref:   gitforge.DefaultBranch,
		Depth: 1,
	}
	f.cred = executor.GitCredential{Username: credUser, Password: credToken}
	f.set = redact.New(f.cred.Secrets()...)
	return f
}

// request builds the Request under test, capturing everything emitted.
func (f *fixture) request() gitprovision.Request {
	return gitprovision.Request{
		Dir:        f.dir,
		Workspace:  f.ws,
		Credential: f.cred,
		Host:       "this test executor",
		Emit:       func(s string) { f.emitted.WriteString(s) },
	}
}

func (f *fixture) provision() error {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return gitprovision.Provision(ctx, f.request())
}

// log is everything Emit received, for a failure message.
func (f *fixture) log() string { return f.emitted.String() }

// assertNoLeak runs every leak assertion this package can make against one
// provisioning: the error, the emitted log, the workspace tree and the home
// directory. It returns how many files the on-disk scan actually read.
//
// It is one helper rather than four call sites per test because the whole point
// is that these four surfaces are checked *together* — a change that moves a
// credential from the error message into a dotfile has not fixed anything, and
// a test that only looked at the error would call it fixed.
//
// The count is returned rather than asserted here because a zero is only a
// problem for the test whose claim is about the disk: after a rollback the
// workspace is legitimately empty, and failing every such test for scanning
// nothing would be noise. TestProvisionCredentialNeverReachesDisk makes the
// non-vacuity assertion where it means something.
func (f *fixture) assertNoLeak(err error) int {
	f.t.Helper()
	if err != nil {
		gitforge.NoSecretIn(f.t, f.set, "the returned error", err.Error())
	}
	gitforge.NoSecretIn(f.t, f.set, "the emitted log", f.log())
	return gitforge.NoSecretUnder(f.t, f.set, f.dir) +
		gitforge.NoSecretUnder(f.t, f.set, f.home)
}

// --- the happy path -----------------------------------------------------------

func TestProvisionClonesTheRepositoryAndAuthenticates(t *testing.T) {
	f := newFixture(t, gitforge.Options{})

	if err := f.provision(); err != nil {
		t.Fatalf("Provision: %v\nlog:\n%s", err, f.log())
	}

	// The tree is real, not merely a .git directory.
	if b, err := os.ReadFile(filepath.Join(f.dir, "README.md")); err != nil {
		t.Fatalf("the provisioned tree has no README.md: %v", err)
	} else if string(b) != "seed\n" {
		t.Errorf("README.md = %q, want the seeded content", b)
	}

	// The forge is the witness that the credential was actually used: it
	// refuses anonymous requests, so a served fetch is an authenticated one.
	reqs := f.forge.Requests()
	if len(reqs) == 0 {
		t.Fatal("the forge received no requests, so nothing was fetched over the network")
	}
	for _, r := range reqs {
		if !r.Authorized {
			t.Errorf("the forge refused %s %s; the credential did not reach it", r.Method, r.Path)
		}
	}

	f.assertNoLeak(nil)
}

// --- the credential never escapes ---------------------------------------------

// TestProvisionCredentialNeverEscapesOnFailure is the assertion the package's
// own doc comment makes: every error has already been through
// executor.RedactSecrets.
//
// The failure modes are chosen because each makes git say something different
// about the request it made, and git is perfectly willing to quote a URL or a
// header back. A redaction that only covered one message shape would pass a
// single-case test.
func TestProvisionCredentialNeverEscapesOnFailure(t *testing.T) {
	cases := map[string]struct {
		opt  gitforge.Options
		warp func(*fixture)
	}{
		"the credential is wrong": {
			opt: gitforge.Options{User: credUser, Password: "a-different-secret-entirely"},
		},
		"the repository does not exist": {
			warp: func(f *fixture) { f.ws.Repo = f.forge.RepoURL(owner, "no-such-repo") },
		},
		"the ref does not exist": {
			warp: func(f *fixture) { f.ws.Ref = "refs/heads/branch-that-was-never-pushed" },
		},
		"the forge is broken": {
			opt: gitforge.Options{
				User: credUser, Password: credToken,
				Intercept: func(w http.ResponseWriter, _ *http.Request) bool {
					http.Error(w, "forge exploded", http.StatusInternalServerError)
					return true
				},
			},
		},
		"the host is unreachable": {
			warp: func(f *fixture) {
				// Port 1 on loopback: refused immediately, no timeout.
				f.ws.Repo = "https://127.0.0.1:1/" + owner + "/" + repo + ".git"
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.opt)
			if tc.warp != nil {
				tc.warp(f)
			}

			err := f.provision()
			if err == nil {
				t.Fatalf("Provision succeeded, but this case is supposed to fail\nlog:\n%s", f.log())
			}
			if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
				t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
			}
			f.assertNoLeak(err)
		})
	}
}

// TestProvisionCredentialNeverReachesDisk checks the surface a log scrub cannot
// cover.
//
// The credential travels as a URL-scoped http.extraHeader in the environment of
// one child process, which is the only delivery path that writes nothing. This
// test is what keeps it that way: a future change to a credential helper file,
// an askpass script or a `git config` entry would satisfy every other test in
// this file and fail this one — on the success path *and* the failure path,
// because a helper that is written and then removed only on success is a helper
// that is left behind exactly when something already went wrong.
func TestProvisionCredentialNeverReachesDisk(t *testing.T) {
	t.Run("on the success path", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		if err := f.provision(); err != nil {
			t.Fatalf("Provision: %v\nlog:\n%s", err, f.log())
		}
		if n := f.assertNoLeak(nil); n == 0 {
			t.Fatal("the on-disk scan read no files, so it proves nothing")
		}
		assertNoCredentialConfig(t, f)
	})

	t.Run("on the failure path", func(t *testing.T) {
		// Authentication succeeds, so the credential is genuinely in play, and
		// then the checkout fails on a ref the remote does not have. That order
		// matters: a case that fails before the authenticated step would never
		// have had a credential to leave behind.
		//
		// The workspace is pre-seeded with a file so rollback leaves the
		// directory in place: rollback only empties a directory it found empty,
		// and a scan of nothing would pass for the wrong reason.
		f := newFixture(t, gitforge.Options{})
		f.ws.Ref = "refs/heads/never-pushed"
		gitforge.WriteFile(t, f.dir, "pre-existing.txt", "not ours to delete\n")

		err := f.provision()
		if err == nil {
			t.Fatalf("Provision succeeded against a missing ref\nlog:\n%s", f.log())
		}
		if n := f.assertNoLeak(err); n == 0 {
			t.Fatal("the on-disk scan read no files, so it proves nothing")
		}
	})
}

// assertNoCredentialConfig asks git itself whether the provisioned repository
// carries any of the settings a credential would be stored in.
//
// Scanning the file for the token catches the token; asking git catches the
// shape — a credential.helper that names an external program, an extraHeader
// with a value git would resolve later. Both are leaks; only one is a string
// match.
func assertNoCredentialConfig(t *testing.T, f *fixture) {
	t.Helper()
	tools := gitforge.RequireGit(t)
	out, _ := gitforge.TryGit(t, tools, f.home, f.dir,
		"-C", f.dir, "config", "--local", "--get-regexp", `^(http\.|credential\.)`)
	if strings.TrimSpace(out) != "" {
		t.Errorf("the provisioned repository carries credential-shaped local config:\n%s", out)
	}
}

// TestProvisionCredentialNeverFollowsARedirect is a regression test for a
// credential disclosure.
//
// executor.Workspace.BaseURL scopes the Authorization header to the
// repository's own origin, and its doc comment claimed that scoping meant "a
// repository that redirects elsewhere gets a fetch failure rather than a leaked
// Authorization header". Measured against a real git client, it meant neither.
//
// git's default http.followRedirects is "initial": it follows a redirect on the
// first request and *re-bases the remote URL to the new host*. The redirected
// info/refs arrives at the third party with no Authorization header — which is
// what makes the bug so easy to miss — and then every subsequent
// git-upload-pack POST goes to the third party carrying the extraHeader that
// was resolved for the original origin. The fetch succeeds. A brokered
// credential is handed to a host the grant never covered, and nothing anywhere
// records that it happened.
//
// The fix is executor.baseGitConfig's http.followRedirects=false, which turns
// the disclosure into the loud failure the comment always described.
func TestProvisionCredentialNeverFollowsARedirect(t *testing.T) {
	// The third party. It accepts anonymous requests, so anything it receives,
	// it receives because the client chose to send it.
	elsewhere := gitforge.Start(t, gitforge.Options{})
	elsewhere.Create(t, owner, repo)

	f := newFixture(t, gitforge.Options{
		User: credUser, Password: credToken,
		Intercept: func(w http.ResponseWriter, r *http.Request) bool {
			// Only the initial request, which is the one git's default would
			// have followed — and the one that re-bases everything after it.
			if !strings.HasSuffix(r.URL.Path, "/info/refs") {
				return false
			}
			http.Redirect(w, r, elsewhere.URL()+r.URL.Path+queryOf(r), http.StatusMovedPermanently)
			return true
		},
	})
	// Both certificates are trusted, so a fetch that fails here fails because
	// of the redirect policy and not because of TLS.
	trustBoth(t, f.forge.CAFile(), elsewhere.CAFile())

	err := f.provision()
	if err == nil {
		t.Fatalf("Provision followed a redirect to a host the grant does not cover\nlog:\n%s",
			f.log())
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
	}

	// Nothing at all should reach the third party. Asserting only "no
	// Authorization header arrived" would be the weaker claim, and it is the
	// one that passed while the credential was leaking on the *next* request.
	if saw := elsewhere.Requests(); len(saw) != 0 {
		for _, r := range saw {
			t.Errorf("the third-party host received %s %s (auth=%q); the fetch was redirected "+
				"to a host the grant does not cover", r.Method, r.Path, r.Authorization)
		}
	}
	f.assertNoLeak(err)
}

func queryOf(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

// trustBoth concatenates two CA files into one bundle and points
// GIT_SSL_CAINFO at it, because git takes a single path.
func trustBoth(t *testing.T, a, b string) {
	t.Helper()
	var bundle []byte
	for _, p := range []string{a, b} {
		pemBytes, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		bundle = append(bundle, pemBytes...)
	}
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("writing the CA bundle: %v", err)
	}
	t.Setenv("GIT_SSL_CAINFO", path)
}

// --- the environment handed to git is closed ----------------------------------

// TestProvisionDoesNotInheritTheHostEnvironment puts each hostile setting in
// the process environment and asserts the fetch behaves as though it were not
// there.
//
// This is the only way to test executor.GitBaseEnv that is not a restatement of
// it. An assertion that the slice contains "GIT_CONFIG_GLOBAL=/dev/null" proves
// the constant has not changed; an assertion that a ~/.gitconfig with an
// insteadOf rewrite does not divert the fetch proves the machine cannot
// influence it.
func TestProvisionDoesNotInheritTheHostEnvironment(t *testing.T) {
	t.Run("GIT_SSL_NO_VERIFY is not on the transport allowlist", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		// Withdraw the one legitimate way to trust the forge, and offer the
		// illegitimate one in its place. If GIT_SSL_NO_VERIFY were forwarded,
		// the fetch would succeed.
		t.Setenv("GIT_SSL_CAINFO", "")
		t.Setenv("GIT_SSL_NO_VERIFY", "true")

		if err := f.provision(); err == nil {
			t.Fatalf("Provision succeeded against an untrusted certificate: GIT_SSL_NO_VERIFY "+
				"reached git, which would hand a brokered token to whoever answers the "+
				"port\nlog:\n%s", f.log())
		}
		if n := f.forge.Count(); n != 0 {
			t.Errorf("the forge served %d request(s) despite an untrusted certificate: %s",
				n, f.forge.Log())
		}
	})

	t.Run("GIT_SSL_CAINFO is on it", func(t *testing.T) {
		// The positive control for the case above. Without it, that test would
		// also pass if the fetch were broken for some unrelated reason.
		f := newFixture(t, gitforge.Options{})
		if err := f.provision(); err != nil {
			t.Fatalf("Provision: %v\nlog:\n%s", err, f.log())
		}
	})

	t.Run("an ambient GIT_CONFIG_* injection is ignored", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		// git's own config-through-environment protocol, pointed at a rewrite
		// that would divert every https fetch to a dead port. It is inherited
		// by any child that does not set GIT_CONFIG_COUNT itself.
		t.Setenv("GIT_CONFIG_COUNT", "1")
		t.Setenv("GIT_CONFIG_KEY_0", "url.https://127.0.0.1:1/.insteadOf")
		t.Setenv("GIT_CONFIG_VALUE_0", "https://")

		if err := f.provision(); err != nil {
			t.Fatalf("an ambient GIT_CONFIG_COUNT diverted the fetch: %v\nlog:\n%s", err, f.log())
		}
		if f.forge.Count() == 0 {
			t.Error("the forge received nothing; the fetch went somewhere else")
		}
	})

	t.Run("a hostile HOME and gitconfig are unreachable", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		hostile := t.TempDir()
		if err := os.WriteFile(filepath.Join(hostile, ".gitconfig"),
			[]byte("[url \"https://127.0.0.1:1/\"]\n\tinsteadOf = https://\n"+
				"[credential]\n\thelper = !echo password=stolen\n"), 0o600); err != nil {
			t.Fatalf("writing the hostile gitconfig: %v", err)
		}
		t.Setenv("HOME", hostile)
		t.Setenv("XDG_CONFIG_HOME", hostile)

		if err := f.provision(); err != nil {
			t.Fatalf("a gitconfig in HOME influenced the fetch: %v\nlog:\n%s", err, f.log())
		}
	})

	t.Run("a host GIT_ASKPASS is never consulted", func(t *testing.T) {
		// No credential at all, against a forge that demands one. The only way
		// the fetch could succeed is by asking the host's askpass helper — the
		// exact path by which a machine's ambient credential would be used in
		// place of the one the grant issued.
		f := newFixture(t, gitforge.Options{})
		f.cred = executor.GitCredential{}
		f.set = redact.New(credToken)

		marker := filepath.Join(t.TempDir(), "askpass-ran")
		script := filepath.Join(t.TempDir(), "askpass.sh")
		body := "#!/bin/sh\ntouch " + marker + "\necho " + credToken + "\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatalf("writing the askpass script: %v", err)
		}
		t.Setenv("GIT_ASKPASS", script)
		t.Setenv("SSH_ASKPASS", script)
		t.Setenv("GIT_TERMINAL_PROMPT", "1")

		if err := f.provision(); err == nil {
			t.Fatalf("Provision succeeded with no credential against a forge that demands "+
				"one\nlog:\n%s", f.log())
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("the host's GIT_ASKPASS helper ran: git was allowed to answer a " +
				"credential challenge with material the grant never issued")
		}
	})
}

// TestTransportEnvForwardsOnlyTheAllowlist is the unit half of the test above:
// the allowlist is what an operator can contribute, and the one omission that
// matters is deliberate.
func TestTransportEnvForwardsOnlyTheAllowlist(t *testing.T) {
	allowed := map[string]string{
		"HTTPS_PROXY":    "http://proxy.example.invalid:3128",
		"https_proxy":    "http://proxy.example.invalid:3128",
		"ALL_PROXY":      "socks5://proxy.example.invalid:1080",
		"all_proxy":      "socks5://proxy.example.invalid:1080",
		"NO_PROXY":       "127.0.0.1",
		"no_proxy":       "127.0.0.1",
		"GIT_SSL_CAINFO": "/etc/ssl/certs/ca.pem",
		"GIT_SSL_CAPATH": "/etc/ssl/certs",
		"SSL_CERT_FILE":  "/etc/ssl/cert.pem",
		"SSL_CERT_DIR":   "/etc/ssl",
	}
	// Set alongside them: settings an operator might expect to be forwarded and
	// which must not be, because each one either redirects the fetch or removes
	// the protection the credential depends on.
	refused := map[string]string{
		"GIT_SSL_NO_VERIFY":   "true",
		"GIT_CONFIG_GLOBAL":   "/tmp/evil.gitconfig",
		"GIT_CONFIG_COUNT":    "1",
		"GIT_ASKPASS":         "/tmp/askpass.sh",
		"GIT_TERMINAL_PROMPT": "1",
		"GIT_PROXY_COMMAND":   "/tmp/proxy.sh",
		"HTTP_PROXY":          "http://cleartext.example.invalid:3128",
		"GITHUB_TOKEN":        "cloop-test-not-forwarded-value",
	}
	for k, v := range allowed {
		t.Setenv(k, v)
	}
	for k, v := range refused {
		t.Setenv(k, v)
	}
	// An allowlisted name whose value is empty must be dropped, not forwarded
	// as an empty string: an empty proxy variable means something different
	// from an absent one to libcurl.
	t.Setenv("ALL_PROXY", "")
	delete(allowed, "ALL_PROXY")

	got := map[string]string{}
	for _, kv := range gitprovision.TransportEnv() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("TransportEnv returned %q, which is not a KEY=VALUE pair", kv)
		}
		got[k] = v
	}

	for k, want := range allowed {
		if got[k] != want {
			t.Errorf("TransportEnv did not forward %s: got %q, want %q", k, got[k], want)
		}
	}
	for k := range refused {
		if v, ok := got[k]; ok {
			t.Errorf("TransportEnv forwarded %s=%q; it is not on the allowlist, and forwarding "+
				"it would let the machine decide the outcome of a fetch the control plane asked for",
				k, v)
		}
	}
	if _, ok := got["ALL_PROXY"]; ok {
		t.Error("TransportEnv forwarded an empty ALL_PROXY; an empty proxy variable is not the " +
			"same as an absent one")
	}
}

// --- refusals that must happen before the network ------------------------------

func TestProvisionRefusesAnExpiredCredentialBeforeContactingTheRemote(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.cred.ExpiresAt = time.Now().Add(-1 * time.Minute)

	err := f.provision()
	if err == nil {
		t.Fatalf("Provision accepted a lapsed credential\nlog:\n%s", f.log())
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
	}
	// The refusal is the point, but *where* it happens is the property: an
	// opaque 401 halfway through a transfer points the operator at the
	// repository instead of at the lease.
	if n := f.forge.Count(); n != 0 {
		t.Errorf("the forge received %d request(s); the lapsed credential was used rather than "+
			"refused: %s", n, f.forge.Log())
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error does not say the credential expired, so an operator would look at "+
			"the repository: %v", err)
	}
	f.assertNoLeak(err)
}

func TestProvisionRefusesAWorkspaceItDoesNotProvision(t *testing.T) {
	for _, kind := range []executor.WorkspaceKind{
		executor.WorkspaceUnspecified,
		executor.WorkspaceBind,
		executor.WorkspaceNone,
	} {
		t.Run(string(kind)+"/", func(t *testing.T) {
			f := newFixture(t, gitforge.Options{})
			f.ws = executor.Workspace{Kind: kind}

			err := f.provision()
			if err == nil {
				t.Fatalf("Provision accepted workspace kind %q", kind)
			}
			if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
				t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
			}
			if n := f.forge.Count(); n != 0 {
				t.Errorf("the forge received %d request(s) for a non-git workspace", n)
			}
		})
	}
}

// --- reuse and rollback --------------------------------------------------------

func TestProvisionReusesAnExistingCheckout(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	if err := f.provision(); err != nil {
		t.Fatalf("first Provision: %v\nlog:\n%s", err, f.log())
	}

	// A file the second provisioning has no business destroying: an untracked
	// artefact of the first run, which is what makes "reuse" different from
	// "clone again".
	keep := filepath.Join(f.dir, "untracked-work.txt")
	if err := os.WriteFile(keep, []byte("in flight\n"), 0o644); err != nil {
		t.Fatalf("writing the untracked file: %v", err)
	}

	f.emitted.Reset()
	if err := f.provision(); err != nil {
		t.Fatalf("second Provision: %v\nlog:\n%s", err, f.log())
	}
	if !strings.Contains(f.log(), "reusing the existing checkout") {
		t.Errorf("the second provisioning did not report reuse; it re-initialised over an "+
			"existing checkout\nlog:\n%s", f.log())
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("the untracked file did not survive re-provisioning: %v", err)
	}
	f.assertNoLeak(nil)
}

// TestProvisionRefusesToCloneOverADifferentRemote covers the case where
// re-provisioning would silently discard somebody's work.
func TestProvisionRefusesToCloneOverADifferentRemote(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	if err := f.provision(); err != nil {
		t.Fatalf("first Provision: %v\nlog:\n%s", err, f.log())
	}
	before := headOf(t, f)

	other := f.forge.RepoURL(owner, "a-completely-different-repo")
	f.forge.Create(t, owner, "a-completely-different-repo")
	f.ws.Repo = other

	f.emitted.Reset()
	err := f.provision()
	if err == nil {
		t.Fatalf("Provision re-cloned over a checkout of a different repository\nlog:\n%s", f.log())
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
	}
	// Both URLs, because the operator's next question is which one is wrong.
	for _, want := range []string{f.forge.RepoURL(owner, repo), other} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if after := headOf(t, f); after != before {
		t.Errorf("the existing checkout moved from %s to %s during a refusal", before, after)
	}
}

func headOf(t *testing.T, f *fixture) string {
	t.Helper()
	tools := gitforge.RequireGit(t)
	return strings.TrimSpace(gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "rev-parse", "HEAD"))
}

// TestProvisionRollsBackOnlyWhatItCreated is the asymmetry the package
// documents: a half-fetched repository must not be left for the next attempt to
// reuse, and files this machine did not create must never be deleted.
//
// Failure is induced after the repository exists — a fetch of a ref the remote
// does not have — so every case really does have a partial .git to clean up.
func TestProvisionRollsBackOnlyWhatItCreated(t *testing.T) {
	t.Run("an empty directory is emptied again", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		f.ws.Ref = "refs/heads/never-pushed"
		if err := os.MkdirAll(f.dir, 0o700); err != nil {
			t.Fatalf("creating the workspace: %v", err)
		}

		if err := f.provision(); err == nil {
			t.Fatal("Provision succeeded against a missing ref")
		}
		entries, err := os.ReadDir(f.dir)
		if err != nil {
			t.Fatalf("reading the workspace: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("the failed provisioning left %d entr(ies) behind: %v; the next attempt "+
				"would take the reuse path over a tree in an unknown state",
				len(entries), names(entries))
		}
	})

	t.Run("pre-existing files survive", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		f.ws.Ref = "refs/heads/never-pushed"
		if err := os.MkdirAll(f.dir, 0o700); err != nil {
			t.Fatalf("creating the workspace: %v", err)
		}
		mine := filepath.Join(f.dir, "not-yours.txt")
		if err := os.WriteFile(mine, []byte("someone else's only copy\n"), 0o644); err != nil {
			t.Fatalf("writing the pre-existing file: %v", err)
		}

		if err := f.provision(); err == nil {
			t.Fatal("Provision succeeded against a missing ref")
		}
		if _, err := os.Stat(mine); err != nil {
			t.Errorf("rollback deleted a file it did not create: %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, ".git")); err == nil {
			t.Error("rollback left the partial repository behind")
		}
	})

	t.Run("an existing checkout is left alone", func(t *testing.T) {
		f := newFixture(t, gitforge.Options{})
		if err := f.provision(); err != nil {
			t.Fatalf("first Provision: %v\nlog:\n%s", err, f.log())
		}
		before := headOf(t, f)

		f.ws.Ref = "refs/heads/never-pushed"
		f.emitted.Reset()
		if err := f.provision(); err == nil {
			t.Fatal("Provision succeeded against a missing ref")
		}
		if _, err := os.Stat(filepath.Join(f.dir, ".git")); err != nil {
			t.Fatalf("rollback removed a repository this machine did not create: %v", err)
		}
		if after := headOf(t, f); after != before {
			t.Errorf("the reused checkout moved from %s to %s during a failure", before, after)
		}
	})
}

func names(entries []os.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// --- resource ceilings ---------------------------------------------------------

// TestProvisionEnforcesTheDiskLimit covers the check that has to happen here
// because there is nothing else between the fetch and the filesystem.
func TestProvisionEnforcesTheDiskLimit(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	// Incompressible, so the pack is at least as large as the blob and the
	// limit is crossed before the checkout as well as after it.
	f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, "big.bin", incompressible(3<<20), "big")
	f.ws.SizeLimitMB = 1

	err := f.provision()
	if err == nil {
		t.Fatalf("Provision accepted a tree over the workload's disk limit\nlog:\n%s", f.log())
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
	}
	if !strings.Contains(err.Error(), "limit of 1 MB") {
		t.Errorf("the refusal does not name the limit that was crossed: %v", err)
	}
	// Rollback still applies: an oversized half-fetch is exactly the tree the
	// next attempt must not reuse.
	if _, err := os.Stat(filepath.Join(f.dir, ".git")); err == nil {
		t.Error("the oversized partial repository was left behind")
	}
}

// incompressible returns n bytes that zlib cannot shrink, so a size limit
// measured on the working tree is also crossed inside the pack.
func incompressible(n int) string {
	b := make([]byte, n)
	// A xorshift PRNG rather than math/rand: the content must be identical on
	// every run so a failure is reproducible, and it must not depend on a
	// package-level seed another test could have changed.
	var x uint32 = 0x2545F491
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return string(b)
}

func TestTreeSizeCountsRegularFilesAndNeverFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	gitforge.WriteFile(t, dir, "a.txt", strings.Repeat("a", 100))
	gitforge.WriteFile(t, dir, "nested/b.txt", strings.Repeat("b", 250))
	// A symlink to the root of the filesystem: counted as itself, never
	// descended into. Without that property a repository containing one link
	// would measure as the whole machine.
	if err := os.Symlink("/", filepath.Join(dir, "escape")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	size, entries, err := gitprovision.TreeSize(dir)
	if err != nil {
		t.Fatalf("TreeSize: %v", err)
	}
	if size != 350 {
		t.Errorf("TreeSize = %d bytes, want 350 (the two regular files only)", size)
	}
	// dir, a.txt, nested, nested/b.txt, escape.
	if entries != 5 {
		t.Errorf("TreeSize counted %d entries, want 5", entries)
	}
}

// --- cancellation ---------------------------------------------------------------

// TestProvisionReturnsWhenCancelledMidFetch is a regression test for a hang.
//
// Before gitprovision.BoundChild existed, this test did not fail — it never
// finished. exec.CommandContext killed the git process at the deadline, but
// `git fetch` runs the transfer in git-remote-https, which inherits the
// captured stdout and stderr pipes; with the parent gone the helper kept the
// write end open, CombinedOutput's copy goroutine never saw EOF, and Wait
// blocked until the helper gave up on its own. Against a remote that accepts
// the connection and then says nothing — a hung forge, a black-holed route, a
// proxy that stopped answering — that is never.
//
// The consequence was worse than a slow provisioning: the caller's context
// deadline did nothing, so an edge agent or an init container would sit there
// with the harness unstarted and the task neither running nor failed. Nothing
// in the package's behaviour changed, which is why no functional test could see
// it — the only observable is that Provision returns at all.
func TestProvisionReturnsWhenCancelledMidFetch(t *testing.T) {
	// A forge that accepts the request and never answers. The response is
	// deliberately never written.
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })

	f := newFixture(t, gitforge.Options{
		User: credUser, Password: credToken,
		Intercept: func(_ http.ResponseWriter, r *http.Request) bool {
			select {
			case <-blocked:
			case <-r.Context().Done():
			}
			return true
		},
	})

	const deadline = 750 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	err := gitprovision.Provision(ctx, f.request())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Provision succeeded against a forge that never answers\nlog:\n%s", f.log())
	}
	// The bound, not the exact duration: the group kill should return almost
	// immediately, and BoundChild's WaitDelay backstop caps the worst case a few
	// seconds later. Anything beyond that means cancellation is not reaching the
	// transport helper and the hang is back.
	if limit := deadline + 30*time.Second; elapsed > limit {
		t.Errorf("Provision took %s to honour a %s deadline (limit %s): cancellation is not "+
			"reaching the transport helper", elapsed, deadline, limit)
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error does not wrap ErrWorkspaceUnavailable: %v", err)
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("a cancelled fetch is not reported as one, so an operator would read it as a "+
			"repository failure: %v", err)
	}
	f.assertNoLeak(err)
}

// --- pure helpers ----------------------------------------------------------------

func TestSameRemote(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "https://h/o/r", "https://h/o/r", true},
		{"a trailing .git is noise", "https://h/o/r.git", "https://h/o/r", true},
		{"a trailing slash is noise", "https://h/o/r/", "https://h/o/r", true},
		{"both kinds of noise", "https://h/o/r.git/", "https://h/o/r", true},
		{"surrounding space is noise", "  https://h/o/r  ", "https://h/o/r", true},
		{"a different path is a different repo", "https://h/o/r", "https://h/o/other", false},
		{"a different host is a different repo", "https://h/o/r", "https://g/o/r", false},
		{"case is not folded", "https://h/O/R", "https://h/o/r", false},
		{"an empty left side never matches", "", "", false},
		{"an empty left side never matches a real one", "", "https://h/o/r", false},
		{"an empty right side does not match", "https://h/o/r", "", false},
		{"a bare .git is empty once normalised", ".git", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitprovision.SameRemote(tc.a, tc.b); got != tc.want {
				t.Errorf("SameRemote(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestCollapseKeepsTheTail(t *testing.T) {
	if got := gitprovision.Collapse("  a\n\tb   c \n"); got != "a b c" {
		t.Errorf("Collapse folded to %q, want %q", got, "a b c")
	}
	if got := gitprovision.Collapse(""); got != "" {
		t.Errorf("Collapse(%q) = %q, want the empty string", "", got)
	}
	// git puts the actual reason last, so the tail is what must survive.
	long := strings.Repeat("x", 500) + " THE-REASON"
	got := gitprovision.Collapse(long)
	if !strings.HasSuffix(got, "THE-REASON") {
		t.Errorf("Collapse dropped the tail, which is where git puts the reason: %q", got)
	}
	if !strings.HasPrefix(got, "…") {
		t.Errorf("Collapse did not mark the truncation: %q", got)
	}
	if n := len([]rune(got)); n != 401 {
		t.Errorf("Collapse returned %d runes, want 401 (the ellipsis plus 400)", n)
	}
}

func TestHostLabelReadsAsASentence(t *testing.T) {
	got := gitprovision.HostLabel("device")
	if !strings.HasPrefix(got, "this device") {
		t.Errorf("HostLabel(%q) = %q, want it to start with %q", "device", got, "this device")
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		// The hostname is the identifier an operator can act on, so it must be
		// there when it is available.
		if !strings.Contains(got, strings.TrimSpace(h)) {
			t.Errorf("HostLabel = %q, which does not name the host %q", got, h)
		}
	}
}

// TestRequestHostFallsBackToALabel covers the one thing a caller contributes.
func TestRequestHostFallsBackToALabel(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Ref = "refs/heads/never-pushed"

	// Named: the diagnostic uses the caller's label.
	err := f.provision()
	if err == nil || !strings.Contains(err.Error(), "this test executor") {
		t.Errorf("the failure does not carry the caller's host label: %v", err)
	}

	// Unnamed: it falls back rather than producing a sentence with a hole in it.
	req := f.request()
	req.Host = "   "
	req.Emit = nil // also covers the nil-Emit path
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err = gitprovision.Provision(ctx, req)
	if err == nil {
		t.Fatal("Provision succeeded against a missing ref")
	}
	if !strings.Contains(err.Error(), "this machine") {
		t.Errorf("an unnamed host did not fall back to a label: %v", err)
	}
}
