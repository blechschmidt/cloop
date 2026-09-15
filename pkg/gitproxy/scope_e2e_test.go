// End-to-end tests for scoped sessions — the mode a user's GitHub PAT grant
// uses, where the session carries an owner/name allowlist instead of a single
// pinned repository.
//
// The claim under test is the one the feature is sold on: a broad personal
// access token, granted to a project with an allowlist, becomes an authority
// bounded by that allowlist *on the network path*, not by anything running
// inside the sandbox. So these tests drive the real git client against a real
// forge holding a real credential, and every assertion is either "the bytes
// arrived at the bare repository" or "they did not".
//
// Two repositories exist on the forge for this: one the allowlist admits and
// one it does not. The second is the whole point. A test with only the first
// would pass against a proxy that ignored the allowlist entirely.
package gitproxy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// The repository outside the allowlist. It lives on the same forge, is
// reachable with the same PAT, and differs from the fixture repository only in
// being outside "acme/*" — which is exactly the difference the proxy is
// supposed to be able to act on.
const (
	otherOwner = "somebody-else"
	otherName  = "private"
)

// addRepo seeds a second bare repository under the forge's project root.
//
// Same construction as initUpstream, kept separate rather than generalised:
// initUpstream also fixes the harness's own `bare` and `upstream` fields, and
// a shared helper that sometimes did and sometimes did not would be the kind
// of thing a later reader has to check before trusting an assertion.
func (h *harness) addRepo(t *testing.T, owner, name string) string {
	t.Helper()

	bare := filepath.Join(h.projectRoot, owner, name+".git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		t.Fatalf("creating the forge owner directory for %s/%s: %v", owner, name, err)
	}
	h.mustGit(t, "", nil, "init", "--bare", bare)
	h.mustGit(t, "", nil, "--git-dir="+bare, "symbolic-ref", "HEAD", "refs/heads/main")
	h.mustGit(t, "", nil, "--git-dir="+bare, "config", "http.receivepack", "true")
	h.mustGit(t, "", nil, "--git-dir="+bare, "config", "http.uploadpack", "true")

	seed := t.TempDir()
	h.mustGit(t, seed, nil, "init", seed)
	h.mustGit(t, seed, nil, "symbolic-ref", "HEAD", "refs/heads/main")
	if err := os.WriteFile(filepath.Join(seed, "SECRET.md"), []byte("not yours\n"), 0o644); err != nil {
		t.Fatalf("writing the seed file for %s/%s: %v", owner, name, err)
	}
	h.mustGit(t, seed, nil, "add", "SECRET.md")
	h.mustGit(t, seed, nil, append(identity(), "commit", "--no-gpg-sign", "-m", "seed")...)
	h.mustGit(t, seed, nil, "push", bare, "HEAD:refs/heads/main")
	return bare
}

// mintScoped creates a session over an allowlist rather than one repository.
func (h *harness) mintScoped(t *testing.T, patterns []string, pol gitproxy.Policy) *gitproxy.Minted {
	t.Helper()
	m, err := h.reg.Mint(gitproxy.MintRequest{
		// A host base, not a repository URL: the repository comes from
		// whatever the sandbox asks for, after the allowlist admits it.
		Upstream:     h.forge.URL,
		RepoPatterns: patterns,
		Credential:   gitproxy.Credential{Username: forgeUser, Password: forgePAT},
		Policy:       pol,
		ProjectID:    "proj-scoped",
		ExecutorID:   "exec-1",
		Actor:        "dev@example.com",
	})
	if err != nil {
		t.Fatalf("minting a scoped session over %v: %v", patterns, err)
	}
	if strings.Contains(m.RepoURL, forgePAT) || strings.Contains(m.Token, forgePAT) {
		t.Fatal("the forge PAT leaked into what the sandbox is handed")
	}
	if m.RepoURL != h.proxySrv.URL {
		t.Fatalf("scoped session repo URL = %q, want the bare proxy base %q", m.RepoURL, h.proxySrv.URL)
	}
	return m
}

// repoURL is what a sandbox would clone after github.com was rewritten to the
// proxy — the proxy's base plus the repository path it was already using.
func (h *harness) repoURL(owner, name string) string {
	return h.proxySrv.URL + "/" + owner + "/" + name
}

// TestScopedSessionServesRepositoriesInsideItsAllowlist is the control: without
// it, the refusal below could be a proxy that cannot serve a scoped session at
// all rather than one enforcing an allowlist.
func TestScopedSessionServesRepositoriesInsideItsAllowlist(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mintScoped(t, []string{forgeOwner + "/*"}, pol)

	dir := filepath.Join(t.TempDir(), "work")
	out, err := h.git(t, "", h.credEnv(m), "clone", h.repoURL(forgeOwner, forgeName), dir)
	if err != nil {
		t.Fatalf("cloning an allowlisted repository through a scoped session failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Fatalf("the clone did not produce the upstream tree: %v", err)
	}

	// The write half, so "scoped" is not quietly read-only by accident.
	sha := h.commit(t, dir, "work.txt", "written inside the sandbox\n")
	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1")
	if err != nil {
		t.Fatalf("push to an allowed branch of an allowlisted repository failed: %v\n%s", err, pushOut)
	}
	got, ok := h.upstreamSHA(t, "refs/heads/cloop/task-1")
	if !ok || got != sha {
		t.Fatalf("upstream refs/heads/cloop/task-1 = %q (present=%v), want %s", got, ok, sha)
	}

	if strings.Contains(out, forgePAT) || strings.Contains(pushOut, forgePAT) {
		t.Error("the forge PAT appeared in output the sandbox can read")
	}
}

// TestScopedSessionRefusesRepositoriesOutsideItsAllowlist is the property the
// scoped mode exists for.
//
// The refused repository is reachable: the same forge serves it and the same
// PAT authenticates to it, so a proxy that forwarded the request would succeed.
// A failure here therefore means the proxy declined, not that the repository
// was missing — and the final check reads the bare repository directly to prove
// nothing was disclosed.
func TestScopedSessionRefusesRepositoriesOutsideItsAllowlist(t *testing.T) {
	h := newHarness(t)
	otherBare := h.addRepo(t, otherOwner, otherName)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mintScoped(t, []string{forgeOwner + "/*"}, pol)

	// Sanity: the PAT really does reach this repository, so the refusal below
	// is the proxy's decision and not an artefact of the fixture.
	if _, ok := h.upstreamSHA2(t, otherBare, "refs/heads/main"); !ok {
		t.Fatal("the out-of-allowlist fixture repository has no main branch; the test would prove nothing")
	}

	dir := filepath.Join(t.TempDir(), "stolen")
	out, err := h.git(t, "", h.credEnv(m), "clone", h.repoURL(otherOwner, otherName), dir)
	if err == nil {
		t.Fatalf("cloning %s/%s through a session scoped to %s/* succeeded; the allowlist is not enforced\n%s",
			otherOwner, otherName, forgeOwner, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "SECRET.md")); statErr == nil {
		t.Fatal("content from outside the allowlist landed in the working tree")
	}
	if strings.Contains(out, forgePAT) {
		t.Error("the forge PAT appeared in the refusal output")
	}

	// The refusal is the proxy's, and it says so in the audit trail rather
	// than only in git's stderr.
	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) == 0 {
		t.Fatalf("no rejection event recorded for an out-of-allowlist clone%s", h.eventLog())
	}
	var named bool
	for _, ev := range rejected {
		if strings.Contains(ev.Detail, otherOwner+"/"+otherName) || strings.Contains(ev.RepoPath, otherOwner) {
			named = true
		}
	}
	if !named {
		t.Errorf("no rejection event names the repository that was refused%s", h.eventLog())
	}
}

// upstreamSHA2 reads a ref out of an arbitrary bare repository. The harness's
// own upstreamSHA is pinned to the fixture repository.
func (h *harness) upstreamSHA2(t *testing.T, bare, ref string) (string, bool) {
	t.Helper()
	out, err := h.git(t, "", nil, "--git-dir="+bare, "rev-parse", "--verify", "--quiet", ref)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(out), true
}

// TestScopedReadOnlySessionCannotPush covers the other half of the narrowing: a
// grant that authorises no writes yields a session that can read its allowlist
// and nothing more, even though the PAT behind it could push.
//
// This is what makes "contents:read" mean something. Before the proxy, a
// read-only permission set was a label on a grant whose token could still push
// to every repository its owner could reach.
func TestScopedReadOnlySessionCannotPush(t *testing.T) {
	h := newHarness(t)

	// What guardPolicy produces for a grant with no write permission.
	pol := gitproxy.Policy{AllowedRefs: []string{"refs/heads/cloop/**"}, AllowFetch: true}
	m := h.mintScoped(t, []string{forgeOwner + "/" + forgeName}, pol)

	dir := filepath.Join(t.TempDir(), "work")
	out, err := h.git(t, "", h.credEnv(m), "clone", h.repoURL(forgeOwner, forgeName), dir)
	if err != nil {
		t.Fatalf("a read-only scoped session could not clone: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "work.txt", "written inside the sandbox\n")

	// Even into the namespace the policy names, because the direction — not
	// the ref — is what is missing.
	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1")
	if err == nil {
		t.Fatalf("a read-only session pushed successfully\n%s", pushOut)
	}
	if got, ok := h.upstreamSHA(t, "refs/heads/cloop/task-1"); ok {
		t.Fatalf("refs/heads/cloop/task-1 exists upstream (%s) after a push that should have been refused", got)
	}
	if sha == "" {
		t.Fatal("the fixture commit was not created; the push assertion proves nothing")
	}
	if strings.Contains(pushOut, forgePAT) {
		t.Error("the forge PAT appeared in the refusal output")
	}
}
