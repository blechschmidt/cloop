package gitproxy_test

// Every audit event about a request names the repository that request
// addressed (Task 20346).
//
// Found against a live hub and a sandbox on an edge device: a guarded GitHub
// lease mints a *scoped* session, whose RepoPath is empty, and the proxy
// recorded every fetch, push_allowed and push_denied through it against that
// empty field — the trail said a sandbox had pushed, and not where. A refused
// cross-repository request was misrecorded the other way on a pinned session:
// under the repository the session was minted for, not the one the sandbox
// tried.

import (
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

func TestScopedSessionEventsNameTheRepository(t *testing.T) {
	h := newHarness(t)
	h.addRepo(t, otherOwner, otherName)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mintScoped(t, []string{forgeOwner + "/*"}, pol)

	dir := filepath.Join(t.TempDir(), "work")
	if out, err := h.git(t, "", h.credEnv(m), "clone", h.repoURL(forgeOwner, forgeName), dir); err != nil {
		t.Fatalf("clone through the scoped session: %v\n%s", err, out)
	}
	h.commit(t, dir, "work.txt", "written inside the sandbox\n")
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1"); err != nil {
		t.Fatalf("push to an allowed branch: %v\n%s", err, out)
	}
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/main"); err == nil {
		t.Fatalf("push to main succeeded\n%s", out)
	}
	if out, err := h.git(t, "", h.credEnv(m), "ls-remote", h.repoURL(otherOwner, otherName)); err == nil {
		t.Fatalf("ls-remote outside the allowlist succeeded\n%s", out)
	}
	h.reg.Close(m.Session.ID, "test finished")

	admitted := forgeOwner + "/" + forgeName
	for _, c := range []struct {
		kind gitproxy.EventKind
		repo string
	}{
		{gitproxy.EventFetch, admitted},
		{gitproxy.EventPushAllowed, admitted},
		{gitproxy.EventPushDenied, admitted},
		// The repository the sandbox tried, not the allowlist it fell outside.
		{gitproxy.EventRejected, otherOwner + "/" + otherName},
		// A session's own rows name what it admits, as its mint row does.
		{gitproxy.EventSessionMinted, forgeOwner + "/*"},
		{gitproxy.EventSessionClosed, forgeOwner + "/*"},
	} {
		evs := h.eventsOf(c.kind)
		if len(evs) == 0 {
			t.Errorf("no %s event recorded%s", c.kind, h.eventLog())
			continue
		}
		for _, e := range evs {
			if e.RepoPath != c.repo {
				t.Errorf("%s event names repository %q, want %q%s", c.kind, e.RepoPath, c.repo, h.eventLog())
			}
		}
	}
}

// TestScopedSessionEventsNormaliseAnAdmittedPath: an admitted request is
// recorded in the form grants are matched in, whatever case the sandbox used,
// so one repository does not become several in the trail.
func TestScopedSessionEventsNormaliseAnAdmittedPath(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mintScoped(t, []string{forgeOwner + "/*"}, pol)

	// The forge path itself is lowercase; only the proxy sees the variant.
	dir := filepath.Join(t.TempDir(), "work")
	if out, err := h.git(t, "", h.credEnv(m), "clone", h.repoURL("ACME", "Tool"), dir); err != nil {
		t.Fatalf("clone of a case variant of an allowlisted repository: %v\n%s", err, out)
	}
	if rejected := h.eventsOf(gitproxy.EventRejected); len(rejected) != 0 {
		t.Fatalf("an admitted case variant was refused%s", h.eventLog())
	}
	fetches := h.eventsOf(gitproxy.EventFetch)
	if len(fetches) == 0 {
		t.Fatalf("the clone recorded no fetch%s", h.eventLog())
	}
	for _, e := range fetches {
		if e.RepoPath != forgeOwner+"/"+forgeName {
			t.Errorf("fetch event names %q, want the normalised %q%s", e.RepoPath, forgeOwner+"/"+forgeName, h.eventLog())
		}
	}
}

// TestPinnedSessionRefusalNamesTheRepositoryTried: a session pinned to one
// repository, used against another, is recorded against the other.
func TestPinnedSessionRefusalNamesTheRepositoryTried(t *testing.T) {
	h := newHarness(t)
	h.addRepo(t, otherOwner, otherName)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mint(t, pol, 0)

	if out, err := h.git(t, "", h.credEnv(m), "ls-remote", h.repoURL(otherOwner, otherName)); err == nil {
		t.Fatalf("a session pinned to %s/%s read %s/%s\n%s", forgeOwner, forgeName, otherOwner, otherName, out)
	}
	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) == 0 {
		t.Fatalf("the refusal left no audit row%s", h.eventLog())
	}
	for _, e := range rejected {
		if e.RepoPath != otherOwner+"/"+otherName {
			t.Errorf("rejected event names %q, want the repository tried, %s/%s%s",
				e.RepoPath, otherOwner, otherName, h.eventLog())
		}
	}
}
