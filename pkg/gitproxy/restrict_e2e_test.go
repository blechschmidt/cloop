package gitproxy_test

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// TestPushOutsideAGrantsBranchesIsRefused drives a grant's branch restriction
// (Task 20340) with a real git client against a real forge.
//
// The ceiling here is deliberately wide — the whole refs/heads namespace, which
// is what an operator who wants projects to reach their own branches configures
// — so that everything the proxy refuses below is refused by the grant's list
// and by nothing else.
func TestPushOutsideAGrantsBranchesIsRefused(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.Policy{
		AllowedRefs:  []string{"refs/heads/**"},
		RestrictRefs: []string{"feature/*"},
		AllowCreate:  true,
		AllowUpdate:  true,
		AllowFetch:   true,
	}
	m := h.mint(t, pol, 0)

	mainBefore, ok := h.upstreamSHA(t, "refs/heads/main")
	if !ok {
		t.Fatal("the fixture has no refs/heads/main to protect")
	}

	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("cloning through the proxy failed: %v\n%s", err, out)
	}
	local := h.commit(t, dir, "work.txt", "written inside the sandbox\n")

	// The ceiling admits main; the grant does not. This is the push that
	// landed on main in the Task 20340 report, and it must stop here.
	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/main")
	if err == nil {
		t.Fatalf("push to refs/heads/main succeeded although the grant allows only feature/*\n%s", pushOut)
	}
	if after, _ := h.upstreamSHA(t, "refs/heads/main"); after != mainBefore {
		t.Fatalf("upstream main moved from %s to %s despite the refusal\n%s", mainBefore, after, pushOut)
	}
	// git prints the proxy's reason next to the ref. It has to say which list
	// refused, or the person reading it widens the wrong one.
	if !strings.Contains(pushOut, "grant may push to") || !strings.Contains(pushOut, "refs/heads/feature/*") {
		t.Errorf("the refusal does not explain that the grant's branch list excluded main:\n%s", pushOut)
	}

	// A branch the grant does name goes through, over the same session.
	pushOut, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/feature/login")
	if err != nil {
		t.Fatalf("push to a branch inside the grant's list failed: %v\n%s", err, pushOut)
	}
	if got, ok := h.upstreamSHA(t, "refs/heads/feature/login"); !ok || got != local {
		t.Fatalf("upstream feature/login = %q (exists=%v), want %s\n%s", got, ok, local, pushOut)
	}

	// One level too deep for "*": still refused, so the pattern is matched the
	// way the documentation says rather than as a prefix.
	pushOut, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/feature/login/v2")
	if err == nil {
		t.Fatalf("push to feature/login/v2 succeeded; \"*\" must not cross a slash\n%s", pushOut)
	}

	denied := h.eventsOf(gitproxy.EventPushDenied)
	if len(denied) != 2 {
		t.Fatalf("got %d push_denied events, want 2%s", len(denied), h.eventLog())
	}
	if !strings.Contains(denied[0].Detail, "refs/heads/main") {
		t.Errorf("push_denied detail does not name the ref: %q", denied[0].Detail)
	}
	minted := h.eventsOf(gitproxy.EventSessionMinted)
	if len(minted) == 0 || !strings.Contains(minted[0].Detail, "narrowed to refs/heads/feature/*") {
		t.Errorf("the session_minted audit row does not record the grant's narrowing%s", h.eventLog())
	}
}
