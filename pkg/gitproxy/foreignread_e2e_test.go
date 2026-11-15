package gitproxy_test

// Foreign reads (Task 20499): a run of one project fetching another project's
// repository, lent to it only while that project's readers list names it.
// Driven with a real git client against a real forge, so "fetch-only" and "the
// list is asked at every request" are what git sees, not what a unit test
// asserts about a struct.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// listedReaders is a readers list the test changes while sessions are live.
type listedReaders struct {
	mu     sync.Mutex
	pairs  map[string]bool // "project|reader"
	asked  int
	byPair map[string]int
}

func newListedReaders() *listedReaders {
	return &listedReaders{pairs: map[string]bool{}, byPair: map[string]int{}}
}

func (l *listedReaders) set(project, reader string, listed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pairs[project+"|"+reader] = listed
}

// check is what the hub hands the proxy as Options.Readers: the pair must be
// listed, and the repository must be the read project's own.
func (l *listedReaders) check(f gitproxy.ForeignRead) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked++
	l.byPair[f.Project+"|"+f.Reader]++
	if f.Repo != forgeOwner+"/"+forgeName || f.ForgeHost == "" {
		return fmt.Errorf("%s/%s is not %s's repository", f.ForgeHost, f.Repo, f.Project)
	}
	if l.pairs[f.Project+"|"+f.Reader] {
		return nil
	}
	return fmt.Errorf("%s's readers list does not name %s", f.Project, f.Reader)
}

func (l *listedReaders) times() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.asked
}

// withReaders stands a proxy asking readers in front of the harness's forge.
func (h *harness) withReaders(t *testing.T, readers func(gitproxy.ForeignRead) error) {
	t.Helper()
	px, err := gitproxy.New(h.reg, gitproxy.Options{Transport: h.forge.Client().Transport, Readers: readers})
	if err != nil {
		t.Fatalf("gitproxy.New: %v", err)
	}
	h.setHandler(px)
}

const (
	readerProject = "/srv/projects/alpha"
	readProject   = "/srv/projects/bravo"
)

// mintForeign mints alpha's run a session reading bravo's repository, asking
// for far more than reading.
func (h *harness) mintForeign(t *testing.T) *gitproxy.Minted {
	t.Helper()
	m, err := h.reg.Mint(gitproxy.MintRequest{
		Upstream:   h.upstream,
		Credential: gitproxy.Credential{Username: forgeUser, Password: forgePAT},
		// Everything a write-back session may do, and more: a foreign read
		// must come out fetch-only all the same.
		Policy: gitproxy.Policy{AllowedRefs: []string{"refs/heads/**"}, AllowCreate: true, AllowUpdate: true,
			AllowDelete: true, AllowFetch: true},
		ProjectID:    readerProject,
		ReadsProject: readProject,
		RunID:        "run-alpha",
		Actor:        "alice@example.com",
	})
	if err != nil {
		t.Fatalf("minting a foreign read: %v", err)
	}
	return m
}

func TestForeignReadIsFetchOnlyAndNeverDurable(t *testing.T) {
	reg, err := gitproxy.NewRegistry("https://proxy.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	base := gitproxy.MintRequest{Upstream: "https://github.com/acme/tool.git", ProjectID: readerProject,
		ReadsProject: readProject}

	m, err := reg.Mint(func() gitproxy.MintRequest {
		r := base
		r.Policy = gitproxy.Policy{AllowedRefs: []string{"refs/heads/**"}, AllowCreate: true, AllowUpdate: true,
			AllowDelete: true}
		return r
	}())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	p := m.Session.Policy
	if p.AllowCreate || p.AllowUpdate || p.AllowDelete || !p.AllowFetch {
		t.Errorf("a foreign read's policy = %+v, want fetch and nothing else whatever was asked for", p)
	}
	if m.Session.ReadsProject != readProject || m.Session.ProjectID != readerProject {
		t.Errorf("session reads %q for %q, want %q for %q", m.Session.ReadsProject, m.Session.ProjectID,
			readProject, readerProject)
	}

	for name, mutate := range map[string]func(*gitproxy.MintRequest){
		"durable":           func(r *gitproxy.MintRequest) { r.Durable = true },
		"no reader":         func(r *gitproxy.MintRequest) { r.ProjectID = "" },
		"the reader itself": func(r *gitproxy.MintRequest) { r.ReadsProject = r.ProjectID },
	} {
		req := base
		mutate(&req)
		if _, err := reg.Mint(req); !errors.Is(err, gitproxy.ErrForeignRead) {
			t.Errorf("%s: Mint = %v, want ErrForeignRead", name, err)
		}
	}
}

func TestForeignReadFetchesOnlyWhileTheReadersListNamesTheReader(t *testing.T) {
	h := newHarness(t)
	readers := newListedReaders()
	h.withReaders(t, readers.check)
	m := h.mintForeign(t)

	// Not listed: refused before a byte reaches the forge, saying why.
	if _, out, err := h.clone(t, m); err == nil {
		t.Fatalf("cloning another project's repository succeeded while its readers list leaves the reader out\n%s", out)
	} else if !strings.Contains(out, "readers list does not name") {
		t.Errorf("the refusal does not say the readers list refused:\n%s", out)
	}
	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) == 0 || rejected[len(rejected)-1].ReadsProject != readProject ||
		rejected[len(rejected)-1].ProjectID != readerProject {
		t.Fatalf("the refusal's audit event does not name both projects%s", h.eventLog())
	}
	if n := len(h.eventsOf(gitproxy.EventFetch)); n != 0 {
		t.Fatalf("%d fetches reached the forge while the reader was not listed%s", n, h.eventLog())
	}

	// Listed: the same session fetches.
	readers.set(readProject, readerProject, true)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("cloning a project's repository its readers list names the reader for failed: %v\n%s", err, out)
	}
	fetches := h.eventsOf(gitproxy.EventFetch)
	if len(fetches) == 0 || fetches[0].ReadsProject != readProject {
		t.Fatalf("the fetch's audit event does not name the project read%s", h.eventLog())
	}

	// Never a push, listed or not.
	before, _ := h.upstreamSHA(t, "refs/heads/main")
	h.commit(t, dir, "foreign.txt", "written by another project's run\n")
	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/foreign")
	if err == nil {
		t.Fatalf("a foreign read pushed to the repository it may only read\n%s", pushOut)
	}
	if !strings.Contains(pushOut, "never pushes") {
		t.Errorf("the push refusal does not say a foreign read never pushes:\n%s", pushOut)
	}
	if _, ok := h.upstreamSHA(t, "refs/heads/cloop/foreign"); ok {
		t.Fatal("the refused push created a branch upstream")
	}
	if after, _ := h.upstreamSHA(t, "refs/heads/main"); after != before {
		t.Fatalf("upstream main moved from %s to %s", before, after)
	}

	// Taken off the list mid-session: the next fetch is refused, without
	// waiting for the session to end.
	readers.set(readProject, readerProject, false)
	asked := readers.times()
	if out, err := h.git(t, dir, h.credEnv(m), "fetch", "origin"); err == nil {
		t.Fatalf("a fetch after the reader was taken off the list succeeded\n%s", out)
	}
	if readers.times() <= asked {
		t.Error("the proxy did not ask the readers list again for the fetch after the change")
	}
}

func TestAProxyWithNoReadersListServesNoForeignRead(t *testing.T) {
	h := newHarness(t)
	// The harness's own proxy has no Readers.
	m := h.mintForeign(t)
	if _, out, err := h.clone(t, m); err == nil {
		t.Fatalf("a proxy with no readers list served another project's repository\n%s", out)
	} else if !strings.Contains(out, "no readers list to ask") {
		t.Errorf("the refusal does not say why:\n%s", out)
	}

	// A session of the run's own project is not a foreign read, and is not
	// asked about: it clones as it always did.
	own := h.mint(t, gitproxy.Policy{AllowFetch: true, AllowCreate: true}, 0)
	if _, out, err := h.clone(t, own); err != nil {
		t.Fatalf("a session of the run's own project could not clone: %v\n%s", err, out)
	}
}
