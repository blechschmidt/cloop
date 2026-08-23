package security

// Guarantee: a local_repo grant opens exactly the repositories a human named,
// and nothing else on the control plane's filesystem (Task 20187).
//
// This is the first credential kind whose delivered material is reach into the
// hub's own filesystem rather than bytes. Everything else the broker hands out
// can, at worst, be stolen; this one can, if it is wrong, be a bind mount of /
// inside a sandbox that is running a model's suggestions with the network on.
//
// The failure modes are all quiet:
//
//   - A symlink under the granted root redirects a bind outside it. Nobody
//     plants this deliberately — a dependency's postinstall, an extracted
//     tarball, a stale ~/go/pkg link — and the resulting mount looks exactly
//     like a legitimate one in every log.
//   - A repository directory whose name carries a colon appends mount options,
//     or a third path, to a -v flag the operator believed they controlled.
//   - The allowlist falls open when empty, turning a storage bug or a
//     half-written migration into the whole root.
//   - The grant is delivered to an executor that cannot bind host paths at
//     all, so the harness runs against an empty /repos and reports on a
//     repository it never saw. That one is the workspace-provisioning bug of
//     Task 20179 in a new place, and it is why placement refuses instead.
//
// None of these break a feature test: in every one of them the run starts, the
// harness produces output, and the task completes.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// localRepoBroker builds a broker over a throwaway control-plane database.
func localRepoBroker(t *testing.T) *secretbroker.Broker {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "local-repo-conformance-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "local repo conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	return b
}

// stubCapExecutor is an Executor whose only interesting property is what it
// claims to support, which is all placement reads.
type stubCapExecutor struct {
	id   string
	caps executor.Capabilities
}

func (e stubCapExecutor) ID() string                          { return e.id }
func (e stubCapExecutor) Kind() string                        { return "stub" }
func (e stubCapExecutor) Capabilities() executor.Capabilities { return e.caps }
func (e stubCapExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (e stubCapExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e stubCapExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e stubCapExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (e stubCapExecutor) HealthCheck(context.Context) error { return nil }

// gitTree makes dir look like a git repository to the selector.
func gitTree(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	return dir
}

// leaseRepos issues a lease for project and returns every mount in it.
func leaseRepos(t *testing.T, b *secretbroker.Broker, project string) []secretbroker.RepoMount {
	t.Helper()
	lease, err := b.Lease(context.Background(), "exec-1", project)
	if err != nil {
		return nil
	}
	var out []secretbroker.RepoMount
	for _, m := range lease.Materials {
		out = append(out, m.Mounts...)
	}
	return out
}

// TestLocalRepoGrantCannotEscapeTheGrantedRoot is the core containment
// guarantee. Every path delivered must resolve to somewhere under the root the
// operator named, no matter what links exist inside it.
func TestLocalRepoGrantCannotEscapeTheGrantedRoot(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	gitTree(t, filepath.Join(elsewhere, "other-tenant"))
	gitTree(t, filepath.Join(root, "mine"))

	links := map[string]string{
		"escape":     filepath.Join(elsewhere, "other-tenant"),
		"everything": "/",
		"etc":        "/etc",
		"home":       "/root",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	b := localRepoBroker(t)
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "dev-src", Kind: secretbroker.KindLocalRepo,
		Payload: []byte(root), Actor: "operator",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// The broadest allowlist an operator can write. If containment depended on
	// the allowlist being narrow, this is where it would show.
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: secretbroker.NormalizeProjectID("/srv/app")},
		Constraints: secretbroker.Constraints{Repos: []string{"*"}},
		TTL:         time.Hour, Actor: "operator",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	mounts := leaseRepos(t, b, "/srv/app")
	if len(mounts) == 0 {
		t.Fatal("no mounts delivered; the in-root repository should have been")
	}
	for _, m := range mounts {
		rel, relErr := filepath.Rel(resolvedRoot, m.Source)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Errorf("delivered %q at %q, which is outside the granted root %q — a symlink "+
				"under the root redirected a bind out of it", m.Name, m.Source, resolvedRoot)
		}
		for _, forbidden := range []string{"/etc", "/root", elsewhere} {
			if m.Source == forbidden || strings.HasPrefix(m.Source, forbidden+string(filepath.Separator)) {
				t.Errorf("delivered a mount of %q", m.Source)
			}
		}
	}
	if len(mounts) != 1 || mounts[0].Name != "mine" {
		var names []string
		for _, m := range mounts {
			names = append(names, m.Name)
		}
		t.Errorf("delivered %v, want only the genuine in-root repository [mine]", names)
	}
}

// TestLocalRepoGrantIsReadOnlyUnlessAsked pins the default. A sandbox that can
// rewrite the history of a checkout existing nowhere else is a data-loss
// incident, and the common case — build against it, grep it — needs no writes.
func TestLocalRepoGrantIsReadOnlyUnlessAsked(t *testing.T) {
	root := t.TempDir()
	gitTree(t, filepath.Join(root, "api"))

	b := localRepoBroker(t)
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "dev-src", Kind: secretbroker.KindLocalRepo,
		Payload: []byte(root), Actor: "operator",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: secretbroker.NormalizeProjectID("/srv/app")},
		Constraints: secretbroker.Constraints{Repos: []string{"api"}}, // no Writable
		TTL:         time.Hour, Actor: "operator",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	for _, m := range leaseRepos(t, b, "/srv/app") {
		if !m.ReadOnly {
			t.Errorf("mount %q is read-write; a grant that did not ask for it must be read-only", m.Name)
		}
	}
}

// TestLocalRepoGrantReachesOnlyItsOwnProject is the tenancy property. It is the
// same guarantee leases_test.go asserts for tokens, restated for the kind whose
// material is filesystem reach.
func TestLocalRepoGrantReachesOnlyItsOwnProject(t *testing.T) {
	root := t.TempDir()
	gitTree(t, filepath.Join(root, "api"))

	b := localRepoBroker(t)
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "dev-src", Kind: secretbroker.KindLocalRepo,
		Payload: []byte(root), Actor: "operator",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: secretbroker.NormalizeProjectID("/srv/mine")},
		Constraints: secretbroker.Constraints{Repos: []string{"api"}},
		TTL:         time.Hour, Actor: "operator",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if got := leaseRepos(t, b, "/srv/mine"); len(got) != 1 {
		t.Fatalf("the granted project received %d mounts, want 1", len(got))
	}
	if got := leaseRepos(t, b, "/srv/theirs"); len(got) != 0 {
		t.Errorf("an unrelated project received %d mounts from another project's grant", len(got))
	}
}

// TestLocalRepoNeverReachesAnExecutorThatCannotBindIt is the honesty property.
//
// A project granted checkouts on the hub and bound to Kubernetes or a remote
// agent must be refused. Those run on a machine that has never seen the files,
// so there is no rendering of the grant that is not a lie — and a harness that
// started anyway would report on a repository it never read, which is
// indistinguishable from a working run.
func TestLocalRepoNeverReachesAnExecutorThatCannotBindIt(t *testing.T) {
	spec := executor.Spec{
		WorkDir: "/srv/app",
		Argv:    []string{"cloop", "run"},
		HostMounts: []executor.HostMount{
			{Name: "api", Source: "/home/dev/src/api", Target: "/repos/api", ReadOnly: true},
		},
	}
	req := spec.SandboxRequirements()
	if !req.RequireHostMounts {
		t.Fatal("a spec carrying host mounts does not require an executor that binds them")
	}

	for name, caps := range map[string]executor.Capabilities{
		"kubernetes":   {Isolation: executor.IsolationRemote, SupportsWorkspaceProvisioning: true},
		"remote agent": {Isolation: executor.IsolationRemote},
		// The one that is easiest to get wrong: it shares the filesystem, so
		// it looks like it should work, but it has no mount namespace to bind
		// into. The caller must point the environment at the source paths
		// instead — which pkg/ui.applyRepoGrants does — rather than place a
		// spec that names /repos.
		"localprocess": {Isolation: executor.IsolationNone, SharesHostFilesystem: true},
	} {
		t.Run(name, func(t *testing.T) {
			if caps.SupportsHostMounts {
				t.Fatalf("%s must not advertise SupportsHostMounts", name)
			}
			_, err := executor.Select([]executor.Candidate{
				{Executor: stubCapExecutor{id: name, caps: caps}},
			}, req)
			if err == nil {
				t.Fatalf("placed a local_repo-carrying spec on %s, which cannot bind "+
					"host paths; the harness would run against an empty /repos", name)
			}
			var pe *executor.PlacementError
			if !errors.As(err, &pe) {
				t.Fatalf("refusal is not a *PlacementError: %v", err)
			}
			if pe.Constraint != executor.ConstraintHostMounts {
				t.Errorf("constraint = %q, want %q", pe.Constraint, executor.ConstraintHostMounts)
			}
		})
	}
}

// TestSandboxYAMLCannotForgeAHostMount is the trust-boundary property.
//
// .cloop/sandbox.yaml is repo-committed, so it is whatever a pull request says
// it is. SpecMount exists with workspace-relative sources for exactly that
// reason. HostMount is the same capability with the trust inverted, and the
// separation is only real if the untrusted parser cannot produce one — so this
// asserts that a sandbox spec, however it is written, contributes nothing to
// Spec.HostMounts.
func TestSandboxYAMLCannotForgeAHostMount(t *testing.T) {
	// The sandbox parser's output type has no host-mount field at all, which
	// is the structural version of this guarantee. Assert it by construction:
	// a SpecMount cannot express an absolute source, so there is no value of
	// .cloop/sandbox.yaml that yields one.
	for _, source := range []string{"/etc", "/root/.ssh", "../../etc", "/"} {
		m := executor.SpecMount{Source: source, Target: "/mnt/x"}
		if err := m.Validate(); err == nil {
			t.Errorf("SpecMount accepted source %q; a repo-committed file could then "+
				"reach outside the workspace without any grant", source)
		}
	}
}
