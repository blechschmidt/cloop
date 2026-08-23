// Secret-lease plumbing for the Web UI (Task 20159).
//
// Before the broker, the orchestrator read the whole flat secret store and
// put every entry in the environment of every workload. This file replaces
// that at the UI's two spawn points: a workload now gets a lease — only the
// grants whose subject matches its executor and project, each minimized
// against its own constraints — materialised into a tmpfs directory that is
// wiped when the workload exits.
//
// Failure policy is deliberate and asymmetric:
//
//   - No CLOOP_SECRET_KEY, no broker tables, no grants: the workload starts
//     with no brokered credentials. This is the pre-broker status quo for an
//     install that has not adopted the broker, and failing the run would
//     make upgrading cloop break every project that never had secrets.
//   - A broker that exists but denies a specific grant: the denial is
//     audited and that credential is absent. The run continues, because a
//     revoked GitHub token should not stop a task that does not need GitHub.
//
// What never happens is a widening: there is no path here that falls back to
// the old "inject everything" behaviour when the broker is unavailable.

package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leaseTimeout bounds how long acquiring credentials may delay a start.
// A workload that cannot get its lease promptly starts without it rather
// than hanging an HTTP handler.
const leaseTimeout = 10 * time.Second

// liveLeases tracks the leases this hub has issued and still holds open, so
// GET /api/leases can answer "which executor is holding which credential
// right now" and POST /api/leases/{id}/revoke can take it away (Task 20171).
//
// A registry is needed because Broker.leases is per-instance and every spawn
// builds its own broker over the control-plane database. Asking a freshly
// constructed broker to list leases would truthfully report none, which is
// the worst possible answer for a panel whose job is to show outstanding
// access.
//
// It holds only leases this process issued and has not yet wiped. That is
// the honest scope: a lease's materials live in a tmpfs directory this
// process owns, so a lease it does not hold is one it could not revoke
// either, and listing it would offer a button that does nothing.
var liveLeases = &leaseRegistry{active: make(map[string]*secretLease)}

// leaseRegistry is a concurrent set of open leases keyed by lease ID.
type leaseRegistry struct {
	mu     sync.Mutex
	active map[string]*secretLease
}

// add records an open lease. Called once per successful materialisation.
func (lr *leaseRegistry) add(sl *secretLease) {
	if sl == nil || sl.lease == nil {
		return
	}
	lr.mu.Lock()
	lr.active[sl.lease.ID] = sl
	lr.mu.Unlock()
}

// remove forgets a lease without wiping it. Close calls this; callers that
// want the credentials gone want revoke instead.
func (lr *leaseRegistry) remove(id string) {
	lr.mu.Lock()
	delete(lr.active, id)
	lr.mu.Unlock()
}

// snapshot returns the currently open leases, newest first.
func (lr *leaseRegistry) snapshot() []*secretLease {
	lr.mu.Lock()
	out := make([]*secretLease, 0, len(lr.active))
	for _, sl := range lr.active {
		out = append(out, sl)
	}
	lr.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].lease.IssuedAt.After(out[j].lease.IssuedAt)
	})
	return out
}

// revoke wipes one lease's credential directory and releases it, reporting
// whether the lease was open here.
//
// The lease is dropped from the map *before* Close runs. Close calls remove
// itself, and holding the mutex across it would deadlock; doing it in this
// order also means a second concurrent revoke of the same ID reports false
// rather than racing to wipe the same directory twice.
func (lr *leaseRegistry) revoke(id string) (*secretLease, bool) {
	lr.mu.Lock()
	sl, ok := lr.active[id]
	delete(lr.active, id)
	lr.mu.Unlock()
	if !ok {
		return nil, false
	}
	sl.Close()
	return sl, true
}

// secretLease couples a lease to whichever rendering of it the bound executor
// can consume, so a caller has one thing to close.
//
// Exactly one of mount and delivery is set, and which one is a property of the
// executor rather than of the lease:
//
//   - mount: the credentials are files in this host's tmpfs, and the workload
//     will open them there. Only a driver that runs the workload directly on
//     the control plane's filesystem (localprocess) can.
//   - delivery: the credentials stayed in memory, and the driver is handed the
//     bytes to place inside the sandbox — a container's own tmpfs, a
//     Kubernetes Secret, an edge agent's confined lease directory.
//
// The asymmetry is the point. Writing plaintext into the hub's /dev/shm for a
// workload that cannot open it produces a credential file on the control plane
// that nothing ever reads, which is pure exposure.
type secretLease struct {
	broker   *secretbroker.Broker
	lease    *secretbroker.Lease
	mount    *secretbroker.Mount
	delivery *secretbroker.Delivery
	closer   func()

	// db and dir together are the durable trace of a mount: dir is the
	// directory this hub wrote plaintext into, and db holds the row saying so.
	// Both are empty for a delivery, which puts nothing on this host's disk and
	// so has nothing a restart could orphan.
	db  *statedb.DB
	dir string

	once sync.Once
}

// Env returns the environment additions for the workload, or nil.
func (sl *secretLease) Env() []string {
	if sl == nil {
		return nil
	}
	if sl.mount != nil {
		return sl.mount.Env()
	}
	return sl.delivery.Env()
}

// Mounts returns the local repositories this lease opened. Nil when the
// project holds no local_repo grant, which is the overwhelmingly common case.
func (sl *secretLease) Mounts() []secretbroker.RepoMount {
	if sl == nil {
		return nil
	}
	if sl.mount != nil {
		return sl.mount.Mounts()
	}
	return sl.delivery.Mounts()
}

// SecretFiles returns the credential files the driver has to place, with their
// contents. Empty for a hub-materialised lease, where the files already exist
// at the paths the bindings name.
func (sl *secretLease) SecretFiles() []executor.SecretFile {
	if sl == nil || sl.delivery == nil {
		return nil
	}
	raw := sl.delivery.Files()
	if len(raw) == 0 {
		return nil
	}
	out := make([]executor.SecretFile, 0, len(raw))
	for _, f := range raw {
		out = append(out, executor.SecretFile{
			LeaseID: sl.lease.ID,
			GrantID: f.GrantID,
			Dir:     f.Dir,
			Name:    f.Name,
			Mode:    f.Mode,
			Content: f.Content,
		})
	}
	return out
}

// leaseBindings returns the per-grant attribution from whichever rendering is
// in play.
func (sl *secretLease) leaseBindings() []secretbroker.LeaseBinding {
	if sl == nil {
		return nil
	}
	if sl.mount != nil {
		return sl.mount.Bindings()
	}
	return sl.delivery.Bindings()
}

// Bindings projects the mount's per-grant attribution onto the driver-facing
// executor.SecretBinding, so the executor that receives this spec can take one
// credential back mid-run instead of only at exit.
//
// The TTL rides along. A driver that loses contact with the control plane can
// then expire the material locally rather than holding it indefinitely, which
// is the difference between a lease TTL that binds the whole system and one
// that binds only the hub.
func (sl *secretLease) Bindings() []executor.SecretBinding {
	if sl == nil || sl.lease == nil {
		return nil
	}
	raw := sl.leaseBindings()
	out := make([]executor.SecretBinding, 0, len(raw))
	for _, b := range raw {
		out = append(out, executor.SecretBinding{
			LeaseID:    sl.lease.ID,
			GrantID:    b.GrantID,
			SecretName: b.SecretName,
			Kind:       string(b.Kind),
			EnvKeys:    b.EnvKeys,
			Files:      b.Files,
			Dir:        b.Dir,
			Egress:     b.Kind == secretbroker.KindEgressProxy,
			ExpiresAt:  sl.lease.ExpiresAt,
		})
	}
	return out
}

// ExecutorID returns the executor this lease was issued to, or "".
func (sl *secretLease) ExecutorID() string {
	if sl == nil || sl.lease == nil {
		return ""
	}
	return sl.lease.ExecutorID
}

// Close wipes the credential directory and releases the lease. Idempotent,
// so it is safe both in a defer and on an explicit early return.
func (sl *secretLease) Close() {
	if sl == nil {
		return
	}
	sl.once.Do(func() {
		if sl.lease != nil {
			liveLeases.remove(sl.lease.ID)
		}
		if sl.mount != nil {
			err := sl.mount.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "ui: wipe secret lease: %v\n", err)
			}
			// Clear the durable record only once the wipe has actually
			// succeeded. Deleting it unconditionally would discard the one
			// thing that lets the next startup finish the job — a failed wipe
			// is exactly the case the sweep exists for, and forgetting the
			// directory because we tried and failed to clean it would turn a
			// recoverable orphan into a permanent one.
			if err == nil && sl.db != nil && sl.dir != "" {
				if derr := sl.db.DeleteSecretLeaseDir(sl.dir); derr != nil {
					fmt.Fprintf(os.Stderr, "ui: clear lease directory record %s: %v\n", sl.dir, derr)
				}
			}
		}
		if sl.delivery != nil {
			// Nothing to unlink — the plaintext never left this process — but
			// the buffers holding it are zeroed rather than left for the
			// garbage collector, so a heap dump taken an hour later does not
			// contain a credential this hub merely relayed.
			_ = sl.delivery.Close()
		}
		if sl.broker != nil && sl.lease != nil {
			sl.broker.Release(sl.lease.ID)
		}
		if sl.closer != nil {
			sl.closer()
		}
	})
}

// acquireSecretLease leases the credentials for a workload and renders them
// for the executor that will run it.
//
// It returns nil (not an error) when there is nothing to deliver, so callers
// can treat "no secrets" and "broker not configured" identically: both mean
// "start the workload with its ordinary environment".
//
// The executor is a parameter rather than an ID because *where* the plaintext
// goes is its decision. See secretLease: a lease bound for an isolated sandbox
// is never written to this host at all.
func acquireSecretLease(controlPlaneDir, workDir string, ex executor.Executor) *secretLease {
	executorID := ""
	if ex != nil {
		executorID = ex.ID()
	}
	broker, db, closeDB, err := openUIBrokerDB(controlPlaneDir)
	if err != nil {
		// Not configured is the common case and is not worth a log line on
		// every run; a genuine failure is.
		if !isBrokerUnconfigured(err) {
			fmt.Fprintf(os.Stderr, "ui: secret broker unavailable: %v\n", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), leaseTimeout)
	defer cancel()

	lease, err := broker.LeaseFor(ctx, secretbroker.Requester{
		ExecutorID: executorID,
		ProjectID:  workDir,
	}, "ui")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: lease secrets for %s: %v\n", workDir, err)
		closeDB()
		return nil
	}
	if lease.Empty() {
		broker.Release(lease.ID)
		closeDB()
		return nil
	}

	sl := &secretLease{broker: broker, lease: lease, closer: closeDB}
	if ex != nil && ex.Capabilities().SecretFilesFromHostPath {
		// Name the directory, record the intent, *then* write the plaintext.
		//
		// The ordering is what makes an orphan recoverable. Materialize used to
		// pick its own directory and the only record of it was the goroutine
		// waiting to wipe it, so a hub killed at any point before that
		// goroutine ran left credential files in /dev/shm that nothing — not
		// the TTL janitor, which sweeps an in-memory registry, and not the next
		// startup — would ever collect. With the row written first, a crash
		// anywhere after this point leaves a trace the startup sweep reconciles.
		dir, derr := secretbroker.NewLeaseDirPath("")
		if derr != nil {
			fmt.Fprintf(os.Stderr, "ui: choose lease directory: %v\n", derr)
			broker.Release(lease.ID)
			closeDB()
			return nil
		}
		row := statedb.SecretLeaseDirRow{
			Dir:         dir,
			LeaseID:     lease.ID,
			ExecutorID:  executorID,
			ProjectPath: workDir,
			ExpiresAt:   lease.ExpiresAt,
		}
		if err := db.PutSecretLeaseDir(row); err != nil {
			// Fail closed. A credential this hub cannot account for is one it
			// cannot promise to destroy, and running the task without secrets
			// is a visible, diagnosable failure — where writing the plaintext
			// anyway would be an invisible one.
			fmt.Fprintf(os.Stderr,
				"ui: refusing to materialize lease %s: cannot record its directory, "+
					"so a restart could not clean it up: %v\n", lease.ID, err)
			broker.Release(lease.ID)
			closeDB()
			return nil
		}
		mount, merr := lease.MaterializeAt(dir)
		if merr != nil {
			fmt.Fprintf(os.Stderr, "ui: materialize secret lease: %v\n", merr)
			// The directory was never populated, so drop the row rather than
			// leaving the next startup an orphan to chase.
			if derr := db.DeleteSecretLeaseDir(dir); derr != nil {
				fmt.Fprintf(os.Stderr, "ui: clear lease directory record %s: %v\n", dir, derr)
			}
			broker.Release(lease.ID)
			closeDB()
			return nil
		}
		sl.mount = mount
		sl.db = db
		sl.dir = dir
	} else {
		// The sandbox will find its credentials here; the driver is
		// responsible for putting them there. Nothing is written on this host,
		// which is why a hub can broker a kubeconfig to a Kubernetes executor
		// or a PAT to an edge device without ever holding the plaintext on a
		// filesystem of its own.
		delivery, derr := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
		if derr != nil {
			fmt.Fprintf(os.Stderr, "ui: prepare secret lease: %v\n", derr)
			broker.Release(lease.ID)
			closeDB()
			return nil
		}
		sl.delivery = delivery
	}
	// Registered only once the credentials actually exist on disk: every
	// earlier return path has already released the lease, and a registry
	// entry for one of those would offer a revoke button for a lease that
	// was never held.
	liveLeases.add(sl)
	return sl
}

// openUIBroker builds a broker over the control plane's database.
//
// Grants live in the control plane's own database rather than each project's,
// for the same reason executor bindings do (see lookupProjectExecutor): a
// project pinned to a remote executor may have no readable local .cloop
// directory, and a tenant must not be able to grant itself credentials by
// writing to a database it owns.
func openUIBroker(controlPlaneDir string) (*secretbroker.Broker, func(), error) {
	broker, _, closeDB, err := openUIBrokerDB(controlPlaneDir)
	return broker, closeDB, err
}

// openUIBrokerDB is openUIBroker plus the underlying database handle, for the
// one caller that also needs to write to it: acquireSecretLease records where
// it is about to put plaintext (see migrations/0022_secret_lease_dirs.sql) and
// clears that row once it has wiped.
//
// The handle stays valid until closeDB runs, which secretLease.Close calls
// last — after the row delete, so the delete still has a live connection.
func openUIBrokerDB(controlPlaneDir string) (*secretbroker.Broker, *statedb.DB, func(), error) {
	if controlPlaneDir == "" {
		return nil, nil, nil, fmt.Errorf("no control plane directory")
	}
	dbPath := state.DBPath(controlPlaneDir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, nil, fmt.Errorf("no state database: %w", err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, nil, err
	}
	store, err := secretstore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}
	return broker, db, func() { _ = db.Close() }, nil
}

// isBrokerUnconfigured reports whether the broker simply is not set up on
// this install, as opposed to being set up and broken. A missing state
// database or an unset CLOOP_SECRET_KEY are the ordinary "not adopted yet"
// states and should not produce a log line on every run.
func isBrokerUnconfigured(err error) bool {
	if err == nil {
		return false
	}
	return os.IsNotExist(err) ||
		errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, secretbroker.ErrNoKey)
}

// applyLease appends a lease's environment — and, for an isolating executor,
// its credential files — to a spec.
//
// Spec.Env nil means "inherit the control plane's environment", which is the
// behaviour every existing UI spawn relies on. Adding lease variables means
// we must now materialise that inheritance explicitly, or the workload would
// lose everything it used to get from the server's environment.
//
// The refusal is the part worth reading. A lease can carry files, and files
// are how the interesting grants enforce themselves: a repository-scoped
// github_pat ships a credential helper, a token file and a gitconfig, and
// deliberately exports no bare GITHUB_TOKEN, because an environment variable
// is unscoped by construction. An executor that cannot receive files therefore
// receives *nothing usable* from such a grant while still receiving the
// variables that name the missing paths — a sandbox that starts, runs, and
// fails to authenticate to git with nothing in its transcript pointing at the
// cause. So the combination is refused here, typed as ErrUnsupported, before
// anything starts.
func applyLease(spec executor.Spec, ex executor.Executor, sl *secretLease) (executor.Spec, error) {
	env := sl.Env()
	if len(env) == 0 {
		return spec, nil
	}
	// Attribution travels with the material. Without it the executor sees an
	// environment it cannot take anything back out of, and a revocation could
	// only ever kill the workload — see pkg/executor.SecretBinding.
	spec.Secrets = append(spec.Secrets, sl.Bindings()...)
	spec.SecretFiles = append(spec.SecretFiles, sl.SecretFiles()...)

	if spec.NeedsSecretFiles() && ex != nil && !ex.Capabilities().SupportsSecretFiles {
		return spec, fmt.Errorf(
			"%w: executor %s (%s) cannot deliver credential files to the workload, but this "+
				"project's grants for %s deliver %s as files. Placing the workload there would "+
				"leave it holding paths it cannot open and, for a repository-scoped github_pat, "+
				"no token at all. Bind the project to a container or Kubernetes executor, or "+
				"upgrade the remote agent",
			executor.ErrUnsupported, ex.ID(), ex.Kind(),
			strings.Join(sl.lease.SecretNames(), ", "), describeSecretFileKinds(sl))
	}

	base := spec.Env
	if base == nil {
		base = os.Environ()
	}
	merged := make([]string, 0, len(base)+len(env))
	merged = append(merged, base...)
	merged = append(merged, env...)
	spec.Env = merged
	return spec, nil
}

// describeSecretFileKinds names the credential kinds in this lease that are
// delivered as files, so a refusal says which grant is the problem rather than
// leaving the operator to work it out from a list of every secret they hold.
func describeSecretFileKinds(sl *secretLease) string {
	seen := make(map[string]struct{})
	var kinds []string
	for _, b := range sl.leaseBindings() {
		if len(b.Files) == 0 {
			continue
		}
		k := string(b.Kind)
		if k == "" {
			k = "unknown"
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		kinds = append(kinds, k)
	}
	if len(kinds) == 0 {
		return "credentials"
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ", ")
}

// applyRepoGrants attaches the local repositories a lease opened to the spec,
// in the form the bound executor can actually honour.
//
// The same grant reaches a workload three different ways, and which one is
// correct is a property of the driver, not of the grant:
//
//   - A driver that can bind (container, Kata) gets Spec.HostMounts, and the
//     workload finds the repositories under /repos.
//   - A driver that shares the hub's filesystem but has no mount namespace to
//     bind into (localprocess) gets no mounts at all, because the repositories
//     are already visible at their own paths. The environment names those
//     paths instead.
//   - Anything else — Kubernetes, a remote agent — is refused. Those run on a
//     machine that has never seen these files, so there is no rendering of the
//     grant that is not a lie, and a harness that started anyway would report
//     that the repository is empty.
//
// The refusal is the interesting case and it is deliberately a hard error
// rather than a warning. This is the point where "I granted my checkouts to
// this project" and "I bound this project to a remote sandbox" turn out to be
// incompatible, and the person who needs to know is the one who just clicked
// Run.
func applyRepoGrants(spec executor.Spec, ex executor.Executor, sl *secretLease) (executor.Spec, error) {
	mounts := sl.Mounts()
	if len(mounts) == 0 {
		return spec, nil
	}
	caps := ex.Capabilities()

	// Path variables are added here rather than by the broker because only
	// this function knows which of the two answers is true. The names of the
	// repositories (CLOOP_LOCAL_REPOS) came with the material and are already
	// on the spec; these say where they landed.
	env := make([]string, 0, len(mounts)+1)
	bind := caps.SupportsHostMounts

	if !bind && !caps.SharesHostFilesystem {
		names := make([]string, 0, len(mounts))
		for _, m := range mounts {
			names = append(names, m.Name)
		}
		return spec, fmt.Errorf(
			"%w: executor %s (%s) cannot receive repositories from the control-plane host, "+
				"but this project holds a local_repo grant for %s. Bind the project to a "+
				"container or Kata executor running on the hub, or publish the repositories "+
				"over https and grant a github_pat instead",
			executor.ErrInvalidSpec, ex.ID(), ex.Kind(), strings.Join(names, ", "))
	}

	// Two grants can legitimately name the same repository — /a/api and /b/api
	// are different trees with the same basename — and they would collide at
	// /repos/api. That must not be a hard failure: it would fail *every* run of
	// a project whose grants happen to overlap, at start time, until an
	// operator noticed and revoked one. The first grant wins (grant order is
	// stable) and the loser is named on stderr, which is recoverable; a run
	// that cannot start is not.
	claimed := make(map[string]string, len(mounts))
	kept := make([]secretbroker.RepoMount, 0, len(mounts))
	for _, m := range mounts {
		if prev, dup := claimed[m.Name]; dup {
			fmt.Fprintf(os.Stderr,
				"ui: local_repo grants collide on %q (%s and %s); using %s. "+
					"Rename one checkout or narrow one grant's --repos.\n",
				m.Name, prev, m.Source, prev)
			continue
		}
		claimed[m.Name] = m.Source
		kept = append(kept, m)
	}

	// A repository whose name has no unambiguous variable rendering gets no
	// variable, and so does one that would collide with another's. "my-api"
	// and "my.api" both fold to CLOOP_LOCAL_REPO_MY_API; emitting both would
	// mean a workload read whichever was appended last. Both are still mounted
	// and both are still in CLOOP_LOCAL_REPOS — only the shortcut is withheld.
	keyOwners := make(map[string]int, len(kept))
	for _, m := range kept {
		if k := repoEnvKey(m.Name); k != "" {
			keyOwners[k]++
		}
	}

	for _, m := range kept {
		path := m.Source
		if bind {
			path = m.Target
			spec.HostMounts = append(spec.HostMounts, executor.HostMount{
				Name:     m.Name,
				Source:   m.Source,
				Target:   m.Target,
				ReadOnly: m.ReadOnly,
			})
		}
		if key := repoEnvKey(m.Name); key != "" && keyOwners[key] == 1 {
			env = append(env, key+"="+path)
		}
	}
	if bind {
		// Validate the assembled list, not just the entries. Dedup above has
		// already removed the collisions this would otherwise catch, so a
		// failure here means something the caller cannot fix by renaming — and
		// is worth refusing.
		if err := executor.ValidateHostMounts(spec.HostMounts); err != nil {
			return spec, err
		}
		env = append(env, "CLOOP_LOCAL_REPO_ROOT="+secretbroker.SandboxRepoRoot)
	} else {
		// The shares-the-filesystem case. The repositories are reachable at
		// their own paths, which also means a read-only grant is not enforced
		// here: the harness runs as the hub user and can write to them however
		// the grant was written. Say so rather than letting the dashboard's
		// "read-only" badge be believed — this driver has the whole filesystem
		// anyway, which is why it is the one an operator turns off first.
		for _, m := range kept {
			if m.ReadOnly {
				fmt.Fprintf(os.Stderr,
					"ui: executor %s shares the hub filesystem, so the read-only local_repo "+
						"grant on %q is not enforced; bind a container executor to enforce it\n",
					ex.ID(), m.Name)
			}
		}
	}

	base := spec.Env
	if base == nil {
		base = os.Environ()
	}
	spec.Env = append(append(make([]string, 0, len(base)+len(env)), base...), env...)
	return spec, nil
}

// repoEnvKey renders a repository name as an environment variable name, or ""
// when the name contains anything that has no rendering at all.
//
// It does not detect collisions — two names can render to the same key, and
// deciding what to do about that needs the whole set. The caller counts owners
// per key and withholds any key claimed more than once.
func repoEnvKey(name string) string {
	var b strings.Builder
	b.WriteString("CLOOP_LOCAL_REPO_")
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune('_')
		default:
			return ""
		}
	}
	return b.String()
}
