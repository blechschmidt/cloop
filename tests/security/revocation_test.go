package security

// Guarantee 11: material handed to an executor can be taken back mid-run, and
// nothing writes it somewhere a revocation cannot reach.
//
// The second half is the one that is easy to get wrong. Revocation is a
// property of *every* copy of a credential, so a copy written to a place with
// no revoke path — a database row, a log, a serialised spec — silently voids
// the guarantee no matter how well the online path works. There is no frame
// that reaches a row in SQLite.
//
// The per-component behaviour (files unlinked, tasks killed, acks replayed) is
// asserted end-to-end in pkg/executor/remote and pkg/executor/agent, against a
// real agent running a real process. What is asserted here is the part that
// spans components and would otherwise belong to nobody.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leasedCredential is the canary. It is written into a dispatched spec and
// must not survive into any persisted or serialised form.
const leasedCredential = "ghp_persisted_canary_must_not_survive"

// dispatchedSpec is what pkg/ui hands an executor after applying a lease: the
// credential in Env, and a binding naming which variable it came from.
func dispatchedSpec() executor.Spec {
	return executor.Spec{
		WorkDir: "/srv/project",
		Argv:    []string{"cloop", "run"},
		Env: []string{
			"PATH=/usr/bin",
			"GITHUB_TOKEN=" + leasedCredential,
			"HOME=/home/cloop",
		},
		Secrets: []executor.SecretBinding{{
			LeaseID:    "lease_canary",
			GrantID:    "grant_canary",
			SecretName: "github-ci",
			Kind:       "github_pat",
			EnvKeys:    []string{"GITHUB_TOKEN"},
			ExpiresAt:  time.Now().Add(15 * time.Minute),
		}},
	}
}

// TestDispatchedSpecNeverPersistsLeasedCredentials is the durability half of
// the revocation guarantee.
//
// A dispatched spec is recorded in `executor_sessions` so a failed-over
// workload can be re-dispatched. Recorded verbatim, it would write a
// fifteen-minute credential into a table that outlives the lease, survives the
// revocation meant to withdraw it, and is copied into every backup of the
// control-plane database.
//
// Only the variables the lease contributed are redacted. The operator's own
// environment is not the broker's to touch, and blanking it would break
// failover for a reason unrelated to secrets.
func TestDispatchedSpecNeverPersistsLeasedCredentials(t *testing.T) {
	store := newSessionStore(t)

	sess := executor.Session{
		ID:          "sess_canary",
		ExecutorID:  "edge-01",
		HandleID:    "handle_canary",
		ProjectPath: "/srv/project",
		ClaimToken:  "tok",
		Attempt:     1,
		StartedAt:   time.Now(),
		Spec:        dispatchedSpec(),
	}
	if err := store.OpenSession(sess); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	running, err := store.RunningSessions("edge-01")
	if err != nil {
		t.Fatalf("RunningSessions: %v", err)
	}
	if len(running) != 1 {
		t.Fatalf("RunningSessions returned %d rows, want 1", len(running))
	}
	stored := running[0]

	joined := strings.Join(stored.Spec.Env, "\n")
	if strings.Contains(joined, leasedCredential) {
		t.Errorf("a leased credential was persisted into executor_sessions.\n"+
			"  A row in SQLite outlives its lease and no revoke frame can reach it.\n"+
			"  Redact leased Env values in executorstore.marshalSpec.\n"+
			"  stored env: %q", joined)
	}
	// The variable survives, marked — "this was withdrawn" and "this was never
	// set" call for different responses on failover.
	if !strings.Contains(joined, "GITHUB_TOKEN=") {
		t.Errorf("the variable itself should survive so failover can see it was redacted; got %q", joined)
	}
	// Everything the lease did not contribute is untouched.
	for _, want := range []string{"PATH=/usr/bin", "HOME=/home/cloop"} {
		if !strings.Contains(joined, want) {
			t.Errorf("redaction widened past the lease's own keys: %q is missing from %q", want, joined)
		}
	}
	if len(stored.Spec.Argv) != 2 {
		t.Errorf("redaction must not disturb the rest of the spec; argv = %v", stored.Spec.Argv)
	}
}

// TestSecretBindingCarriesNoMaterial pins the shape of the attribution that
// travels with a workload.
//
// SecretBinding is the one struct that crosses every boundary at once: it goes
// into a spec, over the wire in a start frame, into `executor_sessions`, and
// into audit rows. If it ever gains a field capable of holding a value, the
// credential follows it into all four at the same time — so the check is on
// the serialised form rather than on any single call site.
func TestSecretBindingCarriesNoMaterial(t *testing.T) {
	spec := dispatchedSpec()
	// Populate every field, including the ones a real binding often leaves
	// empty, so a value-shaped field cannot hide behind omitempty.
	spec.Secrets[0].Files = []string{"/dev/shm/cloop-lease-abc/token"}
	spec.Secrets[0].Dir = "/dev/shm/cloop-lease-abc"
	spec.Secrets[0].Egress = true

	encoded, err := json.Marshal(spec.Secrets[0])
	if err != nil {
		t.Fatalf("marshal binding: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal binding: %v", err)
	}

	// A closed, reviewed set. Adding a key here should require reading the
	// question "can this hold a credential?" and answering it.
	allowed := map[string]bool{
		"lease_id": true, "grant_id": true, "secret_name": true, "kind": true,
		"env_keys": true, "files": true, "dir": true, "egress": true,
		"expires_at": true,
	}
	for key := range decoded {
		if !allowed[key] {
			t.Errorf("SecretBinding gained an unreviewed JSON field %q.\n"+
				"  This struct is serialised into start frames, executor_sessions and audit rows.\n"+
				"  If it can hold a value, the credential reaches all three at once.", key)
		}
	}
	// env_keys are names. A "K=V" entry here would be a credential in a field
	// nobody thinks of as one.
	for _, k := range spec.Secrets[0].EnvKeys {
		if strings.Contains(k, "=") {
			t.Errorf("EnvKeys must carry names, not assignments; got %q", k)
		}
	}
	if strings.Contains(string(encoded), leasedCredential) {
		t.Errorf("the binding serialised a credential: %s", encoded)
	}
}

// TestRevocationStatesAreDistinct guards the honesty property the UI depends
// on.
//
// "Sent" is not "landed". If these ever collapse — if an unreachable agent
// were reported as revoked because the frame was written — an operator could
// close an incident on a credential that is still live on a machine the hub
// cannot reach. The distinction is only useful if it is preserved all the way
// to the response.
func TestRevocationStatesAreDistinct(t *testing.T) {
	states := []remote.RevokeState{
		remote.RevokeStatePending,
		remote.RevokeStateRevoked,
		remote.RevokeStateUnreachable,
		remote.RevokeStateFailed,
	}
	seen := map[remote.RevokeState]bool{}
	for _, s := range states {
		if seen[s] {
			t.Fatalf("two revocation states share the value %q; the UI cannot tell them apart", s)
		}
		seen[s] = true
	}

	// Exactly one state may be terminal. A terminal "unreachable" would stop
	// the reconnect replay; a non-terminal "revoked" would re-send forever.
	terminal := 0
	for _, s := range states {
		if s.Terminal() {
			terminal++
			if s != remote.RevokeStateRevoked {
				t.Errorf("%q must not be terminal: the material is still out there", s)
			}
		}
	}
	if terminal != 1 {
		t.Errorf("exactly one revocation state may be terminal, got %d", terminal)
	}
}

// TestRevocableMaterialRequiresARevocableAgent is the placement rule, asserted
// against the version constants rather than a live session.
//
// The promise "revoking this lease takes the credential away" must not depend
// on which devices in a fleet happen to be up to date. An agent that cannot
// honour the frame must not receive material that depends on it.
func TestRevocableMaterialRequiresARevocableAgent(t *testing.T) {
	if remote.SupportsRevocation(remote.MinRevocationVersion - 1) {
		t.Error("a protocol below MinRevocationVersion must not claim revocation support")
	}
	if !remote.SupportsRevocation(remote.MinRevocationVersion) {
		t.Error("MinRevocationVersion must itself support revocation")
	}
	if remote.ProtocolVersion < remote.MinRevocationVersion {
		t.Errorf("ProtocolVersion (%d) is below MinRevocationVersion (%d): "+
			"no agent could ever negotiate revocation",
			remote.ProtocolVersion, remote.MinRevocationVersion)
	}

	// A binding with nothing delivered is not revocable and must not trigger
	// the placement refusal — otherwise an empty lease would strand work on
	// older agents for no benefit.
	empty := executor.Spec{Argv: []string{"true"}, Secrets: []executor.SecretBinding{{LeaseID: "l"}}}
	if got := empty.RevocableSecrets(); len(got) != 0 {
		t.Errorf("a binding that delivered nothing must not count as revocable; got %v", got)
	}
	// And one with no lease ID cannot be targeted by a revoke, so it must not
	// pass as revocable either.
	orphan := executor.Spec{Argv: []string{"true"}, Secrets: []executor.SecretBinding{{EnvKeys: []string{"X"}}}}
	if got := orphan.RevocableSecrets(); len(got) != 0 {
		t.Errorf("a binding with no lease id cannot be revoked; got %v", got)
	}
	if got := dispatchedSpec().RevocableSecrets(); len(got) != 1 {
		t.Errorf("a real leased spec must report its revocable binding; got %v", got)
	}
}

// newSessionStore returns a real SQLite-backed scheduling store.
//
// Real rather than in-memory because the redaction under test happens on the
// way *into* the row: a fake store that kept the struct in a map would hold
// the original pointer and pass while production wrote plaintext to disk.
func newSessionStore(t *testing.T) *executorstore.Scheduler {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		t.Fatalf("executorstore.NewScheduler: %v", err)
	}
	return sched
}
