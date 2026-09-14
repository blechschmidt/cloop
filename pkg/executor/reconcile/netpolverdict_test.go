package reconcile

// netpolverdict_test.go covers the durability half of the enforcement gate.
//
// It matters for a reason that is easy to miss: the probe is expensive and
// interactive — three Pods, up to three minutes, an operator watching — so a
// verdict that does not survive a hub restart means the capability silently
// disappears at the next deploy and every egress-scoped project starts being
// refused with no configuration having changed.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func verdictDB(t *testing.T) (*statedb.DB, string) {
	t.Helper()
	dir := t.TempDir()
	// state.DBPath puts the database under .cloop/, which a bare temp dir does
	// not have — the same shape openSweepDB uses.
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, dir
}

func sampleVerdict() kubernetes.ProbeVerdict {
	return kubernetes.ProbeVerdict{
		Enforced:     true,
		ObservedAt:   time.Now().UTC().Truncate(time.Second),
		Namespace:    "cloop",
		ExecutorID:   "k8s-prod",
		Detail:       "a Pod reached the target with no policy and could not with one",
		ProbeVersion: kubernetes.CurrentProbeVersion,
	}
}

// TestVerdictRoundTrip: what the probe wrote is what the next hub reads.
func TestVerdictRoundTrip(t *testing.T) {
	db, _ := verdictDB(t)
	want := sampleVerdict()

	if err := SaveNetworkPolicyVerdict(db, "k8s-prod", want); err != nil {
		t.Fatalf("SaveNetworkPolicyVerdict: %v", err)
	}
	got, err := LoadNetworkPolicyVerdict(db, "k8s-prod")
	if err != nil {
		t.Fatalf("LoadNetworkPolicyVerdict: %v", err)
	}
	if got.Enforced != want.Enforced || got.Namespace != want.Namespace ||
		got.ExecutorID != want.ExecutorID || got.ProbeVersion != want.ProbeVersion {
		t.Errorf("round trip lost fields:\n got %+v\nwant %+v", got, want)
	}
	if !got.ObservedAt.Equal(want.ObservedAt) {
		t.Errorf("ObservedAt = %s, want %s — a verdict whose timestamp does not survive cannot "+
			"be expired", got.ObservedAt, want.ObservedAt)
	}
	// And it resolves to the capability, which is the only thing it is for.
	status, _ := kubernetes.NetworkPolicyEnforcement{Verdict: got}.Resolve("k8s-prod", time.Now())
	if !status.Enforced() {
		t.Errorf("a round-tripped proof resolves to %q, which refuses the capability", status)
	}
}

// TestVerdictIsScopedPerExecutor: two clusters, two answers, no bleed.
func TestVerdictIsScopedPerExecutor(t *testing.T) {
	db, _ := verdictDB(t)

	good := sampleVerdict()
	bad := sampleVerdict()
	bad.Enforced = false
	bad.ExecutorID = "k8s-legacy"

	if err := SaveNetworkPolicyVerdict(db, "k8s-prod", good); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := SaveNetworkPolicyVerdict(db, "k8s-legacy", bad); err != nil {
		t.Fatalf("save: %v", err)
	}

	gotProd, _ := LoadNetworkPolicyVerdict(db, "k8s-prod")
	gotLegacy, _ := LoadNetworkPolicyVerdict(db, "k8s-legacy")
	if !gotProd.Enforced {
		t.Error("the enforcing cluster's verdict was overwritten by the other one")
	}
	if gotLegacy.Enforced {
		t.Error("the non-enforcing cluster inherited the other one's proof — which would grant a " +
			"capability on a cluster that was measured not to have it")
	}
}

// TestLoadMissingVerdictIsNotAnError.
//
// Absence is the state every deployment starts in, and it already fails closed:
// an unrecorded verdict resolves to unverified. Making it an error would mean a
// hub refusing to start over a record whose only function is to grant.
func TestLoadMissingVerdictIsNotAnError(t *testing.T) {
	db, _ := verdictDB(t)
	got, err := LoadNetworkPolicyVerdict(db, "never-probed")
	if err != nil {
		t.Fatalf("LoadNetworkPolicyVerdict on a fresh database: %v", err)
	}
	if got.Recorded() {
		t.Errorf("a never-probed executor has a verdict: %+v", got)
	}
	status, _ := kubernetes.NetworkPolicyEnforcement{Verdict: got}.Resolve("never-probed", time.Now())
	if status.Enforced() {
		t.Error("an absent verdict grants the capability")
	}
}

// TestCorruptVerdictReadsAsAbsent.
//
// The failure direction is the whole argument: a record that will not parse
// must deny, and it must deny without taking the hub down with it.
func TestCorruptVerdictReadsAsAbsent(t *testing.T) {
	db, _ := verdictDB(t)
	if err := db.SetHubMeta(NetworkPolicyVerdictKey("k8s-prod"), "{not json"); err != nil {
		t.Fatalf("SetHubMeta: %v", err)
	}
	got, err := LoadNetworkPolicyVerdict(db, "k8s-prod")
	if err != nil {
		t.Fatalf("a corrupt record produced an error rather than a denial: %v", err)
	}
	if got.Recorded() {
		t.Errorf("a corrupt record parsed into a usable verdict: %+v", got)
	}
}

// TestSaveRefusesAnUnobservedVerdict.
//
// Recorded() is what every reader uses to mean "a probe actually ran". Writing
// a zero-valued verdict would store something that reads as evidence, is not,
// and is indistinguishable from having written nothing at all.
func TestSaveRefusesAnUnobservedVerdict(t *testing.T) {
	db, _ := verdictDB(t)
	if err := SaveNetworkPolicyVerdict(db, "k8s-prod", kubernetes.ProbeVerdict{Enforced: true}); err == nil {
		t.Fatal("saved a verdict with no observation time")
	}
	if err := SaveNetworkPolicyVerdict(db, "", sampleVerdict()); err == nil {
		t.Fatal("saved a verdict with no executor id")
	}
}

// TestForgetVerdictReturnsToUnverified is the operator's escape hatch after a
// CNI change, and it must not need them to know how the record is stored.
func TestForgetVerdictReturnsToUnverified(t *testing.T) {
	db, _ := verdictDB(t)
	if err := SaveNetworkPolicyVerdict(db, "k8s-prod", sampleVerdict()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := ForgetNetworkPolicyVerdict(db, "k8s-prod"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	got, _ := LoadNetworkPolicyVerdict(db, "k8s-prod")
	if got.Recorded() {
		t.Errorf("the verdict survived being forgotten: %+v", got)
	}
	// Idempotent: forgetting what is not there is what the caller asked for.
	if err := ForgetNetworkPolicyVerdict(db, "k8s-prod"); err != nil {
		t.Errorf("forgetting an absent verdict errored: %v", err)
	}
}

// TestLoadFromDirTolerantOfAMissingDatabase.
//
// The read happens during executor reconciliation, which runs on CLI
// invocations in directories that have never been a hub. A hard failure there
// would turn "no database" into "no executors".
func TestLoadFromDirTolerantOfAMissingDatabase(t *testing.T) {
	got, err := LoadNetworkPolicyVerdictFromDir(filepath.Join(t.TempDir(), "nope"), "k8s-prod")
	if err != nil {
		t.Fatalf("LoadNetworkPolicyVerdictFromDir on a nonexistent dir: %v", err)
	}
	if got.Recorded() {
		t.Errorf("got a verdict from nowhere: %+v", got)
	}
}

// TestLoadFromDirReadsWhatWasSaved closes the loop the hub actually walks:
// `cloop hub doctor --probe-network-policy` writes, the next boot reads.
func TestLoadFromDirReadsWhatWasSaved(t *testing.T) {
	db, dir := verdictDB(t)
	if err := SaveNetworkPolicyVerdict(db, "k8s-prod", sampleVerdict()); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Close first: a second handle on the same file is exactly what the next
	// boot has, and WAL means an uncommitted write would not be visible.
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := LoadNetworkPolicyVerdictFromDir(dir, "k8s-prod")
	if err != nil {
		t.Fatalf("LoadNetworkPolicyVerdictFromDir: %v", err)
	}
	if !got.Enforced || !got.Recorded() {
		t.Errorf("the verdict did not survive a reopen: %+v", got)
	}
}
