package statedb

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

func isolationRow(id, runtime string, verdict isolationprobe.Kind, at time.Time) IsolationEvidenceRow {
	return IsolationEvidenceRow{
		IsolationRecord: executor.IsolationRecord{
			ExecutorID: id, Runtime: runtime, Claim: executor.IsolationClaim(runtime),
			Verdict: verdict, Detail: "the sandbox's kernel is the host's own", ProbedAt: at,
			Point: executor.ProbePointReconcile,
		},
		Engine: "docker", Image: "ghcr.io/blechschmidt/cloop-harness:latest",
		Evidence: `{"release":"6.8.0-79-generic"}`, ProbedBy: "member-a",
	}
}

// TestIsolationEvidenceKeepsTheVerdictThroughAFailedProbe: a probe that cannot
// run records that it tried and leaves the last verdict standing, so breaking
// the probe is not a way to clear a contradiction.
func TestIsolationEvidenceKeepsTheVerdictThroughAFailedProbe(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 17, 5, 0, 0, 0, time.UTC)

	if err := db.RecordIsolationProbe(isolationRow("sgx", "kata", isolationprobe.KindHostKernel, at)); err != nil {
		t.Fatal(err)
	}
	fail := IsolationEvidenceRow{IsolationRecord: executor.IsolationRecord{
		ExecutorID: "sgx", Runtime: "kata", Claim: isolationprobe.KindVM,
		AttemptedAt: at.Add(time.Hour), Error: "the device went offline", Point: executor.ProbePointDaily,
	}, ProbedBy: "member-b"}
	if err := db.RecordIsolationProbeFailure(fail); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.IsolationEvidence("sgx", "kata")
	if err != nil || !ok {
		t.Fatalf("IsolationEvidence = %v, %v", ok, err)
	}
	if got.Verdict != isolationprobe.KindHostKernel || !got.ProbedAt.Equal(at) || got.Detail == "" {
		t.Fatalf("the failed attempt replaced the verdict: %+v", got)
	}
	if got.Error != "the device went offline" || !got.AttemptedAt.Equal(at.Add(time.Hour)) ||
		got.Point != executor.ProbePointDaily || got.ProbedBy != "member-b" {
		t.Fatalf("the failed attempt was not recorded: %+v", got)
	}
	if got.Status() != isolationprobe.StatusContradicted {
		t.Errorf("Status = %s, want contradicted", got.Status())
	}

	// A probe that runs again replaces the verdict and clears the error.
	if err := db.RecordIsolationProbe(isolationRow("sgx", "kata", isolationprobe.KindVM, at.Add(2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	got, _, _ = db.IsolationEvidence("sgx", "kata")
	if got.Verdict != isolationprobe.KindVM || got.Error != "" || got.Status() != isolationprobe.StatusVerified {
		t.Fatalf("after a probe that ran: %+v", got)
	}
}

// TestIsolationEvidenceIsPerRuntime: evidence about one runtime says nothing
// about another, and a first attempt that fails creates an unknown record.
func TestIsolationEvidenceIsPerRuntime(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 17, 5, 0, 0, 0, time.UTC)
	if err := db.RecordIsolationProbe(isolationRow("sgx", "runsc", isolationprobe.KindUserspaceKernel, at)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.IsolationEvidence("sgx", "kata"); ok {
		t.Fatal("a runsc verdict answered for kata")
	}
	if err := db.RecordIsolationProbeFailure(IsolationEvidenceRow{IsolationRecord: executor.IsolationRecord{
		ExecutorID: "sgx", Runtime: "kata", Claim: isolationprobe.KindVM, AttemptedAt: at,
	}}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.IsolationEvidence("sgx", "kata")
	if err != nil || !ok || got.Verdict != isolationprobe.KindUnknown || !got.ProbedAt.IsZero() ||
		!strings.Contains(got.Error, "without saying why") {
		t.Fatalf("first failed attempt: %+v, %v, %v", got, ok, err)
	}
	all, err := db.ListIsolationEvidence()
	if err != nil || len(all) != 2 || all[0].Runtime != "kata" || all[1].Runtime != "runsc" {
		t.Fatalf("ListIsolationEvidence = %+v, %v", all, err)
	}
	if err := db.ForgetIsolationEvidence("sgx"); err != nil {
		t.Fatal(err)
	}
	if all, _ := db.ListIsolationEvidence(); len(all) != 0 {
		t.Fatalf("ForgetIsolationEvidence left %+v", all)
	}
}

func TestIsolationEvidenceRefusesWhatIsNotAProbeResult(t *testing.T) {
	db := openTestDB(t)
	row := isolationRow("sgx", "kata", isolationprobe.KindVM, time.Time{})
	if err := db.RecordIsolationProbe(row); err == nil {
		t.Error("a verdict with no probe time was recorded")
	}
	row = isolationRow("sgx", "kata", isolationprobe.Kind("vm-ish"), time.Now())
	if err := db.RecordIsolationProbe(row); err == nil {
		t.Error("a verdict this build does not know was recorded")
	}
	if err := db.RecordIsolationProbeFailure(IsolationEvidenceRow{}); err == nil {
		t.Error("a failure with no executor was recorded")
	}
}

// TestIsolationEvidenceMigrationIsAdditive: the stable UI shares this
// database and predates the table, so 0082 must be a shape every older binary
// tolerates — a guarded CREATE TABLE and nothing else.
func TestIsolationEvidenceMigrationIsAdditive(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Version != 82 {
			continue
		}
		if got := classifyMigration(m.SQL); got != CompatAdditive {
			t.Fatalf("0082 classifies as %s, want additive", got)
		}
		if !strings.Contains(m.SQL, "CREATE TABLE IF NOT EXISTS isolation_evidence") {
			t.Fatal("0082's CREATE TABLE is not guarded")
		}
		return
	}
	t.Fatal("migration 0082 not found")
}
