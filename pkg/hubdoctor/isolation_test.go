package hubdoctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func seedIsolation(t *testing.T, rows ...statedb.IsolationEvidenceRow) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, r := range rows {
		var err error
		if r.ProbedAt.IsZero() {
			err = db.RecordIsolationProbeFailure(r)
		} else {
			err = db.RecordIsolationProbe(r)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func evidenceRow(id, runtime string, verdict isolationprobe.Kind, at time.Time) statedb.IsolationEvidenceRow {
	return statedb.IsolationEvidenceRow{IsolationRecord: executor.IsolationRecord{
		ExecutorID: id, Runtime: runtime, Claim: executor.IsolationClaim(runtime), Verdict: verdict,
		Detail: "the sandbox's kernel is the host's own: it reports the host's boot ID (2d725fb0…)", ProbedAt: at,
		AttemptedAt: at,
	}}
}

func isolationFindings(dir string) []Finding {
	var out []Finding
	checkIsolationEvidence(dir, func(f Finding) { out = append(out, f) })
	return out
}

// TestIsolationEvidenceCheck: a contradicted claim fails with the evidence
// and the remedy; an unverified one warns; a stale one warns; a fleet whose
// claims are all verified passes.
func TestIsolationEvidenceCheck(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	prev := isolationNow
	isolationNow = func() time.Time { return now }
	t.Cleanup(func() { isolationNow = prev })

	failed := statedb.IsolationEvidenceRow{IsolationRecord: executor.IsolationRecord{
		ExecutorID: "sgx", Runtime: "kata", Claim: isolationprobe.KindVM, AttemptedAt: now,
		Error: "agent sgx (sgx) speaks protocol v25, and the hub needs v26 to probe what its sandbox runtime really is.",
	}}
	dir := seedIsolation(t,
		evidenceRow("kata-alias", "kata", isolationprobe.KindHostKernel, now.Add(-time.Hour)),
		failed,
		evidenceRow("old-gv", "runsc", isolationprobe.KindUserspaceKernel, now.Add(-72*time.Hour)),
		evidenceRow("plain", "", isolationprobe.KindHostKernel, now.Add(-time.Hour)),
	)
	fs := isolationFindings(dir)
	var fail, warns int
	for _, f := range fs {
		if f.Check != "executors.isolation" {
			t.Errorf("check id %q", f.Check)
		}
		if f.Severity != SeverityPass && f.Remediation == "" {
			t.Errorf("a %s finding without a remediation: %s", f.Severity, f.Message)
		}
		switch f.Severity {
		case SeverityFail:
			fail++
			for _, want := range []string{"kata-alias", "a virtual machine", "the host kernel", "2d725fb0", "refused"} {
				if !strings.Contains(f.Message, want) {
					t.Errorf("fail finding %q does not name %q", f.Message, want)
				}
			}
		case SeverityWarn:
			warns++
		}
	}
	if fail != 1 || warns != 2 {
		t.Fatalf("findings = %+v, want one fail and two warnings", fs)
	}
	joined := ""
	for _, f := range fs {
		joined += f.Message + "\n"
	}
	if !strings.Contains(joined, "needs v26") || !strings.Contains(joined, "old-gv") {
		t.Errorf("the warnings do not say why: %s", joined)
	}
	if strings.Contains(joined, "plain") {
		t.Error("an executor claiming nothing was reported")
	}

	// All verified and fresh: one pass.
	ok := seedIsolation(t, evidenceRow("gv", "runsc", isolationprobe.KindUserspaceKernel, now.Add(-time.Hour)))
	fs = isolationFindings(ok)
	if len(fs) != 1 || fs[0].Severity != SeverityPass || !strings.Contains(fs[0].Message, "gv") {
		t.Fatalf("findings = %+v, want one pass", fs)
	}

	// No control plane at all: nothing to say, and no database created.
	empty := t.TempDir()
	if fs := isolationFindings(empty); len(fs) != 0 {
		t.Fatalf("findings with no database: %+v", fs)
	}
	if _, err := os.Stat(state.DBPath(empty)); err == nil {
		t.Fatal("the check created a database")
	}
}
