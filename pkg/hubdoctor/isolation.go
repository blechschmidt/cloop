package hubdoctor

// Isolation evidence: whether each executor's runtime is what its name claims
// (Task 20439).
//
// An executor's Virtualized and KernelIsolated are read off its runtime's name,
// and the hub verifies the claim by running `cloop isolation-probe` under the
// runtime and recording what the kernel serving the sandbox said about itself.
// This check reads those records, the same rows placement acts on:
//
//   - an executor whose evidence contradicts its claim fails — projects that
//     require kernel isolation or a hypervisor are refused there, and the
//     runtime is not what an operator believes it to be;
//   - one whose claim was never verified, or whose probe could not run or was
//     inconclusive, warns, because placement admits it on the name alone
//     unless executors.isolation_evidence is required;
//   - evidence older than two days warns: the daily round should have renewed
//     it, so something is stopping the probe;
//   - an executor whose claim is verified passes.
//
// The records come from the hub's database, so this works from the CLI and for
// devices that are offline. "Never verified" needs the registry, and is said
// for the executors this process has registered: the hub's own in the Hub
// health panel, the configured ones under `cloop hub doctor`.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// isolationStaleAfter is how old a verdict may grow before the check warns.
const isolationStaleAfter = 48 * time.Hour

// isolationNow is the check's clock; tests pin it.
var isolationNow = time.Now

const isolationTitle = "Executor isolation evidence"

// isolationRemedy is what clears a contradiction.
const isolationRemedy = "Register the runtime the executor is named for — /etc/docker/daemon.json \"runtimes\", " +
	"the RuntimeClass's handler on the cluster's nodes, or the device's engine — or set the executor's runtime to " +
	"the one it really is; then press Re-probe on its card in the Executors panel"

func checkIsolationEvidence(dir string, add addFn) {
	rows, err := isolationRows(dir)
	if err != nil {
		add(Finding{
			Check: "executors.isolation", Title: isolationTitle, Severity: SeverityWarn,
			Message:     fmt.Sprintf("the isolation evidence could not be read: %v", err),
			Remediation: "Check the storage findings above; the evidence lives in .cloop/state.db",
		})
		return
	}
	byKey := map[string]statedb.IsolationEvidenceRow{}
	for _, r := range rows {
		byKey[r.ExecutorID+"\x00"+r.Runtime] = r
	}

	// Registered executors that claim isolation with no record at all.
	var never []string
	for _, ex := range executor.List() {
		rt, has := executor.IsolationRuntimeOf(ex)
		if !has {
			continue
		}
		caps := ex.Capabilities()
		if !caps.Virtualized && !caps.KernelIsolated {
			continue
		}
		if _, ok := byKey[ex.ID()+"\x00"+strings.TrimSpace(rt)]; !ok {
			never = append(never, fmt.Sprintf("%s (runtime %q)", ex.ID(), rt))
		}
	}

	var unverified, stale, verified []string
	now := isolationNow()
	for _, r := range rows {
		label := fmt.Sprintf("%s (runtime %q)", r.ExecutorID, r.Runtime)
		if r.Claim == isolationprobe.KindHostKernel || r.Claim == "" {
			continue // claims nothing a verdict could break
		}
		switch r.Status() {
		case isolationprobe.StatusContradicted:
			add(Finding{
				Check: "executors.isolation", Title: "Isolation of " + r.ExecutorID, Severity: SeverityFail,
				Message: fmt.Sprintf("%s claims %s, but its isolation probe on %s found %s: %s. Projects whose "+
					".cloop/sandbox.yaml requires kernel isolation or virtualization are refused there",
					label, r.Claim.Phrase(), r.ProbedAt.UTC().Format("2006-01-02 15:04 UTC"), r.Verdict.Phrase(),
					r.Detail),
				Remediation: isolationRemedy,
				Details: map[string]any{"executor": r.ExecutorID, "runtime": r.Runtime, "claim": string(r.Claim),
					"verdict": string(r.Verdict), "probed_at": r.ProbedAt.UTC().Format(time.RFC3339)},
			})
		case isolationprobe.StatusUnverified:
			why := "inconclusive: " + r.Detail
			if r.ProbedAt.IsZero() {
				why = "its probe could not run: " + r.Error
			}
			unverified = append(unverified, label+" — "+why)
		default:
			last := r.AttemptedAt
			if last.IsZero() {
				last = r.ProbedAt
			}
			if now.Sub(last) > isolationStaleAfter {
				stale = append(stale, fmt.Sprintf("%s, last probed %s", label, last.UTC().Format("2006-01-02 15:04 UTC")))
				continue
			}
			verified = append(verified, label)
		}
	}
	sort.Strings(never)
	if len(never) > 0 || len(unverified) > 0 {
		policy := "they are admitted to projects that require isolation, with a warning on each run"
		if executor.IsolationEvidenceRequired() {
			policy = "executors.isolation_evidence is required, so projects that require isolation are refused there"
		}
		var parts []string
		if len(never) > 0 {
			parts = append(parts, "never probed: "+strings.Join(never, ", "))
		}
		parts = append(parts, unverified...)
		add(Finding{
			Check: "executors.isolation", Title: isolationTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("%d executor(s) claim isolation that no probe has verified, so the claim rests on "+
				"a runtime's name — %s; %s", len(never)+len(unverified), strings.Join(parts, "; "), policy),
			Remediation: "Press Re-probe on each card in the Executors panel once its probe can run: the device " +
				"connected with an agent that answers the probe (the card names the upgrade when it does not), " +
				"the executor's image present, the runtime registered",
		})
	}
	if len(stale) > 0 {
		add(Finding{
			Check: "executors.isolation", Title: isolationTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("the isolation evidence of %s is older than %s, although the hub probes each "+
				"executor daily", strings.Join(stale, "; "), isolationStaleAfter),
			Remediation: "Check that the hub is running and the device connected, and read the hub's log for " +
				"\"isolation probe\" lines; press Re-probe on the card to probe now",
		})
	}
	if len(verified) > 0 && len(never) == 0 && len(unverified) == 0 && len(stale) == 0 {
		add(Finding{
			Check: "executors.isolation", Title: isolationTitle, Severity: SeverityPass,
			Message: fmt.Sprintf("every executor claiming isolation has it verified: %s", strings.Join(verified, ", ")),
		})
	}
}

// isolationRows reads the evidence, or nothing when there is no control plane
// — a check never creates a database.
func isolationRows(dir string) ([]statedb.IsolationEvidenceRow, error) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	return db.ListIsolationEvidence()
}
