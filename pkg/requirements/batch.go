package requirements

import "time"

// A check reaches its executor as `cloop requirements check --spec=<JSON>`,
// one argument, which Linux caps at 128 KiB: a long list of requirements goes
// as several dispatches. The hub's Requirements tab and the orchestrator's
// requirements gate (Task 20461) both split a check this way.
const (
	// BatchBytes and BatchSize bound one dispatch's spec.
	BatchBytes = 96 << 10
	BatchSize  = 25
	// AssessTimeout is the model's time on one requirement that has no tests.
	AssessTimeout = 5 * time.Minute
	// DispatchSlack is a batch's time beyond its tests and model calls:
	// starting the check where the project runs.
	DispatchSlack = 3 * time.Minute
)

// Batches splits reqs into the dispatches that check them: as few as fit one
// argument each, every requirement in the form a spec carries it. A
// requirement too large for any — one written to the database past what
// Normalize admits — is a batch of its own, which OversizedBatch reports, so
// the caller can say so rather than send it.
func Batches(reqs []Requirement) [][]Requirement {
	var (
		out  [][]Requirement
		cur  []Requirement
		size int
	)
	for _, q := range reqs {
		n := q.EncodedSize()
		if len(cur) > 0 && (len(cur) >= BatchSize || size+n > BatchBytes || n > BatchBytes) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, q.ForSpec())
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// OversizedBatch reports whether batch cannot be sent as one argument.
func OversizedBatch(batch []Requirement) bool {
	size := 0
	for _, q := range batch {
		size += q.EncodedSize()
	}
	return size > BatchBytes
}

// BatchBudget is how long one dispatch may take: its tests, its model calls
// when assess asks for them, and starting the check.
func BatchBudget(batch []Requirement, assess bool) time.Duration {
	d := DispatchSlack
	for _, q := range batch {
		for _, t := range q.Tests {
			d += t.Timeout()
		}
		if assess && !q.Tested() {
			d += AssessTimeout
		}
	}
	return d
}

// FailedReport is a report saying the check of each of batch did not work,
// and why: what a dispatch that brought back nothing readable records.
func FailedReport(batch []Requirement, why string, now time.Time) Report {
	why = truncateRunes(oneLine(why), MaxSummaryRunes)
	rep := Report{Results: make([]Result, 0, len(batch))}
	for _, q := range batch {
		rep.Results = append(rep.Results, Result{
			RequirementID: q.ID, Fingerprint: q.Fingerprint(), Method: methodFor(q), Verdict: VerdictError,
			Summary: "the check did not run: " + why, StartedAt: now,
			Tests: brokenTests(q.Tests, why),
		})
	}
	return rep
}

func brokenTests(ts []Test, why string) []TestResult {
	if len(ts) == 0 {
		return nil
	}
	out := make([]TestResult, len(ts))
	for i, t := range ts {
		out[i] = TestResult{Name: t.Name, Command: t.Command, Outcome: OutcomeError, ExitCode: -1, Error: why}
	}
	return out
}
