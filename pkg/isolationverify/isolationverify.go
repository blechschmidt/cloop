// Package isolationverify runs the isolation probe under the runtimes of the
// hub's executors and keeps what it found (Task 20439).
//
// It is the half of pkg/executor/isolation.go that has a database. pkg/executor
// decides, at placement, what an executor's evidence means — it cannot import
// pkg/statedb, which imports it — and reads that evidence through a
// process-wide source. This package is that source, and the writer behind it:
// it runs a probe, classifies what came back, records the verdict per executor
// and runtime in isolation_evidence, appends an executor.isolation_verdict
// audit row when the verdict changes, and counts the probe in
// cloop_executor_isolation_probes_total.
//
// Placement reads through a short-lived cache rather than the database. A
// lookup happens inside reject(), once per candidate, and a hub cluster's
// members each probe the executors they can reach: a member's own verdicts
// enter its cache the moment they are written, and another member's within
// CacheTTL.
package isolationverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DueAfter is how old an executor's latest attempt may be before the daily
// round probes it again.
const DueAfter = 24 * time.Hour

// probeTimeout bounds one probe, whatever the driver allows itself.
const probeTimeout = 5 * time.Minute

// defaultCacheTTL is how stale placement's view of another member's verdicts
// may be.
const defaultCacheTTL = 30 * time.Second

// maxErrorText bounds a failed probe's recorded reason.
const maxErrorText = 2048

// ErrNoRuntime is returned for an executor whose payloads run under no runtime
// — a device in host mode — where there is no claim to verify.
var ErrNoRuntime = errors.New("isolationverify: the executor runs its payloads under no sandbox runtime")

// Options configures a Verifier.
type Options struct {
	// DBPath is the control plane's state database. Empty keeps records in
	// memory only — a test, or a directory with no control plane.
	DBPath string
	// Instance names this hub member on each attempt it records.
	Instance string
	// Now overrides the clock.
	Now func() time.Time
	// Logf receives one line per probe. Nil discards them.
	Logf func(format string, args ...any)
	// CacheTTL bounds how stale a lookup may be. Zero is 30 seconds.
	CacheTTL time.Duration
}

type key struct{ id, runtime string }

// Verifier runs probes and answers placement's lookups.
type Verifier struct {
	opts Options

	mu       sync.Mutex
	cache    map[key]executor.IsolationRecord
	loadedAt time.Time
	inflight map[key]bool
	onRecord func(executorID string)
	wg       sync.WaitGroup
}

// New builds a Verifier. It does no I/O.
func New(opts Options) *Verifier {
	return &Verifier{opts: opts, cache: map[key]executor.IsolationRecord{}, inflight: map[key]bool{}}
}

// SetOnRecord installs what runs after each recorded attempt — the hub
// broadcasts an executor update, so open dashboards re-read the card.
func (v *Verifier) SetOnRecord(fn func(executorID string)) {
	v.mu.Lock()
	v.onRecord = fn
	v.mu.Unlock()
}

func (v *Verifier) now() time.Time {
	if v.opts.Now != nil {
		return v.opts.Now()
	}
	return time.Now()
}

func (v *Verifier) logf(format string, args ...any) {
	if v.opts.Logf != nil {
		v.opts.Logf(format, args...)
	}
}

func (v *Verifier) ttl() time.Duration {
	if v.opts.CacheTTL > 0 {
		return v.opts.CacheTTL
	}
	return defaultCacheTTL
}

// Lookup implements executor.IsolationEvidenceSource.
func (v *Verifier) Lookup(executorID, runtime string) (executor.IsolationRecord, bool) {
	v.mu.Lock()
	stale := v.opts.DBPath != "" && v.now().Sub(v.loadedAt) > v.ttl()
	v.mu.Unlock()
	if stale {
		v.reload()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	r, ok := v.cache[key{strings.TrimSpace(executorID), strings.TrimSpace(runtime)}]
	return r, ok
}

// reload replaces the cache with what the database holds. A database that
// cannot be read keeps the cache it had: a verdict this process already knew
// is still the best evidence it has, and an empty cache would read every
// executor as never verified.
func (v *Verifier) reload() {
	rows, ok, err := v.readAll()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.loadedAt = v.now()
	if err != nil {
		v.logf("isolation evidence: read the control plane: %v", err)
		return
	}
	if !ok {
		// No database to read: what this process recorded is all there is.
		return
	}
	next := make(map[key]executor.IsolationRecord, len(rows))
	for _, r := range rows {
		next[key{r.ExecutorID, r.Runtime}] = r.IsolationRecord
	}
	v.cache = next
}

// readAll reads every record, reporting false when there is no control plane
// to read them from.
func (v *Verifier) readAll() ([]statedb.IsolationEvidenceRow, bool, error) {
	db, ok, err := v.open()
	if err != nil || !ok {
		return nil, ok, err
	}
	defer db.Close()
	rows, err := db.ListIsolationEvidence()
	return rows, err == nil, err
}

// open opens the control plane, reporting false when there is none — a
// directory that never had one is not a failure, and a probe must not create
// a database as a side effect.
func (v *Verifier) open() (*statedb.DB, bool, error) {
	if v.opts.DBPath == "" {
		return nil, false, nil
	}
	if _, err := os.Stat(v.opts.DBPath); err != nil {
		return nil, false, nil
	}
	db, err := statedb.Open(v.opts.DBPath)
	if err != nil {
		return nil, false, err
	}
	return db.AsControlPlane(), true, nil
}

// Probe runs the probe once under ex's runtime now and records what came of
// it. point names where it was asked from (executor.ProbePoint*).
//
// A probe that could not run returns its error and records only the attempt:
// the verdict an earlier probe reached stands.
func (v *Verifier) Probe(ctx context.Context, ex executor.IsolationProber, point string) (executor.IsolationRecord, error) {
	runtime, ok := ex.IsolationRuntime()
	if !ok {
		return executor.IsolationRecord{}, ErrNoRuntime
	}
	runtime = strings.TrimSpace(runtime)
	id := ex.ID()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	attempted := v.now()
	probe, perr := safeProbe(ctx, ex)
	prev, hadPrev := v.previous(id, runtime)

	rec := executor.IsolationRecord{
		ExecutorID: id, Runtime: runtime, Claim: executor.IsolationClaim(runtime),
		Verdict: isolationprobe.KindUnknown, AttemptedAt: attempted, Point: point,
	}
	row := statedb.IsolationEvidenceRow{Engine: probe.Engine, Image: probe.Image, ProbedBy: v.opts.Instance}

	if perr != nil {
		if hadPrev {
			// The verdict and its evidence stand; only the attempt is new.
			rec.Verdict, rec.Detail, rec.ProbedAt = prev.Verdict, prev.Detail, prev.ProbedAt
		}
		rec.Error = bound(perr.Error(), maxErrorText)
		row.IsolationRecord = rec
		if err := v.write(func(db *statedb.DB) error { return db.RecordIsolationProbeFailure(row) }); err != nil {
			v.logf("isolation evidence: record a failed probe of %s: %v", id, err)
		}
		hubmetrics.IsolationProbes.Inc(point, hubmetrics.IsolationProbeFailed)
		v.logf("executor %s: isolation probe (%s) under %s could not run: %s", id, point, runtimeLabel(runtime), rec.Error)
		v.adopt(rec)
		return rec, perr
	}

	verdict := probe.Verdict()
	rec.Verdict, rec.Detail, rec.ProbedAt = verdict.Kind, verdict.Detail, v.now()
	status := rec.Status()
	row.IsolationRecord = rec
	row.Evidence, row.Reference = marshal(probe.Evidence), marshal(probe.Reference)

	changed := !hadPrev || prev.ProbedAt.IsZero() || prev.Verdict != rec.Verdict || prev.Status() != status
	err := v.write(func(db *statedb.DB) error {
		if err := db.RecordIsolationProbe(row); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		payload := map[string]any{
			"runtime": runtime, "claim": string(rec.Claim), "verdict": string(rec.Verdict),
			"status": string(status), "point": point, "detail": bound(rec.Detail, 1024),
			"previous_verdict": "", "previous_status": "",
		}
		if hadPrev && !prev.ProbedAt.IsZero() {
			payload["previous_verdict"] = string(prev.Verdict)
			payload["previous_status"] = string(prev.Status())
		}
		return db.AppendAuditEvent(&statedb.AuditEvent{
			Actor:      "system",
			EventType:  string(auditaction.ActionExecutorIsolationVerdict),
			EntityType: "executor",
			EntityID:   id,
			Payload:    statedb.MarshalAuditPayload(payload),
		})
	})
	if err != nil {
		v.logf("isolation evidence: record the probe of %s: %v", id, err)
	}
	hubmetrics.IsolationProbes.Inc(point, metricStatus(status))
	v.logf("executor %s: isolation probe (%s): %s — %s", id, point,
		executor.IsolationStanding{Runtime: runtime, Claim: rec.Claim, Status: status, Record: &rec}.Summary(), rec.Detail)
	v.adopt(rec)
	return rec, nil
}

// safeProbe runs the driver's probe, turning a panic into an error: a probe
// is diagnostics, and must not take a hub member down with it.
func safeProbe(ctx context.Context, ex executor.IsolationProber) (p executor.IsolationProbe, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the probe panicked: %v", r)
		}
	}()
	return ex.ProbeIsolation(ctx)
}

// previous returns the record a probe is compared with: the database's, so a
// cluster member compares against another member's verdict too.
func (v *Verifier) previous(id, runtime string) (executor.IsolationRecord, bool) {
	db, ok, err := v.open()
	if err == nil && ok {
		defer db.Close()
		if row, found, err := db.IsolationEvidence(id, runtime); err == nil {
			return row.IsolationRecord, found
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	r, found := v.cache[key{id, runtime}]
	return r, found
}

// write runs fn against the control plane, when there is one.
func (v *Verifier) write(fn func(*statedb.DB) error) error {
	db, ok, err := v.open()
	if err != nil || !ok {
		return err
	}
	defer db.Close()
	return fn(db)
}

// adopt puts a record in the cache and tells whoever asked to hear of it.
func (v *Verifier) adopt(rec executor.IsolationRecord) {
	v.mu.Lock()
	v.cache[key{rec.ExecutorID, rec.Runtime}] = rec
	fn := v.onRecord
	v.mu.Unlock()
	if fn != nil {
		fn(rec.ExecutorID)
	}
}

// ProbeAsync runs Probe in the background, once at a time per executor and
// runtime, and reports whether it started one. The probe is bounded by
// probeTimeout; nothing waits on it but Wait.
func (v *Verifier) ProbeAsync(ex executor.IsolationProber, point string) bool {
	runtime, ok := ex.IsolationRuntime()
	if !ok {
		return false
	}
	k := key{ex.ID(), strings.TrimSpace(runtime)}
	v.mu.Lock()
	if v.inflight[k] {
		v.mu.Unlock()
		return false
	}
	v.inflight[k] = true
	v.wg.Add(1)
	v.mu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				v.logf("isolation evidence: panic probing %s: %v", k.id, r)
			}
			v.mu.Lock()
			delete(v.inflight, k)
			v.mu.Unlock()
			v.wg.Done()
		}()
		_, _ = v.Probe(context.Background(), ex, point)
	}()
	return true
}

// Wait blocks until every probe ProbeAsync started has finished.
func (v *Verifier) Wait() { v.wg.Wait() }

// Due reports whether ex has no attempt recorded for its current runtime, or
// only one older than every.
func (v *Verifier) Due(ex executor.IsolationClaimer, every time.Duration) bool {
	runtime, ok := ex.IsolationRuntime()
	if !ok {
		return false
	}
	rec, found := v.Lookup(ex.ID(), runtime)
	if !found {
		return true
	}
	last := rec.AttemptedAt
	if last.IsZero() {
		last = rec.ProbedAt
	}
	return last.IsZero() || v.now().Sub(last) >= every
}

// Round probes, one at a time, every executor in exs that can be probed and is
// due, and returns how many it probed. It stops when ctx ends.
func (v *Verifier) Round(ctx context.Context, exs []executor.Executor, point string, every time.Duration) int {
	n := 0
	for _, ex := range exs {
		if ctx.Err() != nil {
			break
		}
		p, ok := ex.(executor.IsolationProber)
		if !ok || !v.Due(p, every) {
			continue
		}
		_, _ = v.Probe(ctx, p, point)
		n++
	}
	return n
}

// Forget drops every record for executorID — an executor gone, or one whose
// engine changed under the same runtime name.
func (v *Verifier) Forget(executorID string) error {
	v.mu.Lock()
	for k := range v.cache {
		if k.id == executorID {
			delete(v.cache, k)
		}
	}
	v.mu.Unlock()
	return v.write(func(db *statedb.DB) error { return db.ForgetIsolationEvidence(executorID) })
}

func metricStatus(s isolationprobe.Status) string {
	switch s {
	case isolationprobe.StatusVerified:
		return hubmetrics.IsolationProbeVerified
	case isolationprobe.StatusContradicted:
		return hubmetrics.IsolationProbeContradicted
	}
	return hubmetrics.IsolationProbeUnverified
}

func runtimeLabel(rt string) string {
	if rt == "" {
		return "the default runtime"
	}
	return fmt.Sprintf("runtime %q", rt)
}

func marshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func bound(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}
