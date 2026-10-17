package ui

// isolation.go runs the isolation probe from the hub (Task 20439): it keeps the
// verifier that records what each executor's runtime was found to be, installs
// it as the evidence placement reads, and triggers it at the four points the
// task names — when configured container and Kubernetes executors are
// reconciled, at a device's hello, after a runtime change, and daily — plus on
// an administrator's request from the executor card.
//
// A remote device can only be probed by the hub member holding its socket, so
// every trigger that reaches a device runs where the device is connected: the
// hello and the re-probe button on that member, the daily round on every
// member for the devices it holds. Container and Kubernetes executors belong
// to every member alike; the daily round probes them on the leader only, so a
// cluster does not probe one Kubernetes namespace once per member.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/isolationverify"
	"github.com/blechschmidt/cloop/pkg/state"
)

// isolationVerifierPtr is the process's verifier, installed by
// bootstrapExecutors.
var isolationVerifierPtr atomic.Pointer[isolationverify.Verifier]

// activeIsolationVerifier returns the verifier, or nil before bootstrap.
func activeIsolationVerifier() *isolationverify.Verifier { return isolationVerifierPtr.Load() }

// startIsolationVerifier builds the verifier for dir's control plane and makes
// it the evidence placement reads. Before reconciliation, which hands it the
// configured executors.
func startIsolationVerifier(dir string) *isolationverify.Verifier {
	v := isolationverify.New(isolationverify.Options{
		DBPath:   state.DBPath(dir),
		Instance: processInstanceID(),
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "ui: "+format+"\n", args...)
		},
	})
	isolationVerifierPtr.Store(v)
	executor.SetIsolationEvidenceSource(v.Lookup)
	return v
}

// probeIsolation starts a background probe of ex from point, if ex has a
// runtime to probe and a verifier is running.
func probeIsolation(ex executor.Executor, point string) {
	v := activeIsolationVerifier()
	p, ok := ex.(executor.IsolationProber)
	if v == nil || !ok {
		return
	}
	v.ProbeAsync(p, point)
}

// probeDeviceAndVirtuals probes a device that just connected and every virtual
// executor dispatching through it: each has its own runtime to verify.
func probeDeviceAndVirtuals(agentID string) {
	if ex, err := executor.Get(agentID); err == nil {
		probeIsolation(ex, executor.ProbePointHello)
	}
	for _, ex := range executor.List() {
		if v, ok := ex.(*remote.Virtual); ok && v.ParentID() == agentID {
			probeIsolation(v, executor.ProbePointHello)
		}
	}
}

// makeExecutorConnectProber wraps the connect recorder so a device's hello
// starts the probe of its runtimes, on the member that holds its socket.
func makeExecutorConnectProber(
	inner func(remote.AgentRecord, remote.AgentCapabilities, string),
) func(remote.AgentRecord, remote.AgentCapabilities, string) {
	return func(agent remote.AgentRecord, caps remote.AgentCapabilities, agentVersion string) {
		if inner != nil {
			inner(agent, caps, agentVersion)
		}
		probeDeviceAndVirtuals(agent.AgentID)
	}
}

// probeAfterRuntimeChange is called after an administrator saved an
// executor's sandbox settings or a virtual executor's definition. The evidence
// is about a runtime, so a new runtime name starts unverified on its own; a
// changed engine under the same name could mean a different runtime, so what
// was verified under the old engine is forgotten first.
//
// A device is probed by the member holding its socket, which need not be the
// one that saved the change: that member is asked over the cluster bus.
func (s *Server) probeAfterRuntimeChange(executorID string, before, after executor.SandboxSettings) {
	v := activeIsolationVerifier()
	if v == nil {
		return
	}
	if strings.TrimSpace(before.Engine) != strings.TrimSpace(after.Engine) {
		if err := v.Forget(executorID); err != nil {
			fmt.Fprintf(os.Stderr, "ui: forget isolation evidence for %s: %v\n", executorID, err)
		}
	}
	if agent := s.agentForExecutorID(executorID); agent != "" {
		if _, holds := s.actsForAgent(agent); !holds {
			s.publishAgentChange(executorID, agentEventIsolationProbe)
			return
		}
	}
	if ex, err := executor.Get(executorID); err == nil {
		probeIsolation(ex, executor.ProbePointRuntimeChange)
	}
}

// forgetIsolationEvidence drops an executor's evidence when the executor is
// gone.
func forgetIsolationEvidence(executorID string) {
	if v := activeIsolationVerifier(); v != nil {
		if err := v.Forget(executorID); err != nil {
			fmt.Fprintf(os.Stderr, "ui: forget isolation evidence for %s: %v\n", executorID, err)
		}
	}
}

// isolationRoundInterval is how often the daily round looks for executors due
// a probe; each is probed once a day (isolationverify.DueAfter).
const isolationRoundInterval = time.Hour

// watchIsolationProbes is the daily round, on every member.
func (s *Server) watchIsolationProbes(ctx context.Context) {
	defer recoverGoroutine("isolation-probes")
	// Not at once: reconciliation and the devices' hellos probe everything
	// at startup, and a round on their heels would only repeat them.
	if !sleepContext(ctx, 10*time.Minute) {
		return
	}
	t := time.NewTicker(isolationRoundInterval)
	defer t.Stop()
	for {
		s.isolationRound(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// isolationRound probes what this member should of every executor due one.
func (s *Server) isolationRound(ctx context.Context) {
	v := activeIsolationVerifier()
	if v == nil {
		return
	}
	var mine []executor.Executor
	for _, ex := range executor.List() {
		switch e := ex.(type) {
		case *remote.Executor:
			if e.Connected() {
				mine = append(mine, e)
			}
		case *remote.Virtual:
			if e.Parent().Connected() {
				mine = append(mine, e)
			}
		default:
			if s.isLeader() {
				mine = append(mine, ex)
			}
		}
	}
	v.Round(ctx, mine, executor.ProbePointDaily, isolationverify.DueAfter)
}

// sleepContext waits d or until ctx ends, reporting whether d elapsed.
func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// handleExecutorIsolationProbe serves POST /api/executors/{id}/isolation-probe:
// run the probe now, in the background, and announce the result on the
// executor update stream — the card's Re-probe button.
func (s *Server) handleExecutorIsolationProbe(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	// A device is probed over its socket, which one member holds.
	if s.routeAgentRequest(w, r, id) {
		return
	}
	ex, err := executor.Get(id)
	if err != nil {
		jsonErr(w, fmt.Sprintf("executor %q is not registered", id), http.StatusNotFound)
		return
	}
	p, ok := ex.(executor.IsolationProber)
	if !ok {
		jsonErr(w, fmt.Sprintf("executor %q runs its payloads under no sandbox runtime, so there is no "+
			"isolation claim to verify", id), http.StatusConflict)
		return
	}
	if _, has := p.IsolationRuntime(); !has {
		jsonErr(w, fmt.Sprintf("executor %q runs its payloads on its host, so there is no sandbox runtime "+
			"to probe; set its sandbox mode to container first", id), http.StatusConflict)
		return
	}
	v := activeIsolationVerifier()
	if v == nil {
		jsonErr(w, "the hub's isolation verifier is not running", http.StatusServiceUnavailable)
		return
	}
	started := v.ProbeAsync(p, executor.ProbePointManual)
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{"executor_id": id, "started": started})
}

// executorIsolationView is an executor's claimed isolation against its
// verified one, for its card and its dialogs.
type executorIsolationView struct {
	// Runtime is the runtime the claim rests on, "" for the default.
	Runtime string `json:"runtime"`
	// Claim is what the executor claims now: vm, userspace-kernel, or
	// host-kernel when it claims nothing.
	Claim string `json:"claim"`
	// Status is verified, contradicted or unverified.
	Status string `json:"status"`
	// Summary is the card's sentence: "claims kata, runs on the host kernel".
	Summary string `json:"summary"`
	// Verdict, Detail and ProbedAt are the latest probe that ran.
	Verdict  string `json:"verdict,omitempty"`
	Detail   string `json:"detail,omitempty"`
	ProbedAt string `json:"probed_at,omitempty"`
	// Error is why the latest attempt could not run, and AttemptedAt when.
	Error       string `json:"error,omitempty"`
	AttemptedAt string `json:"attempted_at,omitempty"`
	Point       string `json:"point,omitempty"`
	// Refused says placement refuses a project requiring isolation here.
	Refused bool `json:"refused,omitempty"`
	// Required echoes executors.isolation_evidence: required.
	Required bool `json:"required,omitempty"`
}

// isolationViewFor returns ex's isolation view, nil for an executor whose
// payloads run under no runtime.
func isolationViewFor(ex executor.Executor) *executorIsolationView {
	st := executor.JudgeIsolation(ex)
	if !st.HasRuntime {
		return nil
	}
	view := &executorIsolationView{
		Runtime:  st.Runtime,
		Claim:    string(st.Claim),
		Status:   string(st.Status),
		Summary:  st.Summary(),
		Required: executor.IsolationEvidenceRequired(),
	}
	if rec := st.Record; rec != nil {
		if !rec.ProbedAt.IsZero() {
			view.Verdict = string(rec.Verdict)
			view.Detail = rec.Detail
			view.ProbedAt = rec.ProbedAt.UTC().Format(time.RFC3339)
		}
		view.Error = rec.Error
		if !rec.AttemptedAt.IsZero() {
			view.AttemptedAt = rec.AttemptedAt.UTC().Format(time.RFC3339)
		}
		view.Point = rec.Point
	}
	claims := st.Claim != isolationprobe.KindHostKernel
	view.Refused = claims && (st.Status == isolationprobe.StatusContradicted ||
		(st.Status == isolationprobe.StatusUnverified && view.Required))
	return view
}
