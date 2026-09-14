package ui

// Build info for the dashboard (Task 20249).
//
// The hub could describe every machine in its fleet except itself. An executor
// agent reports its build in the hello frame, the control plane classifies the
// skew and the Executors tab draws a badge for it — but nothing anywhere told
// you which build the *hub* was running, so the one question an operator asks
// after pushing a fix ("is that actually what's serving me?") had no answer
// short of ssh'ing to the host.
//
// That gap is not theoretical here. The reference deployment rebuilds from the
// tip of main on a timer and restarts the service, and that timer has silently
// skipped before — a full disk, a failed build, a rolled-back binary. Every one
// of those failure modes leaves a *healthy* dashboard serving *stale* code,
// which is precisely the state no page on the site could distinguish from
// success.
//
// So this endpoint reports two different things, because "is a recent version
// running" is two questions:
//
//   - What is running: version, revision, and whether the build can identify
//     itself at all (see version.BuildInfo.Identified — the reference hub
//     builds from a `git archive` export, which carries no VCS data, so this
//     is a real state and not a defensive branch).
//   - How recent it is: when the build was produced and when the process
//     started. A deploy moves both. A deploy that silently skipped moves
//     neither, and the age on screen keeps growing until somebody notices.
//
// Ages are computed server-side rather than left to the browser. A client
// clock that is minutes — or months — off would otherwise turn a fresh deploy
// into a scary number, and the whole point of the panel is to be trusted.

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/version"
)

// processStart is when this hub process began serving.
//
// Package-level and set at load time rather than in Server.New, because it
// answers "did the service restart?" — a question about the process, not about
// any particular Server instance. A test that constructs three Servers has not
// restarted anything.
var processStart = time.Now()

// buildInfoResponse is the GET /api/version payload.
//
// Field names are snake_case to match every other endpoint the dashboard reads.
type buildInfoResponse struct {
	Version string `json:"version"`
	// Identified is false when Version is the bare "dev" fallback: the build
	// carries no linker stamp and no VCS data, so it cannot be told apart from
	// any other such build. Surfaced rather than hidden — a dashboard that
	// cannot say what it runs should say *that*, not display "dev" as though
	// it were an answer.
	Identified bool   `json:"identified"`
	Revision   string `json:"revision,omitempty"`
	Modified   bool   `json:"modified,omitempty"`

	BuiltAt *time.Time `json:"built_at,omitempty"`
	// BuiltAtSource names what BuiltAt actually measures ("commit" or
	// "binary"); see pkg/version. The UI labels the timestamp with it instead
	// of calling an executable's mtime a build date.
	BuiltAtSource   string `json:"built_at_source,omitempty"`
	BuildAgeSeconds *int64 `json:"build_age_seconds,omitempty"`

	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`

	Go          string `json:"go"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Protocol    int    `json:"protocol"`
	MinProtocol int    `json:"min_protocol"`

	// BuildID is a single opaque fingerprint of everything above that a
	// redeploy changes — and nothing it does not. The dashboard keeps the
	// value it booted with and compares on every reconnect, so one string
	// comparison replaces reasoning about which of five fields moved.
	//
	// Deliberately excludes StartedAt: restarting the same binary gives the
	// user a byte-identical frontend, and prompting them to reload for it
	// would train them to dismiss the prompt that matters.
	BuildID string `json:"build_id"`
}

// handleVersion reports the running hub's build. GET /api/version.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.buildInfo(time.Now()))
}

// buildInfo assembles the report. Now is a parameter so tests can assert the
// derived ages without sleeping.
func (s *Server) buildInfo(now time.Time) buildInfoResponse {
	b := version.Build()
	out := buildInfoResponse{
		Version:       b.Version,
		Identified:    b.Identified,
		Revision:      b.Revision,
		Modified:      b.Modified,
		BuiltAtSource: b.BuiltAtSource,
		StartedAt:     processStart.UTC(),
		UptimeSeconds: int64(now.Sub(processStart).Seconds()),
		Go:            runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Protocol:      remote.ProtocolVersion,
		MinProtocol:   remote.MinProtocolVersion,
	}
	if !b.BuiltAt.IsZero() {
		at := b.BuiltAt
		out.BuiltAt = &at
		age := int64(now.Sub(at).Seconds())
		// A binary whose mtime is in the future (a clock stepped backwards, a
		// tarball restored with preserved timestamps) would otherwise render
		// as "built in -3 hours". Clamp: unknown age beats a wrong one.
		if age < 0 {
			age = 0
		}
		out.BuildAgeSeconds = &age
	}
	// Negative uptime is impossible from a monotonic clock, but `now` is a
	// parameter and a test passing an earlier instant should not produce a
	// nonsense field in the golden output.
	if out.UptimeSeconds < 0 {
		out.UptimeSeconds = 0
	}
	out.BuildID = buildFingerprint(b, loadAssets().page.etag)
	return out
}

// buildFingerprint reduces a build's identity to one comparable string.
//
// It mixes in the rendered shell's ETag, which is derived from the content
// hashes of the CSS and JS bundles it names. That covers the case the version
// fields cannot: an unstamped build whose frontend changed still reports
// "dev", but its assets hash differently, so the dashboard still knows the
// code in the browser is stale.
func buildFingerprint(b version.BuildInfo, assetETag string) string {
	return contentHash([]byte(b.Version + "\x00" +
		b.Revision + "\x00" +
		strconv.FormatBool(b.Modified) + "\x00" +
		b.BuiltAt.UTC().Format(time.RFC3339) + "\x00" +
		assetETag))
}
