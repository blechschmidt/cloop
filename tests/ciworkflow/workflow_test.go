package ciworkflow_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"
)

// world is one hub with CI federation switched on, and everything it talks to.
type world struct {
	pki      *testPKI
	github   *fakeGitHub
	up       *fakeAnthropic // nil when relaying to the real API
	hub      *hub
	settings ciSettings
	claude   string // "" runs the stand-in
	apiKey   string // the credential the hub relays with
}

func newWorld(t *testing.T) *world {
	t.Helper()
	requireTools(t)
	live := os.Getenv(liveKeyEnv) != ""
	w := &world{pki: newTestPKI(t, live)}
	w.github = newFakeGitHub(t, w.pki)
	opts := hubOptions{issuer: w.github.issuer(), apiKey: hubAnthropicKey}
	if live {
		opts.apiKey = os.Getenv(liveKeyEnv)
		t.Logf("relaying to the real Anthropic API (%s is set)", liveKeyEnv)
	} else {
		w.up = newFakeAnthropic(t, w.pki)
		opts.upstream = w.up.srv.URL
	}
	w.apiKey = opts.apiKey
	w.hub = startHub(t, w.pki, opts)
	w.settings = w.hub.enableFederation(t)
	w.claude = claudeCode(t)
	return w
}

// reviewRule allowlists the guide's example pipeline the way the guide says to:
// by repository, ref and workflow path, and naming no models, so the session
// gets the hub's defaults — the allowlist every operator who follows the guide
// ends up with.
var reviewRule = map[string]any{
	"name":       "acme/tool review on main",
	"enabled":    true,
	"repository": "acme/tool",
	"ref":        "refs/heads/main",
	"workflow":   "acme/tool/.github/workflows/review.yml",
}

const (
	federateStep = "Federate with cloop"
	agentStep    = "Run the agent"

	// guideHost is the placeholder the guide writes where the Settings panel
	// writes the hub's own URL.
	guideHost = "https://cloop.example.com"
)

// publishedJob is the workflow as an operator gets it: the Settings panel's
// snippet, after checking that it is the guide's text.
func (w *world) publishedJob(t *testing.T) workflowJob {
	t.Helper()
	snippet := w.settings.Snippet
	hubRoot := strings.TrimSuffix(w.settings.BaseURL, "/api/ci/anthropic")
	if hubRoot != w.hub.url {
		t.Fatalf("the Settings panel names the hub %q; it is at %q", hubRoot, w.hub.url)
	}
	if got := strings.ReplaceAll(docsWorkflow(t), guideHost, hubRoot); got != snippet {
		t.Fatalf("docs/guides/ci-pipelines.md publishes a different workflow from the one the "+
			"Settings panel renders (ciWorkflowSnippet); the guide says to copy the panel's, so the two "+
			"must agree apart from the hub's URL.\n--- guide ---\n%s\n--- panel ---\n%s", got, snippet)
	}
	return parseJob(t, snippet)
}

// TestPublishedWorkflow runs the guide's workflow on a played runner against a
// real hub, and checks each of the three things it depends on: that the job
// can mint a token the hub accepts, that the exchange hands the next step a
// session through $GITHUB_ENV, and that Claude Code can do its work through
// the relay with that session — and nothing else.
func TestPublishedWorkflow(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.hub.addRule(t, reviewRule)
	job := w.publishedJob(t)

	// A step after the published ones, as a job that also runs an SDK would
	// have: the SDKs send ANTHROPIC_API_KEY in x-api-key rather than a
	// bearer, and the guide says the relay accepts either.
	job.Steps = append(job.Steps, workflowStep{
		Name:  "Call the API the way an SDK does",
		Shell: "bash", // -o pipefail, so a refusal on the left of the pipe fails the step
		Run: `curl -sS --fail-with-body "$ANTHROPIC_BASE_URL/v1/messages" \
  -H "x-api-key: $ANTHROPIC_AUTH_TOKEN" -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":64,"messages":[{"role":"user","content":"ping"}]}' \
  | jq -er '.content[0].text'`,
	})

	r := newRunner(t, w.github, w.pki, w.claude)
	res := r.run(job)
	t.Logf("job log:\n%s", res.Log)
	if res.Failed() {
		t.Fatalf("the job failed; hub output:\n%s", w.hub.tail())
	}

	// --- Token generation -------------------------------------------------
	reqs := w.github.idTokenRequests()
	if len(reqs) != 1 {
		t.Fatalf("the job asked GitHub for %d ID tokens, want 1: %v", len(reqs), reqs)
	}
	idReq := reqs[0]
	if !idReq.Authorized || idReq.APIVersion != "2.0" || idReq.Token == "" {
		t.Fatalf("the ID-token request was not the runtime's: %v", idReq)
	}
	if idReq.Audience != w.settings.Audience {
		t.Errorf("the job asked for audience %q; the hub verifies %q", idReq.Audience, w.settings.Audience)
	}
	claims := decodeClaims(t, idReq.Token)
	if claims["sub"] != "repo:acme/tool:ref:refs/heads/main" || claims["sha"] != r.sha {
		t.Errorf("the token does not describe the job: sub=%v sha=%v (checked out %s)",
			claims["sub"], claims["sha"], r.sha)
	}
	if d, k := w.github.keyFetches(); d == 0 || k == 0 {
		t.Errorf("the hub never fetched GitHub's discovery document (%d) or key set (%d), "+
			"so whatever it accepted, it did not verify against them", d, k)
	}

	// --- The exchange, and $GITHUB_ENV -----------------------------------
	if got := res.Env["ANTHROPIC_BASE_URL"]; got != w.settings.BaseURL {
		t.Errorf("ANTHROPIC_BASE_URL = %q, want %q", got, w.settings.BaseURL)
	}
	session := res.Env["ANTHROPIC_AUTH_TOKEN"]
	if !strings.HasPrefix(session, "cloop_ci_") {
		t.Fatalf("ANTHROPIC_AUTH_TOKEN is not a CI session token: %q", redact(session))
	}
	if !res.masked(session) {
		t.Error("the session token was never registered with ::add-mask::")
	}

	var accepted []ciExchange
	for _, e := range w.hub.exchanges(t) {
		if e.Accepted {
			accepted = append(accepted, e)
		} else {
			t.Errorf("the hub refused an exchange: %s (%s)", e.Reason, e.Detail)
		}
	}
	if len(accepted) != 1 {
		t.Fatalf("the hub recorded %d accepted exchanges, want 1", len(accepted))
	}
	ex := accepted[0]
	if ex.RuleName != reviewRule["name"] || ex.Repository != "acme/tool" || ex.Ref != "refs/heads/main" {
		t.Errorf("the exchange was admitted as %q for %s@%s", ex.RuleName, ex.Repository, ex.Ref)
	}

	// --- Claude through the relay ----------------------------------------
	calls := r.npxInvocations()
	if len(calls) != 1 || len(calls[0]) < 2 || calls[0][0] != "-y" || calls[0][1] != "@anthropic-ai/claude-code" {
		t.Fatalf("the agent step did not run Claude Code through npx as published: %q", calls)
	}
	prompt := promptOf(calls[0])
	if prompt == "" {
		t.Fatalf("the agent step passed Claude Code no -p prompt: %q", calls[0])
	}

	// Claude Code's call or calls, and the SDK-style one after it.
	sess := w.waitSettled(t, ex.SessionID, w.relayedAll(2))
	if sess.Repository != "acme/tool" || sess.Workflow != "Review" || sess.Actor != "dana" {
		t.Errorf("the session is attributed to %s (%s) by %s", sess.Repository, sess.Workflow, sess.Actor)
	}
	if want := "https://github.com/acme/tool/actions/runs/9876543210"; sess.RunURL != want {
		t.Errorf("the session links to run %q, want %q", sess.RunURL, want)
	}
	if sess.Usage.Denied != 0 {
		t.Errorf("the relay refused %d of the job's requests", sess.Usage.Denied)
	}
	if sess.Usage.OutputTokens == 0 {
		t.Error("the relay metered no output tokens for the session")
	}
	if n := len(w.hub.auditEvents(t, "ci.relay.allowed")); n == 0 {
		t.Error("no ci.relay.allowed event reached the audit trail")
	}
	if n := len(w.hub.auditEvents(t, "ci.exchange.accepted")); n != 1 {
		t.Errorf("%d ci.exchange.accepted events in the audit trail, want 1", n)
	}

	if w.up != nil {
		if !strings.Contains(res.Log, w.up.reply) {
			t.Errorf("the model's answer never reached the job log; want %q", w.up.reply)
		}
		w.checkUpstream(t, sess, prompt, session, idReq.Token)
	}

	// --- What must not be in the log -------------------------------------
	for name, secret := range map[string]string{
		"the session token":    session,
		"the job's ID token":   idReq.Token,
		"the request token":    w.github.requestToken,
		"the hub's credential": w.apiKey,
	} {
		if strings.Contains(res.Log, secret) {
			t.Errorf("%s appears in the job log", name)
		}
	}

	// --- Single use --------------------------------------------------------
	// The guide: "Exchange it once; ask the forge for a fresh one if you need
	// another." The token is still well inside its five minutes.
	if status := w.hub.exchangeRaw(t, idReq.Token); status != http.StatusUnauthorized {
		t.Errorf("presenting the job's ID token a second time: HTTP %d, want 401", status)
	}
}

// checkUpstream asserts what the relay sent the API: every call carried the
// hub's credential and nothing of the pipeline's, the agent's prompt got
// through, and the model and output bound were ones the rule admits.
func (w *world) checkUpstream(t *testing.T, sess ciSession, prompt, session, idToken string) {
	t.Helper()
	seen := w.up.seen()
	if len(seen) == 0 {
		t.Fatal("no request reached the Anthropic API")
	}
	var promptSeen bool
	var in, out int64
	for i, u := range seen {
		where := u.Method + " " + u.Path
		t.Logf("API request %d: %s model=%q max_tokens=%d stream=%v → HTTP %d",
			i, where, u.Model, u.MaxTokens, u.Stream, u.Status)
		if u.Status != http.StatusOK {
			t.Errorf("request %d (%s) was refused by the API: HTTP %d %s", i, where, u.Status, u.Body)
		}
		if got := u.Header.Get("X-Api-Key"); got != hubAnthropicKey {
			t.Errorf("request %d (%s) carried x-api-key %q, not the hub's credential", i, where, redact(got))
		}
		if a := u.Header.Get("Authorization"); a != "" {
			t.Errorf("request %d (%s) carried an Authorization header: %q", i, where, redact(a))
		}
		blob := u.Query + " " + string(u.Body)
		for k, vv := range u.Header {
			blob += " " + k + ": " + strings.Join(vv, ",")
		}
		if strings.Contains(blob, session) || strings.Contains(blob, idToken) {
			t.Errorf("request %d (%s) carried the pipeline's credential to the API", i, where)
		}
		if strings.Contains(string(u.Body), prompt) {
			promptSeen = true
		}
		if u.Path == "/v1/messages" {
			if !admitted(sess.Models, u.Model) {
				t.Errorf("request %d asked for %q, which the session's models %v do not admit — "+
					"the relay should have refused it", i, u.Model, sess.Models)
			}
			if u.MaxTokens > 32000 {
				t.Errorf("request %d reached the API with max_tokens %d, over the default cap of 32000",
					i, u.MaxTokens)
			}
		}
		in += u.InputTokens
		out += u.OutputTokens
	}
	if !promptSeen {
		t.Errorf("the workflow's prompt %q never reached the API", prompt)
	}
	if sess.Usage.Requests != int64(len(seen)) {
		t.Errorf("the session counted %d requests; the API saw %d", sess.Usage.Requests, len(seen))
	}
	if sess.Usage.InputTokens != in || sess.Usage.OutputTokens != out {
		t.Errorf("the session metered %d in / %d out; the API reported %d / %d",
			sess.Usage.InputTokens, sess.Usage.OutputTokens, in, out)
	}
}

// TestWorkflowWithoutIDTokenPermission checks the guide's claim about the line
// people forget: "Without it $ACTIONS_ID_TOKEN_REQUEST_URL is unset and the
// step fails before it reaches the hub."
func TestWorkflowWithoutIDTokenPermission(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.hub.addRule(t, reviewRule)
	job := w.publishedJob(t)
	if job.Permissions["id-token"] != "write" {
		t.Fatalf("the published workflow does not declare id-token: write: %v", job.Permissions)
	}
	delete(job.Permissions, "id-token")

	r := newRunner(t, w.github, w.pki, w.claude)
	res := r.run(job)
	t.Logf("job log:\n%s", res.Log)

	if st := res.step(t, federateStep); !st.Ran || st.ExitCode == 0 {
		t.Fatalf("%q succeeded without an ID token; it must fail, or the job goes on to run the "+
			"agent against whatever it exported", federateStep)
	}
	if st := res.step(t, agentStep); st.Ran {
		t.Errorf("%q ran after federation failed", agentStep)
	}
	if !strings.Contains(res.Log, "ACTIONS_ID_TOKEN_REQUEST_URL") {
		t.Error("the job log does not name the missing ACTIONS_ID_TOKEN_REQUEST_URL, so nothing " +
			"points at the permission that is missing")
	}
	if len(res.Env) != 0 {
		t.Errorf("the failed step still exported %v", keys(res.Env))
	}
	if n := len(w.github.idTokenRequests()); n != 0 {
		t.Errorf("the job reached GitHub's token endpoint %d times without the permission", n)
	}
	if ex := w.hub.exchanges(t); len(ex) != 0 {
		t.Errorf("the step reached the hub: %d exchanges recorded", len(ex))
	}
}

// TestWorkflowForAPipelineTheHubRefuses runs the published workflow from a
// branch the rule does not admit. The job has to stop at the exchange, with
// the hub's sentence in the log — not carry on with ANTHROPIC_BASE_URL=null
// and fail two steps later somewhere that has nothing to do with the cause.
func TestWorkflowForAPipelineTheHubRefuses(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.hub.addRule(t, reviewRule)
	job := w.publishedJob(t)

	feature := defaultJob()
	feature.Ref = "refs/heads/feature"
	feature.WorkflowRef = "acme/tool/.github/workflows/review.yml@refs/heads/feature"
	w.github.setJob(feature)

	r := newRunner(t, w.github, w.pki, w.claude)
	res := r.run(job)
	t.Logf("job log:\n%s", res.Log)

	if st := res.step(t, federateStep); !st.Ran || st.ExitCode == 0 {
		t.Fatalf("%q succeeded although the hub refused the pipeline", federateStep)
	}
	if st := res.step(t, agentStep); st.Ran {
		t.Errorf("%q ran after the hub refused the pipeline", agentStep)
	}
	if len(res.Env) != 0 {
		t.Errorf("the refused exchange still exported %v", keys(res.Env))
	}
	if !strings.Contains(res.Log, "this pipeline is not on the hub's CI allowlist") {
		t.Error("the job log does not carry the hub's refusal, so the pipeline's author cannot " +
			"tell a refusal from an outage")
	}
	ex := w.hub.exchanges(t)
	if len(ex) != 1 || ex[0].Accepted || ex[0].Reason != "no_rule" || ex[0].Ref != "refs/heads/feature" {
		t.Errorf("the hub's exchange log does not record one no_rule refusal for the feature "+
			"branch: %+v", ex)
	}
}

// TestAgentOnAModelTheRuleDoesNotAdmit runs the agent step against a model
// outside the session's allowlist. The relay must refuse it before the API is
// reached, and the harness must turn that refusal into a failed job.
func TestAgentOnAModelTheRuleDoesNotAdmit(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.hub.addRule(t, reviewRule)
	job := w.publishedJob(t)

	agent := &job.Steps[len(job.Steps)-1]
	if agent.Name != agentStep {
		t.Fatalf("the published workflow's last step is %q, not %q", agent.Name, agentStep)
	}
	modelFlag := regexp.MustCompile(`--model\s+\S+`)
	if len(modelFlag.FindAllString(agent.Run, -1)) != 1 {
		t.Fatalf("the agent step does not choose its model with one --model flag: %s", agent.Run)
	}
	// Opus is outside the hub's default allowlist on purpose: "an operator
	// who wants the largest model available to CI should have to say so".
	agent.Run = modelFlag.ReplaceAllString(agent.Run, "--model opus")

	r := newRunner(t, w.github, w.pki, w.claude)
	res := r.run(job)
	t.Logf("job log:\n%s", res.Log)

	if st := res.step(t, federateStep); st.ExitCode != 0 {
		t.Fatalf("%q failed; this test is about the step after it", federateStep)
	}
	if st := res.step(t, agentStep); st.ExitCode == 0 {
		t.Fatalf("%q succeeded on a model the rule does not admit", agentStep)
	}
	if !strings.Contains(res.Log, "is not permitted for this pipeline") {
		t.Error("the job log does not carry the relay's refusal")
	}
	if w.up != nil {
		if n := len(w.up.seen()); n != 0 {
			t.Errorf("%d requests reached the API; a refused model must never be forwarded", n)
		}
	}
	ex := w.hub.exchanges(t)
	if len(ex) != 1 || !ex[0].Accepted {
		t.Fatalf("want one accepted exchange, got %+v", ex)
	}
	sess := w.waitSettled(t, ex[0].SessionID, func(s ciSession) bool { return s.Usage.Denied >= 1 })
	if sess.Usage.Requests != 0 {
		t.Errorf("the session was charged %d requests for calls the relay refused", sess.Usage.Requests)
	}
	if n := len(w.hub.auditEvents(t, "ci.relay.denied")); n == 0 {
		t.Error("no ci.relay.denied event reached the audit trail")
	}
}

// waitSettled polls the hub's session list until the session satisfies done,
// and returns it.
//
// A job that has finished does not mean the hub has: the relay adds a
// request's tokens to its session after the last byte of the response has gone
// out, because it reads them from the response as it passes — and the fake API
// records a request only once it has answered it. So the job's end is followed
// by a bounded wait for the two sides to agree, not by a read of either. On
// timeout the last reading is returned, so the assertions that follow report
// which number is wrong rather than only that something never settled.
func (w *world) waitSettled(t *testing.T, id string, done func(ciSession) bool) ciSession {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var last *ciSession
		for _, s := range w.hub.sessions(t) {
			if s.ID == id {
				s := s
				last = &s
			}
		}
		if last == nil {
			t.Fatalf("the hub lists no session %s", id)
		}
		if done(*last) {
			return *last
		}
		if time.Now().After(deadline) {
			b, _ := json.Marshal(last)
			t.Errorf("session %s did not settle within 10s: %s", id, b)
			return *last
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// relayedAll reports whether the session's meter agrees with what the fake API
// saw: every request counted and every token it reported. In a live run there
// is no record to agree with, and some output having been metered is the
// most that can be said.
func (w *world) relayedAll(min int64) func(ciSession) bool {
	return func(s ciSession) bool {
		if s.Usage.Requests < min {
			return false
		}
		if w.up == nil {
			return s.Usage.OutputTokens > 0
		}
		seen := w.up.seen()
		var in, out int64
		for _, u := range seen {
			in += u.InputTokens
			out += u.OutputTokens
		}
		return int64(len(seen)) == s.Usage.Requests &&
			s.Usage.InputTokens == in && s.Usage.OutputTokens == out
	}
}

// admitted reports whether a model matches one of the session's globs, with
// the same matcher the relay uses.
func admitted(globs []string, model string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, model); err == nil && ok {
			return true
		}
	}
	return false
}

// promptOf returns the argument after -p or --print.
func promptOf(argv []string) string {
	for i, a := range argv {
		if (a == "-p" || a == "--print") && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// redact shortens a credential for a failure message.
func redact(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}
