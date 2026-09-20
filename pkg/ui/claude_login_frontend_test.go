package ui

// What the Claude Code panel shows when the hub refuses a login (Task 20320).
//
// The bug report was "an [object Object] error is returned". That string is what
// JavaScript produces when an object is concatenated into text, and the hub had
// started sending one: every refusal written by pkg/apierror nests its message
// inside {"error": {code, message, details}}, while the panel read
// response.error and interpolated it directly. Authorization, quota and
// rate-limit denials all come from middleware, so they are precisely the errors
// that arrived structured — and precisely the ones worth reading.
//
// Driven through the real bundle rather than grepped: the assertion is about
// what is on screen after the click, and a grep proving errText() is called
// cannot prove the sentence rendered.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rawJSONFetch matches a fetch() whose response is decoded with .json()
// directly, bypassing parseAPIResponse.
var rawJSONFetch = regexp.MustCompile(`r\.json\(\)|resp\.json\(\)|pr\.json\(\)`)

// knownRawJSONFetches is the number of self-decoding fetches each fragment still
// has. A budget per file rather than an allowlist of files, so that adding one
// to a fragment that already has some still fails: the list ratchets down and
// cannot quietly grow.
//
// Every entry is a latent instance of the bug Task 20320 fixed in the Claude
// Code panel — a refusal from this fetch reaches the DOM as "[object Object]",
// a 401 does not reopen the login modal, and a 403 is not explained. They are
// recorded rather than fixed here because converting them is not uniform: the
// dictation uploads are multipart and cannot go through api()'s JSON body, two
// fragments belong to another task's uncommitted work, and each conversion
// needs its own check of what the caller does with the decoded body.
var knownRawJSONFetches = map[string]int{
	"assets/js/12-task-crud.js": 5,
	"assets/js/15-voice.js":     2, // multipart audio upload
	"assets/js/18-shortcuts.js": 2,
	"assets/js/23-executors.js": 2,
	"assets/js/25-replay.js":    1,
	"assets/js/26-sessions.js":  1,
}

// No panel may decode an API response itself.
//
// parseAPIResponse is the single place the dashboard handles a 401 (reopen the
// login modal), a 403 (explain the refusal) and the hub's two error dialects —
// pkg/ui's {"error":"text"} and pkg/apierror's {"error":{code,message}}. Reaching
// for fetch().then(r => r.json()) opts out of all three at once, which is
// exactly how the Claude Code panel came to render a refusal as the literal
// "[object Object]" while every other panel handled the same body correctly.
//
// A gate rather than a comment, because the broken form and the correct form
// differ only by which helper is called: both compile, both work against a 200,
// and the difference appears only against a response shape the author probably
// did not have in front of them.
func TestDashboard_APIResponsesGoThroughParseAPIResponse(t *testing.T) {
	// 00-core.js is where parseAPIResponse lives, and it also holds the login
	// gate's deliberate bare-token probe. 16/17-*.js read SSE token streams with
	// getReader(), which is not a JSON body at all.
	exempt := map[string]bool{
		"assets/js/00-core.js":      true,
		"assets/js/16-chat.js":      true,
		"assets/js/17-assistant.js": true,
	}
	counts := map[string][]string{}
	for _, name := range bundleFiles {
		if exempt[name] {
			continue
		}
		src, err := assetFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if rawJSONFetch.MatchString(line) {
				counts[name] = append(counts[name], strconv.Itoa(i+1)+": "+trimmed)
			}
		}
	}
	for name, hits := range counts {
		if len(hits) > knownRawJSONFetches[name] {
			t.Errorf("%s decodes an API response itself in %d place(s), budget %d. "+
				"Use api()/apiMethod(): a raw fetch().then(r => r.json()) skips "+
				"parseAPIResponse, losing the 401 login modal, the 403 "+
				"explanation, and the flattening of a pkg/apierror body — which "+
				"is how a refusal reaches the DOM as \"[object Object]\".\n  %s",
				name, len(hits), knownRawJSONFetches[name], strings.Join(hits, "\n  "))
		}
	}
	// A budget that outlives the thing it counts stops being a ratchet.
	for name, want := range knownRawJSONFetches {
		if got := len(counts[name]); got < want {
			t.Errorf("%s now has %d self-decoding fetch(es), below its recorded %d — "+
				"lower knownRawJSONFetches so the gate keeps its grip", name, got, want)
		}
	}
}

type claudeRefusalResult struct {
	SeenLen                 int    `json:"seen_len"`
	ShowsObjectObject       bool   `json:"shows_object_object"`
	NamesSecretKey          bool   `json:"names_secret_key"`
	NamesMaxClaimAge        bool   `json:"names_max_claim_age"`
	NamesRequiredPermission bool   `json:"names_required_permission"`
	ShowsMessage            bool   `json:"shows_message"`
	OffersCodeInput         bool   `json:"offers_code_input"`
	FocusedID               string `json:"focused_id"`
	FieldPreNormalise       string `json:"field_pre_normalise"`
	FieldFlatDialect        string `json:"field_flat_dialect"`
	Error                   string `json:"error"`
}

func runClaudeLoginErrorScenarios(t *testing.T) map[string]claudeRefusalResult {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/claude_login_error_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]claudeRefusalResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if fatal, ok := results["fatal"]; ok {
		t.Fatalf("the scenarios threw: %s", fatal.Error)
	}
	return results
}

func TestDashboard_ClaudeLoginRefusalIsReadable(t *testing.T) {
	results := runClaudeLoginErrorScenarios(t)

	need := func(name string) claudeRefusalResult {
		got, ok := results[name]
		if !ok {
			t.Fatalf("the %s scenario did not report", name)
		}
		return got
	}

	// The reported bug, in the shape that caused it.
	got := need("structured_403")
	if got.ShowsObjectObject {
		t.Error("a structured refusal rendered \"[object Object]\" — this is the " +
			"reported bug: the message is nested under error.message and was " +
			"interpolated as an object")
	}
	if got.SeenLen == 0 {
		t.Error("nothing was shown at all after a refusal")
	}
	// A refusal is only useful if the remedy survives to the screen. These are
	// the two config changes that would fix a hub in this state, and before this
	// fix handleForbidden discarded the message that names them in favour of the
	// required_permission alone.
	if !got.NamesSecretKey || !got.NamesMaxClaimAge {
		t.Errorf("the refusal reached the user without its remedy: "+
			"names CLOOP_SECRET_KEY=%v, names max_claim_age_minutes=%v",
			got.NamesSecretKey, got.NamesMaxClaimAge)
	}
	if !got.NamesRequiredPermission {
		t.Error("the permission the action required was not named, which is the " +
			"one detail that tells an operator what to grant")
	}

	// A structured non-403 resolves, so it reaches the panel's own branch.
	if got := need("structured_409"); got.ShowsObjectObject || !got.ShowsMessage {
		t.Errorf("a structured 409 did not render in the panel: object_object=%v shows_message=%v",
			got.ShowsObjectObject, got.ShowsMessage)
	}

	// The older flat dialect must keep working.
	if got := need("flat_409"); got.ShowsObjectObject || !got.ShowsMessage {
		t.Errorf("a plain string error regressed: object_object=%v shows_message=%v",
			got.ShowsObjectObject, got.ShowsMessage)
	}

	// And a success must not be read as a failure.
	got = need("success")
	if got.ShowsObjectObject {
		t.Error("a successful login start rendered \"[object Object]\"")
	}
	if !got.OffersCodeInput {
		t.Error("a successful login start did not advance to the code-entry step — " +
			"normalizeAPIError or a truthy-error check is treating success as failure")
	}

	// Flattening must not eat the details another panel depends on. The OIDC
	// form blames a specific input from error.details.field, which is why
	// normalizeAPIError parks the original object on errorDetail.
	got = need("oidc_field_blamed")
	if got.ShowsObjectObject || !got.ShowsMessage {
		t.Errorf("the OIDC settings refusal did not render: object_object=%v shows_message=%v",
			got.ShowsObjectObject, got.ShowsMessage)
	}
	if got.FocusedID != "issuer" {
		t.Errorf("oidcErrField on a flattened body = %q, want \"issuer\" — "+
			"error.details.field did not survive normalizeAPIError, so the OIDC "+
			"form would blame the wrong input", got.FocusedID)
	}
	if got.FieldPreNormalise != "issuer" {
		t.Errorf("oidcErrField on an un-normalised body = %q, want \"issuer\" — a "+
			"direct fetch() still hands over the nested shape", got.FieldPreNormalise)
	}
	if got.FieldFlatDialect != "" {
		t.Errorf("oidcErrField invented a field %q for a flat-dialect error",
			got.FieldFlatDialect)
	}
}
