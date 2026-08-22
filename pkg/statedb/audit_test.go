package statedb

// Tests for the audit trail: filter correctness, tamper detection, and the
// redaction guarantee (Task 20167).
//
// The chain is the whole point of the table, so the tamper tests do their
// mutation the way a real tamper would — raw SQL behind cloop's back, not
// through AppendAuditEvent — and then assert the chain notices.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newAuditDB opens a temp database with audit emission on, since the package
// default can be flipped by other tests in the same binary.
func newAuditDB(t *testing.T) *DB {
	t.Helper()
	prev := auditEnabled
	SetAuditEnabled(true)
	t.Cleanup(func() { SetAuditEnabled(prev) })

	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedAuditEvents appends a fixed, deterministic set of rows spanning the
// dimensions the filter supports.
func seedAuditEvents(t *testing.T, db *DB) []AuditEvent {
	t.Helper()
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	specs := []AuditEvent{
		{Timestamp: base, Actor: "alice@example.com", EventType: "task.upsert", EntityType: "task", EntityID: "1", Payload: `{"title":"first"}`},
		{Timestamp: base.Add(1 * time.Hour), Actor: "bob@example.com", EventType: "task.delete", EntityType: "task", EntityID: "1", Payload: `{"id":1}`},
		{Timestamp: base.Add(2 * time.Hour), Actor: "alice@example.com", EventType: "executor.enroll", EntityType: "executor", EntityID: "edge-1", Payload: `{"name":"edge one"}`},
		{Timestamp: base.Add(3 * time.Hour), Actor: "system", EventType: "config.set", EntityType: "config", EntityID: "", Payload: `{"yaml":"provider: claudecode"}`},
		{Timestamp: base.Add(4 * time.Hour), Actor: "bob@example.com", EventType: "authz.denied", EntityType: "permission", EntityID: "run.start", Payload: `{"outcome":"denied"}`},
	}
	out := make([]AuditEvent, 0, len(specs))
	for i := range specs {
		ev := specs[i]
		if err := db.AppendAuditEvent(&ev); err != nil {
			t.Fatalf("append event %d: %v", i, err)
		}
		out = append(out, ev)
	}
	return out
}

func TestAuditFilterCorrectness(t *testing.T) {
	db := newAuditDB(t)
	seeded := seedAuditEvents(t, db)
	base := seeded[0].Timestamp

	cases := []struct {
		name    string
		filter  AuditFilter
		wantIDs []int64
	}{
		{"no filter returns everything ascending", AuditFilter{}, []int64{1, 2, 3, 4, 5}},
		{"actor", AuditFilter{Actor: "alice@example.com"}, []int64{1, 3}},
		{"event_type", AuditFilter{EventType: "task.delete"}, []int64{2}},
		{"entity_type", AuditFilter{EntityType: "task"}, []int64{1, 2}},
		{"entity_id within type", AuditFilter{EntityType: "executor", EntityID: "edge-1"}, []int64{3}},
		{"actor and entity_type combine as AND", AuditFilter{Actor: "alice@example.com", EntityType: "task"}, []int64{1}},
		{"since is inclusive", AuditFilter{Since: base.Add(3 * time.Hour)}, []int64{4, 5}},
		{"until is inclusive", AuditFilter{Until: base.Add(1 * time.Hour)}, []int64{1, 2}},
		{"since and until bound a window", AuditFilter{Since: base.Add(1 * time.Hour), Until: base.Add(3 * time.Hour)}, []int64{2, 3, 4}},
		{"search matches payload case-insensitively", AuditFilter{Search: "EDGE ONE"}, []int64{3}},
		{"search that matches nothing returns nothing", AuditFilter{Search: "no-such-payload"}, nil},
		{"limit truncates", AuditFilter{Limit: 2}, []int64{1, 2}},
		{"offset skips", AuditFilter{Limit: 2, Offset: 2}, []int64{3, 4}},
		{"descending order", AuditFilter{Order: "desc"}, []int64{5, 4, 3, 2, 1}},
		{"desc with limit takes the newest", AuditFilter{Order: "desc", Limit: 2}, []int64{5, 4}},
		{"from_id lower-bounds", AuditFilter{FromID: 4}, []int64{4, 5}},
		{"to_id upper-bounds", AuditFilter{ToID: 2}, []int64{1, 2}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, total, err := db.ListAuditEvents(tc.filter)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			// total is the unfiltered table count regardless of filter —
			// the paging UI relies on that, so pin it.
			if total != len(seeded) {
				t.Errorf("total = %d, want %d (the unfiltered count)", total, len(seeded))
			}
			got := make([]int64, 0, len(rows))
			for _, r := range rows {
				got = append(got, r.ID)
			}
			if !equalInt64s(got, tc.wantIDs) {
				t.Errorf("ids = %v, want %v", got, tc.wantIDs)
			}
		})
	}
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestVerifyAuditChainAcceptsAnIntactChain(t *testing.T) {
	db := newAuditDB(t)
	seedAuditEvents(t, db)

	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("chain reported broken on an untouched log: %s", report.Reason)
	}
	if report.Total != 5 {
		t.Errorf("Total = %d, want 5", report.Total)
	}
	if report.BreakAtID != 0 || report.ExpectedHash != "" || report.ActualHash != "" {
		t.Errorf("clean report should carry no break details, got %+v", report)
	}
}

// TestVerifyAuditChainDetectsMutatedRow is the test the whole table exists
// for: an edit made behind cloop's back must be detectable.
func TestVerifyAuditChainDetectsMutatedRow(t *testing.T) {
	db := newAuditDB(t)
	seeded := seedAuditEvents(t, db)
	victim := seeded[2] // id 3

	// Tamper the way an attacker with database access would: change the
	// payload in place and leave the stored hashes alone.
	if _, err := db.conn.Exec(
		`UPDATE audit_events SET payload = ? WHERE id = ?`,
		`{"name":"something else entirely"}`, victim.ID,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("chain verified clean after a row was edited in place")
	}
	if report.BreakAtID != victim.ID {
		t.Errorf("BreakAtID = %d, want %d", report.BreakAtID, victim.ID)
	}
	if report.ActualHash != victim.RowHash {
		t.Errorf("ActualHash = %q, want the stored hash %q", report.ActualHash, victim.RowHash)
	}
	if report.ExpectedHash == "" || report.ExpectedHash == report.ActualHash {
		t.Errorf("ExpectedHash should be the recomputed hash and differ from the stored one; got expected=%q actual=%q",
			report.ExpectedHash, report.ActualHash)
	}
	if !strings.Contains(report.Reason, "row_hash mismatch") {
		t.Errorf("Reason = %q, want it to name the row_hash mismatch", report.Reason)
	}
}

// TestVerifyAuditChainDetectsDeletedRow covers the other half of tampering:
// removing an inconvenient row rather than editing one.
func TestVerifyAuditChainDetectsDeletedRow(t *testing.T) {
	db := newAuditDB(t)
	seedAuditEvents(t, db)

	if _, err := db.conn.Exec(`DELETE FROM audit_events WHERE id = ?`, 3); err != nil {
		t.Fatalf("delete: %v", err)
	}

	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("chain verified clean after a row was deleted")
	}
	if report.BreakAtID != 4 {
		t.Errorf("BreakAtID = %d, want 4 (the row after the gap)", report.BreakAtID)
	}
	if !strings.Contains(report.Reason, "id gap") {
		t.Errorf("Reason = %q, want it to name the id gap", report.Reason)
	}
}

// TestVerifyAuditChainDetectsForgedRow covers an insertion whose own hash is
// self-consistent but whose prev_hash does not chain to its predecessor —
// the case a naive per-row checksum would miss.
func TestVerifyAuditChainDetectsForgedRow(t *testing.T) {
	db := newAuditDB(t)
	seedAuditEvents(t, db)

	forged := AuditEvent{
		ID: 3, Timestamp: time.Date(2026, 3, 1, 14, 0, 0, 0, time.UTC),
		Actor: "mallory", EventType: "task.upsert", EntityType: "task", EntityID: "9",
		Payload: `{"title":"forged"}`,
		// Chains to nothing: a plausible-looking but unrelated hash.
		PrevHash: strings.Repeat("ab", 32),
	}
	forged.RowHash = computeRowHash(forged) // internally consistent

	if _, err := db.conn.Exec(
		`UPDATE audit_events SET actor=?, event_type=?, entity_type=?, entity_id=?,
		 payload=?, prev_hash=?, row_hash=?, timestamp=? WHERE id=?`,
		forged.Actor, forged.EventType, forged.EntityType, forged.EntityID,
		forged.Payload, forged.PrevHash, forged.RowHash,
		forged.Timestamp.Format(time.RFC3339Nano), forged.ID,
	); err != nil {
		t.Fatalf("forge: %v", err)
	}

	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("a self-consistent row that chains to nothing was accepted")
	}
	if report.BreakAtID != 3 {
		t.Errorf("BreakAtID = %d, want 3", report.BreakAtID)
	}
	if !strings.Contains(report.Reason, "prev_hash mismatch") {
		t.Errorf("Reason = %q, want it to name the prev_hash mismatch", report.Reason)
	}
}

// ── Redaction ───────────────────────────────────────────────────────────────

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{
		"api_key", "apiKey", "APIKey", "anthropic_api_key",
		"secret", "client_secret", "ClientSecret",
		"password", "passphrase",
		"token", "bearer_token", "BearerToken", "enrollment_token",
		"credential", "credentials", "authorization",
		"private_key", "session_key", "kubeconfig", "sealed", "ciphertext",
		"github_pat", "pat",
	}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = false, want true", k)
		}
	}

	// The counters and structural fields that must survive: redacting these
	// would break cost reconciliation and make the trail unreadable.
	safe := []string{
		"total_input_tokens", "total_output_tokens", "input_tokens",
		"output_tokens", "max_tokens", "TotalInputTokens",
		"path", "project_path", "pattern", "separator", "compatible",
		"cache_key", "owner_key", "sort_key", "visibility_key",
		"id", "title", "status", "actor", "event_type", "author",
	}
	for _, k := range safe {
		if isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = true, want false — this is not a credential", k)
		}
	}
}

func TestMarshalAuditPayloadRedactsNestedSecrets(t *testing.T) {
	const canary = "sk-ant-SUPERSECRET-canary-value-0123456789"

	blob := MarshalAuditPayload(map[string]any{
		"executor_id": "edge-1",
		"api_key":     canary,
		"nested": map[string]any{
			"github_pat": canary,
			"safe_field": "visible",
		},
		"list": []any{
			map[string]any{"token": canary},
		},
		"total_input_tokens": 1234,
	})

	if strings.Contains(blob, canary) {
		t.Fatalf("audit payload discloses the credential: %s", blob)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(blob), &decoded); err != nil {
		t.Fatalf("redacted payload is not valid JSON: %v (%s)", err, blob)
	}
	if decoded["executor_id"] != "edge-1" {
		t.Errorf("non-sensitive field was lost: %v", decoded["executor_id"])
	}
	if decoded["api_key"] != redactedMarker {
		t.Errorf("api_key = %v, want %q", decoded["api_key"], redactedMarker)
	}
	// The counter must survive as a number, not become a marker.
	if got, ok := decoded["total_input_tokens"].(float64); !ok || got != 1234 {
		t.Errorf("total_input_tokens = %v, want the number 1234", decoded["total_input_tokens"])
	}
	nested, _ := decoded["nested"].(map[string]any)
	if nested["github_pat"] != redactedMarker {
		t.Errorf("nested github_pat = %v, want redacted", nested["github_pat"])
	}
	if nested["safe_field"] != "visible" {
		t.Errorf("nested safe_field = %v, want it preserved", nested["safe_field"])
	}
}

func TestMarshalAuditPayloadPreservesEmptyAndNullSecrets(t *testing.T) {
	// An unset credential must not be reported as a withheld one: that would
	// tell an auditor a key existed when none did.
	blob := MarshalAuditPayload(map[string]any{"api_key": "", "token": nil})
	var decoded map[string]any
	if err := json.Unmarshal([]byte(blob), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["api_key"] != "" {
		t.Errorf("empty api_key = %v, want the empty string preserved", decoded["api_key"])
	}
	if decoded["token"] != nil {
		t.Errorf("null token = %v, want nil preserved", decoded["token"])
	}
}

func TestRedactYAMLSecrets(t *testing.T) {
	const canary = "sk-ant-CANARY-0123456789abcdef"
	in := "provider: claudecode\n" +
		"anthropic:\n" +
		"    api_key: " + canary + "\n" +
		"    model: claude-opus-4-6\n" +
		"openai:\n" +
		"    api_key: " + canary + "\n" +
		"    base_url: \"\"\n" +
		"# a comment mentioning nothing\n" +
		"step_timeout: \"0\"\n"

	got := redactYAMLSecrets(in)
	if strings.Contains(got, canary) {
		t.Fatalf("redacted YAML still contains the key:\n%s", got)
	}
	for _, want := range []string{
		"provider: claudecode",
		"    api_key: " + redactedMarker,
		"    model: claude-opus-4-6",
		"# a comment mentioning nothing",
		`step_timeout: "0"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("redacted YAML missing %q:\n%s", want, got)
		}
	}
	// Structure must survive: same number of lines, same indentation.
	if gotLines, inLines := strings.Count(got, "\n"), strings.Count(in, "\n"); gotLines != inLines {
		t.Errorf("line count changed: %d → %d", inLines, gotLines)
	}
}

func TestRedactYAMLSecretsHandlesBlockScalars(t *testing.T) {
	const canary = "MULTILINE-CANARY-VALUE"
	in := "kubeconfig: |\n" +
		"    apiVersion: v1\n" +
		"    " + canary + "\n" +
		"next_key: visible\n"

	got := redactYAMLSecrets(in)
	if strings.Contains(got, canary) {
		t.Fatalf("block scalar leaked its content:\n%s", got)
	}
	if !strings.Contains(got, "kubeconfig: "+redactedMarker) {
		t.Errorf("block introducer not redacted:\n%s", got)
	}
	if !strings.Contains(got, "next_key: visible") {
		t.Errorf("redaction swallowed the following key:\n%s", got)
	}
}

// TestAuditExecutorLifecycleEmits pins the emitter added for the executor
// fleet, which was the gap in the trail before Task 20167.
func TestAuditExecutorLifecycleEmits(t *testing.T) {
	db := newAuditDB(t)

	AuditExecutorLifecycle(db, ExecutorAuditInput{
		Action:     "enroll",
		ExecutorID: "edge-7",
		Actor:      "alice@example.com",
		Detail:     map[string]any{"name": "edge seven", "token": "must-not-appear"},
	})

	rows, _, err := db.ListAuditEvents(AuditFilter{EntityType: "executor"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d executor rows, want 1", len(rows))
	}
	ev := rows[0]
	if ev.EventType != "executor.enroll" {
		t.Errorf("EventType = %q, want executor.enroll", ev.EventType)
	}
	if ev.EntityID != "edge-7" {
		t.Errorf("EntityID = %q, want edge-7", ev.EntityID)
	}
	if ev.Actor != "alice@example.com" {
		t.Errorf("Actor = %q, want the acting identity", ev.Actor)
	}
	if !strings.Contains(ev.Payload, "edge seven") {
		t.Errorf("payload lost the descriptive detail: %s", ev.Payload)
	}
	// Even a caller that wrongly passes a token gets it redacted centrally.
	if strings.Contains(ev.Payload, "must-not-appear") {
		t.Errorf("payload discloses a token passed by a careless caller: %s", ev.Payload)
	}
}
