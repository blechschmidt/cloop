package security

// Guarantee 8: the compliance audit trail never contains credential material
// (Task 20167).
//
// The audit trail is the one table in cloop designed to leave the machine.
// An operator exports it to a SIEM, hands it to an auditor, and keeps it for
// years — long after the credentials it mentions have been rotated. It is
// also append-only and hash-chained, which makes a leak there uniquely
// unfixable: you cannot delete the offending row without breaking the chain
// that gives the rest of the trail its value. So "no secret ever lands in an
// audit row" has to hold by construction, not by every emitter remembering.
//
// This asserts it end to end against the real writers: saving a config that
// contains API keys, recording an executor enrollment, and recording a
// secret-broker decision. Each is driven through the same entry point
// production uses, then the entire trail is read back and scanned for the
// canary in every encoding it might have taken on the way through.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditCanary is deliberately shaped like a real Anthropic key so that a
// naive "does it look like a secret" filter cannot pass this test by
// accident, and long enough that a substring match is unambiguous.
const auditCanary = "sk-ant-api03-AUDITCANARY-must-never-be-persisted-0123456789abcdef"

// newAuditProject initialises a real cloop project in a temp dir and returns
// its workdir. state.Init already writes audit rows, so the trail is
// non-empty before the test adds anything.
func newAuditProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := state.Init(dir, "audit conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return dir
}

// dumpTrail returns every audit row concatenated, in both JSON and Go-syntax
// renderings. Both are checked because a credential can survive one and not
// the other: a struct field with no JSON tag vanishes from the first and is
// printed in full by the second.
func dumpTrail(t *testing.T, workDir string) string {
	t.Helper()
	log, err := eventlog.Open(workDir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()

	rows, _, err := log.List(eventlog.AuditFilter{})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("audit trail is empty — this test would pass vacuously")
	}

	var b strings.Builder
	for _, ev := range rows {
		fmt.Fprintf(&b, "%+v\n", ev)
		b.WriteString(ev.Payload)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestConfigAPIKeysNeverReachTheAuditTrail covers the leak this task found:
// pkg/config serialises the whole of config.yaml — API keys included — into
// SetConfigBlob, which emits a config.set audit row.
func TestConfigAPIKeysNeverReachTheAuditTrail(t *testing.T) {
	dir := newAuditProject(t)

	cfg := config.Default()
	cfg.Anthropic.APIKey = auditCanary
	cfg.OpenAI.APIKey = auditCanary + "-openai"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	trail := dumpTrail(t, dir)

	// Sanity: the config.set row must actually exist, or the assertion below
	// is checking an absence that was never at risk.
	if !strings.Contains(trail, "config.set") {
		t.Fatal("no config.set row in the trail — the test is not exercising the path it claims to")
	}
	assertNoSecretLeak(t, trail, cfg.Anthropic.APIKey, "the audit trail (anthropic api_key)")
	assertNoSecretLeak(t, trail, cfg.OpenAI.APIKey, "the audit trail (openai api_key)")

	// The row must still be useful: redaction that dropped the whole payload
	// would pass the leak check while destroying the record.
	if !strings.Contains(trail, "provider") {
		t.Error("the config.set payload lost its non-secret structure; " +
			"redaction should withhold values, not delete the record")
	}
}

// TestExecutorEnrollmentTokenNeverReachesTheAuditTrail covers the emitter
// added for the executor fleet. Enrollment tokens are single-use and
// short-lived, which makes writing one into a permanent record worse than it
// looks: the trail outlives the token's usefulness to its owner but not its
// usefulness to an attacker reading a shipped log.
func TestExecutorEnrollmentTokenNeverReachesTheAuditTrail(t *testing.T) {
	dir := newAuditProject(t)

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()

	// A caller that carelessly passes the token in Detail must still not
	// leak it: the guarantee is a property of the writer, not of the caller.
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action:     "enroll",
		ExecutorID: "edge-1",
		Actor:      "alice@example.com",
		Detail: map[string]any{
			"name":             "edge one",
			"token":            auditCanary,
			"enrollment_token": auditCanary,
			"nested":           map[string]any{"bearer_token": auditCanary},
		},
	})

	trail := dumpTrail(t, dir)
	if !strings.Contains(trail, "executor.enroll") {
		t.Fatal("no executor.enroll row — the emitter did not run")
	}
	assertNoSecretLeak(t, trail, auditCanary, "the audit trail (executor enrollment)")

	if !strings.Contains(trail, "edge one") {
		t.Error("the executor row lost its descriptive detail; the trail must still " +
			"answer which device was enrolled")
	}
}

// TestSecretBrokerDecisionsNeverCarryMaterial covers the broker path, which
// already redacts upstream — this asserts the audit writer is a second,
// independent barrier rather than trusting that.
func TestSecretBrokerDecisionsNeverCarryMaterial(t *testing.T) {
	dir := newAuditProject(t)

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()

	statedb.AuditSecretDecision(db, statedb.SecretAuditInput{
		Actor:     "maintainer@example.com",
		EventType: "secret.lease",
		EntityID:  "github-pat",
		Payload: map[string]any{
			"decision":    "allow",
			"executor_id": "edge-1",
			"secret":      auditCanary,
			"credential":  auditCanary,
			"sealed":      auditCanary,
			"kubeconfig":  auditCanary,
		},
	})

	trail := dumpTrail(t, dir)
	if !strings.Contains(trail, "secret.lease") {
		t.Fatal("no secret.lease row — the emitter did not run")
	}
	assertNoSecretLeak(t, trail, auditCanary, "the audit trail (secret broker decision)")

	if !strings.Contains(trail, "edge-1") {
		t.Error("the lease row lost the executor it was issued to; that is the " +
			"question the trail exists to answer")
	}
}

// TestRedactionSurvivesTheHashChain asserts the two mechanisms compose:
// redaction happens before the row hash is computed, so a redacted trail
// still verifies. If redaction ran after hashing, every row would fail
// verification and the trail would be worthless.
func TestRedactionSurvivesTheHashChain(t *testing.T) {
	dir := newAuditProject(t)

	cfg := config.Default()
	cfg.Anthropic.APIKey = auditCanary
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action: "enroll", ExecutorID: "edge-1", Actor: "alice",
		Detail: map[string]any{"token": auditCanary},
	})

	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("a redacted trail failed chain verification at id=%d: %s "+
			"(redaction must happen before the row hash is computed)",
			report.BreakAtID, report.Reason)
	}
	if report.Total < 2 {
		t.Errorf("only %d rows verified; expected the config and executor rows", report.Total)
	}
}

// TestEveryAuditRowIsScannedForSecrets is the belt-and-braces sweep: drive
// several writers into one trail and scan the whole thing at once, so a new
// emitter added later without its own test is still covered by this one.
func TestEveryAuditRowIsScannedForSecrets(t *testing.T) {
	dir := newAuditProject(t)

	cfg := config.Default()
	cfg.Anthropic.APIKey = auditCanary
	cfg.OpenAI.APIKey = auditCanary
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()

	for _, action := range []string{"enroll", "revoke", "cordon", "drain", "bind", "unbind"} {
		statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
			Action: action, ExecutorID: "edge-1", Actor: "alice@example.com",
			Detail: map[string]any{"reason": "routine", "api_key": auditCanary},
		})
	}
	for _, evType := range []string{"secret.mint", "secret.grant", "secret.lease", "secret.revoke"} {
		statedb.AuditSecretDecision(db, statedb.SecretAuditInput{
			Actor: "alice@example.com", EventType: evType, EntityID: "github-pat",
			Payload: map[string]any{"password": auditCanary, "decision": "allow"},
		})
	}

	log, err := eventlog.Open(dir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()
	rows, _, err := log.List(eventlog.AuditFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) < 10 {
		t.Fatalf("only %d rows in the trail; expected the config, executor and secret rows", len(rows))
	}

	// Scan each row individually so a failure names the offending id rather
	// than reporting that "the trail" leaked.
	for _, ev := range rows {
		assertNoSecretLeak(t, ev.Payload, auditCanary,
			fmt.Sprintf("audit row #%d (%s)", ev.ID, ev.EventType))
		assertNoSecretLeak(t, fmt.Sprintf("%+v", ev), auditCanary,
			fmt.Sprintf("audit row #%d (%s) Go-syntax rendering", ev.ID, ev.EventType))
	}
}
