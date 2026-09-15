package auditaction

import (
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// actionNameShape is the vocabulary an action name may use: lowercase letters,
// digits and underscores inside a segment, dots between segments.
//
// Enforced rather than assumed because the names are consumed by things that
// treat them as opaque keys — a SIEM field, a detection rule, an mkdocs
// heading anchor — and an action with a capital letter or a hyphen would work
// everywhere except the one place someone later depends on.
var actionNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

func TestRegistryIsWellFormed(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("registry is empty")
	}
	seen := map[Action]bool{}
	for _, e := range registry {
		if seen[e.Action] {
			t.Errorf("action %q is registered twice", e.Action)
		}
		seen[e.Action] = true

		if !actionNameShape.MatchString(string(e.Action)) {
			t.Errorf("action %q does not match the name shape %s", e.Action, actionNameShape)
		}
		if strings.TrimSpace(e.Entity) == "" {
			t.Errorf("action %q has no entity type", e.Action)
		}
		if strings.TrimSpace(e.Trigger) == "" {
			t.Errorf("action %q has no trigger", e.Action)
		}
		if !strings.HasSuffix(strings.TrimSpace(e.Trigger), ".") {
			t.Errorf("action %q: trigger should be a sentence ending in a full stop, got %q",
				e.Action, e.Trigger)
		}
		if !e.Stability.Valid() {
			t.Errorf("action %q has stability %q, which is not one of stable/beta/deprecated",
				e.Action, e.Stability)
		}
		if !e.Read.Valid() {
			t.Errorf("action %q names read permission %q, which pkg/authz does not define",
				e.Action, e.Read)
		}
		if len(e.Payload) == 0 {
			t.Errorf("action %q lists no payload keys; if it genuinely carries none, say so explicitly",
				e.Action)
		}
		for _, k := range e.Payload {
			if strings.TrimSpace(k) == "" {
				t.Errorf("action %q has an empty payload key", e.Action)
			}
		}
		if dup := firstDuplicate(e.Payload); dup != "" {
			t.Errorf("action %q lists payload key %q twice", e.Action, dup)
		}
	}
}

func firstDuplicate(keys []string) string {
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			return k
		}
		seen[k] = true
	}
	return ""
}

// TestEveryEntryIsReachableByConstant proves the constants in actions.go and
// the entries in registry.go describe the same set.
//
// The two files are separate so a reviewer sees a declaration and its
// documentation as one diff, but separation is exactly what lets them drift:
// a constant with no entry documents nothing, and an entry with no constant
// cannot be referenced by an emission site, which is the whole mechanism.
func TestEveryEntryIsReachableByConstant(t *testing.T) {
	// The constants are the package's exported surface, so the honest check is
	// that Lookup answers for each entry and that nothing else claims to be an
	// action. Go gives no reflection over untyped constants, so the companion
	// direction — a constant with no entry — is checked in
	// tests/arch/auditaction_test.go, which parses actions.go as source.
	for _, e := range registry {
		got, ok := Lookup(e.Action)
		if !ok {
			t.Errorf("Lookup(%q) says it is not registered, but it is in the registry", e.Action)
			continue
		}
		if got.Action != e.Action {
			t.Errorf("Lookup(%q) returned the entry for %q", e.Action, got.Action)
		}
	}
	if Registered("task.definitely_not_an_action") {
		t.Error("Registered accepted a name that is not in the registry")
	}
}

// TestFamilyAndVerbSplitTheName pins the two accessors the emission sites
// depend on. Verb in particular is load-bearing: several emitters put the bare
// verb in the payload alongside the qualified name in the column, and a
// converted site that got this wrong would change bytes in rows that are
// already sealed into a hash chain.
func TestFamilyAndVerbSplitTheName(t *testing.T) {
	cases := []struct {
		action Action
		family string
		verb   string
	}{
		{ActionTaskUpsert, "task", "upsert"},
		{ActionExecutorCordon, "executor", "cordon"},
		{ActionExecutorStateChange, "executor", "state_change"},
		{ActionSandboxImageDenied, "sandbox", "image_denied"},
		{ActionSandboxAttachOpen, "sandbox.attach", "open"},
		{ActionSecretLease, "secret", "lease"},
		{ActionSecretLeaseSweep, "secret.lease", "sweep"},
		{ActionCIRejected, "ci", "rejected"},
		{ActionCISessionMinted, "ci.session", "minted"},
		{ActionCIRuleCreated, "ci.rule", "created"},
		{ActionGitHubAppTokenDestroy, "github_app", "token_destroy"},
		{ActionProjectMemberLeave, "project.member", "leave"},
		{ActionUserOffboardSession, "user", "offboard_session"},
	}
	for _, c := range cases {
		if got := c.action.Family(); got != c.family {
			t.Errorf("%q.Family() = %q, want %q", c.action, got, c.family)
		}
		if got := c.action.Verb(); got != c.verb {
			t.Errorf("%q.Verb() = %q, want %q", c.action, got, c.verb)
		}
	}
}

// TestSecretLeasePairIsNotAmbiguous guards the one genuinely awkward pair in
// the registry: `secret.lease` is an action and `secret.lease.sweep` is a
// different action in a different family. A naive prefix rule would put the
// first inside the second's family and silently move it on the page.
func TestSecretLeasePairIsNotAmbiguous(t *testing.T) {
	if ActionSecretLease.Family() != "secret" {
		t.Errorf("secret.lease landed in family %q", ActionSecretLease.Family())
	}
	if ActionSecretLeaseSweep.Family() != "secret.lease" {
		t.Errorf("secret.lease.sweep landed in family %q", ActionSecretLeaseSweep.Family())
	}
	for _, e := range InFamily("secret") {
		if e.Action == ActionSecretLeaseSweep {
			t.Error("secret.lease.sweep is listed under the secret family as well as its own")
		}
	}
}

// TestFamilyConstructorsProduceRegisteredActions covers the five emitters that
// compose their name at runtime. The domain of each constructor — which verbs
// can actually reach it — is proven against the source enums in
// tests/arch/auditaction_test.go; what is checked here is the composition
// itself, so a change to compose() cannot quietly reshape every name.
func TestFamilyConstructorsProduceRegisteredActions(t *testing.T) {
	cases := []struct {
		name string
		got  Action
		want Action
	}{
		{"executor", ExecutorLifecycle("cordon"), ActionExecutorCordon},
		{"workspace", WorkspacePhase("provision_start"), ActionWorkspaceProvisionStart},
		{"gitproxy", GitProxyEvent("push_denied"), ActionGitProxyPushDenied},
		{"kubeguard", KubeGuardEvent("request_denied"), ActionKubeGuardRequestDenied},
		{"authz", AuthzOutcome("denied"), ActionAuthzDenied},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s constructor produced %q, want %q", c.name, c.got, c.want)
		}
		if !Registered(c.got) {
			t.Errorf("%s constructor produced unregistered action %q", c.name, c.got)
		}
	}
}

// TestComposeCollapsesAnEmptyVerb pins the guard that keeps an unset field from
// producing a name ending in a dot. "executor." matches nothing and reads like
// a truncation bug in whatever consumed it; "executor" is visibly a
// misconfiguration in a query result.
func TestComposeCollapsesAnEmptyVerb(t *testing.T) {
	for _, in := range []string{"", "   ", "\t"} {
		if got := ExecutorLifecycle(in); got != Action(FamilyExecutor) {
			t.Errorf("ExecutorLifecycle(%q) = %q, want %q", in, got, FamilyExecutor)
		}
	}
	if got := GitProxyEvent("  push_denied  "); got != ActionGitProxyPushDenied {
		t.Errorf("GitProxyEvent trimmed to %q", got)
	}
}

// TestAllIsSortedAndCopied checks the two properties callers rely on: a stable
// order, and a slice they may mutate. The generated page sorts within a family
// and the gates iterate All(), so an aliased backing array would let one
// caller's sort reorder another's registry.
func TestAllIsSortedAndCopied(t *testing.T) {
	all := All()
	if len(all) != len(registry) {
		t.Fatalf("All() returned %d entries, registry has %d", len(all), len(registry))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Action >= all[i].Action {
			t.Fatalf("All() is not sorted: %q then %q", all[i-1].Action, all[i].Action)
		}
	}
	all[0].Action = "mutated.by.caller"
	if All()[0].Action == "mutated.by.caller" {
		t.Error("All() aliases the registry; a caller can rewrite it")
	}
}

// TestEveryFamilyHasAHome guards the page's grouping. A family whose name is
// not covered by the multi-segment list and has no dot at all would render as
// its own heading with one action in it — harmless but a sign the name is
// wrong.
func TestEveryFamilyHasAHome(t *testing.T) {
	for _, f := range Families() {
		if !strings.Contains(f, ".") && len(InFamily(f)) == 0 {
			t.Errorf("family %q has no entries", f)
		}
		if f == "" {
			t.Error("an action produced an empty family name")
		}
	}
}

// TestReadPermissionIsRealAndAdminOnly pins the claim the generated page makes
// about who can read the trail. If someone widens PermAuditRead down the role
// ladder, this fails and the page has to be regenerated to say so — which is
// the point: the page must not keep claiming "admin only" after it stops
// being true.
func TestReadPermissionIsRealAndAdminOnly(t *testing.T) {
	holders := rolesHolding(authz.PermAuditRead)
	if len(holders) == 0 {
		t.Fatal("no role holds audit.read; the trail would be unreadable through the API")
	}
	for _, r := range holders {
		if r != authz.RoleAdmin {
			t.Errorf("role %q now holds audit.read; regenerate docs/reference/audit-events.md "+
				"with `make docs-audit` so the page stops saying the trail is admin-only", r)
		}
	}
}

// TestMarkdownRendersEveryAction is the cheap guard against a rendering change
// that silently drops a section. The page-level drift gate lives in
// tests/docs, but that gate compares against a checked-in file which would be
// regenerated alongside the bug.
func TestMarkdownRendersEveryAction(t *testing.T) {
	page := Markdown("# test\n\nintro\n")
	for _, e := range registry {
		if !strings.Contains(page, "`"+string(e.Action)+"`") {
			t.Errorf("action %q does not appear in the rendered page", e.Action)
		}
	}
	for _, f := range Families() {
		if !strings.Contains(page, "### "+f+".*") {
			t.Errorf("family %q has no heading in the rendered page", f)
		}
	}
}

// TestMarkdownEscapesTableCells checks that prose containing a pipe cannot
// break the table it is rendered into. No entry has one today; the guard is
// for the one that will.
func TestMarkdownEscapesTableCells(t *testing.T) {
	if got := cell("a | b\nc"); got != "a \\| b c" {
		t.Errorf("cell() = %q, want %q", got, "a \\| b c")
	}
}
