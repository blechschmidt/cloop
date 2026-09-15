package docs_test

// docs/reference/audit-events.md is generated, not written (Task 20284).
//
// The hub writes a hundred-odd distinct action names into audit_events and,
// until pkg/auditaction existed, every one of them was an inline string
// literal at its emission site across eight packages. No page listed them. An
// operator wiring the SIEM export into a detection rule had to read emission
// code to learn what they could key on, and docs/security/model.md cited two
// action names as evidence that a control works with nothing guaranteeing
// those strings were still in the code it described.
//
// Writing the page by hand would have documented the vocabulary accurately for
// about a release. So it is rendered from the registry, by this test, and the
// checked-in copy is compared against a fresh rendering on every run:
//
//	make docs-audit    # or: go test ./tests/docs -run TestAuditEventsReference -update
//
// The other tests here close the reverse direction. A page generated from the
// registry cannot go stale, but the prose pages that *cite* action names can —
// and those citations are load-bearing, because they are what tells a reader
// that a named control leaves evidence. TestActionCitationsResolve makes a
// citation of an action that no longer exists a build failure, and
// TestSecurityClaimsCiteLiveActions stops a page from opting out by rewriting
// the citation as a bare literal.

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// updateAudit rewrites the checked-in page instead of asserting against it.
var updateAudit = flag.Bool("update-audit", false, "regenerate docs/reference/audit-events.md")

// auditEventsPage is the page's path relative to the repository root.
const auditEventsPage = "docs/reference/audit-events.md"

// repoRoot is defined in drift_test.go, in this same package.

// auditPageIntro is the page's hand-written lead. What the trail is, what a
// row costs, and how to read the stability column is a human's job; the
// hundred-odd rows below it are not, and everything after this string is
// generated from pkg/auditaction.
const auditPageIntro = `# Audit event reference

Every action name cloop writes to the ` + "`event_type`" + ` column of
` + "`audit_events`" + `, generated from the registry the emitters reference. Do not
edit this file: it is rendered by ` + "`tests/docs/audit_events_test.go`" + ` from
` + "`pkg/auditaction`" + `, and a CI check fails when it stops matching. Regenerate
with ` + "`make docs-audit`" + `.

For what the trail is and how it is protected see the
[security model](../security/model.md); for the endpoints that read it see the
[HTTP API reference](http-api.md).

## How to read this

` + "`audit_events`" + ` is cloop's legal record: one append-only, hash-chained row per
mutation that actually changed something. It is distinct from the ` + "`events`" + `
table, which is a UI journal that may be lossy and is prunable at will. A row
carries an actor, an action, an entity type and id, and a JSON payload.

The **action** is the value of ` + "`event_type`" + `. It is the field a detection rule
keys on, and it is stable: a name in this list will not be renamed, because
renaming it would orphan rows already sealed into a chain that cannot be
rewritten. A superseded action is marked deprecated here and keeps being
emitted until retention has passed over the last row carrying it.

The **entity** is the value of ` + "`entity_type`" + `, and it says which id space
` + "`entity_id`" + ` is in. Filtering a subject's whole history means filtering on
both.

**Payload keys are conditional.** An emitter omits what it does not know, so
the keys listed for an action are what a consumer may expect to see, not what
every row carries. New keys may be added to a stable action without notice — a
consumer must tolerate that — but no listed key is removed or repurposed.

**Stability** is a contract with consumers, not a measure of code quality:

| Marker | Means |
| --- | --- |
| ` + "`stable`" + ` | Safe to key a paging alert on. The name and the listed payload keys will not change. |
| ` + "`beta`" + ` | The rows are real, but the name or payload may still change while the surface emitting them settles. Key a dashboard on it, not a pager. |
| ` + "`deprecated`" + ` | Still emitted, replaced by something else. The note says by what. |

### Exporting

` + "`cloop audit export`" + ` writes these rows as JSONL or CEF for a SIEM, and
` + "`cloop audit verify`" + ` checks the hash chain. Both are documented under
[commands](commands.md). Note that the trail exists per project *and* in the
control plane, with separate chains — a row emitted to one is not visible in
the other.
`

// TestAuditEventsReference regenerates the page with -update-audit, and
// otherwise fails when the checked-in copy has drifted from the registry.
func TestAuditEventsReference(t *testing.T) {
	path := filepath.Join(repoRoot(t), auditEventsPage)
	want := auditaction.Markdown(auditPageIntro)

	if *updateAudit {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatalf("writing %s: %v", auditEventsPage, err)
		}
		t.Logf("regenerated %s (%d bytes, %d actions)", auditEventsPage, len(want), len(auditaction.All()))
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is missing: %v\nRegenerate it with: make docs-audit", auditEventsPage, err)
	}
	if string(got) == want {
		return
	}
	t.Errorf("%s is out of date with pkg/auditaction.\nRegenerate it with: make docs-audit\n%s",
		auditEventsPage, describeActionDiff(string(got), want))
}

// describeActionDiff names the actions that moved rather than dumping two
// documents. The useful half of this failure is which action was added or
// removed; the rest is prose churn a reader can see in the diff.
func describeActionDiff(got, want string) string {
	gotActions, wantActions := actionsIn(got), actionsIn(want)

	var added, removed []string
	for a := range wantActions {
		if !gotActions[a] {
			added = append(added, a)
		}
	}
	for a := range gotActions {
		if !wantActions[a] {
			removed = append(removed, a)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	var b strings.Builder
	if len(added) > 0 {
		b.WriteString("\nActions the registry has but the page does not:\n")
		for _, a := range added {
			b.WriteString("  " + a + "\n")
		}
	}
	if len(removed) > 0 {
		b.WriteString("\nActions the page has but the registry does not:\n")
		for _, a := range removed {
			b.WriteString("  " + a + "\n")
		}
	}
	if b.Len() == 0 {
		b.WriteString("\n(The action rows match; a trigger, payload, note or the prose differs.)\n")
	}
	return b.String()
}

// actionsIn pulls the action names out of a rendered page's table rows. Only
// the first cell counts: a note or a trigger may mention a neighbouring action
// by name, and counting those would make the diff report churn as change.
func actionsIn(page string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(page, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 2 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if strings.Contains(name, ".") {
			out[name] = true
		}
	}
	return out
}

// TestAuditEventsReferenceIsSubstantial guards against the gate above passing
// vacuously. A page rendered from an empty registry would match a page
// regenerated from an empty registry, and both would be worthless.
func TestAuditEventsReferenceIsSubstantial(t *testing.T) {
	all := auditaction.All()
	if len(all) < 100 {
		t.Errorf("the registry has %d actions; the hub emitted more than a hundred "+
			"when it was written, so something is no longer being registered", len(all))
	}

	page, err := os.ReadFile(filepath.Join(repoRoot(t), auditEventsPage))
	if err != nil {
		t.Fatalf("%s is missing: %v", auditEventsPage, err)
	}
	text := string(page)
	for _, e := range all {
		if !strings.Contains(text, "`"+string(e.Action)+"`") {
			t.Errorf("action %q is registered but does not appear on %s", e.Action, auditEventsPage)
		}
	}

	// Each of the families a reader is most likely to arrive looking for,
	// named explicitly so a refactor that collapses one is visible here.
	for _, family := range []string{"task", "secret", "gitproxy", "kubeguard", "authz", "session"} {
		if !strings.Contains(text, "### "+family+".*") {
			t.Errorf("%s has no section for the %s.* family", auditEventsPage, family)
		}
	}
}

// actionCitation matches a markdown link whose text is a backticked action
// name and whose target is the generated reference page:
//
//	[`gitproxy.push_denied`](../reference/audit-events.md#gitproxy)
//
// A convention rather than a bare scan for dotted literals, and the reason is
// that a bare scan cannot work: `kubeguard.request_denied` is an action and
// `kubeguard.enabled` is a YAML key, and nothing lexical separates them. A
// scan that guessed would need a growing exemption list of config keys — which
// is the hand-maintained list this whole task exists to abolish.
//
// Making the citation a link costs the writer four characters and buys two
// things a scan cannot: the claim is checkable, and a reader who meets
// "denials are audited as X" in a threat model can click X and find out what X
// actually records.
var actionCitation = regexp.MustCompile("\\[`([a-z][a-z0-9_.]*)`\\]\\(([^)]*audit-events\\.md(?:#([a-z0-9_-]+))?)\\)")

// citingPages are the pages whose argument depends on an action existing.
// Each states that a control leaves evidence and names the row as proof, so a
// page that stops citing anything has either lost the claim or stopped
// backing it — both worth failing on.
var citingPages = []string{
	"docs/security/model.md",
	"docs/security/threat-model.md",
}

// TestActionCitationsResolve fails when a page cites an audit action the
// registry does not know, or links to a family section that does not exist.
//
// This is the check the task that created this file was really about.
// docs/security/threat-model.md says the image trust policy works and names
// `sandbox.image_denied` as the evidence; it does the same for
// `gitproxy.push_denied` against the git proxy. Those citations are the
// difference between a claim and a verifiable one, and nothing stopped the
// code from renaming either string and leaving both claims pointing at a row
// that is never written.
func TestActionCitationsResolve(t *testing.T) {
	root := repoRoot(t)
	anchors := renderedAnchors(t, root)

	var cited int
	err := filepath.Walk(filepath.Join(root, "docs"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, m := range actionCitation.FindAllStringSubmatch(string(body), -1) {
			name, anchor := m[1], m[3]
			cited++
			if !auditaction.Registered(auditaction.Action(name)) {
				t.Errorf("%s cites audit action `%s`, which pkg/auditaction does not know.\n"+
					"    A page that names an action as evidence a control works is only worth\n"+
					"    something if the action still exists. Either the action was renamed and\n"+
					"    this citation needs updating, or it never existed and the claim needs\n"+
					"    different evidence.", rel, name)
				continue
			}
			if anchor == "" {
				continue
			}
			if !anchors[anchor] {
				t.Errorf("%s links `%s` to #%s, which is not a heading on %s.\n"+
					"    The family sections are generated; link to the one this action is in.",
					rel, name, anchor, auditEventsPage)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking docs/: %v", err)
	}
	if cited == 0 {
		t.Error("no page under docs/ cites an audit action.\n" +
			"    The security pages did when this gate was written; if the citations were\n" +
			"    rewritten as bare literals, this check is now guarding nothing.")
	}
}

// TestSecurityClaimsCiteLiveActions requires each page that argues from audit
// evidence to keep at least one checkable citation.
//
// Without it the gate above is opt-out by accident: dropping the link syntax
// turns a verified claim back into an unverified one, and the suite goes green
// on the way.
func TestSecurityClaimsCiteLiveActions(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range citingPages {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s is missing: %v", rel, err)
			continue
		}
		if len(actionCitation.FindAllStringSubmatch(string(body), -1)) == 0 {
			t.Errorf("%s no longer cites any audit action as a link to %s.\n"+
				"    This page argues that controls leave evidence and names the rows as\n"+
				"    proof. Write the citation as [`action.name`](../reference/audit-events.md#family)\n"+
				"    so the claim fails the build if the action is ever renamed away.",
				rel, auditEventsPage)
		}
	}
}

// renderedAnchors returns the heading slugs on the generated page, computed
// the way GitHub and mkdocs compute them.
func renderedAnchors(t *testing.T, root string) map[string]bool {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, auditEventsPage))
	if err != nil {
		t.Fatalf("%s is missing: %v", auditEventsPage, err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		heading, ok := strings.CutPrefix(line, "### ")
		if !ok {
			continue
		}
		var slug strings.Builder
		for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
				slug.WriteRune(r)
			case r == ' ':
				slug.WriteRune('-')
			}
		}
		out[slug.String()] = true
	}
	if len(out) < 20 {
		t.Fatalf("found only %d family headings on %s", len(out), auditEventsPage)
	}
	return out
}
