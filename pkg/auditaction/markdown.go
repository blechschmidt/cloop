package auditaction

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// Markdown renders the whole registry as docs/reference/audit-events.md.
//
// The page is generated rather than written for the same reason
// docs/reference/http-api.md is: a hand-maintained list of 100-odd strings
// diverges from the code within one release, and the divergence is invisible
// — a stale page still reads as authoritative. tests/docs/audit_events_test.go
// compares this output against the checked-in file and fails when they differ.
//
// intro is the hand-written lead. It is passed in rather than embedded here so
// the prose that explains the trail lives next to the test that owns the page,
// where a writer will find it, rather than inside a package whose job is the
// data.
func Markdown(intro string) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(intro, "\n"))
	b.WriteString("\n\n")

	writeReaders(&b)

	b.WriteString("## Actions by family\n\n")
	b.WriteString(fmt.Sprintf(
		"%d actions in %d families. Every action is listed: this section is the whole\n"+
			"vocabulary of the `event_type` column.\n\n",
		len(registry), len(Families())))
	writeFamilyIndex(&b)

	for _, fam := range Families() {
		writeFamily(&b, fam)
	}
	return b.String()
}

// writeReaders renders who may read the trail. Derived from pkg/authz rather
// than stated, so a change to the role ladder moves this section on the next
// regeneration instead of quietly making it wrong.
func writeReaders(b *strings.Builder) {
	b.WriteString("## Who may read these\n\n")

	perms := map[authz.Permission][]Entry{}
	for _, e := range registry {
		perms[e.Read] = append(perms[e.Read], e)
	}
	var ordered []authz.Permission
	for p := range perms {
		ordered = append(ordered, p)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	for _, p := range ordered {
		holders := rolesHolding(p)
		var names []string
		for _, r := range holders {
			names = append(names, "`"+string(r)+"`")
		}
		held := strings.Join(names, ", ")
		if held == "" {
			held = "no role in the default ladder"
		}
		count := "all " + fmt.Sprintf("%d", len(perms[p]))
		if len(perms) > 1 {
			count = fmt.Sprintf("%d", len(perms[p]))
		}
		b.WriteString(fmt.Sprintf(
			"Reading %s of the actions below requires the `%s` permission, held by %s.\n",
			count, p, held))
	}
	b.WriteString("\n" + readerNote + "\n\n")
}

const readerNote = "The trail is one table behind one pair of admin-only endpoints, so the\n" +
	"permission does not vary by action today. It is recorded per action anyway,\n" +
	"because the day one family needs narrower reads than the rest, the registry\n" +
	"has to be able to say so without a schema change — and because a reader is\n" +
	"better served by a column that says \"the same everywhere\" than by prose that\n" +
	"leaves them guessing whether it varies."

// rolesHolding returns the roles whose default permission set contains p.
func rolesHolding(p authz.Permission) []authz.Role {
	var out []authz.Role
	for _, r := range authz.AllRoles {
		for _, held := range r.Permissions() {
			if held == p {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// writeFamilyIndex renders the jump table. With this many actions a reader
// arriving from a SIEM rule needs to get to one family without scrolling past
// twenty others.
func writeFamilyIndex(b *strings.Builder) {
	var cells []string
	for _, fam := range Families() {
		cells = append(cells, fmt.Sprintf("[`%s.*`](#%s) (%d)", fam, familyAnchor(fam), len(InFamily(fam))))
	}
	b.WriteString(strings.Join(cells, " · "))
	b.WriteString("\n\n")
}

// familyAnchor is the heading slug for a family section, as GitHub and mkdocs
// both compute it: lowercase, drop everything that is not a word character or
// a hyphen, turn spaces into hyphens.
//
// Underscores survive — they are word characters to both sluggers — which
// matters for `api_token.*`, `role_binding.*`, `sealing_key.*` and
// `github_app.*`. Hyphenating them here would produce four index links that
// scroll nowhere, and nothing in the docs build checks an intra-page anchor.
// The headings are `family.*`, so the dot and the star are what vanish.
func familyAnchor(family string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(familyHeading(family)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			out.WriteRune(r)
		case r == ' ':
			out.WriteRune('-')
		}
	}
	return out.String()
}

func familyHeading(family string) string { return family + ".*" }

func writeFamily(b *strings.Builder, family string) {
	entries := InFamily(family)
	b.WriteString("### " + familyHeading(family) + "\n\n")

	b.WriteString("| Action | Entity | Stability | Fires when |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s |\n",
			e.Action, e.Entity, e.Stability, cell(e.Trigger)))
	}
	b.WriteString("\n")

	writePayloads(b, entries)

	var noted []Entry
	for _, e := range entries {
		if strings.TrimSpace(e.Note) != "" {
			noted = append(noted, e)
		}
	}
	if len(noted) > 0 {
		for _, e := range noted {
			b.WriteString(fmt.Sprintf("- `%s` — %s\n", e.Action, oneLine(e.Note)))
		}
		b.WriteString("\n")
	}
}

// writePayloads renders the payload keys for a family, collapsing the common
// case where every action in the family goes through one emitter and therefore
// carries one shape. Repeating twenty-three identical key lists for the secret
// family would bury the two places where the shape genuinely differs.
func writePayloads(b *strings.Builder, entries []Entry) {
	shared := true
	for _, e := range entries[1:] {
		if !sameKeys(e.Payload, entries[0].Payload) {
			shared = false
			break
		}
	}
	if shared {
		b.WriteString("Payload keys, on every action above: " + keyList(entries[0].Payload) + "\n\n")
		return
	}
	b.WriteString("Payload keys:\n\n")
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("- `%s` — %s\n", e.Action, keyList(e.Payload)))
	}
	b.WriteString("\n")
}

func sameKeys(a, b []string) bool {
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

func keyList(keys []string) string {
	if len(keys) == 0 {
		return "_none_"
	}
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = "`" + k + "`"
	}
	return strings.Join(out, ", ")
}

// cell makes a string safe to put in a markdown table cell: a literal pipe
// would end the cell, and a newline would end the row.
func cell(s string) string {
	return strings.ReplaceAll(oneLine(s), "|", "\\|")
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
