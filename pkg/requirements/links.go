package requirements

// links.go: the requirements a task implements (Task 20460) — how people name
// one, which links a project accepts, and what the agent working on the task
// is told about them.
//
// A link is a requirement id stored on the task (pm.Task.Requirements). Ids
// belong to a project: each project's database numbers its own requirements,
// so a link is always read in the task's own project, and an id that names a
// requirement only in another project names nothing here — CheckLinks refuses
// it like any other unknown id.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	// MaxTaskLinks bounds how many requirements one task implements: each
	// travels into the task's prompt in full.
	MaxTaskLinks = 32
	// MaxContractBytes bounds the contract a prompt carries: room for the
	// largest requirement Normalize admits (MaxEncodedBytes) and then some.
	// Past it the rest are named with their titles and where to read them.
	MaxContractBytes = 96 << 10
)

// ParseRef reads a requirement as people name it: 3, R-3, r-3 or #3.
func ParseRef(s string) (int, error) {
	a := strings.TrimSpace(s)
	a = strings.TrimPrefix(strings.TrimPrefix(a, "R-"), "r-")
	id, err := strconv.Atoi(strings.TrimPrefix(a, "#"))
	if err != nil || id <= 0 {
		return 0, invalid("%q is not a requirement: give its number, or R-<number>", truncateRunes(s, 32))
	}
	return id, nil
}

// ParseRefs reads requirements named one per argument or comma-separated.
func ParseRefs(args []string) ([]int, error) {
	var out []int
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			id, err := ParseRef(part)
			if err != nil {
				return nil, err
			}
			out = append(out, id)
		}
	}
	return out, nil
}

// Refs is a list of requirements as a client sends it: numbers, or strings
// such as "R-3".
type Refs []int

// UnmarshalJSON reads a JSON array of requirement ids or names.
func (r *Refs) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return invalid("requirements must be a list of requirement ids")
	}
	if len(raw) > MaxRequirements {
		return invalid("a task implements at most %d requirements, not %d", MaxTaskLinks, len(raw))
	}
	out := make(Refs, 0, len(raw))
	for _, e := range raw {
		e = bytes.TrimSpace(e)
		var id int
		if len(e) > 0 && e[0] == '"' {
			var s string
			if err := json.Unmarshal(e, &s); err != nil {
				return invalid("requirements must be a list of requirement ids")
			}
			n, err := ParseRef(s)
			if err != nil {
				return err
			}
			id = n
		} else if err := json.Unmarshal(e, &id); err != nil || id <= 0 {
			return invalid("%s is not a requirement id", truncateRunes(string(e), 32))
		}
		out = append(out, id)
	}
	*r = out
	return nil
}

// CheckLinks checks ids as the requirements a task implements, in the project
// whose requirements are reqs, and returns them in order without repeats.
// already is what the task implements now. Every id must name one of reqs: an
// id is the project's own, so one that names no requirement here — deleted,
// mistyped, or another project's — is refused. A new link to a deprecated
// requirement is refused too; one the task already has may stay, since
// deprecating a requirement does not rewrite the tasks made for it.
func CheckLinks(ids []int, reqs []Requirement, already []int) ([]int, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	out := slices.Clone(ids)
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxTaskLinks {
		return nil, invalid("a task implements at most %d requirements, not %d", MaxTaskLinks, len(out))
	}
	byID := make(map[int]Requirement, len(reqs))
	for _, r := range reqs {
		byID[r.ID] = r
	}
	var unknown, deprecated []string
	for _, id := range out {
		r, ok := byID[id]
		switch {
		case id <= 0 || !ok:
			unknown = append(unknown, Key(id))
		case r.CurrentStatus() == StatusDeprecated && !slices.Contains(already, id):
			deprecated = append(deprecated, Key(id))
		}
	}
	switch {
	case len(unknown) == 1:
		return nil, invalid("%s is not a requirement of this project", unknown[0])
	case len(unknown) > 1:
		return nil, invalid("%s are not requirements of this project", strings.Join(unknown, ", "))
	case len(deprecated) == 1:
		return nil, invalid("%s is deprecated: a task can no longer be linked to it", deprecated[0])
	case len(deprecated) > 1:
		return nil, invalid("%s are deprecated: a task can no longer be linked to them", strings.Join(deprecated, ", "))
	}
	return out, nil
}

// Resolve looks ids up in reqs, in the order ids names them: linked are the
// requirements found, missing the ids that name none.
func Resolve(ids []int, reqs []Requirement) (linked []Requirement, missing []int) {
	byID := make(map[int]Requirement, len(reqs))
	for _, r := range reqs {
		byID[r.ID] = r
	}
	seen := map[int]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if r, ok := byID[id]; ok {
			linked = append(linked, r)
		} else {
			missing = append(missing, id)
		}
	}
	return linked, missing
}

// ContractSection is what the agent working on a task is told about the
// requirements the task implements: each one's title, details and tests, that
// the task is done only when those tests pass, and that they must not be
// weakened to get there. linked are the task's requirements as the project
// holds them, in the task's order; missing are the ids the task links that
// the project does not hold here — deleted since, or not sent to this
// executor. Empty when the task implements none.
//
// A deprecated requirement is named and left out: the project no longer
// requires it, whatever the task was made for.
func ContractSection(linked []Requirement, missing []int) string {
	var active, retired []Requirement
	for _, r := range linked {
		if r.CurrentStatus() == StatusDeprecated {
			retired = append(retired, r)
		} else {
			active = append(active, r)
		}
	}
	if len(active) == 0 && len(retired) == 0 && len(missing) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## ACCEPTANCE CONTRACT — REQUIREMENTS THIS TASK IMPLEMENTS\n")
	if len(active) > 0 {
		b.WriteString("This task implements the project requirements below, and they are its acceptance\n" +
			"contract. The task is done only when every test listed here passes — each run from\n" +
			"the project's root, passing when it exits 0 — and the requirements without tests\n" +
			"hold as their details describe. Run every test before you finish, and say in your\n" +
			"summary which you ran and how each ended.\n\n" +
			"The tests and the requirements must not be weakened to make them pass: do not edit,\n" +
			"skip, disable, delete or loosen a requirement's tests or the test code they run,\n" +
			"and do not narrow what a requirement says. If a test cannot pass, or is wrong, say\n" +
			"which and why, and end with TASK_FAILED rather than TASK_DONE.\n")
	}
	used := b.Len()
	for i, r := range active {
		part := contractEntry(r)
		if used+len(part) > MaxContractBytes {
			b.WriteString("\nThese requirements are part of the contract too, but their details and tests did not\n" +
				"fit in this prompt; read each with `cloop requirements show <id>` in the project:\n")
			for _, rest := range active[i:] {
				fmt.Fprintf(&b, "- %s: %s\n", Key(rest.ID), oneLine(rest.Title))
			}
			break
		}
		b.WriteString(part)
		used += len(part)
	}
	if len(retired) > 0 || len(missing) > 0 {
		b.WriteString("\n")
	}
	for _, r := range retired {
		fmt.Fprintf(&b, "%s (%s) is linked to this task but deprecated: the project no longer requires it, "+
			"and it is not part of the contract.\n", Key(r.ID), oneLine(r.Title))
	}
	if len(missing) > 0 {
		keys := make([]string, len(missing))
		for i, id := range missing {
			keys[i] = Key(id)
		}
		if len(keys) == 1 {
			fmt.Fprintf(&b, "%s is linked to this task, but its text is not available to this run.\n", keys[0])
		} else {
			fmt.Fprintf(&b, "%s are linked to this task, but their text is not available to this run.\n",
				strings.Join(keys, ", "))
		}
	}
	b.WriteString("\n")
	return b.String()
}

// contractEntry is one requirement as the contract states it.
func contractEntry(r Requirement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s: %s", Key(r.ID), oneLine(r.Title))
	var labels []string
	if r.Priority != "" {
		labels = append(labels, r.Priority)
	}
	if r.CurrentStatus() == StatusDraft {
		labels = append(labels, "draft")
	}
	if len(labels) > 0 {
		fmt.Fprintf(&b, " [%s]", strings.Join(labels, ", "))
	}
	b.WriteString("\n")
	if d := strings.TrimSpace(r.Description); d != "" {
		b.WriteString(d)
		b.WriteString("\n")
	}
	if len(r.Tests) == 0 {
		b.WriteString("It has no automated test: its details are the contract. Say in your summary how\n" +
			"the change makes it hold.\n")
		return b.String()
	}
	b.WriteString("Tests:\n")
	for i, t := range r.Tests {
		label := ""
		if t.Name != "" {
			label = oneLine(t.Name) + " — "
		}
		cmd := strings.TrimSpace(t.Command)
		if !strings.ContainsAny(cmd, "`\n") {
			fmt.Fprintf(&b, "%d. %s`%s` (timeout %s)\n", i+1, label, cmd, t.Timeout())
			continue
		}
		fence := strings.Repeat("`", max(3, longestRun(cmd, '`')+1))
		fmt.Fprintf(&b, "%d. %s(timeout %s)\n%ssh\n%s\n%s\n", i+1, label, t.Timeout(), fence, cmd, fence)
	}
	return b.String()
}

// longestRun is the length of the longest run of c in s.
func longestRun(s string, c rune) int {
	best, cur := 0, 0
	for _, r := range s {
		if r == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}

// ForSeed is r as a project seed carries it to an executor that does not
// share the hub's database: what the contract and a check read, and none of
// who wrote it when.
func (r Requirement) ForSeed() Requirement {
	return Requirement{ID: r.ID, Title: r.Title, Description: r.Description, Priority: r.Priority,
		Status: r.CurrentStatus(), Tags: r.Tags, Tests: r.Tests}
}
