package cmd

// Gates on the help grouping introduced in Task 20216.
//
// The grouping is a lookup table (zz_groups.go) rather than a field on each
// registration, which buys one edit per new command but costs the compiler's
// help: nothing stops a new command from being registered and never named in
// the table, landing it in cobra's "Additional Commands" bucket. These tests
// are that missing compiler check, in both directions — a command with no
// entry fails, and an entry with no command fails.
//
// The second half asserts the demotion stayed additive: hiding a command must
// not change what `cloop task ai-coach` resolves to.

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// groupedParents are the commands whose children are bucketed. Each entry pairs
// the parent with the table that is supposed to cover every one of its children.
func groupedParents(t *testing.T) []struct {
	cmd    *cobra.Command
	groups []*cobra.Group
	assign map[string]string
} {
	t.Helper()
	// cobra synthesizes the help command at Execute time. Force it now so the
	// tree under test is the tree a user sees.
	rootCmd.InitDefaultHelpCmd()
	return []struct {
		cmd    *cobra.Command
		groups []*cobra.Group
		assign map[string]string
	}{
		{rootCmd, rootGroups, rootCommandGroups},
		{taskCmd, taskGroups, taskCommandGroups},
		{planCmd, planGroups, planCommandGroups},
	}
}

// TestEveryRegisteredCommandHasAGroup is the regression gate the task asks for:
// a newly added command cannot silently drop out of the grouping.
func TestEveryRegisteredCommandHasAGroup(t *testing.T) {
	for _, p := range groupedParents(t) {
		var ungrouped []string
		for _, sub := range p.cmd.Commands() {
			if sub.GroupID == "" {
				ungrouped = append(ungrouped, sub.Name())
			}
		}
		if len(ungrouped) > 0 {
			sort.Strings(ungrouped)
			t.Errorf("%s: %d subcommand(s) have no GroupID: %s\n"+
				"add each to the matching map in cmd/zz_groups.go",
				p.cmd.CommandPath(), len(ungrouped), strings.Join(ungrouped, ", "))
		}
	}
}

// TestEveryGroupIDIsDefined catches a typo'd or removed group: cobra renders a
// command whose GroupID matches no registered group nowhere at all, silently.
func TestEveryGroupIDIsDefined(t *testing.T) {
	for _, p := range groupedParents(t) {
		if len(p.cmd.Groups()) == 0 {
			t.Fatalf("%s: no groups registered", p.cmd.CommandPath())
		}
		for _, sub := range p.cmd.Commands() {
			if sub.GroupID != "" && !p.cmd.ContainsGroup(sub.GroupID) {
				t.Errorf("%s: GroupID %q is not a group of %s",
					sub.CommandPath(), sub.GroupID, p.cmd.CommandPath())
			}
		}
	}
}

// TestNoStaleGroupAssignments fails when a map names a command that no longer
// exists — a renamed command would otherwise leave a dead entry behind and
// lose its group without anything noticing.
func TestNoStaleGroupAssignments(t *testing.T) {
	for _, p := range groupedParents(t) {
		registered := map[string]bool{}
		for _, sub := range p.cmd.Commands() {
			registered[sub.Name()] = true
		}
		var stale []string
		for name := range p.assign {
			if !registered[name] {
				stale = append(stale, name)
			}
		}
		if len(stale) > 0 {
			sort.Strings(stale)
			t.Errorf("%s: group map names %d command(s) that are not registered: %s",
				p.cmd.CommandPath(), len(stale), strings.Join(stale, ", "))
		}
	}
}

// TestGroupTitlesAreUnique guards against two buckets rendering under the same
// heading, which reads as one duplicated section in the help output.
func TestGroupTitlesAreUnique(t *testing.T) {
	for _, p := range groupedParents(t) {
		seenID := map[string]bool{}
		seenTitle := map[string]bool{}
		for _, g := range p.groups {
			if seenID[g.ID] {
				t.Errorf("%s: duplicate group ID %q", p.cmd.CommandPath(), g.ID)
			}
			if seenTitle[g.Title] {
				t.Errorf("%s: duplicate group title %q", p.cmd.CommandPath(), g.Title)
			}
			seenID[g.ID], seenTitle[g.Title] = true, true
		}
	}
}

// TestHiddenAIHelpersStillResolve is the "purely additive" half of the demotion:
// every hidden helper must still be reachable by the exact path scripts already
// use. Hidden suppresses the listing and nothing else.
func TestHiddenAIHelpersStillResolve(t *testing.T) {
	if len(hiddenAIHelpers) == 0 {
		t.Fatal("hiddenAIHelpers is empty — the demotion is not in effect")
	}
	for _, path := range hiddenAIHelpers {
		found, rest, err := rootCmd.Find(path)
		if err != nil {
			t.Errorf("cloop %s: Find: %v", strings.Join(path, " "), err)
			continue
		}
		if len(rest) != 0 {
			t.Errorf("cloop %s: did not fully resolve, leftover args %v",
				strings.Join(path, " "), rest)
			continue
		}
		want := "cloop " + strings.Join(path, " ")
		if got := found.CommandPath(); got != want {
			t.Errorf("cloop %s: resolved to %q", strings.Join(path, " "), got)
		}
		if !found.Hidden {
			t.Errorf("%s: expected Hidden, so it stops crowding %s",
				want, found.Parent().CommandPath())
		}
		if !found.Runnable() {
			t.Errorf("%s: hidden and not runnable — it is unreachable", want)
		}
	}
}

// TestPreviouslyWorkingCommandPathsStillResolve samples the invocation surface
// across every root group plus both regrouped subtrees. Grouping and hiding are
// display-only changes; if any of these stop resolving, they were not.
func TestPreviouslyWorkingCommandPathsStillResolve(t *testing.T) {
	paths := [][]string{
		// One per root group, so a group-wide mistake cannot hide.
		{"init"}, {"run"}, {"status"}, {"log"},
		{"task"}, {"plan"}, {"suggest"},
		{"ui"}, {"serve"}, {"executor"},
		{"secret"}, {"config"}, {"audit-log"},
		{"report"}, {"insights"},
		{"ask"}, {"chat"},
		{"providers"}, {"compare"},
		{"github"}, {"review"},
		{"doctor"}, {"db"}, {"version"},
		// Nested paths, including the ones the demotion touched.
		{"task", "list"}, {"task", "add"}, {"task", "done"}, {"task", "decompose"},
		{"task", "ai-coach"}, {"task", "ai-what-if"},
		{"plan", "history"}, {"plan", "critique"}, {"plan", "ai-brief"},
		{"config", "validate"}, {"hub", "doctor"},
	}
	for _, path := range paths {
		found, rest, err := rootCmd.Find(path)
		if err != nil {
			t.Errorf("cloop %s: Find: %v", strings.Join(path, " "), err)
			continue
		}
		if len(rest) != 0 {
			t.Errorf("cloop %s: leftover args %v", strings.Join(path, " "), rest)
			continue
		}
		if want, got := "cloop "+strings.Join(path, " "), found.CommandPath(); got != want {
			t.Errorf("cloop %s: resolved to %q", strings.Join(path, " "), got)
		}
	}
}

// TestRootHelpRendersEveryGroup renders the real help text and asserts the wall
// is gone: every heading present, and nothing spilled into cobra's ungrouped
// "Additional Commands" bucket.
func TestRootHelpRendersEveryGroup(t *testing.T) {
	rootCmd.InitDefaultHelpCmd()
	usage := rootCmd.UsageString()

	for _, g := range rootGroups {
		if !strings.Contains(usage, g.Title) {
			t.Errorf("root help is missing group heading %q", g.Title)
		}
	}
	if strings.Contains(usage, "Additional Commands:") {
		t.Error("root help has an \"Additional Commands:\" section — " +
			"some command is registered without a group")
	}
}

// TestRootHelpFooterAdvertisesHealthChecks covers requirement (4): the three
// diagnostics that already existed and went unmentioned.
func TestRootHelpFooterAdvertisesHealthChecks(t *testing.T) {
	usage := rootCmd.UsageString()
	for _, want := range []string{
		"cloop doctor",
		"cloop config validate",
		"cloop hub doctor",
		docsURL,
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("root help footer does not mention %q", want)
		}
	}
}

// TestHelpFooterIsOptIn keeps the footer off the ~180 commands that did not ask
// for one. The template is inherited by every subcommand, so this is the thing
// that could plausibly regress.
func TestHelpFooterIsOptIn(t *testing.T) {
	leaf, _, err := rootCmd.Find([]string{"task", "list"})
	if err != nil {
		t.Fatalf("find task list: %v", err)
	}
	if got := leaf.UsageString(); strings.Contains(got, "Health checks:") ||
		strings.Contains(got, "Single-shot AI advisories") {
		t.Errorf("cloop task list help picked up a parent's footer:\n%s", got)
	}
}

// TestHiddenHelperFooterNamesEveryHiddenCommand ties the footer to the hidden
// set, so demoting another command cannot leave it unmentioned anywhere.
func TestHiddenHelperFooterNamesEveryHiddenCommand(t *testing.T) {
	for _, path := range hiddenAIHelpers {
		found, _, err := rootCmd.Find(path)
		if err != nil {
			t.Errorf("cloop %s: Find: %v", strings.Join(path, " "), err)
			continue
		}
		footer := found.Parent().Annotations[helpFooterAnnotation]
		if !strings.Contains(footer, found.Name()) {
			t.Errorf("%s help footer does not name hidden subcommand %q",
				found.Parent().CommandPath(), found.Name())
		}
	}
}

// TestApplyCommandGroupsIsIdempotent guards the one non-obvious hazard in
// zz_groups.go: AddGroup appends, so a second pass would duplicate every
// heading in the help output.
func TestApplyCommandGroupsIsIdempotent(t *testing.T) {
	before := len(rootCmd.Groups())
	applyCommandGroups()
	if after := len(rootCmd.Groups()); after != before {
		t.Errorf("applyCommandGroups duplicated groups: %d -> %d", before, after)
	}
	if got := strings.Count(rootCmd.UsageTemplate(), helpFooterAnnotation); got != 1 {
		t.Errorf("usage template footer applied %d times, want 1", got)
	}
}

// TestHiddenAIHelpersAreDocumented keeps docs/reference/commands.md in step with
// the hidden set. A hidden command is invisible to `--help` and to shell
// completion, so the doc is the only place a reader can discover it — which
// makes a stale doc worse here than anywhere else in the tree.
func TestHiddenAIHelpersAreDocumented(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "docs", "reference", "commands.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	doc := string(raw)

	for _, p := range hiddenAIHelpers {
		invocation := "cloop " + strings.Join(p, " ")
		if !strings.Contains(doc, invocation) {
			t.Errorf("docs/reference/commands.md does not mention %q\n"+
				"hidden commands are absent from --help and from shell completion, "+
				"so the docs are the only way to find them", invocation)
		}
	}
}

func TestWrapNames(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		width int
		want  []string
	}{
		{"empty", nil, 20, nil},
		{"single fits", []string{"alpha"}, 20, []string{"alpha"}},
		{"two fit", []string{"alpha", "beta"}, 20, []string{"alpha, beta"}},
		{"wraps", []string{"alpha", "beta", "gamma"}, 12, []string{"alpha, beta,", "gamma"}},
		{"name longer than width still emitted",
			[]string{"a-very-long-command-name"}, 5, []string{"a-very-long-command-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapNames(tt.names, tt.width)
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("line %d: got %q, want %q", i, got[i], tt.want[i])
				}
				if strings.HasSuffix(got[i], " ") {
					t.Errorf("line %d has trailing space: %q", i, got[i])
				}
			}
		})
	}
}
