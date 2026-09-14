package cmd

// zz_groups.go buckets the CLI into cobra help groups.
//
// cloop registers 115 top-level commands and 64 more under `cloop task`. Rendered
// flat — which is what cobra does when no command carries a GroupID — that is a
// wall of names at one indentation level with no hierarchy to navigate by. This
// file is the one place that says which bucket a command belongs to.
//
// The "zz_" prefix is load-bearing, for the same reason zz_completion_register.go
// carries it: Go runs a package's init() functions in file-name order, so this
// one runs after every cmd/*.go has registered its command and the tree is
// complete. Groups are therefore assigned by walking the tree and matching on
// name, not by touching 180 registration sites.
//
// Adding a command means adding one line to the map below. Forgetting to is a
// test failure, not a silently ungrouped entry — see zz_groups_test.go.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// Group IDs for the root command. The order they appear in rootGroups is the
// order they render in `cloop --help`.
const (
	groupCore      = "core"
	groupPlan      = "plan"
	groupHub       = "hub"
	groupAccess    = "access"
	groupInsight   = "insight"
	groupAI        = "ai"
	groupProviders = "providers"
	groupDelivery  = "delivery"
	groupMaint     = "maint"
)

// Group IDs for `cloop task` and `cloop plan`, the two subtrees large enough to
// need the same treatment as the root.
const (
	groupTaskLifecycle = "task-lifecycle"
	groupTaskOrganize  = "task-organize"
	groupTaskShape     = "task-shape"
	groupTaskVerify    = "task-verify"

	groupPlanVersions = "plan-versions"
	groupPlanAI       = "plan-ai"

	groupHubSetup   = "hub-setup"
	groupHubAccess  = "hub-access"
	groupHubOperate = "hub-operate"
)

// helpFooterAnnotation opts a command into a trailing block in its help output.
// The usage template installed below prints the annotation's value verbatim
// after the flags, and prints nothing for commands that do not set it — so
// `cloop task list --help` stays clean while `cloop --help` gets a footer.
const helpFooterAnnotation = "cloop.help.footer"

// docsURL is the published documentation site (Task 20208). The root help block
// points here instead of trying to be a manual.
const docsURL = "https://blechschmidt.github.io/cloop/"

var rootGroups = []*cobra.Group{
	{ID: groupCore, Title: "Core workflow:"},
	{ID: groupPlan, Title: "Plan and tasks:"},
	{ID: groupHub, Title: "Hub, executors and serving:"},
	{ID: groupAccess, Title: "Secrets, access and spend:"},
	{ID: groupInsight, Title: "Insight and reporting:"},
	{ID: groupAI, Title: "AI assistants:"},
	{ID: groupProviders, Title: "Providers and models:"},
	{ID: groupDelivery, Title: "Integrations and delivery:"},
	{ID: groupMaint, Title: "Maintenance and diagnostics:"},
}

// rootCommandGroups maps a top-level command name to its group. Every child of
// rootCmd must appear here; TestEveryRootCommandHasAGroup enforces it in both
// directions, so a stale entry fails as loudly as a missing one.
var rootCommandGroups = map[string]string{
	// Core workflow — what you run to get work done.
	"init":   groupCore,
	"run":    groupCore,
	"status": groupCore,
	"log":    groupCore,
	"goal":   groupCore,
	"queue":  groupCore,
	"watch":  groupCore,
	"reset":  groupCore,
	"clean":  groupCore,

	// Plan and tasks — everything that shapes or displays the task plan.
	"task":       groupPlan,
	"plan":       groupPlan,
	"milestone":  groupPlan,
	"sprint":     groupPlan,
	"backlog":    groupPlan,
	"suggest":    groupPlan,
	"scope":      groupPlan,
	"analyze":    groupPlan,
	"optimize":   groupPlan,
	"prioritize": groupPlan,
	"lint":       groupPlan,
	"pivot":      groupPlan,
	"rollback":   groupPlan,
	"explain":    groupPlan,
	"simulate":   groupPlan,
	"import":     groupPlan,
	"kanban":     groupPlan,
	"timeline":   groupPlan,
	"viz":        groupPlan,
	"forecast":   groupPlan,
	"alert":      groupPlan,

	// Hub, executors and serving — the long-running processes and the
	// isolated backends they dispatch work to.
	"ui":        groupHub,
	"tui":       groupHub,
	"serve":     groupHub,
	"hub":       groupHub,
	"executor":  groupHub,
	"egress":    groupHub,
	"worktree":  groupHub,
	"daemon":    groupHub,
	"agent":     groupHub,
	"mcp":       groupHub,
	"workspace": groupHub,
	"session":   groupHub,

	// Secrets, access and spend — credentials, the audit trail, and budgets.
	"secret":    groupAccess,
	"env":       groupAccess,
	"config":    groupAccess,
	"budget":    groupAccess,
	"cost":      groupAccess,
	"audit":     groupAccess,
	"audit-log": groupAccess,
	"events":    groupAccess,

	// Insight and reporting — read-only views over work already done.
	"report":       groupInsight,
	"retro":        groupInsight,
	"standup":      groupInsight,
	"insights":     groupInsight,
	"metrics":      groupInsight,
	"stats":        groupInsight,
	"search":       groupInsight,
	"trace":        groupInsight,
	"notebook":     groupInsight,
	"export":       groupInsight,
	"diff":         groupInsight,
	"replay":       groupInsight,
	"team":         groupInsight,
	"perf":         groupInsight,
	"prompt-stats": groupInsight,
	"eval":         groupInsight,
	"self-improve": groupInsight,

	// AI assistants — interactive or one-shot AI you drive directly.
	"ask":      groupAI,
	"chat":     groupAI,
	"shell":    groupAI,
	"do":       groupAI,
	"ai-pair":  groupAI,
	"context":  groupAI,
	"memory":   groupAI,
	"kb":       groupAI,
	"skill":    groupAI,
	"recipe":   groupAI,
	"flow":     groupAI,
	"risk":     groupAI,
	"test":     groupAI,
	"scaffold": groupAI,
	"onboard":  groupAI,
	"listen":   groupAI,
	"voice":    groupAI,

	// Providers and models — picking and tuning the backend.
	"providers": groupProviders,
	"profile":   groupProviders,
	"router":    groupProviders,
	"tune":      groupProviders,
	"bench":     groupProviders,
	"compare":   groupProviders,
	"cache":     groupProviders,

	// Integrations and delivery — everything that talks to a system outside
	// the .cloop directory, plus the git/release surface.
	"github":       groupDelivery,
	"sync":         groupDelivery,
	"ci":           groupDelivery,
	"release":      groupDelivery,
	"pr":           groupDelivery,
	"commit-msg":   groupDelivery,
	"review":       groupDelivery,
	"docs":         groupDelivery,
	"adr":          groupDelivery,
	"changelog":    groupDelivery,
	"notify":       groupDelivery,
	"integrations": groupDelivery,
	"plugin":       groupDelivery,
	"finetune":     groupDelivery,

	// Maintenance and diagnostics — the health checks and the repair tools.
	"doctor":     groupMaint,
	"db":         groupMaint,
	"migrate":    groupMaint,
	"compact":    groupMaint,
	"snapshot":   groupMaint,
	"checkpoint": groupMaint,
	"chaos":      groupMaint,
	"templates":  groupMaint,
	"upgrade":    groupMaint,
	"version":    groupMaint,
	"completion": groupMaint,
	"help":       groupMaint,
}

var taskGroups = []*cobra.Group{
	{ID: groupTaskLifecycle, Title: "Task lifecycle:"},
	{ID: groupTaskOrganize, Title: "Organize and annotate:"},
	{ID: groupTaskShape, Title: "Reshape the plan:"},
	{ID: groupTaskVerify, Title: "Verify and analyze:"},
}

// taskCommandGroups maps a `cloop task` subcommand to its group.
var taskCommandGroups = map[string]string{
	// Lifecycle — create a task, look at it, move it through its states.
	"list":      groupTaskLifecycle,
	"next":      groupTaskLifecycle,
	"show":      groupTaskLifecycle,
	"add":       groupTaskLifecycle,
	"edit":      groupTaskLifecycle,
	"remove":    groupTaskLifecycle,
	"done":      groupTaskLifecycle,
	"fail":      groupTaskLifecycle,
	"skip":      groupTaskLifecycle,
	"reset":     groupTaskLifecycle,
	"move":      groupTaskLifecycle,
	"approve":   groupTaskLifecycle,
	"archive":   groupTaskLifecycle,
	"unarchive": groupTaskLifecycle,
	"exec":      groupTaskLifecycle,
	"watch":     groupTaskLifecycle,

	// Organize and annotate — metadata that does not change the work itself.
	"tag":       groupTaskOrganize,
	"untag":     groupTaskOrganize,
	"pin":       groupTaskOrganize,
	"unpin":     groupTaskOrganize,
	"annotate":  groupTaskOrganize,
	"notes":     groupTaskOrganize,
	"link":      groupTaskOrganize,
	"journal":   groupTaskOrganize,
	"feedback":  groupTaskOrganize,
	"deadlines": groupTaskOrganize,
	"recurring": groupTaskOrganize,
	"promote":   groupTaskOrganize,
	"branch":    groupTaskOrganize,
	"chain":     groupTaskOrganize,
	"deps":      groupTaskOrganize,
	"auto-deps": groupTaskOrganize,
	"relocate":  groupTaskOrganize,

	// Reshape the plan — split, merge, re-rank, re-describe.
	"decompose":        groupTaskShape,
	"split":            groupTaskShape,
	"merge":            groupTaskShape,
	"clone":            groupTaskShape,
	"reorder":          groupTaskShape,
	"bulk":             groupTaskShape,
	"bulk-assign":      groupTaskShape,
	"batch-edit":       groupTaskShape,
	"effort-calibrate": groupTaskShape,
	"query":            groupTaskShape,
	"summarize":        groupTaskShape,
	"narrative":        groupTaskShape,

	// Verify and analyze — evidence about a task that already ran.
	"stats":          groupTaskVerify,
	"generate-tests": groupTaskVerify,
	"tdd":            groupTaskVerify,
	"replay":         groupTaskVerify,
	"replay-suite":   groupTaskVerify,
	"reproduce":      groupTaskVerify,
	// reproduce-exec is the in-sandbox half of reproduce (Task 20221). Hidden,
	// because it is an argv the executor builds rather than something a person
	// runs — but still a registered subcommand, so the gate requires a row.
	"reproduce-exec":   groupTaskVerify,
	"checkpoint-diff":  groupTaskVerify,
	"time-travel":      groupTaskVerify,
	"audit-ledger":     groupTaskVerify,
	"ical":             groupTaskVerify,
	"import-github-pr": groupTaskVerify,

	// Single-shot AI advisories. Grouped so unhiding one needs no extra edit,
	// but hidden from the list — see hiddenAIHelpers.
	"ai-acceptance-criteria": groupTaskShape,
	"ai-coach":               groupTaskShape,
	"ai-complexity":          groupTaskShape,
	"ai-impact":              groupTaskShape,
	"ai-naming":              groupTaskShape,
	"ai-what-if":             groupTaskShape,
	"ai-blocker":             groupTaskVerify,
	"ai-risk-matrix":         groupTaskVerify,
	"ai-standup":             groupTaskVerify,
}

var planGroups = []*cobra.Group{
	{ID: groupPlanVersions, Title: "Versions and interchange:"},
	{ID: groupPlanAI, Title: "AI planning:"},
}

// planCommandGroups maps a `cloop plan` subcommand to its group.
var planCommandGroups = map[string]string{
	"history": groupPlanVersions,
	"diff":    groupPlanVersions,
	"export":  groupPlanVersions,
	"import":  groupPlanVersions,

	"critique": groupPlanAI,
	"edit":     groupPlanAI,

	// Hidden — see hiddenAIHelpers.
	"ai-brief":   groupPlanAI,
	"ai-epic":    groupPlanAI,
	"ai-roadmap": groupPlanAI,
}

var hubGroups = []*cobra.Group{
	{ID: groupHubSetup, Title: "Standing up a hub:"},
	{ID: groupHubAccess, Title: "Access and incident response:"},
	{ID: groupHubOperate, Title: "Running it:"},
}

// hubCommandGroups maps a `cloop hub` subcommand to its group.
//
// The subtree got its own buckets when the incident-response commands landed
// (Task 20248). Eleven entries is past the point where a flat list is a list
// rather than a wall, and the split that matters is the one below: an on-call
// engineer reaching for this tree at 3am is looking for exactly one of the
// access commands and should not have to read past TLS setup to find it.
var hubCommandGroups = map[string]string{
	"bootstrap": groupHubSetup,
	"tls-init":  groupHubSetup,
	"pin":       groupHubSetup,

	"user":    groupHubAccess,
	"session": groupHubAccess,
	"role":    groupHubAccess,
	"quota":   groupHubAccess,
	"token":   groupHubAccess,
	"key":     groupHubAccess,

	"doctor":      groupHubOperate,
	"healthcheck": groupHubOperate,
	"lease":       groupHubOperate,
	"audit":       groupHubOperate,
	"retention":   groupHubOperate,
	"telemetry":   groupHubOperate,
}

// hubHelpFooter points at the runbook rather than trying to be it. The three
// incident playbooks are sequences across several commands plus the REST API,
// which is not something a --help block can hold.
const hubHelpFooter = `Incident response:
  cloop hub session revoke --identity <who> --reason "..."   contain a stolen session
  cloop hub quota set <who> --limit daily_cost_usd=5 ...     cap a runaway tenant
  cloop hub role revoke email <who> --reason "..."           demote a compromised admin

Full playbooks: docs/operations/runbook.md`

// hiddenAIHelpers are the single-shot `ai-*` advisory wrappers: each one makes
// one provider call, prints a report, and changes nothing unless you pass
// --apply. Nine of them under `cloop task` and three under `cloop plan` is a
// third of those lists spent on commands nobody reaches for by browsing.
//
// Hidden, not removed. Every path below still resolves, still parses its flags,
// and still works in a script — cobra's Hidden only suppresses the help listing.
// The parent's help footer names them so they stay findable, and
// TestHiddenAIHelpersStillResolve asserts they stay callable.
var hiddenAIHelpers = [][]string{
	{"task", "ai-acceptance-criteria"},
	{"task", "ai-blocker"},
	{"task", "ai-coach"},
	{"task", "ai-complexity"},
	{"task", "ai-impact"},
	{"task", "ai-naming"},
	{"task", "ai-risk-matrix"},
	{"task", "ai-standup"},
	{"task", "ai-what-if"},
	{"plan", "ai-brief"},
	{"plan", "ai-epic"},
	{"plan", "ai-roadmap"},
}

// rootHelpFooter advertises the three health checks that already exist and were
// invisible in a 115-line list, plus where the real documentation lives.
const rootHelpFooter = `Health checks:
  cloop doctor            environment, configuration, and provider reachability
  cloop config validate   validate .cloop/config.yaml and the project state
  cloop hub doctor        control-plane readiness for a hosted hub

Documentation: ` + docsURL

// applyCommandGroups registers the help groups and assigns every command to
// one. Safe to call more than once: AddGroup is skipped for a group the parent
// already carries, and the rest is idempotent field assignment.
func applyCommandGroups() {
	assignGroups(rootCmd, rootGroups, rootCommandGroups)

	// The help command is synthesized by cobra at Execute time, after this
	// runs, so it cannot be assigned by walking the tree. Naming the group
	// up front is how cobra stamps it when it builds the command.
	rootCmd.SetHelpCommandGroupID(groupMaint)

	if taskCmd != nil {
		assignGroups(taskCmd, taskGroups, taskCommandGroups)
	}
	if planCmd != nil {
		assignGroups(planCmd, planGroups, planCommandGroups)
	}
	if hubCmd != nil {
		assignGroups(hubCmd, hubGroups, hubCommandGroups)
		hubCmd.Annotations = withAnnotation(hubCmd.Annotations, helpFooterAnnotation, hubHelpFooter)
	}

	hideAIHelpers()

	rootCmd.Annotations = withAnnotation(rootCmd.Annotations, helpFooterAnnotation, rootHelpFooter)
	installHelpFooterTemplate(rootCmd)
}

// assignGroups registers groups on parent and stamps each child that the map
// names. Children the map does not name are left with an empty GroupID rather
// than guessed at — the grouping test turns that into a build failure, which is
// a better signal than a command quietly landing in "Additional Commands".
func assignGroups(parent *cobra.Command, groups []*cobra.Group, assign map[string]string) {
	for _, g := range groups {
		if !parent.ContainsGroup(g.ID) {
			parent.AddGroup(g)
		}
	}
	for _, sub := range parent.Commands() {
		if id, ok := assign[sub.Name()]; ok {
			sub.GroupID = id
		}
	}
}

// hideAIHelpers drops the single-shot advisory wrappers out of their parent's
// listing and records, on the parent, a footer naming every one it hid. The
// footer is generated rather than written out so it cannot drift from the list.
func hideAIHelpers() {
	byParent := map[*cobra.Command][]string{}
	for _, path := range hiddenAIHelpers {
		sub, _, err := rootCmd.Find(path)
		if err != nil || sub == nil || sub.Name() != path[len(path)-1] {
			// A helper was renamed or removed. Nothing to hide, and no
			// reason to fail a user's command over it — the grouping
			// test is where this gets caught.
			continue
		}
		sub.Hidden = true
		parent := sub.Parent()
		byParent[parent] = append(byParent[parent], sub.Name())
	}

	for parent, names := range byParent {
		sort.Strings(names)
		parent.Annotations = withAnnotation(parent.Annotations, helpFooterAnnotation, hiddenHelperFooter(parent, names))
	}
}

// hiddenHelperFooter renders the "these exist, they are just not listed" block.
func hiddenHelperFooter(parent *cobra.Command, names []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Single-shot AI advisories, hidden to keep this list navigable.\n")
	fmt.Fprintf(&b, "They still run and still script — %s <name>:\n", parent.CommandPath())
	for _, line := range wrapNames(names, 72) {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	fmt.Fprintf(&b, "\nRun \"%s <name> --help\" for any of them.", parent.CommandPath())
	return b.String()
}

// wrapNames packs comma-separated names into lines of at most width runes.
func wrapNames(names []string, width int) []string {
	var lines []string
	cur := ""
	for i, n := range names {
		piece := n
		if i < len(names)-1 {
			piece += ","
		}
		switch {
		case cur == "":
			cur = piece
		case len(cur)+1+len(piece) <= width:
			cur += " " + piece
		default:
			lines = append(lines, cur)
			cur = piece
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// withAnnotation sets key on a possibly-nil annotation map and returns it.
func withAnnotation(m map[string]string, key, value string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[key] = value
	return m
}

// installHelpFooterTemplate extends cobra's usage template with an opt-in
// trailing block. Usage templates are inherited by subcommands, so the guard
// matters: a command without the annotation renders exactly as before.
func installHelpFooterTemplate(root *cobra.Command) {
	const footer = "{{with (index .Annotations \"" + helpFooterAnnotation + "\")}}\n{{.}}\n{{end}}"
	tmpl := root.UsageTemplate()
	if strings.Contains(tmpl, helpFooterAnnotation) {
		return
	}
	root.SetUsageTemplate(tmpl + footer)
}

func init() {
	applyCommandGroups()
}
