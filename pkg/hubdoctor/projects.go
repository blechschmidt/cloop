package hubdoctor

// Project confinement (Task 20418): every registered project's directory
// against the invariant pkg/projectconfine states.
//
// The hub refuses a creation that breaks it and re-checks it at every
// dispatch, so a row that breaks it now cannot run — but it can still exist:
// an operator's `cloop ui --projects`, a registry written before the rule, a
// projects root moved under an old project. Nothing here deletes or moves
// one. A row the hub will not run is a project somebody expects to work, and
// the operator is the one to decide where it goes; what this check owes them
// is the list, with what each row overlaps.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectconfine"
)

// confinementScan bounds the search below each project for a hub's control
// plane. Narrower than a creation's: the doctor walks every project, and a
// project too broad to search is reported as unverified rather than failed.
var confinementScan = projectconfine.ScanLimits{MaxDepth: 8, MaxDirs: 20000}

// hostHubs lists the working directories of the hubs running on this host.
// A variable so tests can say which hubs run, rather than inherit the
// machine's.
var hostHubs = func() []string {
	var dirs []string
	for _, h := range multiui.HubProcesses() {
		dirs = append(dirs, h.Dir)
	}
	return dirs
}

func checkProjectConfinement(dir string, cfg *config.Config, add addFn) {
	const check, title = "projects.confinement", "Project directories"
	entries, err := multiui.Load()
	if err != nil {
		add(Finding{Check: check, Title: title, Severity: SeverityWarn,
			Message:     fmt.Sprintf("the project registry could not be read, so no project was checked: %v", err),
			Remediation: "Check the permissions of ~/.cloop/projects.json (or $CLOOP_HOME/projects.json) for the hub's user"})
		return
	}
	home, _ := os.UserHomeDir()
	policy := projectconfine.Policy{
		ControlPlane: canonical(dir),
		ProjectsRoot: canonical(projectsRoot(cfg, home)),
		Home:         home,
		Existing:     true,
		Scan:         confinementScan,
	}
	for _, h := range hostHubs() {
		policy.HubDirs = append(policy.HubDirs, canonical(h))
	}
	for _, e := range entries {
		policy.Projects = append(policy.Projects, canonical(e.Path))
	}

	var broken, unverified []string
	for _, e := range entries {
		_, err := policy.Check(e.Path)
		v, ok := projectconfine.IsViolation(err)
		switch {
		case !ok:
			continue
		case v.Rule == projectconfine.RuleUnverifiable:
			unverified = append(unverified, e.Path+": "+v.Error())
		default:
			broken = append(broken, e.Path+": "+v.Error())
		}
	}
	sort.Strings(broken)
	sort.Strings(unverified)
	if len(broken) > 0 {
		add(Finding{Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("%d registered project(s) overlap what the hub must never bind into a sandbox, "+
				"so the hub refuses to run them: %s", len(broken), strings.Join(broken, "; ")),
			Remediation: "Move each listed project to a directory of its own inside ui.projects_root (or remove " +
				"it from the hub without deleting its directory), then re-run. Nothing was changed.",
			Details: map[string]any{"projects": broken}})
	}
	if len(unverified) > 0 {
		add(Finding{Check: check, Title: title, Severity: SeverityWarn,
			Message: fmt.Sprintf("%d project tree(s) are too large to search for another hub's control plane: %s",
				len(unverified), strings.Join(unverified, "; ")),
			Remediation: "Confirm by hand that no .cloop/hub.env lies under the listed directories",
			Details:     map[string]any{"projects": unverified}})
	}
	if len(broken) == 0 && len(unverified) == 0 {
		add(Finding{Check: check, Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("%d registered project(s); none overlaps the control plane, the projects root, "+
				"another hub or another project", len(entries))})
	}
}

// projectsRoot is ui.projects_root, or projects/ in the hub user's home.
func projectsRoot(cfg *config.Config, home string) string {
	if cfg != nil {
		if root := strings.TrimSpace(cfg.UI.ProjectsRoot); root != "" {
			if filepath.IsAbs(root) {
				return filepath.Clean(root)
			}
			return ""
		}
	}
	if strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, "projects")
}

// canonical resolves a path the way the hub does, or cleans it when it cannot
// be resolved.
func canonical(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	if c, err := projectconfine.Canonical(path); err == nil {
		return c
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}
