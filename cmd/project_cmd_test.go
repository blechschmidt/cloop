package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func membersCmd(t *testing.T, src *cobra.Command, kind string, args ...string) error {
	t.Helper()
	return runHubSub(t, src, func(c *cobra.Command) { registerProjectMemberFlags(c, kind) }, args...)
}

// TestProjectMembersCLI drives add, change and remove against a hub
// directory: each change commits with its audit row and is announced on the
// cluster bus, and the inputs that could never grant anybody anything are
// refused before anything is written.
func TestProjectMembersCLI(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())
	hub := hubDir(t)
	project := t.TempDir()
	if err := multiui.AddPathsOwned([]string{project}, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(project)
	wd := "--workdir=" + hub

	if err := membersCmd(t, projectMembersAddCmd, "add", name, "Bob@Example.com", "--role=operator",
		"--reason=pairing on payments", wd); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := membersCmd(t, projectMembersAddCmd, "add", project, "bob@example.com", "--role=viewer",
		"--reason=read-only from now on", wd); err != nil {
		t.Fatalf("change: %v", err)
	}
	for what, args := range map[string][]string{
		"no reason":       {name, "carol@example.com"},
		"not an identity": {name, "carol", "--reason=because reasons"},
		"no such role":    {name, "carol@example.com", "--role=owner", "--reason=because reasons"},
		"unregistered":    {t.TempDir(), "carol@example.com", "--reason=because reasons"},
		"unknown name":    {"no-such-project", "carol@example.com", "--reason=because reasons"},
		"a feature":       {featureDir(t, project), "carol@example.com", "--reason=because reasons"},
	} {
		if err := membersCmd(t, projectMembersAddCmd, "add", append(args, wd)...); err == nil {
			t.Errorf("add accepted %s", what)
		}
	}

	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListProjectMembers()
	if err != nil || len(rows) != 1 || rows[0].IdentityKey != "bob@example.com" || rows[0].Role != "viewer" {
		t.Fatalf("after add and change the table holds %+v (%v)", rows, err)
	}

	if err := membersCmd(t, projectMembersRemoveCmd, "remove", name, "bob@example.com", wd); err == nil {
		t.Error("remove without a reason was accepted")
	}
	if err := membersCmd(t, projectMembersRemoveCmd, "remove", name, "bob@example.com", "--reason=left the team", wd); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := membersCmd(t, projectMembersRemoveCmd, "remove", name, "bob@example.com", "--reason=left the team", wd); err == nil {
		t.Error("removing a non-member reported success")
	}
	if rows, _ := db.ListProjectMembers(); len(rows) != 0 {
		t.Fatalf("after remove the table holds %+v", rows)
	}

	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project_member"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ev := range evs {
		got = append(got, ev.EventType)
		if !strings.HasPrefix(ev.Actor, "cli:") || !strings.Contains(ev.Payload, `"via":"cli"`) {
			t.Errorf("%s row: actor %q payload %s", ev.EventType, ev.Actor, ev.Payload)
		}
	}
	if strings.Join(got, ",") != "project.member.grant,project.member.change,project.member.revoke" {
		t.Errorf("audit rows %v", got)
	}

	events, err := db.HubEventsAfter(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	announced := 0
	for _, ev := range events {
		if ev.Topic == "invalidate" && ev.Key == "members" && strings.Contains(ev.Payload, project) {
			announced++
		}
	}
	if announced != 3 {
		t.Errorf("%d bus announcements, want one per change (3)", announced)
	}

	// list, as JSON, after everything is gone.
	if err := membersCmd(t, projectMembersListCmd, "list", "--json", wd); err != nil {
		t.Errorf("list: %v", err)
	}
}

// featureDir makes a feature of project the way `cloop feature new` leaves one.
func featureDir(t *testing.T, project string) string {
	t.Helper()
	dir := feature.Path(project, "login")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}
