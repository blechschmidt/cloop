package ui

// Branch restrictions on a project's repository access, through the HTTP
// surface the dashboard uses (Task 20340).
//
// The broker's own tests decide what a restricted grant delivers; these pin
// what the panel can do with one: create it, read back what it amounts to on
// this hub, and change it in place — which, because grants are immutable, is a
// new grant plus the revocation of the old, and has to leave exactly one.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// repoAssignment is one row of the repositories panel, with the fields this
// task added.
type repoAssignment struct {
	GrantID           string    `json:"grant_id"`
	SecretID          string    `json:"secret_id"`
	Kind              string    `json:"kind"`
	Repos             []string  `json:"repos"`
	Access            string    `json:"access"`
	Branches          []string  `json:"branches"`
	BranchEnforcement string    `json:"branch_enforcement"`
	Replaceable       bool      `json:"replaceable"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type repoPanel struct {
	Assignments []repoAssignment `json:"assignments"`
	GitProxy    *struct {
		Running  bool     `json:"running"`
		Required bool     `json:"required"`
		PushRefs []string `json:"push_refs"`
	} `json:"git_proxy"`
}

func loadRepoPanel(t *testing.T, f *personalFixture, who string) repoPanel {
	t.Helper()
	code, body := getFull(t, f.clients[who], f.base+"/api/projects/0/repositories")
	if code != http.StatusOK {
		t.Fatalf("%s GET repositories = %d\nbody: %s", who, code, body)
	}
	var out repoPanel
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode repositories: %v\nbody: %s", err, body)
	}
	return out
}

// assign posts to the panel's endpoint and decodes a successful answer.
func assign(t *testing.T, f *personalFixture, who string, body map[string]any) (int, string, repoAssignment) {
	t.Helper()
	code, raw := f.postJSON(t, who, "/api/projects/0/repositories", body)
	var out repoAssignment
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("decode assignment: %v\nbody: %s", err, raw)
		}
	}
	return code, raw, out
}

// withNoGitProxy pins the process-wide proxy state for a test that asserts on
// what a restriction amounts to without one.
func withNoGitProxy(t *testing.T) {
	t.Helper()
	prevSvc, prevReq := gitProxySingleton.Load(), gitProxyRequired.Load()
	gitProxySingleton.Store(nil)
	gitProxyRequired.Store(false)
	t.Cleanup(func() {
		gitProxySingleton.Store(prevSvc)
		gitProxyRequired.Store(prevReq)
	})
}

// hubGrants lists every grant in the hub's broker, revoked ones included.
func hubGrants(t *testing.T, f *personalFixture) []secretbroker.Grant {
	t.Helper()
	db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	b, err := secretbroker.New(store)
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	grants, err := b.ListGrants(secretbroker.GrantFilter{})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	return grants
}

func TestProjectRepositoriesCarryABranchRestriction(t *testing.T) {
	withNoGitProxy(t)
	f := newPersonalFixture(t)
	f.seedShared(t, "shared-pat", "ghp_sharedTokenForBranchTests000000")

	code, raw, a := assign(t, f, "lead", map[string]any{
		"secret":   "shared-pat",
		"repos":    []string{"acme/api"},
		"access":   "write",
		"branches": []string{" cloop/* ", "feature/**", ""},
	})
	if code != http.StatusOK {
		t.Fatalf("assigning write access limited to branches = %d\nbody: %s", code, raw)
	}
	if !slices.Equal(a.Branches, []string{"cloop/*", "feature/**"}) {
		t.Errorf("branches = %q, want the trimmed list", a.Branches)
	}
	// This fixture runs no git proxy, and a PAT cannot be narrowed to
	// read-only, so the honest answer is that it will not be delivered.
	if a.BranchEnforcement != branchesNotDelivered {
		t.Errorf("branch_enforcement = %q, want %q", a.BranchEnforcement, branchesNotDelivered)
	}

	panel := loadRepoPanel(t, f, "lead")
	if len(panel.Assignments) != 1 {
		t.Fatalf("panel shows %d assignments, want 1", len(panel.Assignments))
	}
	row := panel.Assignments[0]
	if row.Access != "write" || !slices.Equal(row.Branches, a.Branches) ||
		row.BranchEnforcement != branchesNotDelivered || !row.Replaceable {
		t.Errorf("panel row = %+v", row)
	}
	// Answered before anyone types a branch, which is when it matters.
	if panel.GitProxy == nil || panel.GitProxy.Running {
		t.Errorf("git_proxy = %+v; the panel cannot tell whether a restriction will be enforced", panel.GitProxy)
	}

	// The same panel as a reader: an operator may see the project's access,
	// branches included, but may not change it.
	if rows := loadRepoPanel(t, f, "alice").Assignments; len(rows) != 1 || !slices.Equal(rows[0].Branches, a.Branches) {
		t.Errorf("a project reader sees %+v", rows)
	}
	if code, raw, _ := assign(t, f, "alice", map[string]any{
		"secret": "shared-pat", "repos": []string{"acme/api"}, "access": "write",
		"branches": []string{"main"}, "replaces": a.GrantID,
	}); code != http.StatusForbidden {
		t.Errorf("an operator replacing a grant = %d, want 403\nbody: %s", code, raw)
	}
}

func TestProjectRepositoriesRefuseABranchListWithoutWrite(t *testing.T) {
	withNoGitProxy(t)
	f := newPersonalFixture(t)
	f.seedShared(t, "shared-pat", "ghp_sharedTokenForBranchTests000000")

	code, raw, _ := assign(t, f, "lead", map[string]any{
		"secret": "shared-pat", "repos": []string{"acme/api"}, "access": "read",
		"branches": []string{"cloop/*"},
	})
	if code != http.StatusBadRequest || !strings.Contains(raw, "Read and write") {
		t.Errorf("read access with branches = %d %s; want a 400 that names the fix", code, raw)
	}

	code, raw, _ = assign(t, f, "lead", map[string]any{
		"secret": "shared-pat", "repos": []string{"acme/api"}, "access": "write",
		"branches": []string{"../main"},
	})
	if code != http.StatusBadRequest || !strings.Contains(raw, "../main") {
		t.Errorf("a malformed branch pattern = %d %s; want a 400 naming it", code, raw)
	}
	if n := len(hubGrants(t, f)); n != 0 {
		t.Errorf("%d grants exist after two refusals", n)
	}
}

// TestEditingAnAssignmentReplacesItsGrant is the edit path: one grant before,
// one grant after, carrying the new restriction and the old lifetime.
func TestEditingAnAssignmentReplacesItsGrant(t *testing.T) {
	withNoGitProxy(t)
	f := newPersonalFixture(t)
	f.seedShared(t, "shared-pat", "ghp_sharedTokenForBranchTests000000")

	code, raw, before := assign(t, f, "lead", map[string]any{
		"secret": "shared-pat", "repos": []string{"acme/api"}, "access": "write",
		"ttl_minutes": 600,
	})
	if code != http.StatusOK {
		t.Fatalf("initial assignment = %d\nbody: %s", code, raw)
	}
	if len(before.Branches) != 0 || before.BranchEnforcement != "" {
		t.Errorf("an unrestricted grant reports branches %q / %q", before.Branches, before.BranchEnforcement)
	}

	code, raw, after := assign(t, f, "lead", map[string]any{
		"secret": before.SecretID, "repos": before.Repos, "access": "write",
		"branches": []string{"cloop/*"}, "replaces": before.GrantID,
	})
	if code != http.StatusOK {
		t.Fatalf("editing the assignment = %d\nbody: %s", code, raw)
	}
	if after.GrantID == before.GrantID {
		t.Fatal("the edit returned the old grant")
	}
	if !slices.Equal(after.Branches, []string{"cloop/*"}) {
		t.Errorf("edited branches = %q", after.Branches)
	}
	// An edit changes what the grant allows, not how long it lasts.
	if d := after.ExpiresAt.Sub(before.ExpiresAt); d < -5*time.Second || d > 5*time.Second {
		t.Errorf("edit moved the expiry from %s to %s", before.ExpiresAt, after.ExpiresAt)
	}

	var active, revoked []string
	for _, g := range hubGrants(t, f) {
		if g.RevokedAt.IsZero() {
			active = append(active, g.ID)
		} else {
			revoked = append(revoked, g.ID)
		}
	}
	if !slices.Equal(active, []string{after.GrantID}) || !slices.Equal(revoked, []string{before.GrantID}) {
		t.Fatalf("after the edit: active %v, revoked %v; want exactly the new grant live", active, revoked)
	}
	if rows := loadRepoPanel(t, f, "lead").Assignments; len(rows) != 1 || rows[0].GrantID != after.GrantID {
		t.Errorf("the panel shows %+v after the edit", rows)
	}

	// The old grant is gone, so it cannot be edited again.
	code, raw, _ = assign(t, f, "lead", map[string]any{
		"secret": before.SecretID, "repos": before.Repos, "access": "read", "replaces": before.GrantID,
	})
	if code != http.StatusConflict {
		t.Errorf("replacing a revoked grant = %d, want 409\nbody: %s", code, raw)
	}
	code, raw, _ = assign(t, f, "lead", map[string]any{
		"secret": before.SecretID, "repos": before.Repos, "access": "read", "replaces": "grant_nope",
	})
	if code != http.StatusNotFound {
		t.Errorf("replacing an unknown grant = %d, want 404\nbody: %s", code, raw)
	}
	if n := len(hubGrants(t, f)); n != 2 {
		t.Errorf("%d grants exist; a refused edit must not create one", n)
	}
}

// TestAnEditCannotReachAnotherProjectsGrant: the grant to replace is checked
// against the project in the path, so an index a maintainer holds cannot be
// used to withdraw access somewhere else.
func TestAnEditCannotReachAnotherProjectsGrant(t *testing.T) {
	withNoGitProxy(t)
	f := newPersonalFixture(t)
	f.seedShared(t, "shared-pat", "ghp_sharedTokenForBranchTests000000")

	code, raw := f.postJSON(t, "root", "/api/grants", map[string]any{
		"secret_ref": "shared-pat", "subject": "project:/srv/elsewhere",
		"repos": []string{"acme/api"}, "permissions": []string{"contents:write"},
		"branches": []string{"release/**"},
	})
	if code != http.StatusOK {
		t.Fatalf("creating the other project's grant = %d\nbody: %s", code, raw)
	}
	var other struct {
		ID                string `json:"id"`
		BranchEnforcement string `json:"branch_enforcement"`
		Constraints       struct {
			Branches []string `json:"branches"`
		} `json:"constraints"`
	}
	if err := json.Unmarshal([]byte(raw), &other); err != nil {
		t.Fatalf("decode grant: %v", err)
	}
	// The Secrets panel's view of the same restriction.
	if !slices.Equal(other.Constraints.Branches, []string{"release/**"}) ||
		other.BranchEnforcement != branchesNotDelivered {
		t.Errorf("grant view = %+v", other)
	}

	code, raw, _ = assign(t, f, "lead", map[string]any{
		"secret": "shared-pat", "repos": []string{"acme/api"}, "access": "read", "replaces": other.ID,
	})
	if code != http.StatusForbidden {
		t.Fatalf("replacing another project's grant = %d, want 403\nbody: %s", code, raw)
	}
	for _, g := range hubGrants(t, f) {
		if g.ID == other.ID && !g.RevokedAt.IsZero() {
			t.Fatal("the other project's grant was revoked through this project")
		}
	}
}
