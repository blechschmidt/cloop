package feature

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Dark mode":                     "dark-mode",
		"  Login / Sign-up  ":           "login-sign-up",
		"API v2 — rate limits!":         "api-v2-rate-limits",
		"___":                           "",
		"ÜBER cool":                     "ber-cool",
		strings.Repeat("abc ", 20):      "abc-abc-abc-abc-abc-abc-abc-abc-abc-abc",
		"trailing-dash-at-limit------x": "trailing-dash-at-limit-x",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
		if got := Slugify(in); got != "" {
			if err := ValidSlug(got); err != nil {
				t.Errorf("Slugify(%q) = %q, which ValidSlug rejects: %v", in, got, err)
			}
		}
	}
}

func TestValidSlug(t *testing.T) {
	good := []string{"a", "dark-mode", "v2", "0-day", strings.Repeat("a", MaxSlugLen)}
	bad := []string{"", "-a", "a-", "A", "a_b", "a/b", "..", "a--b", "a b", strings.Repeat("a", MaxSlugLen+1), "features"}
	for _, s := range good {
		if err := ValidSlug(s); err != nil {
			t.Errorf("ValidSlug(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range bad[:len(bad)-1] {
		if err := ValidSlug(s); err == nil {
			t.Errorf("ValidSlug(%q) = nil, want an error", s)
		}
	}
	// "features" is a fine slug; it is only listed to show that a slug
	// equal to the directory name is not special.
	if err := ValidSlug("features"); err != nil {
		t.Errorf("ValidSlug(features) = %v", err)
	}
}

func TestParentOf(t *testing.T) {
	cases := []struct {
		path, parent, slug string
		ok                 bool
	}{
		{"/srv/proj/.cloop/features/dark-mode", "/srv/proj", "dark-mode", true},
		{"/srv/proj/.cloop/features/dark-mode/", "/srv/proj", "dark-mode", true},
		{"/srv/proj/.cloop/features/Dark", "", "", false},
		{"/srv/proj/.cloop/features", "", "", false},
		{"/srv/proj/.cloop/worktrees/task-1", "", "", false},
		{"/srv/proj/cloop/features/x", "", "", false},
		{"/srv/proj/.cloop/features/x/src", "", "", false},
		// A feature of a feature is not a feature.
		{"/srv/proj/.cloop/features/a/.cloop/features/b", "", "", false},
		{"/.cloop/features/x", "/", "x", true},
		{"", "", "", false},
	}
	for _, c := range cases {
		parent, slug, ok := ParentOf(c.path)
		if ok != c.ok || parent != c.parent || slug != c.slug {
			t.Errorf("ParentOf(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.path, parent, slug, ok, c.parent, c.slug, c.ok)
		}
	}
}

func TestInsideFeature(t *testing.T) {
	cases := []struct {
		path, root string
		ok         bool
	}{
		{"/p/.cloop/features/x", "/p/.cloop/features/x", true},
		{"/p/.cloop/features/x/.cloop/worktrees/task-3", "/p/.cloop/features/x", true},
		{"/p/.cloop/features/x/src/pkg", "/p/.cloop/features/x", true},
		{"/p/.cloop/features", "", false},
		{"/p/.cloop/worktrees/task-1", "", false},
		{"/p", "", false},
		{"/p/.cloop/features/Not_A_Slug/x", "", false},
	}
	for _, c := range cases {
		root, ok := InsideFeature(c.path)
		if ok != c.ok || root != c.root {
			t.Errorf("InsideFeature(%q) = (%q, %v), want (%q, %v)", c.path, root, ok, c.root, c.ok)
		}
	}
}

// writeFeature creates a feature directory with a record, as Create would.
func writeFeature(t *testing.T, project, slug string, created time.Time) string {
	t.Helper()
	dir := Path(project, slug)
	if err := os.MkdirAll(filepath.Join(dir, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}
	m := &Meta{
		Slug: slug, Title: "Feature " + slug, Branch: BranchName(slug),
		Base: "main", Parent: project, CreatedAt: created,
	}
	if err := SaveMeta(dir, m); err != nil {
		t.Fatalf("SaveMeta: %v", err)
	}
	return dir
}

func TestMetaRoundTrip(t *testing.T) {
	project := t.TempDir()
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	dir := writeFeature(t, project, "login", created)

	m, err := LoadMeta(dir)
	if err != nil {
		t.Fatalf("LoadMeta: %v", err)
	}
	if m.Version != metaVersion || m.Slug != "login" || m.Branch != "cloop/feature/login" ||
		m.Base != "main" || m.Parent != project || !m.CreatedAt.Equal(created) {
		t.Errorf("round trip lost data: %+v", m)
	}

	m.PR = &PR{Number: 7, URL: "https://github.com/o/r/pull/7", State: "open", CreatedAt: created}
	if err := SaveMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	again, err := LoadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.PR == nil || again.PR.Number != 7 || again.PR.State != "open" {
		t.Errorf("PR not persisted: %+v", again.PR)
	}
}

func TestSaveMetaRejectsInvalidRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := []*Meta{
		nil,
		{Slug: "Bad", Branch: "cloop/feature/Bad", Base: "main", Parent: "/p"},
		{Slug: "ok", Branch: "main", Base: "main", Parent: "/p"},
		{Slug: "ok", Branch: "cloop/feature/ok", Base: "", Parent: "/p"},
		{Slug: "ok", Branch: "cloop/feature/ok", Base: "main", Parent: "relative"},
	}
	for i, m := range bad {
		if err := SaveMeta(dir, m); err == nil {
			t.Errorf("case %d: SaveMeta accepted an invalid record %+v", i, m)
		}
	}
}

func TestLoadMetaRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"", "{", `{"slug":"x"}`, strings.Repeat("x", maxMetaBytes+1)} {
		if err := os.WriteFile(MetaPath(dir), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadMeta(dir); err == nil {
			t.Errorf("LoadMeta accepted %q…", body[:min(len(body), 20)])
		}
	}
}

func TestListAndOrphans(t *testing.T) {
	project := t.TempDir()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	writeFeature(t, project, "zeta", base)
	writeFeature(t, project, "alpha", base.Add(time.Hour))
	writeFeature(t, project, "beta", base) // same time as zeta: slug breaks the tie

	// Things that are not features.
	if err := os.MkdirAll(filepath.Join(Dir(project), "no-record"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(Dir(project), "Bad_Name"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(project), "stray-file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	moved := writeFeature(t, project, "moved", base)
	if err := os.Rename(moved, filepath.Join(Dir(project), "renamed")); err != nil {
		t.Fatal(err)
	}

	infos, err := List(project)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, in := range infos {
		got = append(got, in.Meta.Slug)
		if in.Path != Path(project, in.Meta.Slug) {
			t.Errorf("path of %s = %s", in.Meta.Slug, in.Path)
		}
	}
	if strings.Join(got, ",") != "beta,zeta,alpha" {
		t.Errorf("List = %v, want [beta zeta alpha] (oldest first, slug tie-break)", got)
	}

	orphans, err := Orphans(project)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"no-record", "Bad_Name", "stray-file", "renamed"} {
		if _, ok := orphans[filepath.Join(Dir(project), name)]; !ok {
			t.Errorf("Orphans did not report %s: %v", name, orphans)
		}
	}
	if len(orphans) != 4 {
		t.Errorf("Orphans reported %d entries, want 4: %v", len(orphans), orphans)
	}

	// A project without features, and a feature asked for its features.
	if infos, err := List(t.TempDir()); err != nil || len(infos) != 0 {
		t.Errorf("List(empty) = %v, %v", infos, err)
	}
	if infos, err := List(Path(project, "alpha")); err != nil || len(infos) != 0 {
		t.Errorf("List(feature) = %v, %v; features have no features", infos, err)
	}
}

func TestIsFeature(t *testing.T) {
	project := t.TempDir()
	dir := writeFeature(t, project, "x", time.Now())
	if !IsFeature(dir) {
		t.Error("IsFeature(real feature) = false")
	}
	if IsFeature(project) {
		t.Error("IsFeature(project) = true")
	}
	// A directory shaped like a feature with no record is not one.
	bare := Path(project, "bare")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	if IsFeature(bare) {
		t.Error("IsFeature(no record) = true")
	}
	// A record naming a different slug is somebody else's.
	other := Path(project, "other")
	if err := os.Rename(dir, other); err != nil {
		t.Fatal(err)
	}
	if IsFeature(other) {
		t.Error("IsFeature(record for another slug) = true")
	}
}

func TestPRBody(t *testing.T) {
	m := &Meta{Slug: "login", Title: "Login", Description: "Let users sign in.",
		Branch: "cloop/feature/login", Base: "main", Parent: "/p"}
	tasks := []*pm.Task{
		{ID: 1, Title: "Form", Status: pm.TaskDone},
		{ID: 2, Title: "Hash\npasswords", Status: pm.TaskDone},
		{ID: 3, Title: "Remember me", Status: pm.TaskPending},
		{ID: 4, Title: "OAuth", Status: pm.TaskInProgress},
		{ID: 5, Title: "SAML", Status: pm.TaskSkipped},
		nil,
	}
	body := PRBody(m, tasks)
	for _, want := range []string{
		"Let users sign in.",
		"## Completed tasks",
		"- [x] #1 Form",
		"- [x] #2 Hash passwords",
		"## Not completed",
		"- [ ] #3 Remember me\n",
		"- [ ] #4 OAuth (in_progress)",
		"## Skipped or failed",
		"- [ ] #5 SAML (skipped)",
		"branch `cloop/feature/login`, based on `main`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("PR body lacks %q:\n%s", want, body)
		}
	}
	if PRTitle(m) != "Login" || PRTitle(&Meta{Slug: "s"}) != "s" {
		t.Error("PRTitle")
	}

	var many []*pm.Task
	for i := 0; i < maxPRBodyTasks+5; i++ {
		many = append(many, &pm.Task{ID: i + 1, Title: "t" + strconv.Itoa(i), Status: pm.TaskDone})
	}
	if body := PRBody(m, many); !strings.Contains(body, "… and 5 more") {
		t.Errorf("long task lists are not truncated:\n%s", body)
	}
	if body := PRBody(m, nil); !strings.Contains(body, "no tasks recorded") {
		t.Errorf("empty plan not described:\n%s", body)
	}
}

// TestPackageSpawnsNoProcesses keeps this package pure. pkg/ui imports it to
// list features on every dashboard refresh, and pkg/ui may not spawn
// processes (pkg/ui/no_direct_exec_test.go) — which it would be doing by
// proxy if anything here ran git.
func TestPackageSpawnsNoProcesses(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" || strings.HasSuffix(p, "/featureops") {
				t.Errorf("%s imports %s; pkg/feature must stay free of process spawning", f, p)
			}
		}
	}
}

// TestSymlinksNeverAdoptAnotherProjectsFeatures: an agent that can write into
// one project's directory — a container bind-mounts all of it — must not be
// able to make another project's features appear as its own by linking them in.
func TestSymlinksNeverAdoptAnotherProjectsFeatures(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	attacker := filepath.Join(root, "attacker")
	writeFeature(t, victim, "secret", time.Now())
	if err := os.MkdirAll(filepath.Join(attacker, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}

	// The whole features directory linked in.
	if err := os.Symlink(Dir(victim), Dir(attacker)); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if infos, _ := List(attacker); len(infos) != 0 {
		t.Errorf("a linked features directory was listed: %v", infos)
	}
	if IsFeature(Path(attacker, "secret")) {
		t.Error("a feature reached through a linked features directory counts as the linker's")
	}

	// One feature linked in, inside a real features directory.
	if err := os.Remove(Dir(attacker)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(Dir(attacker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(Path(victim, "secret"), Path(attacker, "secret")); err != nil {
		t.Fatal(err)
	}
	if infos, _ := List(attacker); len(infos) != 0 || IsFeature(Path(attacker, "secret")) {
		t.Errorf("a linked feature directory was accepted: %v", infos)
	}

	// A real feature directory whose record is a link to someone else's.
	if err := os.Remove(Path(attacker, "secret")); err != nil {
		t.Fatal(err)
	}
	fake := Path(attacker, "secret")
	if err := os.MkdirAll(filepath.Join(fake, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(MetaPath(Path(victim, "secret")), MetaPath(fake)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMeta(fake); err == nil {
		t.Error("a linked record was read")
	}
	// The victim's own feature is untouched by all of this.
	if !IsFeature(Path(victim, "secret")) {
		t.Error("the real feature stopped being one")
	}
}
