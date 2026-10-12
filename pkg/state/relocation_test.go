package state

// A project's own files cannot relocate it (Task 20418). The hub reads and
// writes a registered project's state on its behalf, and two values that point
// that I/O at a directory are read from files the project's workload can write:
// the active session's name and the workdir column of its database. Neither
// may send the hub anywhere but the project's own directory.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func writeActiveSession(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "active_session"), []byte(name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestActiveDirRefusesANameThatLeavesTheProject(t *testing.T) {
	dir := t.TempDir()
	victim := t.TempDir()
	for _, name := range []string{
		"../../../../" + victim,
		"..",
		"a/b",
		"/etc",
		"bad name",
	} {
		writeActiveSession(t, dir, name)
		if got := ActiveDir(dir); got != dir {
			t.Errorf("active session %q resolved to %q; want the project's own state at %q", name, got, dir)
		}
	}
}

func TestActiveDirRefusesALinkedSession(t *testing.T) {
	dir := t.TempDir()
	victim := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop", "sessions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".cloop", "sessions", "alpha")); err != nil {
		t.Fatal(err)
	}
	writeActiveSession(t, dir, "alpha")
	if got := ActiveDir(dir); got != dir {
		t.Fatalf("a session that is a link resolved to %q; want %q", got, dir)
	}

	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(other, ".cloop", "sessions")); err != nil {
		t.Fatal(err)
	}
	writeActiveSession(t, other, "alpha")
	if got := ActiveDir(other); got != other {
		t.Fatalf("a sessions directory that is a link resolved to %q; want %q", got, other)
	}
}

func TestResolveWorkDir(t *testing.T) {
	project := t.TempDir()
	other := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(project, ".cloop", "sessions", "alpha")
	if err := os.MkdirAll(session, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, stored, dir, want string
	}{
		{"nothing stored", "", project, project},
		{"the same directory", project, project, project},
		{"the same directory by another spelling", link, project, link},
		{"another project that exists", other, project, project},
		{"the filesystem root", "/", project, project},
		{"an ancestor of the project", filepath.Dir(project), project, project},
		{"a directory inside the project", session, project, project},
		{"a hub path the sandbox cannot see", "/var/lib/cloop/projects/gone", project, project},
		{"a session's own project", project, session, project},
		{"a session claiming another project", other, session, session},
	} {
		if got := resolveWorkDir(c.stored, c.dir); got != c.want {
			t.Errorf("%s: resolveWorkDir(%q, %q) = %q, want %q", c.name, c.stored, c.dir, got, c.want)
		}
	}
}

// TestASavedProjectStaysInItsDirectory is the end-to-end claim: a project
// whose database names another project's directory — one UPDATE away for a
// workload that can write the file — is loaded and saved in its own, and the
// other project's database is not touched.
func TestASavedProjectStaysInItsDirectory(t *testing.T) {
	victim := t.TempDir()
	v, err := Init(victim, "the victim's goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	tenant := t.TempDir()
	st, err := Init(tenant, "the tenant's goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", DBPath(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE metadata SET value = ? WHERE key = 'workdir'`, victim); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	loaded, err := Load(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WorkDir != tenant {
		t.Fatalf("the tenant's state loads with WorkDir %q, want its own directory %q", loaded.WorkDir, tenant)
	}
	loaded.Goal = "written by the hub on the tenant's behalf"
	if err := loaded.Save(); err != nil {
		t.Fatal(err)
	}
	after, err := Load(victim)
	if err != nil {
		t.Fatal(err)
	}
	if after.Goal != "the victim's goal" {
		t.Fatalf("a save for the tenant reached the victim's database: its goal is now %q", after.Goal)
	}
	mine, err := Load(tenant)
	if err != nil || mine.Goal != "written by the hub on the tenant's behalf" {
		t.Fatalf("the tenant's save did not land in its own database: %v, %+v", err, mine)
	}
}
