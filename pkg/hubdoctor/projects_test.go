package hubdoctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectconfine"
)

// confinementWorld is a hub directory, a projects root beside it and the
// registry rows a test hands the check.
func confinementWorld(t *testing.T, rows ...string) (hub string, cfg *config.Config) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hub = filepath.Join(base, "hub")
	root := filepath.Join(base, "projects")
	for _, d := range []string{filepath.Join(hub, ".cloop"), root} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var entries []multiui.ProjectEntry
	for _, r := range rows {
		path := strings.NewReplacer("$HUB", hub, "$ROOT", root, "$BASE", base).Replace(r)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, multiui.ProjectEntry{Name: filepath.Base(path), Path: path})
	}
	if err := multiui.Save(entries); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = multiui.Save(nil) })
	cfg = &config.Config{}
	cfg.UI.ProjectsRoot = root
	return hub, cfg
}

func confinementFindings(t *testing.T, hub string, cfg *config.Config) []Finding {
	t.Helper()
	var got []Finding
	checkProjectConfinement(hub, cfg, func(f Finding) { got = append(got, f) })
	return got
}

// TestProjectConfinementFailsOnOverlappingRows: a row inside the hub's own
// directory and two rows of which one contains the other — both of them, since
// neither can run while the other is registered — fail the doctor, each named
// with what it overlaps, and nothing is touched.
func TestProjectConfinementFailsOnOverlappingRows(t *testing.T) {
	hub, cfg := confinementWorld(t,
		"$HUB",            // the hub's own entry: allowed
		"$HUB/nested",     // inside the control plane
		"$ROOT/alice",     // contains alice/sub
		"$ROOT/alice/sub", // inside alice
		"$ROOT/bob",       // fine
		"$BASE/elsewhere", // an administrator's, fine
	)
	got := confinementFindings(t, hub, cfg)
	if len(got) != 1 || got[0].Severity != SeverityFail || got[0].Check != "projects.confinement" {
		t.Fatalf("findings = %+v, want one failure", got)
	}
	msg := got[0].Message
	root := cfg.UI.ProjectsRoot
	for _, want := range []string{
		filepath.Join(hub, "nested") + ": ", "inside the hub's control plane",
		filepath.Join(root, "alice", "sub") + ": ", "inside the project at " + filepath.Join(root, "alice") + ":",
		filepath.Join(root, "alice") + ": ", "contains the project at " + filepath.Join(root, "alice", "sub"),
		"3 registered project(s)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the finding does not say %q:\n%s", want, msg)
		}
	}
	for _, clean := range []string{hub + ": ", filepath.Join(root, "bob") + ": ", "elsewhere: "} {
		if strings.Contains(msg, clean) {
			t.Errorf("the finding flags a clean row (%q):\n%s", clean, msg)
		}
	}
	if got[0].Remediation == "" {
		t.Error("a failure without a remediation")
	}
	// Flagged, never deleted.
	for _, d := range []string{filepath.Join(hub, "nested"), filepath.Join(root, "alice", "sub")} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s is gone after the check: %v", d, err)
		}
	}
	if entries, _ := multiui.Load(); len(entries) != 6 {
		t.Errorf("the registry has %d rows after the check, want all 6", len(entries))
	}
}

// TestProjectConfinementFlagsTheRootAndWhatIsUnderIt: the projects root
// registered as a project — what a maintainer could do before Task 20418 —
// contains every project created by name, and none of them can run until it is
// gone.
func TestProjectConfinementFlagsTheRootAndWhatIsUnderIt(t *testing.T) {
	hub, cfg := confinementWorld(t, "$HUB", "$ROOT", "$ROOT/carol")
	got := confinementFindings(t, hub, cfg)
	root := cfg.UI.ProjectsRoot
	if len(got) != 1 || got[0].Severity != SeverityFail {
		t.Fatalf("findings = %+v, want one failure", got)
	}
	for _, want := range []string{root + ": " + root + " is the hub's projects root",
		filepath.Join(root, "carol") + ": " + filepath.Join(root, "carol") + " is inside the project at " + root,
		"2 registered project(s)"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("the finding does not say %q:\n%s", want, got[0].Message)
		}
	}
}

func TestProjectConfinementPassesACleanRegistry(t *testing.T) {
	hub, cfg := confinementWorld(t, "$HUB", "$ROOT/alice", "$ROOT/bob", "$ROOT/bob2")
	got := confinementFindings(t, hub, cfg)
	if len(got) != 1 || got[0].Severity != SeverityPass || !strings.Contains(got[0].Message, "4 registered") {
		t.Fatalf("findings = %+v, want one pass over 4 projects", got)
	}
}

// TestProjectConfinementFindsAHubBelowARow: a row above a directory holding
// another hub's hub.env fails, though nothing is registered there.
func TestProjectConfinementFindsAHubBelowARow(t *testing.T) {
	hub, cfg := confinementWorld(t, "$BASE/srv")
	other := filepath.Join(filepath.Dir(hub), "srv", "hub2")
	if err := os.MkdirAll(filepath.Join(other, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, projectconfine.HubEnvFile), []byte("CLOOP_SECRET_KEY=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := confinementFindings(t, hub, cfg)
	if len(got) != 1 || got[0].Severity != SeverityFail || !strings.Contains(got[0].Message, other) {
		t.Fatalf("findings = %+v, want a failure naming %s", got, other)
	}
}
