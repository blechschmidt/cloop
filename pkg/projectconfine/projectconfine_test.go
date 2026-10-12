package projectconfine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// world is a scratch filesystem with a hub, its projects root and a tenant
// project, laid out the way a bare-metal hub is: the control plane and the
// projects root side by side.
type world struct {
	base   string // the scratch directory, resolved
	hub    string // the control plane
	root   string // ui.projects_root
	tenant string // a registered project under the root
}

func newWorld(t *testing.T) world {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := world{
		base:   base,
		hub:    filepath.Join(base, "srv", "hub"),
		root:   filepath.Join(base, "srv", "projects"),
		tenant: filepath.Join(base, "srv", "projects", "alice"),
	}
	for _, d := range []string{filepath.Join(w.hub, ".cloop"), w.tenant} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func (w world) policy(confine bool) Policy {
	return Policy{
		ControlPlane:  w.hub,
		ProjectsRoot:  w.root,
		ConfineToRoot: confine,
		Projects:      []string{w.hub, w.tenant},
	}
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte("CLOOP_SECRET_KEY=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// expect runs one case and checks the rule (or the absence of one) and, when
// asked, the relation and the directory collided with.
type expect struct {
	name  string
	path  string
	rule  Rule // "" means allowed
	rel   Relation
	other string
	canon string // when set, the canonical path the check must return
}

func run(t *testing.T, p Policy, cases []expect) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			canon, err := p.Check(c.path)
			if c.rule == "" {
				if err != nil {
					t.Fatalf("Check(%q) refused: %v", c.path, err)
				}
			} else {
				v, ok := IsViolation(err)
				if !ok {
					t.Fatalf("Check(%q) = %v, want a %s violation", c.path, err, c.rule)
				}
				if v.Rule != c.rule {
					t.Fatalf("Check(%q) broke %s (%v), want %s", c.path, v.Rule, v, c.rule)
				}
				if c.rel != "" && v.Relation != c.rel {
					t.Errorf("Check(%q) relation %q, want %q (%v)", c.path, v.Relation, c.rel, v)
				}
				if c.other != "" && v.Other != c.other {
					t.Errorf("Check(%q) names %q, want %q (%v)", c.path, v.Other, c.other, v)
				}
				if v.Path == "" || !strings.Contains(v.Error(), v.Path) {
					t.Errorf("the refusal does not name the path: %q", v.Error())
				}
			}
			if c.canon != "" && canon != c.canon {
				t.Errorf("Check(%q) canonical = %q, want %q", c.path, canon, c.canon)
			}
		})
	}
}

// TestCheckForAMaintainer is the invariant as a maintainer meets it: inside the
// projects root, and nowhere that overlaps the hub or another project.
func TestCheckForAMaintainer(t *testing.T) {
	w := newWorld(t)
	run(t, w.policy(true), []expect{
		{name: "a new directory under the root", path: filepath.Join(w.root, "bob"),
			canon: filepath.Join(w.root, "bob")},
		{name: "trailing slash", path: filepath.Join(w.root, "bob") + "/",
			canon: filepath.Join(w.root, "bob")},
		{name: "dot-dot that stays inside", path: filepath.Join(w.root, "x", "..", "bob"),
			canon: filepath.Join(w.root, "bob")},
		{name: "the root itself", path: w.root, rule: RuleProjectsRoot, rel: Same},
		{name: "the root with a trailing slash", path: w.root + "/", rule: RuleProjectsRoot, rel: Same},
		{name: "the root's parent", path: filepath.Join(w.root, ".."), rule: RuleProjectsRoot, rel: Contains},
		{name: "dot-dot climbing out", path: filepath.Join(w.root, "bob", "..", ".."), rule: RuleProjectsRoot, rel: Contains},
		{name: "outside the root", path: filepath.Join(w.base, "elsewhere"), rule: RuleOutsideRoot, other: w.root},
		{name: "a sibling sharing the root's prefix", path: w.root + "2/bob", rule: RuleOutsideRoot},
		{name: "a hidden directory under the root", path: filepath.Join(w.root, ".ssh"), rule: RuleOutsideRoot},
		{name: "hidden below a visible one", path: filepath.Join(w.root, "bob", ".config"), rule: RuleOutsideRoot},
		{name: "an existing project", path: w.tenant, rule: RuleProject, rel: Same, other: w.tenant},
		{name: "inside another project", path: filepath.Join(w.tenant, "sub"), rule: RuleProject, rel: Inside, other: w.tenant},
		{name: "a sibling sharing a project's prefix", path: w.tenant + "2"},
		{name: "the control plane", path: w.hub, rule: RuleOutsideRoot},
	})
}

// TestCheckForAnAdministrator: an administrator may place a project outside the
// root, and is held to every other rule.
func TestCheckForAnAdministrator(t *testing.T) {
	w := newWorld(t)
	mkdir(t, filepath.Join(w.base, "data", "repo"))
	run(t, w.policy(false), []expect{
		{name: "outside the root", path: filepath.Join(w.base, "data", "repo")},
		{name: "the hub's directory", path: w.hub, rule: RuleControlPlane, rel: Same, other: w.hub},
		{name: "an ancestor of the hub", path: filepath.Join(w.base, "srv"), rule: RuleProjectsRoot},
		{name: "an ancestor of the hub beside the root", path: filepath.Dir(filepath.Join(w.base, "srv")),
			rule: RuleProjectsRoot},
		{name: "inside the hub", path: filepath.Join(w.hub, "src"), rule: RuleControlPlane, rel: Inside, other: w.hub},
		{name: "inside the hub's state", path: filepath.Join(w.hub, ".cloop", "x"), rule: RuleUnsafe},
		{name: "a sibling sharing the hub's prefix", path: w.hub + "2"},
		{name: "containing a project", path: filepath.Join(w.base, "srv", "projects2"), rule: ""},
		{name: "the root", path: w.root, rule: RuleProjectsRoot, rel: Same},
	})
}

// TestControlPlaneAncestorWithoutTheRoot: with no projects root between them,
// an ancestor of the control plane is refused for being one.
func TestControlPlaneAncestorWithoutTheRoot(t *testing.T) {
	w := newWorld(t)
	p := w.policy(false)
	p.ProjectsRoot = ""
	run(t, p, []expect{
		{name: "parent of the hub", path: filepath.Join(w.base, "srv"), rule: RuleControlPlane, rel: Contains, other: w.hub},
		{name: "parent of a project", path: w.root, rule: RuleProject, rel: Contains, other: w.tenant},
	})
}

// TestPackagedLayout is the image's: HOME, the control plane and the default
// projects root all under /var/lib/cloop. Inside the control plane is allowed
// there only under the root.
func TestPackagedLayout(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hub := filepath.Join(base, "var", "lib", "cloop")
	root := filepath.Join(hub, "projects")
	touch(t, filepath.Join(hub, HubEnvFile))
	mkdir(t, filepath.Join(hub, ".claude"))
	p := Policy{ControlPlane: hub, ProjectsRoot: root, ConfineToRoot: true, Projects: []string{hub}, Home: hub}
	run(t, p, []expect{
		{name: "a project under the root", path: filepath.Join(root, "widgets")},
		{name: "the hub's Claude login", path: filepath.Join(hub, ".claude"), rule: RuleOutsideRoot},
		{name: "/var/lib", path: filepath.Join(base, "var", "lib"), rule: RuleUnsafe}, // contains HOME
		{name: "the root's parent", path: filepath.Join(root, ".."), rule: RuleUnsafe},
	})
	admin := p
	admin.ConfineToRoot = false
	run(t, admin, []expect{
		{name: "inside the hub, outside the root", path: filepath.Join(hub, "other"), rule: RuleControlPlane, rel: Inside},
		{name: "the hub's Claude login", path: filepath.Join(hub, ".claude"), rule: RuleControlPlane, rel: Inside},
		{name: "under the root", path: filepath.Join(root, "x")},
	})
}

// TestSymlinkedAncestor: the check is about the directory the kernel would
// create, so a link in the path is followed before any rule is applied.
func TestSymlinkedAncestor(t *testing.T) {
	w := newWorld(t)
	link := filepath.Join(w.root, "link-to-hub")
	if err := os.Symlink(w.hub, link); err != nil {
		t.Fatal(err)
	}
	up := filepath.Join(w.root, "link-up")
	if err := os.Symlink(filepath.Join(w.base, "srv"), up); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(w.root, "dangling")
	if err := os.Symlink(filepath.Join(w.base, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	run(t, w.policy(true), []expect{
		{name: "through a link into the hub", path: filepath.Join(link, "evil"), rule: RuleOutsideRoot,
			canon: filepath.Join(w.hub, "evil")},
		{name: "a link to the hub's parent", path: up, rule: RuleProjectsRoot, rel: Contains},
		{name: "a dangling link", path: filepath.Join(dangling, "x"), rule: RuleUnresolvable},
	})
	run(t, w.policy(false), []expect{
		{name: "admin through a link into the hub", path: filepath.Join(link, "evil"), rule: RuleControlPlane, rel: Inside},
		{name: "admin through a link to the hub's parent", path: up, rule: RuleProjectsRoot},
	})
}

// TestOtherHubs: a directory holding .cloop/hub.env is a hub, found above the
// candidate, below it by the bounded search, or named as a running hub.
func TestOtherHubs(t *testing.T) {
	w := newWorld(t)
	other := filepath.Join(w.base, "opt", "hub2")
	touch(t, filepath.Join(other, HubEnvFile))
	running := filepath.Join(w.base, "opt", "hub3")
	mkdir(t, filepath.Join(running, "x"))

	p := w.policy(false)
	run(t, p, []expect{
		{name: "the other hub", path: other, rule: RuleHub, rel: Same, other: other},
		{name: "inside the other hub", path: filepath.Join(other, "proj"), rule: RuleHub, rel: Inside, other: other},
		// Without the search an ancestor is not found below...
		{name: "an ancestor, unsearched", path: filepath.Join(w.base, "opt")},
	})
	p.Scan = DefaultScan
	run(t, p, []expect{
		// ...and with it, it is.
		{name: "an ancestor, searched", path: filepath.Join(w.base, "opt"), rule: RuleHub, rel: Contains, other: other},
	})
	p.Scan = ScanLimits{}
	p.HubDirs = []string{running}
	run(t, p, []expect{
		{name: "a running hub's parent", path: filepath.Join(w.base, "opt"), rule: RuleHub, rel: Contains, other: running},
		{name: "a running hub itself", path: running, rule: RuleHub, rel: Same, other: running},
		// A running hub keeping no hub.env exposes nothing to a directory
		// inside it; one started in somebody's home must not stop every
		// project there.
		{name: "inside a running hub", path: filepath.Join(running, "x")},
	})
}

// TestExistingRows is the re-check of a row that is already a project: at
// dispatch, in the doctor, on the Projects tab.
func TestExistingRows(t *testing.T) {
	w := newWorld(t)
	inner := filepath.Join(w.hub, "nested")
	mkdir(t, inner)
	p := w.policy(false)
	p.Existing = true
	p.Projects = append(p.Projects, inner)
	run(t, p, []expect{
		{name: "the hub's own entry", path: w.hub},
		{name: "a tenant's own row", path: w.tenant},
		{name: "a row inside the hub", path: inner, rule: RuleControlPlane, rel: Inside},
		{name: "a row containing a tenant", path: w.root, rule: RuleProjectsRoot},
	})
}

func TestUnsafeReason(t *testing.T) {
	home := t.TempDir()
	for path, unsafe := range map[string]bool{
		"":                             true,
		"relative/path":                true,
		"/":                            true,
		"/etc":                         true,
		"/etc/cloop":                   true,
		"/usr/local/lib/x":             true,
		"/proc/1":                      true,
		"/var":                         true,
		"/tmp":                         true,
		"/srv/p/.cloop/features/x":     true,
		home:                           true,
		filepath.Dir(home):             true,
		filepath.Join(home, "x"):       false,
		"/var/lib/cloop/projects/demo": false,
		"/srv/p/.cloopy":               false,
		"/srv/projects/api":            false,
	} {
		if got := UnsafeReason(path, home) != ""; got != unsafe {
			t.Errorf("UnsafeReason(%q) unsafe=%v, want %v (%q)", path, got, unsafe, UnsafeReason(path, home))
		}
	}
}

func TestRelate(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want Relation
	}{
		{"/srv/p", "/srv/p", Same},
		{"/srv/p/x", "/srv/p", Inside},
		{"/srv/p", "/srv/p/x", Contains},
		{"/srv/p2", "/srv/p", ""},
		{"/srv/p", "/srv/p2", ""},
		{"/srv/p", "/", Inside},
		{"/", "/srv", Contains},
	} {
		if got := Relate(c.a, c.b); got != c.want {
			t.Errorf("Relate(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestHubsBelow(t *testing.T) {
	base := t.TempDir()
	touch(t, filepath.Join(base, "a", "b", "hub", HubEnvFile))
	touch(t, filepath.Join(base, ".hidden", "hub", HubEnvFile))
	touch(t, filepath.Join(base, "node_modules", "hub", HubEnvFile))
	elsewhere := t.TempDir()
	touch(t, filepath.Join(elsewhere, "hub", HubEnvFile))
	if err := os.Symlink(elsewhere, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	found, truncated := HubsBelow(base, DefaultScan)
	if truncated || len(found) != 1 || found[0] != filepath.Join(base, "a", "b", "hub") {
		t.Fatalf("HubsBelow = %v (truncated %v), want only a/b/hub", found, truncated)
	}
	// Too shallow to reach it: the depth limit is not a refusal.
	if found, truncated := HubsBelow(base, ScanLimits{MaxDepth: 2, MaxDirs: 100}); len(found) != 0 || truncated {
		t.Fatalf("a two-level search = %v (truncated %v)", found, truncated)
	}
	// Too narrow to finish: that is.
	if _, truncated := HubsBelow(base, ScanLimits{MaxDepth: 8, MaxDirs: 2}); !truncated {
		t.Fatal("a search that ran out of directories says it finished")
	}
	p := Policy{Scan: ScanLimits{MaxDepth: 8, MaxDirs: 2}}
	if _, err := p.Check(base); err == nil {
		t.Fatal("a tree too large to search was accepted")
	} else if v, _ := IsViolation(err); v == nil || v.Rule != RuleUnverifiable {
		t.Fatalf("a tree too large to search: %v, want %s", err, RuleUnverifiable)
	}
}

func TestBackstop(t *testing.T) {
	w := newWorld(t)
	other := filepath.Join(w.base, "opt", "hub2")
	touch(t, filepath.Join(other, HubEnvFile))
	mkdir(t, filepath.Join(other, "proj"))
	for _, c := range []struct {
		name string
		dir  string
		rule Rule
	}{
		{"the hub's own project", w.hub, ""},
		{"a tenant", w.tenant, ""},
		{"inside the hub, outside its state", filepath.Join(w.hub, "src"), ""},
		{"the hub's state", filepath.Join(w.hub, ".cloop"), RuleControlPlane},
		{"inside the hub's state", filepath.Join(w.hub, ".cloop", "features", "x"), RuleControlPlane},
		{"the hub's parent", filepath.Join(w.base, "srv"), RuleControlPlane},
		{"inside another hub", filepath.Join(other, "proj"), RuleHub},
	} {
		err := Backstop(w.hub, c.dir)
		if c.rule == "" {
			if err != nil {
				t.Errorf("%s: Backstop refused: %v", c.name, err)
			}
			continue
		}
		if v, ok := IsViolation(err); !ok || v.Rule != c.rule {
			t.Errorf("%s: Backstop = %v, want %s", c.name, err, c.rule)
		}
	}
	if err := Backstop("", "/"); err != nil {
		t.Errorf("Backstop with no control plane refused: %v", err)
	}
}

func TestCanonical(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	mkdir(t, real)
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		filepath.Join(base, "link"):                    real,
		filepath.Join(base, "link") + "/":              real,
		filepath.Join(base, "link", "new", "deeper"):   filepath.Join(real, "new", "deeper"),
		filepath.Join(base, "link", "..", "x"):         filepath.Join(base, "x"),
		filepath.Join(base, "real", ".", "a", "", "b"): filepath.Join(real, "a", "b"),
	} {
		got, err := Canonical(in)
		if err != nil || got != want {
			t.Errorf("Canonical(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := Canonical("  "); err == nil {
		t.Error("Canonical of an empty path succeeded")
	}
}

// TestRelocatedState: a project whose .cloop is a link out of its directory —
// to another project's, or the hub's — breaks the invariant; one whose link
// stays inside it does not.
func TestRelocatedState(t *testing.T) {
	w := newWorld(t)
	evil := filepath.Join(w.root, "evil")
	mkdir(t, evil)
	if err := os.Symlink(filepath.Join(w.hub, ".cloop"), filepath.Join(evil, ".cloop")); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(w.root, "inside")
	mkdir(t, filepath.Join(inside, "state"))
	if err := os.Symlink(filepath.Join(inside, "state"), filepath.Join(inside, ".cloop")); err != nil {
		t.Fatal(err)
	}
	p := w.policy(false)
	p.Existing = true
	p.Projects = append(p.Projects, evil, inside)
	run(t, p, []expect{
		{name: "linked to the hub's state", path: evil, rule: RuleRelocated, other: filepath.Join(w.hub, ".cloop")},
		{name: "linked inside itself", path: inside},
	})
	if v, _ := IsViolation(func() error { _, err := p.Check(evil); return err }()); v == nil ||
		!strings.Contains(v.Error(), "would land there") {
		t.Fatalf("the refusal does not say what the link does: %v", v)
	}
}
