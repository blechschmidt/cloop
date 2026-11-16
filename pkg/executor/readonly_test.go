package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOnlySlugIsAValidUniqueDirectoryName(t *testing.T) {
	taken := map[string]bool{}
	for _, tc := range []struct{ name, path, want string }{
		{"Shop API", "/p/shop", "shop-api"},
		{"Shop API", "/p/other", "shop-api-2"},
		{"", "/srv/projects/Billing_Service", "billing_service"},
		{"../../etc", "/p/x", "etc"},
		{"…", "/p/.hidden", "hidden"},
		{"", "/", "project"},
		{strings.Repeat("a", 80), "/p/long", strings.Repeat("a", 63)},
	} {
		got := ReadOnlySlug(tc.name, tc.path, taken)
		if got != tc.want || !ValidReadOnlySlug(got) {
			t.Errorf("ReadOnlySlug(%q, %q) = %q, want %q", tc.name, tc.path, got, tc.want)
		}
	}
	for _, bad := range []string{"", ".", "..", ".cloop", "a/b", "a:b", "A", "-a", strings.Repeat("a", 64)} {
		if ValidReadOnlySlug(bad) {
			t.Errorf("ValidReadOnlySlug(%q) = true", bad)
		}
	}
}

func TestReadOnlyHiddenNamesTheControlGitAndCredentialEntries(t *testing.T) {
	for _, name := range []string{".cloop", ".git", ".env", ".env.production", ".envrc", ".netrc", ".npmrc",
		".ssh", ".aws", ".kube", ".claude", ".mcp.json", "id_ed25519", "server.key", "cert.P12"} {
		if !ReadOnlyHidden(name) {
			t.Errorf("%s is not hidden", name)
		}
	}
	for _, name := range []string{"src", "README.md", ".gitignore", "env", ".environment", "id_ed25519.pub", "keys"} {
		if ReadOnlyHidden(name) {
			t.Errorf("%s is hidden", name)
		}
	}
	if !ReadOnlyHiddenPath("services/api/.env") || !ReadOnlyHiddenPath(".cloop/state.db") ||
		ReadOnlyHiddenPath("services/api/main.go") {
		t.Error("ReadOnlyHiddenPath disagrees with ReadOnlyHidden")
	}
}

// TestReadOnlyEntriesHidesWhatAHiddenLinkPointsInto: a project that keeps its
// .cloop as a link to a directory of its own tree has that directory hidden
// too, and a link is never an entry granted one by one.
func TestReadOnlyEntriesHidesWhatAHiddenLinkPointsInto(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"src", "state", "docs"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{".cloop": "state", "elsewhere": "/etc"} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	visible, hidden, err := ReadOnlyEntries(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := func(paths []string) string {
		var out []string
		for _, p := range paths {
			out = append(out, filepath.Base(p))
		}
		return strings.Join(out, ",")
	}
	if got := names(visible); got != "docs,src" {
		t.Errorf("visible = %s, want docs,src", got)
	}
	if got := names(hidden); got != ".env,state" {
		t.Errorf("hidden = %s, want .env,state", got)
	}
	if got := ReadOnlyHiddenAliases(dir); len(got) != 1 || got[0] != "state" {
		t.Errorf("ReadOnlyHiddenAliases = %v, want [state]", got)
	}
}

func TestReadOnlyManifestRoundTrips(t *testing.T) {
	entries := []ReadOnlyManifestEntry{{Slug: "api", Project: "/p/api", Name: "API", Path: "/readonly/api"}}
	got, err := DecodeReadOnlyManifest(EncodeReadOnlyManifest(entries))
	if err != nil || len(got) != 1 || got[0] != entries[0] {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	for _, bad := range []string{"{", `[{"slug":"a","path":"relative"}]`, `[{"slug":"../x","path":"/x"}]`,
		`[{"slug":"a","path":"/x"},{"slug":"a","path":"/y"}]`} {
		if _, err := DecodeReadOnlyManifest(bad); err == nil {
			t.Errorf("DecodeReadOnlyManifest(%s) accepted it", bad)
		}
	}
	env := WithReadOnlyManifest([]string{"A=1", EnvReadOnlyProjects + "=old"}, entries)
	if len(env) != 2 || env[0] != "A=1" || !strings.HasPrefix(env[1], EnvReadOnlyProjects+"=[") {
		t.Fatalf("WithReadOnlyManifest = %v", env)
	}
	if env := WithReadOnlyManifest([]string{EnvReadOnlyProjects + "=old"}, nil); len(env) != 0 {
		t.Fatalf("an empty manifest left %v", env)
	}
}

func TestValidateReadOnly(t *testing.T) {
	ok := ReadOnlyProject{Slug: "api", Project: "/p/a:b", Source: "/p/api",
		Snapshot: &ReadOnlySnapshotRef{URL: "https://hub/x", TokenEnv: "T"}}
	if err := ValidateReadOnly([]ReadOnlyProject{ok}); err != nil {
		t.Fatalf("a valid project was refused: %v", err)
	}
	for name, mutate := range map[string]func(*ReadOnlyProject){
		"bad slug":        func(p *ReadOnlyProject) { p.Slug = "../api" },
		"relative source": func(p *ReadOnlyProject) { p.Source = "api" },
		"unclean project": func(p *ReadOnlyProject) { p.Project = "/p/../api" },
		"snapshot no url": func(p *ReadOnlyProject) { p.Snapshot = &ReadOnlySnapshotRef{TokenEnv: "T"} },
		"snapshot no env": func(p *ReadOnlyProject) { p.Snapshot = &ReadOnlySnapshotRef{URL: "https://h/x"} },
	} {
		p := ok
		mutate(&p)
		if err := ValidateReadOnly([]ReadOnlyProject{p}); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: ValidateReadOnly = %v", name, err)
		}
	}
	if err := ValidateReadOnly([]ReadOnlyProject{ok, ok}); err == nil {
		t.Error("a slug used twice was accepted")
	}
}

func TestReadOnlyBindableRefusesWhatAMountFlagCannotCarry(t *testing.T) {
	dir := t.TempDir()
	if err := ReadOnlyBindable(dir); err != nil {
		t.Fatalf("a plain project is not bindable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.prod:bak"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadOnlyBindable(dir); err == nil {
		t.Error("a hidden entry with a colon in its name was taken as bindable")
	}
	if err := ReadOnlyBindable("/p/a,b"); err == nil {
		t.Error("a path with a comma was taken as bindable")
	}
}
