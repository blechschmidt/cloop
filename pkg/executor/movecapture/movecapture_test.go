package movecapture

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/projectmove"
)

// gitEnv is a git with no configuration but the identity the tests commit as.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
	)
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "init.defaultBranch=main", "-c", "safe.directory=*"}, args...)...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// scene is a trees root holding a project's working copy and one feature's,
// as a device keeps them, and a scratch directory of the agent's own.
type scene struct {
	root, wc, feature, scratch, outside string
}

const (
	wcName      = "proj-0a1b2c3d"
	featureName = "widget-4e5f6a7b"
)

func newScene(t *testing.T) *scene {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	s := &scene{
		root:    filepath.Join(base, "trees"),
		scratch: filepath.Join(base, "scratch"),
		outside: filepath.Join(base, "outside"),
	}
	s.wc = filepath.Join(s.root, wcName)
	s.feature = filepath.Join(s.root, featureName)
	for _, d := range []string{s.wc, s.feature, s.outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(s.outside, "secret.txt"), "outside the trees root\n")

	// The project: main pushed, a topic branch that is not, a remote whose
	// URL carries a token, and uncommitted work of every kind.
	git(t, s.wc, "init", "-q")
	write(t, filepath.Join(s.wc, "README.md"), "the project\n")
	write(t, filepath.Join(s.wc, "src/app.go"), "package app\n")
	git(t, s.wc, "add", "-A")
	git(t, s.wc, "commit", "-qm", "first")
	git(t, s.wc, "remote", "add", "origin", "https://x-access-token:ghs_s3cr3tTokenValue@example.com/acme/app.git")
	git(t, s.wc, "update-ref", "refs/remotes/origin/main", "HEAD")
	git(t, s.wc, "checkout", "-qb", "topic")
	write(t, filepath.Join(s.wc, "src/topic.go"), "package app // topic\n")
	git(t, s.wc, "add", "-A")
	git(t, s.wc, "commit", "-qm", "topic work")
	write(t, filepath.Join(s.wc, "README.md"), "the project, edited\n")
	write(t, filepath.Join(s.wc, "src/staged.go"), "package app // staged\n")
	git(t, s.wc, "add", "src/staged.go")
	write(t, filepath.Join(s.wc, "notes.txt"), "untracked notes\n")
	// .cloop: what runs wrote, what stays, what is a database, and a link.
	write(t, filepath.Join(s.wc, ".cloop/artifacts/1_output.txt"), "task one's output\n")
	write(t, filepath.Join(s.wc, ".cloop/tasks/1-first.md"), "# first\n")
	write(t, filepath.Join(s.wc, ".cloop/config.yaml"), "anthropic:\n  api_key: sk-not-for-travel\n")
	write(t, filepath.Join(s.wc, ".cloop/state.db"), "not really a database")
	if err := os.Symlink(filepath.Join(s.outside, "secret.txt"), filepath.Join(s.wc, ".cloop/artifacts/escape.txt")); err != nil {
		t.Fatal(err)
	}

	// A feature's working copy, a repository of its own beside the project's.
	git(t, s.feature, "init", "-q")
	write(t, filepath.Join(s.feature, "feature.go"), "package widget\n")
	git(t, s.feature, "add", "-A")
	git(t, s.feature, "commit", "-qm", "feature start")
	// main is on the feature's forge; the feature's own branch is not.
	git(t, s.feature, "update-ref", "refs/remotes/origin/main", "HEAD")
	git(t, s.feature, "checkout", "-qb", "cloop/feature/widget")
	write(t, filepath.Join(s.feature, "feature.go"), "package widget // more\n")
	git(t, s.feature, "commit", "-qam", "feature work")
	write(t, filepath.Join(s.feature, "wip.go"), "package widget // wip\n")
	write(t, filepath.Join(s.feature, ".cloop/artifacts/2_output.txt"), "feature task output\n")
	return s
}

func (s *scene) request(mode string) Request {
	return Request{
		Root: s.root, WorkDir: wcName, Mode: mode, MoveID: "0123456789abcdef",
		Features: []Feature{{Slug: "widget", Dir: featureName}},
		Scratch:  s.scratch, MaxBundleBytes: 64 << 20, MaxFilesBytes: 64 << 20,
	}
}

func TestCaptureCarriesTheWorkingCopyAndItsFeature(t *testing.T) {
	s := newScene(t)
	ctx := context.Background()
	res, err := Capture(ctx, s.request(ModeCapture))
	if err != nil {
		t.Fatal(err)
	}
	doc := res.Doc
	if !doc.Present || doc.Manifest == nil || !doc.Manifest.Repository {
		t.Fatalf("capture found no repository: %+v", doc)
	}
	m := *doc.Manifest
	if m.Head.Branch != "refs/heads/topic" || !m.Snapshot.Dirty {
		t.Errorf("HEAD %+v, dirty %v; want topic and dirty", m.Head, m.Snapshot.Dirty)
	}
	var unpushed []string
	for _, b := range m.Unpushed() {
		unpushed = append(unpushed, b.Name)
	}
	if strings.Join(unpushed, ",") != "refs/heads/topic" {
		t.Errorf("unpushed branches = %v, want topic alone", unpushed)
	}
	for _, r := range m.Remotes {
		if strings.Contains(r.URL, "ghs_") || strings.Contains(r.URL, "x-access-token") {
			t.Errorf("the manifest keeps the remote's credential: %s", r.URL)
		}
	}
	if len(doc.Features) != 1 || doc.Features[0] != "widget" {
		t.Errorf("features read = %v", doc.Features)
	}
	var ext *movegit.Worktree
	for i := range m.Worktrees {
		if m.Worktrees[i].Rel == ".cloop/features/widget" {
			ext = &m.Worktrees[i]
		}
	}
	if ext == nil || !strings.HasPrefix(ext.Ref, movegit.ExternalRefPrefix+"0123456789abcdef/") || !ext.Dirty {
		t.Fatalf("the feature's working copy is not carried: %+v", m.Worktrees)
	}
	if len(m.Carried) == 0 {
		t.Fatal("the feature's branches are not carried")
	}
	// What a target built from the forge would not see of the feature: its
	// own branch, not main, which its forge holds.
	var lost []string
	for _, c := range m.UnpushedCarried() {
		lost = append(lost, m.CarriedName(c))
	}
	if strings.Join(lost, ",") != "refs/heads/cloop/feature/widget" {
		t.Errorf("the feature's unpushed branches = %v", lost)
	}
	if err := movegit.ValidateManifest(m, "0123456789abcdef"); err != nil {
		t.Fatalf("the device's own manifest fails validation: %v", err)
	}

	// The bundle rebuilds the working copy, every ref and the snapshot.
	dst := filepath.Join(t.TempDir(), "rebuilt")
	if err := movegit.Restore(ctx, movegit.RestoreOptions{Dir: dst, BundlePath: res.BundlePath, Manifest: m}); err != nil {
		t.Fatal(err)
	}
	o, err := movegit.Inspect(ctx, dst, movegit.InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mm := movegit.Compare(m, o); len(mm) > 0 {
		t.Errorf("the rebuilt copy differs from the capture: %v", mm)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "notes.txt")); err != nil || string(b) != "untracked notes\n" {
		t.Errorf("the untracked file did not come back: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".cloop")); err == nil {
		t.Error("the bundle carried .cloop into the working tree")
	}

	// The tar: what runs wrote, the project's and the feature's; never the
	// configuration, the database, or what a link points at.
	got := tarNames(t, res.TarPath)
	want := []string{"artifacts/1_output.txt", "features/widget/.cloop/artifacts/2_output.txt", "tasks/1-first.md"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("tar holds %v, want %v", got, want)
	}
	var kept []string
	for _, it := range doc.Kept {
		kept = append(kept, it.Name)
	}
	if strings.Join(kept, ",") != projectmove.FilesConfig {
		t.Errorf("kept = %v, want the configuration alone", kept)
	}
	if err := projectmove.ValidateFiles(doc.Files); err != nil {
		t.Errorf("the device's own file list fails validation: %v", err)
	}

	// What the hub reads back is what was written.
	raw, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDocument(raw, ModeCapture, "0123456789abcdef"); err != nil {
		t.Fatalf("the hub refuses the device's document: %v", err)
	}
	if _, err := DecodeDocument(raw, ModeCapture, "ffffffffffffffff"); err == nil {
		t.Error("a document for another move was accepted")
	}
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var names []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return names
}

func TestInspectReportsTheWorkingCopyAndItsFeature(t *testing.T) {
	s := newScene(t)
	doc, err := Inspect(context.Background(), s.request(ModeInspect))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Present || doc.Inspection == nil {
		t.Fatalf("inspection found nothing: %+v", doc)
	}
	g := doc.Inspection.Git
	byRel := map[string]bool{}
	for _, w := range g.Worktrees {
		byRel[w.Rel] = w.Dirty()
	}
	if !byRel[""] || !byRel[".cloop/features/widget"] {
		t.Errorf("worktrees = %+v, want the project and the feature, both dirty", g.Worktrees)
	}
	var featureBranch bool
	for _, b := range g.Branches {
		featureBranch = featureBranch || strings.HasPrefix(b.Name, "feature widget: ")
	}
	if !featureBranch {
		t.Errorf("the feature's branches are not reported: %+v", g.Branches)
	}
	if _, ok := doc.Inspection.Files.Category(projectmove.FilesArtifacts); !ok {
		t.Errorf("the project's artifacts are not inventoried: %+v", doc.Inspection.Files)
	}
	if _, ok := doc.Inspection.FeatureFiles["widget"]; !ok {
		t.Error("the feature's .cloop is not inventoried")
	}
	if doc.Inspection.Files.Links != 1 {
		t.Errorf("links = %d, want the one planted (not followed)", doc.Inspection.Files.Links)
	}
	raw, _ := doc.Encode()
	if _, err := DecodeDocument(raw, ModeInspect, ""); err != nil {
		t.Fatalf("the hub refuses the device's inspection: %v", err)
	}
	// Inspection writes nothing.
	if out := git(t, s.wc, "for-each-ref", "refs/cloop/"); out != "" {
		t.Errorf("an inspection wrote refs: %s", out)
	}
}

func TestAbsentWorkingCopyIsReportedAbsent(t *testing.T) {
	s := newScene(t)
	req := s.request(ModeCapture)
	req.WorkDir = "never-ran-00000000"
	res, err := Capture(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Doc.Present || res.BundlePath != "" || res.TarPath != "" {
		t.Errorf("an absent working copy produced %+v", res)
	}
}

func TestExcludedPathsAreNeverCaptured(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.wc, ".home/.claude/.credentials.json"), `{"token":"x"}`)
	req := s.request(ModeCapture)
	req.Exclude = []string{".home"}
	res, err := Capture(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	ls := git(t, s.wc, "ls-tree", "-r", "--name-only", res.Doc.Manifest.Snapshot.WorktreeTree)
	if strings.Contains(ls, ".home") || strings.Contains(ls, "credentials") {
		t.Errorf("an excluded path was captured:\n%s", ls)
	}
	if !strings.Contains(ls, "notes.txt") {
		t.Errorf("the snapshot lost the untracked file:\n%s", ls)
	}
}

// TestEscapesAreRefused: every way a working copy could lead git, or a read,
// outside the trees root is refused before git runs there.
func TestEscapesAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, s *scene)
		want  error
	}{
		{"the working copy is a link", func(t *testing.T, s *scene) {
			if err := os.RemoveAll(s.wc); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(s.outside, s.wc); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{".git is a link", func(t *testing.T, s *scene) {
			other := filepath.Join(s.outside, "repo")
			git(t, s.outside, "init", "-q", other)
			if err := os.RemoveAll(filepath.Join(s.wc, ".git")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(other, ".git"), filepath.Join(s.wc, ".git")); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{".git is a gitfile", func(t *testing.T, s *scene) {
			other := filepath.Join(s.outside, "repo")
			git(t, s.outside, "init", "-q", other)
			if err := os.RemoveAll(filepath.Join(s.wc, ".git")); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(s.wc, ".git"), "gitdir: "+filepath.Join(other, ".git")+"\n")
		}, ErrConfinement},
		{"alternates name another object store", func(t *testing.T, s *scene) {
			write(t, filepath.Join(s.wc, ".git/objects/info/alternates"), filepath.Join(s.outside, "objects")+"\n")
		}, ErrConfinement},
		{"a ref is a link", func(t *testing.T, s *scene) {
			if err := os.Symlink(filepath.Join(s.outside, "secret.txt"), filepath.Join(s.wc, ".git/refs/heads/evil")); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{"core.worktree moves the working tree", func(t *testing.T, s *scene) {
			git(t, s.wc, "config", "core.worktree", s.outside)
		}, ErrConfinement},
		{"the configuration includes a file", func(t *testing.T, s *scene) {
			git(t, s.wc, "config", "include.path", filepath.Join(s.outside, "secret.txt"))
		}, ErrConfinement},
		{"a conditional include", func(t *testing.T, s *scene) {
			git(t, s.wc, "config", "includeIf.gitdir:/.path", filepath.Join(s.outside, "secret.txt"))
		}, ErrConfinement},
		{"a feature's .git is a link", func(t *testing.T, s *scene) {
			if err := os.RemoveAll(filepath.Join(s.feature, ".git")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(s.wc, ".git"), filepath.Join(s.feature, ".git")); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{"a linked worktree reached through a link", func(t *testing.T, s *scene) {
			git(t, s.wc, "worktree", "add", "-q", "sub/wt", "main")
			// Move the worktree's parent out of the trees root and leave a
			// link in its place: git's record still names a path inside.
			if err := os.Rename(filepath.Join(s.wc, "sub"), filepath.Join(s.outside, "sub")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(s.outside, "sub"), filepath.Join(s.wc, "sub")); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{"a linked worktree's gitfile names another repository", func(t *testing.T, s *scene) {
			git(t, s.wc, "worktree", "add", "-q", "wt", "main")
			other := filepath.Join(s.outside, "repo")
			git(t, s.outside, "init", "-q", other)
			write(t, filepath.Join(s.wc, "wt/.git"), "gitdir: "+filepath.Join(other, ".git")+"\n")
		}, ErrConfinement},
		{"a worktree's record without commondir", func(t *testing.T, s *scene) {
			git(t, s.wc, "worktree", "add", "-q", "wt", "main")
			if err := os.Remove(filepath.Join(s.wc, ".git/worktrees/wt/commondir")); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{"a worktree's record with a configuration of its own", func(t *testing.T, s *scene) {
			git(t, s.wc, "worktree", "add", "-q", "wt", "main")
			write(t, filepath.Join(s.wc, ".git/worktrees/wt/config"), "[core]\n\tworktree = "+s.outside+"\n")
		}, ErrConfinement},
		{"a worktree's configuration names a filter", func(t *testing.T, s *scene) {
			git(t, s.wc, "worktree", "add", "-q", "wt", "main")
			write(t, filepath.Join(s.wc, ".git/worktrees/wt/config.worktree"), "[filter \"x\"]\n\tclean = cat "+s.outside+"/secret.txt\n")
		}, ErrConfinement},
		{"a signing program", func(t *testing.T, s *scene) {
			git(t, s.wc, "config", "gpg.program", filepath.Join(s.outside, "sign"))
		}, ErrConfinement},
		{"a remote's upload-pack", func(t *testing.T, s *scene) {
			git(t, s.wc, "config", "remote.origin.uploadpack", filepath.Join(s.outside, "run"))
		}, ErrConfinement},
		{"a nested repository's gitfile leads outside", func(t *testing.T, s *scene) {
			other := filepath.Join(s.outside, "repo")
			git(t, s.outside, "init", "-q", other)
			write(t, filepath.Join(s.wc, "vendor/lib/.git"), "gitdir: "+filepath.Join(other, ".git")+"\n")
		}, ErrConfinement},
		{"a nested repository's .git is a link", func(t *testing.T, s *scene) {
			other := filepath.Join(s.outside, "repo")
			git(t, s.outside, "init", "-q", other)
			if err := os.MkdirAll(filepath.Join(s.wc, "vendor/lib"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(other, ".git"), filepath.Join(s.wc, "vendor/lib/.git")); err != nil {
				t.Fatal(err)
			}
		}, ErrConfinement},
		{"a nested repository names another's objects", func(t *testing.T, s *scene) {
			nested := filepath.Join(s.wc, "vendor/lib")
			git(t, s.wc, "init", "-q", nested)
			write(t, filepath.Join(nested, ".git/objects/info/alternates"), filepath.Join(s.outside, "objects")+"\n")
		}, ErrConfinement},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{ModeCapture, ModeInspect} {
				s := newScene(t)
				tc.plant(t, s)
				var err error
				if mode == ModeCapture {
					_, err = Capture(context.Background(), s.request(mode))
				} else {
					_, err = Inspect(context.Background(), s.request(mode))
				}
				if !errors.Is(err, tc.want) {
					t.Errorf("%s: err = %v, want %v", mode, err, tc.want)
				}
				if mode == ModeCapture {
					if _, statErr := os.Stat(filepath.Join(s.scratch, BundleName)); statErr == nil {
						t.Errorf("a refused capture left a bundle behind")
					}
				}
			}
		})
	}
}

func TestRequestsOutsideTheirShapeAreRefused(t *testing.T) {
	s := newScene(t)
	for name, mutate := range map[string]func(r *Request){
		"a path, not a name":              func(r *Request) { r.WorkDir = "../" + wcName },
		"a nested name":                   func(r *Request) { r.WorkDir = wcName + "/sub" },
		"dot-dot":                         func(r *Request) { r.WorkDir = ".." },
		"a feature path":                  func(r *Request) { r.Features[0].Dir = "../escape" },
		"the project named as a feature":  func(r *Request) { r.Features[0].Dir = wcName },
		"scratch inside the working copy": func(r *Request) { r.Scratch = filepath.Join(s.wc, "scratch") },
		"a relative root":                 func(r *Request) { r.Root = "trees" },
		"an exclusion that climbs":        func(r *Request) { r.Exclude = []string{"../x"} },
		"no move":                         func(r *Request) { r.MoveID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			req := s.request(ModeCapture)
			req.Features = append([]Feature(nil), req.Features...)
			mutate(&req)
			if _, err := Capture(context.Background(), req); !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("err = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestDecodeDocumentRefusesWhatACaptureNeverWrites(t *testing.T) {
	s := newScene(t)
	res, err := Capture(context.Background(), s.request(ModeCapture))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(d *Document){
		"an option for a tree":        func(d *Document) { d.Manifest.Snapshot.WorktreeTree = "--index-output=/etc/x" },
		"a branch outside refs/heads": func(d *Document) { d.Manifest.Branches[0].Name = "refs/remotes/origin/x" },
		"a HEAD that climbs":          func(d *Document) { d.Manifest.Head.Branch = "refs/heads/../../config" },
		"a remote URL like an option": func(d *Document) { d.Manifest.Remotes[0].URL = "--upload-pack=touch /tmp/x" },
		"a file that climbs":          func(d *Document) { d.Files[0].Path = "../../etc/passwd" },
		"a file a move keeps":         func(d *Document) { d.Files[0].Path = "config.yaml" },
		"a stash ref of another move": func(d *Document) {
			d.Manifest.Stash = append(d.Manifest.Stash, movegit.Ref{Name: movegit.StashRefPrefix + "ffff/0", Object: strings.Repeat("a", 40)})
		},
		"no tar digest": func(d *Document) { d.FilesTar = nil },
		"another mode":  func(d *Document) { d.Mode = ModeInspect },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := res.Doc.Encode()
			var d Document
			if _, err := DecodeDocument(raw, ModeCapture, "0123456789abcdef"); err != nil {
				t.Fatalf("the unmodified document is refused: %v", err)
			}
			d, _ = DecodeDocument(raw, ModeCapture, "0123456789abcdef")
			mutate(&d)
			bad, _ := d.Encode()
			if _, err := DecodeDocument(bad, ModeCapture, "0123456789abcdef"); !errors.Is(err, ErrInvalidDocument) {
				t.Errorf("err = %v, want ErrInvalidDocument", err)
			}
		})
	}
}

func TestDecodeDocumentCleansText(t *testing.T) {
	s := newScene(t)
	doc, err := Inspect(context.Background(), s.request(ModeInspect))
	if err != nil {
		t.Fatal(err)
	}
	doc.Inspection.Git.Worktrees[0].ChangedPaths = []string{"\x1b[31mred\x1b[0m", strings.Repeat("x", 10000)}
	raw, _ := doc.Encode()
	got, err := DecodeDocument(raw, ModeInspect, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got.Inspection.Git.Worktrees[0].ChangedPaths {
		if strings.ContainsRune(p, 0x1b) || len(p) > maxDocText+8 {
			t.Errorf("an uncleaned path reached the hub: %q", p[:min(len(p), 40)])
		}
	}
}

// TestAnOrdinaryConfigurationIsAccepted: what git init writes, what a person
// or a harness plausibly sets, and the main configuration's filter drivers —
// which every git command the capture runs neutralises — do not refuse it.
func TestAnOrdinaryConfigurationIsAccepted(t *testing.T) {
	s := newScene(t)
	for _, kv := range [][2]string{
		{"user.name", "Somebody"}, {"core.autocrlf", "false"}, {"pull.rebase", "true"},
		{"branch.topic.remote", "origin"}, {"branch.topic.merge", "refs/heads/topic"},
		{"filter.lfs.clean", "git-lfs clean -- %f"}, {"filter.lfs.required", "true"},
		{"http.https://git.example.com/.sslCAInfo", "/etc/ssl/ca.pem"}, {"cloop.upstream", "https://git.example.com/acme/app.git"},
	} {
		git(t, s.wc, "config", kv[0], kv[1])
	}
	if _, err := Capture(context.Background(), s.request(ModeCapture)); err != nil {
		t.Fatalf("an ordinary configuration was refused: %v", err)
	}
}

// TestGitRunsAsTheWorkingCopysOwner: an agent running as root captures a
// working copy a workload's account owns as that account — what git writes in
// the repository stays the workload's, and git reads nothing the workload
// could not.
func TestGitRunsAsTheWorkingCopysOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the agent changes to the owner's account only as root")
	}
	const owner = 65534
	s := newScene(t)
	// The test's directories are root's alone; the owner must reach its trees.
	for d := filepath.Dir(s.root); d != filepath.Dir(d); d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o005 != 0o005 {
			if err := os.Chmod(d, fi.Mode().Perm()|0o005); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(d, fi.Mode().Perm()) })
		}
		if d == os.TempDir() {
			break
		}
	}
	for _, tree := range []string{s.wc, s.feature} {
		if err := filepath.Walk(tree, func(p string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, owner, owner)
		}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Capture(context.Background(), s.request(ModeCapture))
	if err != nil {
		t.Fatalf("capture as the owner: %v", err)
	}
	uid := func(p string) uint32 {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t).Uid
	}
	if got := uid(res.BundlePath); got != owner {
		t.Errorf("the bundle belongs to %d, want the owner %d", got, owner)
	}
	// What git wrote in the repository: the objects it carried a feature's
	// work in, and the snapshot.
	var rootOwned []string
	_ = filepath.Walk(filepath.Join(s.wc, ".git"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Sys().(*syscall.Stat_t).Uid != owner {
			rootOwned = append(rootOwned, p)
		}
		return nil
	})
	if len(rootOwned) > 0 {
		t.Errorf("git wrote in the repository as another user: %v", rootOwned)
	}
	if len(res.Doc.Manifest.Carried) == 0 || res.Doc.Manifest.Snapshot == nil {
		t.Errorf("the capture as the owner is incomplete: %+v", res.Doc.Manifest)
	}
}
