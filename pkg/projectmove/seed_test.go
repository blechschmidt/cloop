package projectmove

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/gitstate"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func put(t *testing.T, p string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func bin(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13) ^ seed
	}
	b[1] = 0
	return b
}

// files is what a tree holds outside .git and .cloop.
func files(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		top := strings.Split(filepath.ToSlash(rel), "/")[0]
		if top == ".git" || top == ".cloop" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[rel] = "link " + l
		case info.Mode().IsRegular():
			b, _ := os.ReadFile(p)
			s := sha256.Sum256(b)
			out[rel] = hex.EncodeToString(s[:8])
			if info.Mode()&0o100 != 0 {
				out[rel] += " +x"
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// dirtyProject is a project with a repository whose working tree holds every
// kind of change — a rename, deletions, binary files changed, added and
// untracked, untracked text, a link, an executable bit — and a .cloop holding
// files a move delivers and files it keeps on the hub.
func dirtyProject(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init", "-q", "-b", "main")
	put(t, filepath.Join(dir, "a.txt"), []byte("a\n"), 0o644)
	put(t, filepath.Join(dir, "rename-me.txt"), []byte("r\n"), 0o644)
	put(t, filepath.Join(dir, "delete-me.txt"), []byte("d\n"), 0o644)
	put(t, filepath.Join(dir, "blob.bin"), bin(2048, 1), 0o644)
	put(t, filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o644)
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", "base")
	runGit(t, dir, "remote", "add", "origin", "https://x-access-token:tok-123@github.com/acme/app.git")
	runGit(t, dir, "checkout", "-q", "-b", "topic")
	put(t, filepath.Join(dir, "a.txt"), []byte("topic\n"), 0o644)
	runGit(t, dir, "commit", "-q", "-am", "topic")
	runGit(t, dir, "mv", "rename-me.txt", "renamed.txt")
	if err := os.Remove(filepath.Join(dir, "delete-me.txt")); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "blob.bin"), bin(4096, 2), 0o644)
	put(t, filepath.Join(dir, "new.bin"), bin(777, 3), 0o644)
	runGit(t, dir, "add", "new.bin")
	put(t, filepath.Join(dir, "untracked", "notes.txt"), []byte("untracked\n"), 0o644)
	put(t, filepath.Join(dir, "loose.bin"), bin(99, 4), 0o644)
	put(t, filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o755)
	if err := os.Symlink("renamed.txt", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	cl := filepath.Join(dir, ".cloop")
	put(t, filepath.Join(cl, "artifacts", "7_output.txt"), []byte("output of task 7\n"), 0o644)
	put(t, filepath.Join(cl, "tasks", "7-fix.md"), []byte("# fix\n"), 0o644)
	put(t, filepath.Join(cl, "attachments", "outbox", "report.pdf"), bin(500, 5), 0o644)
	put(t, filepath.Join(cl, "checkpoints", "7.json"), []byte(`{"task":7}`), 0o644)
	put(t, filepath.Join(cl, "sandbox.yaml"), []byte("image: alpine\n"), 0o644)
	put(t, filepath.Join(cl, "requirements.yaml"), []byte("requirements: []\n"), 0o644)
	put(t, filepath.Join(cl, "config.yaml"), []byte("stt:\n  groq_api_key: secret\n"), 0o600)
	put(t, filepath.Join(cl, "attachments", "ab", "cdef"), []byte("stored attachment"), 0o600)
	put(t, filepath.Join(cl, "state.db"), []byte("database"), 0o600)
	put(t, filepath.Join(cl, "moves", "old", "repo.bundle"), []byte("an older move's store"), 0o600)
	put(t, filepath.Join(cl, "hub-ca.key"), []byte("PRIVATE"), 0o600)
	if err := os.Symlink("/etc/passwd", filepath.Join(cl, "artifacts", "link-out")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// capture is what the hub's capture phase does, in-process.
func capture(t *testing.T, dir, id string) (*CaptureRecord, string) {
	t.Helper()
	ctx := context.Background()
	store := t.TempDir()
	m, err := movegit.Capture(ctx, movegit.CaptureOptions{MoveID: id, Dir: dir, BundlePath: filepath.Join(store, CarrierBundle)})
	if err != nil {
		t.Fatal(err)
	}
	fl, kept, sum, err := PackFiles(dir, filepath.Join(store, CarrierFiles), 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := &CaptureRecord{Store: store, Delivery: DeliverDevice, Git: m, Files: fl, FilesTar: CarrierFiles, TarSum: &sum, KeptOnHub: kept}
	if m.Repository {
		rec.Bundle = CarrierBundle
	}
	return rec, store
}

// ship builds the carrier and provisions target from it exactly as a device
// provisions a feature's shipped branch.
func ship(t *testing.T, rec *CaptureRecord, store, id, target string) {
	t.Helper()
	ctx := context.Background()
	sm := SeedManifest{MoveID: id, Git: rec.Git, Files: rec.Files, FilesTar: rec.TarSum, Upstream: "https://hub.example/git/acme/app"}
	raw, _ := json.Marshal(sm)
	manifest := filepath.Join(store, CarrierManifest)
	put(t, manifest, raw, 0o600)
	cf := []movegit.CarrierFile{{Name: CarrierManifest, Path: manifest}, {Name: CarrierFiles, Path: filepath.Join(store, CarrierFiles)}}
	if rec.Git.Repository {
		cf = append(cf, movegit.CarrierFile{Name: CarrierBundle, Path: filepath.Join(store, CarrierBundle)})
	}
	out := filepath.Join(store, "seed.bundle")
	c, err := movegit.BuildCarrier(ctx, t.TempDir(), CarrierBranch(id), cf, out, executor.MaxBranchBundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	ws := executor.Workspace{Kind: executor.WorkspaceBundle, Branch: &executor.BranchBundle{
		Branch: CarrierBranch(id), Head: c.Head, Bytes: c.Digest.Bytes, SHA256: c.Digest.SHA256}}
	if err := ws.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := gitprovision.Provision(ctx, gitprovision.Request{Dir: target, Workspace: ws, BranchBundleFile: out, Host: "test-device"}); err != nil {
		t.Fatal(err)
	}
}

func TestTheSeedRebuildsADirtyWorkingCopyByteIdentical(t *testing.T) {
	ctx := context.Background()
	src := dirtyProject(t)
	status := runGit(t, src, "status", "--porcelain=v2", "--untracked-files=all", "--", ".", ":(exclude).cloop")
	before := files(t, src)
	rec, store := capture(t, src, "0123456789abcdef")

	// What stays on the hub.
	kept := map[string]int{}
	for _, it := range rec.KeptOnHub {
		kept[it.Name] = it.Count
	}
	if kept[FilesConfig] != 1 || kept[FilesAttachments] != 1 || kept[FilesOther] != 1 {
		t.Errorf("kept on the hub = %+v", rec.KeptOnHub)
	}
	delivered := map[string]bool{}
	for _, f := range rec.Files {
		delivered[f.Path] = true
	}
	for _, p := range []string{"artifacts/7_output.txt", "tasks/7-fix.md", "attachments/outbox/report.pdf", "checkpoints/7.json", "sandbox.yaml", "requirements.yaml"} {
		if !delivered[p] {
			t.Errorf("%s is not delivered: %v", p, delivered)
		}
	}
	for _, p := range []string{"config.yaml", "state.db", "hub-ca.key", "artifacts/link-out", "moves/old/repo.bundle", "attachments/ab/cdef"} {
		if delivered[p] {
			t.Errorf("%s is delivered", p)
		}
	}

	target := filepath.Join(t.TempDir(), "device-root", executor.DeviceWorkDir(src))
	ship(t, rec, store, "0123456789abcdef", target)
	report, err := SeedWorkingCopy(ctx, target, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if mm := CompareReport(rec, report); len(mm) > 0 {
		t.Fatalf("the seeded copy does not match the capture: %v", mm)
	}
	after := files(t, target)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: %q on the source, %q on the target", k, v, after[k])
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s exists only on the target", k)
		}
	}
	if got := runGit(t, target, "status", "--porcelain=v2", "--untracked-files=all", "--", ".", ":(exclude).cloop"); got != status {
		t.Errorf("status differs:\n%s\nvs\n%s", status, got)
	}
	if got := runGit(t, target, "symbolic-ref", "HEAD"); got != "refs/heads/topic" {
		t.Errorf("HEAD = %s", got)
	}
	if got := runGit(t, target, "branch", "--list", "cloop/move/*"); got != "" {
		t.Errorf("the carrier branch was left behind: %s", got)
	}
	if got := runGit(t, target, "config", "remote.origin.url"); got != "https://hub.example/git/acme/app" {
		t.Errorf("origin = %s", got)
	}
	if cfg, _ := os.ReadFile(filepath.Join(target, ".git", "config")); strings.Contains(string(cfg), "tok-123") {
		t.Error("the source's remote credential reached the target")
	}
	for _, p := range []string{"config.yaml", "hub-ca.key", "attachments/ab/cdef"} {
		if _, err := os.Lstat(filepath.Join(target, ".cloop", p)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf(".cloop/%s reached the target: %v", p, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(target, ".cloop", "attachments", "outbox", "report.pdf")); string(b) != string(bin(500, 5)) {
		t.Error("the outbox file came back different")
	}
	// Seeding again only reports, and the report is the same.
	again, err := SeedWorkingCopy(ctx, target, "0123456789abcdef")
	if err != nil || len(CompareReport(rec, again)) > 0 {
		t.Errorf("a second seed: %v %v", err, CompareReport(rec, again))
	}
	verify, err := ReportWorkingCopy(ctx, target, "0123456789abcdef")
	if err != nil || len(CompareReport(rec, verify)) > 0 {
		t.Errorf("verify: %v %v", err, CompareReport(rec, verify))
	}
	// The verification sees one changed byte of a delivered file.
	put(t, filepath.Join(target, ".cloop", "checkpoints", "7.json"), []byte(`{"task":8}`), 0o644)
	verify, _ = ReportWorkingCopy(ctx, target, "0123456789abcdef")
	if mm := CompareReport(rec, verify); len(mm) != 1 || !strings.Contains(mm[0], "checkpoints/7.json") {
		t.Errorf("mismatches = %v", mm)
	}
	// And the report survives a round trip through a workload's output.
	line, err := FormatReport(verify)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReport("workspace: provisioning...\n" + line + "\nexit\n")
	if err != nil || parsed.Git.WorktreeTree != verify.Git.WorktreeTree || len(parsed.Files) != len(verify.Files) {
		t.Errorf("parsed = %+v, %v", parsed, err)
	}
}

func TestTheSeedOfAProjectWithNoRepository(t *testing.T) {
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "plain")
	put(t, filepath.Join(src, ".cloop", "artifacts", "1_output.txt"), []byte("one\n"), 0o644)
	put(t, filepath.Join(src, ".cloop", "sandbox.yaml"), []byte("image: x\n"), 0o644)
	rec, store := capture(t, src, "fedcba9876543210")
	if rec.Git.Repository || rec.Bundle != "" || len(rec.Files) != 2 {
		t.Fatalf("capture = %+v", rec)
	}
	target := filepath.Join(t.TempDir(), "plain-copy")
	ship(t, rec, store, "fedcba9876543210", target)
	report, err := SeedWorkingCopy(ctx, target, "fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	if mm := CompareReport(rec, report); len(mm) > 0 {
		t.Fatalf("mismatches: %v", mm)
	}
	if _, err := os.Lstat(filepath.Join(target, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the transport's repository was left: %v", err)
	}
	for _, name := range []string{CarrierManifest, CarrierFiles} {
		if _, err := os.Lstat(filepath.Join(target, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the carrier's %s was left: %v", name, err)
		}
	}
}

func TestProbeTellsAnEmptyDirectoryAPartialSeedAndSomethingElse(t *testing.T) {
	ctx := context.Background()
	r, err := ProbeWorkingCopy(ctx, filepath.Join(t.TempDir(), "absent"), "aaaa")
	if err != nil || !r.Empty {
		t.Errorf("absent: %+v %v", r, err)
	}
	src := dirtyProject(t)
	rec, store := capture(t, src, "bbbbbbbbbbbbbbbb")
	target := filepath.Join(t.TempDir(), "t")
	ship(t, rec, store, "bbbbbbbbbbbbbbbb", target)
	r, _ = ProbeWorkingCopy(ctx, target, "bbbbbbbbbbbbbbbb")
	if r.Empty || !r.OnCarrier || r.SeededBy != "" {
		t.Errorf("provisioned, not yet seeded: %+v", r)
	}
	// A seed stopped half-way — its marker written, its record not yet —
	// is recognised as this move's, so the hub redoes it rather than
	// refusing the directory as somebody's work.
	half := filepath.Join(t.TempDir(), "half")
	put(t, filepath.Join(half, "renamed.txt"), []byte("r\n"), 0o644)
	put(t, filepath.Join(half, ".cloop", MovingInFile), []byte("bbbbbbbbbbbbbbbb"), 0o600)
	r, _ = ProbeWorkingCopy(ctx, half, "bbbbbbbbbbbbbbbb")
	if r.Seeding != "bbbbbbbbbbbbbbbb" || r.SeededBy != "" || r.Empty {
		t.Errorf("half-seeded: %+v", r)
	}
	if _, err := SeedWorkingCopy(ctx, target, "bbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	r, _ = ProbeWorkingCopy(ctx, target, "bbbbbbbbbbbbbbbb")
	if r.SeededBy != "bbbbbbbbbbbbbbbb" || r.OnCarrier || r.Seeding != "" {
		t.Errorf("seeded: %+v", r)
	}
	if _, err := os.Lstat(filepath.Join(target, ".cloop", MovingInFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a finished seed left its marker: %v", err)
	}
	other := t.TempDir()
	put(t, filepath.Join(other, "work.txt"), []byte("somebody's"), 0o644)
	r, _ = ProbeWorkingCopy(ctx, other, "bbbbbbbbbbbbbbbb")
	if r.Empty || r.SeededBy != "" || r.OnCarrier || r.Entries != 1 {
		t.Errorf("foreign: %+v", r)
	}
	if _, err := SeedWorkingCopy(ctx, other, "bbbbbbbbbbbbbbbb"); err == nil {
		t.Error("a seed ran in a directory the carrier never provisioned")
	}
}

// tarOf writes a tar holding the given entries.
func tarOf(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.tar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		body := entries[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	f.Close()
	return p
}

func fileOf(p, body string) File {
	s := sha256.Sum256([]byte(body))
	return File{Path: p, Bytes: int64(len(body)), SHA256: hex.EncodeToString(s[:]), Mode: 0o644}
}

func TestExtractFilesRefusesWhatTheCaptureDidNotRecord(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	cl := filepath.Join(root, "proj", ".cloop")
	for name, tc := range map[string]struct {
		entries map[string]string
		want    []File
	}{
		"traversal":     {map[string]string{"../escape": "x"}, []File{fileOf("../escape", "x")}},
		"unrecorded":    {map[string]string{"artifacts/a": "x", "extra": "y"}, []File{fileOf("artifacts/a", "x")}},
		"wrong digest":  {map[string]string{"artifacts/a": "x"}, []File{fileOf("artifacts/a", "z")}},
		"missing entry": {map[string]string{"artifacts/a": "x"}, []File{fileOf("artifacts/a", "x"), fileOf("artifacts/b", "y")}},
	} {
		t.Run(name, func(t *testing.T) {
			_ = os.RemoveAll(cl)
			if err := ExtractFiles(tarOf(t, tc.entries), cl, tc.want); err == nil {
				t.Error("extracted")
			}
			if _, err := os.Lstat(filepath.Join(root, "proj", "escape")); !errors.Is(err, os.ErrNotExist) {
				t.Error("a traversal entry was written")
			}
		})
	}
	// A link standing where a directory should be is never written through.
	_ = os.RemoveAll(cl)
	if err := os.MkdirAll(cl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cl, "artifacts")); err != nil {
		t.Fatal(err)
	}
	err := ExtractFiles(tarOf(t, map[string]string{"artifacts/a": "x"}), cl, []File{fileOf("artifacts/a", "x")})
	if err == nil {
		t.Error("extracted through a link")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("wrote through the link: %v", entries)
	}
	if mm := CheckFiles(cl, []File{fileOf("artifacts/a", "x")}); len(mm) != 1 {
		t.Errorf("CheckFiles through a link = %v", mm)
	}
}

func TestPackFilesIsBounded(t *testing.T) {
	src := dirtyProject(t)
	_, _, _, err := PackFiles(src, filepath.Join(t.TempDir(), "x.tar"), 10)
	if !errors.Is(err, ErrFilesTooLarge) {
		t.Errorf("err = %v", err)
	}
	fl, _, _, err := PackFiles(filepath.Join(t.TempDir(), "no-cloop"), filepath.Join(t.TempDir(), "y.tar"), 0)
	if err == nil && len(fl) != 0 {
		t.Errorf("a project with no .cloop delivered %v", fl)
	}
}

func TestTheJournalInTheControlPlane(t *testing.T) {
	ctx := context.Background()
	path := statedbtest.Path(t)
	open := func() (*statedb.DB, error) { return statedb.Open(path) }
	store := DBStore{Open: open}
	m := Move{ID: "1111111111111111", Project: testProject, Source: "local", Target: "dev1", Phase: PhasePreflight,
		CreatedAt: time.Now(), Detail: Detail{Timeline: []Step{{Phase: PhasePreflight}}}}
	m, err := store.Create(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	second := m
	second.ID = "2222222222222222"
	if _, err := store.Create(ctx, second); !errors.Is(err, ErrMoveOpen) {
		t.Fatalf("a second open move: %v", err)
	}
	m, err = store.Advance(ctx, m, PhaseQuiesce)
	if err != nil || m.Phase != PhaseQuiesce || m.Version != 2 {
		t.Fatalf("advance: %+v %v", m, err)
	}
	stale := m
	stale.Version = 1
	if _, err := store.Advance(ctx, stale, PhaseCapture); !errors.Is(err, ErrChanged) {
		t.Fatalf("a stale write: %v", err)
	}
	m, _ = store.Advance(ctx, m, PhaseCapture)
	m, _ = store.Advance(ctx, m, PhaseSwitch)

	db, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.BindProjectExecutor(testProject.Path, "local", "test"); !errors.Is(err, statedb.ErrExecutorNotFound) {
		// The executors this test binds to must be recorded first.
		t.Logf("binding to an unrecorded executor: %v", err)
	}
	for _, id := range []string{"local", "dev1"} {
		if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Name: id, Kind: "remote", Status: "ready", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.BindProjectExecutor(testProject.Path, "local", "test"); err != nil {
		t.Fatal(err)
	}
	// A switch to an executor with no record changes nothing at all.
	ghost := m
	ghost.Target = "ghost"
	if _, err := SwitchOn(db, ghost, PhaseSeed, "ghost", "test", nil); !errors.Is(err, statedb.ErrExecutorNotFound) {
		t.Fatalf("switch to a ghost: %v", err)
	}
	// Nor does one whose path-keyed writes fail.
	if _, err := SwitchOn(db, m, PhaseSeed, "dev1", "test", func(*statedb.FirewallTx) error { return errors.New("firewall") }); err == nil {
		t.Fatal("a switch whose firewall write failed went through")
	}
	if id, _, _ := db.ProjectExecutor(testProject.Path); id != "local" {
		t.Fatalf("binding after refused switches = %q", id)
	}
	cur, _ := store.Get(ctx, m.ID)
	if cur.Phase != PhaseSwitch || cur.Version != m.Version {
		t.Fatalf("a refused switch moved the journal: %s v%d", cur.Phase, cur.Version)
	}
	m, err = SwitchOn(db, m, PhaseSeed, "dev1", "test", nil)
	if err != nil || m.Phase != PhaseSeed {
		t.Fatalf("switch: %+v %v", m, err)
	}
	if id, _, _ := db.ProjectExecutor(testProject.Path); id != "dev1" {
		t.Fatalf("binding = %q", id)
	}
	if open, ok, err := OpenMove(db, testProject.Path); err != nil || !ok || open.ID != m.ID {
		t.Fatalf("open move = %+v %v %v", open, ok, err)
	}
	// Rolled back to no binding at all: the row goes.
	m.FailedPhase, m.Error = PhaseSeed, "the device went away"
	m, err = SwitchOn(db, m, PhaseRolledBack, "", "test", nil)
	if err != nil || m.Phase != PhaseRolledBack || m.FinishedAt.IsZero() || m.Error != "the device went away" || m.FailedPhase != PhaseSeed {
		t.Fatalf("rollback: %+v %v", m, err)
	}
	if _, ok, _ := db.ProjectExecutor(testProject.Path); ok {
		t.Error("the binding row survived a rollback to none")
	}
	if _, ok, _ := OpenMove(db, testProject.Path); ok {
		t.Error("a rolled-back move is still open")
	}
	// A later write to an ended move — a cleanup's — keeps when it ended.
	ended := m.FinishedAt
	m.Detail.Retained = &Retained{Command: "x"}
	later, err := store.Advance(ctx, m, m.Phase)
	if err != nil || !later.FinishedAt.Equal(ended) || later.Detail.Retained == nil || later.Error != m.Error {
		t.Errorf("a later write: finished %v (was %v), %+v, %v", later.FinishedAt, ended, later.Detail.Retained, err)
	}
	if _, err := store.Create(ctx, second); err != nil {
		t.Fatalf("a new move after one ended: %v", err)
	}
	list, err := ListMoves(db, statedb.ProjectMoveFilter{ProjectPath: testProject.Path})
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d %v", len(list), err)
	}
	if _, err := store.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get nothing: %v", err)
	}
	got, err := store.Get(ctx, m.ID)
	if err != nil || len(got.Detail.Timeline) != 1 || got.Source != "local" || got.Target != "dev1" {
		t.Errorf("read back: %+v %v", got, err)
	}
}

func TestTheMovesPreflightLetsQuiesceStopRuns(t *testing.T) {
	env := newEnv()
	since := time.Now().Add(-time.Minute)
	resumes := time.Now().Add(time.Hour)
	env.runs[testProject.Path] = RunFacts{Executing: true, ExecutingDetail: "a cloop run process on the hub", Status: "running"}
	rep, err := Preflight(context.Background(), env, testProject, "dev1", Options{Quiesce: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Blocked {
		t.Errorf("a run the move stops blocks it: %+v", rep.Of(KindRun))
	}
	if f := rep.Of(KindRun); len(f) != 1 || f[0].Severity != SeverityWillCarry || !strings.Contains(f[0].Title, "stops the run") {
		t.Errorf("run findings = %+v", f)
	}
	// Without the move's own quiesce it still blocks.
	rep, _ = Preflight(context.Background(), env, testProject, "dev1", Options{})
	if !rep.Blocked {
		t.Error("the plain preflight stopped blocking a running run")
	}
	// A pool run a runner was handed cannot be taken back.
	env.runs[testProject.Path] = RunFacts{Queued: &QueuedRun{PoolID: "p1", State: "assigned", Since: since}}
	rep, _ = Preflight(context.Background(), env, testProject, "dev1", Options{Quiesce: true})
	if !rep.Blocked {
		t.Error("an assigned pool run did not block")
	}
	env.runs[testProject.Path] = RunFacts{Queued: &QueuedRun{PoolID: "p1", State: "waiting", Since: since}}
	rep, _ = Preflight(context.Background(), env, testProject, "dev1", Options{Quiesce: true})
	if rep.Blocked {
		t.Error("a waiting pool run blocked a move that unqueues it")
	}
	env.runs[testProject.Path] = RunFacts{Status: "paused", Pause: &pausereason.Reason{Code: pausereason.CodeUsageCap, ResumesAt: &resumes}}
	rep, _ = Preflight(context.Background(), env, testProject, "dev1", Options{Quiesce: true})
	if rep.Blocked {
		t.Errorf("a scheduled restart blocked the move: %+v", rep.Of(KindRun))
	}
}

func TestAPoolTargetTakesOnlyWhatTheForgeHas(t *testing.T) {
	env := newEnv()
	env.pools["p1"] = PoolFacts{Found: true, Name: "pool", Admitted: true, OwnerMayRead: true, Template: deviceExec("tmpl")}
	env.tree.Git.Worktrees = []gitstate.Worktree{{Path: testProject.Path, Changed: 2}}
	rep, err := Preflight(context.Background(), env, testProject, "pool:p1", Options{Quiesce: true})
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Of(KindWorkingTree)
	if len(f) != 1 || f[0].Severity != SeverityBlocker {
		t.Errorf("dirty work for a pool = %+v", f)
	}
}
