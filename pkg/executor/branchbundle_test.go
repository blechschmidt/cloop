package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	bbHead   = strings.Repeat("a", 40)
	bbBase   = strings.Repeat("b", 40)
	bbDigest = strings.Repeat("c", 64)
)

func bundleWS(mut func(*BranchBundle)) Workspace {
	b := &BranchBundle{Branch: "cloop/feature/widget", Head: bbHead, Bytes: 100, SHA256: bbDigest}
	if mut != nil {
		mut(b)
	}
	return Workspace{Kind: WorkspaceBundle, Branch: b}
}

func overlayWS(mut func(*Workspace)) Workspace {
	w := Workspace{Kind: WorkspaceGit, Repo: "https://github.com/acme/app", Ref: bbBase,
		Branch: &BranchBundle{Branch: "cloop/feature/widget", Head: bbHead, Bytes: 100, SHA256: bbDigest}}
	if mut != nil {
		mut(&w)
	}
	return w
}

func TestBranchBundleValidation(t *testing.T) {
	good := map[string]Workspace{
		"bundle":         bundleWS(nil),
		"shallow bundle": bundleWS(func(b *BranchBundle) { b.Shallow = []string{bbBase} }),
		"overlay":        overlayWS(nil),
		"empty overlay": overlayWS(func(w *Workspace) {
			w.Branch = &BranchBundle{Branch: "cloop/feature/widget", Head: bbBase}
		}),
	}
	for name, w := range good {
		if err := w.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]Workspace{
		"bundle kind with no branch":      {Kind: WorkspaceBundle},
		"bundle with no bytes":            bundleWS(func(b *BranchBundle) { b.Bytes, b.SHA256 = 0, "" }),
		"branch outside cloop/":           bundleWS(func(b *BranchBundle) { b.Branch = "main" }),
		"branch that is a flag":           bundleWS(func(b *BranchBundle) { b.Branch = "-cloop/x" }),
		"short head":                      bundleWS(func(b *BranchBundle) { b.Head = "abc" }),
		"digest not hex":                  bundleWS(func(b *BranchBundle) { b.SHA256 = strings.Repeat("z", 64) }),
		"over the ceiling":                bundleWS(func(b *BranchBundle) { b.Bytes = MaxBranchBundleBytes + 1 }),
		"negative size":                   bundleWS(func(b *BranchBundle) { b.Bytes = -1 }),
		"bad shallow commit":              bundleWS(func(b *BranchBundle) { b.Shallow = []string{"nope"} }),
		"repo on a bundle workspace":      func() Workspace { w := bundleWS(nil); w.Repo = "https://x/y/z"; return w }(),
		"overlay on a branch ref":         overlayWS(func(w *Workspace) { w.Ref = "main" }),
		"empty overlay at another commit": overlayWS(func(w *Workspace) { w.Branch.Bytes, w.Branch.SHA256 = 0, "" }),
		"shallow overlay":                 overlayWS(func(w *Workspace) { w.Branch.Shallow = []string{bbBase} }),
		"branch on a bind workspace":      {Kind: WorkspaceBind, Branch: &BranchBundle{Branch: "cloop/feature/w", Head: bbHead}},
		"digest without bytes":            bundleWS(func(b *BranchBundle) { b.Bytes = 0 }),
		"too many shallow commits":        bundleWS(func(b *BranchBundle) { b.Shallow = make([]string, MaxBranchBundleShallow+1) }),
	}
	for name, w := range bad {
		if err := w.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

func TestSpecWithAShippedBranch(t *testing.T) {
	spec := Spec{Argv: []string{"cloop", "run"}, Workspace: bundleWS(nil),
		WriteBack: WriteBack{Mode: WriteBackBundle, Branch: "cloop/feature/widget"}}
	if err := spec.Validate(); err != nil {
		t.Fatalf("a feature's spec does not validate: %v", err)
	}
	if spec.WriteBackBase() != bbHead {
		t.Errorf("WriteBackBase = %s, want the shipped head", spec.WriteBackBase())
	}
	// A bundle needs no network to be built, so a sandbox without one can
	// still run a feature.
	spec.DisableNetwork = true
	if err := spec.Validate(); err != nil {
		t.Errorf("a bundle workspace with the network off: %v", err)
	}
	req := spec.SandboxRequirements()
	if !req.RequireBranchBundle || req.RequireWorkspaceProvisioning || !req.RequireWriteBack {
		t.Errorf("requirements = %+v", req)
	}
	overlay := Spec{Argv: []string{"cloop", "run"}, Workspace: overlayWS(nil)}
	if r := overlay.SandboxRequirements(); !r.RequireBranchBundle || !r.RequireWorkspaceProvisioning {
		t.Errorf("an overlay needs both a fetch and a shipped branch: %+v", r)
	}
	// Work comes back on the branch that was shipped, and nowhere else.
	spec.WriteBack.Branch = "cloop/feature/other"
	if err := spec.Validate(); err == nil {
		t.Error("a write-back onto a branch other than the shipped one validated")
	}
}

func TestBranchBundleVerifyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.bundle")
	data := []byte("not really a bundle, but bytes all the same")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	b := &BranchBundle{Branch: "cloop/feature/w", Head: bbHead, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	if err := b.VerifyFile(path); err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	short := *b
	short.Bytes++
	if err := short.VerifyFile(path); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("a size mismatch = %v", err)
	}
	wrong := *b
	wrong.SHA256 = bbDigest
	if err := wrong.VerifyFile(path); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("a digest mismatch = %v", err)
	}
	link := filepath.Join(dir, "link.bundle")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyFile(link); err == nil {
		t.Error("a link standing in for the bundle was followed")
	}
	if err := b.VerifyFile(""); err == nil {
		t.Error("a missing bundle verified")
	}
}

func TestHardenedGitConfigCoversEveryDriver(t *testing.T) {
	pairs := HardenedGitConfig([]string{"lfs", "my.crypt"})
	set := map[string]string{}
	for _, p := range pairs {
		set[p[0]] = p[1]
	}
	for _, want := range []string{"core.hooksPath", "core.fsmonitor", "commit.gpgSign"} {
		if _, ok := set[want]; !ok {
			t.Errorf("%s is not neutralised", want)
		}
	}
	for _, d := range []string{"lfs", "my.crypt"} {
		for _, v := range []string{"clean", "smudge", "process"} {
			if got, ok := set["filter."+d+"."+v]; !ok || got != "" {
				t.Errorf("filter.%s.%s = %q, %v; want emptied", d, v, got, ok)
			}
		}
	}
	// One configuration block, with the redirect guard still in it.
	env := GitEnv(pairs...)
	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_CONFIG_COUNT=") {
			count++
		}
	}
	if count != 1 || !strings.Contains(strings.Join(env, "\n"), "http.followRedirects") {
		t.Errorf("GitEnv rendered %d blocks: %v", count, env)
	}
}
