package taskreplay

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run real git. Every claim CompareBundle makes — "the same tree",
// "the project was not modified" — is a claim about git's behaviour, and a fake
// would only be testing the fake.

func gitAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

// run executes git in dir and fails the test on error.
func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// newProject builds a repo with a base commit and returns its path and the
// base SHA.
func newProject(t *testing.T) (dir, base string) {
	t.Helper()
	dir = t.TempDir()
	run(t, dir, "init", "--quiet", "-b", "main")
	write(t, dir, "main.go", "package main\n\nfunc main() {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "--quiet", "-m", "base")
	return dir, run(t, dir, "rev-parse", "HEAD")
}

// commitChange adds a commit on a new branch off base and returns its SHA.
func commitChange(t *testing.T, dir, base, branch, file, content string) string {
	t.Helper()
	run(t, dir, "checkout", "--quiet", "-B", branch, base)
	write(t, dir, file, content)
	run(t, dir, "add", ".")
	run(t, dir, "commit", "--quiet", "-m", "change on "+branch)
	sha := run(t, dir, "rev-parse", "HEAD")
	run(t, dir, "checkout", "--quiet", "main")
	return sha
}

// bundleFrom clones the project at base into a scratch repo, applies content,
// commits it on branch, and returns a bundle path — which is exactly the shape
// an isolating executor returns from a bundle-mode write-back.
func bundleFrom(t *testing.T, projectDir, base, branch, file, content string) string {
	t.Helper()
	sandbox := t.TempDir()
	run(t, sandbox, "clone", "--quiet", "--no-checkout", projectDir, "work")
	work := filepath.Join(sandbox, "work")
	run(t, work, "checkout", "--quiet", "-B", strings.TrimPrefix(branch, "refs/heads/"), base)
	write(t, work, file, content)
	run(t, work, "add", ".")
	run(t, work, "commit", "--quiet", "-m", "reproduction")

	bundle := filepath.Join(t.TempDir(), "out.bundle")
	run(t, work, "bundle", "create", bundle, branch)
	return bundle
}

// projectFingerprint captures everything CompareBundle promises not to change.
func projectFingerprint(t *testing.T, dir string) string {
	t.Helper()
	refs := run(t, dir, "show-ref")
	head := run(t, dir, "rev-parse", "HEAD")
	status := run(t, dir, "status", "--porcelain")
	return refs + "\n" + head + "\n" + status
}

func TestCompareBundleIdenticalTree(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)

	const change = "package main\n\nfunc main() { println(\"hi\") }\n"
	original := commitChange(t, dir, base, "cloop/task-1", "main.go", change)
	bundle := bundleFrom(t, dir, base, "refs/heads/cloop/reproduce-1", "main.go", change)

	prov := &Provenance{OriginalCommit: original, BaseSHA: base, BaseSource: BaseRecorded}
	got, err := CompareBundle(context.Background(), dir, bundle, "cloop/reproduce-1", prov)
	if err != nil {
		t.Fatalf("CompareBundle: %v", err)
	}

	if !got.Identical {
		t.Errorf("Identical = false for the same content; trees were %s and %s",
			got.OriginalTree, got.ReplayTree)
	}
	if got.OriginalCommit == got.ReplayCommit {
		t.Error("the two commit SHAs matched — the fixture is not exercising the real case, " +
			"which is different commits with the same tree")
	}
	if !got.BaseConfirmed {
		t.Error("BaseConfirmed = false for a recorded base one commit behind the tip")
	}
	if got.DiffOfDiffs != "" {
		t.Errorf("an identical result carried a diff: %q", got.DiffOfDiffs)
	}
}

func TestCompareBundleDivergentTree(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)

	original := commitChange(t, dir, base, "cloop/task-1", "main.go",
		"package main\n\nfunc main() { println(\"one\") }\n")
	bundle := bundleFrom(t, dir, base, "refs/heads/cloop/reproduce-1", "main.go",
		"package main\n\nfunc main() { println(\"two\") }\n")

	prov := &Provenance{OriginalCommit: original, BaseSHA: base, BaseSource: BaseRecorded}
	got, err := CompareBundle(context.Background(), dir, bundle, "cloop/reproduce-1", prov)
	if err != nil {
		t.Fatalf("CompareBundle: %v", err)
	}

	if got.Identical {
		t.Fatal("Identical = true for different content")
	}
	if len(got.FilesDiffering) != 1 || got.FilesDiffering[0] != "main.go" {
		t.Errorf("FilesDiffering = %v, want [main.go]", got.FilesDiffering)
	}
	if !strings.Contains(got.DiffOfDiffs, "two") || !strings.Contains(got.DiffOfDiffs, "one") {
		t.Errorf("the diff-of-diffs does not show both sides of the disagreement:\n%s", got.DiffOfDiffs)
	}
	if got.DiffStat == "" {
		t.Error("DiffStat is empty for a divergent result")
	}
}

// TestCompareBundleLeavesTheProjectAlone is the non-destructive contract.
//
// It is asserted on the repository rather than on the code because that is the
// promise: an operator running a reproduction on a repository they are working
// in must get their refs, their HEAD and their uncommitted changes back exactly
// as they left them.
func TestCompareBundleLeavesTheProjectAlone(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)
	original := commitChange(t, dir, base, "cloop/task-1", "main.go", "package main\n// original\n")
	bundle := bundleFrom(t, dir, base, "refs/heads/cloop/reproduce-1", "main.go", "package main\n// replay\n")

	// An uncommitted edit, because that is what is actually at risk.
	write(t, dir, "scratch.txt", "work in progress\n")

	before := projectFingerprint(t, dir)

	prov := &Provenance{OriginalCommit: original, BaseSHA: base, BaseSource: BaseRecorded}
	if _, err := CompareBundle(context.Background(), dir, bundle, "cloop/reproduce-1", prov); err != nil {
		t.Fatalf("CompareBundle: %v", err)
	}

	if after := projectFingerprint(t, dir); after != before {
		t.Errorf("the project changed during a reproduction.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := os.Stat(filepath.Join(dir, "scratch.txt")); err != nil {
		t.Errorf("the operator's uncommitted file did not survive: %v", err)
	}
	// The replay branch must exist nowhere in the project: the bundle was read
	// into a scratch store, never fetched into here.
	if refs := run(t, dir, "show-ref"); strings.Contains(refs, "reproduce") {
		t.Errorf("a reproduction ref leaked into the project:\n%s", refs)
	}
}

// TestResolveBaseFindsTheForkPoint covers the ordinary unrecorded case: the
// base was never written to the event journal, and the branch point recovers
// it exactly — including for a write-back of more than one commit, which is
// what the first-parent guess gets wrong.
func TestResolveBaseFindsTheForkPoint(t *testing.T) {
	gitAvailable(t)

	for _, commits := range []int{1, 3} {
		t.Run(map[int]string{1: "single commit", 3: "three commits"}[commits], func(t *testing.T) {
			dir, base := newProject(t)
			run(t, dir, "checkout", "--quiet", "-B", "cloop/task-1", base)
			for i := 0; i < commits; i++ {
				write(t, dir, "main.go", "package main\n// step\n//"+strings.Repeat("x", i)+"\n")
				run(t, dir, "add", ".")
				run(t, dir, "commit", "--quiet", "-m", "step")
			}
			original := run(t, dir, "rev-parse", "HEAD")
			run(t, dir, "checkout", "--quiet", "main")

			prov := &Provenance{OriginalCommit: original}
			if err := ResolveBase(context.Background(), dir, prov); err != nil {
				t.Fatalf("ResolveBase: %v", err)
			}
			if prov.BaseSHA != base {
				t.Errorf("BaseSHA = %s, want the fork point %s", prov.BaseSHA, base)
			}
			if prov.BaseSource != BaseForkPoint {
				t.Errorf("BaseSource = %q, want %q", prov.BaseSource, BaseForkPoint)
			}
			if !prov.BaseSource.Trusted() {
				t.Error("a fork point should be trusted; it is correct for any write-back length")
			}
			if len(prov.Warnings) == 0 {
				t.Error("an unrecorded base must leave a warning, so a verdict is never read " +
					"without knowing where its base came from")
			}
		})
	}
}

// TestResolveBaseKeepsARecordedBase: a base the original run actually recorded
// must never be second-guessed by inference.
func TestResolveBaseKeepsARecordedBase(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)
	original := commitChange(t, dir, base, "cloop/task-1", "main.go", "package main\n// v\n")

	prov := &Provenance{OriginalCommit: original, BaseSHA: "recorded-sha", BaseSource: BaseRecorded}
	if err := ResolveBase(context.Background(), dir, prov); err != nil {
		t.Fatalf("ResolveBase: %v", err)
	}
	if prov.BaseSHA != "recorded-sha" || prov.BaseSource != BaseRecorded {
		t.Errorf("a recorded base was overwritten: %s (%s)", prov.BaseSHA, prov.BaseSource)
	}
	if len(prov.Warnings) != 0 {
		t.Errorf("a recorded base should warn about nothing, got %v", prov.Warnings)
	}
}

// TestFirstParentFallbackIsNeverTrusted pins the safety property: when the
// branch point cannot be recovered, the parent is used but no strong verdict
// may be issued from it. A three-commit write-back reproduced from its tip's
// parent starts two-thirds done, and would otherwise report IDENTICAL.
func TestFirstParentFallbackIsNeverTrusted(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)

	// Commit the write-back onto main itself, then advance HEAD to it: the
	// merge base of HEAD and the tip is now the tip, so there is no range to
	// measure and ResolveBase must fall back.
	run(t, dir, "checkout", "--quiet", "main")
	for _, v := range []string{"a", "b", "c"} {
		write(t, dir, "main.go", "package main\n// "+v+"\n")
		run(t, dir, "add", ".")
		run(t, dir, "commit", "--quiet", "-m", "step "+v)
	}
	original := run(t, dir, "rev-parse", "HEAD")

	prov := &Provenance{OriginalCommit: original}
	if err := ResolveBase(context.Background(), dir, prov); err != nil {
		t.Fatalf("ResolveBase: %v", err)
	}
	if prov.BaseSource != BaseFirstParent {
		t.Fatalf("BaseSource = %q, want %q when the write-back is already merged into HEAD",
			prov.BaseSource, BaseFirstParent)
	}
	if prov.BaseSource.Trusted() {
		t.Fatal("the first-parent fallback reported itself trusted")
	}

	bundle := bundleFrom(t, dir, base, "refs/heads/cloop/reproduce-1", "main.go", "package main\n// c\n")
	got, err := CompareBundle(context.Background(), dir, bundle, "cloop/reproduce-1", prov)
	if err != nil {
		t.Fatalf("CompareBundle: %v", err)
	}
	if got.BaseConfirmed {
		t.Error("BaseConfirmed = true on a first-parent guess — the reproduction cannot be " +
			"shown to have started from the tree the original did")
	}
	if verdict, reason := verdictFor(got, nil, nil, false, false); verdict != VerdictInconclusive {
		t.Errorf("verdict = %q on an unconfirmed base, want inconclusive (%s)", verdict, reason)
	}
}

// TestCompareBundleRequiresAResolvedBase: CompareBundle no longer infers, so a
// caller that skipped ResolveBase must get a clear refusal rather than a
// verdict computed against nothing.
func TestCompareBundleRequiresAResolvedBase(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)
	original := commitChange(t, dir, base, "cloop/task-1", "main.go", "package main\n// v\n")
	bundle := bundleFrom(t, dir, base, "refs/heads/cloop/reproduce-1", "main.go", "package main\n// v\n")

	prov := &Provenance{OriginalCommit: original} // ResolveBase not called
	_, err := CompareBundle(context.Background(), dir, bundle, "cloop/reproduce-1", prov)
	if err == nil || !strings.Contains(err.Error(), "no base commit was resolved") {
		t.Fatalf("err = %v, want a refusal naming the unresolved base", err)
	}
}

func TestCompareBundleRejectsUnknownCommit(t *testing.T) {
	gitAvailable(t)
	dir, base := newProject(t)
	bundle := bundleFrom(t, dir, base, "refs/heads/cloop/reproduce-1", "main.go", "package main\n// x\n")

	prov := &Provenance{
		OriginalCommit: "0123456789abcdef0123456789abcdef01234567",
		BaseSHA:        base, BaseSource: BaseRecorded,
	}
	_, err := CompareBundle(context.Background(), dir, bundle, "cloop/reproduce-1", prov)
	if err == nil {
		t.Fatal("CompareBundle accepted a commit that is not in the repository")
	}
	if !strings.Contains(err.Error(), "not in this repository") {
		t.Errorf("error = %v, want it to name the missing commit as the problem", err)
	}
}

func TestCompareBundleRejectsNoProvenance(t *testing.T) {
	if _, err := CompareBundle(context.Background(), t.TempDir(), "", "b", nil); err == nil {
		t.Error("CompareBundle accepted nil provenance")
	}
	_, err := CompareBundle(context.Background(), t.TempDir(), "", "b", &Provenance{})
	if err == nil {
		t.Error("CompareBundle accepted provenance with no original commit")
	}
}

func TestRefFor(t *testing.T) {
	cases := map[string]string{
		"cloop/x":            "refs/heads/cloop/x",
		"refs/heads/cloop/x": "refs/heads/cloop/x",
		"":                   "HEAD",
		"  ":                 "HEAD",
	}
	for in, want := range cases {
		if got := refFor(in); got != want {
			t.Errorf("refFor(%q) = %q, want %q", in, got, want)
		}
	}
}
