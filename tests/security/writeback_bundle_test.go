package security

// Guarantee 12: what an isolated executor sends back is content, and never
// configuration for the program that is about to read it.
//
// Every other guarantee in this suite is about keeping something *out* of a
// sandbox — a credential, a host path, an unvetted image. This one runs the
// other way. Task 20180 opened a channel from the sandbox to the hub's own
// repository, and a channel that carries a git commit range carries more than
// files: a tree can name a path inside .git, where a blob is not data but the
// configuration of the next checkout, and it can name a symlink, where the
// escape is not in the path that was written but in every path written through
// it afterwards.
//
// The failure mode is quiet. A write-back containing .git/hooks/post-checkout
// merges cleanly, reviews as a one-file diff nobody can see in `git show`
// without looking, and executes on the control plane the next time anyone
// checks the branch out. Nothing fails, and the transcript is honest.
//
// Two layers are asserted here because the production code has two:
//
//   - the rules themselves (executor.ValidateWriteBackPath, ValidateBundleEntry,
//     InspectWriteBack), against a table — every spelling of an escape at once,
//     which is the only way to cover the case-folding and NTFS forms;
//   - the same rules reached through real git — a real hostile commit, a real
//     bundle, a real fetch, a real writeback.Apply — because a rule that is
//     correct and never called is not a defence, and the wiring between the
//     bundle and the rule is where that goes wrong.
//
// The end-to-end half also pins something the local-transport tests reveal
// about the other layer: git's own fetch.fsckObjects/hasDotgit check does *not*
// fire for a fetch from a bundle file or a local path (git 2.43), because
// neither goes through index-pack. Over https it would. So on the path these
// tests take, executor.InspectWriteBack is the only thing standing between a
// sandbox and a hook on the hub — which is exactly why it is asserted against
// real objects rather than only against a table.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/writeback"
)

// writeBackTestBranch is namespaced under cloop/ because
// ValidateWriteBackBranch refuses anything else, and a test that used a branch
// the hub would reject on its name alone would never reach the content rules
// it claims to be about.
const writeBackTestBranch = "cloop/task-20180-write-back"

// writeBackFakeSHA is a well-formed object name for the table-driven half,
// where no repository exists and the SHA is only there to be echoed back in the
// rejection.
var writeBackFakeSHA = strings.Repeat("a", 40)

// --- the rules --------------------------------------------------------------

// TestWriteBackPathCannotEscapeTheProjectRoot: a write-back path is relative to
// the project root and stays there.
//
// The non-clean spellings are in the table for the same reason the traversals
// are. "a//b" and "a/./b" name the same file as "a/b" to the kernel but not to
// a string comparison, so admitting them would mean every later check — an
// allowlist, a review tool, a path this suite itself asserts on — could be
// handed a spelling it does not recognise.
func TestWriteBackPathCannotEscapeTheProjectRoot(t *testing.T) {
	escapes := map[string]string{
		"parent traversal":     "../etc/passwd",
		"mid-path traversal":   "a/../../b",
		"absolute path":        "/etc/passwd",
		"deep traversal":       "foo/../../../bar",
		"dot prefix":           "./x",
		"empty element":        "a//b",
		"dot element":          "a/./b",
		"trailing dot element": "a/b/.",
		"the root itself":      ".",
		"backslash separator":  `a\..\..\etc\passwd`,
	}
	for name, p := range escapes {
		t.Run(name, func(t *testing.T) {
			if err := executor.ValidateWriteBackPath(p); err == nil {
				t.Fatalf("ValidateWriteBackPath(%q) = nil — a sandbox could write outside "+
					"the project it was given", p)
			}
			rej := mustRejectWriteBackEntry(t, executor.BundleEntry{Path: p, Mode: executor.ModeFile})
			if rej.Path != p {
				t.Errorf("the rejection names %q, not the offending path %q — an operator's "+
					"first question is which path was refused", rej.Path, p)
			}
		})
	}
}

// TestWriteBackPathCannotReachTheGitDirectory is the hook-and-config half.
//
// A blob at .git/hooks/post-checkout runs the next time anyone checks the
// branch out, on the hub. A blob at .git/config can redirect a fetch or install
// a credential helper. Neither needs the path check to fail — it needs the path
// check not to know that .git is special, and the spellings below are how a
// checker that only compares against ".git" is bypassed on the machine that
// eventually does the checkout.
func TestWriteBackPathCannotReachTheGitDirectory(t *testing.T) {
	injections := map[string]string{
		"checkout hook":  ".git/hooks/post-checkout",
		"commit hook":    ".git/hooks/pre-commit",
		"config":         ".git/config",
		"upper case":     ".GIT/config",
		"mixed case":     ".Git/hooks/x",
		"trailing dot":   ".git./config",
		"trailing space": ".git /config",
		"8.3 short name": ".git~1/config",
		"nested":         "sub/.git/config",
		"nested folded":  "sub/.GIT./hooks/post-checkout",
	}
	for name, p := range injections {
		t.Run(name, func(t *testing.T) {
			if err := executor.ValidateWriteBackPath(p); err == nil {
				t.Fatalf("ValidateWriteBackPath(%q) = nil — this is not a file, it is "+
					"configuration for the program that checks the branch out", p)
			}
			rej := mustRejectWriteBackEntry(t, executor.BundleEntry{Path: p, Mode: executor.ModeExec})
			if rej.Path != p {
				t.Errorf("the rejection names %q, not %q", rej.Path, p)
			}
		})
	}

	// What isDotGit actually does, asserted rather than assumed. NTFS derives
	// the 8.3 short name GIT~1 for .git — the leading dot is dropped in the
	// generated name — so the folding is applied without requiring one, and a
	// top-level file literally named "git~1" is refused. That is a real (if
	// tiny) restriction on legitimate filenames, and it is the right trade: the
	// alternative is a spelling that resolves back to .git on the machine that
	// checks the tree out.
	for _, p := range []string{"git~1", "a/git~1/b", "git~1/config"} {
		if err := executor.ValidateWriteBackPath(p); err == nil {
			t.Errorf("ValidateWriteBackPath(%q) = nil — GIT~1 is the 8.3 short name of "+
				".git, and isDotGit folds it with and without the leading dot", p)
		}
	}
}

// TestWriteBackSymlinkCannotLeaveTheProjectRoot.
//
// A symlink is the one tree entry whose danger is not in its own path. "config"
// is a fine path; it stays a fine path right up until it is a link to /etc, at
// which point every subsequent "config/x" the merge queue or a later task
// writes is a write to the control plane's /etc.
//
// The accepted case at the end is not decoration. A rule that refuses every
// symlink would pass every hostile row above while breaking ordinary
// repositories, and the two are indistinguishable without a control.
func TestWriteBackSymlinkCannotLeaveTheProjectRoot(t *testing.T) {
	escapes := map[string]executor.BundleEntry{
		"absolute target": {
			Path: "link", Mode: executor.ModeSymlink, LinkTarget: "/etc/passwd",
		},
		"relative climb": {
			Path: "link", Mode: executor.ModeSymlink, LinkTarget: "../../../etc/passwd",
		},
		"climb from a subdirectory": {
			Path: "docs/link", Mode: executor.ModeSymlink, LinkTarget: "../../README.md",
		},
		"resolves into .git": {
			Path: "a/b", Mode: executor.ModeSymlink, LinkTarget: "../.git/config",
		},
		"resolves into .git folded": {
			Path: "a/b", Mode: executor.ModeSymlink, LinkTarget: "../.GIT/hooks/post-checkout",
		},
		"empty target": {
			Path: "link", Mode: executor.ModeSymlink, LinkTarget: "",
		},
		"whitespace target": {
			Path: "link", Mode: executor.ModeSymlink, LinkTarget: "   ",
		},
		"control character in target": {
			Path: "link", Mode: executor.ModeSymlink, LinkTarget: "a\nb",
		},
	}
	for name, e := range escapes {
		t.Run(name, func(t *testing.T) {
			if err := executor.ValidateBundleEntry(e); err == nil {
				t.Fatalf("ValidateBundleEntry(%+v) = nil — every later write through this "+
					"link lands wherever it points", e)
			}
			rej := mustRejectWriteBackEntry(t, e)
			if rej.Path != e.Path {
				t.Errorf("the rejection names path %q, not %q", rej.Path, e.Path)
			}
			if rej.Target != e.LinkTarget {
				t.Errorf("the rejection names target %q, not %q — the target is the whole "+
					"reason this entry was refused", rej.Target, e.LinkTarget)
			}
		})
	}

	// The control: a relative link that stays under the root is ordinary, and
	// refusing it would break repositories for no security benefit.
	contained := executor.BundleEntry{
		Path: "docs/link", Mode: executor.ModeSymlink, LinkTarget: "../README.md",
	}
	if err := executor.ValidateBundleEntry(contained); err != nil {
		t.Errorf("ValidateBundleEntry(%+v) = %v — docs/link -> ../README.md resolves to "+
			"README.md, which is inside the project; a rule that rejects everything is not a rule",
			contained, err)
	}
	if err := executor.InspectWriteBack(writeBackTestBranch, writeBackFakeSHA,
		[]executor.BundleEntry{contained}); err != nil {
		t.Errorf("InspectWriteBack refused a contained symlink: %v", err)
	}
}

// TestWriteBackRefusesSubmodulesAndUnknownModes.
//
// A gitlink names a repository URL rather than content, so a path check sees
// nothing wrong: the entry's own path is benign and the code it fetches is
// chosen by whoever wrote the entry. And an unrecognised mode is refused rather
// than ignored, because the set of things a git tree can hold is small and
// closed — "a mode we did not think about" is not a category worth admitting on
// a boundary whose input is model-authored.
func TestWriteBackRefusesSubmodulesAndUnknownModes(t *testing.T) {
	t.Run("submodule", func(t *testing.T) {
		e := executor.BundleEntry{Path: "vendor/lib", Mode: executor.ModeSubmodule}
		rej := mustRejectWriteBackEntry(t, e)
		if rej.Mode != executor.ModeSubmodule {
			t.Errorf("the rejection names mode %q, not %q", rej.Mode, executor.ModeSubmodule)
		}
		if !strings.Contains(rej.Reason, "submodule") {
			t.Errorf("the reason does not say what was refused: %q", rej.Reason)
		}
	})

	for name, mode := range map[string]string{
		"setuid-looking":      "104755",
		"unusual permission":  "100600",
		"symlink-exec hybrid": "120755",
		"nonsense":            "abcdef",
		"empty":               "",
	} {
		t.Run("unknown mode "+name, func(t *testing.T) {
			rej := mustRejectWriteBackEntry(t, executor.BundleEntry{Path: "x", Mode: mode})
			if rej.Mode != mode {
				t.Errorf("the rejection names mode %q, not %q", rej.Mode, mode)
			}
		})
	}

	// The closed set that is admitted, asserted so that shrinking it is a
	// deliberate act and growing it shows up in this file.
	for _, mode := range []string{
		executor.ModeFile, executor.ModeExec, executor.ModeTree, executor.ModeAbsent,
	} {
		if err := executor.ValidateBundleEntry(
			executor.BundleEntry{Path: "app/main.go", Mode: mode}); err != nil {
			t.Errorf("mode %q on an ordinary path was refused: %v", mode, err)
		}
	}
}

// TestWriteBackRefusesAnOversizeChangeSet: the inspection walks every changed
// path, so an unbounded change set is an unbounded walk on the control plane
// driven by a sandbox.
func TestWriteBackRefusesAnOversizeChangeSet(t *testing.T) {
	entries := make([]executor.BundleEntry, executor.MaxWriteBackFiles+1)
	for i := range entries {
		entries[i] = executor.BundleEntry{
			Path: fmt.Sprintf("gen/%d.txt", i), Mode: executor.ModeFile,
		}
	}

	err := executor.InspectWriteBack(writeBackTestBranch, writeBackFakeSHA, entries)
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("InspectWriteBack accepted %d entries, over the limit of %d: %v",
			len(entries), executor.MaxWriteBackFiles, err)
	}
	var rej *executor.WriteBackRejection
	if !errors.As(err, &rej) {
		t.Fatalf("want a *WriteBackRejection, got %T", err)
	}
	if !strings.Contains(rej.Reason, fmt.Sprint(executor.MaxWriteBackFiles)) {
		t.Errorf("the refusal does not name the limit it applied: %q", rej.Reason)
	}
	if rej.Branch != writeBackTestBranch || rej.CommitSHA != writeBackFakeSHA {
		t.Errorf("the refusal does not locate itself in the sandbox's output: %+v", rej)
	}

	// The boundary itself is admitted, so the check is a ceiling and not an
	// off-by-one that silently rejects a legitimate large refactor.
	if err := executor.InspectWriteBack(writeBackTestBranch, writeBackFakeSHA,
		entries[:executor.MaxWriteBackFiles]); err != nil {
		t.Errorf("InspectWriteBack refused exactly %d entries: %v", executor.MaxWriteBackFiles, err)
	}
}

// TestWriteBackAcceptsOrdinaryContent is the control for the whole table.
//
// Without it every row above would still pass if ValidateWriteBackPath returned
// an error unconditionally, and the write-back feature would be dead rather
// than safe. Note .github: it is not .git, and a rule that folded it in would
// make every repository with a CI workflow unable to write back.
func TestWriteBackAcceptsOrdinaryContent(t *testing.T) {
	ordinary := []string{
		"README.md",
		"a/b/c.go",
		".gitignore",
		".github/workflows/ci.yml",
		".gitlab-ci.yml",
		// Inert on its own: a .gitmodules file without a gitlink fetches
		// nothing, and the gitlink itself is refused by ValidateBundleEntry.
		".gitmodules",
		"docs/a file with spaces.md",
		"vendor/github.com/pkg/errors/errors.go",
	}
	for _, p := range ordinary {
		if err := executor.ValidateWriteBackPath(p); err != nil {
			t.Errorf("ValidateWriteBackPath(%q) = %v — this is an ordinary file", p, err)
		}
	}

	entries := make([]executor.BundleEntry, 0, len(ordinary))
	for _, p := range ordinary {
		entries = append(entries, executor.BundleEntry{Path: p, Mode: executor.ModeFile})
	}
	entries = append(entries,
		executor.BundleEntry{Path: "scripts/build.sh", Mode: executor.ModeExec},
		executor.BundleEntry{Path: "old/removed.go", Mode: executor.ModeAbsent},
	)
	if err := executor.InspectWriteBack(writeBackTestBranch, writeBackFakeSHA, entries); err != nil {
		t.Errorf("InspectWriteBack refused an ordinary change set: %v", err)
	}
}

// --- the same rules, through real git ---------------------------------------

// TestWriteBackBundleCannotDeliverAGitHook is the end-to-end version of the
// .git rule, and the most important test in this file.
//
// The hostile tree is built with plumbing because the porcelain will not build
// it: `git add .git/hooks/post-checkout` and
// `git update-index --add --cacheinfo 100755,<blob>,.git/hooks/post-checkout`
// both fail with "Invalid path". `git mktree` performs no such check, and
// neither does `git commit-tree` — which is the whole point. A sandbox running
// model-authored code has all of git available and is under no obligation to
// use the half that protects the hub. The tree is inspected with `git ls-tree`
// below before anything is asserted, so the test cannot pass because the
// hostile object was never constructed.
//
// Both transports are exercised. A sandbox holding a push credential can push a
// hook as easily as it can bundle one, and a suite that only checked the
// bundle would be securing the path that needs no credential while leaving open
// the one that does.
//
// The two subtests assert different things about *which* layer refuses, because
// they genuinely differ, and the difference is worth pinning rather than
// papering over:
//
//   - bundle: git's fetch-time fsck does not run, so executor.InspectWriteBack
//     is the only defence and the refusal is the typed *WriteBackRejection
//     naming the hook path.
//   - push: the sandbox's push packs the objects, the hub's fetch runs them
//     through index-pack, and fetch.fsckObjects/hasDotgit refuses them before
//     the inspection is ever reached. That refusal is real, but pkg/writeback
//     wraps a failed fetch as ErrWriteBackUnavailable — the sentinel that means
//     "infrastructure problem, retry it" — so a *security* event arrives
//     classified as an outage. See the note on assertGitHookNeverLands.
func TestWriteBackBundleCannotDeliverAGitHook(t *testing.T) {
	t.Run("bundle transport", func(t *testing.T) {
		s := newWriteBackScene(t)
		commit := s.plantGitDirectoryHook(t, writeBackTestBranch)
		raw := s.bundleRange(t, writeBackTestBranch)

		_, err := writeback.Apply(context.Background(), writeback.Request{
			RepoDir: s.hub, TaskID: 20180,
			Reported: executor.WriteBackResult{
				Mode: executor.WriteBackBundle, Branch: writeBackTestBranch,
				CommitSHA: commit, BaseSHA: s.base,
				BundleBytes: int64(len(raw)), BundleSHA256: gitwriteback.SHA256(raw),
			},
			Bundle: raw,
		})
		assertGitHookNeverLands(t, s, err)

		// On this transport the content policy is what stopped it, and it says
		// so: the path an operator has to see is in the error.
		if !errors.Is(err, executor.ErrWriteBackRejected) {
			t.Fatalf("a bundled .git/hooks/post-checkout was not refused by the content "+
				"policy: %v\n  git's own fsck does not run on a bundle fetch, so "+
				"InspectWriteBack is the only thing between a sandbox and a hook on the hub.", err)
		}
		var rej *executor.WriteBackRejection
		if !errors.As(err, &rej) {
			t.Fatalf("want a *WriteBackRejection an operator can read, got %T: %v", err, err)
		}
		if rej.Path != ".git/hooks/post-checkout" {
			t.Errorf("the rejection names %q, not the hook path", rej.Path)
		}
	})

	t.Run("push transport", func(t *testing.T) {
		s := newWriteBackScene(t)
		commit := s.plantGitDirectoryHook(t, writeBackTestBranch)
		gitIn(t, s.sandbox, "push", "--quiet", "origin",
			"refs/heads/"+writeBackTestBranch+":refs/heads/"+writeBackTestBranch)

		_, err := writeback.Apply(context.Background(), writeback.Request{
			RepoDir: s.hub, TaskID: 20180,
			Reported: executor.WriteBackResult{
				Mode: executor.WriteBackPush, Branch: writeBackTestBranch,
				CommitSHA: commit, BaseSHA: s.base, Pushed: true,
			},
		})
		assertGitHookNeverLands(t, s, err)
	})
}

// assertGitHookNeverLands is the property that must hold on every transport: the
// hook does not become a branch on the hub, and nothing unvetted outlives the
// attempt.
//
// The error is required to carry one of the two write-back sentinels rather than
// specifically ErrWriteBackRejected, and that weakening is a finding rather than
// a convenience. Which layer refuses a .git tree depends on whether git had to
// run index-pack — that is, on whether the source happened to hand over a pack
// or loose objects — and the applier reports git's own refusal through
// ErrWriteBackUnavailable, whose documented meaning is "nothing about the task's
// code is implicated; the remedy is an operator's". A hub that retried on that
// sentinel would retry a hostile write-back. Tightening it means classifying an
// fsck failure during untrustedFetch as a rejection; when that lands, this
// assertion should become errors.Is(err, ErrWriteBackRejected) on both
// transports.
func assertGitHookNeverLands(t *testing.T, s *writeBackScene, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("a commit adding .git/hooks/post-checkout was accepted\n" +
			"  A hook delivered this way runs on the hub at the next checkout of the branch.")
	}
	if !errors.Is(err, executor.ErrWriteBackRejected) &&
		!errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Fatalf("the refusal carries neither write-back sentinel, so no caller can classify "+
			"it: %T: %v", err, err)
	}
	assertWriteBackLeftNoTrace(t, s, writeBackTestBranch)
}

// TestWriteBackBundleCannotDeliverAnEscapingSymlink drives the symlink rule
// through a bundle a real sandbox really produced.
//
// Unlike the .git case this needs no plumbing: `git add` stores a symlink
// happily, which is what makes it the easier of the two attacks and the one
// worth proving round-trips into a bundle and is still refused on arrival.
func TestWriteBackBundleCannotDeliverAnEscapingSymlink(t *testing.T) {
	cases := map[string]struct{ link, target string }{
		"absolute escape":        {link: "escape", target: "/etc/passwd"},
		"relative escape":        {link: "docs/escape", target: "../../../../etc/passwd"},
		"into the git directory": {link: "docs/escape", target: "../.git/config"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newWriteBackScene(t)
			linkPath := filepath.Join(s.sandbox, filepath.FromSlash(tc.link))
			if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tc.target, linkPath); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}

			produced, raw := s.produceBundle(t)
			if produced.Skipped {
				t.Fatalf("the producer skipped a tree containing a symlink: %+v",
					produced.WriteBackResult)
			}
			// The symlink really is in the objects the sandbox produced, stored
			// as mode 120000. Without this the test could pass because git
			// dereferenced the link and committed a copy of the target.
			listing := gitIn(t, s.sandbox, "ls-tree", "-r", produced.CommitSHA)
			if !strings.Contains(listing, executor.ModeSymlink+" blob") {
				t.Fatalf("no symlink entry in the produced commit; the attack was never "+
					"constructed:\n%s", listing)
			}

			_, err := writeback.Apply(context.Background(), writeback.Request{
				RepoDir: s.hub, TaskID: 20180,
				Reported: produced.WriteBackResult, Bundle: raw,
			})
			if !errors.Is(err, executor.ErrWriteBackRejected) {
				t.Fatalf("a symlink to %q was accepted: %v\n"+
					"  Every later write through this link lands outside the project.", tc.target, err)
			}
			var rej *executor.WriteBackRejection
			if !errors.As(err, &rej) {
				t.Fatalf("want a *WriteBackRejection, got %T: %v", err, err)
			}
			if rej.Path != tc.link {
				t.Errorf("the rejection names %q, not the link %q", rej.Path, tc.link)
			}
			if rej.Target != tc.target {
				t.Errorf("the rejection names target %q, not %q", rej.Target, tc.target)
			}
			assertWriteBackLeftNoTrace(t, s, writeBackTestBranch)
		})
	}
}

// TestWriteBackBundleCannotExceedTheHardByteCeiling.
//
// The ceiling is a ceiling on attacker-influenced input: the sandbox chooses the
// bundle's contents, and a stream with no limit is how a hub runs out of memory.
// The gate runs before git is invoked at all, so the oversize case is built as a
// slice of the right length rather than as 128 MiB of real git objects — which
// would take minutes to produce and prove nothing extra, since the bytes are
// never read.
func TestWriteBackBundleCannotExceedTheHardByteCeiling(t *testing.T) {
	s := newWriteBackScene(t)
	oversize := executor.MaxWriteBackBundleBytes + 1

	_, err := writeback.Apply(context.Background(), writeback.Request{
		RepoDir: s.hub, TaskID: 20180,
		Reported: executor.WriteBackResult{
			Mode: executor.WriteBackBundle, Branch: writeBackTestBranch,
			// A well-formed SHA that is not the base, so the request gets past
			// the shape checks and is refused on its size rather than its form.
			CommitSHA: writeBackFakeSHA, BaseSHA: s.base,
			BundleBytes: oversize,
		},
		Bundle: make([]byte, oversize),
	})
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("a %d-byte bundle was accepted over the hard limit of %d: %v",
			oversize, executor.MaxWriteBackBundleBytes, err)
	}
	assertWriteBackLeftNoTrace(t, s, writeBackTestBranch)
}

// TestWriteBackBundleDeliversOrdinaryWork is the control for the end-to-end
// half, and the reason the three refusals above mean anything.
//
// It carries a contained symlink alongside the ordinary files deliberately: the
// symlink rule is the one most easily satisfied by refusing the whole category,
// and this is where that would show up.
func TestWriteBackBundleDeliversOrdinaryWork(t *testing.T) {
	s := newWriteBackScene(t)
	writeInto(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")
	writeInto(t, filepath.Join(s.sandbox, "docs", "guide.md"), "# guide\n")
	if err := os.Symlink("../README.md", filepath.Join(s.sandbox, "docs", "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	produced, raw := s.produceBundle(t)
	if produced.Skipped {
		t.Fatalf("the producer skipped a dirty tree: %+v", produced.WriteBackResult)
	}

	res, err := writeback.Apply(context.Background(), writeback.Request{
		RepoDir: s.hub, TaskID: 20180, TaskTitle: "add a retry",
		Reported: produced.WriteBackResult, Bundle: raw,
	})
	if err != nil {
		t.Fatalf("ordinary work was refused: %v\n"+
			"  If this fails, the rules above are passing because everything is rejected.", err)
	}
	if res.CommitSHA != produced.CommitSHA {
		t.Errorf("landed %s, the sandbox produced %s", res.CommitSHA, produced.CommitSHA)
	}
	if got := gitIn(t, s.hub, "rev-parse", "refs/heads/"+writeBackTestBranch); got != produced.CommitSHA {
		t.Errorf("the hub's branch is at %s, want %s", got, produced.CommitSHA)
	}
	// The content genuinely arrived, including the contained link.
	if body := gitIn(t, s.hub, "show", writeBackTestBranch+":app/retry.go"); !strings.Contains(body, "package main") {
		t.Errorf("app/retry.go on the landed branch = %q", body)
	}
	if target := gitIn(t, s.hub, "show", writeBackTestBranch+":docs/link"); target != "../README.md" {
		t.Errorf("docs/link on the landed branch points at %q, want ../README.md", target)
	}
	// An accepted write-back leaves no unpromoted second name for the commit.
	if quarantineRefExists(s.hub, writeBackTestBranch) {
		t.Error("the quarantine ref survived an accepted write-back")
	}
}

// --- helpers ----------------------------------------------------------------

// mustRejectWriteBackEntry asserts that one entry is refused by
// InspectWriteBack, as the typed rejection, and hands it back for inspection.
//
// It goes through InspectWriteBack rather than ValidateBundleEntry because the
// typed *WriteBackRejection — the thing an operator reads and the thing
// errors.Is(err, ErrWriteBackRejected) matches — is produced there. A rule that
// refuses correctly but loses its type on the way out is a security event
// indistinguishable from a corrupt download.
func mustRejectWriteBackEntry(t *testing.T, e executor.BundleEntry) *executor.WriteBackRejection {
	t.Helper()
	err := executor.InspectWriteBack(writeBackTestBranch, writeBackFakeSHA,
		[]executor.BundleEntry{e})
	if err == nil {
		t.Fatalf("InspectWriteBack accepted %+v", e)
	}
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("InspectWriteBack(%+v) = %v, which does not match ErrWriteBackRejected", e, err)
	}
	var rej *executor.WriteBackRejection
	if !errors.As(err, &rej) {
		t.Fatalf("InspectWriteBack(%+v) returned %T, want a *WriteBackRejection naming the path", e, err)
	}
	if rej.Reason == "" {
		t.Errorf("the rejection of %+v carries no reason", e)
	}
	return rej
}

// assertWriteBackLeftNoTrace: a refusal that leaves a ref behind is not a
// refusal.
//
// Both names are checked. refs/heads/<branch> is a branch — `git branch` lists
// it, a person or the merge queue can check it out, and a checkout is what makes
// a .git/hooks entry execute. The quarantine ref is where unvetted objects live
// while they are being inspected, and it must not outlive the inspection that
// refused it.
func assertWriteBackLeftNoTrace(t *testing.T, s *writeBackScene, branch string) {
	t.Helper()
	if listed := gitIn(t, s.hub, "branch", "--list", branch); listed != "" {
		t.Errorf("a rejected write-back created the branch %s on the hub: %q\n"+
			"  A ref under refs/heads is checkout-able by the merge queue and by a person.",
			branch, listed)
	}
	if quarantineRefExists(s.hub, branch) {
		t.Errorf("the quarantine ref %s%s survived a rejection — unvetted objects must not "+
			"outlive the inspection that refused them", writeback.QuarantineRefPrefix, branch)
	}
}

func quarantineRefExists(repo, branch string) bool {
	err := exec.Command("git", "-C", repo, "rev-parse", "--verify",
		writeback.QuarantineRefPrefix+branch).Run()
	return err == nil
}

// writeBackScene is the real system's shape: an origin, the hub's clone of it
// (the project on the control plane), and the sandbox's clone (the untrusted
// party). The bugs worth catching here are the ones where those three roles get
// confused, so a fake git would prove only that the fake agrees with the test.
type writeBackScene struct {
	origin  string // bare
	hub     string // the project on the control plane
	sandbox string // the untrusted working tree
	base    string // the commit both clones start at
}

func newWriteBackScene(t *testing.T) *writeBackScene {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()

	seed := filepath.Join(root, "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, seed, "init", "--quiet", "--initial-branch=main")
	writeInto(t, filepath.Join(seed, "README.md"), "hello\n")
	writeInto(t, filepath.Join(seed, "app", "main.go"), "package main\n")
	gitIn(t, seed, "add", "-A")
	gitIn(t, seed, "commit", "--quiet", "-m", "seed")

	origin := filepath.Join(root, "origin.git")
	gitIn(t, root, "clone", "--quiet", "--bare", seed, origin)
	hub := filepath.Join(root, "hub")
	gitIn(t, root, "clone", "--quiet", origin, hub)
	sandbox := filepath.Join(root, "sandbox")
	gitIn(t, root, "clone", "--quiet", origin, sandbox)

	return &writeBackScene{
		origin: origin, hub: hub, sandbox: sandbox,
		base: gitIn(t, hub, "rev-parse", "HEAD"),
	}
}

// produceBundle runs the real sandbox-side producer against the sandbox tree,
// so what Apply is handed is a bundle the shipping code actually makes.
func (s *writeBackScene) produceBundle(t *testing.T) (gitwriteback.Result, []byte) {
	t.Helper()
	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir: s.sandbox,
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit,
			Repo: "https://example.invalid/acme/widgets.git",
			Ref:  "main",
		},
		WriteBack: executor.WriteBack{
			Mode:    executor.WriteBackBundle,
			Branch:  writeBackTestBranch,
			Message: "cloop(task-20180): work from an isolated executor",
		},
		BaseSHA: s.base,
		Host:    "this sandbox",
	})
	if err != nil {
		t.Fatalf("gitwriteback.Produce: %v", err)
	}
	if res.BundlePath == "" {
		return res, nil
	}
	t.Cleanup(func() { _ = os.Remove(res.BundlePath) })
	raw, err := os.ReadFile(res.BundlePath)
	if err != nil {
		t.Fatalf("read the produced bundle: %v", err)
	}
	return res, raw
}

// plantGitDirectoryHook builds, in the sandbox, a commit whose tree holds
// .git/hooks/post-checkout, points branch at it, and returns its SHA.
//
// gitwriteback.Produce cannot be used for this one: it goes through `git add`,
// which refuses the path outright. That is not a gap in the producer — it is the
// reason the hub cannot rely on the producer. The objects are built with
// mktree/commit-tree, which is what a sandbox running model-authored code would
// do, and the result is verified with ls-tree before it is used.
func (s *writeBackScene) plantGitDirectoryHook(t *testing.T, branch string) string {
	t.Helper()

	blob := gitInput(t, s.sandbox, "#!/bin/sh\ntouch /tmp/cloop-pwned\n", "hash-object", "-w", "--stdin")
	hooks := gitInput(t, s.sandbox, "100755 blob "+blob+"\tpost-checkout\n", "mktree")
	dotGit := gitInput(t, s.sandbox, "040000 tree "+hooks+"\thooks\n", "mktree")

	baseTree := gitIn(t, s.sandbox, "rev-parse", s.base+"^{tree}")
	root := gitInput(t, s.sandbox,
		gitIn(t, s.sandbox, "ls-tree", baseTree)+"\n040000 tree "+dotGit+"\t.git\n", "mktree")

	commit := gitInput(t, s.sandbox, "a hook, delivered as if it were content",
		"commit-tree", root, "-p", s.base)
	gitIn(t, s.sandbox, "update-ref", "refs/heads/"+branch, commit)

	// Verify the attack was actually constructed. If a future git refuses to
	// build this tree, this fails loudly here rather than turning the test into
	// a check that a benign commit is accepted.
	listing := gitIn(t, s.sandbox, "ls-tree", "-r", "--name-only", commit)
	if !strings.Contains(listing, ".git/hooks/post-checkout") {
		t.Fatalf("could not construct a tree containing .git/hooks/post-checkout; "+
			"git built this instead:\n%s", listing)
	}
	return commit
}

// bundleRange packs base..branch the same way the producer does, for the cases
// where the producer cannot be used to build the commit.
func (s *writeBackScene) bundleRange(t *testing.T, branch string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "writeback.bundle")
	gitIn(t, s.sandbox, "bundle", "create", path, s.base+"..refs/heads/"+branch)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the bundle: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("the bundle is empty; nothing would be inspected")
	}
	return raw
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return gitInput(t, dir, "", args...)
}

// gitInput runs one git command with a closed configuration, so nothing in
// whoever-owns-this-machine's ~/.gitconfig can decide what these tests observe.
func gitInput(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeInto(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
