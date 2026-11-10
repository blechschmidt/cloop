package gitprovision

// pristine.go: a checkout kept on an executor pool runner's persistent volume
// (Task 20484), and the git object cache beside it.
//
// A runner whose controller keeps a volume per project finds the project's
// checkout from its last run and fetches instead of cloning. That checkout is
// unlike one a permanent device keeps: it is nobody's only copy of anything —
// a runner's run returns its work to the hub before it ends, and the hub is
// the source of truth — and it was last written by a run, whose code a model
// wrote. So it is trusted for its objects, which git verifies by their names,
// and for nothing else:
//
//   - its own configuration is rewritten, before git reads it for anything,
//     to what a checkout cloop provisioned, and a harness committed in,
//     carries (reusedConfigKept). Anything else — a url.insteadOf, a proxy,
//     http.sslVerify, a filter, an include, a hooks path — is a setting the
//     next fetch would obey with the next run's credential in its
//     environment, and is dropped. One that names its origin other than
//     exactly once, or that a replace ref or a grafts file would redirect,
//     is discarded and cloned afresh; every git command it runs has hooks
//     and the file-system monitor turned off;
//   - before the reset, every object the fetched commit needs is checked
//     present and intact;
//   - after the fetch it is reset to exactly the commit fetched: tracked files
//     restored, untracked ones removed, ignored ones — node_modules, target/,
//     the build caches that make a kept workspace worth keeping — left;
//   - then checked: HEAD is the fetched commit and no tracked file differs
//     from it. A checkout that fails the check is discarded and cloned afresh.
//
// The git object cache is a bare repository per upstream, beside the trees on
// the same volume. A fresh checkout takes the objects it already has with a
// local fetch before its authenticated one, which then sends only what is new;
// each provisioning refreshes it. Best effort throughout: a cache that cannot
// be read or written costs a full fetch and a line in the log, never the run.
// It is vetted like a checkout before it is used, for the same reason.

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git's own object names, checked as git computes them
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// reusedConfigKept are the configuration keys a kept checkout keeps when its
// configuration is rewritten, as git lists them: section and variable
// lowercased, a subsection as written. git's own defaults on Linux, the
// origin, the upstream cloop records, a commit identity, and the branches a
// harness made. Everything else — a hooks path husky set, an LFS filter, a
// proxy, an insteadOf — is dropped rather than obeyed: a setting the last run
// wrote is not one the next run's fetch, holding its credential, should follow.
var reusedConfigKept = []*regexp.Regexp{
	regexp.MustCompile(`^core\.(repositoryformatversion|filemode|bare|logallrefupdates)$`),
	regexp.MustCompile(`^remote\.origin\.url$`),
	regexp.MustCompile(`^extensions\.objectformat$`),
	regexp.MustCompile(`^cloop\.upstream$`),
	regexp.MustCompile(`^user\.(name|email)$`),
	regexp.MustCompile(`^branch\.[^\x00\n]+\.(remote|merge)$`),
}

// cacheConfigAllowed is what a git object cache's configuration may carry:
// what `git init --bare` writes, and nothing else.
var cacheConfigAllowed = []*regexp.Regexp{
	regexp.MustCompile(`^core\.(repositoryformatversion|filemode|bare)$`),
	regexp.MustCompile(`^extensions\.objectformat$`),
}

// maxReusedConfigEntries bounds a kept checkout's configuration: a real one
// carries a dozen keys.
const maxReusedConfigEntries = 512

// defaultFetchRefspec is the only fetch refspec a checkout cloop provisioned
// carries.
const defaultFetchRefspec = "+refs/heads/*:refs/remotes/origin/*"

// configRecord is one key of a configuration file, as git lists it.
type configRecord struct{ name, value string }

// readConfigFile lists a configuration file's keys and values, includes not
// followed, or says why it cannot be read.
func readConfigFile(ctx context.Context, path string) ([]configRecord, string) {
	cmd := exec.CommandContext(ctx, "git", "config", "--file", path, "--no-includes", "--null", "--list")
	cmd.Env = executor.GitEnv(noRepoPrograms...)
	cmd.Dir = filepath.Dir(path)
	BoundChild(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Sprintf("its configuration cannot be read: %v: %s", err, Collapse(stderr.String()))
	}
	raw := strings.Split(strings.TrimRight(stdout.String(), "\x00"), "\x00")
	if len(raw) > maxReusedConfigEntries {
		return nil, fmt.Sprintf("its configuration holds %d keys", len(raw))
	}
	var out []configRecord
	for _, rec := range raw {
		if rec == "" {
			continue
		}
		name, value, _ := strings.Cut(rec, "\n")
		out = append(out, configRecord{name: name, value: value})
	}
	return out, ""
}

func matchesAny(res []*regexp.Regexp, name string) bool {
	for _, re := range res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// vetCacheConfig returns why a git object cache's configuration may not be
// trusted, "" when it may: only what `git init --bare` writes, each once.
func vetCacheConfig(ctx context.Context, gitDir string) string {
	recs, why := readConfigFile(ctx, filepath.Join(gitDir, "config"))
	if why != "" {
		return why
	}
	seen := map[string]bool{}
	for _, r := range recs {
		switch {
		case !matchesAny(cacheConfigAllowed, r.name):
			return fmt.Sprintf("its configuration sets %s, which a cache does not carry", quoteName(r.name))
		case seen[r.name]:
			return fmt.Sprintf("its configuration sets %s more than once", quoteName(r.name))
		}
		seen[r.name] = true
	}
	return ""
}

// sanitizeReusedConfig rewrites a kept checkout's configuration to the keys
// reusedConfigKept names, each once, with the default fetch refspec, and
// returns what it dropped. why says the checkout is to be discarded instead:
// its configuration cannot be read, or names its origin other than exactly
// once — git fetches from the first url and reports the last, and which one
// was meant cannot be told.
func sanitizeReusedConfig(ctx context.Context, gitDir string) (dropped []string, why string) {
	path := filepath.Join(gitDir, "config")
	recs, why := readConfigFile(ctx, path)
	if why != "" {
		return nil, why
	}
	urls := 0
	for _, r := range recs {
		if r.name == "remote.origin.url" {
			urls++
		}
	}
	if urls != 1 {
		return nil, fmt.Sprintf("its configuration names its origin %d times", urls)
	}
	var kept []configRecord
	seen, droppedSeen := map[string]bool{}, map[string]bool{}
	fetchOK := false
	for _, r := range recs {
		switch {
		case r.name == "remote.origin.fetch":
			if r.value == defaultFetchRefspec && !fetchOK {
				fetchOK = true
				continue
			}
			fetchOK = false
			if !droppedSeen[r.name] {
				droppedSeen[r.name] = true
				dropped = append(dropped, r.name)
			}
		case matchesAny(reusedConfigKept, r.name) && !seen[r.name]:
			seen[r.name] = true
			kept = append(kept, r)
		default:
			if !droppedSeen[r.name] {
				droppedSeen[r.name] = true
				dropped = append(dropped, r.name)
			}
		}
	}
	if len(dropped) == 0 && fetchOK {
		return nil, ""
	}
	tmp := path + ".cloop-sanitized"
	_ = os.Remove(tmp)
	write := func(name, value string) error {
		cmd := exec.CommandContext(ctx, "git", "config", "--file", tmp, "--add", name, value)
		cmd.Env = executor.GitEnv(noRepoPrograms...)
		cmd.Dir = gitDir
		BoundChild(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, Collapse(string(out)))
		}
		return nil
	}
	for _, r := range kept {
		if err := write(r.name, r.value); err != nil {
			_ = os.Remove(tmp)
			return nil, fmt.Sprintf("its configuration could not be rewritten: %v", err)
		}
	}
	if err := write("remote.origin.fetch", defaultFetchRefspec); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Sprintf("its configuration could not be rewritten: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Sprintf("its configuration could not be rewritten: %v", err)
	}
	return dropped, ""
}

// vetReusedRepository returns why the kept repository in dir may not be
// trusted, "" when it may: .git must be a directory of its own, with nothing
// that points git at another repository or replaces its objects, and a
// configuration that sanitizeReusedConfig can rewrite. What it dropped from
// that configuration is emitted.
func vetReusedRepository(ctx context.Context, dir string, emit func(string)) string {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitDir)
	if err != nil {
		return fmt.Sprintf("its .git cannot be read: %v", err)
	}
	if !info.IsDir() {
		return ".git is not a directory"
	}
	for _, rel := range append(redirectFiles, "config.worktree", filepath.Join("info", "grafts")) {
		if _, err := os.Lstat(filepath.Join(gitDir, rel)); err == nil {
			return fmt.Sprintf(".git/%s points git elsewhere, or replaces what it reads", rel)
		}
	}
	if fi, err := os.Lstat(filepath.Join(gitDir, "config")); err != nil || !fi.Mode().IsRegular() {
		return ".git/config is not a regular file"
	}
	// Replacement objects make git read one object for another: the commit
	// fetched would not be the tree checked out.
	if fi, err := os.Lstat(filepath.Join(gitDir, "refs", "replace")); err == nil && fi.IsDir() {
		if entries, _ := os.ReadDir(filepath.Join(gitDir, "refs", "replace")); len(entries) > 0 {
			return "it carries replacement refs"
		}
	}
	if b, err := os.ReadFile(filepath.Join(gitDir, "packed-refs")); err == nil && strings.Contains(string(b), " refs/replace/") {
		return "it carries replacement refs"
	}
	dropped, why := sanitizeReusedConfig(ctx, gitDir)
	if why != "" {
		return why
	}
	if len(dropped) > 0 {
		names := dropped
		if len(names) > 8 {
			names = append(names[:8:8], fmt.Sprintf("and %d more", len(dropped)-8))
		}
		emit(fmt.Sprintf("workspace: the kept checkout's configuration set what no checkout needs; dropped %s\n",
			strings.Join(names, ", ")))
	}
	return ""
}

func quoteName(s string) string {
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return fmt.Sprintf("%q", s)
}

// discardTree empties dir, which must already be confined by the caller.
// RemoveAll removes a link it meets, never what the link points at; a
// directory a run made unwritable is made writable again first.
func discardTree(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(p); err != nil {
			_ = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
				if err == nil && d.IsDir() {
					_ = os.Chmod(q, 0o700)
				}
				return nil
			})
			if err := os.RemoveAll(p); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// pristineEnv is the environment of every git command the reset runs in a
// kept checkout: local, no program of the repository's, and no replacement
// objects.
func pristineEnv(dir string) []string {
	return append(localGitEnv(dir), "GIT_NO_REPLACE_OBJECTS=1")
}

// pristineReset makes a kept checkout exactly the commit just fetched, and
// checks that it is. Run with the configuration vetted, and in pristineEnv,
// so no step of it can run a program the checkout names.
//
//   - What the last run left in .git that would outlive the reset goes: its
//     hooks, which the next run's own git would run, and the exclude and
//     attributes files, with which it could hide files from the clean below.
//   - Every object the fetched commit's checkout is made of is checked
//     against its name (verifyCheckoutObjects): a kept object store is the
//     last run's, and an object planted under the name of one the fetch then
//     does not download would be checked out as if fetched.
//   - The index goes before the checkout, so every tracked file is written
//     from those objects rather than kept because its timestamps say it is
//     unchanged.
func pristineReset(ctx context.Context, dir string) error {
	gitDir := filepath.Join(dir, ".git")
	for _, rel := range []string{"hooks", filepath.Join("info", "exclude"), filepath.Join("info", "attributes"),
		"index", "index.lock", "rebase-merge", "rebase-apply", "sequencer", "MERGE_HEAD", "MERGE_MSG",
		"CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG", "BISECT_START", "BISECT_TERMS"} {
		if err := os.RemoveAll(filepath.Join(gitDir, rel)); err != nil {
			return fmt.Errorf("remove .git/%s: %v", rel, err)
		}
	}
	env := pristineEnv(dir)
	fetched, err := gitIn(ctx, dir, env, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return err
	}
	if err := verifyCheckoutObjects(ctx, dir, env, strings.TrimSpace(fetched)); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"checkout", "--quiet", "--force", "--detach", "FETCH_HEAD"},
		{"clean", "-ffdq"},
	} {
		if _, err := gitIn(ctx, dir, env, args...); err != nil {
			return err
		}
	}
	head, err := gitIn(ctx, dir, env, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	if strings.TrimSpace(head) != strings.TrimSpace(fetched) {
		return fmt.Errorf("HEAD is %s after the reset, not the fetched %s", strings.TrimSpace(head), strings.TrimSpace(fetched))
	}
	status, err := gitIn(ctx, dir, env, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all")
	if err != nil {
		return err
	}
	if s := strings.TrimSpace(status); s != "" {
		return fmt.Errorf("tracked files still differ from the fetched commit: %s", Collapse(s))
	}
	return nil
}

// verifyCheckoutObjects checks every object the checkout of commit is made
// of against its name: the commit itself, hashed here, and its tree and every
// blob, which `git rev-list --verify-objects` hashes as it reads them. A kept
// object store is the last run's, and an object planted under the name of one
// the fetch therefore did not download would otherwise be checked out as if
// fetched. Only the checkout's objects: the rest of history is not what the
// harness starts on, and checking it would cost a full fsck every run.
func verifyCheckoutObjects(ctx context.Context, dir string, env []string, commit string) error {
	format, err := gitIn(ctx, dir, env, "rev-parse", "--show-object-format")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "cat-file", "commit", commit)
	cmd.Env = env
	cmd.Dir = dir
	BoundChild(cmd)
	var content, stderr bytes.Buffer
	cmd.Stdout = &content
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("read commit %s: %v: %s", commit, err, Collapse(stderr.String()))
	}
	header := fmt.Sprintf("commit %d\x00", content.Len())
	var sum string
	switch strings.TrimSpace(format) {
	case "sha256":
		h := sha256.New()
		h.Write([]byte(header))
		h.Write(content.Bytes())
		sum = hex.EncodeToString(h.Sum(nil))
	default:
		h := sha1.New()
		h.Write([]byte(header))
		h.Write(content.Bytes())
		sum = hex.EncodeToString(h.Sum(nil))
	}
	if sum != commit {
		return fmt.Errorf("the object stored as commit %s is not that commit", commit)
	}
	verify := exec.CommandContext(ctx, "git", "-C", dir, "rev-list", "--objects", "--verify-objects", "--no-walk", commit)
	verify.Env = env
	verify.Dir = dir
	verify.Stdout = io.Discard
	stderr.Reset()
	verify.Stderr = &stderr
	BoundChild(verify)
	if err := verify.Run(); err != nil {
		return fmt.Errorf("the objects of commit %s do not match their names: %v: %s", commit, err, Collapse(stderr.String()))
	}
	return nil
}

// gitIn runs git in dir with env and returns its standard output.
func gitIn(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = env
	cmd.Dir = dir
	BoundChild(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, Collapse(stderr.String()))
	}
	return stdout.String(), nil
}

// ── the object cache ───────────────────────────────────────────────────────

// cacheRefPrefix is where a fresh checkout keeps the cache's branches while it
// fetches: refs, so the authenticated fetch offers them as what it has.
const cacheRefPrefix = "refs/cloop-cache/"

// cacheRepo is the cache's bare repository for w's upstream.
func cacheRepo(cacheDir string, w executor.Workspace) string {
	sum := sha256.Sum256([]byte(strings.TrimSuffix(strings.TrimRight(w.UpstreamRepo(), "/"), ".git")))
	return filepath.Join(cacheDir, hex.EncodeToString(sum[:12])+".git")
}

// usableCache returns the cache repository for w when one exists and may be
// trusted; one that may not is removed.
func usableCache(ctx context.Context, cacheDir string, w executor.Workspace, emit func(string)) string {
	repo := cacheRepo(cacheDir, w)
	info, err := os.Lstat(repo)
	if err != nil || !info.IsDir() {
		if err == nil {
			_ = os.Remove(repo)
		}
		return ""
	}
	if why := vetCacheRepo(ctx, repo); why != "" {
		emit(fmt.Sprintf("workspace: the git object cache %s cannot be trusted (%s); removing it\n", repo, why))
		_ = discardTree(repo)
		_ = os.Remove(repo)
		return ""
	}
	return repo
}

// vetCacheRepo returns why a cache repository may not be trusted, "" when it
// may: a bare repository of cloop's, nothing pointing git elsewhere or
// replacing objects, and a configuration only `git init --bare` makes.
func vetCacheRepo(ctx context.Context, repo string) string {
	for _, rel := range append(redirectFiles, "config.worktree", filepath.Join("info", "grafts")) {
		if _, err := os.Lstat(filepath.Join(repo, rel)); err == nil {
			return rel + " points git elsewhere, or replaces what it reads"
		}
	}
	if fi, err := os.Lstat(filepath.Join(repo, "config")); err != nil || !fi.Mode().IsRegular() {
		return "its config is not a regular file"
	}
	if fi, err := os.Lstat(filepath.Join(repo, "refs", "replace")); err == nil && fi.IsDir() {
		if entries, _ := os.ReadDir(filepath.Join(repo, "refs", "replace")); len(entries) > 0 {
			return "it carries replacement refs"
		}
	}
	return vetCacheConfig(ctx, repo)
}

// seedFromCache copies the objects the cache holds for w into the fresh
// checkout in dir, under refs the fetch then offers as what it has.
func seedFromCache(ctx context.Context, dir, repo string, emit func(string)) bool {
	_, err := gitIn(ctx, dir, localGitEnv(dir), "fetch", "--quiet", "--no-tags", "--", repo,
		"+refs/heads/*:"+cacheRefPrefix+"*")
	if err != nil {
		emit(fmt.Sprintf("workspace: could not take objects from the git object cache: %v\n", err))
		return false
	}
	emit("workspace: took what the git object cache holds; fetching only what is new\n")
	return true
}

// dropCacheRefs removes the refs seedFromCache made, leaving the objects.
func dropCacheRefs(ctx context.Context, dir string) {
	env := localGitEnv(dir)
	out, err := gitIn(ctx, dir, env, "for-each-ref", "--format=%(refname)", cacheRefPrefix)
	if err != nil {
		return
	}
	var stdin strings.Builder
	for _, ref := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(ref, cacheRefPrefix) {
			stdin.WriteString("delete " + ref + "\n")
		}
	}
	if stdin.Len() == 0 {
		return
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "update-ref", "--stdin")
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin.String())
	BoundChild(cmd)
	_ = cmd.Run()
}

// refreshCache brings what the checkout in dir now holds into the cache, under
// a branch named for the ref it fetched.
func refreshCache(ctx context.Context, dir, cacheDir string, w executor.Workspace, emit func(string)) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		emit(fmt.Sprintf("workspace: could not create the git object cache: %v\n", err))
		return
	}
	repo := cacheRepo(cacheDir, w)
	if _, err := os.Lstat(repo); err == nil {
		// Written to by git below: it has to be trustworthy first, like any
		// repository a run could have reached.
		if usableCache(ctx, cacheDir, w, emit) == "" {
			if _, err := os.Lstat(repo); err == nil {
				return
			}
		}
	}
	if _, err := os.Lstat(repo); errors.Is(err, fs.ErrNotExist) {
		if _, err := gitIn(ctx, cacheDir, executor.GitEnv(noRepoPrograms...), "init", "--quiet", "--bare", "--", repo); err != nil {
			emit(fmt.Sprintf("workspace: could not create the git object cache: %v\n", err))
			return
		}
	}
	branch := "default"
	if ref := strings.TrimSpace(w.Ref); ref != "" {
		sum := sha256.Sum256([]byte(ref))
		branch = "ref-" + hex.EncodeToString(sum[:8])
	}
	// gc off in the cache: a checkout borrows nothing from it, but a cache
	// that collected while a fetch read it would hand that fetch a half pack.
	env := executor.GitEnv(append([][2]string{{"gc.auto", "0"}, {"maintenance.auto", "false"}}, noRepoPrograms...)...)
	if _, err := gitIn(ctx, repo, env, "fetch", "--quiet", "--no-tags", "--", dir,
		"+HEAD:refs/heads/"+branch); err != nil {
		emit(fmt.Sprintf("workspace: could not refresh the git object cache: %v\n", err))
	}
}
