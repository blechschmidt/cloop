package movecapture

// confine.go keeps a capture inside the working copies it was asked for.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// Bounds on what the checks read.
const (
	// maxGitEntries bounds the walk of a repository's .git directory: a
	// repository of loose objects is large, and one built to make the walk
	// itself the attack is refused past this.
	maxGitEntries = 2_000_000
	// maxGitFileBytes bounds a linked worktree's .git file and a commondir.
	maxGitFileBytes = 4096
	// configTimeout bounds reading one configuration file.
	configTimeout = 30 * time.Second
	// maxConfigOutput bounds what git prints of one configuration file.
	maxConfigOutput = 4 << 20
)

// openRoot opens the trees root.
func openRoot(dir string) (*os.Root, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("movecapture: open the trees root: %w", err)
	}
	return r, nil
}

// openTree opens the working copy name under the trees root: a directory, not
// a link, and the directory the root then holds is the one that was checked.
// A working copy that does not exist answers os.ErrNotExist.
func openTree(trees *os.Root, rootPath, name string) (*tree, error) {
	li, err := trees.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("movecapture: %w", err)
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory (a link is not followed)", ErrConfinement, name)
	}
	sub, err := trees.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("movecapture: open %s: %w", name, err)
	}
	si, err := sub.Stat(".")
	if err != nil || !os.SameFile(li, si) {
		_ = sub.Close()
		return nil, fmt.Errorf("%w: %s changed while it was opened", ErrConfinement, name)
	}
	return &tree{name: name, path: filepath.Join(rootPath, name), root: sub}, nil
}

// checkRepository refuses a working copy whose repository could lead git
// outside it. A working copy with no .git has nothing to check.
func checkRepository(ctx context.Context, t *tree) error {
	li, err := t.root.Lstat(".git")
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("movecapture: %w", err)
	case li.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%w: %s/.git is a symbolic link", ErrConfinement, t.name)
	case !li.IsDir():
		// A gitfile names a repository anywhere on the device.
		return fmt.Errorf("%w: %s/.git is a file, which names a repository elsewhere", ErrConfinement, t.name)
	}
	n := 0
	walkErr := fs.WalkDir(t.root.FS(), ".git", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n++
		if n > maxGitEntries {
			return fmt.Errorf("%w: %s/.git holds more than %d entries", ErrConfinement, t.name, maxGitEntries)
		}
		typ := d.Type()
		switch {
		case typ&fs.ModeSymlink != 0:
			return fmt.Errorf("%w: %s/%s is a symbolic link", ErrConfinement, t.name, p)
		case d.IsDir(), typ.IsRegular():
			return nil
		default:
			return fmt.Errorf("%w: %s/%s is neither a file nor a directory", ErrConfinement, t.name, p)
		}
	})
	if walkErr != nil {
		if errors.Is(walkErr, ErrConfinement) {
			return walkErr
		}
		return fmt.Errorf("movecapture: read %s/.git: %w", t.name, walkErr)
	}
	// Another repository's objects, or another repository's everything.
	for _, f := range []string{".git/objects/info/alternates", ".git/objects/info/http-alternates", ".git/commondir"} {
		if _, err := t.root.Lstat(f); err == nil {
			return fmt.Errorf("%w: %s/%s points git at another repository", ErrConfinement, t.name, f)
		}
	}
	type configFile struct {
		rel  string
		main bool
	}
	configs := []configFile{{".git/config", true}, {".git/config.worktree", false}}
	linked, err := fs.ReadDir(t.root.FS(), ".git/worktrees")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("movecapture: read %s/.git/worktrees: %w", t.name, err)
	}
	for _, e := range linked {
		base := ".git/worktrees/" + e.Name()
		if !e.IsDir() {
			return fmt.Errorf("%w: %s/%s is not a worktree's record", ErrConfinement, t.name, base)
		}
		// A record without commondir is a repository of its own to git —
		// its own configuration, objects and refs, none of which is the
		// project's — and one naming another is another repository's.
		raw, err := readSmall(t.root, base+"/commondir")
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%w: %s/%s has no commondir, so git would read it as a repository of its own", ErrConfinement, t.name, base)
		case err != nil:
			return err
		case strings.TrimSpace(string(raw)) != "../..":
			return fmt.Errorf("%w: %s/%s/commondir names another repository", ErrConfinement, t.name, base)
		}
		for _, own := range []string{"config", "objects"} {
			if _, err := t.root.Lstat(base + "/" + own); err == nil {
				return fmt.Errorf("%w: %s/%s holds %s, which only a repository has", ErrConfinement, t.name, base, own)
			}
		}
		configs = append(configs, configFile{base + "/config.worktree", false})
	}
	for _, c := range configs {
		if _, err := t.root.Lstat(c.rel); err != nil {
			continue
		}
		if err := checkConfig(ctx, filepath.Join(t.path, filepath.FromSlash(c.rel)), t.name+"/"+c.rel, c.main); err != nil {
			return err
		}
	}
	// Anything else git reads to resolve a name — a submodule's repository
	// under .git/modules, which a gitlink's HEAD is read from — names no
	// other repository either.
	return fs.WalkDir(t.root.FS(), ".git", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch path.Base(p) {
		case "alternates", "http-alternates":
			if strings.HasSuffix(path.Dir(p), "objects/info") {
				return fmt.Errorf("%w: %s/%s points git at another repository", ErrConfinement, t.name, p)
			}
		case "commondir":
			if !strings.HasPrefix(p, ".git/worktrees/") || strings.Count(p, "/") != 3 {
				return fmt.Errorf("%w: %s/%s points git at another repository", ErrConfinement, t.name, p)
			}
		}
		return nil
	})
}

// readSmall reads a small file through root, refusing a large one.
func readSmall(root *os.Root, name string) ([]byte, error) {
	li, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() || li.Size() > maxGitFileBytes {
		return nil, fmt.Errorf("%w: %s is not a small regular file", ErrConfinement, name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%w: %s changed while it was read", ErrConfinement, name)
	}
	buf := make([]byte, maxGitFileBytes+1)
	n, _ := f.Read(buf)
	return buf[:n], nil
}

// checkConfig refuses a repository configuration holding any key outside
// configAllowed — read the way git reads it, by git, with includes left
// unread. A working copy's configuration is the workload's to write, and git
// obeys it: a worktree moved elsewhere, a file included from anywhere, a
// filter or a transport's command run as the agent, a fetch redirected to
// another project's repository. A key nothing here needs is not one to let
// through on the chance it is harmless. main says the file is the
// repository's own configuration, whose filter drivers the hardened
// configuration neutralises; a worktree's may define none.
func checkConfig(ctx context.Context, file, name string, main bool) error {
	cctx, cancel := context.WithTimeout(ctx, configTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "config", "--file", file, "--no-includes", "--list", "-z")
	cmd.Env = append(executor.GitEnv(executor.HardenedGitConfig(nil)...), "LC_ALL=C")
	cmd.Dir = filepath.Dir(file)
	gitprovision.BoundChild(cmd)
	var out, stderr limitedBuffer
	out.max, stderr.max = maxConfigOutput, 64<<10
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: git cannot read %s: %v %s", ErrConfinement, name, err, strings.TrimSpace(stderr.buf.String()))
	}
	if out.cut {
		return fmt.Errorf("%w: %s is larger than a repository's configuration is", ErrConfinement, name)
	}
	for _, entry := range bytes.Split(out.buf.Bytes(), []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		key, value, _ := bytes.Cut(entry, []byte{'\n'})
		k := string(key)
		if !configAllowed(k, main) {
			return fmt.Errorf("%w: %s sets %s, which a capture does not let through; remove it from the working copy's configuration on the device", ErrConfinement, name, k)
		}
		if strings.EqualFold(k, "core.bare") && strings.EqualFold(strings.TrimSpace(string(value)), "true") {
			return fmt.Errorf("%w: %s says the repository is bare", ErrConfinement, name)
		}
	}
	return nil
}

// configKeys are the keys a working copy's configuration may hold, by
// section, with no subsection: what git init writes, what cloop provisions,
// and settings a harness plausibly makes that change nothing a capture does.
var configKeys = map[string]map[string]bool{
	"core": set("repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase", "precomposeunicode",
		"symlinks", "autocrlf", "safecrlf", "eol", "checkstat", "trustctime", "quotepath", "sparsecheckout",
		"sparsecheckoutcone", "untrackedcache", "splitindex", "commitgraph", "multipackindex", "compression",
		"loosecompression", "bigfilethreshold", "abbrev", "longpaths", "preloadindex", "fscache", "editor", "pager",
		"warnambiguousrefs", "hookspath", "fsmonitor"),
	"extensions":  set("objectformat", "worktreeconfig", "refstorage"),
	"user":        set("name", "email", "useconfigonly", "signingkey"),
	"author":      set("name", "email"),
	"committer":   set("name", "email"),
	"init":        set("defaultbranch"),
	"commit":      set("gpgsign", "verbose", "cleanup", "status"),
	"tag":         set("gpgsign", "sort", "forcesignannotated"),
	"gc":          set("auto", "autodetach", "autopacklimit", "pruneexpire", "reflogexpire", "reflogexpireunreachable", "writecommitgraph"),
	"maintenance": set("auto", "strategy"),
	"submodule":   set("recurse", "active"),
	"diff":        set("renames", "algorithm", "colormoved", "mnemonicprefix", "ignoresubmodules", "submodule", "statgraphwidth"),
	"merge":       set("conflictstyle", "ff", "log", "renames"),
}

// configSubsectionKeys are the keys allowed with a subsection, by section:
// a remote's address and refspecs (never its upload-pack, proxy or promisor),
// a branch's upstream, a submodule's address, the git proxy's CA for its URL.
var configSubsectionKeys = map[string]map[string]bool{
	"remote":    set("url", "pushurl", "fetch", "push", "tagopt", "prune", "prunetags", "mirror", "skipdefaultupdate", "skipfetchall"),
	"branch":    set("remote", "merge", "rebase", "pushremote", "description"),
	"submodule": set("url", "active", "branch", "path", "ignore", "shallow"),
	"http":      set("sslcainfo", "sslverify", "extraheader"),
}

// configSections are sections whose every key, with or without a
// subsection, is allowed: cloop's own, settings for porcelain a capture never
// runs, and transport settings, which a capture — running git with no
// transport at all — never reaches.
var configSections = set("cloop", "advice", "color", "status", "log", "format", "help", "pull", "push", "rebase",
	"index", "pack", "fetch", "lfs", "feature", "credential")

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// configAllowed reports whether key, as git lists it — section and variable
// lowercased, a subsection as written — may stand in a working copy's
// configuration. main allows the filter drivers the hardened configuration
// neutralises.
func configAllowed(key string, main bool) bool {
	first := strings.Index(key, ".")
	last := strings.LastIndex(key, ".")
	if first <= 0 || last == len(key)-1 {
		return false
	}
	section, variable := strings.ToLower(key[:first]), strings.ToLower(key[last+1:])
	if configSections[section] {
		return true
	}
	if first == last {
		return configKeys[section][variable]
	}
	if section == "filter" {
		return main && (variable == "clean" || variable == "smudge" || variable == "process" || variable == "required")
	}
	return configSubsectionKeys[section][variable]
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
	cut bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.cut = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.cut = true
	}
	return len(p), nil
}

// confiner is movegit's and gitstate's Confine for working copies under the
// trees root: a directory git is about to work in must lie under the root,
// reached through no link, and be a repository (an external tree, checked
// before it is named) or a linked worktree whose .git file names a directory
// under its own working copy's .git/worktrees.
func confiner(trees *os.Root, rootPath string) func(dir string) error {
	rootPath = filepath.Clean(rootPath)
	return func(dir string) error {
		rel, err := filepath.Rel(rootPath, filepath.Clean(dir))
		if err != nil || !relativeClean(filepath.ToSlash(rel)) {
			return fmt.Errorf("%w: %s is outside the trees root", ErrConfinement, dir)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		cur := ""
		for _, part := range parts {
			cur = path.Join(cur, part)
			fi, err := trees.Lstat(cur)
			if err != nil {
				return fmt.Errorf("movecapture: %w", err)
			}
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				return fmt.Errorf("%w: %s is not a directory (a link is not followed)", ErrConfinement, cur)
			}
		}
		gi, err := trees.Lstat(cur + "/.git")
		switch {
		case err != nil:
			return fmt.Errorf("%w: %s has no .git, so git would answer for the repository above it", ErrConfinement, cur)
		case gi.IsDir() && len(parts) == 1:
			// A working copy of its own: checked by checkRepository before
			// it is named.
			return nil
		case !gi.Mode().IsRegular():
			return fmt.Errorf("%w: %s/.git is neither a gitfile nor a repository git may read", ErrConfinement, cur)
		}
		raw, err := readSmall(trees, cur+"/.git")
		if err != nil {
			return err
		}
		line := strings.TrimSpace(string(raw))
		target, ok := strings.CutPrefix(line, "gitdir:")
		if !ok || strings.ContainsAny(line, "\n\r") {
			return fmt.Errorf("%w: %s/.git is not a gitfile", ErrConfinement, cur)
		}
		target = strings.TrimSpace(target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(rootPath, filepath.FromSlash(cur), target)
		}
		target = filepath.Clean(target)
		owner := filepath.Join(rootPath, parts[0], ".git", "worktrees")
		trel, err := filepath.Rel(owner, target)
		if err != nil || !relativeClean(filepath.ToSlash(trel)) || strings.Contains(filepath.ToSlash(trel), "/") {
			return fmt.Errorf("%w: %s/.git names %s, outside %s's own .git/worktrees", ErrConfinement, cur, target, parts[0])
		}
		if fi, err := trees.Lstat(parts[0] + "/.git/worktrees/" + trel); err != nil || !fi.IsDir() {
			return fmt.Errorf("%w: %s/.git names a worktree record that is not there", ErrConfinement, cur)
		}
		return nil
	}
}

// maxTreeEntries bounds the walk of a working copy for nested repositories.
const maxTreeEntries = 2_000_000

// checkNested refuses a working copy holding, anywhere beneath its top, a .git
// that is a link, a gitfile naming anything but a directory under the working
// copy's own .git (a submodule's or a worktree's), or a repository that would
// lead git elsewhere: a snapshot records a nested repository as a gitlink, and
// git reads the HEAD it points at to do it.
func checkNested(ctx context.Context, t *tree) error {
	n := 0
	return fs.WalkDir(t.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("movecapture: walk %s: %w", t.name, err)
		}
		if p == "." {
			return nil
		}
		if p == ".git" {
			return fs.SkipDir // checkRepository's
		}
		if n++; n > maxTreeEntries {
			return fmt.Errorf("%w: %s holds more than %d entries", ErrConfinement, t.name, maxTreeEntries)
		}
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if d.Name() != ".git" {
			return nil
		}
		typ := d.Type()
		switch {
		case typ&fs.ModeSymlink != 0:
			return fmt.Errorf("%w: %s/%s is a symbolic link", ErrConfinement, t.name, p)
		case d.IsDir():
			parent := path.Dir(p)
			sub, err := t.root.OpenRoot(parent)
			if err != nil {
				return fmt.Errorf("movecapture: open %s/%s: %w", t.name, parent, err)
			}
			defer sub.Close()
			nested := &tree{name: t.name + "/" + parent, path: filepath.Join(t.path, filepath.FromSlash(parent)), root: sub}
			if err := checkRepository(ctx, nested); err != nil {
				return err
			}
			return fs.SkipDir
		case typ.IsRegular():
			raw, err := readSmall(t.root, p)
			if err != nil {
				return err
			}
			line := strings.TrimSpace(string(raw))
			target, ok := strings.CutPrefix(line, "gitdir:")
			if !ok || strings.ContainsAny(line, "\n\r") {
				return fmt.Errorf("%w: %s/%s is not a gitfile", ErrConfinement, t.name, p)
			}
			target = strings.TrimSpace(target)
			if !filepath.IsAbs(target) {
				target = filepath.Join(t.path, filepath.FromSlash(path.Dir(p)), target)
			}
			rel, err := filepath.Rel(filepath.Join(t.path, ".git"), filepath.Clean(target))
			if err != nil || !relativeClean(filepath.ToSlash(rel)) {
				return fmt.Errorf("%w: %s/%s names %s, outside the working copy's own .git", ErrConfinement, t.name, p, target)
			}
			if fi, err := t.root.Lstat(".git/" + filepath.ToSlash(rel)); err != nil || !fi.IsDir() {
				return fmt.Errorf("%w: %s/%s names a repository that is not there", ErrConfinement, t.name, p)
			}
			return nil
		default:
			return fmt.Errorf("%w: %s/%s is neither a file nor a directory", ErrConfinement, t.name, p)
		}
	})
}

// ownerOf is the user git runs as in t: its owner, when the agent runs as root
// and the owner is not — the workload's own account, so what git writes in its
// repository stays the workload's and what git could read is no more than the
// workload could. Nil runs git as the agent.
func ownerOf(t *tree) (*syscall.Credential, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	fi, err := t.root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("movecapture: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return nil, nil
	}
	// No supplementary groups: root's would come along otherwise.
	return &syscall.Credential{Uid: st.Uid, Gid: st.Gid}, nil
}

// hasRepository reports whether t holds a .git of its own.
func hasRepository(t *tree) bool {
	_, err := t.root.Lstat(".git")
	return err == nil
}
