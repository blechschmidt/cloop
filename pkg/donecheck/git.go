package donecheck

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// gitBaseArgs keep the repository's own configuration from running anything
// while it is read — no filesystem monitor, no signature verification, no
// pager — and keep paths unquoted.
var gitBaseArgs = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.quotepath=off",
	"-c", "log.showSignature=false",
	"--no-pager",
}

// gitEnv is the environment git runs in: the process's own, without the
// variables that would point it at another repository, and with optional
// locks off so that reading the status never rewrites the index behind the
// agent's back.
func gitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
			"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
			"GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0")
}

// runGit runs git in dir and returns at most limit bytes of its standard
// output, reporting whether there was more. A process that passes the limit is
// stopped rather than left to write output nobody will read.
func runGit(parent context.Context, dir string, limit int, args ...string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(parent, gitTimeout)
	defer cancel()
	argv := append(append(append([]string{}, gitBaseArgs...), "-C", dir), args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	cmd.Env = gitEnv()
	cmd.Stdin = nil
	// A child git (a submodule's status) that outlives its parent must not
	// hold Wait open on an inherited pipe.
	cmd.WaitDelay = 5 * time.Second
	var stderr limitedBuffer
	stderr.max = 4096
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("git %s: %w", args[0], err)
	}
	data, rerr := io.ReadAll(io.LimitReader(stdout, int64(limit)+1))
	if len(data) > limit {
		cancel()
		_ = cmd.Wait()
		return data[:limit], true, nil
	}
	werr := cmd.Wait()
	if rerr != nil {
		return nil, false, fmt.Errorf("git %s: %w", args[0], rerr)
	}
	if werr != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, false, fmt.Errorf("git %s: %w: %s", args[0], werr, msg)
		}
		return nil, false, fmt.Errorf("git %s: %w", args[0], werr)
	}
	return data, false, nil
}

// gitLine runs git and returns its output's first line, trimmed.
func gitLine(ctx context.Context, dir string, args ...string) (string, error) {
	out, _, err := runGit(ctx, dir, 64<<10, args...)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line), nil
}

// revParse resolves rev — HEAD or @{upstream}, never anything from the
// repository — to a commit name, or "" when it names none.
func revParse(ctx context.Context, dir, rev string) string {
	out, err := gitLine(ctx, dir, "rev-parse", "--verify", "-q", rev+"^{commit}")
	if err != nil || !isCommitName(out) {
		return ""
	}
	return out
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }

// entry is one path `git status` reports.
type entry struct {
	// path is relative to the repository's top level, as git prints it; an
	// untracked directory (a nested repository) keeps its trailing slash.
	path string
	// code is the two-letter status `git status --short` would print.
	code string
	// state is everything git says about the entry besides its working-tree
	// content: the status letters, modes, index object names, a rename's
	// source. It is half of the fingerprint.
	state string
	// dir marks an entry that is a directory: a submodule, or an untracked
	// nested repository.
	dir bool
}

// listDirty lists every path under dir that `git status` reports — modified,
// staged, deleted, conflicted or untracked — except those under dir's own
// .cloop/, which is cloop's bookkeeping (and holds the task worktrees and
// feature worktrees, which are separate checkouts). It reports whether the
// listing was cut at maxStatusBytes.
func listDirty(ctx context.Context, dir string) ([]entry, bool, error) {
	out, cut, err := runGit(ctx, dir, maxStatusBytes,
		"status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=none",
		"--", ".", ":(exclude).cloop")
	if err != nil {
		return nil, false, fmt.Errorf("donecheck: %s: %w", dir, err)
	}
	if cut {
		// Drop the record the limit cut through.
		if i := bytes.LastIndexByte(out, 0); i >= 0 {
			out = out[:i+1]
		} else {
			out = nil
		}
	}
	return parseStatus(out), cut, nil
}

// parseStatus reads `git status --porcelain=v2 -z`. Records it does not know
// are skipped rather than failing the check: a newer git may add some.
func parseStatus(out []byte) []entry {
	var es []entry
	fields := bytes.Split(out, []byte{0})
	for i := 0; i < len(fields); i++ {
		rec := string(fields[i])
		if rec == "" {
			continue
		}
		switch rec[0] {
		case '1':
			// 1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>
			f := strings.SplitN(rec, " ", 9)
			if len(f) != 9 || len(f[1]) != 2 {
				continue
			}
			es = append(es, entry{path: f[8], code: shortCode(f[1]),
				state: strings.Join([]string{"1", f[1], f[2], f[4], f[5], f[7]}, " "),
				dir:   strings.HasPrefix(f[2], "S")})
		case '2':
			// 2 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <X><score> <path>, then
			// the source path as the next field.
			f := strings.SplitN(rec, " ", 10)
			if len(f) != 10 || len(f[1]) != 2 {
				continue
			}
			orig := ""
			if i+1 < len(fields) {
				i++
				orig = string(fields[i])
			}
			es = append(es, entry{path: f[9], code: shortCode(f[1]),
				state: strings.Join([]string{"2", f[1], f[2], f[4], f[5], f[7], f[8], orig}, " "),
				dir:   strings.HasPrefix(f[2], "S")})
		case 'u':
			// u <XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path>
			f := strings.SplitN(rec, " ", 11)
			if len(f) != 11 || len(f[1]) != 2 {
				continue
			}
			es = append(es, entry{path: f[10], code: f[1],
				state: strings.Join(append([]string{"u"}, f[1:10]...), " "),
				dir:   strings.HasPrefix(f[2], "S")})
		case '?':
			if len(rec) < 3 {
				continue
			}
			p := rec[2:]
			es = append(es, entry{path: p, code: "??", state: "?", dir: strings.HasSuffix(p, "/")})
		}
	}
	return es
}

// shortCode turns porcelain v2's "XY" ('.' for unmodified) into the short
// format's (' ').
func shortCode(xy string) string {
	return strings.ReplaceAll(xy, ".", " ")
}
