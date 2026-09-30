package reviewgate

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// HelperTransport is the git transport name held pushes are rewritten to.
// git runs "git-remote-" + HelperTransport for a URL of the form
// "cloopgate::<url>".
const HelperTransport = "cloopgate"

// HelperSubcommand is the hidden cloop subcommand that serves the transport.
const HelperSubcommand = "review-gate-remote-helper"

// HoldFileEnv names the file the helper records held pushes in. It is set in
// the agent's environment only; the helper refuses to run without it.
const HoldFileEnv = "CLOOP_REVIEW_GATE_HOLD"

// heldReason is what git shows the agent for a held push, in parentheses after
// "[remote rejected]". It says what happened and what to do about it.
const heldReason = "held by cloop's review gate: cloop pushes it after the reviewer approves this task; do not retry"

// Bounds on the hold file, which the agent can also write to.
const (
	maxHeldPushes    = 64
	maxHoldFileBytes = 256 << 10
	maxHeldFieldLen  = 1024
)

// rewritePrefixes are the URL prefixes rewritten to the helper. The empty
// prefix matches every URL; the rest are the same rewrite spelled for the
// common schemes, so a git that ignored an empty pushInsteadOf value would
// still hold everything but an unusual remote. The longest match wins and all
// of them produce "cloopgate::<the original URL>".
var rewritePrefixes = []string{"", "https://", "http://", "ssh://", "git://", "file://", "/", "git@"}

// HeldPush is one ref update the agent pushed while the gate held it.
type HeldPush struct {
	// Repo is the top-level directory of the repository pushed from.
	Repo string `json:"repo"`
	// Remote is the remote name git was given, or the URL when the push
	// named one directly. URL is where git would have pushed.
	Remote string `json:"remote"`
	URL    string `json:"url,omitempty"`
	// Src is the source as git passed it ("HEAD", "refs/heads/main"); empty
	// for a deletion. SrcRef is the ref it named when held ("" when it named
	// a commit), SrcSHA the object it resolved to then.
	Src    string `json:"src,omitempty"`
	SrcRef string `json:"src_ref,omitempty"`
	SrcSHA string `json:"src_sha,omitempty"`
	// Dst is the ref on the remote ("refs/heads/main").
	Dst string `json:"dst"`
	// Force reports a forced update; Expect is the value git was shown for
	// Dst, which a replay leases against.
	Force  bool   `json:"force,omitempty"`
	Expect string `json:"expect,omitempty"`
	// At is when git asked.
	At time.Time `json:"at"`
}

// Delete reports whether the push deletes Dst.
func (h HeldPush) Delete() bool { return h.Src == "" }

// Hold holds the pushes of one task's agent. Create it before the agent runs,
// hand Env to the agent's process, and Close it when the task is decided.
type Hold struct {
	dir  string
	file string
}

// NewHold prepares a hold whose helper runs helperArgv (the cloop binary and
// HelperSubcommand) with git's arguments appended.
func NewHold(helperArgv []string) (*Hold, error) {
	if len(helperArgv) == 0 || !filepath.IsAbs(helperArgv[0]) {
		return nil, errors.New("reviewgate: the push helper needs an absolute program path")
	}
	dir, err := os.MkdirTemp("", "cloop-review-gate-")
	if err != nil {
		return nil, fmt.Errorf("reviewgate: hold directory: %w", err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("reviewgate: hold directory: %w", err)
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\n# cloop review gate: hold this push until the task's changes are approved.\nexec")
	for _, a := range helperArgv {
		script.WriteString(" ")
		script.WriteString(shellQuote(a))
	}
	script.WriteString(" \"$@\"\n")
	helper := filepath.Join(bin, "git-remote-"+HelperTransport)
	if err := os.WriteFile(helper, []byte(script.String()), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("reviewgate: push helper: %w", err)
	}
	return &Hold{dir: dir, file: filepath.Join(dir, "held.jsonl")}, nil
}

// Env returns the variables that make the agent's pushes land in this hold.
// They go on top of the agent's inherited environment: the git configuration
// entries are numbered after any the environment already carries, because
// GIT_CONFIG_COUNT is one variable for the whole environment and a sandbox's
// workspace delivery uses it too.
func (h *Hold) Env() []string {
	if h == nil {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("GIT_CONFIG_COUNT")))
	if err != nil || n < 0 {
		n = 0
	}
	env := []string{
		"PATH=" + filepath.Join(h.dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		HoldFileEnv + "=" + h.file,
		"GIT_CONFIG_COUNT=" + strconv.Itoa(n+len(rewritePrefixes)),
	}
	for i, prefix := range rewritePrefixes {
		idx := strconv.Itoa(n + i)
		env = append(env,
			"GIT_CONFIG_KEY_"+idx+"=url."+HelperTransport+"::"+prefix+".pushInsteadOf",
			"GIT_CONFIG_VALUE_"+idx+"="+prefix)
	}
	return env
}

// Pushes returns what the hold recorded, oldest first, bounded and with
// malformed lines skipped: the file is in reach of the agent.
func (h *Hold) Pushes() []HeldPush {
	if h == nil {
		return nil
	}
	return ReadHeld(h.file)
}

// Close removes the hold's files. The agent's environment still names them,
// so a push after Close fails rather than going out unreviewed.
func (h *Hold) Close() {
	if h != nil && h.dir != "" {
		_ = os.RemoveAll(h.dir)
	}
}

// ReadHeld parses a hold file.
func ReadHeld(path string) []HeldPush {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []HeldPush
	sc := bufio.NewScanner(io.LimitReader(f, maxHoldFileBytes))
	sc.Buffer(make([]byte, 0, 8192), 16<<10)
	for sc.Scan() && len(out) < maxHeldPushes {
		var p HeldPush
		if json.Unmarshal(sc.Bytes(), &p) != nil || p.Dst == "" || p.Repo == "" || p.Remote == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ServeRemoteHelper answers git's remote-helper protocol for a push made
// under the review gate. args are git's (the remote name and URL). It
// advertises the remote-tracking refs as the remote's state, so git's own
// fast-forward and lease checks still run against what the agent last
// fetched; records each ref update git then asks for in the hold file; and
// refuses every one of them with heldReason.
//
// It holds rather than pushes by construction: nothing here can reach a
// remote, so a helper run outside a hold — HoldFileEnv unset — has nowhere to
// record to and refuses outright.
func ServeRemoteHelper(ctx context.Context, args []string, holdFile string, in io.Reader, out io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: git-remote-" + HelperTransport + " <remote> [<url>]")
	}
	remote := clip(args[0], maxHeldFieldLen)
	url := ""
	if len(args) > 1 {
		url = clip(args[1], maxHeldFieldLen)
	}
	repo := ""
	if top, err := gitOut(ctx, ".", "rev-parse", "--show-toplevel"); err == nil {
		repo = absClean(strings.TrimSpace(top))
	}

	br := bufio.NewReader(io.LimitReader(in, 1<<20))
	bw := bufio.NewWriter(out)
	defer bw.Flush()
	advertised := map[string]string{}
	var batch []string
	for {
		line, err := br.ReadString('\n')
		if err != nil && line == "" {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "capabilities":
			bw.WriteString("push\n\n")
		case line == "list" || strings.HasPrefix(line, "list "):
			for ref, sha := range trackedRemoteRefs(ctx, repo, remote) {
				advertised[ref] = sha
				fmt.Fprintf(bw, "%s %s\n", sha, ref)
			}
			bw.WriteString("\n")
		case strings.HasPrefix(line, "push "):
			batch = append(batch, strings.TrimPrefix(line, "push "))
			continue // the batch ends with a blank line
		case line == "":
			if len(batch) == 0 {
				return nil // the end of git's command stream
			}
			for _, spec := range batch {
				p := parseRefspec(spec)
				p.Repo, p.Remote, p.URL, p.At = repo, remote, url, time.Now().UTC()
				p.Expect = advertised[p.Dst]
				// git hands over a parsed refspec, so a source beginning
				// with "-" cannot occur; it is refused rather than passed to
				// rev-parse, which would read it as an option.
				if p.Src != "" && repo != "" && !strings.HasPrefix(p.Src, "-") {
					if ref, err := gitOut(ctx, repo, "rev-parse", "--verify", "-q", "--symbolic-full-name", p.Src); err == nil {
						if ref = strings.TrimSpace(ref); strings.HasPrefix(ref, "refs/") {
							p.SrcRef = clip(ref, maxHeldFieldLen)
						}
					}
					p.SrcSHA = revParse(ctx, repo, p.Src)
				}
				reason := heldReason
				switch {
				case repo == "":
					// A bare repository, or one git could not place: nothing
					// here could be reviewed, so it cannot be held for later.
					reason = "cloop's review gate holds pushes from a working tree only, so this one was not sent"
				default:
					if err := appendHeld(holdFile, p); err != nil {
						reason = "cloop's review gate could not record this push, so it was not sent: " + err.Error()
					}
				}
				fmt.Fprintf(bw, "error %s %s\n", p.Dst, oneLine(reason))
			}
			bw.WriteString("\n")
			batch = nil
		default:
			// Nothing else was advertised, so git has no reason to ask; an
			// unknown command ends the session rather than guessing.
			return fmt.Errorf("git-remote-%s: unsupported command %q", HelperTransport, clip(line, 80))
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}
}

// parseRefspec splits git's "[+]<src>:<dst>".
func parseRefspec(spec string) HeldPush {
	var p HeldPush
	if strings.HasPrefix(spec, "+") {
		p.Force = true
		spec = spec[1:]
	}
	src, dst, ok := strings.Cut(spec, ":")
	if !ok {
		src, dst = spec, spec
	}
	p.Src, p.Dst = clip(src, maxHeldFieldLen), clip(dst, maxHeldFieldLen)
	return p
}

// trackedRemoteRefs returns the remote's branches as this repository last
// fetched them, keyed by their name on the remote.
func trackedRemoteRefs(ctx context.Context, repo, remote string) map[string]string {
	refs := map[string]string{}
	if repo == "" || !validRemoteName(remote) {
		return refs
	}
	prefix := "refs/remotes/" + remote + "/"
	out, err := gitOut(ctx, repo, "for-each-ref", "--format=%(objectname) %(refname)", prefix)
	if err != nil {
		return refs
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		sha, ref, ok := strings.Cut(line, " ")
		if !ok || !strings.HasPrefix(ref, prefix) || strings.HasSuffix(ref, "/HEAD") {
			continue
		}
		refs["refs/heads/"+strings.TrimPrefix(ref, prefix)] = sha
	}
	return refs
}

// appendHeld adds one record to the hold file. Each record is a single write
// below PIPE_BUF with O_APPEND, so concurrent helpers — two repositories
// pushed at once — cannot interleave.
func appendHeld(path string, p HeldPush) error {
	if path == "" {
		return errors.New("no review gate is holding pushes here (" + HoldFileEnv + " is unset)")
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxHoldFileBytes {
		return errors.New("too many pushes are already held")
	}
	line, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(line) > 4000 {
		return errors.New("the push is too large to hold")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// oneLine flattens s for a single protocol line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
