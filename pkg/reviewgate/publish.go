package reviewgate

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// pushTimeout bounds one replayed push.
const pushTimeout = 3 * time.Minute

// maxUnreviewedScan bounds how many commits a replay inspects when checking
// that it would publish nothing the reviewer did not see.
const maxUnreviewedScan = 5000

// publishMu serialises replays across tasks: parallel tasks in one working
// tree push the same branches, and two pushes updating one remote-tracking
// ref at once fail on its lock.
var publishMu sync.Mutex

// Dedupe returns held pushes with only the latest attempt per repository,
// remote and destination ref, in the order they were first made. An agent
// that pushed, fixed a finding and pushed again meant the second.
func Dedupe(pushes []HeldPush) []HeldPush {
	type key struct{ repo, remote, dst string }
	idx := map[key]int{}
	var out []HeldPush
	for _, p := range pushes {
		k := key{absClean(p.Repo), p.Remote, p.Dst}
		if i, ok := idx[k]; ok {
			out[i] = p
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	return out
}

// Withhold records held pushes as not sent, with why.
func Withhold(root string, pushes []HeldPush, why string) []pm.ReviewPublish {
	var out []pm.ReviewPublish
	for _, p := range Dedupe(pushes) {
		out = append(out, record(root, p, "", pm.PublishWithheld, why))
	}
	return out
}

// Publish replays the pushes a review approved.
//
// Each push is sent at the commit the review saw — its source ref as it stands
// now, which is where the agent's fixes are, provided that is still the
// reviewed HEAD or behind it — and only if every commit it would deliver lies
// in the reviewed range. A push that fails that check is refused, not sent: an
// approval covers what the reviewer read, and nothing else.
func Publish(ctx context.Context, reviewed *Changes, pushes []HeldPush) []pm.ReviewPublish {
	publishMu.Lock()
	defer publishMu.Unlock()
	root := ""
	if reviewed != nil {
		root = reviewed.Root
	}
	var out []pm.ReviewPublish
	for _, p := range Dedupe(pushes) {
		out = append(out, publishOne(ctx, root, reviewed.Repo(p.Repo), p))
	}
	return out
}

func publishOne(ctx context.Context, root string, rc *RepoChanges, p HeldPush) pm.ReviewPublish {
	refuse := func(sha, why string) pm.ReviewPublish { return record(root, p, sha, pm.PublishRefused, why) }
	if rc == nil {
		return refuse("", "the push came from a repository the review did not cover")
	}
	if !strings.HasPrefix(p.Dst, "refs/") || strings.HasPrefix(p.Remote, "-") {
		return refuse("", "the destination is not a ref git can be asked to push")
	}

	var refspec string
	var sha string
	if p.Delete() {
		refspec = ":" + p.Dst
	} else {
		obj := p.SrcSHA
		if p.SrcRef != "" {
			obj = p.SrcRef
		}
		if obj == "" {
			return refuse("", "the pushed source could not be resolved when it was held")
		}
		sha = revParse(ctx, rc.Dir, obj+"^{commit}")
		if sha == "" {
			return refuse("", "the pushed source "+obj+" no longer exists")
		}
		if rc.Head == "" || !isAncestor(ctx, rc.Dir, sha, rc.Head) {
			return refuse(sha, "the branch moved after the review; its new commits were not reviewed")
		}
		if n, first := unreviewedCommits(ctx, rc, p.Remote, sha); n > 0 {
			return refuse(sha, fmt.Sprintf("it would also publish %d commit(s) the reviewer did not see, starting with %s", n, first))
		}
		// Tags go by name, so an annotated tag's own object is what arrives;
		// everything else goes at the checked commit, not at wherever the
		// branch has moved since.
		src := sha
		if strings.HasPrefix(p.SrcRef, "refs/tags/") {
			src = p.SrcRef
		}
		refspec = src + ":" + p.Dst
	}

	args := []string{"push", "--porcelain"}
	if p.Force {
		if p.Expect != "" {
			// A forced push is leased against what the agent saw, so a
			// replay cannot clobber work that reached the remote while the
			// review ran.
			args = append(args, "--force-with-lease="+p.Dst+":"+p.Expect)
		} else {
			args = append(args, "--force")
		}
	}
	args = append(args, p.Remote, refspec)

	pctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	cmd := exec.CommandContext(pctx, "git", append([]string{"-C", rc.Dir}, args...)...)
	cmd.Env = gitEnv([]string{"GIT_TERMINAL_PROMPT=0"})
	out, err := cmd.CombinedOutput()
	if err != nil {
		return record(root, p, sha, pm.PublishFailed, lastLines(redactURLs(string(out)), 3))
	}
	return record(root, p, sha, pm.PublishPushed, "")
}

// unreviewedCommits counts the commits pushing sha to remote would deliver
// that lie outside the reviewed range, and names the oldest.
func unreviewedCommits(ctx context.Context, rc *RepoChanges, remote, sha string) (int, string) {
	notOnRemote := []string{"rev-list", "-n", fmt.Sprint(maxUnreviewedScan), sha}
	if validRemoteName(remote) {
		notOnRemote = append(notOnRemote, "--not", "--remotes="+remote)
	} else {
		notOnRemote = append(notOnRemote, "--not", "--remotes")
	}
	out, err := gitOut(ctx, rc.Dir, notOnRemote...)
	if err != nil {
		return 1, "(the commits it would send could not be listed)"
	}
	pending := strings.Fields(out)
	if len(pending) == 0 || rc.Base == "" {
		// Nothing to send, or the review covered the whole history.
		return 0, ""
	}
	if len(pending) >= maxUnreviewedScan {
		// More than can be checked. A partial check would approve by default
		// whatever lies past the limit, which is the one thing this refuses to do.
		return len(pending), "more unpublished commits than the gate checks (" + fmt.Sprint(maxUnreviewedScan) + ")"
	}
	reviewedOut, err := gitOut(ctx, rc.Dir, "rev-list", rc.Base+".."+rc.Head)
	if err != nil {
		return len(pending), short(pending[len(pending)-1])
	}
	reviewed := map[string]bool{}
	for _, c := range strings.Fields(reviewedOut) {
		reviewed[c] = true
	}
	n, oldest := 0, ""
	for _, c := range pending {
		if !reviewed[c] {
			n++
			oldest = c // rev-list lists newest first
		}
	}
	return n, short(oldest)
}

func isAncestor(ctx context.Context, dir, a, b string) bool {
	if a == b {
		return true
	}
	_, err := gitOut(ctx, dir, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

func record(root string, p HeldPush, sha, outcome, detail string) pm.ReviewPublish {
	ref := p.Dst
	if p.Delete() {
		ref = "delete " + p.Dst
	}
	return pm.ReviewPublish{
		Repo:    relTo(root, absClean(p.Repo)),
		Remote:  redactURLs(p.Remote),
		Ref:     ref,
		Commit:  sha,
		Outcome: outcome,
		Detail:  detail,
	}
}

// userinfoRe matches credentials embedded in a URL.
var userinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// redactURLs removes credentials from URLs in s. git echoes remote URLs in its
// errors, and a remote configured with a token in it would otherwise land in
// the task record.
func redactURLs(s string) string {
	return userinfoRe.ReplaceAllString(s, "${1}***@")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return clip(strings.Join(lines, " / "), 400)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
