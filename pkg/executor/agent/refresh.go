package agent

// refresh.go is the device side of replacing a credential file a running
// workload holds (Task 20375, protocol v17).
//
// The hub re-mints a GitHub App installation token before GitHub's hour ends
// and sends the new token file. Like a revoke, the frame is authenticated by
// the session it arrives on; unlike one, it writes rather than removes, so its
// confinement is stricter still: it may only *replace* a file this device was
// given for that very lease at start, inside the lease directory this agent
// created. It cannot create a file, name a directory, or reach a lease another
// workload holds — a compromised hub gains nothing it could not already do by
// dispatching a workload with whatever files it liked.
//
// The write is a rename inside the lease directory, so a workload reading the
// file sees the old token or the new one and never half of each, and in
// container mode — where that directory is bind-mounted into the sandbox whole
// — the sandbox sees the new file at once.
//
// "A file this device was given" means one this agent placed itself, for a
// workload that holds the lease (vault.own) — not merely a path the start
// frame's bindings named, which a compromised hub could point at another
// workload's lease directory.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// handleSecretRefresh honours a secret_refresh frame and acks with what it
// rewrote. The ack is sent on every path, for the reason handleRevoke's is.
func (a *Agent) handleSecretRefresh(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic handling secret refresh: %v", r)
			a.reply(ctx, sess, remote.TypeSecretRefreshed, frame.ID, "", remote.SecretRefreshedPayload{
				Error: "the agent panicked while rewriting this lease's files; the workload keeps the files it had",
			})
		}
	}()

	payload, err := remote.DecodeSecretRefresh(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	req := payload.Request()
	// Scrubbed before it is written: a terminal open on a workload holding the
	// lease must not show the new token the moment the file has it.
	values := req.Values()
	for _, id := range a.vault.handlesFor(req.LeaseID) {
		if wl, ok := a.workload(id); ok {
			wl.addRedactions(values...)
		}
	}
	report := a.vault.refresh(req.LeaseID, req.Files)
	ack := remote.SecretRefreshedPayload{
		LeaseID:        req.LeaseID,
		Known:          report.Known,
		FilesRewritten: report.rewritten,
		Handles:        report.handles,
	}
	if len(report.errors) > 0 {
		ack.Error = strings.Join(report.errors, "; ")
	}
	switch {
	case !report.Known:
		a.cfg.logf("secret refresh %s: not held by this agent (nothing to rewrite)", req.LeaseID)
	default:
		a.cfg.logf("secret refresh %s: rewrote %d file(s)%s%s", req.LeaseID, report.rewritten,
			reasonSuffix(req.Reason), errorSuffix(ack.Error))
	}
	a.reply(ctx, sess, remote.TypeSecretRefreshed, frame.ID, "", ack)
}

// refreshReport is what a vault refresh achieved.
type refreshReport struct {
	Known     bool
	rewritten int
	handles   []string
	errors    []string
}

// refresh rewrites, in place, the files this device holds for leaseID that
// files carry new content for.
//
// Each file is matched by name against the files the lease delivered here —
// the hub names the directory it declared, and this agent relocated that onto
// a directory of its own at start, so the declared one means nothing on this
// machine. A name the lease did not deliver, or delivered more than once, is
// refused rather than guessed. A lease already scrubbed has nothing to
// refresh: its credential was taken back, and a refresh must not put one back.
func (v *vault) refresh(leaseID string, files []executor.SecretFile) refreshReport {
	id := strings.TrimSpace(leaseID)
	v.mu.Lock()
	defer v.mu.Unlock()

	held, ok := v.leases[id]
	if !ok {
		return refreshReport{}
	}
	report := refreshReport{Known: true}
	for h := range held.handles {
		report.handles = append(report.handles, h)
	}
	sort.Strings(report.handles)
	if held.allScrubbed() {
		report.errors = append(report.errors, fmt.Sprintf(
			"lease %s was already taken back on this device, so there is nothing to refresh", id))
		return report
	}
	// Only the files of grants not taken back: a grant revoked on its own
	// (Task 20403) must not have its credential put back by a refresh of the
	// lease that carried it.
	live := held.liveFiles()
	for _, f := range files {
		var matches []string
		for _, p := range live {
			if filepath.Base(p) == f.Name {
				matches = append(matches, p)
			}
		}
		if len(matches) != 1 {
			report.errors = append(report.errors, fmt.Sprintf(
				"%s was not delivered to this device for lease %s, so it is not refreshed", f.Name, id))
			continue
		}
		// Only a file this agent placed itself, for a workload holding this
		// lease. A binding path is the hub's word, and a hub's word is not
		// enough to make this device overwrite a file.
		target := matches[0]
		if !v.ownsLocked(held, target) {
			report.errors = append(report.errors, fmt.Sprintf(
				"%s was not placed by this agent for lease %s, so it is not refreshed", f.Name, id))
			continue
		}
		// ReplaceSecretFile holds the rest of the confinement: the parent must
		// be a lease directory and the file a regular file already there. The
		// replacement keeps the owner of the file it replaces, so a sandbox
		// that could read the first token — a container running as the user
		// the agent wrote it as — reads the second.
		if err := executor.ReplaceSecretFile(target, f.Content, executor.ReplaceOptions{
			Mode: f.FileMode(), Owner: ownerOf(target),
		}); err != nil {
			report.errors = append(report.errors, err.Error())
			continue
		}
		report.rewritten++
	}
	return report
}

// ownerOf returns the owner a replacement of the file at path should be given:
// the file's own, or nil when that is this process — the production case, since
// the agent wrote the file — or cannot be read.
func ownerOf(path string) *executor.FileOwner {
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, gid := int(st.Uid), int(st.Gid)
	if uid == os.Geteuid() && gid == os.Getegid() {
		return nil
	}
	return &executor.FileOwner{UID: uid, GID: gid}
}

// errorSuffix renders an error for a log line, or nothing.
func errorSuffix(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return ""
	}
	return " (" + msg + ")"
}
