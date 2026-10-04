package ui

// secrets_refresh.go keeps a GitHub App token the sandbox holds as a file
// working past GitHub's hour (Task 20375).
//
// Without the git proxy, a github_app grant reaches the workload as a token in
// its lease directory, which the lease's credential helper reads with `cat` on
// every git call. GitHub stops honouring that token an hour after dispatch, so
// a run still using git after that failed — though its lease was kept alive.
// Rewriting the file is enough to fix that, and this is what rewrites it: on
// every keepalive tick the lease asks its broker whether a token is near its
// end, has the broker re-mint it at its original scope, and hands the new file
// to every executor holding the lease (executor.SecretRefresher) — the host
// driver rewrites the hub's own tmpfs copy, the container driver its staged
// directory, Kubernetes the run's Secret, and a device's agent its own lease
// directory over the v17 secret_refresh frame.
//
// Under the git proxy none of this runs: the token never left the hub, and the
// session presenting it upstream renews it on its own request path
// (pkg/gitproxy/refresh.go).
//
// # Where it cannot reach
//
// The hub asks before it mints. When a holder cannot take a new file — a device
// whose agent speaks a protocol older than v17, or one that is offline — no
// token is minted for it, the dispatch is left alone, and the project's journal
// says once that the run's GitHub access ends when the token it holds expires,
// with the upgrade that would change that. A delivery that fails is retried on
// the next tick while the old token still works. A refresh the broker or GitHub
// refuses ends the grant's access as a revocation does — the broker destroys
// the tokens — and the journal says why.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leaseRefreshTimeout bounds one tick's refresh: a mint at GitHub and a round
// trip to each holder.
const leaseRefreshTimeout = 90 * time.Second

// refreshGiveUpAfter is how many ticks running a delivery may fail the same way
// before the holder is treated as unable to take one: no further token is
// minted for it, and the journal says so once.
const refreshGiveUpAfter = 3

// refreshFailure is one executor's repeating delivery failure.
type refreshFailure struct {
	err   string
	count int
}

// refreshAppTokens runs the file refresh for one keepalive tick. It reports
// whether the lease has App tokens the keepalive should keep watching.
func (sl *secretLease) refreshAppTokens(ctx context.Context, now time.Time) bool {
	if sl == nil || sl.lease == nil || sl.broker == nil {
		return false
	}
	leaseID := sl.lease.ID
	if !sl.broker.HoldsFileAppTokens(leaseID) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, leaseRefreshTimeout)
	defer cancel()

	// Superseded tokens whose replacement has been in the workload's hands for
	// the grace period are destroyed at GitHub first, refresh or no refresh.
	sl.broker.RetireSuperseded(ctx, leaseID)
	if !sl.broker.AppTokensDue(leaseID) {
		return true
	}
	sl.mu.Lock()
	alive := sl.alive
	sl.mu.Unlock()
	if alive != nil && !alive(ctx) {
		return false
	}

	// Ask where the file would go before a token is minted for it: a token
	// nothing here can deliver — no holder on this hub, or one that cannot
	// take a new file — would be a live credential minted for no one.
	targets := leaseRefreshTargets(leaseID)
	sl.mu.Lock()
	for id, why := range sl.refreshCannot {
		targets.cannot[id] = why
	}
	sl.mu.Unlock()
	if len(targets.cannot) > 0 {
		sl.noteUndeliverable(targets.cannot)
		return true
	}
	if targets.holders == 0 || targets.offline > 0 {
		// Nothing to deliver to, or a device that is away right now: ask
		// again next tick. A token that lapses meanwhile is replaced when the
		// device is back, since the mint does not need the old one.
		return true
	}

	fr, err := sl.broker.RefreshLeaseFiles(ctx, sl.lease)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: refresh github app tokens of lease %s: %v\n", leaseID, err)
		return true
	}
	if fr == nil {
		return true
	}
	defer fr.Close()

	for _, refused := range fr.Refused {
		sl.journal(fmt.Sprintf("GitHub access through grant %s (%s) ended: its GitHub App token could not be "+
			"renewed, and was destroyed at GitHub — %s", refused.GrantID, refused.SecretName, refused.Reason),
			map[string]any{"lease_id": leaseID, "grant_id": refused.GrantID, "refused": true})
	}
	if len(fr.Files) == 0 {
		return true
	}

	req := executor.SecretRefreshRequest{
		LeaseID: leaseID,
		Reason:  "a GitHub App installation token was re-minted before GitHub's hour ran out",
	}
	dir := sl.leaseDir()
	for _, f := range fr.Files {
		req.Files = append(req.Files, executor.SecretFile{
			LeaseID: leaseID,
			GrantID: f.GrantID,
			Dir:     dir,
			Name:    f.Name,
			Mode:    f.Mode,
			Content: f.Content,
		})
	}

	results := refreshLeaseOnHolders(ctx, req)
	if len(results) == 0 {
		// Nothing holds the lease any more: the workload finished between the
		// liveness check and here. The new token is destroyed with the lease.
		return true
	}
	delivered, eventual := true, false
	grants := grantList(fr.Files)
	for _, res := range results {
		if res.report.Delivered() {
			sl.mu.Lock()
			delete(sl.refreshFailed, res.executorID)
			sl.mu.Unlock()
			sl.auditRefresh(res.executorID, grants, fileNames(fr.Files), res.report, fr.Summary)
			eventual = eventual || res.report.Eventual
			continue
		}
		delivered = false
		if res.report.Unsupported {
			sl.giveUp(res.executorID, res.report.Error)
			continue
		}
		// Retried each tick while the old token lasts — but a failure that
		// repeats is audited once, and one that keeps repeating is treated
		// as the executor being unable to take a refresh at all.
		first, count := sl.noteFailure(res.executorID, res.report.Error)
		if first {
			sl.auditRefresh(res.executorID, grants, fileNames(fr.Files), res.report, fr.Summary)
			fmt.Fprintf(os.Stderr, "ui: refreshed github app token for lease %s did not reach %s "+
				"(retried while the old token lasts): %s\n", leaseID, res.executorID, res.report.Error)
		}
		if count >= refreshGiveUpAfter {
			sl.giveUp(res.executorID, res.report.Error)
		}
	}
	if delivered {
		fr.Delivered(eventual)
	}
	return true
}

// noteFailure records one failed delivery to executorID and reports whether it
// is a new failure — not the one the last tick already reported — and how many
// ticks running it has now repeated.
func (sl *secretLease) noteFailure(executorID, errText string) (first bool, count int) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.refreshFailed == nil {
		sl.refreshFailed = map[string]refreshFailure{}
	}
	prev := sl.refreshFailed[executorID]
	if prev.err != errText {
		prev = refreshFailure{err: errText}
	}
	prev.count++
	sl.refreshFailed[executorID] = prev
	return prev.count == 1, prev.count
}

// giveUp stops minting tokens for an executor that cannot take one, and says
// so once on the journal.
func (sl *secretLease) giveUp(executorID, why string) {
	sl.mu.Lock()
	if sl.refreshCannot == nil {
		sl.refreshCannot = map[string]string{}
	}
	sl.refreshCannot[executorID] = why
	sl.mu.Unlock()
	sl.noteUndeliverable(map[string]string{executorID: why})
}

// leaseDir is where the lease's files are, as the workload sees them.
func (sl *secretLease) leaseDir() string {
	if sl.mount != nil {
		return sl.mount.Dir
	}
	if sl.delivery != nil {
		return sl.delivery.Dir
	}
	return secretbroker.SandboxLeaseDir(sl.lease.ID)
}

// holderRefresh is one executor's answer to a refresh.
type holderRefresh struct {
	executorID string
	report     executor.SecretRefreshReport
}

// refreshLeaseOnHolders hands req to every executor holding the lease: the
// devices through the agent hub, and every hub-local driver that holds it.
func refreshLeaseOnHolders(ctx context.Context, req executor.SecretRefreshRequest) []holderRefresh {
	var out []holderRefresh
	if hub := activeRemoteHub(); hub != nil {
		for _, res := range hub.RefreshLease(ctx, req) {
			out = append(out, holderRefresh{executorID: res.ExecutorID, report: res.Report})
		}
	}
	for _, ex := range executor.List() {
		if _, isRemote := ex.(*remote.Executor); isRemote {
			continue
		}
		rv, ok := executor.AsRevoker(ex)
		if !ok || !rv.HoldsLease(req.LeaseID) {
			continue
		}
		sr, ok := executor.AsSecretRefresher(ex)
		if !ok {
			out = append(out, holderRefresh{executorID: ex.ID(), report: executor.SecretRefreshReport{
				LeaseID: req.LeaseID, Known: true, Unsupported: true,
				Error: fmt.Sprintf("the %s driver cannot replace a credential file in a running workload", ex.Kind()),
			}})
			continue
		}
		rep := sr.RefreshSecretFiles(ctx, req)
		if !rep.Known && rep.Error == "" {
			continue
		}
		out = append(out, holderRefresh{executorID: ex.ID(), report: rep})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].executorID < out[j].executorID })
	return out
}

// refreshTargets is where a lease's refreshed token file would go.
type refreshTargets struct {
	// holders counts the executors on this hub holding the lease.
	holders int
	// cannot names the holders that cannot take a new file at all — an agent
	// too old for the frame, a driver with no way to rewrite one — and why.
	cannot map[string]string
	// offline counts holders that could, but are not connected right now.
	offline int
}

// leaseRefreshTargets finds the executors on this hub holding leaseID.
//
// An agent connected to another member of a hub cluster is not counted: the
// lease's keepalive runs on the member that issued it, and a refresh does not
// travel between members — see docs/architecture/git-proxy.md.
func leaseRefreshTargets(leaseID string) refreshTargets {
	out := refreshTargets{cannot: map[string]string{}}
	if hub := activeRemoteHub(); hub != nil {
		for _, ex := range hub.Executors() {
			if !ex.HoldsLease(leaseID) {
				continue
			}
			out.holders++
			if !ex.Connected() {
				out.offline++
				continue
			}
			if why := ex.SecretRefreshShortfall(); why != "" {
				out.cannot[ex.ID()] = why
			}
		}
	}
	for _, ex := range executor.List() {
		if _, isRemote := ex.(*remote.Executor); isRemote {
			continue
		}
		rv, ok := executor.AsRevoker(ex)
		if !ok || !rv.HoldsLease(leaseID) {
			continue
		}
		out.holders++
		if _, ok := executor.AsSecretRefresher(ex); !ok {
			out.cannot[ex.ID()] = fmt.Sprintf("the %s driver cannot replace a credential file in a running "+
				"workload", ex.Kind())
		}
	}
	return out
}

// noteUndeliverable journals, once per executor and reason, that a holder
// cannot receive a refreshed token — and so that the run's GitHub access ends
// when the token it holds expires.
func (sl *secretLease) noteUndeliverable(shortfalls map[string]string) {
	ids := make([]string, 0, len(shortfalls))
	for id := range shortfalls {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	until := sl.appTokenDeadline()
	for _, id := range ids {
		why := shortfalls[id]
		sl.mu.Lock()
		if sl.refreshNoted == nil {
			sl.refreshNoted = map[string]string{}
		}
		seen := sl.refreshNoted[id] == why
		sl.refreshNoted[id] = why
		sl.mu.Unlock()
		if seen {
			continue
		}
		msg := fmt.Sprintf("Executor %q cannot be handed a renewed GitHub App token for this run, so its GitHub "+
			"access ends when the token it holds expires", id)
		if !until.IsZero() {
			msg += " (" + until.UTC().Format(time.RFC3339) + ")"
		}
		msg += ". " + why
		sl.journal(msg, map[string]any{"lease_id": sl.lease.ID, "executor_id": id, "undeliverable": true})
		sl.auditRefresh(id, nil, nil, executor.SecretRefreshReport{
			LeaseID: sl.lease.ID, Known: true, Unsupported: true, Error: why,
		}, "not minted: the executor cannot receive a refreshed token")
	}
}

// appTokenDeadline is when the first GitHub token the workload holds expires,
// or zero: the broker's word once it minted the lease's tokens — a refresh that
// reached the workload moved it — else what the lease announced at dispatch.
func (sl *secretLease) appTokenDeadline() time.Time {
	if sl.broker != nil {
		return sl.broker.HeldAppTokenExpiry(sl.lease.ID)
	}
	var earliest time.Time
	for _, m := range sl.lease.Materials {
		if t := m.GitHubTokenExpiresAt(); !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	return earliest
}

// journal writes one row on the project's event journal.
func (sl *secretLease) journal(msg string, details map[string]any) {
	if sl.workDir == "" {
		fmt.Fprintf(os.Stderr, "ui: %s\n", msg)
		return
	}
	state.LogEventDetails(sl.workDir, state.EventRow{
		Type:    state.EventCredentialRefresh,
		Step:    state.NoStep,
		Message: msg,
	}, details)
}

// auditRefresh writes one lease.refresh row for one executor's outcome.
func (sl *secretLease) auditRefresh(executorID string, grants, files []string, rep executor.SecretRefreshReport, reason string) {
	db := sl.auditDB
	if db == nil {
		return
	}
	decision := secretbroker.DecisionAllow
	if !rep.Delivered() {
		decision = secretbroker.DecisionDeny
	}
	payload := map[string]any{
		"decision":    string(decision),
		"lease_id":    sl.lease.ID,
		"grant_id":    strings.Join(grants, ","),
		"executor_id": executorID,
		"project_id":  sl.lease.ProjectID,
		"files":       strings.Join(files, ","),
		"handles":     strings.Join(rep.Handles, ","),
		"eventual":    rep.Eventual,
		"reason":      reason,
	}
	if rep.Error != "" {
		payload["error"] = rep.Error
	}
	statedb.AuditSecretDecision(db, statedb.SecretAuditInput{
		Actor:     "ui",
		EventType: auditaction.Action(secretbroker.ActionLeaseRefresh),
		EntityID:  sl.lease.ID,
		Payload:   payload,
	})
}

func grantList(files []secretbroker.DeliveredFile) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		if f.GrantID != "" && !seen[f.GrantID] {
			seen[f.GrantID] = true
			out = append(out, f.GrantID)
		}
	}
	sort.Strings(out)
	return out
}

func fileNames(files []secretbroker.DeliveredFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}
