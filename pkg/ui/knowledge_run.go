package ui

// knowledge_run.go: a run's knowledge session (Task 20472).
//
// A run of a project with knowledge sources bound to it is dispatched with a
// knowledge session: a bearer token, cloop_know1_<id>.<secret>, good for the
// hub's run-scoped knowledge search (knowledge_run_api.go) of that project and
// of nothing else, and the URL it is served at. The run's orchestrator uses it
// to put the passages that best match each task into the task's prompt; the
// agent uses it through cloop's MCP server or `cloop knowledge search`.
//
// It is the run's own credential, minted with the run:
//
//   - what it opens is read access to the project's knowledge, through the
//     project's bindings — never another project's, and never the credentials
//     the hub reads the sources with, which no executor receives;
//   - only its SHA-256 is stored (proxy_sessions, kind "knowledge"), so a copy
//     of the database opens nothing, and every hub member can check it;
//   - it lives as long as the run: renewed every ten minutes, from the process
//     that streams the run, while the workload is running, closed when the run
//     ends, and taken over — like the run's leases and egress sessions — by the
//     process that adopts the run after a restart. A run whose session lapsed
//     or closed is refused, and searches nothing.
//
// Nothing about it fails a dispatch: a hub with no URL its runs can reach, a
// database that cannot record the session, give a run without knowledge, and
// say so in the project's journal.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// How long a knowledge session lasts without renewal, and how often the
// process streaming its run renews it.
var (
	knowledgeSessionTTL        = 30 * time.Minute
	knowledgeSessionRenewEvery = 10 * time.Minute
)

// knowledgeReadsKeep is how long a run's unclaimed reads are kept at most.
const knowledgeReadsKeep = 7 * 24 * time.Hour

// knowledgeRunHub is the Server whose listener runs reach the knowledge
// search on: its public URL, or its own address for a run on its host.
var knowledgeRunHub atomic.Pointer[Server]

// setKnowledgeRunServer names the Server runs reach the knowledge search on.
func setKnowledgeRunServer(s *Server) {
	if s != nil {
		knowledgeRunHub.Store(s)
	}
}

// knowledgeRouteFor is the base URL a workload on ex reaches the hub's
// run-scoped knowledge search at, or why there is none.
//
// The hub's public URL — ui.external_url, else the sign-in callback's origin —
// is where everything outside the hub reaches it, a device's agent included,
// so it is where a sandbox reaches it too. A hub without one is reachable from
// its own host only: a run there, sharing the host's network, is given the
// hub's own address; any other is given nothing.
func knowledgeRouteFor(ex executor.Executor) (string, string) {
	s := knowledgeRunHub.Load()
	if s == nil {
		return "", "this hub process serves no knowledge search"
	}
	if public, key := s.publicURL(); public != "" {
		u, err := url.Parse(public)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", fmt.Sprintf("%s (%q) is not an http or https URL", key, public)
		}
		return u.Scheme + "://" + u.Host + knowledgerun.MountPath, ""
	}
	if ex == nil || executor.IsolatesFromHost(ex) {
		return "", "this hub has no ui.external_url, the address its sandboxes would reach it at"
	}
	if s.TLSEnabled() {
		return "", "this hub serves TLS and has no ui.external_url naming the address its certificate is for"
	}
	addr, ok := s.BoundAddr().(*net.TCPAddr)
	if !ok || addr == nil {
		return "", "this hub is not listening yet"
	}
	host := "127.0.0.1"
	switch {
	case addr.IP == nil || addr.IP.IsUnspecified():
		if addr.IP != nil && addr.IP.To4() == nil {
			host = "::1"
		}
	default:
		host = addr.IP.String()
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(addr.Port)) + knowledgerun.MountPath, ""
}

// isRunArgv reports whether argv runs a project's orchestrator: `cloop run`.
func isRunArgv(argv []string) bool {
	return len(argv) > 1 && argv[1] == "run"
}

// runKnowledge is the knowledge session a dispatch minted.
type runKnowledge struct {
	id      string
	workDir string
	// handle is the workload holding it, once bindHandle has run.
	handle atomic.Pointer[string]
}

// knowledgeSessionEntry is one workload's knowledge sessions in this process.
type knowledgeSessionEntry struct {
	ex      executor.Executor
	workDir string
	ids     []string
}

// knowledgeRegistry indexes the knowledge sessions this process keeps alive
// by the handle of the workload holding them.
type knowledgeRegistry struct {
	mu       sync.Mutex
	byHandle map[string]*knowledgeSessionEntry
	keeper   sync.Once
}

// liveKnowledge is every knowledge session this process keeps alive.
var liveKnowledge = &knowledgeRegistry{byHandle: map[string]*knowledgeSessionEntry{}}

func (r *knowledgeRegistry) bind(ex executor.Executor, workDir, handleID, id string) {
	if handleID == "" || id == "" {
		return
	}
	r.mu.Lock()
	e := r.byHandle[handleID]
	if e == nil {
		e = &knowledgeSessionEntry{ex: ex, workDir: workDir}
		r.byHandle[handleID] = e
	}
	if !containsRef(e.ids, id) {
		e.ids = append(e.ids, id)
		sort.Strings(e.ids)
	}
	r.mu.Unlock()
	r.keeper.Do(func() { go keepKnowledgeSessions() })
}

// idsForHandle returns the sessions the workload with handleID holds: what
// a run's owner row names, so the process adopting the run takes them over.
func (r *knowledgeRegistry) idsForHandle(handleID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.byHandle[handleID]; e != nil {
		return append([]string(nil), e.ids...)
	}
	return nil
}

// take removes and returns the workload's sessions.
func (r *knowledgeRegistry) take(handleID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.byHandle[handleID]
	delete(r.byHandle, handleID)
	if e == nil {
		return nil
	}
	return e.ids
}

// drop forgets one session, which was closed or taken elsewhere.
func (r *knowledgeRegistry) drop(handleID, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.byHandle[handleID]
	if e == nil {
		return
	}
	kept := e.ids[:0]
	for _, have := range e.ids {
		if have != id {
			kept = append(kept, have)
		}
	}
	e.ids = kept
	if len(e.ids) == 0 {
		delete(r.byHandle, handleID)
	}
}

// known reports whether this process keeps session id alive.
func (r *knowledgeRegistry) known(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.byHandle {
		if containsRef(e.ids, id) {
			return true
		}
	}
	return false
}

// snapshot copies the registry.
func (r *knowledgeRegistry) snapshot() map[string]knowledgeSessionEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]knowledgeSessionEntry, len(r.byHandle))
	for h, e := range r.byHandle {
		out[h] = knowledgeSessionEntry{ex: e.ex, workDir: e.workDir, ids: append([]string(nil), e.ids...)}
	}
	return out
}

// knowledgeRecordDB opens the control plane, where knowledge sessions are
// recorded.
func knowledgeRecordDB() (*statedb.DB, error) {
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return nil, err
	}
	return db.AsControlPlane(), nil
}

// projectHasKnowledge reports whether knowledge sources are bound to the
// project workDir belongs to — a feature reads its parent's.
func projectHasKnowledge(db *statedb.DB, workDir string) (bool, error) {
	rows, err := db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{ProjectPath: policyProjectPath(workDir)})
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// newKnowledgeToken mints a session's id and token.
func newKnowledgeToken() (id, token string, err error) {
	var idb [12]byte
	var secret [32]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(idb[:])
	return id, knowledgerun.TokenPrefix + id + "." + base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

// knowledgeTokenID returns the session id a token names, and false for a
// string that is not a knowledge session token.
func knowledgeTokenID(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, knowledgerun.TokenPrefix)
	if !ok || len(token) > 256 {
		return "", false
	}
	id, secret, ok := strings.Cut(rest, ".")
	if !ok || len(id) != 24 || len(secret) < 32 {
		return "", false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", false
	}
	return id, true
}

// knowledgeTokenLen is the length of every token newKnowledgeToken mints: its
// prefix, a 24-hex-digit id, a dot and 32 bytes of base64url — the length an
// adopted run's output is searched for its token by (adopted_tokens.go).
const knowledgeTokenLen = len(knowledgerun.TokenPrefix) + 24 + 1 + 43

// tokenSHA256 is the hex SHA-256 a session records of its token.
func tokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// knowledgeScope is what a knowledge session's record keeps beyond its
// columns: the directory the run works in, which a feature's run has of its
// own while its knowledge is its parent's.
type knowledgeScope struct {
	WorkDir string `json:"workdir"`
}

// applyKnowledgeSession gives a run of a project with knowledge sources bound
// to it a knowledge session: minted, recorded, and its token and URL put in
// spec's environment, declared sensitive so the workload's output is scrubbed
// of the token and the stored spec never carries it. A run of a project
// without knowledge, or a dispatch that is not a run, gets nothing; so does a
// run the session cannot be made for, which the project's journal is told.
func applyKnowledgeSession(spec executor.Spec, ex executor.Executor, workDir, runID, identity string, argv []string) (executor.Spec, *runKnowledge) {
	if ex == nil || strings.TrimSpace(workDir) == "" || !isRunArgv(argv) {
		return spec, nil
	}
	db, err := knowledgeRecordDB()
	if err != nil {
		return spec, nil
	}
	defer func() { _ = db.Close() }()
	has, err := projectHasKnowledge(db, workDir)
	if err != nil {
		noteKnowledge(workDir, "The run was started without access to the project's knowledge sources: the hub could "+
			"not read their bindings ("+err.Error()+").")
		return spec, nil
	}
	if !has {
		return spec, nil
	}
	base, why := knowledgeRouteFor(ex)
	if base == "" {
		noteKnowledge(workDir, fmt.Sprintf("Knowledge sources are bound to this project, but its runs on %s cannot "+
			"reach this hub's knowledge search: %s. The run's tasks get no reference material and its agent no "+
			"knowledge search.", ex.ID(), why))
		return spec, nil
	}
	id, token, err := newKnowledgeToken()
	if err != nil {
		noteKnowledge(workDir, "The run was started without access to the project's knowledge sources: no session "+
			"token could be minted ("+err.Error()+").")
		return spec, nil
	}
	scope, _ := json.Marshal(knowledgeScope{WorkDir: workDir})
	now := time.Now().UTC()
	if err := db.PutProxySession(statedb.ProxySessionRow{
		Kind: statedb.ProxySessionKnowledge, SessionID: id, TokenSHA256: tokenSHA256(token),
		Holder: leaseHolderID(), RunID: runID, ProjectID: policyProjectPath(workDir), ExecutorID: ex.ID(),
		Actor: identity, Scope: string(scope), IssuedAt: now, ExpiresAt: now.Add(knowledgeSessionTTL), UpdatedAt: now,
	}); err != nil {
		noteKnowledge(workDir, "The run was started without access to the project's knowledge sources: its session "+
			"could not be recorded ("+err.Error()+").")
		return spec, nil
	}
	spec = withSensitiveEnv(spec, ex, map[string]string{
		knowledgerun.EnvURL:   base,
		knowledgerun.EnvToken: token,
	}, []string{knowledgerun.EnvToken})
	return spec, &runKnowledge{id: id, workDir: workDir}
}

// withSensitiveEnv sets vars in spec's environment, replacing any of the same
// names it carried, and declares sensitive (redact.EnvKey) the ones named:
// the executor scrubs their values from the output it captures, the workload
// from its own, and the dispatched spec is stored without them.
func withSensitiveEnv(spec executor.Spec, ex executor.Executor, vars map[string]string, sensitive []string) executor.Spec {
	base := spec.Env
	if base == nil && !executor.IsolatesFromHost(ex) {
		// nil means "inherit" on the host driver; an Env holding only these
		// would strip PATH and HOME from the harness (see applyLease).
		base = os.Environ()
	}
	declared := map[string]bool{}
	out := make([]string, 0, len(base)+len(vars)+1)
	for _, kv := range base {
		name, value, _ := strings.Cut(kv, "=")
		if name == redact.EnvKey {
			for _, n := range strings.Split(value, ",") {
				if n = strings.TrimSpace(n); n != "" {
					declared[n] = true
				}
			}
			continue
		}
		if _, replaced := vars[name]; replaced {
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+vars[k])
	}
	for _, k := range sensitive {
		declared[k] = true
	}
	names := make([]string, 0, len(declared))
	for n := range declared {
		names = append(names, n)
	}
	sort.Strings(names)
	spec.Env = append(out, redact.EnvKey+"="+strings.Join(names, ","))
	return spec
}

// bindHandle hands the session to the workload that holds it: kept alive from
// this process while the workload runs, named on the run's owner row.
func (k *runKnowledge) bindHandle(ex executor.Executor, handleID string) {
	if k == nil || handleID == "" {
		return
	}
	k.handle.Store(&handleID)
	liveKnowledge.bind(ex, k.workDir, handleID, k.id)
}

// abandon closes the session of a dispatch that did not start its run, or
// whose run it stopped again.
func (k *runKnowledge) abandon(reason string) {
	if k == nil {
		return
	}
	if h := k.handle.Load(); h != nil {
		liveKnowledge.drop(*h, k.id)
	}
	closeKnowledgeSessions([]string{k.id}, reason)
}

// closeRunKnowledge ends the knowledge sessions the workload with handleID
// holds: its run is over, and so is its access to the project's knowledge.
func closeRunKnowledge(handleID, reason string) {
	if handleID == "" {
		return
	}
	closeKnowledgeSessions(liveKnowledge.take(handleID), reason)
}

// closeKnowledgeSessions closes the sessions ids names that this process
// holds, and forgets what was recorded of their reads and was not collected.
func closeKnowledgeSessions(ids []string, reason string) {
	if len(ids) == 0 {
		return
	}
	db, err := knowledgeRecordDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: close knowledge sessions: %v\n", err)
		return
	}
	defer func() { _ = db.Close() }()
	now := time.Now().UTC()
	for _, id := range ids {
		if _, err := db.CloseProxySession(statedb.ProxySessionKnowledge, id, leaseHolderID(), now, reason, ""); err != nil {
			fmt.Fprintf(os.Stderr, "ui: close knowledge session %s: %v\n", id, err)
		}
	}
	if _, err := db.PurgeKnowledgeRunReads(now.Add(-knowledgeReadsKeep)); err != nil {
		fmt.Fprintf(os.Stderr, "ui: purge knowledge reads: %v\n", err)
	}
}

// retireRunKnowledge closes the knowledge sessions of a run that ended while
// no hub process held them: whoever held them is gone, so the close is fenced
// on the holder the record names.
func retireRunKnowledge(ids []string, reason string) {
	if len(ids) == 0 {
		return
	}
	db, err := knowledgeRecordDB()
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	now := time.Now().UTC()
	for _, id := range ids {
		row, err := db.GetProxySession(statedb.ProxySessionKnowledge, id)
		if err != nil || !row.Open() {
			continue
		}
		_, _ = db.CloseProxySession(statedb.ProxySessionKnowledge, id, row.Holder, now, reason, "")
	}
	_, _ = db.PurgeKnowledgeRunReads(now.Add(-knowledgeReadsKeep))
}

// restoreRunKnowledge takes over the knowledge sessions an adopted run holds,
// by the ids its owner row names: kept alive here from now on, and closed here
// when the run ends. One that closed or lapsed while no process held it stays
// so — the run searches nothing more, and its tasks run without reference
// material, as the journal says.
func restoreRunKnowledge(workDir string, ex executor.Executor, handleID string, ids []string) {
	if len(ids) == 0 || handleID == "" {
		return
	}
	db, err := knowledgeRecordDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: take over knowledge sessions: %v\n", err)
		return
	}
	defer func() { _ = db.Close() }()
	me, now := leaseHolderID(), time.Now().UTC()
	for _, id := range ids {
		row, err := db.GetProxySession(statedb.ProxySessionKnowledge, id)
		if err != nil {
			continue
		}
		if !row.Open() || !now.Before(row.ExpiresAt) {
			why := row.CloseReason
			if why == "" {
				why = "it lapsed"
			}
			noteKnowledge(workDir, fmt.Sprintf("The adopted run's knowledge session %s had ended (%s) before this hub "+
				"process took the run over; the rest of the run has no access to the project's knowledge.", id, why))
			continue
		}
		if row.Holder != me {
			ok, err := db.TakeProxySession(statedb.ProxySessionKnowledge, id, row.Holder, me)
			if err != nil || !ok {
				continue
			}
		}
		_, _ = db.ExtendProxySession(statedb.ProxySessionKnowledge, id, me, now.Add(knowledgeSessionTTL))
		liveKnowledge.bind(ex, workDir, handleID, id)
	}
}

// keepKnowledgeSessions renews, every knowledgeSessionRenewEvery, the
// knowledge sessions of the workloads this process streams, for as long as
// each runs. A session whose workload ended is closed; one another process
// took or closed is forgotten here.
func keepKnowledgeSessions() {
	defer recoverGoroutine("knowledge session keepalive")
	ticker := time.NewTicker(knowledgeSessionRenewEvery)
	defer ticker.Stop()
	for range ticker.C {
		renewKnowledgeSessions()
	}
}

// renewKnowledgeSessions is one keepalive tick.
func renewKnowledgeSessions() {
	live := liveKnowledge.snapshot()
	if len(live) == 0 {
		return
	}
	db, err := knowledgeRecordDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: renew knowledge sessions: %v\n", err)
		return
	}
	defer func() { _ = db.Close() }()
	me := leaseHolderID()
	for handleID, e := range live {
		if e.ex != nil {
			ctx, cancel := context.WithTimeout(context.Background(), workloadStatusTimeout)
			alive := workloadAlive(e.ex, handleID)(ctx)
			cancel()
			if !alive {
				closeRunKnowledge(handleID, "the run ended")
				continue
			}
		}
		for _, id := range e.ids {
			ok, err := db.ExtendProxySession(statedb.ProxySessionKnowledge, id, me,
				time.Now().UTC().Add(knowledgeSessionTTL))
			if err == nil && !ok {
				liveKnowledge.drop(handleID, id)
			}
		}
	}
}

// noteKnowledge writes a knowledge row to the project's journal.
func noteKnowledge(workDir, msg string) {
	state.LogEvent(workDir, state.EventRow{Type: state.EventKnowledge, Step: state.NoStep, Message: msg})
}
