package ui

// gitproxy_pushscan.go feeds the git proxy's push scan (Task 20436): which
// values a session's pushes are scanned for, in which mode and within which
// limits — and files a refused push where the people running the project
// look.
//
// # Which values
//
// The ones the run was given. They are recorded per run when it is
// dispatched, from its lease — every credential a material delivered, taken
// apart by pkg/secretbroker into the values inside each document — and from
// the spec, whose environment also carries what no lease did: the run's
// egress proxy session and its model relay token. Every git proxy session the
// run holds names it (Session.RunID): the lease path's sessions for the
// workload's own git, and since this task the workspace's pinned session too,
// whose push is the run's write-back.
//
// A hub process that adopts a run after the one that dispatched it stopped
// has no spec and no materials. It scans with what Broker.RedactionCredentials
// re-derives from the run's grants — env secrets and personal access tokens —
// and the docs say what that leaves out rather than claim more.
//
// The values live in this process's memory only, for as long as the run or a
// session naming it does. Nothing here writes them anywhere.

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"gopkg.in/yaml.v3"
)

// runPushScan is what one run's pushes are scanned for.
type runPushScan struct {
	workDir  string
	leaseIDs []string
	secrets  []gitproxy.ScanSecret
	// ended: the run is over; the entry goes once no session names it.
	ended bool
}

// pushScans holds every live run's entry, by run id.
var pushScans = struct {
	sync.Mutex
	runs map[string]*runPushScan
}{runs: map[string]*runPushScan{}}

// scanSecrets converts what the broker says a lease delivered.
func scanSecrets(cs []secretbroker.CredentialValue) []gitproxy.ScanSecret {
	out := make([]gitproxy.ScanSecret, 0, len(cs))
	for _, c := range cs {
		out = append(out, gitproxy.ScanSecret{Value: c.Value, Grant: c.GrantID, Secret: c.SecretName, Field: c.Field})
	}
	return out
}

// specScanSecrets are the values a spec's environment declares credentials
// (redact.EnvKey) that its lease did not deliver: an egress proxy session's
// URL and its token, a model relay session's token.
func specScanSecrets(env []string) []gitproxy.ScanSecret {
	lookup := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			lookup[k] = v
		}
	}
	var names []string
	for _, n := range strings.Split(lookup[redact.EnvKey], ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	proxyKey := map[string]bool{}
	for _, k := range egressbroker.ProxyEnvKeys {
		proxyKey[k] = true
	}
	var out []gitproxy.ScanSecret
	for _, n := range names {
		v := lookup[n]
		if v == "" {
			continue
		}
		what := ""
		switch {
		case proxyKey[n]:
			what = "the run's egress proxy session"
		case n == envAnthropicAuth || n == envAnthropicAPIKey:
			what = "the run's model relay session"
		}
		out = append(out, gitproxy.ScanSecret{Value: v, Secret: what, Field: "env " + n})
		if u, err := url.Parse(strings.TrimSpace(v)); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				out = append(out, gitproxy.ScanSecret{Value: pw, Secret: what, Field: "the password in env " + n})
			}
		}
	}
	return out
}

// registerRunPushScan records what runID's pushes are scanned for, and returns
// the function that marks the run over. A hub with no git proxy records
// nothing: nothing it serves is scanned.
func registerRunPushScan(runID, workDir string, lease *secretLease, spec executor.Spec) func() {
	runID = strings.TrimSpace(runID)
	if runID == "" || activeGitProxy() == nil {
		return func() {}
	}
	var secrets []gitproxy.ScanSecret
	var leaseIDs []string
	if lease != nil && lease.lease != nil {
		secrets = append(secrets, scanSecrets(lease.lease.CredentialValues())...)
		leaseIDs = append(leaseIDs, lease.lease.ID)
	}
	secrets = append(secrets, specScanSecrets(spec.Env)...)
	pushScans.Lock()
	pushScans.runs[runID] = &runPushScan{workDir: workDir, leaseIDs: leaseIDs, secrets: secrets}
	pushScans.Unlock()
	var once sync.Once
	return func() { once.Do(func() { endRunPushScan(runID) }) }
}

// adoptRunPushScan records what an adopted run's pushes are scanned for: what
// the broker re-derives from the lease it took over. It extends an entry this
// process already holds rather than replacing it.
func adoptRunPushScan(runID, workDir, leaseID string, creds []secretbroker.CredentialValue) {
	runID = strings.TrimSpace(runID)
	if runID == "" || activeGitProxy() == nil {
		return
	}
	pushScans.Lock()
	defer pushScans.Unlock()
	e := pushScans.runs[runID]
	if e == nil {
		e = &runPushScan{workDir: workDir}
		pushScans.runs[runID] = e
	}
	e.ended = false
	if leaseID != "" && !pushScanHas(e.leaseIDs, leaseID) {
		e.leaseIDs = append(e.leaseIDs, leaseID)
	}
	e.secrets = append(e.secrets, scanSecrets(creds)...)
}

// endRunPushScan marks a run over, and forgets it once no session names it.
func endRunPushScan(runID string) {
	pushScans.Lock()
	if e := pushScans.runs[runID]; e != nil {
		e.ended = true
	}
	pushScans.Unlock()
	sweepRunPushScans()
}

// sweepRunPushScans forgets every run that is over and that no live git
// proxy session names: a workspace's write-back push can outlive the run's own
// lease by the time its pinned session takes to close.
func sweepRunPushScans() {
	named := map[string]bool{}
	if svc := activeGitProxy(); svc != nil && svc.reg != nil {
		for _, sess := range svc.reg.Sessions() {
			if !sess.Closed() && sess.RunID != "" {
				named[sess.RunID] = true
			}
		}
	}
	pushScans.Lock()
	defer pushScans.Unlock()
	for id, e := range pushScans.runs {
		if e.ended && !named[id] {
			delete(pushScans.runs, id)
		}
	}
}

// runPushScanFor finds the entry a session's pushes are scanned with: by its
// run, or else by the lease its credential stands on.
func runPushScanFor(sess *gitproxy.Session) (workDir string, secrets []gitproxy.ScanSecret) {
	pushScans.Lock()
	defer pushScans.Unlock()
	e := pushScans.runs[strings.TrimSpace(sess.RunID)]
	if e == nil && sess.LeaseID != "" {
		for _, cand := range pushScans.runs {
			if pushScanHas(cand.leaseIDs, sess.LeaseID) {
				e = cand
				break
			}
		}
	}
	if e == nil {
		return "", nil
	}
	return e.workDir, append([]gitproxy.ScanSecret(nil), e.secrets...)
}

// pushScanFor is the proxy's PushScan hook.
func (s *gitProxyService) pushScanFor(sess *gitproxy.Session) gitproxy.PushScan {
	scan := gitproxy.PushScan{Mode: s.scanMode, Limits: s.scanLimits}
	workDir, secrets := runPushScanFor(sess)
	scan.Secrets = secrets
	// A project may ask for a stricter scan than the hub's, never a weaker
	// one.
	if m, ok := projectPushScanMode(pushScanProjectDir(workDir, sess.ProjectID)); ok {
		scan.Mode = gitproxy.StricterScanMode(scan.Mode, m)
	}
	return scan
}

// pushScanProjectDir is the project whose own setting a session's pushes are
// held to: its run's, or the session's project when that is a directory here.
func pushScanProjectDir(workDir, projectID string) string {
	if workDir != "" {
		return workDir
	}
	if p := strings.TrimSpace(projectID); filepath.IsAbs(p) {
		if st, err := os.Stat(filepath.Join(p, ".cloop")); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

// projectPushScanMode is the mode a project's own .cloop/config.yaml asks for,
// and whether it asks at all: a project that says nothing leaves the hub's
// mode alone, whatever that is.
//
// It reads the one key and nothing else, from a regular file of bounded size
// opened without blocking: a workload whose sandbox shares the project
// directory may have written that file — which is why the setting can only
// tighten — and must not be able to stall the proxy reading it. A value it
// cannot read asks for values, never for off.
func projectPushScanMode(dir string) (gitproxy.ScanMode, bool) {
	if dir == "" {
		return "", false
	}
	f, err := openProjectFileNoBlock(config.ConfigPath(dir))
	if err != nil {
		return "", false
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(f, projectConfigReadLimit))
	if err != nil {
		return "", false
	}
	var doc struct {
		Executors struct {
			GitProxy struct {
				PushScan string `yaml:"push_scan"`
			} `yaml:"git_proxy"`
		} `yaml:"executors"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return "", false
	}
	raw := strings.TrimSpace(doc.Executors.GitProxy.PushScan)
	if raw == "" {
		return "", false
	}
	m, err := gitproxy.ParseScanMode(raw)
	if err != nil {
		return gitproxy.ScanValues, true
	}
	return m, true
}

// projectConfigReadLimit bounds the project config read on the push path.
const projectConfigReadLimit = 1 << 20

// journalPushScanRefusal files a push the scan refused in the run's history,
// on the task it was running when there was exactly one.
func journalPushScanRefusal(e gitproxy.Event) {
	if e.Scan == "" {
		return
	}
	pushScans.Lock()
	workDir := ""
	if r := pushScans.runs[e.RunID]; r != nil {
		workDir = r.workDir
	}
	pushScans.Unlock()
	if workDir == "" {
		workDir = pushScanProjectDir("", e.ProjectID)
	}
	if workDir == "" {
		return
	}
	row := state.EventRow{Type: state.EventGitPushRefused, Step: state.NoStep, Timestamp: e.At,
		Message: pushRefusalMessage(e)}
	if ps, err := state.Load(workDir); err == nil && ps.Plan != nil {
		var running []*pm.Task
		for _, t := range ps.Plan.Tasks {
			if t.Status == pm.TaskInProgress {
				running = append(running, t)
			}
		}
		if len(running) == 1 {
			row.TaskID, row.TaskTitle = running[0].ID, running[0].Title
		}
	}
	state.LogEventDetails(workDir, row, map[string]any{
		"session_id": e.SessionID,
		"repo":       e.RepoPath,
		"refs":       e.Refs,
		"run_id":     e.RunID,
		"scan":       e.Scan,
		"findings":   e.Findings,
	})
}

// pushRefusalMessage is the journal's one line for a refused push. It is
// built from the event, which carries no value.
func pushRefusalMessage(e gitproxy.Event) string {
	where := e.RepoPath
	if len(e.Refs) > 0 {
		where += " (" + strings.Join(e.Refs, ", ") + ")"
	}
	if e.Scan == gitproxy.ScanResultSecret {
		return fmt.Sprintf("The git proxy refused a push to %s: %s. No ref was updated; take the value out "+
			"of the commits and push again.", where, strings.TrimPrefix(e.Detail, "carries a credential the run was given: "))
	}
	return fmt.Sprintf("The git proxy refused a push to %s without forwarding it: %s",
		where, strings.TrimPrefix(e.Detail, "push scan: "))
}

// pushRefusalsForTask are the refusals the run's history files under a task —
// by its id, or for a refusal no single task was named for, by when the task
// was running — as the lines its details show.
func pushRefusalsForTask(workDir string, t *pm.Task) []pm.Annotation {
	// A refusal is filed under a task that was running, by its id or its
	// window, so a task that never started has none — and its details need
	// not open the journal to say so.
	if t == nil || t.StartedAt == nil {
		return nil
	}
	rows, err := state.ListEventsOfType(workDir, state.EventGitPushRefused, 200)
	if err != nil {
		return nil
	}
	var out []pm.Annotation
	for _, r := range rows {
		mine := r.TaskID == t.ID
		if r.TaskID == 0 && t.StartedAt != nil && !r.Timestamp.Before(*t.StartedAt) {
			end := time.Now()
			if t.CompletedAt != nil {
				end = *t.CompletedAt
			}
			mine = !r.Timestamp.After(end)
		}
		if mine {
			out = append(out, pm.Annotation{Timestamp: r.Timestamp, Author: "git proxy", Text: r.Message})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

func pushScanHas(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// withPushScanJournal files a refused push in its run's history before the
// audit sink records it.
func withPushScanJournal(inner func(gitproxy.Event)) func(gitproxy.Event) {
	return func(e gitproxy.Event) {
		if e.Scan != "" {
			journalPushScanRefusal(e)
		}
		if inner != nil {
			inner(e)
		}
	}
}

// scanModeDescription names a scan mode for the startup line.
func scanModeDescription(m gitproxy.ScanMode) string {
	switch m {
	case gitproxy.ScanOff:
		return "nothing (push_scan: off)"
	case gitproxy.ScanShapes:
		return "the run's credentials and credential shapes (push_scan: shapes)"
	default:
		return "the run's credentials (push_scan: values)"
	}
}
