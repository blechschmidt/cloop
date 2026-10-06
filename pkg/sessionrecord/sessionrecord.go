// Package sessionrecord records the hub's proxy sessions durably (Task 20383):
// the git proxy's lease-path and workspace sessions, the Kubernetes monitor's
// sessions and every run's egress session, in statedb's proxy_sessions
// (migrations/0058_proxy_sessions.sql), so the hub process that adopts a run
// after the one serving it stops can restore them; and the CI relay's
// sessions, in ci_sessions (migrations/0060_ci_sessions.sql, Task 20390), so
// the hub process that receives a job's next call after the one serving it
// stops can restore the job's session.
//
// It is the seam between three registries that must not know about the
// database — pkg/gitproxy, pkg/kubeguard, pkg/egressbroker each define a
// SessionStore — and the table. Each store writes as the hub process its
// Holder names, the cluster member id the run's lease is recorded under, and
// every write after the insert is fenced on it: a session another process took
// over with its run is that process's to extend, checkpoint and close.
//
// What goes in a row is what the registries keep in memory instead of a
// credential: the SHA-256 of the token a sandbox presents, and the scope the
// session enforces. The record types it is handed have no field a credential
// could travel in, and tests/security scans the table after a realistic run
// for anything that did.
package sessionrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ErrNoHolder: the process has no cluster member id to record a session
// under, so nothing could take it over.
var ErrNoHolder = errors.New("this hub process has no cluster member id to record sessions under")

// errNotHeld: a write landed on no row — the session is not this process's any
// more, or was closed already.
var errNotHeld = errors.New("the session's record is not held by this hub process")

// base is what every store shares.
type base struct {
	// DB is the control plane's database.
	DB *statedb.DB
	// Holder names the hub process writing, read on every write: a test
	// plays two processes in one binary by changing what it returns.
	Holder func() string
	// OnError, if set, is told of a write after the insert that failed — an
	// end or renewal a successor will not see. The registries cannot act on
	// one; somebody should hear of it.
	OnError func(kind, id, what string, err error)
}

func (b base) holder() (string, error) {
	if b.Holder == nil {
		return "", ErrNoHolder
	}
	h := b.Holder()
	if h == "" {
		return "", ErrNoHolder
	}
	return h, nil
}

func (b base) report(kind, id, what string, err error) error {
	if err != nil && b.OnError != nil && !errors.Is(err, ErrNoHolder) {
		b.OnError(kind, id, what, err)
	}
	return err
}

// closeRow closes this process's record of a session.
func (b base) closeRow(kind, id, reason string, at time.Time, counters string) error {
	holder, err := b.holder()
	if err != nil {
		return err
	}
	_, err = b.DB.CloseProxySession(kind, id, holder, at, reason, counters)
	return b.report(kind, id, "record its end", err)
}

// ── git ──────────────────────────────────────────────────────────────────────

// GitScope is a git session's scope_json.
type GitScope struct {
	RepoPath     string          `json:"repo_path,omitempty"`
	RepoPatterns []string        `json:"repo_patterns,omitempty"`
	Upstream     string          `json:"upstream"`
	Policy       gitproxy.Policy `json:"policy"`
}

// GitStore is a gitproxy.SessionStore over the control plane's database.
type GitStore struct{ base }

// NewGitStore returns a store writing as holder.
func NewGitStore(db *statedb.DB, holder func() string, onError func(kind, id, what string, err error)) GitStore {
	return GitStore{base{DB: db, Holder: holder, OnError: onError}}
}

// SaveSession implements gitproxy.SessionStore.
func (g GitStore) SaveSession(rec gitproxy.SessionRecord) error {
	holder, err := g.holder()
	if err != nil {
		return err
	}
	scope, err := json.Marshal(GitScope{RepoPath: rec.RepoPath, RepoPatterns: rec.RepoPatterns,
		Upstream: rec.Upstream, Policy: rec.Policy})
	if err != nil {
		return err
	}
	return g.DB.PutProxySession(statedb.ProxySessionRow{
		Kind: statedb.ProxySessionGit, SessionID: rec.ID, TokenSHA256: rec.TokenSHA256,
		LeaseID: rec.LeaseID, GrantID: rec.GrantID, Holder: holder, RunID: rec.RunID,
		ProjectID: rec.ProjectID, ExecutorID: rec.ExecutorID, TaskID: rec.TaskID, Actor: rec.Actor,
		Scope: string(scope), IssuedAt: rec.IssuedAt, ExpiresAt: rec.ExpiresAt,
	})
}

// CloseSession implements gitproxy.SessionStore.
func (g GitStore) CloseSession(id, reason string, at time.Time) error {
	return g.closeRow(statedb.ProxySessionGit, id, reason, at, "")
}

// GitRecord reads a row back into what gitproxy.Registry.Restore takes.
func GitRecord(row statedb.ProxySessionRow) (gitproxy.SessionRecord, error) {
	scope, err := GitScopeOf(row)
	if err != nil {
		return gitproxy.SessionRecord{}, err
	}
	return gitproxy.SessionRecord{
		ID: row.SessionID, TokenSHA256: row.TokenSHA256, RepoPath: scope.RepoPath,
		RepoPatterns: scope.RepoPatterns, Upstream: scope.Upstream, Policy: scope.Policy,
		ProjectID: row.ProjectID, TaskID: row.TaskID, ExecutorID: row.ExecutorID, Actor: row.Actor,
		RunID: row.RunID, GrantID: row.GrantID, LeaseID: row.LeaseID,
		IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt,
	}, nil
}

// GitScopeOf decodes a git row's scope.
func GitScopeOf(row statedb.ProxySessionRow) (GitScope, error) {
	var scope GitScope
	if err := json.Unmarshal([]byte(row.Scope), &scope); err != nil {
		return GitScope{}, fmt.Errorf("decode the scope of git session %s: %w", row.SessionID, err)
	}
	return scope, nil
}

// ── kube ─────────────────────────────────────────────────────────────────────

// KubeScope is a Kubernetes monitor session's scope_json.
type KubeScope struct {
	ClusterURL string           `json:"cluster_url"`
	Context    string           `json:"context,omitempty"`
	Policy     kubeguard.Policy `json:"policy"`
}

// KubeStore is a kubeguard.SessionStore over the control plane's database.
type KubeStore struct{ base }

// NewKubeStore returns a store writing as holder.
func NewKubeStore(db *statedb.DB, holder func() string, onError func(kind, id, what string, err error)) KubeStore {
	return KubeStore{base{DB: db, Holder: holder, OnError: onError}}
}

// SaveSession implements kubeguard.SessionStore.
func (k KubeStore) SaveSession(rec kubeguard.SessionRecord) error {
	holder, err := k.holder()
	if err != nil {
		return err
	}
	scope, err := json.Marshal(KubeScope{ClusterURL: rec.ClusterURL, Context: rec.ContextName, Policy: rec.Policy})
	if err != nil {
		return err
	}
	return k.DB.PutProxySession(statedb.ProxySessionRow{
		Kind: statedb.ProxySessionKube, SessionID: rec.ID, TokenSHA256: rec.TokenSHA256,
		LeaseID: rec.LeaseID, GrantID: rec.GrantID, Holder: holder, RunID: rec.RunID,
		ProjectID: rec.ProjectID, ExecutorID: rec.ExecutorID, TaskID: rec.TaskID, Actor: rec.Actor,
		Scope: string(scope), IssuedAt: rec.IssuedAt, ExpiresAt: rec.ExpiresAt,
	})
}

// CloseSession implements kubeguard.SessionStore.
func (k KubeStore) CloseSession(id, reason string, at time.Time) error {
	return k.closeRow(statedb.ProxySessionKube, id, reason, at, "")
}

// KubeRecord reads a row back into what kubeguard.Registry.Restore takes.
func KubeRecord(row statedb.ProxySessionRow) (kubeguard.SessionRecord, error) {
	scope, err := KubeScopeOf(row)
	if err != nil {
		return kubeguard.SessionRecord{}, err
	}
	return kubeguard.SessionRecord{
		ID: row.SessionID, TokenSHA256: row.TokenSHA256, ClusterURL: scope.ClusterURL,
		ContextName: scope.Context, Policy: scope.Policy, ProjectID: row.ProjectID, TaskID: row.TaskID,
		ExecutorID: row.ExecutorID, Actor: row.Actor, GrantID: row.GrantID, LeaseID: row.LeaseID,
		RunID: row.RunID, IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt,
	}, nil
}

// KubeScopeOf decodes a kube row's scope.
func KubeScopeOf(row statedb.ProxySessionRow) (KubeScope, error) {
	var scope KubeScope
	if err := json.Unmarshal([]byte(row.Scope), &scope); err != nil {
		return KubeScope{}, fmt.Errorf("decode the scope of kubernetes session %s: %w", row.SessionID, err)
	}
	return scope, nil
}

// ── egress ───────────────────────────────────────────────────────────────────

// EgressScope is an egress session's scope_json.
type EgressScope struct {
	Grant  egressbroker.Grant `json:"grant"`
	Labels map[string]string  `json:"labels,omitempty"`
}

// EgressStore is an egressbroker.SessionStore over the control plane's
// database.
type EgressStore struct{ base }

// NewEgressStore returns a store writing as holder.
func NewEgressStore(db *statedb.DB, holder func() string, onError func(kind, id, what string, err error)) EgressStore {
	return EgressStore{base{DB: db, Holder: holder, OnError: onError}}
}

// SaveSession implements egressbroker.SessionStore.
func (e EgressStore) SaveSession(rec egressbroker.SessionRecord) error {
	holder, err := e.holder()
	if err != nil {
		return err
	}
	scope, err := json.Marshal(EgressScope{Grant: rec.Grant, Labels: rec.Labels})
	if err != nil {
		return err
	}
	counters, err := json.Marshal(rec.Counters)
	if err != nil {
		return err
	}
	return e.DB.PutProxySession(statedb.ProxySessionRow{
		Kind: statedb.ProxySessionEgress, SessionID: rec.ID, TokenSHA256: rec.TokenSHA256,
		GrantID: rec.GrantID, Holder: holder, RunID: rec.RunID, ProjectID: rec.ProjectID,
		ExecutorID: rec.ExecutorID, TaskID: rec.TaskID, Actor: rec.Actor, Scope: string(scope),
		Counters: string(counters), IssuedAt: rec.IssuedAt, ExpiresAt: rec.ExpiresAt,
	})
}

// ExtendSession implements egressbroker.SessionStore.
func (e EgressStore) ExtendSession(id string, expiresAt time.Time) error {
	holder, err := e.holder()
	if err != nil {
		return err
	}
	_, err = e.DB.ExtendProxySession(statedb.ProxySessionEgress, id, holder, expiresAt)
	return e.report(statedb.ProxySessionEgress, id, "record its renewal", err)
}

// CheckpointSession implements egressbroker.SessionStore. A checkpoint that
// lands on no row is an error, so the broker writes it again next time rather
// than believing the record holds it.
func (e EgressStore) CheckpointSession(id string, c egressbroker.SessionCounters) error {
	holder, err := e.holder()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	ok, err := e.DB.CheckpointProxySession(statedb.ProxySessionEgress, id, holder, string(raw))
	if err == nil && !ok {
		return errNotHeld
	}
	return e.report(statedb.ProxySessionEgress, id, "checkpoint its counters", err)
}

// CloseSession implements egressbroker.SessionStore.
func (e EgressStore) CloseSession(id, reason string, at time.Time, c egressbroker.SessionCounters) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return e.closeRow(statedb.ProxySessionEgress, id, reason, at, string(raw))
}

// EgressRecord reads a row back into what egressbroker.Broker.RestoreSession
// takes.
func EgressRecord(row statedb.ProxySessionRow) (egressbroker.SessionRecord, error) {
	var scope EgressScope
	if err := json.Unmarshal([]byte(row.Scope), &scope); err != nil {
		return egressbroker.SessionRecord{}, fmt.Errorf("decode the scope of egress session %s: %w", row.SessionID, err)
	}
	var counters egressbroker.SessionCounters
	if err := json.Unmarshal([]byte(row.Counters), &counters); err != nil {
		return egressbroker.SessionRecord{}, fmt.Errorf("decode the counters of egress session %s: %w", row.SessionID, err)
	}
	return egressbroker.SessionRecord{
		ID: row.SessionID, TokenSHA256: row.TokenSHA256, GrantID: row.GrantID, Grant: scope.Grant,
		ExecutorID: row.ExecutorID, ProjectID: row.ProjectID, TaskID: row.TaskID, RunID: row.RunID,
		Actor: row.Actor, Labels: scope.Labels, IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt,
		Counters: counters,
	}, nil
}

// EgressCounters decodes an egress row's counters, zero when they do not parse.
func EgressCounters(row statedb.ProxySessionRow) egressbroker.SessionCounters {
	var c egressbroker.SessionCounters
	_ = json.Unmarshal([]byte(row.Counters), &c)
	return c
}

// ── ci ───────────────────────────────────────────────────────────────────────

// CIProvenance is a CI relay session's provenance_json (Task 20390): which
// pipeline its rule admitted. Claims is the verified payload of the OIDC token
// the session was minted for — the job's identity, not a credential: the
// token's signature is not kept, so nothing here can be exchanged again.
type CIProvenance struct {
	RuleName   string          `json:"rule_name,omitempty"`
	Project    string          `json:"project,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	Repository string          `json:"repository,omitempty"`
	Ref        string          `json:"ref,omitempty"`
	Workflow   string          `json:"workflow,omitempty"`
	Actor      string          `json:"actor,omitempty"`
	RunID      string          `json:"run_id,omitempty"`
	RunURL     string          `json:"run_url,omitempty"`
	Claims     json.RawMessage `json:"claims,omitempty"`
}

// CIStore is a claudeproxy.SessionStore over the control plane's database,
// recording CI relay sessions in ci_sessions (Task 20390). Its writes after
// the insert are fenced on the holder, like the other stores'.
type CIStore struct {
	base
	// instance names the hub instance whose configuration governs the
	// sessions it records (ci_sessions.instance).
	instance string
}

// NewCIStore returns a store writing as holder, for the hub instance named
// instance.
func NewCIStore(db *statedb.DB, holder func() string, instance string,
	onError func(kind, id, what string, err error)) CIStore {
	return CIStore{base: base{DB: db, Holder: holder, OnError: onError}, instance: instance}
}

// ciKind names CI sessions in error reports.
const ciKind = "ci"

// SaveSession implements claudeproxy.SessionStore.
func (c CIStore) SaveSession(rec claudeproxy.SessionRecord) error {
	holder, err := c.holder()
	if err != nil {
		return err
	}
	prov, err := json.Marshal(CIProvenance{
		RuleName: rec.RuleName, Project: rec.Project, Subject: rec.Subject, Repository: rec.Repository,
		Ref: rec.Ref, Workflow: rec.Workflow, Actor: rec.Actor, RunID: rec.RunID, RunURL: rec.RunURL,
		Claims: rec.Claims,
	})
	if err != nil {
		return err
	}
	pol, err := json.Marshal(rec.Policy)
	if err != nil {
		return err
	}
	counters, err := json.Marshal(rec.Usage)
	if err != nil {
		return err
	}
	return c.DB.InsertCISession(statedb.CISessionRow{
		SessionID: rec.ID, TokenSHA256: rec.TokenSHA256, RuleID: rec.RuleID, Holder: holder, Instance: c.instance,
		Provenance: string(prov), Policy: string(pol), Counters: string(counters),
		IssuedAt: rec.IssuedAt, ExpiresAt: rec.ExpiresAt, LastUsedAt: rec.LastUsed,
	})
}

// CheckpointSession implements claudeproxy.SessionStore. A checkpoint that
// lands on no row is an error, so the registry writes it again next time
// rather than believing the record holds it.
func (c CIStore) CheckpointSession(id string, u claudeproxy.Usage, lastUsed time.Time) error {
	holder, err := c.holder()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	ok, err := c.DB.CheckpointCISession(id, holder, string(raw), lastUsed)
	if err == nil && !ok {
		// Closed or taken over by another hub process: the registry stops
		// serving it. Not reported — it is how a revocation made elsewhere
		// reaches this process.
		return claudeproxy.ErrRecordGone
	}
	return c.report(ciKind, id, "checkpoint its counters", err)
}

// CloseSession implements claudeproxy.SessionStore.
func (c CIStore) CloseSession(id, reason string, at time.Time, u claudeproxy.Usage) error {
	holder, err := c.holder()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = c.DB.CloseCISession(id, holder, at, reason, string(raw))
	return c.report(ciKind, id, "record its end", err)
}

// CIRecord reads a row back into what claudeproxy.Registry.Restore takes, and
// its provenance.
func CIRecord(row statedb.CISessionRow) (claudeproxy.SessionRecord, CIProvenance, error) {
	var prov CIProvenance
	if err := json.Unmarshal([]byte(row.Provenance), &prov); err != nil {
		return claudeproxy.SessionRecord{}, CIProvenance{}, fmt.Errorf("decode the provenance of CI session %s: %w",
			row.SessionID, err)
	}
	var pol claudeproxy.Policy
	if err := json.Unmarshal([]byte(row.Policy), &pol); err != nil {
		return claudeproxy.SessionRecord{}, CIProvenance{}, fmt.Errorf("decode the policy of CI session %s: %w",
			row.SessionID, err)
	}
	var u claudeproxy.Usage
	if err := json.Unmarshal([]byte(row.Counters), &u); err != nil {
		return claudeproxy.SessionRecord{}, CIProvenance{}, fmt.Errorf("decode the counters of CI session %s: %w",
			row.SessionID, err)
	}
	return claudeproxy.SessionRecord{
		ID: row.SessionID, TokenSHA256: row.TokenSHA256, Policy: pol, RuleID: row.RuleID,
		RuleName: prov.RuleName, Project: prov.Project, Subject: prov.Subject, Repository: prov.Repository,
		Ref: prov.Ref, Workflow: prov.Workflow, Actor: prov.Actor, RunID: prov.RunID, RunURL: prov.RunURL,
		Claims: prov.Claims, IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt, Usage: u, LastUsed: row.LastUsedAt,
	}, prov, nil
}

// Interface checks.
var (
	_ gitproxy.SessionStore     = GitStore{}
	_ kubeguard.SessionStore    = KubeStore{}
	_ egressbroker.SessionStore = EgressStore{}
	_ claudeproxy.SessionStore  = CIStore{}
)
