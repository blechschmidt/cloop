package ui

// Audit forwarding as the cluster leader's duty (Task 20426).
//
// pkg/auditforward ships every chain's rows to the sinks in audit.forward,
// advancing a durable cursor per sink and chain in the control plane only when
// a sink acknowledges. This file decides the rest: that it runs on the leader
// alone — so a cluster sends each row once per sink rather than once per
// member — which chains it tails (the control plane, then every registered
// project, each database once: the same list the checkpoints pin), where its
// credentials come from (the hub's secret store, never config.yaml), and which
// configuration it runs under (the hub's own, overlay included).
//
// A follower holds no forwarder. Leadership passing to another member cancels
// this one's duty mid-send if need be; the new leader reads the cursors from
// the database and sends again whatever was not acknowledged.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/auditforward"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/version"
)

// auditForwardState is this member's forwarder while it leads.
type auditForwardState struct {
	mu  sync.Mutex
	fwd *auditforward.Forwarder
	// refused is the sinks the last configuration read refused, for the
	// audit row recording a change.
	refused []string

	// Tests steer these: how often a caught-up sink polls and the
	// configuration is re-read, and where a process would die.
	poll, configPoll time.Duration
	hooks            auditforward.Hooks
}

func (st *auditForwardState) current() *auditforward.Forwarder {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.fwd
}

func (st *auditForwardState) set(f *auditforward.Forwarder) {
	st.mu.Lock()
	st.fwd = f
	st.mu.Unlock()
}

// watchAuditForward is the leader duty. It returns when ctx ends, which is
// when this member stops leading or the hub stops.
func (s *Server) watchAuditForward(ctx context.Context) {
	defer recoverGoroutine("watchAuditForward")
	st := &s.auditForward
	st.mu.Lock()
	poll, configPoll, hooks := st.poll, st.configPoll, st.hooks
	st.mu.Unlock()

	cp := state.DBPath(s.WorkDir)
	if abs, err := filepath.Abs(cp); err == nil {
		cp = abs
	}
	fwd, err := auditforward.New(auditforward.Options{
		ControlPlane: cp,
		Config:       s.auditForwardConfig,
		ConfigSource: s.auditForwardConfigSource(),
		Refused:      s.auditForwardRefused,
		Chains:       s.auditForwardChains,
		Credentials:  s.auditForwardCredential,
		Version:      version.String(),
		Poll:         poll,
		ConfigPoll:   configPoll,
		Hooks:        hooks,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[audit-forward] "+format+"\n", args...)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[audit-forward] not started: %v\n", err)
		return
	}
	st.set(fwd)
	defer st.set(nil)
	fwd.Run(ctx)
}

// auditForwardConfig reads audit.forward from the hub's effective
// configuration, and remembers which sinks loading refused.
func (s *Server) auditForwardConfig() (config.AuditForwardConfig, error) {
	cfg, err := s.loadHubConfig()
	if err != nil {
		return config.AuditForwardConfig{}, err
	}
	if cfg == nil {
		return config.AuditForwardConfig{}, nil
	}
	var refused []string
	for _, r := range cfg.LoadRepairs() {
		if auditforward.IsSinkRepair(r) {
			refused = append(refused, strings.TrimPrefix(r.SwitchedOff, "audit.forward.sinks."))
		}
	}
	s.auditForward.mu.Lock()
	s.auditForward.refused = refused
	s.auditForward.mu.Unlock()
	return cfg.Audit.Forward, nil
}

func (s *Server) auditForwardRefused() []string {
	s.auditForward.mu.Lock()
	defer s.auditForward.mu.Unlock()
	return append([]string(nil), s.auditForward.refused...)
}

// auditForwardConfigSource names the files the configuration is read from.
func (s *Server) auditForwardConfigSource() string {
	src := config.ConfigPath(s.WorkDir)
	if overlay := s.hubConfigOverlay(); overlay != "" {
		src += " + " + overlay
	}
	return src
}

// auditForwardChains is every chain the hub serves: the control plane, then
// each registered project with a database, each file once.
func (s *Server) auditForwardChains() []auditforward.Chain {
	var out []auditforward.Chain
	for _, c := range s.auditCheckpointChains() {
		source := auditforward.SourceProject
		if c.chain == auditcheckpoint.ChainControlPlane {
			source = auditforward.SourceControlPlane
		}
		out = append(out, auditforward.Chain{Source: source, Dir: c.dir, Path: c.path})
	}
	return out
}

// auditForwardCredential opens a secret a sink presents — its HEC token, its
// client key — from the hub's secret store.
func (s *Server) auditForwardCredential(ref string) ([]byte, error) {
	bs, err := s.openBrokers()
	if err != nil {
		return nil, err
	}
	defer bs.close()
	if bs.secret == nil {
		return nil, fmt.Errorf("%s: %s", bs.status.Reason, bs.status.Remediation)
	}
	return bs.secret.HubCredential(ref)
}

// collectAuditForward publishes each sink's lag and backlog. Leader only: the
// rows and cursors are the shared database's, and every member exporting them
// would multiply them under sum(). A member that is not leading holds no
// forwarder, so its scrape exports nothing for them either way.
func collectAuditForward(sc *metricsScrape) {
	if !sc.leader {
		return
	}
	fwd := sc.srv.auditForward.current()
	if fwd == nil {
		return
	}
	now := time.Now()
	for _, st := range fwd.Snapshot() {
		hubmetrics.AuditForwardLag.Set(st.Lag(now).Seconds(), st.Name)
		hubmetrics.AuditForwardBacklog.Set(float64(st.Backlog()), st.Name)
	}
}
