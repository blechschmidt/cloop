package ui

// Approval notifications as the cluster leader's duty (Task 20427).
//
// pkg/approvalnotify scans the control plane for moments worth telling an
// approver, records each once, and posts it to the webhooks in
// notifications.webhooks. This file decides the rest: that it runs on the
// leader alone — so a cluster of hubs tells a channel once, not once per
// member — what configuration it runs under (the hub's own, overlay included),
// where a url_env is read (this process's environment), what the dashboard
// link is, and what the hub's own dashboards hear when the scan finds a request
// lapsed or a token waiting: the same opaque broadcasts a decision produces.
//
// The leader is nudged when something changes rather than left to its poll:
// locally when this member handled the change, and over the cluster bus when
// another member did.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/approvalnotify"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretstore"
)

// invalidateApprovals: a grant request or a token changed on another member
// (or the CLI); the leader runs a notification pass now.
const invalidateApprovals = "approvals"

// approvalNotifyState is this member's notifier plumbing.
type approvalNotifyState struct {
	once  sync.Once
	nudge chan struct{}

	// Tests steer these: how often a pass runs with nothing nudging it, and
	// the clock it runs on.
	mu   sync.Mutex
	poll time.Duration
	now  func() time.Time
}

func (st *approvalNotifyState) nudges() chan struct{} {
	st.once.Do(func() { st.nudge = make(chan struct{}, 1) })
	return st.nudge
}

// nudgeApprovalNotify asks the notifier for a pass now: here, and — through
// the bus — on whichever member leads.
func (s *Server) nudgeApprovalNotify() {
	s.nudgeLocalApprovalNotify()
	s.publishInvalidate(invalidateApprovals, nil)
}

func (s *Server) nudgeLocalApprovalNotify() {
	select {
	case s.approvalNotify.nudges() <- struct{}{}:
	default:
	}
}

// watchApprovalNotices is the leader duty. It returns when ctx ends, which is
// when this member stops leading or the hub stops.
func (s *Server) watchApprovalNotices(ctx context.Context) {
	defer recoverGoroutine("watchApprovalNotices")
	st := &s.approvalNotify
	st.mu.Lock()
	poll, now := st.poll, st.now
	st.mu.Unlock()

	eng := approvalnotify.New(approvalnotify.Options{
		OpenDB:   s.controlPlaneDB,
		Settings: s.approvalNotifySettings,
		Snapshot: s.approvalNotifySnapshot,
		Record: func(sink, event, outcome string) {
			hubmetrics.ApprovalNotifications.Inc(sink, event, outcome)
		},
		Now:        now,
		Poll:       poll,
		Nudge:      st.nudges(),
		OnRecorded: s.onApprovalNoticesRecorded,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[approval-notify] "+format+"\n", args...)
		},
	})
	eng.Run(ctx)
}

// onApprovalNoticeRecorded tells this hub's dashboards about the moments only
// the scan observes. A token starts waiting when a policy comes into force
// over it, which no handler sees happen; a request lapses when its deadline
// passes, which the hourly expiry sweep would otherwise be the first to say —
// so the sweep is run now, and its broadcast refreshes the badges and the
// requester's panel. A request filed, decided or withdrawn through `cloop hub
// grant` on the hub's host, or by an offboarding run there, reaches no handler
// either; its notice is announced with the verb a handler would have used. A
// change a handler did make is announced twice, a few hundred milliseconds
// apart, which costs each dashboard one more count and tells the requester
// nothing twice (33-approvals.js says a decision once).
func (s *Server) onApprovalNoticesRecorded(notices []approvalnotify.Notice) {
	lapsed := false
	for _, n := range notices {
		switch n.Event {
		case config.NotifyEventTokenWaiting:
			s.broadcastApprovalsNotice("token_waiting", n.TokenID)
		case config.NotifyEventRequestLapsed:
			lapsed = true
		case config.NotifyEventRequestFiled:
			s.broadcastApprovalsNotice("request_created", n.RequestID)
		case config.NotifyEventRequestApproved:
			s.broadcastApprovalsNotice("request_approved", n.RequestID)
		case config.NotifyEventRequestDenied:
			s.broadcastApprovalsNotice("request_denied", n.RequestID)
		case config.NotifyEventRequestWithdrawn:
			s.broadcastApprovalsNotice("request_withdrawn", n.RequestID)
		}
	}
	if lapsed {
		// One sweep for every lapse the pass found: it moves them all, and
		// broadcasts once.
		go func() {
			defer recoverGoroutine("expire lapsed grant requests")
			s.expireGrantRequests()
		}()
	}
}

// approvalNotifySettings reads notifications from the hub's effective
// configuration, overlay included.
func (s *Server) approvalNotifySettings() (approvalnotify.Settings, error) {
	cfg, err := s.loadHubConfig()
	if err != nil {
		return approvalnotify.Settings{}, err
	}
	if cfg == nil {
		return approvalnotify.Settings{}, nil
	}
	return approvalnotify.Settings{Webhooks: cfg.Notifications.Webhooks, Link: s.approvalsLink(cfg)}, nil
}

// approvalsLink is the address a message points at: the dashboard, opened on
// the approvals inbox. notifications.dashboard_url, then this hub's external
// URL, then the origin people sign in at; with none of them, no link — a
// message pointing at the hub's loopback listener would be a link nobody who
// reads the channel can follow.
func (s *Server) approvalsLink(cfg *config.Config) string {
	base := strings.TrimSpace(cfg.Notifications.DashboardURL)
	if base == "" {
		base = strings.TrimSpace(s.ExternalURL)
	}
	if base == "" {
		base = strings.TrimSpace(cfg.UI.ExternalURL)
	}
	if base == "" {
		if pub, key := cfg.UI.PublicURL(); key == "ui.oidc.redirect_url" {
			if u, err := url.Parse(strings.TrimSpace(pub)); err == nil && u.Scheme != "" && u.Host != "" {
				base = u.Scheme + "://" + u.Host
			}
		}
	}
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	u.Path = strings.TrimSuffix(u.Path, "/") + "/"
	u.RawQuery = "approvals=1"
	return u.String()
}

// approvalNotifySnapshot reads what the scan looks at: every access request
// (no key needed — a request carries no material) and, under an enforced
// role policy, the tokens it suspends until approved.
func (s *Server) approvalNotifySnapshot(context.Context) (approvalnotify.Snapshot, error) {
	var snap approvalnotify.Snapshot
	db, err := s.controlPlaneDB()
	if err != nil {
		return snap, err
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		return snap, err
	}
	reqs, err := store.ListAccessRequests()
	if err != nil {
		return snap, err
	}
	snap.Requests, snap.RequestsKnown = reqs, true

	// Without an enforced policy no token is suspended: nothing is waiting,
	// and that is known.
	snap.TokensKnown = true
	if !s.authzActive() {
		return snap, nil
	}
	mgr, err := s.tokenManager()
	if err != nil {
		snap.TokensKnown = false
		return snap, nil
	}
	tokens, err := mgr.List()
	if err != nil {
		snap.TokensKnown = false
		return snap, nil
	}
	now := time.Now()
	for i := range tokens {
		t := &tokens[i]
		if t.Active(now) && t.AwaitsApproval() {
			snap.Waiting = append(snap.Waiting, approvalnotify.TokenInfo{
				ID: t.ID, Name: t.Name, Roles: append([]string(nil), t.Roles...),
				CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
			})
		}
	}
	return snap, nil
}
