package ui

// model_relay_lease.go: a run's model relay session stands on the run's
// secret lease (Task 20435), as its git proxy session does. It is extended
// when the lease is, ended when the lease is released or revoked and when its
// grant is taken back, suspended when another hub process takes the lease over
// with the run, and restored there with it — its credential re-derived from
// the grant, its model policy held to today's.

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// closeModelRelaySessions ends the relay sessions leaseID's credential fed.
func closeModelRelaySessions(leaseID, reason string) {
	if svc := activeModelRelay(); svc != nil && leaseID != "" {
		svc.reg.CloseForLease(leaseID, reason)
	}
}

// suspendModelRelaySessions stops serving the relay sessions leaseID feeds
// without ending them, for the hub process that took the lease over.
func suspendModelRelaySessions(leaseID, reason string) {
	if svc := activeModelRelay(); svc != nil && leaseID != "" {
		releaseSuspendedSessions(ownerModelRelay, svc.reg.SuspendForLease(leaseID, reason))
	}
}

// closeModelRelayGrantSessions ends the relay sessions standing on leaseID
// whose credential came from grantID, taken back from the lease.
func closeModelRelayGrantSessions(leaseID, grantID, reason string) {
	if svc := activeModelRelay(); svc != nil && leaseID != "" && grantID != "" {
		svc.reg.CloseForGrant(leaseID, grantID, reason)
	}
}

// extendModelRelaySessions moves the relay sessions the lease feeds to the
// lease's deadline, after the keepalive extended it: a session lasts exactly
// as long as the lease it stands on.
func (sl *secretLease) extendModelRelaySessions() {
	svc := activeModelRelay()
	if svc == nil || sl == nil || sl.lease == nil {
		return
	}
	until := sl.ExpiresAt()
	for _, s := range svc.reg.LeaseSessions(sl.lease.ID) {
		if s.Deadline().Before(until) {
			_, _ = svc.reg.Extend(s.ID, until)
		}
	}
}

// relayKeyMatchesKind reports whether a binding's variable is one a credential
// of kind is granted in, so a record cannot point a restore at another of the
// grant's variables.
func relayKeyMatchesKind(key, kind string) bool {
	switch kind {
	case relayKindOAuth:
		return key == envClaudeOAuthToken
	case relayKindAPIKey:
		return key == envAnthropicAPIKey || key == envCloopAnthropicKey
	}
	return false
}

// restoreModelSession brings back a relay session the lease sl has taken over
// feeds. Nothing in the record decides what is spent or where: the credential
// is re-derived from the lease's grant, the upstream is this hub's
// configuration, and the model policy is held to what the hub and the project
// allow now — never wider than what the session was minted with.
func (sl *secretLease) restoreModelSession(row statedb.ProxySessionRow, from string) error {
	svc := activeModelRelay()
	if svc == nil {
		return refusedf("this hub process runs no model relay to serve it")
	}
	if s, ok := svc.reg.Session(row.SessionID); ok {
		if s.Closed() {
			return refusedf("the session was closed by this hub process: %s", s.CloseReason())
		}
		return errSessionLive
	}
	rec, spend, err := sessionrecord.ModelRecord(row)
	if err != nil {
		return refusedf("%v", err)
	}
	if rec.LeaseID != sl.lease.ID {
		return refusedf("it stands on lease %s, not %s", rec.LeaseID, sl.lease.ID)
	}
	var b modelRelayBinding
	if err := json.Unmarshal(rec.Claims, &b); err != nil || strings.TrimSpace(b.WorkDir) == "" {
		return refusedf("its run binding cannot be read")
	}
	if !relayProven(rec.UpstreamKind) {
		return refusedf("a %s is not relayed by this hub", relayKindLabel(rec.UpstreamKind))
	}
	now, err := svc.policyFor(b.WorkDir)
	if err != nil {
		return refusedf("%v", err)
	}
	narrowed, err := claudeproxy.Narrow(rec.Policy, now)
	if err != nil {
		return refusedf("%v", err)
	}
	rec.Policy = narrowed
	// Never past the lease it stands on.
	if exp := sl.ExpiresAt(); !exp.IsZero() && rec.ExpiresAt.After(exp) {
		rec.ExpiresAt = exp
	}
	if err := svc.reg.CheckRestore(rec); err != nil {
		switch {
		case errors.Is(err, claudeproxy.ErrSessionExists):
			return errSessionLive
		case errors.Is(err, claudeproxy.ErrSessionLapsed):
			return refusedf("%v", err)
		}
		return refusedf("%v", err)
	}
	var cred relayCredential
	if b.Hub {
		c, ok := svc.hubCredentialForIDs(b.WorkDir, rec.ExecutorID)
		if !ok {
			return refusedf("the hub's own key is no longer allowed for its project or executor")
		}
		cred = c
	} else {
		if !relayKeyMatchesKind(b.Key, rec.UpstreamKind) {
			return refusedf("its record names %s for a %s", b.Key, relayKindLabel(rec.UpstreamKind))
		}
		v, err := sl.broker.EnvUpstream(sl.lease.ID, rec.GrantID, b.Key)
		if err != nil {
			return err
		}
		cred = relayCredential{Key: b.Key, Kind: rec.UpstreamKind, GrantID: rec.GrantID, value: v}
	}
	up := svc.upstream(cred)
	if up.Kind() != rec.UpstreamKind {
		return refusedf("its credential is now a %s, not a %s", relayKindLabel(up.Kind()),
			relayKindLabel(rec.UpstreamKind))
	}
	// The account first: a call held for this restore is served the moment
	// Restore returns, and what it spends adds to what the session had
	// reached rather than being overwritten by it.
	svc.seedSpend(rec.ID, spend)
	s, err := svc.reg.Restore(claudeproxy.RestoreRequest{Record: rec, From: from, Upstream: &up})
	if err != nil {
		svc.dropSpend(rec.ID)
		if errors.Is(err, claudeproxy.ErrSessionExists) {
			return errSessionLive
		}
		return refusedf("%v", err)
	}
	logModelRelay(b.WorkDir, "Model relay session "+s.ID+" restored by the hub process that adopted the run; "+
		"the run's model calls carry on through it.")
	return nil
}
