package ui

// claude_sweep.go: every hub member removes, from its own tree, the Claude
// Code homes of identities the control plane denies (Task 20422).
//
// An offboarding ends a departed identity's Claude logins on every member it
// reaches (offboard_claude.go), and only names a member that did not answer,
// or a stopped member's tree on a host that is still up. Each copy it could
// not reach keeps the person's OAuth refresh token in plaintext. So each
// member also sweeps its own tree — as it starts, which is when a stopped
// member's tree is read again, and then on the retention timer's hourly
// cadence: every member, not only the leader, because every member keeps a
// tree of its own. Which identities count is offboard.DeniedIdentities:
// denied hub-wide, except by a SCIM suspension still in force, and under no
// legal hold. Each removal is audited as user.claude_home_swept, and `cloop
// hub doctor` reports what is left on its host (offboard.claude_homes).

import (
	"context"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// claudeSweepInterval is how often a member sweeps after its first: the
// retention timer's cadence.
const claudeSweepInterval = retentionCheckInterval

// watchDeniedClaudeHomes sweeps as the member starts, then every
// claudeSweepInterval, until ctx ends.
func (s *Server) watchDeniedClaudeHomes(ctx context.Context) {
	defer recoverGoroutine("watchDeniedClaudeHomes")
	s.sweepDeniedClaudeHomes("startup")
	t := time.NewTicker(claudeSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepDeniedClaudeHomes("timer")
		}
	}
}

// sweepDeniedClaudeHomes removes this member's copies of the Claude homes of
// denied identities — cancelling a login in flight, logging each out where
// this hub may run the CLI, then removing it — audits each, and returns what
// it did. A member with no tree has nothing to sweep, and creates none.
func (s *Server) sweepDeniedClaudeHomes(trigger string) []offboard.ClaudeHomeResult {
	root := s.claudeRoot()
	if root == "" {
		return nil
	}
	if _, err := os.Lstat(root); err != nil {
		return nil
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		s.logClaudeSweep("open the control plane", err)
		return nil
	}
	defer db.Close()
	denied, _, err := offboard.DeniedIdentities(db)
	if err != nil {
		s.logClaudeSweep("read the denied identities", err)
		return nil
	}
	if len(denied) == 0 {
		return nil
	}
	local := s.offboardLocalClaude()
	local.Root = root
	homes, _, err := local.Inspect(offboard.OwnerKeysOf(denied))
	if err != nil {
		s.logClaudeSweep("look for their homes", err)
		return nil
	}
	if len(homes) == 0 {
		return nil
	}
	denies := map[string][]string{}
	for _, id := range denied {
		for _, k := range id.Keys {
			denies[k] = id.Denies
		}
	}
	var keys []string
	for _, h := range homes {
		keys = append(keys, h.OwnerKey)
	}
	results, _, err := local.Sever(keys, false, "", "")
	if err != nil {
		s.logClaudeSweep("remove their homes", err)
	}
	member, host := "", ""
	if n := s.clusterNode(); n != nil {
		member, host = n.ID(), n.Self().Hostname
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	actor := "hub"
	if member != "" {
		actor = "hub:" + member
	}
	for _, r := range results {
		s.auditClaudeSweep(db, actor, map[string]any{
			"identity": r.OwnerKey, "member": member, "host": host, "dir": r.Dir, "denies": denies[r.OwnerKey],
			"had_login": r.Credential, "login_cancelled": r.LoginCancelled, "logged_out": r.LoggedOut,
			"logout": r.Logout, "removed": r.Removed, "error": r.Error, "trigger": trigger,
		})
		s.log().Info(logger.EventAuthz, 0, "removed the Claude Code home of an identity the control plane denies",
			map[string]interface{}{"identity": r.OwnerKey, "dir": r.Dir, "removed": r.Removed, "error": r.Error,
				"trigger": trigger})
	}
	return results
}

// auditClaudeSweep writes one user.claude_home_swept row.
func (s *Server) auditClaudeSweep(db *statedb.DB, actor string, payload map[string]any) {
	blob := statedb.MarshalAuditPayload(payload)
	identity, _ := payload["identity"].(string)
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		EventType:  string(auditaction.ActionUserClaudeHomeSwept),
		EntityType: "user",
		EntityID:   identity,
		Payload:    blob,
	}); err != nil {
		s.logClaudeSweep("record a removal", err)
	}
}

func (s *Server) logClaudeSweep(what string, err error) {
	s.log().Warn(logger.EventAuthz, 0, "Claude home sweep: "+what,
		map[string]interface{}{"error": err.Error()})
}
