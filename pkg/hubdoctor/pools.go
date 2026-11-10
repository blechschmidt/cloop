package hubdoctor

// Executor pools (Task 20486): whether each pool's runs can be started.
//
// A pool's runners are started by a controller outside the hub, so a pool can
// look healthy from the hub's side — defined, bound, its runs queued in order —
// while nothing will ever start them. This check reads the pool's queue, its
// runners and what its controllers last told the hub, and reports through
// executorpool.Assess, the same function the dashboard's pool list calls:
//
//   - runs waiting and no controller in contact — no live credential, none
//     ever used, or none used for ten minutes — fail: those runs never start;
//   - runs waiting for ten minutes while the pool has every runner
//     max_runners allows, or while it is cordoned, warn;
//   - a controller reporting runner volumes stuck Pending, or other trouble
//     that keeps runners from starting, warn;
//   - a controller speaking an older pool-controller protocol than this hub,
//     warn: the hub tells it things it does not act on.
//
// Read from the hub's database, so it works from the CLI with the hub stopped
// and in the Hub health panel alike.

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The check ids, by what a problem is about.
const (
	poolsCheck         = "executors.pools"
	poolsContactCheck  = "executors.pools.contact"
	poolsCapacityCheck = "executors.pools.capacity"
	poolsStorageCheck  = "executors.pools.storage"
	poolsProtocolCheck = "executors.pools.protocol"
)

// poolsNow is the check's clock; tests pin it.
var poolsNow = time.Now

// poolProblemCheck files a problem under its check id.
func poolProblemCheck(kind string) string {
	switch kind {
	case executorpool.ProblemNoController, executorpool.ProblemNoContact:
		return poolsContactCheck
	case executorpool.ProblemAtMax, executorpool.ProblemNotStarting, executorpool.ProblemCordoned:
		return poolsCapacityCheck
	case executorpool.ProblemStorage, executorpool.ProblemPVCsPending:
		return poolsStorageCheck
	case executorpool.ProblemBehind:
		return poolsProtocolCheck
	}
	return poolsCheck
}

func checkExecutorPools(dir string, add addFn) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return // no database, no pools; storage says the rest
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		add(Finding{Check: poolsCheck, Title: "Executor pools", Severity: SeverityWarn,
			Message:     fmt.Sprintf("the executor pools could not be read: %v", err),
			Remediation: "Check the storage findings above; executor pools live in .cloop/state.db"})
		return
	}
	defer func() { _ = db.Close() }()
	store := executorpool.NewStore(db.AsControlPlane()).WithClock(poolsNow)
	pools, err := store.List()
	if err != nil {
		add(Finding{Check: poolsCheck, Title: "Executor pools", Severity: SeverityWarn,
			Message:     fmt.Sprintf("the executor pools could not be read: %v", err),
			Remediation: "Check the storage findings above; executor pools live in .cloop/state.db"})
		return
	}
	for _, p := range pools {
		if p.Revoked() {
			continue
		}
		title := "Executor pool " + p.Name
		in, err := store.HealthInputFor(p)
		if err != nil {
			add(Finding{Check: poolsCheck, Title: title, Severity: SeverityWarn,
				Message:     fmt.Sprintf("executor pool %s could not be read: %v", p.Name, err),
				Remediation: "Check the storage findings above",
				Details:     map[string]any{"pool": p.Name, "pool_id": p.ID}})
			continue
		}
		problems := executorpool.Assess(in)
		for _, pr := range problems {
			sev := SeverityWarn
			if pr.Severity == executorpool.SeverityFail {
				sev = SeverityFail
			}
			details := map[string]any{"pool": p.Name, "pool_id": p.ID, "problem": pr.Kind, "waiting": in.Waiting,
				"runners": in.Runners, "max_runners": p.MaxRunners}
			if pr.CredentialID != "" {
				details["credential_id"] = pr.CredentialID
			}
			add(Finding{Check: poolProblemCheck(pr.Kind), Title: title, Severity: sev, Message: pr.Message,
				Remediation: pr.Remedy, Details: details})
		}
		if len(problems) > 0 {
			continue
		}
		add(Finding{Check: poolsCheck, Title: title, Severity: SeverityPass, Message: poolSummary(p, in),
			Details: map[string]any{"pool": p.Name, "pool_id": p.ID, "waiting": in.Waiting, "runners": in.Runners,
				"max_runners": p.MaxRunners}})
	}
}

// poolSummary says how a pool without problems stands.
func poolSummary(p executorpool.Pool, in executorpool.HealthInput) string {
	state := "live"
	if p.Cordoned() {
		state = "cordoned"
	}
	msg := fmt.Sprintf("executor pool %s is %s: %d of %d runners, %d run(s) waiting", p.Name, state, in.Runners,
		p.MaxRunners, in.Waiting)
	if c, ok := in.Controller(); ok {
		build := c.ControllerVersion
		if build == "" {
			build = "an unnamed build"
		}
		msg += fmt.Sprintf("; its controller (%s, protocol %d) last contacted the hub at %s", build,
			c.ControllerProtocol, c.LastUsedAt.UTC().Format("2006-01-02 15:04 UTC"))
	} else {
		msg += "; no controller has contacted the hub yet"
	}
	return msg
}
