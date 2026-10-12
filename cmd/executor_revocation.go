package cmd

// executor_revocation.go: what `cloop executor cordon|drain|revoke` tell the
// running hubs, and how their answers are reported (Task 20424).
//
// Each command changes the store and then announces the change on the hub bus
// (ui.AnnounceExecutorRevocation): the member holding an edge device's session
// takes the device's leases back, and for a revoked agent every member drops
// it. This file prints, member by member, what they did — and, as plainly,
// what is still pending and what nobody could do.

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// executorRevocationWait is how long a cordon, drain or revoke waits for the
// running hubs to answer. A var so tests can shorten it.
var executorRevocationWait = 30 * time.Second

// announceExecutorRevocation records the change's lease revocations, tells the
// running hubs, and prints what they answered.
func announceExecutorRevocation(db *statedb.DB, id, op, reason string) {
	rep, err := ui.AnnounceExecutorRevocation(db, cliOrigin(), ui.ExecutorRevocationAnnouncement{
		ExecutorID: id, Op: op, Reason: reason, Actor: operatorActor(),
	}, executorRevocationWait)
	printExecutorRevocationReport(id, op, rep, err, executorRevocationWait)
}

// printExecutorRevocationReport says what the running hubs did about a change
// this process announced.
func printExecutorRevocationReport(id, op string, rep ui.ExecutorRevocationReport, err error, wait time.Duration) {
	faint := color.New(color.Faint)
	warn := color.New(color.FgYellow)
	if err != nil {
		warn.Printf("  The running hubs could not be told: %v\n", err)
		faint.Println("  A hub's lease janitor finds a revocation recorded in the store at its next pass, within a")
		faint.Println("  minute; until then the device keeps what it holds.")
		return
	}
	if rep.Device == "" {
		faint.Printf("  %s runs on the hub itself, not on an edge device: this takes no credential back from it,\n"+
			"  and its running workloads keep their leases until they end.\n", id)
		return
	}
	switch n := len(rep.Recorded); {
	case n == 0:
		faint.Printf("  No lease is recorded as issued to %s.\n", id)
	default:
		fmt.Printf("  %d lease(s) recorded as issued to %s are recorded revoked: %s\n", n, id, strings.Join(rep.Recorded, ", "))
	}
	if rep.NoHub {
		faint.Println("  No hub is serving this control plane. The revocations are recorded: the next hub to start")
		faint.Println("  takes the leases back with its lease janitor, and no hub restores their sessions meanwhile.")
		if op == ui.ExecutorOpRevoke {
			faint.Println("  The agent is refused when it next connects, so its device cannot be reached again: what")
			faint.Println("  it already holds stays there. Rotate at the source whatever it held.")
		} else {
			faint.Println("  The device gives them back when it next connects to a hub.")
		}
		return
	}

	disconnected := false
	for _, m := range rep.Answered {
		where := "hub member " + m.Member
		if m.Hostname != "" {
			where += " on " + m.Hostname
		}
		switch {
		case m.Refused != "":
			warn.Printf("  %s did not act: %s\n", where, m.Refused)
			continue
		case m.HoldsSession:
			fmt.Printf("  %s holds %s's connection", where, rep.Device)
		case m.Acted:
			fmt.Printf("  %s (no member holds %s's connection; it leads)", where, rep.Device)
		default:
			fmt.Printf("  %s does not hold %s's connection", where, rep.Device)
		}
		switch {
		case m.Acted && len(m.Leases) == 0:
			fmt.Print(": no lease to take back")
		case m.Acted:
			fmt.Printf(": took back %d lease(s)", len(m.Leases))
		}
		if m.Disconnected {
			disconnected = true
			fmt.Print(", and dropped the agent")
		} else if op == ui.ExecutorOpRevoke {
			fmt.Print("; the agent is out of its registry")
		}
		fmt.Println()
		for _, l := range m.Leases {
			line := fmt.Sprintf("    lease %s: %s", l.LeaseID, l.State)
			if l.State != remote.RevokeStateRevoked && l.Detail != "" {
				line += " — " + l.Detail
			}
			fmt.Println(line)
		}
	}
	for _, member := range rep.Silent {
		warn.Printf("  hub member %s did not answer within %s: it may still be acting, and its lease janitor\n"+
			"  enforces the recorded revocations at its next pass if it missed this announcement\n", member, wait)
	}
	if rep.Exclusive != "" {
		warn.Printf("  hub %s %s\n", rep.Exclusive, rep.ExclusiveDetail)
	}
	if op == ui.ExecutorOpRevoke && !disconnected {
		faint.Printf("  No hub member held %s's connection: it is refused when it next connects.\n", rep.Device)
	}

	var pending []ui.LeaseRevocationState
	for _, l := range rep.Leases {
		if l.Pending {
			pending = append(pending, l)
		}
	}
	switch {
	case len(pending) > 0:
		warn.Printf("  %d lease(s) still pending:\n", len(pending))
		for _, l := range pending {
			detail := l.Detail
			if detail == "" {
				detail = "not yet taken back from the device"
			}
			warn.Printf("    %s: %s\n", l.LeaseID, detail)
		}
	case len(rep.Leases) > 0:
		color.Green("  Every recorded lease was taken back.")
	}
}
