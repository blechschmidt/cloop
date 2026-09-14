package cmd

// Shared plumbing for the incident-response commands — `cloop hub session`,
// `cloop hub quota` and `cloop hub role` (Task 20248).
//
// These exist because every emergency lever on the hub used to be reachable
// only through the Web UI or hand-written curl. On-call could not script a
// session revocation, could not cap a runaway tenant without a browser, and
// could not demote a compromised administrator at all without editing config
// and redeploying. They write to the control-plane database directly, which is
// what lets them work when the HTTP listener does not.
//
// # The lease rule
//
// A running hub also reads these tables, so writing behind its back risks the
// divergence the Task 20214 lease exists to prevent. Whether it actually does
// depends on *how* the hub reads each table, and that differs — so the rule is
// per-table and argued rather than assumed:
//
//   - quota overrides are loaded into the enforcer's memory once at startup
//     and never re-read. A write behind a live hub is invisible until it
//     restarts, and worse, the next override the hub writes from the panel
//     overwrites it. That is exactly the silent divergence the fence is for,
//     so these commands take the lease and refuse when it is held, pointing
//     at the REST endpoint that goes through the enforcer instead.
//
//   - role bindings are read through a TTL-cached source (pkg/rolestore) on
//     every authorization decision, so a write converges within
//     rolestore.DefaultTTL whether or not a hub is running. Taking the lease
//     is unnecessary and refusing would be actively wrong: the whole point of
//     an emergency demotion is that it works while the hub is up.
//
//   - sessions are re-read from SQLite on every cache miss, with the 30-second
//     TTL pkg/oidcauth already accepts as the revocation bound across
//     replicas. Same treatment as role bindings, and the reason `session
//     revoke` still works when the listener is wedged.
//
// Anything added here that a hub caches for its lifetime belongs in the first
// group.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// openHubDB opens the hub's own control-plane database.
//
// Refuses to create one. `cloop hub token` has the same rule and the same
// reason: a mistyped --workdir that silently produced an empty database would
// answer "no sessions" and "no bindings" to somebody running an incident, and
// those are the two answers they would most like to believe.
func openHubDB(workdir string) (*statedb.DB, func(), error) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, nil, fmt.Errorf("resolve working directory: %w", err)
		}
		workdir = wd
	}
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, fmt.Errorf(
			"no cloop state database at %s — run this from the hub's directory, "+
				"or pass --workdir", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", dbPath, err)
	}
	return db, func() { _ = db.Close() }, nil
}

// warnIfNotAHub prints a warning when no hub has ever run in workdir.
//
// openHubDB only proves a cloop database exists, and every cloop project has
// one — so running an incident command one directory off from the hub writes a
// perfectly valid binding into a database nothing will ever read, and prints a
// confident success. The lease table is the discriminator: a directory a hub
// has served from carries a hub_instances row forever, released or not, and one
// that has not carries none.
//
// A warning rather than a refusal. The signal is good but not perfect — a hub
// restored from backup onto a fresh volume has not taken a lease yet — and
// refusing to contain an account because of a heuristic is the wrong failure.
// Written to stderr so it cannot be mistaken for part of a --json payload.
func warnIfNotAHub(workdir string) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return
		}
		workdir = wd
	}
	st, err := hublease.Inspect(hublease.Options{DBPath: state.DBPath(workdir)})
	if err != nil || st.Present {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: no cloop hub has ever run in %s — if this is a managed project\n"+
			"         rather than the hub's own directory, this change will have no effect.\n"+
			"         Pass --workdir <hub directory> to be sure.\n", workdir)
}

// requireHubLease takes the control-plane lease for the duration of a command
// that writes state a running hub holds in memory.
//
// Returns a release function on success. On conflict it returns an error that
// names the holder and the REST route to use instead — `alternative` — because
// "the lease is held" is not actionable on its own to somebody who just wants
// the tenant capped.
//
// There is deliberately no --force, matching `cloop hub lease clear`. Forcing
// past a live hub would not make the write land any better: the hub would keep
// serving from the value it loaded at startup and overwrite this one at the
// next edit, so the operator would be told it worked and it would not have.
func requireHubLease(workdir, alternative string) (func(), error) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve working directory: %w", err)
		}
		workdir = wd
	}
	lease, err := hublease.Acquire(hublease.Options{
		DBPath:  state.DBPath(workdir),
		Address: "cli",
		Version: Version(),
	})
	var conflict *hublease.ConflictError
	if errors.As(err, &conflict) {
		holder := conflict.Holder.InstanceID
		if conflict.Holder.Hostname != "" {
			holder = fmt.Sprintf("%s (%s pid %d)", holder, conflict.Holder.Hostname, conflict.Holder.PID)
		}
		return nil, fmt.Errorf(
			"a hub is running here and holds the control-plane lease: %s\n\n"+
				"This command writes state that hub loaded into memory at startup, so a\n"+
				"write now would neither take effect nor survive its next edit. Use %s\n"+
				"while it is running, or stop it first.", holder, alternative)
	}
	if err != nil {
		return nil, err
	}
	// Not Start()ed: the command finishes in milliseconds, far inside the
	// lease TTL, so a renewal goroutine would only add a way to fail.
	return func() { _ = lease.Release() }, nil
}

// operatorActor identifies who ran the command, for the audit trail.
//
// The real OS user comes from the passwd database rather than $USER, which is
// the caller's to set: an audit record naming whoever the shell felt like
// claiming to be is worse than one naming nobody, because it reads as
// evidence. SUDO_USER is *also* environment, and is reported as a hint
// alongside the real uid rather than in place of it, so a record is never
// ambiguous about which half can be trusted.
func operatorActor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil {
		switch {
		case u.Username != "":
			name = u.Username
		case u.Uid != "":
			name = "uid:" + u.Uid
		}
	}
	if sudo := strings.TrimSpace(os.Getenv("SUDO_USER")); sudo != "" && sudo != name {
		return fmt.Sprintf("cli:%s(sudo:%s)", name, sudo)
	}
	return "cli:" + name
}

// requireReason validates the --reason flag every mutation carries.
//
// Required rather than optional, and non-trivial rather than merely non-empty.
// These commands are used during incidents and read back during reviews, and a
// row that says an administrator was demoted without saying why is a question
// somebody has to answer from memory weeks later. The minimum is short enough
// that it never obstructs the emergency itself.
func requireReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if len(reason) < 4 {
		return "", fmt.Errorf(
			"--reason is required and must say something: this action is recorded in " +
				"the audit trail and read back during review")
	}
	return reason, nil
}

// auditHubAdmin appends one incident-response action to the hash-chained trail.
//
// Unlike the HTTP paths this is *not* best-effort. There the argument for
// swallowing a journal failure is that a wedged trail must not stop a user
// signing in; here the action is the demotion itself, performed by a named
// operator with a stated reason, and an unrecorded one is worse than an
// unperformed one — it is the same authority change with nothing to review.
// Callers write the row first and mutate second, so a failure aborts before
// anything has changed.
func auditHubAdmin(db *statedb.DB, eventType, entityType, entityID, reason string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["reason"] = reason
	payload["via"] = "cli"
	// os_user duplicates the actor field on purpose. Actor is a free-form
	// column shared with every other producer, and a reviewer filtering the
	// trail for "what did a human at a shell do" should not have to parse a
	// prefix convention out of it.
	payload["os_user"] = operatorActor()
	blob, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode audit payload: %w", err)
	}
	ev := &statedb.AuditEvent{
		Timestamp:  time.Now().UTC(),
		Actor:      operatorActor(),
		EventType:  eventType,
		EntityType: entityType,
		EntityID:   entityID,
		Payload:    string(blob),
	}
	if err := db.AppendAuditEvent(ev); err != nil {
		return fmt.Errorf("record %s in the audit trail: %w", eventType, err)
	}
	return nil
}
