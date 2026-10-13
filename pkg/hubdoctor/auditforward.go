package hubdoctor

// Audit forwarding (Task 20426): whether the trail's content leaves the hub,
// and whether every sink it goes to is keeping up.
//
// Checkpoints (checkAuditCheckpoints) catch a chain shortened from the newest
// end; only a copy kept off the box keeps what the deleted rows said. So the
// checks here ask whether there is such a copy, whether each sink the
// configuration names can start — its credentials resolvable, its CA file and
// client certificate readable — and whether each is delivering: a sink that has
// never acknowledged a row with rows waiting, or whose oldest waiting row is
// older than audit.forward.max_lag, is a copy that is not being kept.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditforward"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkAuditForward(dir string, cfg *config.Config, opts Options, add addFn) {
	const title = "Audit forwarding"
	refused := 0
	for _, r := range cfg.LoadRepairs() {
		if !auditforward.IsSinkRepair(r) {
			continue
		}
		refused++
		add(Finding{
			Check: "audit.forward.sink", Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("%s in %s was not started: %s — the rows it was configured to receive go nowhere",
				r.SwitchedOff, r.File, r.Detail),
			Remediation: fmt.Sprintf("Correct the sink in %s; it stays off until it loads", r.File),
			Details:     map[string]any{"file": r.File, "sink": r.SwitchedOff},
		})
	}
	fwd := cfg.Audit.Forward
	if len(fwd.Sinks) == 0 {
		if refused == 0 {
			add(Finding{
				Check: "audit.forward", Title: title, Severity: SeverityWarn,
				Message: "no audit sink is configured: the trail's content leaves this hub only when someone runs " +
					"`cloop audit-log export`, and rows deleted from state.db before then are gone — checkpoints " +
					"say that they were deleted, not what they said",
				Remediation: "Configure audit.forward.sinks (syslog over TLS, an HTTPS collector or Splunk HEC, or a " +
					"file off this volume); see the runbook's \"Forwarding the trail off the box\"",
			})
		}
		return
	}

	for _, s := range fwd.Sinks {
		if msg := sinkPrerequisites(dir, s); msg != "" {
			add(Finding{
				Check: "audit.forward.sink", Title: title, Severity: SeverityFail,
				Message:     fmt.Sprintf("sink %s cannot start: %s", s.Name, msg),
				Remediation: "Fix what the message names; the hub retries the sink with backoff and logs each failure",
				Details:     map[string]any{"sink": s.Name},
			})
		}
	}

	cp := state.DBPath(dir)
	if _, err := os.Stat(cp); err != nil {
		add(Finding{
			Check: "audit.forward", Title: title, Severity: SeverityWarn,
			Message:     fmt.Sprintf("%d sink(s) configured, and no control-plane database to read their progress from", len(fwd.Sinks)),
			Remediation: "Start the hub here; its leader creates each sink's cursors on its first pass",
		})
		return
	}
	reports, err := auditforward.Status(cp, fwd)
	if err != nil {
		add(Finding{
			Check: "audit.forward", Title: title, Severity: SeverityWarn,
			Message:     "could not read the sinks' progress: " + err.Error(),
			Remediation: "Run `cloop hub audit forward status` and fix what it reports",
		})
		return
	}
	now := opts.now()
	maxLag := fwd.EffectiveMaxLag()
	var healthy []string
	for _, r := range reports {
		problem := auditforward.Unhealthy(r, maxLag, now)
		if problem == "" {
			healthy = append(healthy, fmt.Sprintf("%s (%s, lag %s)", r.Sink.Name, r.Sink.Endpoint(), r.Lag(now).Round(time.Second)))
			continue
		}
		add(Finding{
			Check: "audit.forward.lag", Title: title, Severity: SeverityWarn,
			Message: fmt.Sprintf("sink %s (%s) %s", r.Sink.Name, r.Sink.Endpoint(), problem),
			Remediation: "Check the collector is reachable and accepting rows (`cloop hub audit forward status`, and " +
				"the hub's stderr for [audit-forward] lines); the backlog stays in the database and is sent when it is",
			Details: map[string]any{"sink": r.Sink.Name, "backlog": r.Backlog(), "lag_seconds": r.Lag(now).Seconds()},
		})
	}
	if len(healthy) > 0 {
		add(Finding{
			Check: "audit.forward", Title: title, Severity: SeverityPass,
			Message: "forwarding to " + strings.Join(healthy, ", "),
		})
	}
}

// sinkPrerequisites reports what stops a sink starting, judged without
// dialling it: the files it reads, and the secrets it names.
func sinkPrerequisites(dir string, s config.AuditForwardSink) string {
	for _, f := range []struct{ key, path string }{{"ca_file", s.CAFile}, {"client_cert", s.ClientCert}} {
		if f.path == "" {
			continue
		}
		if _, err := os.ReadFile(f.path); err != nil {
			return fmt.Sprintf("%s %s is not readable: %v", f.key, f.path, err)
		}
	}
	if strings.EqualFold(s.Type, config.AuditSinkFile) {
		if err := config.CheckOutsideCloopOnDisk(s.Path); err != nil {
			return "path: " + err.Error()
		}
	}
	refs := s.StoreRefs()
	if len(refs) == 0 {
		return ""
	}
	if roots, err := rootkey.Resolve(); err != nil || !roots.Current.Set() {
		return "it names secrets (" + strings.Join(refs, ", ") + "), and this hub has no " + rootkey.EnvKey +
			" to open the secret store with"
	}
	// No database is checkStorage's finding; opening one here would create it.
	if _, err := os.Stat(state.DBPath(dir)); err != nil {
		return ""
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return "the secret store could not be read: " + err.Error()
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		return "the secret store could not be read: " + err.Error()
	}
	secrets, err := store.ListSecrets()
	if err != nil {
		return "the secret store could not be read: " + err.Error()
	}
	for _, ref := range refs {
		name, _ := config.SplitSecretRef(ref)
		var found *secretbroker.Secret
		for i := range secrets {
			if secrets[i].Name == name || secrets[i].ID == name {
				found = &secrets[i]
				break
			}
		}
		switch {
		case found == nil:
			return fmt.Sprintf("it names secret %q, which the secret store does not hold "+
				"(cloop secret mint %s --kind env --file <file holding the value>)", name, name)
		case found.Kind != secretbroker.KindEnv:
			return fmt.Sprintf("secret %q is a %s secret; a credential the hub presents is an env secret", name, found.Kind)
		case found.Personal():
			return fmt.Sprintf("secret %q belongs to %s; the hub presents only shared secrets as itself", name, found.Owner)
		}
	}
	return ""
}
