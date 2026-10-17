package cmd

// `cloop hub ca` — replacing the hub's own certificate authority online
// (Task 20438).
//
// Like `cloop hub key`, it writes the hub's state database directly rather
// than going through the HTTP API, for the same reason: it is what an
// operator reaches for during an incident — a backup taken with the root key
// is missing, an operator who held the KMS identity has left — and whoever can
// run it can already read the database it works on. Settings → Hub health
// takes the same steps for an administrator without a shell on the hub host.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubCACmd = &cobra.Command{
	Use:   "ca",
	Short: "Inspect and rotate the hub's own certificate authority",
	Long: `Under tls: auto the hub issues its git proxy's and Kubernetes monitor's
certificates from a CA of its own, whose key is sealed under the sealing keys
in the control-plane database, and every sandbox is told to trust that CA for
the monitors' URLs. The certificates it issues renew themselves; the CA is
replaced with ` + "`cloop hub ca rotate`" + `, in steps, so no running sandbox is cut off
by surprise.`,
}

var hubCARotateCmd = &cobra.Command{
	Use:   "rotate (--stage | --activate | --retire-previous | --status | --now | --abort)",
	Short: "Replace the hub CA online: stage a new one, activate it, retire the old one",
	Long: `Replace the hub's certificate authority without stopping the hub.

  --stage            Mint a new CA, sealed exactly as the current one (under
                     the sealing keys; under the KMS when secrets.kms is set).
                     Every hub member hands it to sandboxes beside the current
                     one within a minute: git's per-URL CA bundle, the
                     Kubernetes monitor's kubeconfig, Node's CA file, Pods,
                     devices and virtual executors. Certificates still come
                     from the current CA. The new CA carries X.509 name
                     constraints for the names the monitors are reached at
                     (every certificate issued so far, the configured advertise
                     URLs, and each --name), so it cannot vouch for any other
                     host; --no-name-constraints mints it without.
  --activate         Make the staged CA the one certificates come from; the
                     cluster leader reissues both monitors' certificates and
                     every member serves them within a minute. Refused while a
                     run dispatched before the stage is still running — it
                     trusts only the old CA — unless --force, which names the
                     runs it breaks; and refused while a hub member has not
                     adopted the stage, or runs a build that predates rotation.
  --retire-previous  Once every member serves certificates from the new CA:
                     drop the old CA from every bundle and destroy its sealed
                     key, with secure_delete, so the database file no longer
                     holds it. A backup taken before still does.
  --status           Where the rotation stands, the members, the runs a step
                     waits for, and what to do next. The default.
  --now              Emergency: replace every hub CA at once with a fresh one
                     (abandoning a staged one, whose key is in the same
                     database), reissue the certificates and retire the old CA.
                     Every hub member ends the git proxy, Kubernetes monitor
                     and model relay sessions of the runs that trusted only the
                     old CAs, which are named — whoever holds the old key could
                     otherwise answer for the monitors.
  --abort            Destroy a staged CA that was never activated.

A name constraint is part of the CA's certificate: a monitor moved to a host
the active CA does not permit cannot be served from it. Moving an advertise URL
to a new host is a rotation — stage with --name <new-host>, wait, activate —
before the URL changes.

Read secrets.kms from config.yaml with the overlay of the hub --port names, as
that hub does.`,
	Example: `  cloop hub ca rotate --status
  cloop hub ca rotate --stage
  cloop hub ca rotate --stage --name hub.example.com
  cloop hub ca rotate --activate
  cloop hub ca rotate --activate --force --yes
  cloop hub ca rotate --retire-previous --yes
  cloop hub ca rotate --now --yes`,
	Args: cobra.NoArgs,
	RunE: runHubCARotate,
}

// hubCAModes are the mutually exclusive steps, in the order the help lists them.
var hubCAModes = []string{"stage", "activate", "retire-previous", "status", "now", "abort"}

func runHubCARotate(cmd *cobra.Command, _ []string) error {
	mode := ""
	for _, m := range hubCAModes {
		if on, _ := cmd.Flags().GetBool(m); on {
			if mode != "" {
				return fmt.Errorf("--%s and --%s are separate steps: give one", mode, m)
			}
			mode = m
		}
	}
	if mode == "" {
		mode = "status"
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	force, _ := cmd.Flags().GetBool("force")
	yes, _ := cmd.Flags().GetBool("yes")
	names, _ := cmd.Flags().GetStringSlice("name")
	noConstraints, _ := cmd.Flags().GetBool("no-name-constraints")
	reason, _ := cmd.Flags().GetString("reason")
	wait, _ := cmd.Flags().GetDuration("wait")
	if force && mode != "activate" {
		return errors.New("--force applies to --activate only")
	}
	if (len(names) > 0 || noConstraints) && mode != "stage" && mode != "now" {
		return errors.New("--name and --no-name-constraints apply to --stage and --now only")
	}
	if len(names) > 0 && noConstraints {
		return errors.New("--name and --no-name-constraints contradict each other")
	}
	if _, err := hubca.NormalizeSANs(names); err != nil {
		return err
	}
	destructive := mode == "retire-previous" || mode == "now" || mode == "abort" || (mode == "activate" && force)
	if destructive && !yes {
		return fmt.Errorf("--%s %s: add --yes to confirm", mode, map[string]string{
			"retire-previous": "destroys the previous CA's key",
			"now":             "replaces every hub CA at once and ends the proxy sessions of the runs that trusted them",
			"abort":           "destroys the staged CA's key",
			"activate":        "with --force breaks the runs dispatched before the stage",
		}[mode])
	}

	workdir, _ := cmd.Flags().GetString("workdir")
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		workdir = wd
	}
	port, _ := cmd.Flags().GetInt("port")
	h, err := openHubCAEnv(workdir, mode != "status")
	if err != nil {
		return err
	}
	defer h.close()
	env := h.env

	switch mode {
	case "status":
		return printHubCAStatus(env, asJSON, nil)
	case "stage":
		cfg, _, _ := config.LoadUIInstance(workdir, port)
		res, err := hubca.Stage(env, hubca.StageRequest{
			Names: append(hubdoctor.HubCAConfigNames(cfg), names...), NoNameConstraints: noConstraints})
		if err != nil {
			return err
		}
		h.announce("stage")
		if asJSON {
			return printJSON(res)
		}
		color.Green("Staged hub CA %s (sha256 %s), valid until %s.", res.CA.Serial, res.CA.Fingerprint,
			res.CA.NotAfter.UTC().Format(time.RFC3339))
		if len(res.CA.Names) > 0 {
			fmt.Printf("Its name constraints permit %s and nothing else.\n", strings.Join(res.CA.Names, ", "))
		} else {
			fmt.Println("It carries no name constraints: it may vouch for any name.")
		}
		fmt.Println("Every hub member hands it to new sandboxes beside the current CA within a minute;")
		fmt.Println("certificates still come from the current one. Activate once the runs dispatched")
		fmt.Println("before now have finished: `cloop hub ca rotate --status` lists them.")
		return nil
	case "activate":
		res, err := hubca.Activate(env, hubca.ActivateRequest{Force: force})
		if err != nil {
			return explainHubCAError(err)
		}
		h.announce("activate")
		if !asJSON {
			color.Green("Activated hub CA %s (rotation %s).", res.Rotation.ToSerial, res.Rotation.ID)
			if len(res.Broken) > 0 {
				color.Yellow("%d run(s) dispatched before the stage now fail to verify the monitors:", len(res.Broken))
				for _, r := range res.Broken {
					fmt.Println("  " + r.Describe())
				}
			}
			fmt.Println("The cluster leader reissues the monitors' certificates; every member serves them within a minute.")
		}
		ready := waitHubCA(env, wait, asJSON)
		if asJSON {
			return printJSON(map[string]any{"result": res, "members_caught_up": ready})
		}
		if ready {
			fmt.Println("Every member serves certificates from the new CA. Retire the previous one with")
			fmt.Println("`cloop hub ca rotate --retire-previous --yes` once you no longer need to roll back.")
		}
		return nil
	case "retire-previous":
		res, err := hubca.RetirePrevious(env)
		if err != nil {
			return explainHubCAError(err)
		}
		h.announce("retire_previous")
		if asJSON {
			return printJSON(res)
		}
		color.Green("Retired hub CA %s: it is in no bundle, and its sealed key is gone from the database file.", res.Retired)
		fmt.Println("A backup taken before now still holds it; destroy or re-take those backups.")
		return nil
	case "abort":
		if reason == "" {
			reason = "aborted by " + currentUser()
		}
		rot, err := hubca.Abort(env, reason)
		if err != nil {
			return explainHubCAError(err)
		}
		h.announce("abort")
		if asJSON {
			return printJSON(rot)
		}
		color.Green("Destroyed the staged hub CA %s. Sandboxes dispatched while it was staged trust the current one too.", rot.ToSerial)
		return nil
	case "now":
		cfg, _, _ := config.LoadUIInstance(workdir, port)
		res, err := hubca.Emergency(env, hubca.StageRequest{
			Names: append(hubdoctor.HubCAConfigNames(cfg), names...), NoNameConstraints: noConstraints})
		if err != nil {
			return explainHubCAError(err)
		}
		h.announce("now")
		if !asJSON {
			color.Red("Replaced hub CA(s) %s with %s.", strings.Join(res.Replaced, ", "), res.CA.Serial)
			fmt.Printf("Reissued %d monitor certificate(s) from it; every member serves them within a minute.\n",
				len(res.Leaves))
			if len(res.Cut) == 0 {
				fmt.Println("No running run trusted the hub CA, so no proxy session is ended.")
			} else {
				color.Yellow("Every member ends the proxy sessions of %d run(s) that trusted only the replaced CA(s):", len(res.Cut))
				for _, r := range res.Cut {
					fmt.Println("  " + r.Describe())
				}
			}
		}
		ready := waitHubCA(env, wait, asJSON)
		if asJSON {
			return printJSON(map[string]any{"result": res, "members_caught_up": ready})
		}
		return nil
	}
	return nil
}

// explainHubCAError renders a refusal with what it waits for.
func explainHubCAError(err error) error {
	var re *hubca.RunsError
	if errors.As(err, &re) {
		var b strings.Builder
		fmt.Fprintf(&b, "%d run(s) dispatched before the stage are still running; they trust only the CA being "+
			"replaced and would stop verifying the monitors:\n", len(re.Runs))
		for _, r := range re.Runs {
			b.WriteString("  " + r.Describe() + "\n")
		}
		b.WriteString("Wait for them, or activate with --force --yes, which breaks them")
		return errors.New(b.String())
	}
	return err
}

// hubCAHandles is what the command works against.
type hubCAHandles struct {
	env     hubca.Env
	db      *statedb.DB
	workdir string
	close   func()
}

// openHubCAEnv opens the control plane's database, the CA store and — for a
// step — the sealing keys, read as the hub reads them.
func openHubCAEnv(workdir string, write bool) (*hubCAHandles, error) {
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("no cloop state database at %s — run this from the hub's directory, or pass --workdir", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dbPath, err)
	}
	db = db.AsControlPlane()
	closer := func() { _ = db.Close() }
	store, err := hubca.NewStore(db)
	if err != nil {
		closer()
		return nil, err
	}
	actor := "cli:" + currentUser()
	var sealer hubca.Sealer
	if write {
		ks, err := secretstore.New(db)
		if err != nil {
			closer()
			return nil, err
		}
		kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringActor(actor))
		if err != nil {
			closer()
			if errors.Is(err, secretbroker.ErrNoKey) {
				return nil, hubca.ErrNoKey
			}
			return nil, fmt.Errorf("open sealing keys: %w", err)
		}
		sealer = kr
	}
	h := &hubCAHandles{db: db, workdir: workdir, close: closer}
	h.env = hubca.Env{
		Store: store, Sealer: sealer,
		Options: hubca.Options{
			Actor:    actor,
			Rotation: func(e hubca.RotationEvent) { auditHubCAStep(workdir, actor, e) },
			Audit:    func(i hubca.Issued) { auditHubCALeaf(workdir, actor, i) },
		},
		Alive: func(r statedb.HubMemberRow) bool { return hubcluster.RowAlive(r, time.Now()) },
	}
	return h, nil
}

// announce tells every hub member a step was taken: they re-read their CAs
// at once rather than at their next minute's tick.
func (h *hubCAHandles) announce(step string) {
	payload, _ := json.Marshal(map[string]string{"step": step})
	if _, err := h.db.AppendHubEvents([]statedb.HubEventRow{{
		Origin: "cli:" + currentUser(), Topic: hubca.BusTopic, Key: step, Payload: string(payload),
		CreatedAt: time.Now(),
	}}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the hub members were not told on the cluster bus (%v); they read the "+
			"step within a minute anyway\n", err)
	}
}

// auditHubCAStep records a step on the control plane's trail.
func auditHubCAStep(workdir, actor string, e hubca.RotationEvent) {
	switch e.Step {
	case hubca.StepStage:
		appendHubCAEvent(workdir, actor, auditaction.ActionHubCARotationStaged, e.RotationID, e.Payload("cli"))
	case hubca.StepActivate:
		appendHubCAEvent(workdir, actor, auditaction.ActionHubCARotationActivated, e.RotationID, e.Payload("cli"))
	case hubca.StepRetirePrevious:
		appendHubCAEvent(workdir, actor, auditaction.ActionHubCAPreviousRetired, e.RotationID, e.Payload("cli"))
	case hubca.StepAbandon:
		appendHubCAEvent(workdir, actor, auditaction.ActionHubCARotationAbandoned, e.RotationID, e.Payload("cli"))
	case hubca.StepEmergency:
		appendHubCAEvent(workdir, actor, auditaction.ActionHubCAEmergencyRotated, e.RotationID, e.Payload("cli"))
	}
}

// auditHubCALeaf records a certificate an emergency reissued.
func auditHubCALeaf(workdir, actor string, i hubca.Issued) {
	appendHubCAEvent(workdir, actor, auditaction.ActionHubCALeafIssued, i.Serial, map[string]any{
		"monitor": string(i.Monitor), "serial": i.Serial, "names": i.Names, "issuer": i.Issuer,
		"reason": i.Reason, "replaced": i.Replaced, "not_after": i.NotAfter.UTC().Format(time.RFC3339),
	})
}

func appendHubCAEvent(workdir, actor string, eventType auditaction.Action, entity string, payload map[string]any) {
	log, err := eventlog.Open(workdir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s not written to the audit trail: %v\n", eventType, err)
		return
	}
	defer log.Close()
	blob, err := json.Marshal(payload)
	if err != nil {
		blob = []byte(`{}`)
	}
	if err := log.Append(&eventlog.AuditEvent{
		Actor: actor, EventType: string(eventType), EntityType: "hub_ca", EntityID: entity, Payload: string(blob),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s not written to the audit trail: %v\n", eventType, err)
	}
}

// waitHubCA waits up to d for every member to serve certificates from the
// active CA, saying who it waits for, and reports whether they all did.
func waitHubCA(env hubca.Env, d time.Duration, quiet bool) bool {
	if d <= 0 {
		return false
	}
	deadline := time.Now().Add(d)
	last := ""
	for {
		st, err := hubca.ReadStatus(env)
		if err == nil && (st.Ready || st.Phase == hubca.PhaseSteady) {
			return true
		}
		if err == nil && !quiet && st.NextStep != last {
			fmt.Println("  " + st.NextStep)
			last = st.NextStep
		}
		if time.Now().After(deadline) {
			if !quiet {
				color.Yellow("Not every member had caught up after %s; `cloop hub ca rotate --status` says who.", d)
			}
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// printHubCAStatus prints where the rotation stands.
func printHubCAStatus(env hubca.Env, asJSON bool, _ []string) error {
	st, err := hubca.ReadStatus(env)
	if err != nil {
		return err
	}
	hist, _ := env.Store.Rotations(5)
	if asJSON {
		return printJSON(map[string]any{"status": st, "history": hist})
	}
	bold := color.New(color.Bold)
	bold.Printf("Hub CA: %s\n", st.Phase)
	if st.Phase == hubca.PhaseNone {
		fmt.Println(st.NextStep)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SLOT\tSERIAL\tSHA256\tNOT AFTER\tNAME CONSTRAINTS")
	for _, c := range []*hubca.CAInfo{st.Active, st.Next, st.Previous} {
		if c == nil {
			continue
		}
		cons := "none"
		if len(c.Names) > 0 {
			cons = strings.Join(c.Names, ", ")
		}
		fmt.Fprintf(w, "%s\t%s\t%s…\t%s\t%s\n", c.Slot, c.Serial, c.Fingerprint[:16],
			c.NotAfter.UTC().Format("2006-01-02"), cons)
	}
	_ = w.Flush()
	if r := st.Rotation; r != nil {
		fmt.Printf("\nRotation %s: staged %s by %s", r.ID, shortTime(r.StagedAt), orDash(r.StagedBy))
		if !r.ActivatedAt.IsZero() {
			fmt.Printf(", activated %s by %s", shortTime(r.ActivatedAt), orDash(r.ActivatedBy))
		}
		if len(r.Forced) > 0 {
			fmt.Printf(", forced past %s", strings.Join(r.Forced, ", "))
		}
		fmt.Println()
	}
	if len(st.Leaves) > 0 {
		bold.Println("\nCertificates")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "MONITOR\tSERIAL\tFROM CA\tNAMES\tNOT AFTER")
		for _, l := range st.Leaves {
			fmt.Fprintf(w, "%s\t%s\t%s (%s)\t%s\t%s\n", l.Monitor, short12(l.Serial), short12(l.Issuer),
				orDash(string(l.Slot)), strings.Join(l.Names, ", "), l.NotAfter.UTC().Format(time.RFC3339))
		}
		_ = w.Flush()
	}
	if len(st.Members) > 0 {
		bold.Println("\nHub members")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "MEMBER\tBUILD\tTRUSTS\tSERVES\tCAUGHT UP")
		for _, m := range st.Members {
			trusts, serves := "-", "-"
			if len(m.Trusts) > 0 {
				trusts = strings.Join(short12s(m.Trusts), ",")
			}
			var parts []string
			for _, mon := range hubca.Monitors() {
				if l, ok := m.Leaves[string(mon)]; ok {
					parts = append(parts, string(mon)+"←"+short12(l.Issuer))
				}
			}
			if len(parts) > 0 {
				serves = strings.Join(parts, " ")
			}
			caught := "yes"
			if !m.CaughtUp {
				caught = "no: " + m.Behind
			} else if !m.Serves {
				caught = "yes (runs no monitor under tls: auto)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", m.Name(), orDash(m.Version), trusts, serves, caught)
		}
		_ = w.Flush()
	}
	if len(st.Blocking) > 0 {
		bold.Printf("\nRuns the next step would break (%d of %d running)\n", len(st.Blocking), st.Running)
		for _, r := range st.Blocking {
			fmt.Println("  " + r.Describe())
		}
	}
	fmt.Println()
	if st.Ready {
		color.Green(st.NextStep)
	} else {
		color.Yellow(st.NextStep)
	}
	if len(hist) > 0 {
		bold.Println("\nRecent rotations")
		for _, r := range hist {
			flag := ""
			if r.Emergency {
				flag = " (emergency)"
			}
			fmt.Printf("  %s  %-9s  %s → %s  staged %s%s\n", r.ID, r.State, short12(r.FromSerial), short12(r.ToSerial),
				shortTime(r.StagedAt), flag)
		}
	}
	return nil
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func short12s(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = short12(s)
	}
	return out
}

func init() {
	addHubCARotateFlags(hubCARotateCmd)
	hubCACmd.PersistentFlags().Int("port", defaultUIPort,
		"the hub whose per-instance overlay (.cloop/config.ui-<port>.yaml) to merge over config.yaml when reading "+
			"secrets.kms and the monitors' advertise URLs — as that hub reads them")
	hubCACmd.AddCommand(hubCARotateCmd)
	hubCmd.AddCommand(hubCACmd)
}

// addHubCARotateFlags declares rotate's flags on c.
func addHubCARotateFlags(c *cobra.Command) {
	f := c.Flags()
	f.Bool("stage", false, "mint a new CA that new sandboxes trust beside the current one")
	f.Bool("activate", false, "issue certificates from the staged CA (the cluster leader reissues them)")
	f.Bool("retire-previous", false, "drop the replaced CA from every bundle and destroy its key")
	f.Bool("status", false, "say where the rotation stands (the default)")
	f.Bool("now", false, "emergency: replace every hub CA at once and end the proxy sessions of the runs that trusted them")
	f.Bool("abort", false, "destroy a staged CA that was never activated")
	f.Bool("force", false, "with --activate: break the runs dispatched before the stage, naming them")
	f.Bool("yes", false, "confirm a step that destroys a key or breaks runs")
	f.StringSlice("name", nil, "with --stage or --now: also permit this name in the new CA's name constraints (repeatable)")
	f.Bool("no-name-constraints", false, "with --stage or --now: mint the new CA without name constraints")
	f.String("reason", "", "with --abort: why, for the audit trail")
	f.Duration("wait", 2*time.Minute, "with --activate or --now: how long to wait for every member to serve the new "+
		"certificates (0: do not wait)")
	f.String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	f.Bool("json", false, "emit machine-readable JSON")
}
