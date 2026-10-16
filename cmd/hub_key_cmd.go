package cmd

// `cloop hub key` — the operator surface for envelope encryption and online
// sealing-key rotation (Task 20181).
//
// This exists because the runbook used to contain a paragraph beginning
// "cloop has no automated rotation for the sealing key", followed by a
// procedure whose first real step was "rotate the underlying credentials at
// their sources". That is not key rotation; it is credential rotation with
// extra downtime, and in a regulated deployment "the master key cannot be
// rotated" is a finding, not a caveat.
//
// Like `cloop hub token`, these subcommands write directly to the hub's state
// database rather than going through the HTTP API, and for the same reason:
// the operations here are the ones you need when the hub is not serving —
// after a restore, during an incident, before a first sign-in. Whoever can run
// them can already read the database they operate on, so there is no HTTP
// identity to bound and none is pretended.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubKeyCmd = &cobra.Command{
	Use:   "key",
	Short: "Inspect and rotate the sealing keys that protect stored secrets",
	Long: `Every secret, and every session refresh token, is sealed under its own
random data key (DEK). Only the DEK is sealed under a key-encryption key (KEK)
derived from CLOOP_SECRET_KEY.

That indirection is what makes rotation possible without touching credentials:
rotating rewraps DEKs, which is sixty bytes per row, and never decrypts a
payload. Several KEKs can be openable at once, so a rotation runs against a
serving hub rather than in a maintenance window, and an interrupted one is
resumed by running it again.

Retiring an old key is a deliberate second step. It destroys that key's salt,
so material still sealed under it becomes unrecoverable — which is why
` + "`retire`" + ` refuses while any row still references the key.

CLOOP_SECRET_KEY itself changes online too: restart every hub member with the
new key as CLOOP_SECRET_KEY and the old one as CLOOP_SECRET_KEY_PREVIOUS,
escrow the new key, and run ` + "`cloop hub key rotate --retire-previous`" + `. The
key is read from CLOOP_SECRET_KEY_FILE, the systemd credential
cloop-secret-key, or the environment — the commands here read it as the hub does.

With secrets.kms configured, a KEK is random instead and held only wrapped by
an external key-management service — a Kubernetes KMS v2 plugin, or Vault /
OpenBao Transit — so a copy of the database and the key file opens nothing
without the KMS. Moving onto a KMS, off one, or from one to another is the same
change of root, finished by ` + "`--retire-previous`" + `; ` + "`rewrap`" + ` follows a rotation of
the KMS key. These commands read secrets.kms from config.yaml with the overlay
of the hub --port names merged, as that hub does.`,
}

var hubKeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sealing keys and whether each can still be opened",
	Long: `List every KEK this hub knows about.

"openable" answers the question that matters after a passphrase change: can
the current CLOOP_SECRET_KEY actually derive this key? It is checked against a
key check value, so the answer costs nothing and does not involve reading a
single credential.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")

		h, err := openHubKeyring(workdir, true)
		if err != nil {
			return err
		}
		defer h.close()

		keys := h.keyring.Keys()
		if asJSON {
			return printJSON(keys)
		}
		if len(keys) == 0 {
			fmt.Println("No sealing keys recorded.")
			return nil
		}

		labels := h.keyring.RootLabels()
		fmt.Printf("Root %s", labels[0])
		if len(labels) > 1 {
			fmt.Printf(", previous %s (a change of root is in progress)", labels[1])
		}
		fmt.Print("\n\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATE\tOPENABLE\tROOT\tKMS KEY\tCREATED\tBY")
		for _, k := range keys {
			state := k.State
			if k.Primary {
				state = "primary"
			}
			openable := "yes"
			switch {
			case k.State == secretbroker.KEKStateRetired:
				openable = "shredded"
			case !k.Openable:
				openable = "NO"
			}
			root := orDash(k.Root)
			if k.DerivedBy == secretbroker.RootPrevious {
				root += " (previous)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				k.ID, state, openable, root, orDash(k.KMSKeyID), shortTime(k.CreatedAt), orDash(k.CreatedBy))
		}
		_ = w.Flush()
		if bad := h.keyring.Underivable(); len(bad) > 0 {
			color.Red("\n%d live key(s) open with no root this shell holds. A hub with these roots refuses to start:",
				len(bad))
			reasons := h.keyring.UnderivableReasons()
			for _, id := range bad {
				color.Red("  %s %s", id, reasons[id])
			}
		}

		if h.keyring.HasLegacy() {
			color.New(color.Faint).Println(
				"\nA legacy (pre-envelope) key is present. Run 'cloop hub key rotate' to retire it.")
		}
		return nil
	},
}

var hubKeyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which key each secret is sealed under and rotation progress",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")

		h, err := openHubKeyring(workdir, true)
		if err != nil {
			return err
		}
		defer h.close()

		st, statusErr := h.rotator.Status(5)
		if asJSON {
			if perr := printJSON(st); perr != nil {
				return perr
			}
			return statusErr
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)

		bold.Println("Sealing keys")
		fmt.Printf("  primary        %s\n", orDash(st.PrimaryKeyID))
		fmt.Printf("  keys           %d\n", len(st.Keys))

		bold.Println("\nSealed material")
		if len(st.Usage) == 0 {
			dim.Println("  nothing sealed yet")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  KEY\tROWS\tBREAKDOWN\tNOTE")
			for _, u := range st.Usage {
				note := ""
				switch {
				case u.KeyID == st.PrimaryKeyID:
					note = "current"
				case u.KeyID == secretbroker.LegacyKeyID:
					note = "pre-envelope; rotate to upgrade"
				default:
					note = "awaiting rotation"
				}
				fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n", u.KeyID, u.Total, breakdown(u.BySet), note)
			}
			_ = w.Flush()
		}

		if k := h.keyring.CurrentKMS(); k != nil {
			bold.Println("\nKMS")
			fmt.Printf("  %s\n", k.Name())
			if rep, ok := k.(secretbroker.KMSKeyReporter); ok {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				cur, kerr := rep.CurrentKeyID(ctx)
				cancel()
				switch stale := h.keyring.StaleKMSKeys(cur); {
				case kerr != nil:
					color.Red("  does not answer: %v\n", kerr)
				case len(stale) > 0:
					color.Yellow("  encrypts under %s; %d key(s) are wrapped under an older KMS key — the hub's "+
						"leader rewraps them within a minute, or run 'cloop hub key rewrap'\n", cur, len(stale))
				case h.keyring.KMSHeldKeys() == 0:
					fmt.Printf("  encrypts under %s, and holds no sealing key yet — the change of root below "+
						"mints the first\n", cur)
				default:
					color.Green("  encrypts under %s, and every key it holds is wrapped under it\n", cur)
				}
			}
			dim.Println("  A restore of this hub needs access to this KMS key: no key file or escrow opens what it holds.")
		}

		if st.ChangingRoot {
			bold.Println("\nChange of root")
			prev := h.keyring.RootLabels()[1]
			if st.PreviousRootRows > 0 {
				color.Yellow("  %d row(s) still sealed under keys of the previous root, %s — finish with "+
					"'cloop hub key rotate --retire-previous'\n", st.PreviousRootRows, prev)
			} else {
				color.Yellow("  the previous root %s is configured; finish with 'cloop hub key rotate "+
					"--retire-previous', then remove it from every member\n", prev)
			}
		}

		bold.Println("\nRotation")
		switch {
		case st.Unrotated == 0:
			color.Green("  complete — every row is sealed under %s\n", orDash(st.PrimaryKeyID))
		default:
			color.Yellow("  %d row(s) not yet under %s — run 'cloop hub key rotate --continue'\n",
				st.Unrotated, st.PrimaryKeyID)
		}
		if st.Legacy > 0 && !st.LegacyOpen {
			color.Red("  %d legacy row(s) cannot be opened: the legacy salt is gone or "+
				"CLOOP_SECRET_KEY changed. Those credentials must be re-minted.\n", st.Legacy)
		}

		if len(st.Rotations) > 0 {
			bold.Println("\nRecent rotations")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  STARTED\tTARGET\tSTATE\tREWRAPPED\tSKIPPED\tFAILED")
			for _, r := range st.Rotations {
				fmt.Fprintf(w, "  %s\t%s\t%s\t%d\t%d\t%d\n",
					shortTime(r.StartedAt), r.ToKeyID, r.State, r.Rewrapped, r.Skipped, r.Failed)
			}
			_ = w.Flush()
			if last := st.Rotations[0]; last.LastError != "" {
				dim.Printf("\n  last error: %s\n", last.LastError)
			}
		}
		return statusErr
	},
}

var hubKeyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rewrap every sealed row under a new key-encryption key",
	Long: `Mint a new KEK, make it primary, and rewrap every sealed row onto it.

The hub keeps serving throughout. Rows move one at a time; each write is a
compare-and-swap against the exact bytes that were read, so a credential
re-minted or a session refreshed mid-rotation is never reverted — it is
counted as skipped and picked up on the next pass.

Interruption is safe and costs nothing but the row in flight: the old KEK is
still openable (rotation retires nothing), and the work remaining is defined by
the rows themselves rather than a cursor. Re-run to continue.

  cloop hub key rotate                # mint a new key and rewrap onto it
  cloop hub key rotate --continue     # resume onto the current primary
  cloop hub key rotate --dry-run      # count what would move, write nothing

Retiring the old key is deliberately not part of this command. Do it once
` + "`cloop hub key status`" + ` reports zero unrotated rows:

  cloop hub key retire <old-key-id>

--retire-previous finishes a change of CLOOP_SECRET_KEY itself, with this shell
holding the new key as CLOOP_SECRET_KEY and the old one as
CLOOP_SECRET_KEY_PREVIOUS. It refuses until every live hub member advertises the
new key as its current root and an escrow of the new key is on record; then it
mints a key from the new root if the primary is not one, rewraps every row onto
it, and retires every key of the old root:

  cloop hub key rotate --retire-previous --dry-run
  cloop hub key rotate --retire-previous`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		resume, _ := cmd.Flags().GetBool("continue")
		batch, _ := cmd.Flags().GetInt("batch")
		retirePrevious, _ := cmd.Flags().GetBool("retire-previous")
		if retirePrevious && resume {
			return fmt.Errorf("--retire-previous resumes by being run again; drop --continue")
		}

		h, err := openHubKeyring(workdir, false)
		if err != nil {
			return err
		}
		defer h.close()

		h.rotator.WithBatch(batch)
		if retirePrevious {
			if workdir == "" {
				workdir, _ = os.Getwd()
			}
			return runRetirePrevious(os.Stdout, workdir, h, dryRun, asJSON)
		}
		if err := refuseRotationMidChange(h.keyring, resume, dryRun); err != nil {
			return err
		}

		// Ctrl-C stops the rotation between rows rather than mid-write. The
		// signal handler exists to make interruption *boring*: without it a
		// SIGINT during an Exec would still be safe (the row is transactional)
		// but would print a stack of driver errors instead of a resume hint.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if !asJSON && !dryRun {
			color.New(color.Faint).Println("Rotating. Interrupting is safe — re-run to continue.")
		}

		before := h.keyring.PrimaryID()
		report, rotErr := h.rotator.Rotate(ctx, secretbroker.RotateOptions{
			NewKey: !resume,
			Actor:  "cli:" + currentUser(),
			DryRun: dryRun,
		})

		if !dryRun && report.TargetKeyID != "" {
			appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyRotated, report.TargetKeyID, map[string]any{
				"from_primary": before,
				"to_key":       report.TargetKeyID,
				"rewrapped":    report.Rewrapped,
				"skipped":      report.Skipped,
				"failed":       report.Failed,
				"complete":     report.Complete,
				"via":          "cli",
			})
		}

		if asJSON {
			if perr := printJSON(report); perr != nil {
				return perr
			}
			return rotErr
		}

		if dryRun {
			onto := "a newly minted key"
			if resume {
				onto = report.TargetKeyID
			}
			fmt.Printf("\nDry run: %d row(s) would be rewrapped onto %s.\n", report.Rewrapped, onto)
			for _, s := range report.Sets {
				fmt.Printf("  %-10s %d\n", s.Name, s.Rewrapped)
			}
			return rotErr
		}

		bold := color.New(color.Bold)
		bold.Printf("\nRotation onto %s\n", report.TargetKeyID)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  SET\tREWRAPPED\tSKIPPED\tFAILED")
		for _, s := range report.Sets {
			fmt.Fprintf(w, "  %s\t%d\t%d\t%d\n", s.Name, s.Rewrapped, s.Skipped, s.Failed)
		}
		_ = w.Flush()

		for _, s := range report.Sets {
			for _, e := range s.Errors {
				color.Red("  %s", e)
			}
		}

		switch {
		case rotErr != nil:
			color.Yellow("\nRotation did not finish: %v", rotErr)
			color.New(color.Faint).Println("Re-run 'cloop hub key rotate --continue' to resume.")
			return rotErr
		case report.Complete:
			color.Green("\nEvery row is now sealed under %s.", report.TargetKeyID)
			if before != "" && before != report.TargetKeyID {
				color.New(color.Faint).Printf(
					"Retire the previous key when you are satisfied:\n  cloop hub key retire %s\n", before)
			}
		}
		return nil
	},
}

var hubKeyRetireCmd = &cobra.Command{
	Use:   "retire <key-id>",
	Short: "Destroy an old key's salt, making it permanently underivable",
	Long: `Retire a KEK by destroying its salt.

This is irreversible. After it, the key cannot be derived from CLOOP_SECRET_KEY
at all, and anything still sealed under it is gone — which is why retirement
refuses while any row references the key, and why it is a separate command
from rotation rather than its last step.

Run 'cloop hub key status' first. Retire only when it reports zero unrotated
rows.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		yes, _ := cmd.Flags().GetBool("yes")

		h, err := openHubKeyring(workdir, true)
		if err != nil {
			return err
		}
		defer h.close()

		keyID := strings.TrimSpace(args[0])
		if !yes {
			color.Yellow("About to destroy the salt for %s. Material sealed under it "+
				"becomes unrecoverable.", keyID)
			fmt.Println("Re-run with --yes to confirm.")
			return nil
		}

		if err := h.rotator.RetireKey(keyID); err != nil {
			return err
		}
		appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyRetired, keyID, map[string]any{
			"key_id": keyID,
			"via":    "cli",
		})
		color.Green("Retired %s. Its salt is gone; it can no longer be derived.", keyID)
		return nil
	},
}

// refuseRotationMidChange refuses a rotation that would mint a key while a
// change of root is in progress (Task 20425). A key minted here comes from this
// shell's CLOOP_SECRET_KEY — the new root, mid-change — and promoting it with
// no check that every hub member holds that root would leave those that do not
// unable to seal anything. --retire-previous is the rotation that checks.
// Resuming onto the current primary mints nothing, and neither does a dry run.
func refuseRotationMidChange(kr *secretbroker.Keyring, resume, dryRun bool) error {
	if resume || dryRun || !kr.HasPrevious() || kr.PrimaryFromCurrent() {
		return nil
	}
	return fmt.Errorf("a change of root is in progress — the previous root %s is configured and the primary "+
		"key comes from it — so a key minted here would come from the new root without checking that every hub "+
		"member holds it: finish the change with 'cloop hub key rotate --retire-previous', which checks first",
		kr.RootLabels()[1])
}

var hubKeyRewrapCmd = &cobra.Command{
	Use:   "rewrap",
	Short: "Rewrap KMS-held keys onto the KMS key's current version, after a rotation of the KMS key",
	Long: `Follow a rotation of the KMS key secrets.kms names.

A key-encryption key held by a KMS records the KMS key (and version) that
wrapped it. When the KMS rotates its key — a new Key Vault key version, a
rotated Transit key, a KMS v2 plugin reporting a new key id — every such KEK is
wrapped again under the key the KMS now encrypts under: the KEK itself, held in
memory, is encrypted once more, proven to unwrap, and swapped into its record
under compare-and-swap. One row per key changes; no secret, session or hub CA
key does. Afterwards the KMS's old key version holds nothing of this hub's and
can be disabled.

A serving hub's cluster leader does this on its own within a minute of the KMS
reporting the new key. This command does it now, for a hub that is not serving
or an operator who wants it done before disabling the old version.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		h, err := openHubKeyring(workdir, false)
		if err != nil {
			return err
		}
		defer h.close()
		if h.keyring.CurrentKMS() == nil {
			return fmt.Errorf("the store's current root is %s, not a KMS: there is no KMS key to follow "+
				"(secrets.kms configures one)", h.keyring.RootLabels()[0])
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		rep, rerr := h.keyring.RewrapKMS(ctx)
		for _, k := range rep.Keys {
			if k.ToKey == "" {
				continue
			}
			appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyKMSRewrapped, k.ID, map[string]any{
				"key_id": k.ID, "kms": rep.KMS, "from_kms_key": k.FromKey, "to_kms_key": k.ToKey, "via": "cli",
			})
		}
		if asJSON {
			if perr := printJSON(rep); perr != nil {
				return perr
			}
			return rerr
		}
		fmt.Printf("KMS %s encrypts under %s\n", rep.KMS, orDash(rep.CurrentKey))
		if len(rep.Keys) == 0 && rerr == nil {
			color.Green("Every key it holds is wrapped under it already.")
			return nil
		}
		for _, k := range rep.Keys {
			switch {
			case k.Error != "":
				color.Red("  %s  %s: %s", k.ID, k.FromKey, k.Error)
			case k.Skipped:
				fmt.Printf("  %s  rewrapped by another process meanwhile\n", k.ID)
			default:
				fmt.Printf("  %s  %s → %s\n", k.ID, k.FromKey, k.ToKey)
			}
		}
		if rerr != nil {
			return rerr
		}
		color.Green("Rewrapped %d key(s). Once 'cloop hub key list' names the old KMS key on no live key, "+
			"it can be disabled in the KMS.", rep.Rewrapped)
		return nil
	},
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

// hubKeyring bundles the handles every subcommand needs, so each one opens the
// database exactly once and closes it exactly once.
type hubKeyring struct {
	db      *statedb.DB
	keyring *secretbroker.Keyring
	rotator *secretbroker.Rotator
	close   func()
}

// openHubKeyring opens the hub database and builds a rotator over *both*
// populations of sealed material.
//
// Registering the session store alongside the secret store is load-bearing.
// A rotation that covered only brokered secrets would report success while
// leaving every refresh token sealed under the old KEK, and the retirement
// check would then refuse for reasons the operator could not see — or, worse,
// if the check were similarly partial, would succeed and shred a key that was
// still protecting live sessions.
func openHubKeyring(workdir string, readOnly bool) (*hubKeyring, error) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve working directory: %w", err)
		}
		workdir = wd
	}
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf(
			"no cloop state database at %s — run this from the hub's directory, "+
				"or pass --workdir", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dbPath, err)
	}
	closer := func() { _ = db.Close() }

	store, err := secretstore.New(db)
	if err != nil {
		closer()
		return nil, err
	}
	kopts := []secretbroker.KeyringOption{secretbroker.WithKeyringActor("cli:" + currentUser())}
	if readOnly {
		// `list` and `status` are diagnostics. A diagnostic that mints a key
		// on a fresh hub would report a registry it had just fabricated, and
		// an operator running it to answer "is my hub keyed yet?" would get
		// yes, because they asked.
		kopts = append(kopts, secretbroker.WithoutKeyCreation())
	}
	kr, err := secretbroker.OpenKeyring(store, kopts...)
	if err != nil {
		closer()
		return nil, fmt.Errorf("open sealing keys: %w", err)
	}
	sessions, err := sessionstore.New(db)
	if err != nil {
		closer()
		return nil, err
	}
	// The hub CA's private keys (Task 20409) are sealed under the same
	// registry, so "rotate everything" has to include them — and retirement
	// counts them, or it would shred the key every sandbox's trust rests on.
	tlsKeys, err := hubca.NewStore(db)
	if err != nil {
		closer()
		return nil, err
	}
	rot, err := secretbroker.NewRotator(kr, store, sessions.WithKeyring(kr), tlsKeys)
	if err != nil {
		closer()
		return nil, err
	}
	rot.WithHistory(store)
	return &hubKeyring{db: db, keyring: kr, rotator: rot, close: closer}, nil
}

// appendKeyAuditEvent records a key-lifecycle event in the tamper-evident log.
//
// Key rotation and retirement are exactly the events a compliance reviewer
// asks about, and they are invisible in the data they protect: after a
// successful rotation every row looks normal. The audit entry is the only
// durable evidence that it happened, and it carries key IDs and counts —
// never salts, never DEKs.
func appendKeyAuditEvent(workdir string, eventType auditaction.Action, keyID string, payload map[string]any) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return
		}
		workdir = wd
	}
	log, err := eventlog.Open(workdir)
	if err != nil {
		return
	}
	defer log.Close()
	blob, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = log.Append(&eventlog.AuditEvent{
		Actor:      "cli:" + currentUser(),
		EventType:  string(eventType),
		EntityType: "sealing_key",
		EntityID:   keyID,
		Payload:    string(blob),
	})
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func breakdown(bySet map[string]int) string {
	if len(bySet) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(bySet))
	for _, name := range []string{"secrets", "sessions", "hub_tls"} {
		if n, ok := bySet[name]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", name, n))
		}
	}
	for name, n := range bySet {
		if name != "secrets" && name != "sessions" && name != "hub_tls" && n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", name, n))
		}
	}
	return strings.Join(parts, " ")
}

func shortTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func init() {
	for _, c := range []*cobra.Command{hubKeyListCmd, hubKeyStatusCmd, hubKeyRotateCmd, hubKeyRetireCmd, hubKeyRewrapCmd} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	}
	for _, c := range []*cobra.Command{hubKeyListCmd, hubKeyStatusCmd, hubKeyRotateCmd, hubKeyRewrapCmd} {
		c.Flags().Bool("json", false, "emit machine-readable JSON")
	}
	hubKeyCmd.PersistentFlags().Int("port", defaultUIPort,
		"the hub whose per-instance overlay (.cloop/config.ui-<port>.yaml) to merge over config.yaml when reading "+
			"secrets.kms — as that hub reads it")
	hubKeyRotateCmd.Flags().Bool("dry-run", false, "report what would be rewrapped without writing")
	hubKeyRotateCmd.Flags().Bool("continue", false,
		"resume onto the current primary key instead of minting a new one")
	hubKeyRotateCmd.Flags().Int("batch", secretbroker.DefaultRotationBatch,
		"rows to read per round")
	hubKeyRotateCmd.Flags().Bool("retire-previous", false,
		"finish a change of root: rewrap everything onto a key of the current root ("+rootkey.EnvKey+" or "+
			"secrets.kms) and retire every key of the previous one, once every hub member holds the new root "+
			"(and a new "+rootkey.EnvKey+" is escrowed)")
	hubKeyRetireCmd.Flags().Bool("yes", false, "confirm irreversible destruction of the key's salt")

	hubKeyCmd.AddCommand(hubKeyListCmd)
	hubKeyCmd.AddCommand(hubKeyStatusCmd)
	hubKeyCmd.AddCommand(hubKeyRotateCmd)
	hubKeyCmd.AddCommand(hubKeyRetireCmd)
	hubKeyCmd.AddCommand(hubKeyRewrapCmd)
	hubCmd.AddCommand(hubKeyCmd)
}
