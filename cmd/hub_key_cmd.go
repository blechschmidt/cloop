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

	"github.com/blechschmidt/cloop/pkg/eventlog"
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
` + "`retire`" + ` refuses while any row still references the key.`,
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

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATE\tOPENABLE\tCREATED\tBY")
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
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				k.ID, state, openable, shortTime(k.CreatedAt), orDash(k.CreatedBy))
		}
		_ = w.Flush()

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

  cloop hub key retire <old-key-id>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		resume, _ := cmd.Flags().GetBool("continue")
		batch, _ := cmd.Flags().GetInt("batch")

		h, err := openHubKeyring(workdir, false)
		if err != nil {
			return err
		}
		defer h.close()

		h.rotator.WithBatch(batch)

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
			appendKeyAuditEvent(workdir, "sealing_key.rotated", report.TargetKeyID, map[string]any{
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
		appendKeyAuditEvent(workdir, "sealing_key.retired", keyID, map[string]any{
			"key_id": keyID,
			"via":    "cli",
		})
		color.Green("Retired %s. Its salt is gone; it can no longer be derived.", keyID)
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
	rot, err := secretbroker.NewRotator(kr, store, sessions.WithKeyring(kr))
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
func appendKeyAuditEvent(workdir, eventType, keyID string, payload map[string]any) {
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
		EventType:  eventType,
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
	for _, name := range []string{"secrets", "sessions"} {
		if n, ok := bySet[name]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", name, n))
		}
	}
	for name, n := range bySet {
		if name != "secrets" && name != "sessions" && n > 0 {
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
	for _, c := range []*cobra.Command{hubKeyListCmd, hubKeyStatusCmd, hubKeyRotateCmd, hubKeyRetireCmd} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	}
	for _, c := range []*cobra.Command{hubKeyListCmd, hubKeyStatusCmd, hubKeyRotateCmd} {
		c.Flags().Bool("json", false, "emit machine-readable JSON")
	}
	hubKeyRotateCmd.Flags().Bool("dry-run", false, "report what would be rewrapped without writing")
	hubKeyRotateCmd.Flags().Bool("continue", false,
		"resume onto the current primary key instead of minting a new one")
	hubKeyRotateCmd.Flags().Int("batch", secretbroker.DefaultRotationBatch,
		"rows to read per round")
	hubKeyRetireCmd.Flags().Bool("yes", false, "confirm irreversible destruction of the key's salt")

	hubKeyCmd.AddCommand(hubKeyListCmd)
	hubKeyCmd.AddCommand(hubKeyStatusCmd)
	hubKeyCmd.AddCommand(hubKeyRotateCmd)
	hubKeyCmd.AddCommand(hubKeyRetireCmd)
	hubCmd.AddCommand(hubKeyCmd)
}
