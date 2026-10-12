package cmd

// `cloop hub key escrow` — CLOOP_SECRET_KEY wrapped under an operator's
// passphrase, so losing the key file (or the hub.env of an older hub) is
// recoverable (Task 20410).
//
// Every sealing key the hub has ever used derives from CLOOP_SECRET_KEY, so
// it is the one value whose loss cannot be rotated away. Like the rest of
// `cloop hub key`, these commands work on the hub's directory directly rather
// than through the HTTP API: they are what you run when the hub is not
// serving — before it first starts, during a restore, on a replacement host.

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubKeyEscrowCmd = &cobra.Command{
	Use:   "escrow",
	Short: "Escrow CLOOP_SECRET_KEY under a passphrase, and recover it",
	Long: `Every sealing key derives from CLOOP_SECRET_KEY, so losing its key file loses
every sealed secret, session and hub CA key — rotation cannot help, because
every key it mints comes from the same value. An escrow file holds that value
sealed under a passphrase you choose (argon2id, 64 MiB, then AES-256-GCM): keep
it where you keep root credentials, off this host, and the passphrase somewhere
else again.

  cloop hub key escrow export --output /secure/cloop-hub.escrow   # make one
  cloop hub key escrow verify /secure/cloop-hub.escrow            # rehearse
  cloop hub key escrow import /secure/cloop-hub.escrow            # recover

The hub records the escrow's id and the key's fingerprint — nothing secret —
and 'cloop hub doctor' warns while none is recorded and fails when the one on
record no longer holds the key in use. The key itself never touches disk on the
way: the file holds ciphertext, and import writes it only into the hub's key file.`,
}

var hubKeyEscrowExportCmd = &cobra.Command{
	Use:   "export --output <file>",
	Short: "Seal CLOOP_SECRET_KEY under a passphrase into an escrow file",
	Long: `Seal the CLOOP_SECRET_KEY in this process's environment under a passphrase and
write it to --output, then read the file back and open it to prove it works.

Refused when the key does not open this hub's sealing keys — escrowing the
wrong key is worse than escrowing none — and when --output lies inside a
.cloop/ directory, which is what an escrow has to outlive. The passphrase is
read from the terminal, twice, or from --passphrase-file ("-" for stdin); it
must be at least 15 characters. Five or six random words are easy to remember
and far stronger than anything a person makes up.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		o := escrowOptions{In: os.Stdin, Now: time.Now}
		if err := o.resolveRoots(); err != nil {
			return err
		}
		o.Workdir, _ = cmd.Flags().GetString("workdir")
		o.File, _ = cmd.Flags().GetString("output")
		o.PassphraseFile, _ = cmd.Flags().GetString("passphrase-file")
		o.Force, _ = cmd.Flags().GetBool("force")
		return runEscrowExport(os.Stdout, o)
	},
}

var hubKeyEscrowVerifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Open an escrow file and check it against this hub",
	Long: `Open an escrow file with its passphrase and check what it holds: that it opens
at all, that the key inside derives this hub's sealing keys, whether it is the
escrow the hub has on record, and whether it is the CLOOP_SECRET_KEY in use.
Nothing is written unless --record is given.

Run it when you rehearse a restore. An escrow nobody can open — a forgotten
passphrase, a file that rotted — is found out here, not on the day it is needed.

--record records this file as the hub's escrow, once it is proven to open the
hub's sealing keys: after restoring a backup taken before the escrow was made,
the restored database does not know about it.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		o := escrowOptions{File: args[0], In: os.Stdin, Now: time.Now}
		if err := o.resolveRoots(); err != nil {
			return err
		}
		o.Workdir, _ = cmd.Flags().GetString("workdir")
		o.PassphraseFile, _ = cmd.Flags().GetString("passphrase-file")
		o.Record, _ = cmd.Flags().GetBool("record")
		if code := runEscrowVerify(os.Stdout, o); code != 0 {
			exitProcess(code)
		}
		return nil
	},
}

var hubKeyEscrowImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Recover CLOOP_SECRET_KEY from an escrow file into the hub's key file",
	Long: `Open an escrow file with its passphrase and put the key back where the hub reads
it. That is a key file — --key-file, or the one CLOOP_SECRET_KEY_FILE names, or
cloop-secret-key in the hub's directory, where ` + "`cloop hub bootstrap`" + ` writes
it — unless the hub keeps its key in .cloop/hub.env, as hubs bootstrapped
before Task 20425 do: then its CLOOP_SECRET_KEY line (or --env-file's), every
other line kept. A file that already holds a different key is refused without
--force, and with it kept aside as <file>.pre-import.<UTC>: it may be the only
copy of a key something is still sealed under. --stdout prints the assignment
instead, for a secret manager or systemd-creds; nothing is written.

Then point this shell at it and restore:

  export CLOOP_SECRET_KEY_FILE=/srv/cloop/cloop-secret-key
  cloop db restore <backup> --check
  cloop db restore <backup> --force --reason "…"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		o := escrowOptions{File: args[0], In: os.Stdin, Now: time.Now}
		o.Workdir, _ = cmd.Flags().GetString("workdir")
		o.PassphraseFile, _ = cmd.Flags().GetString("passphrase-file")
		o.EnvFile, _ = cmd.Flags().GetString("env-file")
		o.KeyFile, _ = cmd.Flags().GetString("key-file")
		o.Force, _ = cmd.Flags().GetBool("force")
		o.Stdout, _ = cmd.Flags().GetBool("stdout")
		if code := runEscrowImport(os.Stdout, o); code != 0 {
			exitProcess(code)
		}
		return nil
	},
}

// escrowOptions are the escrow commands' inputs.
type escrowOptions struct {
	Workdir        string
	File           string // --output for export, the argument otherwise
	PassphraseFile string
	EnvFile        string
	KeyFile        string
	Force          bool
	Record         bool
	Stdout         bool
	// Key is the hub's current root and Previous the root a change of root
	// is replacing, as pkg/rootkey resolves them; In is where a passphrase
	// is read from without --passphrase-file.
	Key      string
	Previous string
	In       io.Reader
	Now      func() time.Time
}

// resolveRoots fills Key and Previous from the hub's root sources.
func (o *escrowOptions) resolveRoots() error {
	roots, err := rootkey.Resolve()
	if err != nil {
		return err
	}
	o.Key, o.Previous = roots.Current.Value, roots.Previous.Value
	return nil
}

func (o *escrowOptions) workdir() (string, error) {
	if o.Workdir != "" {
		return o.Workdir, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	return wd, nil
}

// runEscrowExport is `cloop hub key escrow export`.
func runEscrowExport(w io.Writer, o escrowOptions) error {
	if o.File == "" {
		return errors.New("--output is required: a path off this host, where you keep root credentials")
	}
	if o.Key == "" {
		return fmt.Errorf("%s is not set: there is no key to escrow — give this shell the hub's key first "+
			"(%s=<its key file>, or set -a; . .cloop/hub.env; set +a on a hub that keeps it there)",
			keyescrow.EnvKey, rootkey.EnvKeyFile)
	}
	if err := keyescrow.CheckDestination(o.File); err != nil {
		return err
	}
	workdir, err := o.workdir()
	if err != nil {
		return err
	}
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("no cloop state database at %s — run this from the hub's directory after it has "+
			"started once, or pass --workdir", dbPath)
	}
	key := []byte(o.Key)
	defer keyescrow.Zero(key)
	// The key escrowed is the current root. Mid-way through a change of root
	// the keys of the previous one are still live — and are opened by it, so
	// together the two must open every key, and `cloop hub key rotate
	// --retire-previous` is waiting for exactly this escrow (Task 20425).
	hub, err := escrowKeyOpensHub(dbPath, key, []byte(o.Previous))
	if err != nil {
		return err
	} else if len(hub.Missing) > 0 {
		return fmt.Errorf("%s does not open this hub's sealing keys %s: escrowing it would preserve the wrong "+
			"key. Give this shell the hub's own key and run this again", keyescrow.EnvKey, strings.Join(hub.Missing, ", "))
	}

	pass, err := readEscrowPassphrase(o.PassphraseFile, o.In, true)
	if err != nil {
		return err
	}
	defer keyescrow.Zero(pass)
	actor := "cli:" + currentUser()
	f, err := keyescrow.Wrap(key, pass, keyescrow.WrapOptions{CreatedBy: actor, Hub: workdir, Now: o.Now()})
	if err != nil {
		return err
	}
	if err := keyescrow.WriteFile(o.File, f, o.Force); err != nil {
		return err
	}

	// An escrow nobody has opened is a hope, not a backup: read back what
	// is on disk and open it with the same passphrase before saying so.
	if err := openWrittenEscrow(o.File, pass, key); err != nil {
		// A file that does not open is not an escrow; leaving it where the
		// operator was told to look would be worse than leaving nothing.
		_ = os.Remove(o.File)
		return err
	}

	if err := recordEscrow(workdir, dbPath, f, actor, "export", o.Now()); err != nil {
		return err
	}

	header := color.New(color.FgCyan, color.Bold)
	header.Fprintln(w, "Escrowed CLOOP_SECRET_KEY")
	fmt.Fprintf(w, "  file:          %s (opened again to check it)\n", o.File)
	fmt.Fprintf(w, "  escrow:        %s\n", f.ID)
	fmt.Fprintf(w, "  key:           %s\n", f.KeyFingerprint)
	fmt.Fprintf(w, "  derivation:    %s, then %s\n", f.KDF.Params, f.AEAD.Alg)
	fmt.Fprintln(w, "  recorded in the hub: the escrow id and key fingerprint, nothing secret")
	dim := color.New(color.Faint)
	if hub.ByPrevious > 0 {
		dim.Fprintf(w, "  %d sealing key(s) still derive from %s; `cloop hub key rotate --retire-previous` moves\n"+
			"  everything onto this key and retires them, after which only this escrow recovers the hub\n",
			hub.ByPrevious, rootkey.EnvPrevious)
	}
	fmt.Fprintln(w)
	dim.Fprintln(w, "Keep the file where you keep root credentials, off this host, and the passphrase")
	dim.Fprintln(w, "somewhere else again. Rehearse recovery with:")
	dim.Fprintf(w, "  cloop hub key escrow verify %s\n", o.File)
	return nil
}

// runEscrowVerify is `cloop hub key escrow verify`, returning the exit code.
func runEscrowVerify(w io.Writer, o escrowOptions) int {
	pass := color.New(color.FgGreen, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	fail := color.New(color.FgRed, color.Bold)

	f, err := keyescrow.ReadFile(o.File)
	if err != nil {
		fail.Fprintf(w, "NOT AN ESCROW  %v\n", err)
		return 1
	}
	printEscrowHeader(w, o.File, f)
	passphrase, err := readEscrowPassphrase(o.PassphraseFile, o.In, false)
	if err != nil {
		fail.Fprintf(w, "Could not read the passphrase: %v\n", err)
		return 2
	}
	defer keyescrow.Zero(passphrase)
	key, err := f.Open(passphrase)
	if err != nil {
		fail.Fprintf(w, "DOES NOT OPEN  %v\n", err)
		return 1
	}
	defer keyescrow.Zero(key)
	pass.Fprintf(w, "OPENS          the passphrase opens it, and the key inside is %s\n", f.KeyFingerprint)

	code := 0
	current := o.Key != "" && subtle.ConstantTimeCompare(key, []byte(o.Key)) == 1
	switch {
	case o.Key == "":
	case current:
		pass.Fprintln(w, "IN USE         it is the CLOOP_SECRET_KEY in this environment")
	case o.Previous != "" && subtle.ConstantTimeCompare(key, []byte(o.Previous)) == 1:
		warn.Fprintf(w, "PREVIOUS ROOT  it is %s, the key a change of root is replacing: once `cloop hub key "+
			"rotate --retire-previous` has run it opens nothing; escrow %s (%s)\n", rootkey.EnvPrevious,
			keyescrow.EnvKey, keyFingerprintOf(o.Key))
	default:
		warn.Fprintf(w, "NOT IN USE     the CLOOP_SECRET_KEY in this environment is another key (%s)\n",
			keyFingerprintOf(o.Key))
	}

	workdir, err := o.workdir()
	if err != nil {
		fail.Fprintf(w, "%v\n", err)
		return 2
	}
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		color.New(color.Faint).Fprintf(w, "               no hub database at %s to check it against\n", dbPath)
		return code
	}
	// The escrow of the current root, mid-way through a change of root, opens
	// the hub together with the previous root, which this environment holds:
	// the keys it does not derive yet are moved onto it by the retire step.
	var also []byte
	if current {
		also = []byte(o.Previous)
	}
	hub, err := escrowKeyOpensHub(dbPath, key, also)
	switch {
	case err != nil:
		fail.Fprintf(w, "UNCHECKED      could not read the hub's sealing keys: %v\n", err)
		code = 1
	case len(hub.Missing) > 0:
		fail.Fprintf(w, "WRONG HUB      it does not open this hub's sealing keys %s\n", strings.Join(hub.Missing, ", "))
		code = 1
	case hub.Keys == 0:
		color.New(color.Faint).Fprintln(w, "               this hub has no sealing key yet")
	case hub.ByPrevious > 0:
		pass.Fprintf(w, "OPENS THE HUB  it derives %d of this hub's %d live sealing keys; the other %d derive from %s,\n"+
			"               which `cloop hub key rotate --retire-previous` moves onto it\n",
			hub.Keys-hub.ByPrevious, hub.Keys, hub.ByPrevious, rootkey.EnvPrevious)
	default:
		pass.Fprintf(w, "OPENS THE HUB  it derives all %d of this hub's live sealing keys\n", hub.Keys)
	}
	switch rec := hub.Record; {
	case !hub.Recorded:
		warn.Fprintln(w, "NOT ON RECORD  the hub records no escrow (pass --record to record this one)")
	case rec.ID == f.ID:
		pass.Fprintf(w, "ON RECORD      it is the escrow the hub records, made %s\n", rec.CreatedAt)
	case rec.KeyFingerprint == f.KeyFingerprint:
		warn.Fprintf(w, "OTHER ESCROW   the hub records escrow %s of the same key; this file is %s\n", rec.ID, f.ID)
	default:
		warn.Fprintf(w, "OTHER KEY      the hub records escrow %s of key %s\n", rec.ID, rec.KeyFingerprint)
	}

	if o.Record {
		if code != 0 || hub.Keys == 0 {
			fail.Fprintln(w, "Not recorded: only an escrow proven to open this hub's sealing keys is recorded.")
			return 1
		}
		if err := recordEscrow(workdir, dbPath, f, "cli:"+currentUser(), "verify", o.Now()); err != nil {
			fail.Fprintf(w, "Not recorded: %v\n", err)
			return 1
		}
		pass.Fprintln(w, "RECORDED       the hub now records this escrow")
	}
	return code
}

// runEscrowImport is `cloop hub key escrow import`, returning the exit code.
func runEscrowImport(w io.Writer, o escrowOptions) int {
	pass := color.New(color.FgGreen, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	fail := color.New(color.FgRed, color.Bold)
	dim := color.New(color.Faint)

	f, err := keyescrow.ReadFile(o.File)
	if err != nil {
		fail.Fprintf(w, "NOT AN ESCROW  %v\n", err)
		return 1
	}
	printEscrowHeader(w, o.File, f)
	passphrase, err := readEscrowPassphrase(o.PassphraseFile, o.In, false)
	if err != nil {
		fail.Fprintf(w, "Could not read the passphrase: %v\n", err)
		return 2
	}
	defer keyescrow.Zero(passphrase)
	key, err := f.Open(passphrase)
	if err != nil {
		fail.Fprintf(w, "DOES NOT OPEN  %v\n", err)
		return 1
	}
	defer keyescrow.Zero(key)
	pass.Fprintf(w, "OPENS          the key inside is %s\n", f.KeyFingerprint)

	workdir, err := o.workdir()
	if err != nil {
		fail.Fprintf(w, "%v\n", err)
		return 2
	}
	// The database here may be the one being replaced; what it says is
	// information, not a reason to refuse. `cloop db restore` checks the
	// backup itself before swapping anything.
	if dbPath := state.DBPath(workdir); fileExists(dbPath) {
		if hub, err := escrowKeyOpensHub(dbPath, key, nil); err == nil && hub.Keys > 0 {
			if len(hub.Missing) > 0 {
				warn.Fprintf(w, "               it does not open the sealing keys of %s (%s) — "+
					"check the backup you restore with `cloop db restore --check`\n",
					dbPath, strings.Join(hub.Missing, ", "))
			} else {
				pass.Fprintf(w, "OPENS THE HUB  it derives all %d sealing keys in %s\n", hub.Keys, dbPath)
			}
		}
	}

	if o.Stdout {
		fmt.Fprintf(w, "%s=%s\n", keyescrow.EnvKey, key)
		return 0
	}

	envPath, keyPath := escrowImportTarget(o, workdir)
	var (
		res  keyescrow.EnvInstall
		ierr error
	)
	if keyPath != "" {
		res, ierr = keyescrow.WriteKeyFile(keyPath, key, o.Force, o.Now())
	} else {
		res, ierr = keyescrow.WriteEnvFile(envPath, key, o.Force, o.Now())
	}
	if ierr != nil {
		fail.Fprintf(w, "Not installed: %v\n", ierr)
		return 1
	}
	switch {
	case res.Unchanged:
		pass.Fprintf(w, "IN PLACE       %s already holds this key; nothing was written\n", res.Path)
	case res.Created:
		pass.Fprintf(w, "INSTALLED      %s created, mode 0600\n", res.Path)
	case keyPath != "":
		pass.Fprintf(w, "INSTALLED      %s replaced\n", res.Path)
	default:
		pass.Fprintf(w, "INSTALLED      CLOOP_SECRET_KEY in %s replaced, other lines kept\n", res.Path)
	}
	if res.Previous != "" {
		warn.Fprintf(w, "               the previous file, with its key, is kept as %s\n", res.Previous)
	}
	fmt.Fprintln(w)
	dim.Fprintln(w, "Point this shell at it, then check and restore the backup:")
	if keyPath != "" {
		dim.Fprintf(w, "  export %s=%s\n", rootkey.EnvKeyFile, res.Path)
	} else {
		dim.Fprintf(w, "  set -a; . %s; set +a\n", res.Path)
	}
	dim.Fprintln(w, "  cloop db restore <backup> --check")
	dim.Fprintln(w, "  cloop db restore <backup> --force --reason \"…\"")
	if keyPath != "" {
		dim.Fprintf(w, "A unit that loads the key as an encrypted credential needs it re-encrypted:\n"+
			"  systemd-creds encrypt --name=%s %s /etc/credstore.encrypted/%s\n", rootkey.Credential, res.Path,
			rootkey.Credential)
	}
	return 0
}

// escrowImportTarget decides where import puts the key: the env file named by
// --env-file, or a key file — --key-file, the one this shell's
// CLOOP_SECRET_KEY_FILE names, or the bootstrap's in the hub's directory —
// unless the hub keeps its key in .cloop/hub.env, the layout before Task
// 20425, which is kept. Exactly one of the two is returned.
func escrowImportTarget(o escrowOptions, workdir string) (envPath, keyPath string) {
	switch {
	case o.EnvFile != "":
		return o.EnvFile, ""
	case o.KeyFile != "":
		if abs, err := filepath.Abs(o.KeyFile); err == nil {
			return "", abs
		}
		return "", o.KeyFile
	case os.Getenv(rootkey.EnvKeyFile) != "":
		return "", os.Getenv(rootkey.EnvKeyFile)
	}
	if legacy := filepath.Join(workdir, ".cloop", hubEnvFile); keyescrow.EnvFileHoldsKey(legacy) {
		return legacy, ""
	}
	return "", filepath.Join(workdir, hubKeyFile)
}

// openWrittenEscrow reads the escrow file back from disk and opens it, and
// says why it is not the key that was meant to be in it.
func openWrittenEscrow(path string, pass, key []byte) error {
	back, err := keyescrow.ReadFile(path)
	if err != nil {
		return fmt.Errorf("the escrow file was written and does not read back: %w", err)
	}
	got, err := back.Open(pass)
	if err != nil {
		return fmt.Errorf("the escrow file was written and does not open: %w", err)
	}
	same := subtle.ConstantTimeCompare(got, key) == 1
	keyescrow.Zero(got)
	if !same {
		return errors.New("the escrow file was written and opens to a different key")
	}
	return nil
}

func printEscrowHeader(w io.Writer, path string, f *keyescrow.File) {
	color.New(color.FgCyan, color.Bold).Fprintf(w, "Escrow %s\n", path)
	fmt.Fprintf(w, "  escrow %s of key %s, made %s by %s on %s\n", f.ID, f.KeyFingerprint, f.CreatedAt,
		orDash(f.CreatedBy), orDash(f.Hub))
	fmt.Fprintf(w, "  %s, then %s\n\n", f.KDF.Params, f.AEAD.Alg)
}

// escrowHub is what a hub's database says about a key and its escrow.
type escrowHub struct {
	// Keys counts the hub's live sealing keys; Missing names those the key
	// does not derive, and ByPrevious counts those only the previous root
	// checked beside it derives.
	Keys       int
	Missing    []string
	ByPrevious int
	// Record is the escrow the hub records, when Recorded.
	Record   keyescrow.Record
	Recorded bool
}

// escrowKeyOpensHub asks the hub's database at dbPath whether key — with
// previous beside it, the root a change of root is replacing, when it is not
// nil — derives its live sealing keys, and which escrow it records. Read-only
// throughout: verify promises to write nothing, and a newer CLI must not
// migrate the database of an older hub it is asked about.
func escrowKeyOpensHub(dbPath string, key, previous []byte) (escrowHub, error) {
	var out escrowHub
	conn, err := statedb.OpenConn(dbPath, statedb.ReadOnly)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	facts, err := statedb.ReadSealedFacts(conn, secretbroker.LegacySaltMetaKey)
	if err != nil {
		return out, fmt.Errorf("read the hub's sealing keys: %w", err)
	}
	records := make([]secretbroker.KEKRecord, 0, len(facts.KEKs))
	for _, row := range facts.KEKs {
		records = append(records, secretbroker.KEKRecord{ID: row.ID, Salt: row.Salt, State: row.State, CheckValue: row.CheckValue})
	}
	for _, c := range secretbroker.CheckKeys([]string{string(key), string(previous)}, records) {
		if c.Retired {
			continue
		}
		out.Keys++
		switch {
		case !c.Opens:
			out.Missing = append(out.Missing, c.ID)
		case c.Root == 1:
			out.ByPrevious++
		}
	}

	// The record is informational; the key check above is the answer.
	out.Record, out.Recorded, _ = keyescrow.ReadRecord(conn)
	return out, nil
}

// recordEscrow records f as the hub's escrow, and says so in the audit trail.
func recordEscrow(workdir, dbPath string, f *keyescrow.File, actor, how string, now time.Time) error {
	db, err := statedb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open %s to record the escrow: %w", dbPath, err)
	}
	rec := f.Record(actor, now)
	err = keyescrow.SaveRecord(db, rec)
	db.Close() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("record the escrow: %w", err)
	}
	appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyEscrowed, f.ID, map[string]any{
		"escrow_id":       f.ID,
		"key_fingerprint": f.KeyFingerprint,
		"kdf":             rec.KDF,
		"created_at":      f.CreatedAt,
		"recorded":        how,
		"via":             "cli",
	})
	return nil
}

// maxPassphraseFile bounds what --passphrase-file reads.
const maxPassphraseFile = 4096

// readEscrowPassphrase reads the passphrase: from file ("-" is in), or from
// the terminal without echo — twice when confirm is set, since a typo in an
// escrow's passphrase is discovered only when it is too late. One trailing
// newline is stripped from a file; nothing else is.
func readEscrowPassphrase(file string, in io.Reader, confirm bool) ([]byte, error) {
	if file != "" {
		var r io.Reader = in
		if file != "-" {
			fh, err := os.Open(file)
			if err != nil {
				return nil, err
			}
			defer fh.Close()
			if fi, err := fh.Stat(); err == nil && fi.Mode().Perm()&0o077 != 0 {
				fmt.Fprintf(os.Stderr, "warning: %s is readable by other users (mode %s)\n", file, fi.Mode().Perm())
			}
			r = fh
		}
		data, err := io.ReadAll(io.LimitReader(r, maxPassphraseFile+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxPassphraseFile {
			keyescrow.Zero(data)
			return nil, fmt.Errorf("%s holds more than %d bytes: not a passphrase", file, maxPassphraseFile)
		}
		data = bytes.TrimSuffix(data, []byte("\n"))
		data = bytes.TrimSuffix(data, []byte("\r"))
		if len(data) == 0 {
			return nil, fmt.Errorf("%s is empty", file)
		}
		return data, nil
	}

	fd := int(os.Stdin.Fd())
	if f, ok := in.(*os.File); !ok || f != os.Stdin || !term.IsTerminal(fd) {
		return nil, errors.New("no terminal to read the passphrase from: pass --passphrase-file <file> (or - for stdin)")
	}
	fmt.Fprint(os.Stderr, "Escrow passphrase: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return first, nil
	}
	if err := keyescrow.CheckPassphrase(first); err != nil {
		keyescrow.Zero(first)
		return nil, err
	}
	fmt.Fprint(os.Stderr, "Again: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		keyescrow.Zero(first)
		return nil, err
	}
	same := subtle.ConstantTimeCompare(first, second) == 1
	keyescrow.Zero(second)
	if !same {
		keyescrow.Zero(first)
		return nil, errors.New("the passphrases differ")
	}
	return first, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// keyFingerprintOf names a key the way every record sealed under it does.
func keyFingerprintOf(key string) string {
	fp, err := keyescrow.Fingerprint([]byte(key))
	if err != nil {
		return "unknown"
	}
	return fp
}

func init() {
	for _, c := range []*cobra.Command{hubKeyEscrowExportCmd, hubKeyEscrowVerifyCmd, hubKeyEscrowImportCmd} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
		c.Flags().String("passphrase-file", "", "read the passphrase from this file, or - for stdin, instead of the terminal")
	}
	hubKeyEscrowExportCmd.Flags().String("output", "", "where to write the escrow file: off this host, never inside .cloop/ (required)")
	hubKeyEscrowExportCmd.Flags().Bool("force", false, "replace an existing escrow file at --output")
	hubKeyEscrowVerifyCmd.Flags().Bool("record", false, "record this escrow as the hub's, once it is proven to open the hub's sealing keys")
	hubKeyEscrowImportCmd.Flags().String("env-file", "",
		"env file to install the key into (default: .cloop/hub.env when the hub keeps its key there)")
	hubKeyEscrowImportCmd.Flags().String("key-file", "",
		"key file to install the key into (default: "+rootkey.EnvKeyFile+", or "+hubKeyFile+" in the hub's directory)")
	hubKeyEscrowImportCmd.Flags().Bool("force", false, "replace a different key already in the env file, keeping the old file aside")
	hubKeyEscrowImportCmd.Flags().Bool("stdout", false, "print CLOOP_SECRET_KEY=<key> instead of writing a file")
	hubKeyEscrowImportCmd.MarkFlagsMutuallyExclusive("env-file", "key-file", "stdout")

	hubKeyEscrowCmd.AddCommand(hubKeyEscrowExportCmd)
	hubKeyEscrowCmd.AddCommand(hubKeyEscrowVerifyCmd)
	hubKeyEscrowCmd.AddCommand(hubKeyEscrowImportCmd)
	hubKeyCmd.AddCommand(hubKeyEscrowCmd)
}
