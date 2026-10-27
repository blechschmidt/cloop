package cmd

// `cloop login`, `cloop logout` and `cloop whoami` (Task 20412): a developer's
// terminal signing in to a hub with single sign-on.
//
// The terminal runs the device authorization grant against the hub; a
// signed-in browser approves the code it prints. What it gets is a session —
// listed, revoked and offboarded like the browser's, on clocks no longer than
// the browser's — kept in $XDG_CONFIG_HOME/cloop/hubs.json at 0600. Nothing
// here prints the credential, and pkg/hubclient refuses a credential file
// anybody else can read.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	loginCAFile    string
	loginNoBrowser bool
	loginDefault   bool
	loginHostname  string

	logoutAll   bool
	logoutForce bool

	whoamiJSON bool
)

var loginCmd = &cobra.Command{
	Use:   "login <hub-url>",
	Short: "Sign this terminal in to a hub with single sign-on",
	Long: `Sign this terminal in to a cloop hub that uses single sign-on.

The terminal prints a code and the hub's approval page. Open the page in a
browser signed in to the hub, check the code matches, and approve: your identity
provider confirms it is you, and this terminal gets a session of its own. It is a
session like your browser's — it idles out and expires (never later than a browser
session would), re-checks your roles with the identity provider, and can be
revoked from the dashboard's Active Sessions table or ended by ` + "`cloop logout`" + `.

Approve only a code you started yourself: approving signs whoever is running the
terminal in as you.

The session is kept in $XDG_CONFIG_HOME/cloop/hubs.json (~/.config/cloop/hubs.json)
with mode 0600. The first hub you sign in to becomes the default for
` + "`cloop remote`" + `, ` + "`cloop whoami`" + ` and ` + "`cloop task attach`" + `.

Examples:
  cloop login https://cloop.example.com
  cloop login https://cloop.internal --ca-file /etc/ssl/internal-ca.pem
  cloop login https://cloop.example.com --no-browser   # print the link only`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// An unsafe credential file is refused before the sign-in rather
		// than after it.
		if _, _, err := loadHubCredentials(true); err != nil {
			return err
		}
		hubURL, err := hubclient.NormalizeURL(args[0])
		if err != nil {
			return err
		}
		if plainHTTPToAnotherHost(hubURL) {
			fmt.Fprintf(os.Stderr, "warning: %s is plain http to another machine: the session credential will cross "+
				"the network unencrypted, for anybody on the path to read and use\n", hubURL)
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		opts := hubclient.LoginOptions{
			HubURL:   hubURL,
			CAFile:   strings.TrimSpace(loginCAFile),
			Hostname: loginHostname,
			Out:      os.Stderr,
		}
		if !loginNoBrowser && canOpenBrowser() {
			opts.OpenBrowser = openBrowserURL
		}
		h, err := hubclient.Login(ctx, opts)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return errors.New("sign-in cancelled")
			}
			return fmt.Errorf("sign in to %s: %w", hubURL, err)
		}
		// Read the file again: the sign-in took minutes, and a login or
		// logout of another hub in the meantime must not be undone by writing
		// back what was read before it.
		path, f, err := loadHubCredentials(true)
		var prior *hubclient.Hub
		if err == nil {
			prior = f.Hubs[h.URL]
			f.Put(h)
			if loginDefault {
				f.Default = h.URL
			}
			err = f.Save(path)
		}
		if err != nil {
			// A session nothing here holds is a credential nobody will
			// revoke: end it rather than leave it live at the hub.
			endSession(ctx, h)
			return fmt.Errorf("signed in to %s, but could not keep the session, so it was ended: %w", h.URL, err)
		}
		// A session this terminal held for the same hub before is replaced,
		// and ended there once the new one is kept: two live credentials for
		// one terminal is one more than anybody will remember to revoke.
		if prior != nil && prior.Credential != "" && prior.SessionID != h.SessionID {
			endSession(ctx, prior)
		}
		fmt.Printf("Signed in to %s as %s.\n", h.URL, h.Label())
		if !h.ExpiresAt.IsZero() {
			fmt.Printf("The session lasts until %s", h.ExpiresAt.Local().Format("2006-01-02 15:04 MST"))
			if _, idle := h.LoginNotes(); idle > 0 {
				fmt.Printf(", or until it goes unused for %s", idle)
			}
			fmt.Println(".")
		}
		if revalidated, _ := h.LoginNotes(); !revalidated {
			fmt.Fprintln(os.Stderr, "note: this hub keeps no refresh grant for the session (no CLOOP_SECRET_KEY on the "+
				"hub, or the identity provider issued none), so it cannot re-check your roles with the identity "+
				"provider: actions above operator need a fresh `cloop login` once your sign-in is older than the "+
				"hub's ui.oidc.max_claim_age_minutes")
		}
		if f.Default == h.URL && len(f.Hubs) > 1 {
			fmt.Printf("%s is the default hub.\n", h.URL)
		}
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout [hub-url]",
	Short: "End this terminal's session at a hub and forget it",
	Long: `End this terminal's session at a hub, then delete it from the credential file.

The session is revoked at the hub first — the same as revoking it from the
dashboard — and only then removed locally, so a credential that was copied
somewhere stops working too. If the hub cannot be reached, nothing is deleted
unless you pass --force: the session would otherwise stay valid at the hub, with
no copy left here to revoke it with.

Without a URL, the default hub is signed out. --all signs out of every hub, and
is also how to dispose of a credential file other users could read.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strict unless --all. Signing out of one hub writes the others back,
		// private again — and in a file other users could read they may have
		// been copied, so they must be revoked, not made to look safe.
		path, f, err := loadHubCredentials(!logoutAll)
		if err != nil {
			return err
		}
		var targets []string
		switch {
		case logoutAll:
			targets = f.URLs()
		case len(args) == 1:
			u, err := hubclient.NormalizeURL(args[0])
			if err != nil {
				return err
			}
			if _, ok := f.Hubs[u]; !ok {
				return fmt.Errorf("this terminal is not signed in to %s", u)
			}
			targets = []string{u}
		default:
			u, err := defaultHub(f)
			if err != nil {
				return err
			}
			targets = []string{u}
		}
		if len(targets) == 0 {
			fmt.Println("This terminal is not signed in to any hub.")
			return nil
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		var kept []string
		for _, u := range targets {
			h := f.Hubs[u]
			c, cerr := hubclient.New(h.URL, h.CAFile, h.Credential)
			if cerr == nil {
				var ended bool
				ended, cerr = c.Logout(ctx)
				switch {
				case cerr == nil && ended:
					fmt.Printf("Signed out of %s.\n", u)
				case cerr == nil || hubclient.IsUnauthorized(cerr):
					// Nothing live to end: revoked, expired or idle already.
					cerr = nil
					fmt.Printf("The session at %s had already ended; forgetting it.\n", u)
				}
			}
			if cerr != nil {
				if !logoutForce {
					kept = append(kept, u)
					fmt.Fprintf(os.Stderr, "could not end the session at %s: %v\n", u, cerr)
					continue
				}
				fmt.Fprintf(os.Stderr, "warning: could not end the session at %s (%v); deleting it here anyway — "+
					"it stays valid at the hub until it expires or is revoked from the dashboard's Active Sessions\n", u, cerr)
			}
			f.Remove(u)
		}
		if err := saveOrRemove(path, f); err != nil {
			return err
		}
		if len(kept) > 0 {
			return fmt.Errorf("kept the credentials for %s: the hub could not be reached to end the session. "+
				"Try again when it can, or pass --force to delete them anyway", strings.Join(kept, ", "))
		}
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami [hub-url]",
	Short: "Show who this terminal is signed in as",
	Long: `Ask a hub who this terminal's session is: your identity, your role, and how long
the session has left. Without a URL, the default hub is asked; with no session
for it, the hubs this terminal is signed in to are listed.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, f, err := loadHubCredentials(true)
		if err != nil {
			return err
		}
		u := ""
		if len(args) == 1 {
			if u, err = hubclient.NormalizeURL(args[0]); err != nil {
				return err
			}
		} else if u, err = defaultHub(f); err != nil {
			return err
		}
		h, ok := f.Hubs[u]
		if !ok {
			return fmt.Errorf("this terminal is not signed in to %s: run `cloop login %s`", u, u)
		}
		c, err := hubclient.New(h.URL, h.CAFile, h.Credential)
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		me, err := c.Me(ctx)
		if hubclient.IsUnauthorized(err) {
			return fmt.Errorf("the session at %s has ended (revoked, expired or idle): run `cloop login %s`", u, u)
		}
		if err != nil {
			return err
		}
		// The hub answers for whoever holds the session this credential
		// names. Somebody other than who signed in is never right.
		if sub, _ := me["sub"].(string); h.Subject != "" && sub != "" && sub != h.Subject {
			fmt.Fprintf(os.Stderr, "warning: %s answers for this terminal's session as %s, but it was signed in as %s — "+
				"run `cloop logout %s --force`, sign in again, and tell the hub's operator\n", h.URL, identityLine(me), h.Label(), h.URL)
		}
		if whoamiJSON {
			me["hub"] = h.URL
			me["session_id"] = h.SessionID
			return json.NewEncoder(os.Stdout).Encode(me)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Hub:\t%s\n", h.URL)
		fmt.Fprintf(w, "Signed in as:\t%s\n", identityLine(me))
		if kind, _ := me["session_kind"].(string); kind != "" {
			line := kind
			if client, _ := me["client"].(string); client != "" {
				line += " (" + client + ")"
			}
			fmt.Fprintf(w, "Session:\t%s, id %s\n", line, shortID(h.SessionID))
		}
		if role, _ := me["role"].(string); role != "" {
			fmt.Fprintf(w, "Role:\t%s\n", role)
		}
		if secs, ok := me["session_expires_in_seconds"].(float64); ok {
			fmt.Fprintf(w, "Expires in:\t%s\n", (time.Duration(secs) * time.Second).Round(time.Minute))
		}
		if secs, ok := me["idle_timeout_seconds"].(float64); ok && secs > 0 {
			fmt.Fprintf(w, "Ends when unused for:\t%s\n", time.Duration(secs)*time.Second)
		}
		// Sudo mode (Task 20448): how much longer this session may take the
		// actions that ask for a recent sign-in.
		if rs, ok := me["recent_sign_in"].(map[string]any); ok {
			if left, _ := rs["remaining_seconds"].(float64); left > 0 {
				fmt.Fprintf(w, "Privileged actions:\tfor %s more\n", (time.Duration(left) * time.Second).Round(time.Minute))
			} else {
				fmt.Fprintf(w, "Privileged actions:\tneed a fresh sign-in — run `cloop login %s`\n", u)
			}
		}
		if perms, ok := me["global_permissions"].([]any); ok && len(perms) > 0 {
			names := make([]string, 0, len(perms))
			for _, p := range perms {
				if s, ok := p.(string); ok {
					names = append(names, s)
				}
			}
			sort.Strings(names)
			fmt.Fprintf(w, "Hub-wide permissions:\t%s\n", strings.Join(names, ", "))
		}
		return w.Flush()
	},
}

// loadHubCredentials opens the credential file. strict refuses one other users
// can read; logout reads it anyway, to revoke what may have been copied.
func loadHubCredentials(strict bool) (string, *hubclient.File, error) {
	path, err := hubclient.DefaultPath()
	if err != nil {
		return "", nil, err
	}
	var f *hubclient.File
	if strict {
		f, err = hubclient.Load(path)
	} else {
		f, err = hubclient.LoadForRevocation(path)
	}
	if err != nil {
		return "", nil, err
	}
	return path, f, nil
}

// defaultHub is the hub a command acts on when none is named.
func defaultHub(f *hubclient.File) (string, error) {
	if f.Default != "" {
		if _, ok := f.Hubs[f.Default]; ok {
			return f.Default, nil
		}
	}
	urls := f.URLs()
	switch len(urls) {
	case 0:
		return "", errors.New("this terminal is not signed in to any hub: run `cloop login <hub-url>`")
	case 1:
		return urls[0], nil
	}
	return "", fmt.Errorf("this terminal is signed in to %d hubs and none is the default: name one (%s), "+
		"or make one the default with `cloop login <hub-url> --default`", len(urls), strings.Join(urls, ", "))
}

// endSession ends h's session at its hub, whatever the outcome — for one this
// terminal is replacing or could not keep.
func endSession(ctx context.Context, h *hubclient.Hub) {
	if c, err := hubclient.New(h.URL, h.CAFile, h.Credential); err == nil {
		_, _ = c.Logout(ctx)
	}
}

// plainHTTPToAnotherHost reports a hub URL that would carry the session
// credential unencrypted across a network: http, to anything but loopback.
func plainHTTPToAnotherHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// sameHub reports whether two hub URLs name the same hub, as the credential
// file keys them.
func sameHub(a, b string) bool {
	na, errA := hubclient.NormalizeURL(a)
	nb, errB := hubclient.NormalizeURL(b)
	if errA != nil || errB != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return na == nb
}

// saveOrRemove writes the credential file, or deletes it once no hub is left
// in it — an empty file is one more place a credential could have been.
func saveOrRemove(path string, f *hubclient.File) error {
	if len(f.Hubs) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	return f.Save(path)
}

// identityLine renders /api/me's identity: name <email> (sub).
func identityLine(me map[string]any) string {
	name, _ := me["name"].(string)
	email, _ := me["email"].(string)
	sub, _ := me["sub"].(string)
	var b strings.Builder
	switch {
	case name != "" && email != "" && name != email:
		b.WriteString(name + " <" + email + ">")
	case email != "":
		b.WriteString(email)
	case name != "":
		b.WriteString(name)
	default:
		b.WriteString(sub)
	}
	if sub != "" && b.String() != sub {
		b.WriteString(" (" + sub + ")")
	}
	return b.String()
}

// shortID is the first twelve characters of a session id: enough to find it
// in the Active Sessions table.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// canOpenBrowser reports whether this terminal has a browser to open: a
// desktop session, not an SSH login to a headless box, where opening one
// would start a text browser or fail noisily.
func canOpenBrowser() bool {
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	case "linux", "freebsd", "openbsd", "netbsd":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	}
	return false
}

// openBrowserURL opens url in the desktop's browser, as `cloop ui` does.
func openBrowserURL(url string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	if err := c.Start(); err != nil {
		return err
	}
	// Reaped in the background so the opener does not linger as a zombie
	// for as long as the sign-in waits.
	go func() { _ = c.Wait() }()
	return nil
}

func init() {
	loginCmd.Flags().StringVar(&loginCAFile, "ca-file", "",
		"PEM bundle to trust for the hub's certificate (kept with the session for later commands)")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false,
		"Print the approval link without opening a browser")
	loginCmd.Flags().BoolVar(&loginDefault, "default", false,
		"Make this hub the default for commands that name none")
	loginCmd.Flags().StringVar(&loginHostname, "hostname", "",
		"Name this machine on the approval page (default: the host name)")
	logoutCmd.Flags().BoolVar(&logoutAll, "all", false, "Sign out of every hub")
	logoutCmd.Flags().BoolVar(&logoutForce, "force", false,
		"Delete the credentials even if the hub cannot be reached to end the session")
	whoamiCmd.Flags().BoolVar(&whoamiJSON, "json", false, "Print the hub's answer as JSON")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
}
