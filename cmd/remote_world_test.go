package cmd

// The world the `cloop remote` tests run in (Task 20417): a hub with single
// sign-on in this process (internal/ssohubtest), its work dispatched to this
// test binary acting as cloop, and a terminal whose credential file holds a
// session minted by the device flow for whichever identity a test signs in as.

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

// The identities the tests sign in as, one per rung of the default policy.
const (
	rootEmail  = "root@example.com"  // admin, by ui.oidc.admin_emails
	alexEmail  = "alex@example.com"  // maintainer
	oliveEmail = "olive@example.com" // operator
	vicEmail   = "vic@example.com"   // viewer
)

// cliSelfExe writes the wrapper a test hub dispatches its work through: this
// test binary, told to act as cloop (see TestMain).
func cliSelfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cloop")
	script := "#!/bin/sh\n" + cliReexecEnv + "=1 exec " + quoteArg(exe) + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// remoteWorld is a hub and the terminal talking to it.
type remoteWorld struct {
	hub      *ssohubtest.Hub
	credPath string
}

func newRemoteWorld(t *testing.T) *remoteWorld {
	t.Helper()
	credPath := credentialHome(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{
		SelfExe:     cliSelfExe(t),
		AdminEmails: []string{rootEmail},
	})
	// What a commit made by the hub's own work is attributed to, in a child
	// that has no git identity of its own.
	for k, v := range map[string]string{
		"GIT_AUTHOR_NAME": "Remote Test", "GIT_AUTHOR_EMAIL": "remote-test@example.com",
		"GIT_COMMITTER_NAME": "Remote Test", "GIT_COMMITTER_EMAIL": "remote-test@example.com",
	} {
		t.Setenv(k, v)
	}
	return &remoteWorld{hub: hub, credPath: credPath}
}

// as signs the terminal in as email with groups, replacing whoever it was.
func (w *remoteWorld) as(t *testing.T, email string, groups ...string) {
	t.Helper()
	cred := w.hub.Login(t, email, groups...)
	_ = os.Remove(w.credPath)
	writeCredentials(t, w.credPath, &hubclient.Hub{
		URL: mustNormalize(t, w.hub.URL), Credential: cred, SessionID: "terminal", Email: email,
	})
}

// browser signs a browser in as email with groups: the dashboard a test
// compares a terminal's answer against.
func (w *remoteWorld) browser(t *testing.T, email string, groups ...string) *http.Client {
	t.Helper()
	return w.hub.SignIn(t, email, groups...)
}

// runRemoteCLI runs `cloop remote <args>` as a terminal would: through the root
// command, its flags parsed from args and reset afterwards.
func runRemoteCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(remoteCmd)
	t.Cleanup(func() { resetFlags(remoteCmd) })
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"remote"}, args...))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := rootCmd.ExecuteContextC(ctx)
	return out.String(), err
}

// resetFlags puts every flag of c and its subcommands back to its default,
// so one test's flags do not leak into the next run of the same command —
// and drops the context cobra keeps on a command from the run that first
// reached it, which by the next run has been cancelled.
func resetFlags(c *cobra.Command) {
	c.SetContext(nil) //nolint:staticcheck // nil is cobra's "inherit from the parent"
	reset := func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	c.Flags().VisitAll(reset)
	c.PersistentFlags().VisitAll(reset)
	for _, sub := range c.Commands() {
		resetFlags(sub)
	}
}

// checkoutOf makes a git checkout whose origin is remote and changes into it.
func checkoutOf(t *testing.T, remote string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	if remote != "" {
		gitIn(t, dir, "remote", "add", "origin", remote)
	}
	t.Chdir(dir)
	return dir
}
