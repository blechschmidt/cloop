package cmd

// hub_healthcheck.go exists because of a constraint the Dockerfile creates.
//
// The hub image is distroless: no shell, no curl, no wget. That is the right
// trade — a container whose filesystem contains no way to execute a command
// is a much less useful thing for an attacker to land in — but it removes the
// usual `HEALTHCHECK CMD curl -f localhost:8080/healthz`. The alternatives are
// to reintroduce a shell and a HTTP client into the runtime image, or to make
// the binary that is already there able to probe itself. This is the second.
//
// It is a *client*, not a second server: it makes one request to an existing
// hub and maps the answer onto an exit code, so it works identically as a
// Docker HEALTHCHECK, a Kubernetes exec probe, and a line in a shell script.
//
// The two endpoints answer different questions and the flag chooses which:
//
//	/healthz  is this process alive? Never fails while it can accept a
//	          connection, which is what a *restart* decision must be based
//	          on — restarting a hub because its database is briefly locked
//	          turns a stall into an outage.
//	/readyz   should traffic go here? Pings the state database, so it fails
//	          during startup and while storage is unavailable, which is what
//	          a *routing* decision must be based on.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// maxProbeBody bounds what a probe will read from a hub that answers with
// something unexpected. The endpoints return a few dozen bytes; anything
// larger is a misrouted request and must not be able to exhaust this process.
const maxProbeBody = 4 << 10

var hubHealthcheckCmd = &cobra.Command{
	Use:   "healthcheck",
	Short: "Probe a running hub's /healthz or /readyz and exit non-zero on failure",
	Long: `Probe a hub and turn the answer into an exit code.

Written for container images that contain no shell and no HTTP client — the
distroless runtime cloop's Dockerfile builds has neither, so the binary probes
itself:

  HEALTHCHECK CMD ["/usr/local/bin/cloop", "hub", "healthcheck"]

Also usable as a Kubernetes exec probe, or from a script.

Which endpoint to probe is a real choice, not a synonym:

  --endpoint healthz   (default) liveness. Answers "is this process alive",
                       and nothing else, so a restart is never triggered by a
                       dependency being slow.
  --endpoint readyz    readiness. Pings the state database, so it fails during
                       startup and whenever storage is unavailable — the right
                       signal for taking a replica out of a load balancer, and
                       the wrong one for killing it.

A hub that serves its own TLS is probed over https; pass --ca-file to trust a
certificate the system store does not. There is no skip-verify option — the
certificate is a file on this host, so trusting it specifically is both
available and narrower.

Exit codes: 0 healthy, 1 unhealthy (non-2xx, unreachable, or timed out).`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runHubHealthcheck,
}

func runHubHealthcheck(cmd *cobra.Command, _ []string) error {
	base, _ := cmd.Flags().GetString("url")
	endpoint, _ := cmd.Flags().GetString("endpoint")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	caFile, _ := cmd.Flags().GetString("ca-file")

	switch endpoint {
	case "healthz", "readyz":
	default:
		return fmt.Errorf("--endpoint must be healthz or readyz (got %q)", endpoint)
	}
	if timeout <= 0 {
		return fmt.Errorf("--timeout must be positive (got %s)", timeout)
	}

	url := strings.TrimRight(strings.TrimSpace(base), "/") + "/" + endpoint

	// A dedicated transport, not http.DefaultClient: probes run every few
	// seconds forever, and a pooled idle connection to a hub that has since
	// restarted produces a spurious failure at exactly the wrong moment.
	tr := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil, // a probe to localhost must never go via a proxy
	}
	// A hub serving its own TLS is probed over TLS, so the probe needs to
	// trust the certificate. --ca-file rather than a skip-verify switch: the
	// certificate is a file on the same host, so "trust this CA" is available
	// and is strictly narrower than "trust anything". A probe that skipped
	// verification would also be the one piece of cloop that dials TLS
	// without checking it, which is a bad precedent to set for a convenience.
	tlsCfg, err := tlsconf.ClientConfig(tlsconf.ClientOptions{RootCAFile: caFile})
	if err != nil {
		return err
	}
	tr.TLSClientConfig = tlsCfg
	client := &http.Client{Transport: tr, Timeout: timeout}
	defer tr.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build probe request for %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeFailure(fmt.Sprintf("%s is unreachable: %v", url, err))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
		detail := strings.TrimSpace(string(body))
		if detail != "" {
			detail = ": " + detail
		}
		return probeFailure(fmt.Sprintf("%s returned %s%s", url, resp.Status, detail))
	}
	return nil
}

// probeFailure reports on stderr and exits 1 without Cobra's error decoration.
// A HEALTHCHECK's output is captured verbatim into `docker inspect`, and a
// usage banner there is noise that hides the one line that matters.
func probeFailure(msg string) error {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
	return nil // unreachable
}

func init() {
	hubHealthcheckCmd.Flags().String("url", "http://127.0.0.1:8080",
		"base URL of the hub to probe")
	hubHealthcheckCmd.Flags().String("endpoint", "healthz",
		"which probe to run: healthz (liveness) or readyz (readiness)")
	hubHealthcheckCmd.Flags().Duration("timeout", 3*time.Second,
		"give up after this long")
	hubHealthcheckCmd.Flags().String("ca-file", "",
		"PEM bundle to trust in addition to the system store, for a hub serving its own certificate")

	hubCmd.AddCommand(hubHealthcheckCmd)
}
