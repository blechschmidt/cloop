// Scoped egress grants (Task 20163).
//
// `cloop egress` is the operator's side of pkg/egressbroker: it writes the
// grants that say which destinations a sandbox may reach, and it provides
// `cloop egress test` so that "can this project reach api.github.com?" is a
// question answerable in one command rather than by starting a container and
// reading a stack trace.
//
// It deliberately mirrors `cloop secret grant`: same --to syntax, same --ttl,
// same table shape. Network egress is the fourth grantable resource, and an
// operator who has learned the first three should not have to learn a fourth
// interface for it.

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	egressToFlag         string
	egressScopeFlag      string
	egressHostsFlag      []string
	egressCIDRsFlag      []string
	egressPortsFlag      []int
	egressMethodsFlag    []string
	egressMaxUpFlag      string
	egressMaxDownFlag    string
	egressSessionTTLFlag string
	egressTTLFlag        string

	egressListAllFlag     bool
	egressListSubjectFlag string

	egressTestToFlag    string
	egressTestGrantFlag string
	egressTestTimeout   string
)

var egressCmd = &cobra.Command{
	Use:   "egress",
	Short: "Broker the hub's Internet connection to isolated executors",
	Long: `Grant network egress to sandboxes that have no network of their own.

A container, Pod, or remote executor started with network isolation cannot
reach the Internet directly. With an egress grant it reaches the control
plane's forward proxy instead, which opens a connection only to destinations
the grant names — resolving each name once and dialling the resolved address,
so a hostile DNS answer cannot redirect an authorised connection inward.

  cloop egress grant --to project:/srv/app --hosts 'api.github.com,*.githubusercontent.com'
  cloop egress list
  cloop egress test https://api.github.com/rate_limit
  cloop egress revoke egress_2f1c...

Private, loopback, and link-local destinations — including the cloud metadata
service at 169.254.169.254 — are refused even under --hosts '*'. Reaching one
requires naming its range in --cidrs, so an internal destination is always a
sentence somebody wrote on purpose.`,
}

// openEgressBroker builds an egress broker over the current project's state
// database, wired to the same hash-chained audit log the secret broker uses.
//
// The returned close function must be called.
func openEgressBroker() (*egressbroker.Broker, func(), error) {
	workDir, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("egress: resolve working directory: %w", err)
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return nil, nil, fmt.Errorf("egress: open state database: %w", err)
	}
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	opts := []egressbroker.Option{
		egressbroker.WithAuditor(secretstore.NewAuditor(db)),
	}
	// Config is advisory here: a project whose config cannot be read still
	// gets a working broker on the defaults rather than a command that
	// refuses to list grants.
	if cfg, cerr := config.Load(workDir); cerr == nil {
		if m := cfg.Executors.Egress.MaxSessionMinutes; m > 0 {
			opts = append(opts, egressbroker.WithMaxSessionTTL(time.Duration(m)*time.Minute))
		}
		if a := strings.TrimSpace(cfg.Executors.Egress.AdvertiseAddr); a != "" {
			opts = append(opts, egressbroker.WithEndpoint(a))
		}
	}

	broker, err := egressbroker.New(store, opts...)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return broker, func() { _ = db.Close() }, nil
}

// egressQuotaDefaults reads the configured per-session quotas, used when a
// grant is created without explicit ones.
func egressQuotaDefaults(workDir string) (up, down int64) {
	cfg, err := config.Load(workDir)
	if err != nil {
		return 0, 0
	}
	up, _ = egressbroker.ParseBytes(cfg.Executors.Egress.DefaultMaxBytesUp)
	down, _ = egressbroker.ParseBytes(cfg.Executors.Egress.DefaultMaxBytesDown)
	return up, down
}

var egressGrantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Grant a subject scoped, expiring network egress",
	Long: `Authorise a project, an executor, or a labelled fleet to reach named
destinations through the control plane's proxy.

  cloop egress grant --to project:/srv/app --hosts 'api.github.com' --ttl 8h
  cloop egress grant --to executor:edge-01 --hosts '*.pypi.org' --ports 443 --max-down 500m
  cloop egress grant --to label:region=eu --cidrs 10.20.0.0/16 --ports 5432

At least one of --hosts and --cidrs is required; there is no implicit
wildcard. --ports defaults to 80,443 and is written into the grant, so a
listing always shows the ports that will actually be honoured.

--cidrs is both a second allow dimension and the only way to reach a private
address: listing 10.0.0.0/8 waives the SSRF block for exactly that range and
nothing else.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(egressToFlag) == "" {
			return fmt.Errorf("egress: --to is required (e.g. --to project:/srv/app)")
		}
		subject, err := secretbroker.ParseSubject(egressToFlag)
		if err != nil {
			return err
		}
		ttl, err := parseEgressDuration("--ttl", egressTTLFlag)
		if err != nil {
			return err
		}
		sessionTTL, err := parseEgressDuration("--session-ttl", egressSessionTTLFlag)
		if err != nil {
			return err
		}
		maxUp, err := egressbroker.ParseBytes(egressMaxUpFlag)
		if err != nil {
			return fmt.Errorf("egress: invalid --max-up: %w", err)
		}
		maxDown, err := egressbroker.ParseBytes(egressMaxDownFlag)
		if err != nil {
			return fmt.Errorf("egress: invalid --max-down: %w", err)
		}
		if workDir, werr := os.Getwd(); werr == nil {
			defUp, defDown := egressQuotaDefaults(workDir)
			if maxUp == 0 {
				maxUp = defUp
			}
			if maxDown == 0 {
				maxDown = defDown
			}
		}

		broker, closeFn, err := openEgressBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		g, err := broker.Grant(cmd.Context(), egressbroker.GrantRequest{
			Subject:      subject,
			Scope:        egressScopeFlag,
			Hosts:        splitCommaFlags(egressHostsFlag),
			CIDRs:        splitCommaFlags(egressCIDRsFlag),
			Ports:        egressPortsFlag,
			Methods:      splitCommaFlags(egressMethodsFlag),
			MaxBytesUp:   maxUp,
			MaxBytesDown: maxDown,
			SessionTTL:   sessionTTL,
			TTL:          ttl,
			Actor:        currentActor(),
		})
		if err != nil {
			return err
		}

		color.Green("✓ granted egress %s", g.ID)
		faint := color.New(color.Faint)
		faint.Printf("  to      %s\n", g.Subject.String())
		faint.Printf("  policy  %s\n", g.Summary())
		faint.Printf("  expires %s\n", g.ExpiresAt.Local().Format(time.RFC1123))
		if !hasPrivateCIDR(g.CIDRs) {
			faint.Println("  private, loopback, and metadata destinations remain blocked")
		} else {
			color.New(color.FgYellow).Println("  ! this grant opens a private range — verify the CIDRs above")
		}
		return nil
	},
}

// hasPrivateCIDR reports whether any listed prefix reaches inward, so the
// grant confirmation can say which of the two situations the operator is in
// rather than printing the same reassurance either way.
func hasPrivateCIDR(cidrs []string) bool {
	for _, c := range cidrs {
		if pfx, err := netip.ParsePrefix(c); err == nil {
			if egressbroker.BlockReason(pfx.Addr()) != "" {
				return true
			}
		}
	}
	return false
}

var egressListCmd = &cobra.Command{
	Use:   "list",
	Short: "List egress grants",
	Long: `Show egress grants and the destinations they permit.

By default only active grants are listed. --all includes expired and revoked
ones, which is what an audit reader wants: a grant that is gone still
explains what a sandbox could reach while it existed.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		broker, closeFn, err := openEgressBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		grants, err := broker.ListGrants(egressbroker.GrantFilter{
			Subject:    strings.TrimSpace(egressListSubjectFlag),
			ActiveOnly: !egressListAllFlag,
		})
		if err != nil {
			return err
		}
		if len(grants) == 0 {
			if egressListAllFlag {
				fmt.Println("No egress grants.")
			} else {
				fmt.Println("No active egress grants. Use --all to include expired and revoked ones.")
			}
			return nil
		}

		// The ID column is 32 wide because an egress ID is exactly 31
		// characters ("egress_" plus 24 hex); a narrower column would wrap
		// the one field an operator copies out of this table to paste into
		// `cloop egress revoke`.
		bold := color.New(color.Bold)
		fmt.Printf("%-32s %-30s %-10s %-21s %s\n",
			bold.Sprint("ID"), bold.Sprint("SUBJECT"), bold.Sprint("STATUS"),
			bold.Sprint("EXPIRES"), bold.Sprint("POLICY"))
		fmt.Println(strings.Repeat("─", 130))

		now := time.Now()
		for _, g := range grants {
			status := "active"
			paint := color.New(color.FgGreen)
			if reason := g.DenyReason(now); reason != "" {
				if !g.RevokedAt.IsZero() {
					status, paint = "revoked", color.New(color.FgRed)
				} else {
					status, paint = "expired", color.New(color.Faint)
				}
			}
			expires := "never"
			if !g.ExpiresAt.IsZero() {
				expires = g.ExpiresAt.Local().Format("2006-01-02 15:04:05")
			}
			fmt.Printf("%-32s %-30s %-10s %-21s %s\n",
				g.ID, truncate(g.Subject.String(), 30), paint.Sprint(status), expires, g.Summary())
		}
		return nil
	},
}

var egressRevokeCmd = &cobra.Command{
	Use:   "revoke <grant-id>",
	Short: "Revoke an egress grant and close its live sessions",
	Long: `Withdraw a grant.

Unlike a credential grant, revocation here is immediate rather than bounded by
a lease TTL: the capability is brokered, so every live proxy session issued
under the grant is torn down at the proxy — mid-tunnel if necessary — by the
control-plane process that holds it. A revoked grant cannot be re-redeemed.

Revoking an already-revoked grant is a success, so a retry is not an error.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		broker, closeFn, err := openEgressBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		if err := broker.Revoke(cmd.Context(), args[0], currentActor()); err != nil {
			return err
		}
		color.Green("✓ revoked %s", args[0])
		color.New(color.Faint).Println("  live sessions in *this* process were closed; a running " +
			"control plane closes its own on the next grant read")
		return nil
	},
}

var egressTestCmd = &cobra.Command{
	Use:   "test <url>",
	Short: "Check whether a URL is reachable under the current grants",
	Long: `Answer "can this project reach that URL?" without starting a sandbox.

It redeems a real session against the matching grant, starts an ephemeral
proxy on loopback, and makes the request through it — so the verdict comes
from the same code path a container would hit, including the resolve-once
pinning and the SSRF block, rather than from a re-implementation of the rules.

  cloop egress test https://api.github.com/rate_limit
  cloop egress test http://example.com --to executor:edge-01

The session is closed and the proxy shut down when the command exits. The
request is audited exactly as a sandbox's would be.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := url.Parse(strings.TrimSpace(args[0]))
		if err != nil || !target.IsAbs() || target.Host == "" {
			return fmt.Errorf("egress: %q is not an absolute URL (try https://api.github.com/)", args[0])
		}
		switch strings.ToLower(target.Scheme) {
		case "http", "https":
		default:
			return fmt.Errorf("egress: scheme %q is not proxyable (want http or https)", target.Scheme)
		}
		timeout, err := parseEgressDuration("--timeout", egressTestTimeout)
		if err != nil {
			return err
		}
		if timeout == 0 {
			timeout = 30 * time.Second
		}

		workDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("egress: resolve working directory: %w", err)
		}
		requester, err := egressTestRequester(workDir)
		if err != nil {
			return err
		}

		broker, closeFn, err := openEgressBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		// Bind loopback: the client is this process, so nothing else needs to
		// route to it, and an ephemeral port keeps the check from colliding
		// with a control plane's own proxy.
		proxy, err := egressbroker.NewProxy(broker, egressbroker.Options{
			ListenAddr: "127.0.0.1:0",
		})
		if err != nil {
			return err
		}
		serveErr := make(chan error, 1)
		go func() { serveErr <- proxy.ListenAndServe() }()
		defer func() { _ = proxy.Close() }()

		if err := waitForProxy(proxy, serveErr, 5*time.Second); err != nil {
			return err
		}

		red, err := broker.Redeem(cmd.Context(), egressbroker.RedeemRequest{
			Requester: requester,
			TaskID:    "egress-test",
			Actor:     currentActor(),
			GrantID:   strings.TrimSpace(egressTestGrantFlag),
		})
		if err != nil {
			return err
		}
		// Shut down in dependency order, which defers reverse for us: this
		// one runs first and closes the proxy (draining any handler still
		// writing an audit row), then retires the session, and only then does
		// the outer closeFn close the database. Getting this backwards leaves
		// a torn-down transfer's verdict unrecorded. Proxy.Close is
		// idempotent, so the standalone defer above stays as the safety net
		// for the paths that fail before redemption.
		defer func() {
			_ = proxy.Close()
			broker.CloseSession(red.Session.ID, "test finished")
		}()

		faint := color.New(color.Faint)
		faint.Printf("grant   %s\n", red.Session.GrantID)
		faint.Printf("policy  %s\n", red.Session.Grant.Summary())
		faint.Printf("session %s (expires %s)\n", red.Session.ID,
			red.Session.ExpiresAt.Local().Format("15:04:05"))
		fmt.Println()

		ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
		defer cancel()

		// For an https target, probe the tunnel first.
		//
		// Go's Transport reduces a refused CONNECT to the response's reason
		// phrase — the operator sees "Forbidden" and nothing else, because
		// the verdict header and body are discarded before the error is
		// constructed. Since telling the operator *why* is this command's
		// entire job, the probe opens the tunnel by hand to read them. It
		// costs one extra tunnel on the success path, which for a
		// connectivity check is not a cost worth optimising.
		if strings.EqualFold(target.Scheme, "https") {
			verdict, detail, perr := egressConnectProbe(ctx, red, target)
			if perr != nil {
				color.Red("✗ %s", target.Redacted())
				fmt.Printf("  %v\n", perr)
				return fmt.Errorf("egress: tunnel could not be opened")
			}
			if verdict != "" && verdict != "allow" {
				color.Red("✗ %s", target.Redacted())
				fmt.Printf("  verdict %s\n  %s\n", verdict, strings.TrimSpace(detail))
				return fmt.Errorf("egress: %s", verdict)
			}
		}

		status, verdict, body, err := egressTestRequest(ctx, red, target)

		switch {
		case err != nil:
			color.Red("✗ %s", target.Redacted())
			fmt.Printf("  %v\n", err)
			// A transfer cut mid-tunnel reaches the client as a bare EOF —
			// the TLS record stream simply stops, and there is no HTTP status
			// left to carry a reason. The session's own counters still know
			// what happened, so read the verdict off them rather than leaving
			// the operator with "EOF".
			if hint := egressFailureHint(red); hint != "" {
				fmt.Printf("  %s\n", hint)
			}
			// A non-zero exit matters: this command is useful in a CI gate,
			// and a gate that always exits 0 is decoration.
			return fmt.Errorf("egress: request refused or failed")
		case verdict != "" && verdict != "allow":
			color.Red("✗ %s", target.Redacted())
			fmt.Printf("  verdict %s\n  %s\n", verdict, strings.TrimSpace(body))
			return fmt.Errorf("egress: %s", verdict)
		default:
			color.Green("✓ %s", target.Redacted())
			fmt.Printf("  status  %d\n", status)
			fmt.Printf("  bytes   up %s / down %s\n",
				egressbroker.FormatBytes(red.Session.BytesUp()),
				egressbroker.FormatBytes(red.Session.BytesDown()))
			return nil
		}
	},
}

// egressTestRequester builds the identity the test request is made under.
//
// It uses the working directory as the project, matching how a run in this
// directory would be scoped, and a fixed "cli" executor ID so an
// executor-scoped grant is not accidentally satisfied by the test command.
func egressTestRequester(workDir string) (secretbroker.Requester, error) {
	if strings.TrimSpace(egressTestToFlag) != "" {
		sub, err := secretbroker.ParseSubject(egressTestToFlag)
		if err != nil {
			return secretbroker.Requester{}, err
		}
		switch sub.Type {
		case secretbroker.SubjectExecutor:
			return secretbroker.Requester{ExecutorID: sub.Value, ProjectID: workDir}, nil
		case secretbroker.SubjectProject:
			return secretbroker.Requester{ExecutorID: "cli", ProjectID: sub.Value}, nil
		case secretbroker.SubjectLabel:
			return secretbroker.Requester{ExecutorID: "cli", ProjectID: workDir, Labels: sub.Labels}, nil
		default:
			return secretbroker.Requester{ExecutorID: "cli", ProjectID: workDir}, nil
		}
	}
	return secretbroker.Requester{ExecutorID: "cli", ProjectID: workDir}, nil
}

// waitForProxy blocks until the listener has an address, so the client cannot
// be pointed at a port that is not bound yet.
//
// It watches serveErr as well as the clock: a bind failure is immediate and
// specific ("address already in use"), and reporting it as "did not start
// within 5s" would both waste the wait and hide the cause.
func waitForProxy(p *egressbroker.Proxy, serveErr <-chan error, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if p.Addr() != "" {
			return nil
		}
		select {
		case err := <-serveErr:
			if err != nil {
				return err
			}
			return fmt.Errorf("egress: proxy stopped before it accepted a connection")
		case <-time.After(5 * time.Millisecond):
		}
	}
	return fmt.Errorf("egress: proxy did not start within %s", limit)
}

// egressFailureHint explains a transport-level failure from the session's
// state, for the cases where the tunnel died without an HTTP status to carry
// a reason.
func egressFailureHint(red *egressbroker.Redemption) string {
	s := red.Session
	g := s.Grant
	switch {
	case g.MaxBytesDown > 0 && s.BytesDown() >= g.MaxBytesDown:
		return fmt.Sprintf("verdict quota_exceeded — the %s download budget is spent (%s transferred)",
			egressbroker.FormatBytes(g.MaxBytesDown), egressbroker.FormatBytes(s.BytesDown()))
	case g.MaxBytesUp > 0 && s.BytesUp() >= g.MaxBytesUp:
		return fmt.Sprintf("verdict quota_exceeded — the %s upload budget is spent (%s transferred)",
			egressbroker.FormatBytes(g.MaxBytesUp), egressbroker.FormatBytes(s.BytesUp()))
	case s.Closed() || !time.Now().Before(s.ExpiresAt):
		return "verdict session_expired — the proxy session ended mid-request"
	default:
		return ""
	}
}

// egressConnectProbe opens a CONNECT tunnel by hand and reports the proxy's
// verdict, so a refusal reaches the operator with its reason attached rather
// than as a bare "Forbidden".
//
// It returns ("allow", "", nil) when the tunnel opened, and closes it
// immediately — this is a policy probe, not the request.
func egressConnectProbe(ctx context.Context, red *egressbroker.Redemption, target *url.URL) (string, string, error) {
	proxyURL, err := url.Parse(red.ProxyURL)
	if err != nil {
		return "", "", fmt.Errorf("egress: parse proxy url: %w", err)
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	authority := net.JoinHostPort(target.Hostname(), port)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return "", "", fmt.Errorf("egress: reach proxy at %s: %w", proxyURL.Host, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	pass, _ := proxyURL.User.Password()
	if _, err := fmt.Fprintf(conn,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		authority, authority,
		egressbroker.FormatProxyCredential(proxyURL.User.Username(), pass),
	); err != nil {
		return "", "", fmt.Errorf("egress: send CONNECT: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", "", fmt.Errorf("egress: read CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "allow", "", nil
	}
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	verdict := resp.Header.Get("X-Cloop-Egress-Verdict")
	if verdict == "" {
		verdict = strings.ToLower(http.StatusText(resp.StatusCode))
	}
	return verdict, string(detail), nil
}

// egressTestRequest performs the probe through the session's proxy and
// returns the origin's status, the proxy's verdict header, and a short body
// excerpt.
func egressTestRequest(ctx context.Context, red *egressbroker.Redemption, target *url.URL) (int, string, string, error) {
	proxyURL, err := url.Parse(red.ProxyURL)
	if err != nil {
		return 0, "", "", fmt.Errorf("egress: parse proxy url: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()

	// Bounded read: this is a connectivity check, not a download, and the
	// body only exists here to quote a refusal back to the operator.
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, resp.Header.Get("X-Cloop-Egress-Verdict"), string(excerpt), nil
}

// splitCommaFlags flattens repeated and comma-joined flag values, so
// --hosts a --hosts b and --hosts a,b mean the same thing.
func splitCommaFlags(in []string) []string {
	var out []string
	for _, v := range in {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// parseEgressDuration parses a positive duration flag, naming the flag in the
// error so a bad value points at itself.
func parseEgressDuration(flag, s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("egress: invalid %s %q: %w (try 24h, 90m, 7d as 168h)", flag, s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("egress: %s must be positive, got %s", flag, s)
	}
	return d, nil
}

func init() {
	egressGrantCmd.Flags().StringVar(&egressToFlag, "to", "",
		"subject: project:<path>, executor:<id>, label:k=v, or any")
	egressGrantCmd.Flags().StringVar(&egressScopeFlag, "scope", "",
		"operator label for grouping (carries no authority)")
	egressGrantCmd.Flags().StringSliceVar(&egressHostsFlag, "hosts", nil,
		"destination allowlist: api.example.com, *.example.com, or '*'")
	egressGrantCmd.Flags().StringSliceVar(&egressCIDRsFlag, "cidrs", nil,
		"destination CIDRs; listing a private range is the only way to reach it")
	egressGrantCmd.Flags().IntSliceVar(&egressPortsFlag, "ports", nil,
		"destination ports (default 80,443)")
	egressGrantCmd.Flags().StringSliceVar(&egressMethodsFlag, "methods", nil,
		"HTTP methods for plain-HTTP requests (default '*'; CONNECT tunnels are opaque)")
	egressGrantCmd.Flags().StringVar(&egressMaxUpFlag, "max-up", "",
		"per-session upload quota (100m, 2g); empty means unlimited")
	egressGrantCmd.Flags().StringVar(&egressMaxDownFlag, "max-down", "",
		"per-session download quota (100m, 2g); empty means unlimited")
	egressGrantCmd.Flags().StringVar(&egressSessionTTLFlag, "session-ttl", "",
		"lifetime of one redeemed proxy session (default 15m)")
	egressGrantCmd.Flags().StringVar(&egressTTLFlag, "ttl", "",
		"lifetime of the grant itself (default 24h)")

	egressListCmd.Flags().BoolVar(&egressListAllFlag, "all", false,
		"include expired and revoked grants")
	egressListCmd.Flags().StringVar(&egressListSubjectFlag, "to", "",
		"only grants for this subject")

	egressTestCmd.Flags().StringVar(&egressTestToFlag, "to", "",
		"identity to test as (default project:<cwd>)")
	egressTestCmd.Flags().StringVar(&egressTestGrantFlag, "grant", "",
		"pin the test to one grant id")
	egressTestCmd.Flags().StringVar(&egressTestTimeout, "timeout", "",
		"request timeout (default 30s)")

	egressCmd.AddCommand(egressGrantCmd)
	egressCmd.AddCommand(egressListCmd)
	egressCmd.AddCommand(egressRevokeCmd)
	egressCmd.AddCommand(egressTestCmd)
	rootCmd.AddCommand(egressCmd)
}
