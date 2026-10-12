package kube_test

// share_test.go proves `cloop remote kube share` end to end on a real cluster
// (Task 20416).
//
// The other test in this package runs the chart's hub inside the cluster. This
// one needs only the cluster: the hub under test runs here, as `cloop ui`, with
// the Kubernetes access monitor on and the host executor, exactly as a hub on a
// developer's own machine would — which is what lets the test cross a token's
// expiry with a run still in flight and look at both sides.
//
// # What it does
//
//  1. Creates four namespaces: two to share, one the ServiceAccount lives in,
//     one for the "developer" — a ServiceAccount holding `admin` in the first
//     three, the way a developer holds it in their team's namespaces, whose
//     token a fake exec credential plugin prints. The developer's kubeconfig
//     signs in through that plugin (client.authentication.k8s.io/v1, relative
//     command path, provideClusterInfo), so nothing in it is a static
//     credential.
//  2. Starts a hub with executors.kube_guard on (tls: auto) and runs `cloop
//     remote kube share --access write --ttl 10m` against it — ten minutes being
//     the shortest token the TokenRequest API will issue. Checks the plugin ran
//     with the cluster's details, the five objects and their RBAC, that RBAC
//     itself would let the ServiceAccount mint its own token (so the refusals
//     below are the monitor's), and `cloop remote kube list`.
//  3. Grants the share to the hub's project for writes in all three namespaces
//     and dispatches a task running share_probe.sh: kubectl through the monitor
//     reads and writes (P1, P2), and is refused the ServiceAccount's own token
//     (P3), a raw TokenRequest for another (P4), and kube-system (P5).
//  4. Waits for the hub to renew the share at half-life, then until the token
//     the run's session started with has expired (plus the API server's minute
//     of leeway), and has the probe read and write again (P6) — the same
//     session, now presenting the renewed token. A configmap written then is
//     checked from outside.
//  5. Runs `cloop remote kube revoke`, checks no labelled object is left in any
//     namespace and the secret is gone, and has the probe confirm the run is cut
//     off (P7). Then reads the audit trail for the renewal and the monitor's
//     refusals.
//
// It takes about thirteen minutes, nearly all of it waiting for the first token
// to expire. Opt in with CLOOP_KUBE_E2E_KUBECONFIG (cluster-admin on a
// throwaway cluster); CLOOP_KUBE_E2E_CLOOP_BIN supplies the binary.

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

//go:embed share_probe.sh
var shareProbe string

// shareTTL is the shortest token the TokenRequest API issues, which makes the
// expiry the test has to outlast as short as it can be.
const shareTTL = 10 * time.Minute

// tokenLeeway is how long past a token's expiry the API server still accepts
// it (the JWT validator's default leeway), plus margin.
const tokenLeeway = 90 * time.Second

func TestKubeShareWithAnExecPlugin(t *testing.T) {
	kubeconfig := os.Getenv(kubeconfigEnv)
	if kubeconfig == "" {
		t.Skipf("set %s to a throwaway cluster's kubeconfig to run this", kubeconfigEnv)
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Fatalf("kubectl is not on PATH: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Minute)
	defer cancel()
	x := tool{t: t, kubeconfig: kubeconfig}
	root := repoRoot(t)
	work := t.TempDir()
	if w, err := filepath.EvalSymlinks(work); err == nil {
		work = w
	}

	cloop := os.Getenv(binEnv)
	if cloop == "" {
		cloop = filepath.Join(work, "cloop")
		goBuild(ctx, t, root, cloop, ".")
	}

	// ── the cluster: three namespaces and a developer ───────────────────────
	stamp := strings.ToLower(randomAlnum(t, 6))
	nsA, nsB, nsSA, nsDev := "share-a-"+stamp, "share-b-"+stamp, "share-sa-"+stamp, "share-dev-"+stamp
	for _, ns := range []string{nsA, nsB, nsSA, nsDev} {
		x.kubectl(ctx, "create", "namespace", ns)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer ccancel()
		_, _ = x.run(cctx, nil, true, "kubectl", "delete", "namespace", nsA, nsB, nsSA, nsDev, "--wait=false")
	})
	x.kubectl(ctx, "-n", nsDev, "create", "serviceaccount", "developer")
	for _, ns := range []string{nsA, nsB, nsSA} {
		x.kubectl(ctx, "-n", ns, "create", "rolebinding", "developer-admin", "--clusterrole=admin",
			"--serviceaccount="+nsDev+":developer")
	}
	devToken := x.out(ctx, "-n", nsDev, "create", "token", "developer", "--duration=2h")
	server := x.out(ctx, "config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
	caData := x.out(ctx, "config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	if server == "" || caData == "" {
		t.Fatalf("the cluster's kubeconfig names no server or CA (server %q)", server)
	}

	// The developer's kubeconfig signs in only through the plugin.
	devDir := filepath.Join(work, "dev")
	if err := os.MkdirAll(filepath.Join(devDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginRan := filepath.Join(work, "plugin-ran")
	plugin := `#!/bin/sh
printf '%s\n' "$KUBERNETES_EXEC_INFO" >> '` + pluginRan + `'
echo "fake-kubelogin: signed in" >&2
printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%s","expirationTimestamp":"%s"}}' \
  '` + devToken + `' "$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+1H +%Y-%m-%dT%H:%M:%SZ)"
`
	if err := os.WriteFile(filepath.Join(devDir, "bin", "fake-kubelogin"), []byte(plugin), 0o755); err != nil {
		t.Fatal(err)
	}
	devKubeconfig := filepath.Join(devDir, "kubeconfig")
	if err := os.WriteFile(devKubeconfig, []byte(`apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: kind
  cluster:
    server: `+server+`
    certificate-authority-data: `+caData+`
contexts:
- name: dev
  context: {cluster: kind, user: entra-dev, namespace: `+nsA+`}
users:
- name: entra-dev
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ./bin/fake-kubelogin
      args: [get-token, --login, devicecode]
      interactiveMode: Never
      provideClusterInfo: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// ── the hub ─────────────────────────────────────────────────────────────
	hubPort, guardPort := freePort(t), freePort(t)
	hubDir := filepath.Join(work, "hub")
	if err := os.MkdirAll(hubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hubHome := filepath.Join(work, "home")
	binDir := filepath.Join(work, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(root, "scripts", "e2e", "gitproxy", "claude"), filepath.Join(binDir, "claude"))
	adminToken := "share-e2e-" + randomAlnum(t, 32)
	hubEnv := append(os.Environ(),
		"HOME="+hubHome, "XDG_CONFIG_HOME="+filepath.Join(hubHome, ".config"),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"CLOOP_SECRET_KEY=share-e2e-"+randomAlnum(t, 32),
		"CLOOP_UI_TOKEN="+adminToken,
		"KUBECONFIG=/nonexistent", // the hub must not read anyone's kubeconfig
	)
	runIn(ctx, t, hubDir, hubEnv, cloop, "init", "Kubernetes share end to end")
	cfgPath := filepath.Join(hubDir, ".cloop", "config.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = append(cfg, []byte(fmt.Sprintf("\nexecutors:\n  kube_guard:\n    enabled: true\n    listen_addr: 127.0.0.1:%d\n    tls: auto\n", guardPort))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	hubURL := fmt.Sprintf("http://127.0.0.1:%d", hubPort)
	startShareHub(t, cloop, hubDir, hubEnv, hubPort, filepath.Join(work, "hub.log"))
	hub := hubClient{t: t, base: hubURL, token: adminToken, http: &http.Client{Timeout: 60 * time.Second}}
	guard := fmt.Sprintf("127.0.0.1:%d", guardPort)

	// ── share ───────────────────────────────────────────────────────────────
	cliEnv := append(os.Environ(), "HOME="+filepath.Join(work, "cli-home"),
		"XDG_CONFIG_HOME="+filepath.Join(work, "cli-home", ".config"), "KUBECONFIG=/nonexistent")
	name := "e2e-" + stamp
	remote := func(args ...string) string {
		t.Helper()
		full := append([]string{"remote", "kube"}, args...)
		full = append(full, "--hub", hubURL, "--token", adminToken)
		return runIn(ctx, t, work, cliEnv, cloop, full...)
	}
	shareOut := remote("share", name, "--kubeconfig", devKubeconfig, "--context", "dev",
		"--namespaces", nsA+","+nsB, "--access", "write", "--sa-namespace", nsSA, "--ttl", shareTTL.String())
	t.Logf("share:\n%s", shareOut)
	for _, want := range []string{"Signing in to " + server + " with fake-kubelogin", "Shared.", "Renewal         by the hub"} {
		if !strings.Contains(shareOut, want) {
			t.Fatalf("share output lacks %q", want)
		}
	}
	ran, err := os.ReadFile(pluginRan)
	if err != nil {
		t.Fatalf("the exec plugin never ran: %v", err)
	}
	if !strings.Contains(string(ran), `"server":"`+server+`"`) || !strings.Contains(string(ran), `"interactive":false`) {
		t.Errorf("the plugin was not told the cluster (provideClusterInfo) or was told it may interact:\n%s", ran)
	}

	var listed struct {
		Shares []struct {
			Name           string    `json:"name"`
			ShareID        string    `json:"share_id"`
			ServiceAccount string    `json:"service_account"`
			Renewal        string    `json:"renewal"`
			ExpiresAt      time.Time `json:"expires_at"`
			Renewals       int       `json:"renewals"`
		} `json:"shares"`
	}
	listShares := func() {
		t.Helper()
		listed.Shares = nil
		if err := json.Unmarshal([]byte(remote("list", "--json")), &listed); err != nil {
			t.Fatalf("list --json: %v", err)
		}
	}
	listShares()
	if len(listed.Shares) != 1 || listed.Shares[0].Renewal != "hub" {
		t.Fatalf("list = %+v", listed.Shares)
	}
	share := listed.Shares[0]
	firstExpiry := share.ExpiresAt
	saNS, sa, _ := strings.Cut(share.ServiceAccount, "/")
	if saNS != nsSA || share.ShareID == "" {
		t.Fatalf("share = %+v", share)
	}
	if d := time.Until(firstExpiry); d < 8*time.Minute || d > 11*time.Minute {
		t.Errorf("the token expires in %s; asked for %s", d.Round(time.Second), shareTTL)
	}

	// The objects, and what RBAC makes of them.
	selector := "cloop.dev/kube-share=" + share.ShareID
	if got := x.out(ctx, "-n", nsSA, "get", "serviceaccount", sa, "-o", "jsonpath={.metadata.labels.cloop\\.dev/kube-share} {.automountServiceAccountToken}"); got != share.ShareID+" false" {
		t.Errorf("ServiceAccount label/automount = %q", got)
	}
	for _, ns := range []string{nsA, nsB} {
		if got := x.out(ctx, "-n", ns, "get", "rolebinding", sa, "-o", "jsonpath={.roleRef.kind}/{.roleRef.name} {.subjects[0].namespace}/{.subjects[0].name}"); got != "ClusterRole/edit "+nsSA+"/"+sa {
			t.Errorf("RoleBinding in %s = %q", ns, got)
		}
	}
	if got := x.out(ctx, "-n", nsSA, "get", "role", sa+"-renew", "-o", "jsonpath={.rules[0].resources[0]} {.rules[0].verbs[0]} {.rules[0].resourceNames[0]}"); got != "serviceaccounts/token create "+sa {
		t.Errorf("the self-renewal Role = %q", got)
	}
	if out, _ := x.kubectlMay(ctx, "get", "clusterrolebinding", "-l", selector, "-o", "name"); strings.TrimSpace(out) != "" {
		t.Errorf("a share without --cluster-wide created %s", out)
	}
	asSA := "--as=system:serviceaccount:" + nsSA + ":" + sa
	can := func(args ...string) string {
		out, _ := x.kubectlMay(ctx, append([]string{"auth", "can-i"}, append(args, asSA)...)...)
		return strings.TrimSpace(out)
	}
	if got := can("create", "serviceaccounts/"+sa, "--subresource=token", "-n", nsSA); got != "yes" {
		t.Fatalf("RBAC: may the ServiceAccount create its own token? %q — the monitor's refusal below would prove nothing", got)
	}
	for _, c := range [][]string{
		{"create", "secrets", "-n", nsSA}, {"create", "pods", "-n", nsSA},
		{"create", "serviceaccounts/default", "--subresource=token", "-n", nsSA},
		{"list", "pods", "-n", "kube-system"},
	} {
		if got := can(c...); got != "no" {
			t.Errorf("RBAC: %v = %q; the share grants more than it should", c, got)
		}
	}

	// ── grant and dispatch ──────────────────────────────────────────────────
	hub.must(http.MethodPost, "/api/grants", map[string]any{
		"source": "secret", "secret_ref": name, "subject": "project:" + hubDir, "ttl_minutes": 120,
		"namespaces": []string{nsA, nsB, nsSA},
		"verbs":      []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	}, nil)
	probeDir := filepath.Join(work, "probe")
	if err := os.MkdirAll(probeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	probe := strings.NewReplacer("__NS_A__", nsA, "__NS_SA__", nsSA, "__SA__", sa, "__GUARD__", guard,
		"__DIR__", probeDir).Replace(shareProbe)
	hub.must(http.MethodPost, "/api/tasks", map[string]any{
		"title":       "Kubernetes share probe",
		"description": "E2E-SCRIPT-B64: " + base64.StdEncoding.EncodeToString([]byte(probe)),
	}, nil)
	hub.must(http.MethodPost, "/api/run", map[string]any{}, nil)

	results := func() map[string]result {
		raw, _ := os.ReadFile(filepath.Join(probeDir, "results.txt"))
		return parseResults(strings.Split(string(raw), "\n"))
	}
	expect := func(ids ...string) {
		t.Helper()
		got := results()
		for _, id := range ids {
			r, ok := got[id]
			switch {
			case !ok:
				t.Errorf("%s: the probe reported nothing", id)
			case !r.pass:
				t.Errorf("%s FAIL: %s", id, r.detail)
			default:
				t.Logf("%s PASS: %s", id, r.detail)
			}
		}
	}
	awaitFile := func(name string, timeout time.Duration) {
		t.Helper()
		waitFor(t, "the probe's "+name, timeout, func() (bool, string) {
			_, err := os.Stat(filepath.Join(probeDir, name))
			return err == nil, fmt.Sprintf("results so far: %v", results())
		})
	}
	awaitFile("phase1-done", 3*time.Minute)
	expect("P0", "P1", "P2", "P3", "P4", "P5")
	if t.Failed() {
		t.FailNow()
	}

	// ── renewal across the first token's expiry ────────────────────────────
	waitFor(t, "the hub to renew the share", shareTTL, func() (bool, string) {
		listShares()
		if len(listed.Shares) != 1 {
			return false, "no share"
		}
		s := listed.Shares[0]
		return s.Renewals >= 1, fmt.Sprintf("renewals %d, expires %s", s.Renewals, s.ExpiresAt)
	})
	if !listed.Shares[0].ExpiresAt.After(firstExpiry) {
		t.Fatalf("after the renewal the token still expires %s", listed.Shares[0].ExpiresAt)
	}
	t.Logf("renewed: the token now expires %s (the first expired %s)", listed.Shares[0].ExpiresAt, firstExpiry)
	if wait := time.Until(firstExpiry.Add(tokenLeeway)); wait > 0 {
		t.Logf("waiting %s for the first token to expire", wait.Round(time.Second))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	touch(t, filepath.Join(probeDir, "go-renewed"))
	awaitFile("phase2-done", 3*time.Minute)
	expect("P6")
	if got := x.out(ctx, "-n", nsA, "get", "configmap", "share-probe-2", "-o", "jsonpath={.data.phase}"); got != "2" {
		t.Errorf("the configmap written after the first token expired: %q", got)
	}

	// ── revoke ──────────────────────────────────────────────────────────────
	revokeOut := remote("revoke", name, "--kubeconfig", devKubeconfig)
	t.Logf("revoke:\n%s", revokeOut)
	if !strings.Contains(revokeOut, "Deleted ServiceAccount "+nsSA+"/"+sa) || !strings.Contains(revokeOut, "Deleted secret "+name) {
		t.Errorf("revoke output:\n%s", revokeOut)
	}
	for _, kind := range []string{"serviceaccounts,roles,rolebindings", "clusterrolebindings"} {
		args := []string{"get", kind, "-l", selector, "-o", "name"}
		if kind != "clusterrolebindings" {
			args = append(args, "-A")
		}
		if out, err := x.kubectlMay(ctx, args...); err != nil || strings.TrimSpace(out) != "" {
			t.Errorf("after revoke, %s labelled %s: %q (%v)", kind, selector, out, err)
		}
	}
	var secrets struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	hub.must(http.MethodGet, "/api/secrets", nil, &secrets)
	for _, s := range secrets.Secrets {
		if s.Name == name {
			t.Errorf("the hub still holds secret %s after revoke", name)
		}
	}
	touch(t, filepath.Join(probeDir, "go-revoked"))
	awaitFile("probe-done", 3*time.Minute)
	expect("P7")

	// ── the audit trail ─────────────────────────────────────────────────────
	var audit struct {
		Events []struct {
			Actor     string `json:"actor"`
			EventType string `json:"event_type"`
			Payload   string `json:"payload"`
		} `json:"events"`
	}
	hub.must(http.MethodGet, "/api/audit?limit=1000", nil, &audit)
	var renewed, tokenDenied, sessionClosed bool
	for _, e := range audit.Events {
		switch {
		case e.EventType == "secret.renew" && e.Actor == "hub" && strings.Contains(e.Payload, `"decision":"allow"`):
			renewed = true
		case e.EventType == "kubeguard.request_denied" && strings.Contains(e.Payload, "serviceaccounts/token"):
			tokenDenied = true
		case e.EventType == "kubeguard.session_closed":
			// The run's session, closed by the revoke: the share's grant was
			// the lease's only one, so withdrawing it ended the whole lease
			// ("lease released"). That it happened while the run still held
			// the session is P7's to prove.
			sessionClosed = true
		}
	}
	if !renewed {
		t.Error("no secret.renew row by the hub")
	}
	if !tokenDenied {
		t.Error("no kubeguard.request_denied row for serviceaccounts/token")
	}
	if !sessionClosed {
		t.Error("no kubeguard.session_closed row for the run's session")
	}
}

// freePort returns a port nothing listens on now.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// runIn runs a command in dir and returns its combined output, failing the
// test with it when the command fails.
func runIn(ctx context.Context, t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(redactArgs(args), " "), err, tail(string(out), 40))
	}
	return string(out)
}

// startShareHub starts `cloop ui` in dir and waits for it to answer, stopping
// its whole process group when the test ends.
func startShareHub(t *testing.T, cloop, dir string, env []string, port int, logPath string) {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cloop, "ui", "--port", strconv.Itoa(port), "--no-browser")
	cmd.Dir, cmd.Env = dir, env
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the hub: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		_ = logFile.Close()
		if t.Failed() {
			if b, err := os.ReadFile(logPath); err == nil {
				t.Logf("── hub log ──\n%s", tail(string(b), 120))
			}
		}
	})
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	waitFor(t, "the hub to answer at "+url, 60*time.Second, func() (bool, string) {
		resp, err := http.Get(url)
		if err != nil {
			return false, err.Error()
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK, resp.Status
	})
}
