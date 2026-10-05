package e2e_test

// The hub's egress proxy end to end (Task 20378): a real `cloop ui` hosting
// the proxy, a real container executor whose sandboxes sit on an --internal
// network with no route off the host, and a real `cloop run` inside one whose
// stand-in harness fetches over HTTPS through HTTPS_PROXY — as any harness
// that honours the variable does.
//
// What it proves:
//
//   - the hub binds executors.egress.listen_addr, and `cloop hub doctor` reads
//     where it listens from the running hub;
//   - a run whose project holds an egress grant is issued a session at
//     dispatch, and the proxy URL in its environment works from inside the
//     internal network — the name in it pinned to the bridge's gateway;
//   - the grant's --cidrs is what the proxy enforces: a local TLS origin the
//     grant names is fetched, and the same origin at a host address it does
//     not name is refused — with an audit row for each verdict;
//   - the session is closed when the run ends, and its credential is never
//     written down: not in the hub's log, the run's artifacts, the project's
//     journal or the audit trail.
//
// Opt-in, like the container feature test beside it: it needs Docker and
// builds a small sandbox image. CI's flagship job sets
// CLOOP_EGRESS_CONTAINER_E2E=1.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// egressStubClaude stands in for Claude Code. It fetches the two targets the
// test wrote into the workspace through the hub's proxy, keeps what it saw for
// the test, writes down the proxy URL its environment carried — deliberately,
// so the test knows the credential it must find nowhere else — and prints it,
// so the run's own transcript is where redaction has to happen.
const egressStubClaude = `#!/bin/sh
cat >/dev/null
cd /workspace
. ./egress-targets.sh
egressfetch -ca egress-ca.pem "$ALLOWED_URL" > egress-allowed.txt 2>&1
egressfetch -ca egress-ca.pem "$DENIED_URL" > egress-denied.txt 2>&1
printf '%s\n' "$HTTPS_PROXY" > egress-proxy-url.txt
echo "proxy in use: $HTTPS_PROXY"
echo "fetched through the hub's egress proxy"
echo TASK_DONE
`

func TestE2EEgressProxyInAContainer(t *testing.T) {
	if os.Getenv("CLOOP_EGRESS_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_EGRESS_CONTAINER_E2E=1 to run the container egress circuit (needs docker)")
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	bin := binaryPath(t)
	image := buildEgressImage(t)

	allowedIP, deniedIP := egressHostAddresses(t)
	t.Logf("origin reached at %s (granted) and %s (not granted)", allowedIP, deniedIP)
	caPEM, cert := egressCertificates(t, allowedIP, deniedIP)
	originPort := egressOrigin(t, cert)

	root := t.TempDir()
	home := filepath.Join(root, "home")
	gitconfig := filepath.Join(home, ".gitconfig")
	writeTestFile(t, gitconfig, "[user]\n\tname = E2E\n\temail = e2e@example.com\n[safe]\n\tdirectory = *\n")
	const token = "e2e-egress-hub-token"
	env := append(withoutCloopEnv(os.Environ()),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"CLOOP_UI_TOKEN="+token,
		// A secret broker, so the project can be granted the Claude
		// credential a sandboxed claudecode run is refused without (Task
		// 20379). The stand-in harness ignores it.
		"CLOOP_SECRET_KEY=e2e-egress-container",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"NO_COLOR=1",
	)
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cloop %v in %s: %v\n%s", args, dir, err, out)
		}
		return string(out)
	}

	// The project, with its targets and the CA the origin's certificate
	// chains to, where the sandbox will find them.
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	run(proj, "init", "--provider", "claudecode", "--skip-clarify", "Fetch through the hub's egress proxy")
	writeTestFile(t, filepath.Join(proj, "egress-ca.pem"), string(caPEM))
	writeTestFile(t, filepath.Join(proj, "egress-targets.sh"), fmt.Sprintf(
		"ALLOWED_URL=https://%s/allowed\nDENIED_URL=https://%s/denied\n",
		net.JoinHostPort(allowedIP, fmt.Sprint(originPort)), net.JoinHostPort(deniedIP, fmt.Sprint(originPort))))
	if os.Getuid() == 0 {
		// The sandbox runs as the project's owner, and never as root.
		if err := chownTree(proj, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}

	// The hub: strict, a container executor whose sandboxes are on an
	// internal network, and the egress proxy on every interface — the
	// address an internal bridge's gateway answers on.
	hubDir := filepath.Join(root, "hub")
	if err := os.MkdirAll(hubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	grantHarnessCredential(t, run, hubDir, proj)
	f, err := os.OpenFile(filepath.Join(hubDir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "\nexecutors:\n"+
		"    allow_host_process: false\n"+
		"    container:\n        enabled: true\n        runtime: docker\n        image: %s\n        network: bridge\n"+
		"        egress_filter:\n            enabled: true\n            internal: true\n"+
		"    egress:\n        enabled: true\n        listen_addr: \"0.0.0.0:0\"\n        max_session_minutes: 15\n"+
		"        default_max_bytes_down: 10m\n", image)
	_ = f.Close()

	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	hub := exec.Command(bin, "ui", "--port", fmt.Sprint(port), "--no-browser", "--projects", proj)
	hub.Dir, hub.Env = hubDir, env
	hub.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	hubLog := &strings.Builder{}
	hub.Stdout, hub.Stderr = &syncWriter{w: hubLog}, &syncWriter{w: hubLog}
	if err := hub.Start(); err != nil {
		t.Fatal(err)
	}
	var executorID string
	t.Cleanup(func() {
		_ = syscall.Kill(-hub.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = hub.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = syscall.Kill(-hub.Process.Pid, syscall.SIGKILL)
			<-done
		}
		if t.Failed() {
			t.Logf("hub log:\n%s", tail(hubLog.String(), 12000))
		}
		if executorID != "" {
			out, _ := exec.Command("docker", "network", "ls", "-q", "--filter", "name=cloop-sbx-").Output()
			for _, id := range strings.Fields(string(out)) {
				name, _ := exec.Command("docker", "network", "inspect", id, "--format", "{{.Name}}").Output()
				if strings.Contains(string(name), sanitizeNetworkName(executorID)) {
					_ = exec.Command("docker", "network", "rm", id).Run()
				}
			}
		}
	})
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		}
		req, _ := http.NewRequest(method, base+path, rd)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	waitFor := func(what string, timeout time.Duration, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out after %s waiting for %s", timeout, what)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	waitFor("the hub to answer", 30*time.Second, func() bool {
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	if code, _ := call("GET", "/api/projects", nil); code != http.StatusOK {
		t.Fatalf("the hub does not accept its token: %d", code)
	}

	// 1. The hub hosts the proxy, and the doctor reads where from it.
	doctor := exec.Command(bin, "hub", "doctor", "--offline", "--json")
	doctor.Dir, doctor.Env = hubDir, env
	raw, _ := doctor.Output() // exits 1 on unrelated findings; the JSON is what matters
	var report struct {
		Findings []struct{ Check, Severity, Message string } `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("hub doctor --json: %v\n%s", err, raw)
	}
	var hosted string
	for _, fd := range report.Findings {
		if fd.Check == "egress.hosted" {
			hosted = fd.Severity + ": " + fd.Message
		}
	}
	// Every interface, as configured: Go reports a wildcard bind on a
	// dual-stack host as [::].
	if !strings.HasPrefix(hosted, "pass: ") ||
		!(strings.Contains(hosted, "listening on 0.0.0.0:") || strings.Contains(hosted, "listening on [::]:")) ||
		!strings.Contains(hosted, "advertised as ") {
		t.Fatalf("hub doctor's egress.hosted finding = %q", hosted)
	}
	t.Logf("hub doctor: %s", hosted)

	// 2. The grant: the origin at one address, on its port, nothing else.
	run(hubDir, "egress", "grant", "--to", "project:"+proj,
		"--cidrs", allowedIP+"/32", "--ports", fmt.Sprint(originPort), "--ttl", "1h")

	// 3. The project on the container executor, with one task to run.
	_, body := call("GET", "/api/executors", nil)
	rawEx, _ := body["executors"].([]any)
	for _, r := range rawEx {
		if m, _ := r.(map[string]any); m["kind"] == "container" {
			executorID = fmt.Sprint(m["id"])
		}
	}
	if executorID == "" {
		t.Fatalf("no container executor is registered: %v", body)
	}
	idx := egressProjectIdx(t, call, proj)
	if code, out := call("POST", fmt.Sprintf("/api/projects/%d/executor", idx), map[string]any{"executor_id": executorID}); code != http.StatusOK {
		t.Fatalf("bind = %d %v", code, out)
	}
	if code, out := call("POST", fmt.Sprintf("/api/tasks?project_idx=%d", idx),
		map[string]any{"title": "Fetch the origin", "description": "Fetch the origin through the proxy"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("add task = %d %v", code, out)
	}

	// 4. The run.
	if code, out := call("POST", fmt.Sprintf("/api/projects/%d/run", idx), map[string]any{}); code != http.StatusOK {
		t.Fatalf("run = %d %v", code, out)
	}
	waitFor("the stand-in harness's fetches", 3*time.Minute, func() bool {
		_, err := os.Stat(filepath.Join(proj, "egress-proxy-url.txt"))
		return err == nil
	})

	allowed := strings.TrimSpace(string(readTestFile(t, filepath.Join(proj, "egress-allowed.txt"))))
	denied := strings.TrimSpace(string(readTestFile(t, filepath.Join(proj, "egress-denied.txt"))))
	t.Logf("granted fetch: %s", allowed)
	t.Logf("refused fetch: %s", denied)
	if allowed != `status=200 body="the origin answered"` {
		t.Errorf("the granted fetch through the proxy = %q", allowed)
	}
	if !strings.Contains(denied, "Forbidden") || strings.Contains(denied, "status=200") {
		t.Errorf("the fetch of an address the grant does not name = %q, want the proxy's 403", denied)
	}

	proxyURL := strings.TrimSpace(string(readTestFile(t, filepath.Join(proj, "egress-proxy-url.txt"))))
	pu, err := url.Parse(proxyURL)
	if err != nil || pu.User == nil || !strings.HasPrefix(pu.User.Username(), "sess_") ||
		pu.Hostname() != "host.containers.internal" {
		t.Fatalf("the sandbox's HTTPS_PROXY = %q, want a session credential at the gateway name", redactTok(proxyURL))
	}
	tok, _ := pu.User.Password()
	if len(tok) < 32 {
		t.Fatalf("no token in the sandbox's proxy URL")
	}

	// 5. The audit trail: the session, both verdicts, the close.
	db, err := statedb.Open(state.DBPath(hubDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The session's own close row — not a tunnel's, which shares the action —
	// lands when the run's workload ends.
	waitFor("the run's session to close", 2*time.Minute, func() bool {
		rows, _, _ := db.ListAuditEvents(statedb.AuditFilter{EventType: "egress.close", Search: "the run ended"})
		return len(rows) > 0
	})
	waitFor("the sandbox to be removed", time.Minute, func() bool {
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
			"--filter", "label=cloop.project="+proj).Output()
		return strings.TrimSpace(string(out)) == ""
	})
	audit, _, err := db.ListAuditEvents(statedb.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var redeemed, connected, refused, closed bool
	for _, row := range audit {
		p := row.Payload
		switch row.EventType {
		case "egress.redeem":
			redeemed = redeemed || (strings.Contains(p, `"decision":"allow"`) && strings.Contains(p, proj))
		case "egress.connect":
			connected = connected || (strings.Contains(p, `"decision":"allow"`) && strings.Contains(p, `"host":"`+allowedIP+`"`))
			refused = refused || (strings.Contains(p, `"decision":"deny"`) && strings.Contains(p, `"host":"`+deniedIP+`"`))
		case "egress.close":
			closed = closed || strings.Contains(p, "the run ended")
		}
		if strings.Contains(p, tok) {
			t.Errorf("audit row %s carries the session token", row.EventType)
		}
	}
	if !redeemed || !connected || !refused || !closed {
		t.Errorf("audit rows: redeemed=%v connected(granted)=%v refused(other host)=%v closed(run ended)=%v",
			redeemed, connected, refused, closed)
	}

	// 6. The project's journal says what the run was given and when it ended.
	events, _, err := state.ListEvents(proj, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var issued, ended bool
	for _, ev := range events {
		if ev.Type != state.EventEgress {
			continue
		}
		issued = issued || strings.Contains(ev.Message, "proxy session sess_")
		ended = ended || strings.Contains(ev.Message, "closed — the run ended")
		if strings.Contains(ev.Message, tok) {
			t.Errorf("the journal carries the session token: %q", ev.Message)
		}
	}
	if !issued || !ended {
		t.Errorf("journal: issued=%v ended=%v", issued, ended)
	}

	// 7. The credential is nowhere else: the hub's log, and every file the
	// run left in the project's .cloop — its artifacts and transcripts.
	if strings.Contains(hubLog.String(), tok) {
		t.Error("the hub's log carries the session token")
	}
	var sawTranscript bool
	_ = filepath.Walk(filepath.Join(proj, ".cloop"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 64<<20 {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), tok) {
			t.Errorf("%s carries the session token%s", path, whereInDB(path, tok))
		}
		if strings.Contains(string(b), "proxy in use: ") {
			sawTranscript = true
		}
		return nil
	})
	if !sawTranscript {
		t.Log("note: no transcript line naming the proxy was found under .cloop to check for redaction")
	}

	// 8. Nothing is left running.
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
		"--filter", "label=cloop.project="+proj).Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("sandbox containers were left behind: %s", out)
	}
}

// egressProjectIdx is path's index in the hub's project list.
func egressProjectIdx(t *testing.T, call func(string, string, any) (int, map[string]any), path string) int {
	t.Helper()
	_, body := call("GET", "/api/projects", nil)
	raw, _ := body["projects"].([]any)
	for i, r := range raw {
		if m, ok := r.(map[string]any); ok && m["path"] == path {
			return i
		}
	}
	t.Fatalf("%s is not among the hub's projects: %v", path, body)
	return -1
}

// egressHostAddresses returns two IPv4 addresses of this host: the default
// docker bridge's gateway, which the grant names, and another the grant does
// not. The proxy runs on this host, so it reaches the origin at both.
func egressHostAddresses(t *testing.T) (allowed, denied string) {
	t.Helper()
	out, err := exec.Command("docker", "network", "inspect", "bridge",
		"--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
	if err != nil {
		t.Skipf("no default docker bridge to address the origin at: %v", err)
	}
	allowed = strings.TrimSpace(string(out))
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() || ipn.IP.String() == allowed {
				continue
			}
			return allowed, ipn.IP.String()
		}
	}
	t.Skip("this host has only one non-loopback IPv4 address, so there is no second host to be refused")
	return "", ""
}

// egressCertificates issues a throwaway CA and a server certificate for the
// origin's two addresses.
func egressCertificates(t *testing.T, ips ...string) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cloop egress e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "origin"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// egressOrigin serves HTTPS on every interface of this host and returns its
// port.
func egressOrigin(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "the origin answered")
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// buildEgressImage builds the sandbox image: the feature test's base with git
// (the same layer, so CI builds it once), a static cloop, the stand-in claude
// and the fetch client.
func buildEgressImage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(thisFile), "..", "..")
	bin := os.Getenv("CLOOP_FLAGSHIP_BIN")
	if bin == "" {
		bin = filepath.Join(dir, "cloop-static")
		build := exec.Command("go", "build", "-o", bin, ".")
		build.Dir = repo
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build a static cloop: %v\n%s", err, out)
		}
	}
	fetch := filepath.Join(dir, "egressfetch")
	build := exec.Command("go", "build", "-o", fetch, "./tests/e2e/testdata/egressfetch")
	build.Dir = repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the fetch client: %v\n%s", err, out)
	}
	data := readTestFile(t, bin)
	if err := os.WriteFile(filepath.Join(dir, "cloop"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "claude"), egressStubClaude)
	writeTestFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+featureImageBase+"\n"+
		"RUN apk add --no-cache git\n"+
		"COPY cloop /usr/local/bin/cloop\n"+
		"COPY claude /usr/local/bin/claude\n"+
		"COPY egressfetch /usr/local/bin/egressfetch\n"+
		"RUN chmod 0755 /usr/local/bin/cloop /usr/local/bin/claude /usr/local/bin/egressfetch\n")
	sum := sha256.Sum256(append(append(data, readTestFile(t, fetch)...), []byte(egressStubClaude)...))
	tag := "cloop-egress-e2e:" + hex.EncodeToString(sum[:6])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// sanitizeNetworkName mirrors the container driver's network naming closely
// enough to find the bridges this test's executor created.
func sanitizeNetworkName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// redactTok keeps a failing assertion from printing a live credential.
func redactTok(s string) string {
	if i := strings.Index(s, "@"); i > 0 {
		if j := strings.LastIndex(s[:i], ":"); j > 0 {
			return s[:j+1] + "<token>" + s[i:]
		}
	}
	return s
}

// whereInDB names the tables and columns of a SQLite file that hold needle,
// so a leak is reported with its address rather than only its file.
func whereInDB(path, needle string) string {
	if !strings.HasSuffix(path, ".db") {
		return ""
	}
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		return ""
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return ""
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	var hits []string
	for _, tbl := range tables {
		cols, err := conn.Query(`SELECT name FROM pragma_table_info(?)`, tbl)
		if err != nil {
			continue
		}
		var names []string
		for cols.Next() {
			var n string
			_ = cols.Scan(&n)
			names = append(names, n)
		}
		cols.Close()
		for _, c := range names {
			var n int
			q := fmt.Sprintf(`SELECT COUNT(*) FROM %q WHERE CAST(%q AS TEXT) LIKE '%%' || ? || '%%'`, tbl, c)
			if conn.QueryRow(q, needle).Scan(&n) == nil && n > 0 {
				hits = append(hits, fmt.Sprintf("%s.%s (%d row(s))", tbl, c, n))
			}
		}
	}
	if len(hits) == 0 {
		return " (not in any table: the WAL or free pages)"
	}
	return ": " + strings.Join(hits, ", ")
}
