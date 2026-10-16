package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
)

// denials_container_test.go is Task 20437 end to end, against the kernel: the
// real cloop binary as a hub whose own container executor runs a project
// under a firewall rule set with a denylist, and a sandbox that dials three
// destinations the rules do not allow. Each connect must be refused at once —
// a reset, not a five-second timeout — and the hub must have read the
// refusals from its packet log and filed them on the run: one history line
// per destination, naming the rule, and the task's Network section.
//
// Opt-in, and root only, like tests/forwarder: it installs an nftables ruleset
// on a docker bridge and binds an NFLOG group.
//
//	go build -o cloop . && CLOOP_DENIALS_E2E=1 go test ./tests/e2e -run TestE2EFirewallRefusalsAreImmediateAndRecorded -v

const denialsProbe = `#!/bin/sh
# Stands in for cloop inside the sandbox: the hub dispatches "cloop run", and
# this answers it by dialling what the project's firewall does not allow.
ev="$PWD/denial-evidence.txt"
up() { cut -d' ' -f1 /proc/uptime; }
probe() {
  t0=$(up)
  out=$(wget -q -T 5 -O /dev/null "http://$1:$2/" 2>&1)
  rc=$?
  t1=$(up)
  echo "PROBE $1:$2 rc=$rc start=$t0 end=$t1 out=$(echo "$out" | tr '\n' ' ')" >> "$ev"
}
# A real harness talks for minutes; a second is enough for the driver to read
# back the address its refusals are attributed by.
sleep 1
probe 203.0.113.7 443
probe 198.51.100.7 22
probe 10.255.255.1 443
echo DONE >> "$ev"
`

func TestE2EFirewallRefusalsAreImmediateAndRecorded(t *testing.T) {
	if os.Getenv("CLOOP_DENIALS_E2E") != "1" {
		t.Skip("set CLOOP_DENIALS_E2E=1 to run the firewall refusal circuit (needs root, docker and nft)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: the hub installs an nftables ruleset on the sandbox's bridge and binds an NFLOG group")
	}
	for _, tool := range []string{"docker", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	bin := binaryPath(t)
	image := buildDenialsImage(t)

	root := t.TempDir()
	home := filepath.Join(root, "home")
	const token = "e2e-denials-hub-token"
	env := append(withoutCloopEnv(os.Environ()),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"CLOOP_UI_TOKEN="+token,
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

	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	run(proj, "init", "--provider", "mock", "--skip-clarify", "Dial what the firewall denies")
	run(proj, "task", "add", "dial the denied destinations", "--no-ai", "--auto")
	// The sandbox runs as the project's owner, and never as root.
	if err := chownTree(proj, 1000, 1000); err != nil {
		t.Fatal(err)
	}

	hubDir := filepath.Join(root, "hub")
	if err := os.MkdirAll(hubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	f, err := os.OpenFile(filepath.Join(hubDir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "\nexecutors:\n"+
		"    container:\n        enabled: true\n        runtime: docker\n        image: %s\n        network: bridge\n", image)
	_ = f.Close()

	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	hub := exec.Command(bin, "ui", "--port", strconv.Itoa(port), "--listen", "127.0.0.1", "--no-browser", "--projects", proj)
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
		// Only what this test made: its executor's bridges, and their tables.
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

	// The project on the hub's container executor, under rules that allow the
	// public Internet on 443 and deny one range.
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
	rules := map[string]any{
		"allow_public_internet": true, "allow_ports": []int{443}, "resolvers": []string{"1.1.1.1"},
		"deny_cidrs": []string{"203.0.113.0/24"},
	}
	if code, out := call("PUT", fmt.Sprintf("/api/firewall?project_idx=%d", idx), rules); code != http.StatusOK {
		t.Fatalf("project firewall = %d %v", code, out)
	}

	if code, out := call("POST", fmt.Sprintf("/api/projects/%d/run", idx), map[string]any{}); code != http.StatusOK {
		t.Fatalf("run = %d %v", code, out)
	}
	evidence := filepath.Join(proj, "denial-evidence.txt")
	waitFor("the sandbox's probes", 3*time.Minute, func() bool {
		b, _ := os.ReadFile(evidence)
		return strings.Contains(string(b), "DONE")
	})
	raw := string(readTestFile(t, evidence))
	t.Logf("sandbox:\n%s", raw)
	for _, target := range []string{"203.0.113.7:443", "198.51.100.7:22", "10.255.255.1:443"} {
		line := ""
		for _, l := range strings.Split(raw, "\n") {
			if strings.HasPrefix(l, "PROBE "+target+" ") {
				line = l
			}
		}
		if line == "" {
			t.Errorf("no probe of %s", target)
			continue
		}
		var start, end float64
		var rc int
		if _, err := fmt.Sscanf(line[strings.Index(line, " rc="):], " rc=%d start=%f end=%f", &rc, &start, &end); err != nil {
			t.Errorf("unreadable probe line %q: %v", line, err)
			continue
		}
		if rc == 0 {
			t.Errorf("%s connected: the firewall let it through", target)
		}
		if !strings.Contains(line, "refused") {
			t.Errorf("%s failed without a refusal: %s", target, line)
		}
		// Refused, not dropped: a drop would sit out wget's five seconds.
		if end-start > 1.0 {
			t.Errorf("%s took %.2fs to fail — dropped, not refused", target, end-start)
		}
	}

	// The refusals, read from the hub's packet log and filed on the run.
	want := map[string]string{
		"blocked 203.0.113.7:443/tcp":  "in the project's deny list (203.0.113.0/24)",
		"blocked 198.51.100.7:22/tcp":  "port 22 is not one the project's allow list opens (443)",
		"blocked 10.255.255.1:443/tcp": "private (RFC1918/ULA) range 10.0.0.0/8, which the project's allow list does not name",
	}
	waitFor("the refusals in the run's history", time.Minute, func() bool {
		rows, _ := state.ListEventsOfType(proj, state.EventNetworkBlocked, 50)
		found := 0
		for _, r := range rows {
			for prefix, why := range want {
				if strings.HasPrefix(r.Message, prefix) && strings.HasSuffix(r.Message, why) {
					found++
				}
			}
		}
		return found == len(want)
	})
	rows, _ := state.ListEventsOfType(proj, state.EventNetworkBlocked, 50)
	for _, r := range rows {
		t.Logf("history: %s (task %d)", r.Message, r.TaskID)
	}
	// And the project's firewall card. (The stand-in never marks its task
	// running, so the task's own Network section is pkg/ui's tests' to cover.)
	code, card := call("GET", fmt.Sprintf("/api/firewall/blocked?project_idx=%d", idx), nil)
	blocked, _ := card["blocked"].([]any)
	if code != http.StatusOK || card["observable"] != true || len(blocked) != len(want) {
		t.Errorf("the firewall card's recently blocked list = %d %v", code, card)
	}
	for _, b := range blocked {
		m, _ := b.(map[string]any)
		if m["rule"] == "deny:203.0.113.0/24" && m["proposable"] == true {
			t.Errorf("a deny-list refusal is offered an allow rule: %v", m)
		}
	}
	waitFor("the sandbox to be removed", time.Minute, func() bool {
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
			"--filter", "label=cloop.project="+proj).Output()
		return strings.TrimSpace(string(out)) == ""
	})
}

// buildDenialsImage is alpine with the probe standing in for cloop.
func buildDenialsImage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "cloop"), denialsProbe)
	writeTestFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+featureImageBase+"\n"+
		"COPY cloop /usr/local/bin/cloop\nRUN chmod 0755 /usr/local/bin/cloop\n")
	sum := sha256.Sum256([]byte(denialsProbe))
	tag := "cloop-denials-e2e:" + hex.EncodeToString(sum[:6])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}
