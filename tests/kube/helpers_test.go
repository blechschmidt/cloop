package kube_test

// helpers_test.go: the clients the end-to-end test drives the cluster and the
// hub with. Everything shells out to the same tools an operator uses —
// kubectl, helm, docker, kind — so a failure here reads the way it would at a
// terminal.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// tool runs one command-line tool with the test's kubeconfig.
type tool struct {
	t          *testing.T
	kubeconfig string
}

// run executes name args with stdin, returning combined output. It fails the
// test unless allowFail, naming the command and printing what it said.
func (x tool) run(ctx context.Context, stdin []byte, allowFail bool, name string, args ...string) (string, error) {
	x.t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(toolEnv(), "KUBECONFIG="+x.kubeconfig)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil && !allowFail {
		x.t.Fatalf("%s %s: %v\n%s", name, strings.Join(redactArgs(args), " "), err, tail(out.String(), 60))
	}
	return out.String(), err
}

func (x tool) kubectl(ctx context.Context, args ...string) string {
	x.t.Helper()
	out, _ := x.run(ctx, nil, false, "kubectl", args...)
	return out
}

func (x tool) kubectlIn(ctx context.Context, stdin []byte, args ...string) string {
	x.t.Helper()
	out, _ := x.run(ctx, stdin, false, "kubectl", args...)
	return out
}

func (x tool) kubectlMay(ctx context.Context, args ...string) (string, error) {
	x.t.Helper()
	return x.run(ctx, nil, true, "kubectl", args...)
}

// apply submits objects (each a JSON-able value) with kubectl apply.
func (x tool) apply(ctx context.Context, objects ...any) {
	x.t.Helper()
	list := map[string]any{"apiVersion": "v1", "kind": "List", "items": objects}
	b, err := json.Marshal(list)
	if err != nil {
		x.t.Fatal(err)
	}
	x.kubectlIn(ctx, b, "apply", "-f", "-")
}

// toolEnv is the environment for go, docker, kind, helm and kubectl: this
// process's, with the HOME they keep their caches and credentials under.
func toolEnv() []string {
	env := os.Environ()
	if realHome != "" {
		env = append(env, "HOME="+realHome)
	}
	return env
}

// redactArgs keeps a token passed by flag out of a failure message.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, "ghp_") || strings.HasPrefix(a, "token=") {
			a = "<redacted>"
		}
		out[i] = a
	}
	return out
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

// waitFor polls cond until it reports done, failing the test after timeout
// with what it was waiting for and the last thing cond said.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		done, note := cond()
		if done {
			return
		}
		if note != "" {
			last = note
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s; last: %s", timeout, what, last)
		}
		time.Sleep(2 * time.Second)
	}
}

// portForward forwards a free local port to svc's port and returns the base
// URL, stopping the forward when the test ends.
func (x tool) portForward(ns, svc string, port int) string {
	x.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "port-forward", "-n", ns, "svc/"+svc, fmt.Sprintf(":%d", port))
	cmd.Env = append(toolEnv(), "KUBECONFIG="+x.kubeconfig)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		x.t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		x.t.Fatalf("kubectl port-forward: %v", err)
	}
	x.t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	re := regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				select {
				case found <- m[1]:
				default:
				}
			}
		}
	}()
	select {
	case p := <-found:
		return "http://127.0.0.1:" + p
	case <-time.After(30 * time.Second):
		x.t.Fatalf("kubectl port-forward to %s/%s never reported a local port", ns, svc)
	}
	return ""
}

// hubClient speaks the hub's REST API with an API token.
type hubClient struct {
	t     *testing.T
	base  string
	token string
	http  *http.Client
}

// call sends method path with body (JSON-encoded unless nil) and decodes the
// response into out when it is non-nil. It returns the status and raw body.
func (h hubClient) call(method, path string, body, out any) (int, string) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.base+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: decode %q: %v", method, path, tail(string(raw), 5), err)
		}
	}
	return resp.StatusCode, string(raw)
}

// must is call that fails the test on anything but a 2xx.
func (h hubClient) must(method, path string, body, out any) {
	h.t.Helper()
	if code, raw := h.call(method, path, body, out); code >= 300 {
		h.t.Fatalf("%s %s: HTTP %d: %s", method, path, code, tail(raw, 10))
	}
}
