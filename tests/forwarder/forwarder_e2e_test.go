//go:build linux

// Package forwarder_test is the end-to-end test of forwarded devices (Task
// 20430): the real cloop binary as a device forwarder, a token-protected test
// hub — or two hub processes serving one control plane — and a second
// executor agent whose payloads run in a container sandbox, all on this host.
//
// What it proves, each against the kernel rather than a fake:
//
//   - USB: a forwarder carrying a USB device, a binding of it to a project, and
//     a run of that project on the agent put the device in the run's sandbox —
//     /sys/bus/usb/devices there shows it, and its usbfs node answers with the
//     device's descriptor. The agent attached it through vhci_hcd with a
//     socketpair; no process listens anywhere.
//   - Revocation: unbinding mid-run detaches the device from the sandbox and
//     frees the agent host's vhci port within seconds.
//   - L2: a forwarder carrying one end of a veth pair whose other end is in a
//     network namespace standing in for the on-prem segment puts the sandbox
//     on that segment: it resolves the segment's address over ARP and opens a
//     TCP connection to a listener there.
//   - Cluster: with the forwarder's tunnel on one hub member and the agent's on
//     the other, the run's device is relayed between them over the peer
//     channel, the probe is routed to the holder, and a revocation through the
//     member that does not hold the tunnel cuts it at once.
//
// Opt-in, because it needs root, docker, the usbip tool, the usbip-host and
// vhci_hcd modules and a USB device it may take from the host for the
// duration:
//
//	CLOOP_FORWARDER_E2E=1 [CLOOP_FORWARDER_BIN=./cloop] \
//	  [CLOOP_FORWARDER_USB_BUSID=1-1 CLOOP_FORWARDER_USB_VID=0627 CLOOP_FORWARDER_USB_PID=0001] \
//	  go test ./tests/forwarder -run TestForwardedDevices -v -timeout 20m
//
// The device is named by bus id as well as by vendor and product, so nothing
// else plugged in — and nothing already imported over USB/IP — can be taken
// by mistake; afterwards it is unbound from usbip-host (`usbip unbind -b`).
// Nothing this test did not attach is detached.
package forwarder_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const probeImage = "cloop-fwd-e2e:probe"

// probeScript stands in for cloop inside the sandbox: the hub dispatches
// `cloop run`, and this is what the image answers it with. It records what the
// sandbox can see of its forwarded devices into the workspace — which the
// agent keeps on this host — and then waits, reporting the moment the device
// goes away, so the test can revoke a binding mid-run and time the detach.
const probeScript = `#!/bin/sh
ev="$PWD/forward-evidence.txt"
log() { echo "$(cut -d' ' -f1 /proc/uptime) $*" >> "$ev"; echo "$*"; }
log "START $*"
log "ENV $CLOOP_FORWARDED_DEVICES"
# A segment's interface is moved into the sandbox a moment after it starts:
# wait for each one CLOOP_FORWARDED_DEVICES names.
for e in $(echo "$CLOOP_FORWARDED_DEVICES" | tr ',' ' '); do
  case "$e" in *=l2:*)
    want=${e##*=l2:}; n=0
    while [ ! -e "/sys/class/net/$want" ] && [ $n -lt 150 ]; do sleep 0.1; n=$((n+1)); done
    i=0; while ! ip -4 -o addr show dev "$want" 2>/dev/null | grep -q inet && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    log "WAITED $want $n";;
  esac
done
usb=""
for d in /sys/bus/usb/devices/*; do
  [ -f "$d/idVendor" ] && usb="$usb $(basename "$d")=$(cat "$d/idVendor"):$(cat "$d/idProduct")"
done
log "SYSFS$usb"
nodes=$(find /dev/bus/usb -type c 2>/dev/null | tr '\n' ' ')
log "NODES $nodes"
for n in $nodes; do
  log "DESC $n $(head -c 18 "$n" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
done
log "IFACES $(ls /sys/class/net | tr '\n' ' ')"
for i in $(ls /sys/class/net); do
  [ "$i" = lo ] && continue
  log "ADDR $i $(cat /sys/class/net/$i/address) $(ip -4 -o addr show dev $i 2>/dev/null | awk '{print $4}')"
done
if [ -n "$FWD_PEER" ]; then
  if printf 'hello from the sandbox\n' | nc -w 5 "$FWD_PEER" 7777 >/dev/null 2>&1; then log "TCP ok"; else log "TCP failed"; fi
  log "ARP $(grep "^$FWD_PEER " /proc/net/arp | awk '{print $1"/"$4}')"
fi
log PRESENT
i=0
while [ $i -lt 900 ]; do
  alive=0
  for n in $nodes; do head -c 1 "$n" >/dev/null 2>&1 && alive=1; done
  if [ -n "$nodes" ] && [ $alive = 0 ]; then log GONE; break; fi
  [ -f "$PWD/forward-release" ] && break
  sleep 0.2
  i=$((i+1))
done
log END
`

// world is one test's scratch directory, binary, processes and cleanups.
type world struct {
	t     *testing.T
	root  string
	bin   string
	token string
	env   []string

	mu    sync.Mutex
	procs []*exec.Cmd
}

func needRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("CLOOP_FORWARDER_E2E") == "" {
		t.Skip("set CLOOP_FORWARDER_E2E=1 (needs root, docker, usbip and vhci_hcd) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: the agent attaches devices through vhci_hcd and moves TAPs into sandboxes")
	}
	for _, tool := range []string{"docker", "usbip", "ip", "nsenter"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

func newWorld(t *testing.T) *world {
	t.Helper()
	root, err := os.MkdirTemp("", "cloop-fwd-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, root: root, token: "fwd-e2e-" + strconv.FormatInt(time.Now().UnixNano(), 36)}
	t.Cleanup(func() {
		w.stopAll()
		if os.Getenv("CLOOP_FORWARDER_KEEP") == "" {
			_ = os.RemoveAll(root)
		} else {
			t.Logf("kept %s", root)
		}
	})
	home := filepath.Join(root, "home")
	_ = os.MkdirAll(home, 0o700)
	// Nothing inherited from this process's environment that a hub or agent
	// reads: the host this runs on is itself a hub's child, and a CLOOP_*
	// variable leaking in would configure the test hub as that one.
	w.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"CLOOP_HOME=" + filepath.Join(root, "cloop-home"),
		"TMPDIR=" + filepath.Join(root, "tmp"),
	}
	_ = os.MkdirAll(filepath.Join(root, "tmp"), 0o755)
	w.bin = os.Getenv("CLOOP_FORWARDER_BIN")
	if w.bin == "" {
		w.bin = filepath.Join(root, "cloop")
		cmd := exec.Command("go", "build", "-o", w.bin, ".")
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build cloop: %v\n%s", err, out)
		}
	} else if abs, err := filepath.Abs(w.bin); err == nil {
		w.bin = abs
	}
	return w
}

// run runs cloop to completion in dir.
func (w *world) run(dir string, args ...string) string {
	w.t.Helper()
	cmd := exec.Command(w.bin, args...)
	cmd.Dir = dir
	cmd.Env = w.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.t.Fatalf("cloop %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// spawn starts cloop in the background in its own process group, logging to
// name.log, stopped at cleanup.
func (w *world) spawn(name, dir string, extraEnv []string, args ...string) *exec.Cmd {
	w.t.Helper()
	logf, err := os.Create(filepath.Join(w.root, name+".log"))
	if err != nil {
		w.t.Fatal(err)
	}
	cmd := exec.Command(w.bin, args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string(nil), w.env...), extraEnv...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		w.t.Fatalf("start %s: %v", name, err)
	}
	w.mu.Lock()
	w.procs = append(w.procs, cmd)
	w.mu.Unlock()
	go func() { _ = cmd.Wait(); _ = logf.Close() }()
	return cmd
}

func (w *world) stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			if syscall.Kill(cmd.Process.Pid, 0) != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		close(done)
	}()
	<-done
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func (w *world) stopAll() {
	w.mu.Lock()
	procs := append([]*exec.Cmd(nil), w.procs...)
	w.mu.Unlock()
	for i := len(procs) - 1; i >= 0; i-- {
		w.stop(procs[i])
	}
}

func (w *world) logOf(name string) string {
	b, _ := os.ReadFile(filepath.Join(w.root, name+".log"))
	return string(b)
}

// freePort returns a free loopback port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// api calls a hub with the test token.
func (w *world) api(method, url string, body any) (int, []byte) {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (w *world) mustAPI(method, url string, body any, out any) {
	w.t.Helper()
	status, b := w.api(method, url, body)
	if status/100 != 2 {
		w.t.Fatalf("%s %s = %d %s", method, url, status, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			w.t.Fatalf("%s %s: decode %q: %v", method, url, b, err)
		}
	}
}

// eventually polls cond until it holds or d passes.
func eventually(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return cond()
}

// initHub makes dir a cloop project the hub serves, with one task to run.
func (w *world) initHub(dir string) {
	w.t.Helper()
	_ = os.MkdirAll(dir, 0o755)
	w.run(dir, "init", "forwarded device e2e", "--provider", "mock", "--skip-clarify")
	w.run(dir, "task", "add", "probe the forwarded device", "--no-ai", "--auto")
}

// startHub starts `cloop ui` in dir on port, token-protected, and waits until
// it answers.
func (w *world) startHub(name, dir string, port int) string {
	w.t.Helper()
	w.spawn(name, dir, []string{"CLOOP_UI_TOKEN=" + w.token},
		"ui", "--port", strconv.Itoa(port), "--listen", "127.0.0.1", "--no-browser")
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	if !eventually(60*time.Second, func() bool { s, _ := w.api("GET", url+"/api/forwarders", nil); return s == 200 }) {
		w.t.Fatalf("hub %s did not come up:\n%s", name, w.logOf(name))
	}
	return url
}

// buildProbeImage builds the sandbox image: alpine, with the probe as cloop.
func (w *world) buildProbeImage() {
	w.t.Helper()
	dir := filepath.Join(w.root, "img")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "cloop"), []byte(probeScript), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:latest\nCOPY cloop /usr/local/bin/cloop\nENTRYPOINT []\n"), 0o644)
	if out, err := exec.Command("docker", "build", "-q", "-t", probeImage, dir).CombinedOutput(); err != nil {
		w.t.Fatalf("build the probe image: %v\n%s", err, out)
	}
	w.t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", probeImage).Run() })
}

// startAgent enrolls an agent through hubURL and starts it; it returns the
// executor id once the hub lists it online.
func (w *world) startAgent(hubURL, name string, extraEnv []string) string {
	w.t.Helper()
	var enroll struct {
		Token string `json:"token"`
	}
	// The agent runs as root — attaching through vhci_hcd and moving a TAP
	// take it — so its work root belongs to an unprivileged user, whom the
	// agent hands each sandbox's workspace to: the container driver runs a
	// workload as its workspace's owner and refuses root.
	work := filepath.Join(w.root, "agent-work-"+name)
	if err := os.MkdirAll(work, 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.Chown(work, 65532, 65532); err != nil {
		w.t.Fatal(err)
	}
	w.mustAPI("POST", hubURL+"/api/executors/enroll", map[string]any{"name": name, "workdir_root": work}, &enroll)
	w.spawn("agent-"+name, w.root, extraEnv, "executor", "agent",
		"--server", strings.Replace(hubURL, "http://", "ws://", 1)+"/api/executors/connect",
		"--token", enroll.Token, "--credential", filepath.Join(w.root, "agent-"+name+".json"),
		"--workdir-root", work)
	var id string
	if !eventually(60*time.Second, func() bool {
		var list struct {
			Executors []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				Health struct {
					State string `json:"state"`
				} `json:"health"`
			} `json:"executors"`
		}
		s, b := w.api("GET", hubURL+"/api/executors", nil)
		if s != 200 || json.Unmarshal(b, &list) != nil {
			return false
		}
		for _, e := range list.Executors {
			if e.Name == name && (e.Status == "online" || e.Health.State == "healthy") {
				id = e.ID
				return true
			}
		}
		return false
	}) {
		w.t.Fatalf("agent %s never came online:\n%s", name, w.logOf("agent-"+name))
	}
	return id
}

// startForwarder enrolls a forwarder through hubURL for device and runs it.
func (w *world) startForwarder(hubURL, name string, device map[string]any) string {
	w.t.Helper()
	body := map[string]any{"name": name}
	for k, v := range device {
		body[k] = v
	}
	var enroll struct {
		Bundle string `json:"bundle"`
	}
	w.mustAPI("POST", hubURL+"/api/forwarders/enroll", body, &enroll)
	w.spawn("forwarder-"+name, w.root, nil, "forward", "--bundle", enroll.Bundle,
		"--credential", filepath.Join(w.root, "forwarder-"+name+".json"))
	var id string
	if !eventually(30*time.Second, func() bool {
		var list struct {
			Forwarders []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Connected bool   `json:"connected"`
			} `json:"forwarders"`
		}
		s, b := w.api("GET", hubURL+"/api/forwarders", nil)
		if s != 200 || json.Unmarshal(b, &list) != nil {
			return false
		}
		for _, f := range list.Forwarders {
			if f.Name == name && f.Connected {
				id = f.ID
				return true
			}
		}
		return false
	}) {
		w.t.Fatalf("forwarder %s never connected:\n%s", name, w.logOf("forwarder-"+name))
	}
	return id
}

// evidence returns the lines the probe recorded in the agent's work root.
func (w *world) evidence(agentName string) []string {
	var lines []string
	_ = filepath.Walk(filepath.Join(w.root, "agent-work-"+agentName), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Name() == "forward-evidence.txt" {
			f, ferr := os.Open(p)
			if ferr != nil {
				return nil
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			f.Close()
		}
		return nil
	})
	return lines
}

func findLine(lines []string, word string) (string, bool) {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == word {
			return l, true
		}
	}
	return "", false
}

// sandboxNodes is the USB device nodes a probe's NODES line lists.
func sandboxNodes(line string) []string {
	if f := strings.Fields(line); len(f) > 2 {
		return f[2:]
	}
	return nil
}

// releaseProbe lets a probe that is waiting for its device to go stop.
func (w *world) releaseProbe(agentName string) {
	_ = filepath.Walk(filepath.Join(w.root, "agent-work-"+agentName), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Name() == "forward-evidence.txt" {
			_ = os.WriteFile(filepath.Join(filepath.Dir(p), "forward-release"), nil, 0o644)
		}
		return nil
	})
}

// vhciPortsInUse reads the host's vhci ports that hold a device.
func vhciPortsInUse() map[int]string {
	out := map[int]string{}
	b, err := os.ReadFile("/sys/devices/platform/vhci_hcd.0/status")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[0] == "hub" {
			continue
		}
		port, _ := strconv.Atoi(f[1])
		if f[2] != "004" {
			out[port] = f[6]
		}
	}
	return out
}

// uptime is the kernel's uptime in seconds, the clock the sandbox stamps its
// log with.
func uptime() float64 {
	b, _ := os.ReadFile("/proc/uptime")
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// configureSandbox makes the executor run payloads in the probe image, and
// binds the hub's project to it.
func (w *world) configureSandbox(hubURL, executorID string) {
	w.t.Helper()
	w.mustAPI("PUT", hubURL+"/api/executors/"+executorID+"/sandbox",
		map[string]any{"mode": "container", "engine": "docker", "image": probeImage, "network": "none"}, nil)
	w.mustAPI("POST", hubURL+"/api/projects/0/executor", map[string]any{"executor_id": executorID}, nil)
}

// projectPath is the hub's own project as the hub names it.
func (w *world) projectPath(hubURL string) string {
	w.t.Helper()
	var list struct {
		Projects []struct {
			Path string `json:"path"`
		} `json:"projects"`
	}
	w.mustAPI("GET", hubURL+"/api/projects", nil, &list)
	if len(list.Projects) == 0 {
		w.t.Fatal("the hub lists no project")
	}
	return list.Projects[0].Path
}

func (w *world) startRun(hubURL string) {
	w.t.Helper()
	status, b := w.api("POST", hubURL+"/api/run?project_idx=0", map[string]any{})
	if status/100 != 2 {
		w.t.Fatalf("start the run = %d %s", status, b)
	}
}

// waitPresent waits for the probe's first report.
func (w *world) waitPresent(agentName string) []string {
	w.t.Helper()
	var ev []string
	if !eventually(120*time.Second, func() bool {
		ev = w.evidence(agentName)
		_, ok := findLine(ev, "PRESENT")
		return ok
	}) {
		w.t.Fatalf("the sandbox never reported; agent log:\n%s", w.logOf("agent-"+agentName))
	}
	return ev
}

// TestForwardedDevices runs the USB, L2, hub-host and cluster scenarios.
func TestForwardedDevices(t *testing.T) {
	needRoot(t)
	t.Run("usb", testUSB)
	t.Run("l2", testL2)
	t.Run("hostcontainer", testHostContainer)
	t.Run("cluster", testCluster)
}

// usbDevice is the device the USB scenarios forward, by bus id and identity.
func usbDevice() (busid, vid, pid string) {
	return envOr("CLOOP_FORWARDER_USB_BUSID", "1-1"), envOr("CLOOP_FORWARDER_USB_VID", "0627"), envOr("CLOOP_FORWARDER_USB_PID", "0001")
}

func requireUSB(t *testing.T) {
	t.Helper()
	busid, vid, pid := usbDevice()
	dir := filepath.Join("/sys/bus/usb/devices", busid)
	v, _ := os.ReadFile(filepath.Join(dir, "idVendor"))
	p, _ := os.ReadFile(filepath.Join(dir, "idProduct"))
	if strings.TrimSpace(string(v)) != vid || strings.TrimSpace(string(p)) != pid {
		t.Skipf("no USB device %s:%s at %s on this host", vid, pid, busid)
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil && strings.Contains(real, "/vhci_hcd.") {
		t.Skipf("%s is itself imported over USB/IP; it is not this test's to forward", busid)
	}
	t.Cleanup(func() { _ = exec.Command("usbip", "unbind", "-b", busid).Run() })
}

// assertUSBInSandbox checks the probe saw the forwarded device and returns
// the vhci port the agent attached it to.
func assertUSBInSandbox(t *testing.T, w *world, agentName string, before map[int]string) (int, []string) {
	t.Helper()
	_, vid, pid := usbDevice()
	ev := w.waitPresent(agentName)
	sysfs, _ := findLine(ev, "SYSFS")
	nodes, _ := findLine(ev, "NODES")
	t.Logf("sandbox saw: %s | %s", strings.SplitN(sysfs, " ", 2)[1], strings.SplitN(nodes, " ", 2)[1])
	var attached int = -1
	for port, busid := range vhciPortsInUse() {
		if _, had := before[port]; !had {
			attached = port
			if !strings.Contains(sysfs, busid+"="+vid+":"+pid) {
				t.Fatalf("the sandbox's /sys/bus/usb/devices does not show the forwarded device %s at %s: %s", vid+":"+pid, busid, sysfs)
			}
		}
	}
	if attached < 0 {
		t.Fatalf("no new vhci port holds the forwarded device; ports in use: %v", vhciPortsInUse())
	}
	// Its sysfs lists every USB device on the host, as any container's does,
	// but the only node it holds — so the only device it can open — is the
	// forwarded one.
	if got := sandboxNodes(nodes); len(got) != 1 {
		t.Fatalf("the sandbox holds USB device nodes %v; want exactly the forwarded device's", got)
	}
	desc := ""
	for _, l := range ev {
		if strings.Contains(l, " DESC ") {
			desc = l
		}
	}
	// The device descriptor's idVendor and idProduct are bytes 8..11, little
	// endian: 0627:0001 reads 2706 0100.
	wantDesc := vid[2:4] + vid[0:2] + pid[2:4] + pid[0:2]
	if !strings.Contains(strings.ReplaceAll(desc, " ", ""), wantDesc) {
		t.Fatalf("the device node in the sandbox did not answer with the device's descriptor (want %s): %q", wantDesc, desc)
	}
	return attached, ev
}

func testUSB(t *testing.T) {
	requireUSB(t)
	busid, vid, pid := usbDevice()
	w := newWorld(t)
	w.buildProbeImage()
	hubDir := filepath.Join(w.root, "hub")
	w.initHub(hubDir)
	hub := w.startHub("hub", hubDir, freePort(t))

	exID := w.startAgent(hub, "e2e-agent", nil)
	w.configureSandbox(hub, exID)
	fwdID := w.startForwarder(hub, "bench-tablet", map[string]any{
		"kind": "usb", "usb": map[string]any{"vendor_id": vid, "product_id": pid, "port": busid},
	})

	// The probe reaches the device through the tunnel without handing it to
	// anything.
	var probe struct {
		Reachable bool `json:"reachable"`
		Exported  struct {
			BusID string `json:"bus_id"`
		} `json:"exported"`
	}
	w.mustAPI("POST", hub+"/api/forwarders/"+fwdID+"/expose", map[string]any{}, &probe)
	if !probe.Reachable || probe.Exported.BusID != busid {
		t.Fatalf("probe = %+v; want the forwarder's %s reachable", probe, busid)
	}

	before := vhciPortsInUse()
	var bound struct {
		Binding struct {
			ID string `json:"id"`
		} `json:"binding"`
	}
	w.mustAPI("POST", hub+"/api/forwarders/"+fwdID+"/bindings", map[string]any{"project": w.projectPath(hub)}, &bound)
	w.startRun(hub)
	port, _ := assertUSBInSandbox(t, w, "e2e-agent", before)
	if strings.Contains(w.logOf("agent-e2e-agent")+w.logOf("hub"), "usbip --tcp-port") {
		t.Fatal("something still printed a loopback usbip attach command")
	}

	// (e) Revocation mid-run: unbind, and time the device leaving the agent's
	// host and the sandbox. The sandbox stamps its log with the kernel's
	// uptime, which it shares with this process.
	revoked := time.Now()
	revokedUptime := uptime()
	w.mustAPI("DELETE", hub+"/api/forwarders/bindings/"+bound.Binding.ID, nil, nil)
	if !eventually(15*time.Second, func() bool { _, used := vhciPortsInUse()[port]; return !used }) {
		t.Fatalf("vhci port %d still holds the device 15s after the binding was revoked", port)
	}
	hostGone := time.Since(revoked)
	var gone string
	if !eventually(15*time.Second, func() bool { var ok bool; gone, ok = findLine(w.evidence("e2e-agent"), "GONE"); return ok }) {
		t.Fatalf("the sandbox still reaches the device 15s after the binding was revoked")
	}
	ts, _ := strconv.ParseFloat(strings.Fields(gone)[0], 64)
	sandboxGone := time.Duration((ts - revokedUptime) * float64(time.Second))
	t.Logf("revoked mid-run: the agent's host freed vhci port %d after %s, the sandbox lost the device after %s",
		port, hostGone.Round(time.Millisecond), sandboxGone.Round(time.Millisecond))
	if hostGone > 5*time.Second || sandboxGone > 5*time.Second {
		t.Fatalf("the detach took longer than seconds: host %s, sandbox %s", hostGone, sandboxGone)
	}
	for p, b := range before {
		if vhciPortsInUse()[p] != b {
			t.Fatalf("vhci port %d (%s), in use before the test, was disturbed", p, b)
		}
	}
}

func testL2(t *testing.T) {
	w := newWorld(t)
	// The on-prem segment: a veth pair, one end in a namespace with an
	// address and a listener, the other end the forwarder's.
	ns, a, b := "cfwd-e2e-onprem", "cfwdE2Ea", "cfwdE2Eb"
	ipc := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	_ = exec.Command("ip", "netns", "del", ns).Run()
	_ = exec.Command("ip", "link", "del", a).Run()
	ipc("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	ipc("link", "add", a, "type", "veth", "peer", "name", b)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", a).Run() })
	ipc("link", "set", b, "netns", ns)
	ipc("-n", ns, "addr", "add", "10.77.0.1/24", "dev", b)
	ipc("-n", ns, "link", "set", b, "up")
	ipc("-n", ns, "link", "set", "lo", "up")
	ipc("link", "set", a, "up")
	got := filepath.Join(w.root, "listener.out")
	listener := exec.Command("ip", "netns", "exec", ns, "python3", "-c", `
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.77.0.1",7777)); s.listen(4); s.settimeout(300)
c,addr=s.accept(); data=c.recv(4096)
open(sys.argv[1],"w").write("%s %s" % (addr[0], data.decode().strip()))
`, got)
	listener.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-listener.Process.Pid, syscall.SIGKILL); _ = listener.Wait() })

	w.buildProbeImage()
	hubDir := filepath.Join(w.root, "hub")
	w.initHub(hubDir)
	hub := w.startHub("hub", hubDir, freePort(t))
	exID := w.startAgent(hub, "l2-agent", nil)
	w.configureSandbox(hub, exID)
	fwdID := w.startForwarder(hub, "lab-segment", map[string]any{"kind": "l2", "interface": a})
	w.mustAPI("POST", hub+"/api/forwarders/"+fwdID+"/bindings", map[string]any{
		"project": w.projectPath(hub), "interface": map[string]any{"target": "fwd0", "address": "10.77.0.2/24"},
	}, nil)
	// FWD_PEER reaches the probe through the image's environment.
	dir := filepath.Join(w.root, "img")
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:latest\nCOPY cloop /usr/local/bin/cloop\nENV FWD_PEER=10.77.0.1\nENTRYPOINT []\n"), 0o644)
	if out, err := exec.Command("docker", "build", "-q", "-t", probeImage, dir).CombinedOutput(); err != nil {
		t.Fatalf("rebuild the probe image: %v\n%s", err, out)
	}
	w.startRun(hub)
	ev := w.waitPresent("l2-agent")
	w.releaseProbe("l2-agent")
	tcp, _ := findLine(ev, "TCP")
	arp, _ := findLine(ev, "ARP")
	ifaces, _ := findLine(ev, "IFACES")
	t.Logf("sandbox: %s | %s | %s", ifaces, tcp, arp)
	if !strings.Contains(ifaces, "fwd0") {
		t.Fatalf("the sandbox has no fwd0 interface: %s", ifaces)
	}
	if !strings.HasSuffix(tcp, "TCP ok") {
		t.Fatalf("the sandbox could not reach the segment's peer: %v", ev)
	}
	// The peer's MAC, as the sandbox resolved it over ARP through the forward.
	peerMAC, _ := exec.Command("ip", "netns", "exec", ns, "cat", "/sys/class/net/"+b+"/address").Output()
	if !strings.Contains(arp, strings.TrimSpace(string(peerMAC))) {
		t.Fatalf("the sandbox's ARP entry for the peer is %q, want its MAC %s", arp, peerMAC)
	}
	if !eventually(10*time.Second, func() bool { b, _ := os.ReadFile(got); return len(b) > 0 }) {
		t.Fatal("the segment's listener received nothing")
	}
	out, _ := os.ReadFile(got)
	if !strings.HasPrefix(string(out), "10.77.0.2 hello from the sandbox") {
		t.Fatalf("the listener received %q", out)
	}
	t.Logf("the on-prem listener heard: %s", out)
}

func testCluster(t *testing.T) {
	requireUSB(t)
	busid, vid, pid := usbDevice()
	w := newWorld(t)
	w.buildProbeImage()
	hubDir := filepath.Join(w.root, "hub")
	w.initHub(hubDir)
	// Two members serving one control plane: the forwarder dials A, the
	// agent B.
	a := w.startHub("hub-a", hubDir, freePort(t))
	b := w.startHub("hub-b", hubDir, freePort(t))
	if !eventually(30*time.Second, func() bool {
		var st struct {
			Members []json.RawMessage `json:"members"`
		}
		s, body := w.api("GET", a+"/api/cluster", nil)
		return s == 200 && json.Unmarshal(body, &st) == nil && len(st.Members) == 2
	}) {
		t.Fatalf("the two hubs never formed a cluster")
	}
	exID := w.startAgent(b, "cluster-agent", nil)
	w.configureSandbox(b, exID)
	fwdID := w.startForwarder(a, "cluster-tablet", map[string]any{
		"kind": "usb", "usb": map[string]any{"vendor_id": vid, "product_id": pid, "port": busid},
	})

	// B lists the forwarder connected, through A.
	var list struct {
		Forwarders []struct {
			ID           string `json:"id"`
			Connected    bool   `json:"connected"`
			ConnectedVia string `json:"connected_via"`
		} `json:"forwarders"`
	}
	if !eventually(15*time.Second, func() bool {
		w.mustAPI("GET", b+"/api/forwarders", nil, &list)
		return len(list.Forwarders) == 1 && list.Forwarders[0].Connected && list.Forwarders[0].ConnectedVia != ""
	}) {
		t.Fatalf("member B does not show the forwarder A holds as connected: %+v", list)
	}
	// The probe reaches it through B, which forwards to A.
	var probe struct {
		Reachable bool   `json:"reachable"`
		Member    string `json:"member"`
	}
	w.mustAPI("POST", b+"/api/forwarders/"+fwdID+"/expose", map[string]any{}, &probe)
	if !probe.Reachable || probe.Member != list.Forwarders[0].ConnectedVia {
		t.Fatalf("probe through B = %+v; want it served by the member holding the tunnel (%s)", probe, list.Forwarders[0].ConnectedVia)
	}

	before := vhciPortsInUse()
	var bound struct {
		Binding struct {
			ID string `json:"id"`
		} `json:"binding"`
	}
	w.mustAPI("POST", b+"/api/forwarders/"+fwdID+"/bindings", map[string]any{"project": w.projectPath(b)}, &bound)
	w.startRun(b)
	port, _ := assertUSBInSandbox(t, w, "cluster-agent", before)

	// Revoke the forwarder itself through B, which does not hold its tunnel:
	// A cuts the session at once, and the run loses the device.
	revoked := time.Now()
	w.mustAPI("DELETE", b+"/api/forwarders/"+fwdID, nil, nil)
	if !eventually(15*time.Second, func() bool { _, used := vhciPortsInUse()[port]; return !used }) {
		t.Fatalf("vhci port %d still holds the device after the forwarder was revoked through the other member", port)
	}
	if !eventually(15*time.Second, func() bool {
		return strings.Contains(w.logOf("forwarder-cluster-tablet"), "credential revoked") ||
			strings.Contains(w.logOf("forwarder-cluster-tablet"), "revoked")
	}) {
		t.Fatalf("the forwarder's session on A was not cut:\n%s", w.logOf("forwarder-cluster-tablet"))
	}
	t.Logf("revoked through the member without the tunnel: detached after %s", time.Since(revoked).Round(time.Millisecond))
}

// testHostContainer is the hub's own container executor: the hub attaches the
// forwarded device in its own process — vhci_hcd through a socketpair, as the
// agent does — and passes the node into a container on its host. No
// listener is opened for it.
func testHostContainer(t *testing.T) {
	requireUSB(t)
	busid, vid, pid := usbDevice()
	w := newWorld(t)
	// The hub dispatches its own binary's path as argv[0] to a container on
	// its host, so the probe stands in at that path too.
	dir := filepath.Join(w.root, "img")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "cloop"), []byte(probeScript), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(fmt.Sprintf(
		"FROM alpine:latest\nCOPY cloop /usr/local/bin/cloop\nCOPY cloop %s\nENTRYPOINT []\n", w.bin)), 0o644)
	if out, err := exec.Command("docker", "build", "-q", "-t", probeImage, dir).CombinedOutput(); err != nil {
		t.Fatalf("build the probe image: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", probeImage).Run() })

	hubDir := filepath.Join(w.root, "hub")
	w.initHub(hubDir)
	for _, kv := range [][2]string{
		{"executors.container.enabled", "true"},
		{"executors.container.id", "hub-container"},
		{"executors.container.runtime", "docker"},
		{"executors.container.image", probeImage},
		{"executors.container.network", "none"},
	} {
		w.run(hubDir, "config", "set", kv[0], kv[1])
	}
	// The container driver runs a workload as its project directory's owner
	// and refuses root.
	if err := filepath.Walk(hubDir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, 65532, 65532)
	}); err != nil {
		t.Fatal(err)
	}
	hub := w.startHub("hub", hubDir, freePort(t))
	w.mustAPI("POST", hub+"/api/projects/0/executor", map[string]any{"executor_id": "hub-container"}, nil)
	fwdID := w.startForwarder(hub, "host-tablet", map[string]any{
		"kind": "usb", "usb": map[string]any{"vendor_id": vid, "product_id": pid, "port": busid},
	})
	before := vhciPortsInUse()
	var bound struct {
		Binding struct {
			ID string `json:"id"`
		} `json:"binding"`
	}
	w.mustAPI("POST", hub+"/api/forwarders/"+fwdID+"/bindings", map[string]any{"project": w.projectPath(hub)}, &bound)
	w.startRun(hub)

	var ev []string
	if !eventually(120*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(hubDir, "forward-evidence.txt"))
		ev = strings.Split(strings.TrimSpace(string(b)), "\n")
		_, ok := findLine(ev, "PRESENT")
		return ok
	}) {
		t.Fatalf("the sandbox never reported; hub log:\n%s", w.logOf("hub"))
	}
	sysfs, _ := findLine(ev, "SYSFS")
	nodes, _ := findLine(ev, "NODES")
	t.Logf("sandbox on the hub's host saw: %s | %s", sysfs, nodes)
	port := -1
	for p, b := range vhciPortsInUse() {
		if _, had := before[p]; !had {
			port = p
			if !strings.Contains(sysfs, b+"="+vid+":"+pid) {
				t.Fatalf("the sandbox's /sys/bus/usb/devices does not show the device at %s: %s", b, sysfs)
			}
		}
	}
	if port < 0 || len(sandboxNodes(nodes)) != 1 {
		t.Fatalf("the hub did not attach the device, and only it, for its container (port %d, nodes %q)", port, nodes)
	}
	// Nothing listens for it: the hub process holds no new listening socket
	// beyond its own HTTP port.
	if out, _ := exec.Command("ss", "-ltnpH").Output(); strings.Contains(string(out), "usbip") {
		t.Fatalf("a usbip listener exists:\n%s", out)
	}
	revoked := time.Now()
	w.mustAPI("DELETE", hub+"/api/forwarders/bindings/"+bound.Binding.ID, nil, nil)
	if !eventually(15*time.Second, func() bool { _, used := vhciPortsInUse()[port]; return !used }) {
		t.Fatalf("vhci port %d still holds the device after the binding was revoked", port)
	}
	t.Logf("revoked: the hub freed vhci port %d after %s", port, time.Since(revoked).Round(time.Millisecond))
	_ = os.WriteFile(filepath.Join(hubDir, "forward-release"), nil, 0o644)
	// Let the run end and the hub reap its container before the hub stops,
	// so the test leaves no container behind.
	if !eventually(30*time.Second, func() bool {
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.executor=hub-container").Output()
		return strings.TrimSpace(string(out)) == ""
	}) {
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.executor=hub-container").Output()
		for _, id := range strings.Fields(string(out)) {
			_ = exec.Command("docker", "rm", "-f", id).Run()
		}
	}
}
