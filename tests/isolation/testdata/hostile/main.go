// Command hostile stands in for Claude Code in tests/isolation, as an agent
// that has turned on the hub. The claudecode provider runs it as `claude`
// with the task's prompt on stdin; it finds the plan the test wrote into its
// task's description, carries out every attempt in it, and reports what each
// one reached.
//
// It plays one of two roles, as the plan says:
//
//   - attacker: tries to read, write and delete another project's files, its
//     state database and the hub's control plane, to call the hub's run and
//     dashboard routes with the credentials it was given while naming the
//     other project, and to reach the other project's live run. Each attempt
//     is a probe that reports ok or denied with the error; the test decides
//     which outcome is right. Probes that would damage the target if they
//     succeeded are kept to the smallest change that proves the permission
//     (a chmod to the mode the file already has, an open for writing with
//     nothing written), so a hole the suite finds does not also wreck the
//     scene it is reported from.
//   - victim: holds its project's run open, with a TCP listener and a Unix
//     socket in its own tree, until the test lets it finish, so the attacker
//     has a live run to reach.
//
// The report goes to the task's attachments directory ($CLOOP_TASK_ATTACHMENTS),
// which the hub collects from every executor kind, and to stdout. The output
// ends with TASK_DONE whatever the probes found: the test reads the verdicts,
// not the task's status.
//
// It lives under testdata so `go build ./...` and the orphan check never see
// it; the suite builds it, statically, for the hub's host, a device and a
// container image alike.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// plan is what the test asks of one run. It mirrors tests/isolation's
// hostilePlan; the two are kept apart because a testdata program cannot
// import a test file.
type plan struct {
	Role string `json:"role"`
	Tag  string `json:"tag"`
	// HubURL is the hub's base URL as this run reaches it.
	HubURL string `json:"hub_url,omitempty"`
	// HoldSeconds bounds how long a victim holds its run open.
	HoldSeconds int       `json:"hold_seconds,omitempty"`
	Attempts    []attempt `json:"attempts,omitempty"`
}

// attempt is one probe. Paths may start with @own/ (the run's own working
// directory) or @ro:<project path>// (where CLOOP_READONLY_PROJECTS says the
// run finds that project); URLs may start with {readers} (the run's session
// URL) or {hub}.
type attempt struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Dest   string `json:"dest,omitempty"`
	Target string `json:"target,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	// Auth names the environment variable holding the bearer token to send;
	// empty sends none.
	Auth string `json:"auth,omitempty"`
	Body string `json:"body,omitempty"`
}

// result is one probe's outcome.
type result struct {
	Name    string   `json:"name"`
	OK      bool     `json:"ok"`
	Status  int      `json:"status,omitempty"`
	Detail  string   `json:"detail,omitempty"`
	Digest  string   `json:"digest,omitempty"`
	Entries []string `json:"entries,omitempty"`
}

// report is what the test reads back.
type report struct {
	Role    string   `json:"role"`
	Tag     string   `json:"tag"`
	UID     int      `json:"uid"`
	Cwd     string   `json:"cwd"`
	Results []result `json:"results,omitempty"`
	// ReadOnly is CLOOP_READONLY_PROJECTS as the run was given it.
	ReadOnly string `json:"read_only,omitempty"`
	// Credentials names the run credentials found in the environment.
	Credentials []string `json:"credentials,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// ready is what a victim tells the test once its run is open.
type ready struct {
	Tag    string   `json:"tag"`
	PID    int      `json:"pid"`
	Port   int      `json:"port"`
	Socket string   `json:"socket,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
	UID    int      `json:"uid"`
}

var (
	currentTask = regexp.MustCompile(`\*\*Task [0-9]+: ([^\n]*?)\*\*`)
	taskTag     = regexp.MustCompile(`\[iso:([a-z0-9-]+)\]`)
)

func main() {
	prompt, _ := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
	p, err := findPlan(string(prompt))
	if err != nil {
		fmt.Println("hostile: " + err.Error())
		fmt.Println("TASK_DONE")
		return
	}
	switch p.Role {
	case "victim":
		victim(p)
	case "attacker":
		attacker(p)
	default:
		fmt.Printf("hostile: the plan's role %q is neither attacker nor victim\n", p.Role)
	}
	fmt.Println("TASK_DONE")
}

// findPlan is the plan written for the task this prompt is about: the first
// task header names it by its [iso:<tag>] marker, and the description carries
// HOSTILE-PLAN:<tag>:<base64 JSON>.
func findPlan(prompt string) (plan, error) {
	m := currentTask.FindStringSubmatch(prompt)
	if m == nil {
		return plan{}, errors.New("no task in the prompt")
	}
	t := taskTag.FindStringSubmatch(m[1])
	if t == nil {
		return plan{}, fmt.Errorf("the task %q carries no [iso:…] marker", m[1])
	}
	marker := "HOSTILE-PLAN:" + t[1] + ":"
	i := strings.Index(prompt, marker)
	if i < 0 {
		return plan{}, fmt.Errorf("no plan for %s in the prompt", t[1])
	}
	rest := prompt[i+len(marker):]
	end := strings.IndexFunc(rest, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=')
	})
	if end >= 0 {
		rest = rest[:end]
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return plan{}, fmt.Errorf("the plan for %s is not base64: %v", t[1], err)
	}
	var p plan
	if err := json.Unmarshal(raw, &p); err != nil {
		return plan{}, fmt.Errorf("the plan for %s is not JSON: %v", t[1], err)
	}
	if p.Tag != t[1] {
		return plan{}, fmt.Errorf("the plan says it is for %q, the task is %q", p.Tag, t[1])
	}
	return p, nil
}

// ─── the victim ─────────────────────────────────────────────────────────────

func victim(p plan) {
	cwd, _ := os.Getwd()
	dir := filepath.Join(cwd, ".cloop", "hostile-victim")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Println("hostile victim: " + err.Error())
		return
	}
	banner := []byte("victim:" + p.Tag + "\n")
	serve := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write(banner)
			_ = c.Close()
		}
	}
	tcp, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Println("hostile victim: listen: " + err.Error())
		return
	}
	defer tcp.Close()
	go serve(tcp)
	r := ready{Tag: p.Tag, PID: os.Getpid(), Port: tcp.Addr().(*net.TCPAddr).Port, UID: os.Getuid()}
	// A short name at the top of the tree: a Unix socket's path is bounded
	// at 108 bytes. Bound by its relative name, from the working directory.
	_ = os.Remove(".hv.sock")
	if ul, err := net.Listen("unix", ".hv.sock"); err == nil {
		defer ul.Close()
		go serve(ul)
		r.Socket = filepath.Join(cwd, ".hv.sock")
	} else {
		fmt.Println("hostile victim: no unix socket: " + err.Error())
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
				r.Addrs = append(r.Addrs, ipn.IP.String())
			}
		}
	}
	blob, _ := json.Marshal(r)
	tmp := filepath.Join(dir, ".ready.tmp")
	if err := os.WriteFile(tmp, blob, 0o644); err != nil || os.Rename(tmp, filepath.Join(dir, "ready.json")) != nil {
		fmt.Println("hostile victim: could not say it is ready")
		return
	}
	hold := time.Duration(p.HoldSeconds) * time.Second
	if hold <= 0 {
		hold = 4 * time.Minute
	}
	deadline := time.Now().Add(hold)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = os.Remove(".hv.sock")
	fmt.Println("hostile victim: held the run open until released")
}

// ─── the attacker ───────────────────────────────────────────────────────────

func attacker(p plan) {
	cwd, _ := os.Getwd()
	rep := report{Role: "attacker", Tag: p.Tag, UID: os.Getuid(), Cwd: cwd,
		ReadOnly: os.Getenv("CLOOP_READONLY_PROJECTS")}
	for _, name := range credentialVars {
		if os.Getenv(name) != "" {
			rep.Credentials = append(rep.Credentials, name)
		}
	}
	if u := proxyURL(); u != nil && u.User != nil {
		rep.Credentials = append(rep.Credentials, egressSession)
	}
	if os.Getenv("GIT_CONFIG_GLOBAL") != "" || os.Getenv("GIT_CONFIG_COUNT") != "" {
		rep.Credentials = append(rep.Credentials, "@git-config")
	}
	scratch := filepath.Join(cwd, ".cloop", "hostile", p.Tag)
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		rep.Error = "no scratch directory in its own tree: " + err.Error()
	}
	ro := readOnlyPaths(rep.ReadOnly)
	for _, a := range p.Attempts {
		r := probe(a, p, cwd, scratch, ro)
		r.Name = a.Name
		r.Detail = scrub(r.Detail)
		rep.Results = append(rep.Results, r)
	}
	blob, _ := json.MarshalIndent(rep, "", "  ")
	if dir := os.Getenv("CLOOP_TASK_ATTACHMENTS"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(dir, "hostile-report.json"), blob, 0o644)
		}
	}
	_ = os.WriteFile(filepath.Join(cwd, ".cloop", "hostile", p.Tag+".json"), blob, 0o644)
	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(w, "hostile attacker %s: %d probes\n", p.Tag, len(rep.Results))
	for _, r := range rep.Results {
		verdict := "denied"
		if r.OK {
			verdict = "REACHED"
		}
		fmt.Fprintf(w, "  %-8s %s", verdict, r.Name)
		if r.Status != 0 {
			fmt.Fprintf(w, " (HTTP %d)", r.Status)
		}
		fmt.Fprintln(w)
	}
	_ = w.Flush()
}

// egressSession, as an attempt's Auth, sends the egress session's
// credential, which the run holds in its proxy URL rather than a variable.
const egressSession = "@egress-session"

// credentialVars are the run credentials the hub may hand a run; the report
// says which this one held, never their values.
var credentialVars = []string{
	"CLOOP_READERS_TOKEN", "CLOOP_KNOWLEDGE_TOKEN", "CLOOP_SECRET_KEY", "CLOOP_UI_TOKEN",
	"CLOOP_API_TOKEN", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
}

// readOnlyPaths maps each project CLOOP_READONLY_PROJECTS names to where the
// run finds it.
func readOnlyPaths(manifest string) map[string]string {
	out := map[string]string{}
	var entries []struct {
		Project string `json:"project"`
		Path    string `json:"path"`
	}
	if json.Unmarshal([]byte(manifest), &entries) == nil {
		for _, e := range entries {
			out[filepath.Clean(e.Project)] = e.Path
		}
	}
	return out
}

// resolve turns a plan's path into a path on this machine, or why it has
// none.
func resolve(path, cwd string, ro map[string]string) (string, error) {
	switch {
	case strings.HasPrefix(path, "@own/"):
		return filepath.Join(cwd, strings.TrimPrefix(path, "@own/")), nil
	case strings.HasPrefix(path, "@ro:"):
		project, rel, _ := strings.Cut(strings.TrimPrefix(path, "@ro:"), "//")
		base, ok := ro[filepath.Clean(project)]
		if !ok {
			return "", fmt.Errorf("the run was given no read-only copy of %s", project)
		}
		return filepath.Join(base, rel), nil
	}
	return path, nil
}

func probe(a attempt, p plan, cwd, scratch string, ro map[string]string) (r result) {
	defer func() {
		if x := recover(); x != nil {
			r = result{Detail: fmt.Sprintf("probe panicked: %v", x)}
		}
	}()
	path, err := resolve(a.Path, cwd, ro)
	if a.Path != "" && err != nil {
		return result{Detail: err.Error()}
	}
	dest := ""
	if a.Dest != "" {
		if dest, err = resolve(a.Dest, cwd, ro); err != nil {
			return result{Detail: err.Error()}
		}
	}
	switch a.Kind {
	case "read":
		return readFile(path)
	case "list":
		entries, err := os.ReadDir(path)
		if err != nil {
			return denied(err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		if len(names) > 64 {
			names = names[:64]
		}
		return result{OK: true, Entries: names}
	case "stat":
		fi, err := os.Lstat(path)
		if err != nil {
			return denied(err)
		}
		return result{OK: true, Detail: fi.Mode().String()}
	case "create":
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return denied(err)
		}
		_, err = f.WriteString("planted by a hostile run\n")
		_ = f.Close()
		if err != nil {
			return result{OK: true, Detail: "created, but the write failed: " + err.Error()}
		}
		return result{OK: true, Detail: "created"}
	case "open-write":
		// The permission alone: nothing is written.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return denied(err)
		}
		_ = f.Close()
		return result{OK: true, Detail: "opened for writing"}
	case "overwrite":
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return denied(err)
		}
		_, _ = f.WriteString("overwritten by a hostile run\n")
		_ = f.Close()
		return result{OK: true, Detail: "overwritten"}
	case "append":
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return denied(err)
		}
		_, _ = f.WriteString("appended by a hostile run\n")
		_ = f.Close()
		return result{OK: true, Detail: "appended"}
	case "remove":
		if err := os.Remove(path); err != nil {
			return denied(err)
		}
		return result{OK: true, Detail: "removed"}
	case "mkdir":
		if err := os.Mkdir(path, 0o755); err != nil {
			return denied(err)
		}
		return result{OK: true, Detail: "made"}
	case "rename":
		if dest == "" {
			dest = filepath.Join(scratch, "moved-"+filepath.Base(path))
		}
		if err := os.Rename(path, dest); err != nil {
			return denied(err)
		}
		return result{OK: true, Detail: "moved to " + dest}
	case "chmod-same":
		// Changing a file's mode to the one it has proves the permission
		// and changes nothing.
		fi, err := os.Stat(path)
		if err != nil {
			return denied(err)
		}
		if err := os.Chmod(path, fi.Mode().Perm()); err != nil {
			return denied(err)
		}
		return result{OK: true, Detail: "its mode could be changed"}
	case "symlink-read":
		link := filepath.Join(scratch, "link-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		if err := os.Symlink(path, link); err != nil {
			return denied(err)
		}
		return readFile(link)
	case "hardlink":
		link := filepath.Join(scratch, "hard-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		if err := os.Link(path, link); err != nil {
			return denied(err)
		}
		r := readFile(link)
		r.Detail = "linked into its own tree; " + r.Detail
		r.OK = true
		return r
	case "proc":
		return readFile(filepath.Join("/proc", strconv.Itoa(a.PID), a.Target))
	case "signal":
		if a.PID <= 0 {
			return result{Detail: "no process to signal"}
		}
		if err := syscall.Kill(a.PID, 0); err != nil {
			return denied(err)
		}
		return result{OK: true, Detail: "it may signal the process"}
	case "tcp":
		return dial("tcp", a.Target)
	case "unix":
		// The path may be longer than a socket address holds: connect by
		// its name from its directory.
		dir, name := filepath.Split(path)
		back, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			return denied(err)
		}
		defer func() { _ = os.Chdir(back) }()
		return dial("unix", name)
	case "env":
		if os.Getenv(a.Target) != "" {
			return result{OK: true, Detail: a.Target + " is set"}
		}
		return result{Detail: a.Target + " is not set"}
	case "http":
		return request(a, p)
	case "connect":
		return connectThroughProxy(a.Target)
	case "git":
		return runGit(cwd, strings.Fields(a.Target))
	}
	return result{Detail: "unknown probe kind " + a.Kind}
}

// runGit runs git with the run's own environment, as an agent would, and
// says how it ended.
func runGit(cwd string, args []string) result {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	detail := strings.TrimSpace(string(out))
	if len(detail) > 600 {
		detail = detail[len(detail)-600:]
	}
	if err != nil {
		return result{Detail: err.Error() + ": " + detail}
	}
	return result{OK: true, Detail: detail}
}

// proxyURL is the run's HTTPS_PROXY: the hub's egress proxy, with the run's
// session in it, when the run was given one.
func proxyURL() *url.URL {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy"} {
		if v := os.Getenv(k); v != "" {
			if u, err := url.Parse(v); err == nil && u.Host != "" {
				return u
			}
		}
	}
	return nil
}

// connectThroughProxy asks the run's egress proxy for a tunnel to target,
// with the session the run was given, and reports the proxy's answer.
func connectThroughProxy(target string) result {
	u := proxyURL()
	if u == nil {
		return result{Detail: "the run was given no proxy"}
	}
	c, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		return denied(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u.User != nil {
		pass, _ := u.User.Password()
		req += "Proxy-Authorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		return denied(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return denied(err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 600))
	_ = resp.Body.Close()
	return result{Status: resp.StatusCode, OK: resp.StatusCode == http.StatusOK,
		Detail: strings.TrimSpace(resp.Status + " " + string(body))}
}

func denied(err error) result { return result{Detail: err.Error()} }

func readFile(path string) result {
	f, err := os.Open(path)
	if err != nil {
		return denied(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return denied(err)
	}
	sum := sha256.Sum256(data)
	return result{OK: true, Digest: hex.EncodeToString(sum[:]), Detail: fmt.Sprintf("read %d bytes", len(data))}
}

func dial(network, addr string) result {
	if addr == "" {
		return result{Detail: "no address to reach"}
	}
	c, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		return denied(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return result{OK: true, Detail: "connected; it said " + strconv.Quote(strings.TrimSpace(line))}
}

// request sends one HTTP request with the credential the attempt names.
func request(a attempt, p plan) result {
	url := a.URL
	switch {
	case strings.HasPrefix(url, "{readers}"):
		base := os.Getenv("CLOOP_READERS_URL")
		if base == "" {
			base = os.Getenv("CLOOP_KNOWLEDGE_URL")
		}
		if base == "" {
			return result{Detail: "the run was given no session URL"}
		}
		url = strings.TrimRight(base, "/") + strings.TrimPrefix(url, "{readers}")
	case strings.HasPrefix(url, "{hub}"):
		url = strings.TrimRight(p.HubURL, "/") + strings.TrimPrefix(url, "{hub}")
	}
	var body io.Reader
	if a.Body != "" {
		body = strings.NewReader(a.Body)
	}
	req, err := http.NewRequest(a.Method, url, body)
	if err != nil {
		return denied(err)
	}
	if a.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if a.Auth != "" {
		token := os.Getenv(a.Auth)
		if a.Auth == egressSession {
			// The egress session's credential, from the proxy URL the run
			// was given.
			token = ""
			if u := proxyURL(); u != nil && u.User != nil {
				token, _ = u.User.Password()
			}
		}
		if token == "" {
			return result{Detail: "the run holds no " + a.Auth}
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Straight to the hub: an attacker does not send its requests through
	// the egress proxy it was given.
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return denied(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r := result{Status: resp.StatusCode, OK: resp.StatusCode >= 200 && resp.StatusCode < 300}
	if resp.Header.Get("Content-Type") == "application/gzip" {
		sum := sha256.Sum256(data)
		r.Digest, r.Detail = hex.EncodeToString(sum[:]), fmt.Sprintf("an archive of %d bytes", len(data))
		return r
	}
	r.Detail = string(bytes.TrimSpace(data))
	if len(r.Detail) > 600 {
		r.Detail = r.Detail[:600]
	}
	return r
}

// scrub keeps every credential the run holds out of its report.
func scrub(s string) string {
	for _, name := range credentialVars {
		if v := os.Getenv(name); len(v) >= 8 {
			s = strings.ReplaceAll(s, v, "<"+name+">")
		}
	}
	if u := proxyURL(); u != nil && u.User != nil {
		if pass, _ := u.User.Password(); len(pass) >= 8 {
			s = strings.ReplaceAll(s, pass, "<egress session>")
		}
	}
	return s
}
