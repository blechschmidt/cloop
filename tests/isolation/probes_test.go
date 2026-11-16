package isolation_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

// hostilePlan, hostileAttempt, hostileResult, hostileReport and victimReady
// mirror testdata/hostile's types: the plan the test writes into a task and
// what the stand-in harness reports back.
type hostilePlan struct {
	Role        string           `json:"role"`
	Tag         string           `json:"tag"`
	HubURL      string           `json:"hub_url,omitempty"`
	HoldSeconds int              `json:"hold_seconds,omitempty"`
	Attempts    []hostileAttempt `json:"attempts,omitempty"`
}

type hostileAttempt struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Dest   string `json:"dest,omitempty"`
	Target string `json:"target,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Auth   string `json:"auth,omitempty"`
	Body   string `json:"body,omitempty"`
}

type hostileResult struct {
	Name    string   `json:"name"`
	OK      bool     `json:"ok"`
	Status  int      `json:"status,omitempty"`
	Detail  string   `json:"detail,omitempty"`
	Digest  string   `json:"digest,omitempty"`
	Entries []string `json:"entries,omitempty"`
}

type hostileReport struct {
	Role        string          `json:"role"`
	Tag         string          `json:"tag"`
	UID         int             `json:"uid"`
	Cwd         string          `json:"cwd"`
	Results     []hostileResult `json:"results"`
	ReadOnly    string          `json:"read_only"`
	Credentials []string        `json:"credentials"`
	Error       string          `json:"error"`
}

type victimReady struct {
	Tag    string   `json:"tag"`
	PID    int      `json:"pid"`
	Port   int      `json:"port"`
	Socket string   `json:"socket"`
	Addrs  []string `json:"addrs"`
	UID    int      `json:"uid"`
}

// verdict is what a probe must find.
type verdict struct {
	// reached: the probe must succeed; otherwise it must be refused.
	reached bool
	// status is the exact HTTP status an http probe must get.
	status int
	// digest, when set, is what a read that reached must have read.
	digest string
	// limit names the documented limit a probe that reaches is evidence
	// of; empty for a guarantee.
	limit string
	// forbid is the digest of content a read must never return: a file a
	// sandbox hides may be refused, or covered by an empty one, as a
	// container covers it, but never read.
	forbid string
}

// probe is one attempt with the verdict the platform promises for it.
type probe struct {
	hostileAttempt
	want verdict
}

// platform is what the executor under test promises.
type platform struct {
	// hostProcess: the run is a process on the hub's host or a device's,
	// in the host sandbox, rather than in a container.
	hostProcess bool
	// namespaces: the host sandbox adds mount, PID and IPC namespaces,
	// which it does when the hub or the agent runs as root.
	namespaces bool
	// signalsScoped: Landlock ABI 6 or later, under which the sandbox stops
	// a run signalling a process outside it.
	signalsScoped bool
}

func (s *scene) platform() platform {
	abi, _ := hostsandbox.ABI()
	return platform{hostProcess: s.kind != inContainer, namespaces: os.Geteuid() == 0, signalsScoped: abi >= 6}
}

// phase is one round of attacks.
type phase struct {
	name string
	// listed: vault's readers list names mallory.
	listed bool
	// live is vault's run, held open while it is attacked; nil when none.
	live *victimLive
}

// victimLive is vault's run, open while mallory attacks it.
type victimLive struct {
	task  int
	ready victimReady
	// pid is the victim harness's process as this machine sees it.
	pid int
}

const (
	vaultSlug   = "vault"
	librarySlug = "library"
)

// egressSession, as an attempt's Auth, has the hostile run send the egress
// session's credential, which it holds in its proxy URL (testdata/hostile).
const egressSession = "@egress-session"

// attackProbes is everything mallory's run tries in a phase, each with the
// verdict the executor promises.
func (s *scene) attackProbes(ph phase, pf platform) []probe {
	var ps []probe
	add := func(want verdict, a hostileAttempt) { ps = append(ps, probe{hostileAttempt: a, want: want}) }
	deny := verdict{}
	reach := func(digest string) verdict { return verdict{reached: true, digest: digest} }
	status := func(code int) verdict { return verdict{reached: code >= 200 && code < 300, status: code} }
	// What the host sandbox does not cover, where it is the boundary: a
	// file's mode without namespaces, and signals before Landlock ABI 6.
	chmodVerdict, signalVerdict := deny, deny
	if pf.hostProcess && !pf.namespaces {
		chmodVerdict = verdict{reached: true, limit: "without namespaces Landlock does not cover a file's mode"}
		if !pf.signalsScoped {
			signalVerdict = verdict{reached: true, limit: "before Landlock ABI 6 a run may signal its user's processes"}
		}
	}
	vaultSource := digestOf("package vault\n\n// " + s.canary + "\nconst Secret = \"" + s.canary + "\"\n")
	vaultEnv := verdict{forbid: digestOf(s.vaultEnv + "\n")}
	libraryEnv := verdict{forbid: digestOf(s.libraryEnv + "\n")}
	tag := ph.name

	// Controls: its own tree is its to write and read.
	add(reach(""), hostileAttempt{Name: "own: write a file in its own tree", Kind: "create",
		Path: "@own/.cloop/hostile/" + tag + "-own.txt"})
	add(reach(digestOf("# mallory\n")), hostileAttempt{Name: "own: read its own README", Kind: "read",
		Path: "@own/README.md"})

	// vault's tree, everywhere a copy of it is on this machine.
	for i, tree := range s.trees(s.vault) {
		where := "vault on the hub"
		if i > 0 {
			where = "vault on the device"
		}
		// Only on the hub's own host does a listed project's tree reach the
		// run where it is, read-only.
		inPlace := s.kind == onHost && i == 0 && ph.listed
		read := deny
		if inPlace {
			read = reach(vaultSource)
		}
		list := deny
		if inPlace {
			list = reach("")
		}
		p := func(rel string) string { return filepath.Join(tree, filepath.FromSlash(rel)) }
		add(read, hostileAttempt{Name: where + ": read a source file", Kind: "read", Path: p("src/vault.go")})
		add(list, hostileAttempt{Name: where + ": list its tree", Kind: "list", Path: tree})
		add(deny, hostileAttempt{Name: where + ": plant a file", Kind: "create", Path: p("planted.txt")})
		add(deny, hostileAttempt{Name: where + ": overwrite a source file", Kind: "overwrite", Path: p("src/vault.go")})
		add(deny, hostileAttempt{Name: where + ": append to its README", Kind: "append", Path: p("README.md")})
		add(deny, hostileAttempt{Name: where + ": delete a file", Kind: "remove", Path: p("src/remove-me.txt")})
		add(deny, hostileAttempt{Name: where + ": move a file out", Kind: "rename", Path: p("src/remove-me.txt")})
		add(deny, hostileAttempt{Name: where + ": make a directory", Kind: "mkdir", Path: p("planted-dir")})
		add(chmodVerdict, hostileAttempt{Name: where + ": change a file's mode", Kind: "chmod-same", Path: p("src/vault.go")})
		add(read, hostileAttempt{Name: where + ": read a source file through a link", Kind: "symlink-read",
			Path: p("src/vault.go")})
		add(deny, hostileAttempt{Name: where + ": hard-link a source file into its own tree", Kind: "hardlink",
			Path: p("src/vault.go")})
		add(deny, hostileAttempt{Name: where + ": plant a git hook", Kind: "create", Path: p(".git/hooks/post-checkout")})
		add(vaultEnv, hostileAttempt{Name: where + ": read its .env", Kind: "read", Path: p(".env")})
		add(deny, hostileAttempt{Name: where + ": read its git configuration", Kind: "read", Path: p(".git/config")})
		add(deny, hostileAttempt{Name: where + ": read its state database", Kind: "read", Path: p(".cloop/state.db")})
		add(deny, hostileAttempt{Name: where + ": open its state database for writing", Kind: "open-write",
			Path: p(".cloop/state.db")})
		add(deny, hostileAttempt{Name: where + ": delete its state database", Kind: "remove", Path: p(".cloop/state.db")})
		add(deny, hostileAttempt{Name: where + ": read the canary in its .cloop", Kind: "read",
			Path: p(".cloop/victim-canary.txt")})
	}

	// The hub's control plane, and the hub's process.
	hub := func(rel string) string { return filepath.Join(s.hubDir, filepath.FromSlash(rel)) }
	registry := filepath.Join(s.home, ".cloop", "projects.json")
	add(deny, hostileAttempt{Name: "hub: read its database", Kind: "read", Path: hub(".cloop/state.db")})
	add(deny, hostileAttempt{Name: "hub: open its database for writing", Kind: "open-write", Path: hub(".cloop/state.db")})
	add(deny, hostileAttempt{Name: "hub: read its configuration", Kind: "read", Path: hub(".cloop/config.yaml")})
	add(deny, hostileAttempt{Name: "hub: list its directory", Kind: "list", Path: s.hubDir})
	add(deny, hostileAttempt{Name: "hub: read its project registry", Kind: "read", Path: registry})
	add(deny, hostileAttempt{Name: "hub: open its project registry for writing", Kind: "open-write", Path: registry})
	add(deny, hostileAttempt{Name: "hub: read its process's environment", Kind: "proc", PID: s.hub.Process.Pid,
		Target: "environ"})
	add(signalVerdict, hostileAttempt{Name: "hub: signal its process", Kind: "signal", PID: s.hub.Process.Pid})
	add(deny, hostileAttempt{Name: "env: the hub's root key", Kind: "env", Target: "CLOOP_SECRET_KEY"})
	add(deny, hostileAttempt{Name: "env: the hub's static token", Kind: "env", Target: "CLOOP_UI_TOKEN"})

	// library lists mallory: its run reads it, read-only, where its executor
	// put it, and none of what is kept out.
	lib := func(rel string) string { return "@ro:" + s.library + "//" + rel }
	add(reach(digestOf("# library\n\n"+s.libraryCanary+"\n")), hostileAttempt{Name: "library: read it",
		Kind: "read", Path: lib("README.md")})
	add(deny, hostileAttempt{Name: "library: plant a file", Kind: "create", Path: lib("planted.txt")})
	add(deny, hostileAttempt{Name: "library: overwrite its README", Kind: "overwrite", Path: lib("README.md")})
	add(libraryEnv, hostileAttempt{Name: "library: read its .env", Kind: "read", Path: lib(".env")})
	add(deny, hostileAttempt{Name: "library: read its state database", Kind: "read", Path: lib(".cloop/state.db")})

	// vault where its executor would put it for a run its list names.
	ro := func(rel string) string { return "@ro:" + s.vault + "//" + rel }
	given := deny
	if ph.listed {
		given = reach(vaultSource)
	}
	nested := deny
	if ph.listed {
		nested = reach(digestOf("nested\n"))
	}
	add(given, hostileAttempt{Name: "vault read-only: read a source file", Kind: "read", Path: ro("src/vault.go")})
	add(nested, hostileAttempt{Name: "vault read-only: read a nested file", Kind: "read", Path: ro("services/notes.txt")})
	add(deny, hostileAttempt{Name: "vault read-only: plant a file", Kind: "create", Path: ro("planted.txt")})
	add(deny, hostileAttempt{Name: "vault read-only: overwrite a source file", Kind: "overwrite", Path: ro("src/vault.go")})
	add(deny, hostileAttempt{Name: "vault read-only: delete a file", Kind: "remove", Path: ro("src/remove-me.txt")})
	add(vaultEnv, hostileAttempt{Name: "vault read-only: read its .env", Kind: "read", Path: ro(".env")})
	add(deny, hostileAttempt{Name: "vault read-only: read its state database", Kind: "read", Path: ro(".cloop/state.db")})
	add(deny, hostileAttempt{Name: "vault read-only: read its git configuration", Kind: "read", Path: ro(".git/config")})
	add(deny, hostileAttempt{Name: "vault read-only: read the canary in its .cloop", Kind: "read",
		Path: ro(".cloop/victim-canary.txt")})

	// The hub's run routes, with the run's own session, naming vault.
	const session = "CLOOP_READERS_TOKEN"
	body := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	readCode := http.StatusNotFound
	if ph.listed {
		readCode = http.StatusOK
	}
	add(status(readCode), hostileAttempt{Name: "run API: search naming vault", Kind: "http", Method: "POST",
		URL: "{readers}/search", Auth: session, Body: body(map[string]any{"query": "vault secret", "project": s.vault})})
	add(status(http.StatusOK), hostileAttempt{Name: "run API: search naming library", Kind: "http", Method: "POST",
		URL: "{readers}/search", Auth: session, Body: body(map[string]any{"query": "library", "project": s.library})})
	add(status(http.StatusNotFound), hostileAttempt{Name: "run API: search naming the hub's own directory",
		Kind: "http", Method: "POST", URL: "{readers}/search", Auth: session,
		Body: body(map[string]any{"query": "secret", "project": s.hubDir})})
	add(status(readCode), hostileAttempt{Name: "run API: a snapshot of vault", Kind: "http", Method: "POST",
		URL: "{readers}/readonly/snapshot", Auth: session, Body: body(map[string]any{"slug": vaultSlug})})
	add(status(http.StatusOK), hostileAttempt{Name: "run API: a snapshot of library", Kind: "http", Method: "POST",
		URL: "{readers}/readonly/snapshot", Auth: session, Body: body(map[string]any{"slug": librarySlug})})
	add(status(http.StatusOK), hostileAttempt{Name: "run API: which projects it may read", Kind: "http",
		Method: "POST", URL: "{readers}/readonly", Auth: session, Body: "{}"})
	add(verdict{}, hostileAttempt{Name: "run API: citations for vault", Kind: "http", Method: "POST",
		URL: "{readers}/citations", Auth: session, Body: body(map[string]any{"task": 1, "project": s.vault})})

	// The dashboard's routes on vault, with the run's session and with no
	// credential. A run's credential is refused before the hub counts a
	// failed sign-in; a request with none is a failed sign-in, and the hub
	// locks an address out for a minute after five of them — this test's own
	// address too. So four go without a credential, in the first phase only.
	vi := s.idx(s.vault)
	dashboard := []struct {
		hostileAttempt
		bare bool
	}{
		{hostileAttempt{Name: "list the hub's projects", Method: "GET", URL: "{hub}/api/projects"}, true},
		{hostileAttempt{Name: "read vault's state", Method: "GET",
			URL: fmt.Sprintf("{hub}/api/state?project_idx=%d", vi)}, true},
		{hostileAttempt{Name: "add a task to vault", Method: "POST", URL: fmt.Sprintf("{hub}/api/tasks?project_idx=%d", vi),
			Body: body(map[string]any{"title": "planted by mallory", "description": "run anything"})}, true},
		{hostileAttempt{Name: "delete vault's task", Method: "DELETE",
			URL: fmt.Sprintf("{hub}/api/tasks/1?project_idx=%d", vi)}, false},
		{hostileAttempt{Name: "put mallory on vault's readers list", Method: "PUT",
			URL:  fmt.Sprintf("{hub}/api/projects/%d/readers", vi),
			Body: body(map[string]any{"reader": s.mallory})}, true},
		{hostileAttempt{Name: "start vault's run", Method: "POST", URL: fmt.Sprintf("{hub}/api/projects/%d/run", vi),
			Body: "{}"}, false},
	}
	for _, d := range dashboard {
		withSession := d.hostileAttempt
		withSession.Kind, withSession.Auth = "http", session
		withSession.Name = "dashboard with its session: " + d.Name
		add(status(http.StatusForbidden), withSession)
		if d.bare && ph.live != nil {
			bare := d.hostileAttempt
			bare.Kind, bare.Name = "http", "dashboard with no credential: "+d.Name
			add(status(http.StatusUnauthorized), bare)
		}
	}

	// The proxies, with the sessions the hub gave the run: the git proxy
	// asked for vault's repository, the egress proxy for a tunnel to vault's
	// run or to the hub, and the egress session presented to the dashboard.
	if s.github != nil {
		add(reach(""), hostileAttempt{Name: "git proxy: list its own repository's branches", Kind: "git",
			Target: "ls-remote https://github.com/acme/mallory"})
		add(deny, hostileAttempt{Name: "git proxy: list vault's repository's branches", Kind: "git",
			Target: "ls-remote https://github.com/acme/vault"})
		add(deny, hostileAttempt{Name: "git proxy: push to vault's repository", Kind: "git",
			Target: "push https://github.com/acme/vault HEAD:refs/heads/planted-by-mallory"})
	}
	hubAddr := "127.0.0.1:" + strconv.Itoa(s.port)
	if !pf.hostProcess {
		hubAddr = strings.TrimPrefix(s.runBase, "http://")
	}
	add(deny, hostileAttempt{Name: "egress proxy: a tunnel to the hub's dashboard", Kind: "connect", Target: hubAddr})
	add(status(http.StatusForbidden), hostileAttempt{Name: "dashboard with its egress session: read vault's state",
		Kind: "http", Method: "GET", URL: fmt.Sprintf("{hub}/api/state?project_idx=%d", vi), Auth: egressSession})

	// vault's live run.
	if live := ph.live; live != nil {
		tcp, unix := verdict{}, verdict{}
		target := ""
		if pf.hostProcess {
			// The host sandbox gives a run no network of its own, and a Unix
			// socket is not a file Landlock opens.
			tcp = verdict{reached: true, limit: "the host sandbox shares the host's network"}
			unix = verdict{reached: true, limit: "the host sandbox does not stop a connect to a Unix socket"}
			target = "127.0.0.1:" + strconv.Itoa(live.ready.Port)
		} else if len(live.ready.Addrs) > 0 {
			target = live.ready.Addrs[0] + ":" + strconv.Itoa(live.ready.Port)
		}
		add(tcp, hostileAttempt{Name: "vault's run: connect to its listener", Kind: "tcp", Target: target})
		socket := live.ready.Socket
		if !pf.hostProcess {
			// The victim's socket is in its /workspace, which is vault's
			// directory on the hub's host.
			socket = filepath.Join(s.vault, ".hv.sock")
		}
		add(unix, hostileAttempt{Name: "vault's run: connect to the Unix socket in its tree", Kind: "unix", Path: socket})
		viaProxy := target
		if pf.hostProcess {
			viaProxy = "127.0.0.1:" + strconv.Itoa(live.ready.Port)
		}
		add(deny, hostileAttempt{Name: "egress proxy: a tunnel to vault's run", Kind: "connect", Target: viaProxy})
		add(signalVerdict, hostileAttempt{Name: "vault's run: signal its harness", Kind: "signal", PID: live.pid})
		add(deny, hostileAttempt{Name: "vault's run: read its harness's environment", Kind: "proc", PID: live.pid,
			Target: "environ"})
	}
	return ps
}

// checkReport holds every probe's result to its verdict, and the report's
// account of what the run was given to what the phase gives it.
func (s *scene) checkReport(ph phase, probes []probe, rep hostileReport) {
	t := s.t
	t.Helper()
	if rep.Error != "" {
		t.Errorf("%s: the hostile run reports: %s", ph.name, rep.Error)
	}
	got := map[string]hostileResult{}
	for _, r := range rep.Results {
		got[r.Name] = r
	}
	var limits []string
	for _, p := range probes {
		r, ok := got[p.Name]
		if !ok {
			t.Errorf("%s: the hostile run did not report %q", ph.name, p.Name)
			continue
		}
		if msg := judge(p, r); msg != "" {
			t.Errorf("%s: %s: %s", ph.name, p.Name, msg)
			continue
		}
		if p.want.limit != "" {
			limits = append(limits, fmt.Sprintf("%s (%s)", p.Name, p.want.limit))
		}
	}
	if len(limits) > 0 {
		sort.Strings(limits)
		t.Logf("%s: reached, as docs/security/model.md says it can:\n  %s", ph.name, strings.Join(limits, "\n  "))
	}

	// What the run says it was given.
	if !contains(rep.Credentials, "CLOOP_READERS_TOKEN") {
		t.Errorf("%s: the run holds no session (it holds %v), so the run API probes prove nothing", ph.name,
			rep.Credentials)
	}
	if !contains(rep.Credentials, egressSession) {
		t.Errorf("%s: the run holds no egress session (it holds %v), so the egress probes prove nothing", ph.name,
			rep.Credentials)
	}
	for _, c := range []string{"CLOOP_SECRET_KEY", "CLOOP_UI_TOKEN", "CLOOP_API_TOKEN"} {
		if contains(rep.Credentials, c) {
			t.Errorf("%s: the run holds the hub's %s", ph.name, c)
		}
	}
	var manifest []struct {
		Slug    string `json:"slug"`
		Project string `json:"project"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal([]byte(rep.ReadOnly), &manifest); err != nil {
		t.Errorf("%s: the run was told of no read-only projects (%q): %v", ph.name, rep.ReadOnly, err)
	}
	given := map[string]string{}
	for _, m := range manifest {
		given[m.Project] = m.Slug
	}
	if given[s.library] != librarySlug {
		t.Errorf("%s: library, whose list names mallory, was given to the run as %q, want %q (manifest %s)", ph.name,
			given[s.library], librarySlug, rep.ReadOnly)
	}
	switch slug, ok := given[s.vault]; {
	case ph.listed && slug != vaultSlug:
		t.Errorf("%s: vault, whose list names mallory, was given to the run as %q, want %q (manifest %s)", ph.name,
			slug, vaultSlug, rep.ReadOnly)
	case !ph.listed && ok:
		t.Errorf("%s: vault, whose list does not name mallory, was given to the run (manifest %s)", ph.name, rep.ReadOnly)
	}
	if r := got["run API: which projects it may read"]; r.Status == http.StatusOK {
		var answer struct {
			Projects []struct {
				Project  string `json:"project"`
				Readable bool   `json:"readable"`
			} `json:"projects"`
		}
		_ = json.Unmarshal([]byte(r.Detail), &answer)
		readable := map[string]bool{}
		for _, p := range answer.Projects {
			readable[p.Project] = p.Readable
		}
		if !readable[s.library] || readable[s.vault] != ph.listed {
			t.Errorf("%s: the hub told the run it may read %v; want library, and vault only when listed", ph.name,
				answer.Projects)
		}
	}
}

// judge says how a result breaks its probe's verdict, or "".
func judge(p probe, r hostileResult) string {
	w := p.want
	if p.Kind == "http" || p.Kind == "connect" {
		switch {
		case r.Status == 0:
			return "the request did not reach the hub or its proxy, so it proves nothing: " + r.Detail
		case w.status != 0 && r.Status != w.status:
			return fmt.Sprintf("HTTP %d, want %d: %s", r.Status, w.status, r.Detail)
		case w.status == 0 && r.OK:
			return fmt.Sprintf("HTTP %d, want a refusal: %s", r.Status, r.Detail)
		}
		return ""
	}
	switch {
	case w.forbid != "" && r.OK && r.Digest == w.forbid:
		return "READ what it must never read: " + r.Detail
	case w.forbid != "":
		// Refused, or covered by something else: either keeps it.
		return ""
	case w.reached && !r.OK && w.limit != "":
		return "was refused, but docs/security/model.md lists it as a limit (" + w.limit + "): update the " +
			"limit and this verdict together: " + r.Detail
	case w.reached && !r.OK:
		return "was refused, and it must reach: " + r.Detail
	case !w.reached && r.OK:
		return "REACHED: " + r.Detail
	case w.reached && w.digest != "" && r.Digest != w.digest:
		return fmt.Sprintf("read something else (%s): digest %s, want %s", r.Detail, r.Digest, w.digest)
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// openVictim starts vault's run, held open by its harness, and waits until
// it listens.
func (s *scene) openVictim(tag string) *victimLive {
	t := s.t
	t.Helper()
	plan := hostilePlan{Role: "victim", Tag: tag, HoldSeconds: 600}
	id := s.addTask(s.vault, "Hold the vault open [iso:"+tag+"]", encodePlan(t, plan))
	s.run(s.vault)
	readyPath := filepath.Join(s.runTree(s.vault), ".cloop", "hostile-victim", "ready.json")
	var r victimReady
	started := time.Now()
	s.waitFor("vault's run to open", 4*time.Minute, func() bool {
		data, err := os.ReadFile(readyPath)
		if err != nil || json.Unmarshal(data, &r) != nil || r.Tag != tag {
			if tk := s.taskByID(s.vault, id); tk.Status == "failed" || tk.Status == "done" {
				t.Fatalf("vault's run ended %s before it opened: %s", tk.Status, tk.Result)
			}
			if time.Since(started) > 10*time.Second && !s.running(s.vault) {
				t.Fatalf("vault's run ended before its harness opened; the hub log says why")
			}
			return false
		}
		return true
	})
	live := &victimLive{task: id, ready: r, pid: s.harnessPID(s.runTree(s.vault))}
	if live.pid == 0 {
		t.Fatalf("no process of vault's harness is running in %s", s.runTree(s.vault))
	}
	// The listener is up: the attacker's refusal is the boundary's.
	addr := "127.0.0.1"
	if !s.platform().hostProcess && len(r.Addrs) > 0 {
		addr = r.Addrs[0]
	}
	if !dialable(addr + ":" + strconv.Itoa(r.Port)) {
		t.Fatalf("vault's run listens on port %d, and this machine cannot reach it at %s", r.Port, addr)
	}
	return live
}

// releaseVictim lets vault's run finish, and waits for it.
func (s *scene) releaseVictim(live *victimLive) {
	t := s.t
	t.Helper()
	writeFile(t, filepath.Join(s.runTree(s.vault), ".cloop", "hostile-victim", "release"), "go\n")
	s.waitDone(s.vault, live.task, 3*time.Minute)
}

// attack runs one phase of mallory's attacks and checks what they found.
func (s *scene) attack(ph phase) {
	s.t.Helper()
	rep, probes := s.attackWith(ph, s.attackProbes(ph, s.platform()))
	s.checkReport(ph, probes, rep)
}

// attackWith runs mallory's run with probes and returns its report, having
// checked that the run reported from its own tree on the executor under
// test.
func (s *scene) attackWith(ph phase, probes []probe) (hostileReport, []probe) {
	t := s.t
	t.Helper()
	plan := hostilePlan{Role: "attacker", Tag: ph.name, HubURL: s.runBase}
	for _, p := range probes {
		plan.Attempts = append(plan.Attempts, p.hostileAttempt)
	}
	id := s.addTask(s.mallory, "Do mallory's work [iso:"+ph.name+"]", encodePlan(t, plan))
	s.run(s.mallory)
	s.waitDone(s.mallory, id, 5*time.Minute)
	// A device's run brings its attachments back with its outcome, and the
	// hub can show the task done a moment before it has stored them.
	var data []byte
	deadline := time.Now().Add(90 * time.Second)
	for data == nil && time.Now().Before(deadline) {
		if data = s.attachment(s.mallory, id, "hostile-report.json"); data == nil {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if data == nil {
		// Where the run left it, for the failure message.
		data, _ = os.ReadFile(filepath.Join(s.runTree(s.mallory), ".cloop", "hostile", ph.name+".json"))
		t.Fatalf("%s: mallory's task %d has no hostile-report.json attachment; the run's own copy: %s", ph.name, id,
			tail(string(data), 4000))
	}
	var rep hostileReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("%s: the report: %v\n%s", ph.name, err, tail(string(data), 4000))
	}
	if rep.Tag != ph.name {
		t.Fatalf("%s: the report is for %q", ph.name, rep.Tag)
	}
	// Where the attacks came from: mallory's own tree, on the executor under
	// test — its directory on the hub's host, its working copy on the
	// device, /workspace in a container.
	where := s.runTree(s.mallory)
	if s.kind == inContainer {
		where = "/workspace"
	}
	if rep.Cwd != where {
		t.Errorf("%s: the hostile run worked in %s, want %s", ph.name, rep.Cwd, where)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s: the hostile run's report:\n%s", ph.name, tail(string(data), 30000))
		}
	})
	return rep, probes
}

// controlProbes are what any run that is not kept to its project reaches on
// this machine. Run once mallory is opted out of the host sandbox, they show
// that the refusals of the phases before were the sandbox's, and that the
// operator's opt-out lets a project's runs out of it. None of them changes
// anything: an open for writing writes nothing.
func (s *scene) controlProbes() []probe {
	var ps []probe
	reach := func(digest string) verdict { return verdict{reached: true, digest: digest} }
	vaultSource := digestOf("package vault\n\n// " + s.canary + "\nconst Secret = \"" + s.canary + "\"\n")
	for i, tree := range s.trees(s.vault) {
		where := "vault on the hub"
		if i > 0 {
			where = "vault on the device"
		}
		p := func(rel string) string { return filepath.Join(tree, filepath.FromSlash(rel)) }
		ps = append(ps,
			probe{hostileAttempt{Name: where + ": read a source file", Kind: "read", Path: p("src/vault.go")}, reach(vaultSource)},
			probe{hostileAttempt{Name: where + ": list its tree", Kind: "list", Path: tree}, reach("")},
			probe{hostileAttempt{Name: where + ": read its .env", Kind: "read", Path: p(".env")}, reach(digestOf(s.vaultEnv + "\n"))},
			probe{hostileAttempt{Name: where + ": read its state database", Kind: "read", Path: p(".cloop/state.db")}, reach("")},
			probe{hostileAttempt{Name: where + ": open its state database for writing", Kind: "open-write",
				Path: p(".cloop/state.db")}, reach("")},
		)
	}
	ps = append(ps,
		probe{hostileAttempt{Name: "hub: read its database", Kind: "read", Path: filepath.Join(s.hubDir, ".cloop", "state.db")},
			reach("")},
		probe{hostileAttempt{Name: "hub: read its project registry", Kind: "read",
			Path: filepath.Join(s.home, ".cloop", "projects.json")}, reach("")},
	)
	return ps
}

// attackOptedOut is the control: the operator lists mallory in
// executors.host_sandbox.opt_out, and the same probes reach vault and the
// hub's control plane.
func (s *scene) attackOptedOut() {
	t := s.t
	t.Helper()
	s.writeHubConfig(s.mallory)
	ph := phase{name: "opted-out"}
	rep, probes := s.attackWith(ph, s.controlProbes())
	got := map[string]hostileResult{}
	for _, r := range rep.Results {
		got[r.Name] = r
	}
	for _, p := range probes {
		if msg := judge(p, got[p.Name]); msg != "" {
			t.Errorf("%s: %s: %s — so the refusals before prove nothing about the sandbox", ph.name, p.Name, msg)
		}
	}
}

// harnessPID finds the stand-in harness working in dir, as this machine
// numbers it.
func (s *scene) harnessPID(dir string) int {
	if s.kind == inContainer {
		out, err := execOutput("docker", "ps", "-q", "--filter", "label=cloop.project="+s.vault)
		if err != nil {
			return 0
		}
		for _, id := range strings.Fields(out) {
			pid, _ := execOutput("docker", "inspect", "-f", "{{.State.Pid}}", id)
			if n, err := strconv.Atoi(strings.TrimSpace(pid)); err == nil && n > 0 {
				return n
			}
		}
		return 0
	}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil || filepath.Base(exe) != "claude" {
			continue
		}
		if cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd")); err == nil && cwd == dir {
			return pid
		}
	}
	return 0
}
