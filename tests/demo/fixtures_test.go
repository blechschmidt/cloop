package demo_test

// The documentation site's dashboard demo answers every read the dashboard can
// make, and gives away nothing of the machine it was recorded on (Task 20506).
//
// The demo at /demo/ is the real dashboard running against canned answers:
// website/demo/shim.js stands in for the hub and answers each GET from
// website/demo/fixtures, which scripts/demo/record-fixtures.sh records from a
// throwaway hub. Two things can go wrong with that, and neither shows up
// anywhere else:
//
//   - The dashboard grows a read the fixtures do not answer. The shim then
//     answers {} and the panel draws as empty — in the one place a reader
//     forms an impression of the product, and silently. So every GET route in
//     the hub's route table that the dashboard's assets name must be answered
//     by at least one fixture, or be on demoNeedsNoFixture with its reason.
//   - A recording carries something of the machine it was made on: a
//     credential, a path under /root or /tmp, the recording host's name or
//     address. The fixtures are published on a public site, so each one is
//     scanned with pkg/redact's credential registry and for those paths and
//     hosts.
//
// When the first test fails after a dashboard change, re-record the fixtures
// (scripts/demo/README.md) or add one for the new route by hand
// (website/demo/README.md describes the format).

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// fixturesDir and assetsDir are relative to the repository root.
const (
	fixturesDir = "website/demo/fixtures"
	assetsDir   = "pkg/ui/assets"
)

// demoNeedsNoFixture lists the dashboard's GET routes the demo answers without
// a fixture, each with the reason. An entry that stops being a dashboard GET
// route fails the test as stale.
var demoNeedsNoFixture = map[string]string{
	"/api/events": "the event stream is the dashboard's fallback when a WebSocket cannot be opened; " +
		"the shim's WebSocket always opens, and its EventSource stays quiet",
	"/auth/login":    "a page, not a read: the shim turns every link to a sign-in page into its read-only notice",
	"/auth/callback": "the identity provider's redirect target, which the demo never signs in through",
	"/auth/renew":    "loaded in a hidden frame by silent sign-in renewal, which the shim points at about:blank",
	"/api/tasks/{id}/attach": "a live terminal into a running task's sandbox; a recording has no sandbox to " +
		"attach to, and the shim's socket stays quiet",
	"/api/projects/{idx}/repositories/available": "asks GitHub which repositories a GitHub App installation " +
		"can see; the recording's App is made up and has no installation to ask",
	"/api/projects/{idx}/move/{id}": "one move's progress and result; the recording moves no project between " +
		"executors (its preflight is recorded)",
}

// fixture is one entry of a fixture file, as website/demo/README.md describes
// it. Only the request line matters to the coverage test; the leak scan reads
// the whole file.
type fixture struct {
	Request string `json:"request"`
}

// fixturesEnv names another directory of fixtures to judge instead of the
// tree's: scripts/demo/record-fixtures.sh checks a recording with it before
// anything is written into website/demo.
const fixturesEnv = "CLOOP_DEMO_FIXTURES"

// loadFixtures reads every fixture under fixturesDir: file (relative to the
// repository root) -> its parsed JSON and its request lines.
func loadFixtures(t *testing.T, root string) (docs map[string]any, requests map[string][]string) {
	t.Helper()
	docs, requests = map[string]any{}, map[string][]string{}
	dir := filepath.Join(root, fixturesDir)
	if alt := os.Getenv(fixturesEnv); alt != "" {
		dir, root = alt, alt
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		docs[rel] = doc
		var list []fixture
		if err := json.Unmarshal(raw, &list); err != nil {
			var one fixture
			if err := json.Unmarshal(raw, &one); err != nil {
				return fmt.Errorf("%s: neither a fixture nor a list of them: %w", rel, err)
			}
			list = []fixture{one}
		}
		for _, fx := range list {
			requests[rel] = append(requests[rel], fx.Request)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading %s: %v", fixturesDir, err)
	}
	if len(docs) == 0 {
		t.Fatalf("no fixtures under %s — the test would pass vacuously", fixturesDir)
	}
	return docs, requests
}

// pageAsset is an asset index.html names by token, {{asset:theme.js}}.
var pageAsset = regexp.MustCompile(`\{\{asset:([^}]+)\}\}`)

// dashboardSource is the dashboard as the demo carries it: index.html, the
// bundle's fragments (assets/js/*.js), the deferred panels
// (assets/js/deferred) and the page scripts index.html itself names. Not the
// display-glasses or device pages, whose own scripts sit in assets/js/page
// beside the dashboard's and which the demo does not carry.
func dashboardSource(t *testing.T, root string) string {
	t.Helper()
	assets := filepath.Join(root, assetsDir)
	index, err := os.ReadFile(filepath.Join(assets, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(assets, "index.html")}
	for _, m := range pageAsset.FindAllStringSubmatch(string(index), -1) {
		if p := filepath.Join(assets, "js", "page", m[1]); fileExists(p) {
			files = append(files, p)
		}
	}
	for _, glob := range []string{"js/*.js", "js/deferred/*.js"} {
		m, err := filepath.Glob(filepath.Join(assets, glob))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	var b strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if b.Len() < 100000 {
		t.Fatalf("read only %d bytes of dashboard source under %s — not the dashboard", b.Len(), assetsDir)
	}
	return b.String()
}

var wildcard = regexp.MustCompile(`\{[^}]*\}`)

// referenced reports whether the dashboard's source names the route pattern:
// its path up to the first wildcard, as a whole path when it has none (so
// /api/tasks is not taken for named by /api/tasks/{id}/details), and every
// later literal piece of it. That is how the dashboard builds its URLs:
// `'/api/tasks/' + id + '/details'`, or a template literal over
// `/api/projects/${idx}/readers`.
func referenced(src, pattern string) bool {
	pieces := wildcard.Split(pattern, -1)
	first := regexp.QuoteMeta(pieces[0])
	if len(pieces) == 1 && !strings.HasSuffix(pattern, "/") {
		first += `(?:[^A-Za-z0-9_/-]|$)`
	}
	if !regexp.MustCompile(first).MatchString(src) {
		return false
	}
	for _, p := range pieces[1:] {
		if p != "" && !strings.Contains(src, p) {
			return false
		}
	}
	return true
}

// dashboardReads is every GET route in the hub's route table that the
// dashboard's source names: the reads the demo has to answer.
func dashboardReads(t *testing.T, src string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, r := range ui.APIRoutes() {
		if r.Method != "GET" || !(strings.HasPrefix(r.Path, "/api/") || strings.HasPrefix(r.Path, "/auth/")) {
			continue
		}
		if !seen[r.Path] && referenced(src, r.Path) {
			seen[r.Path] = true
			out = append(out, r.Path)
		}
	}
	sort.Strings(out)
	if len(out) < 50 {
		t.Fatalf("found only %d dashboard reads in the route table — is the reference check broken?", len(out))
	}
	return out
}

// routeRegexp matches the paths a ServeMux pattern serves: a {name} wildcard
// is one segment, {name...} the rest of the path, and a pattern ending in "/"
// everything beneath it.
func routeRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, loc := range wildcard.FindAllStringIndex(pattern, -1) {
		b.WriteString(regexp.QuoteMeta(pattern[last:loc[0]]))
		if strings.HasSuffix(pattern[loc[0]:loc[1]], "...}") {
			b.WriteString(".+")
		} else {
			b.WriteString("[^/]+")
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(pattern[last:]))
	if !strings.HasSuffix(pattern, "/") {
		b.WriteString("$")
	}
	return regexp.MustCompile(b.String())
}

// TestEveryDashboardReadHasAFixture: each GET route the dashboard names is
// answered by a fixture — a GET one, or for the socket route a WS one.
func TestEveryDashboardReadHasAFixture(t *testing.T) {
	root := repoRoot(t)
	_, requests := loadFixtures(t, root)
	reads := dashboardReads(t, dashboardSource(t, root))

	type answered struct{ method, path string }
	var all []answered
	for file, lines := range requests {
		for _, line := range lines {
			method, target, ok := strings.Cut(strings.TrimSpace(line), " ")
			if !ok || (method != "GET" && method != "WS") {
				t.Errorf("%s: request %q is not '<GET|WS> /path[?query]'", file, line)
				continue
			}
			path, _, _ := strings.Cut(target, "?")
			all = append(all, answered{method, path})
		}
	}

	isRead := map[string]bool{}
	var missing []string
	for _, route := range reads {
		isRead[route] = true
		if _, ok := demoNeedsNoFixture[route]; ok {
			continue
		}
		re := routeRegexp(route)
		found := false
		for _, a := range all {
			if re.MatchString(a.path) && (a.method == "GET" || route == "/api/ws") {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, route)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d dashboard read(s) have no fixture in %s, so the demo draws them as empty:\n  %s\n"+
			"Re-record the fixtures (scripts/demo/README.md), add one by hand (website/demo/README.md), or, if the "+
			"demo never needs one, add the route to demoNeedsNoFixture with the reason.",
			len(missing), fixturesDir, strings.Join(missing, "\n  "))
	}
	for route := range demoNeedsNoFixture {
		if !isRead[route] {
			t.Errorf("demoNeedsNoFixture lists %s, which is no longer a GET route the dashboard names — remove it", route)
		}
	}
	t.Logf("%d dashboard reads, %d answered by fixtures, %d need none", len(reads), len(reads)-len(missing)-len(demoNeedsNoFixture), len(demoNeedsNoFixture))
}

// Hosts a fixture may name. Anything else in a URL, an e-mail address or a
// host-named field is taken for a real machine: the demo's invented ones live
// under example.com, and the rest are public services the dashboard's data
// legitimately points at.
var (
	allowedHostSuffixes = []string{
		"example.com", "example.org", "example.net", ".example", ".test", ".invalid",
	}
	allowedHosts = map[string]bool{
		// The forge, its API, its registry and its raw content.
		"github.com": true, "api.github.com": true, "ghcr.io": true, "raw.githubusercontent.com": true,
		"objects.githubusercontent.com": true, "codeload.github.com": true, "docs.github.com": true,
		// cloop's own documentation site.
		"blechschmidt.github.io": true,
		// Claude, which the dashboard's sign-in and limit panels name.
		"claude.ai": true, "claude.com": true, "platform.claude.com": true, "api.anthropic.com": true,
		"console.anthropic.com": true, "docs.anthropic.com": true, "anthropic.com": true, "www.anthropic.com": true,
		// Defaults cloop itself ships: Ollama's address, GitHub Actions' token
		// issuer, the speech-to-text service, and the image-signing docs a
		// hub health remedy links. localhost reveals nothing of a machine;
		// 127.0.0.1 with the recording hub's port is scrubbed all the same.
		"localhost": true, "token.actions.githubusercontent.com": true, "api.groq.com": true,
		"docs.sigstore.dev": true,
		// An SVG's XML namespace, inside a recorded attachment.
		"www.w3.org": true,
		// Package registries an egress allowlist names.
		"proxy.golang.org": true, "sum.golang.org": true, "registry.npmjs.org": true, "pypi.org": true,
		"files.pythonhosted.org": true, "deb.debian.org": true, "archive.ubuntu.com": true,
		"security.ubuntu.com": true, "registry-1.docker.io": true, "auth.docker.io": true,
		"production.cloudflare.docker.com": true,
	}
	// Documentation address ranges (RFC 5737, RFC 3849), the only addresses a
	// URL in a fixture may name.
	documentationNets = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"}

	urlHost     = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@\s"'<>]*@)?(\[[0-9a-fA-F:.]+\]|[^/:\s"'<>?#]+)`)
	emailHost   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b`)
	hostKey     = regexp.MustCompile(`(?i)(^|_)(host|hostname|fqdn|domain)s?$`)
	privatePath = regexp.MustCompile(`(^|[^A-Za-z0-9_.~-])/(root|tmp)(/|$|[^A-Za-z0-9_.-])`)
)

func hostAllowed(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]."))
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range documentationNets {
			if _, n, _ := net.ParseCIDR(cidr); n.Contains(ip) {
				return true
			}
		}
		return false
	}
	if allowedHosts[host] {
		return true
	}
	for _, s := range allowedHostSuffixes {
		if host == strings.TrimPrefix(s, ".") || strings.HasSuffix(host, "."+strings.TrimPrefix(s, ".")) {
			return true
		}
	}
	return false
}

// leaks returns what s gives away: a credential pkg/redact recognises, a path
// under /root or /tmp, a host that is not allowed, or the name of the machine
// the test runs on. key is the name of the field s is the value of, if any.
func leaks(s, key, machine string) []string {
	var out []string
	// A path or host also travels percent-encoded, in a URL's query
	// (?project=%2Ftmp%2F…): judged decoded as well.
	if strings.Contains(s, "%") {
		if dec, err := url.QueryUnescape(s); err == nil && dec != s {
			out = append(out, leaks(dec, key, machine)...)
		}
	}
	for _, m := range redact.Find(s) {
		out = append(out, "a credential ("+m.Detector+")")
	}
	if privatePath.MatchString(s) {
		out = append(out, "a path under /root or /tmp")
	}
	for _, m := range urlHost.FindAllStringSubmatch(s, -1) {
		if u, err := url.Parse("x://" + m[1]); err == nil && !hostAllowed(u.Hostname()) {
			out = append(out, "the host "+u.Hostname())
		}
	}
	for _, m := range emailHost.FindAllStringSubmatch(s, -1) {
		if !hostAllowed(m[1]) {
			out = append(out, "an e-mail address at "+m[1])
		}
	}
	if key != "" && hostKey.MatchString(key) && !strings.ContainsAny(s, " /") && !hostAllowed(s) {
		out = append(out, "the host "+s+" in "+key)
	}
	if machine != "" && regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(machine)+`\b`).MatchString(s) {
		out = append(out, "this machine's name, "+machine)
	}
	return out
}

// walkStrings calls fn for every string in v — keys and values — with the key
// a value sits under, and a JSON pointer to where it is.
func walkStrings(v any, key, at string, fn func(s, key, at string)) {
	switch x := v.(type) {
	case string:
		fn(x, key, at)
	case []any:
		for i, e := range x {
			walkStrings(e, key, fmt.Sprintf("%s/%d", at, i), fn)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fn(k, "", at+"/"+k)
			walkStrings(x[k], k, at+"/"+k, fn)
		}
	}
}

// TestFixturesGiveNothingAway: no fixture holds a credential, a /root or /tmp
// path, or a host that is not an invented or public one.
func TestFixturesGiveNothingAway(t *testing.T) {
	root := repoRoot(t)
	docs, _ := loadFixtures(t, root)
	machine, _ := os.Hostname()
	if strings.Contains(machine, ".") {
		machine, _, _ = strings.Cut(machine, ".")
	}
	if len(machine) < 4 || machine == "localhost" {
		machine = "" // too short to search for without false alarms
	}
	files := make([]string, 0, len(docs))
	for f := range docs {
		files = append(files, f)
	}
	sort.Strings(files)
	var problems []string
	for _, file := range files {
		walkStrings(docs[file], "", "", func(s, key, at string) {
			// A string that is itself JSON (a WebSocket frame) is scanned as a
			// document too, so its fields are judged by their own names.
			if (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Valid([]byte(s)) {
				var inner any
				_ = json.Unmarshal([]byte(s), &inner)
				walkStrings(inner, "", at, func(s2, key2, at2 string) {
					for _, l := range leaks(s2, key2, machine) {
						problems = append(problems, fmt.Sprintf("%s %s: %s", file, at2, l))
					}
				})
				return
			}
			for _, l := range leaks(s, key, machine) {
				problems = append(problems, fmt.Sprintf("%s %s: %s", file, at, l))
			}
		})
	}
	if len(problems) > 0 {
		if len(problems) > 40 {
			problems = append(problems[:40], fmt.Sprintf("… and %d more", len(problems)-40))
		}
		t.Errorf("the demo's fixtures give away what a public page must not:\n  %s\n"+
			"Scrub the recording (scripts/demo/recorder.py) and record again, or fix the fixture.",
			strings.Join(problems, "\n  "))
	}
}

// TestLeakCheckCatchesWhatItShould proves the scan is not blind: each kind of
// leak in a made-up string is reported, and the demo's own names are not.
func TestLeakCheckCatchesWhatItShould(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("Ab3", 12) // a classic PAT's shape, made up
	for _, c := range []struct {
		s, key string
		want   string
	}{
		{"cloned with " + ghp, "", "credential"},
		{"open /tmp/cloop-demo-1234/projects/todo-api/.cloop/state.db", "", "/root or /tmp"},
		{"/root/Projects/cloop", "workdir", "/root or /tmp"},
		{"http://127.0.0.1:41234/api/state", "", "host 127.0.0.1"},
		{"https://hub.corp.internal/auth/login", "", "host hub.corp.internal"},
		{"written by someone@corp.internal", "", "e-mail address"},
		{"build-host-17", "hostname", "host build-host-17"},
		{"ran on openclaw-demo-host", "", "this machine's name"},
		{"https://demo.example.com/?project=%2Ftmp%2Fcloop-demo%2Ftodo-api", "", "/root or /tmp"},
	} {
		got := strings.Join(leaks(c.s, c.key, "openclaw-demo-host"), "; ")
		if !strings.Contains(got, c.want) {
			t.Errorf("leaks(%q, %q) = %q, want it to report %q", c.s, c.key, got, c.want)
		}
	}
	for _, s := range []string{
		"/home/demo/projects/todo-api", "https://demo.example.com/api/state", "dev@demo.example.com",
		"https://github.com/acme/todo-api", "https://blechschmidt.github.io/cloop/docs/", "198.51.100.7",
		"the cloop_sbx_demo table", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	} {
		if got := leaks(s, "", "openclaw-demo-host"); len(got) > 0 {
			t.Errorf("leaks(%q) = %v, want nothing", s, got)
		}
	}
}

// TestReferenceCheck pins the route-reference heuristic the coverage test
// relies on, both ways.
func TestReferenceCheck(t *testing.T) {
	src := "api('/api/tasks/' + id + '/details'); fetch(pUrl('/api/state')); api(`/api/projects/${i}/readers`);"
	for _, c := range []struct {
		pattern string
		want    bool
	}{
		{"/api/tasks/{id}/details", true},
		{"/api/state", true},
		{"/api/projects/{idx}/readers", true},
		{"/api/tasks", false},              // named only as a prefix of a longer path
		{"/api/tasks/{id}/blocker", false}, // its tail is never named
		{"/api/states", false},
	} {
		if got := referenced(src, c.pattern); got != c.want {
			t.Errorf("referenced(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
	re := routeRegexp("/api/tasks/{id}/details")
	if !re.MatchString("/api/tasks/12/details") || re.MatchString("/api/tasks/12/details/x") || re.MatchString("/api/tasks/details") {
		t.Errorf("routeRegexp(/api/tasks/{id}/details) = %s matches the wrong paths", re)
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// repoRoot is the repository's root: two directories above this file.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this file")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}
