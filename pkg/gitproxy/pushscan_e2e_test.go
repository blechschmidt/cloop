package gitproxy_test

// End-to-end tests for the push scan (Task 20436): a real git pushes through
// the proxy to a real git-http-backend, and a push carrying a value the run
// was given — in a file, in a commit message, in an annotated tag, in a thin
// delta against what the forge already has — is refused, updates no ref and
// leaves no object behind on the forge, while a clean push lands with the
// forge receiving exactly the bytes git sent.

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// e2eSecret is the value the run holds. Built at run time, for the reason
// pkg/redact/redacttest builds its fixtures: this repository's own pushes are
// scanned too.
var e2eSecret = "acme-internal-" + strings.Repeat("k9Fq", 4) + "-2026"

func e2eScan(mode gitproxy.ScanMode) gitproxy.PushScanFunc {
	return func(*gitproxy.Session) gitproxy.PushScan {
		return gitproxy.PushScan{Mode: mode, Secrets: []gitproxy.ScanSecret{{
			Value: e2eSecret, Grant: "gr_e2e", Secret: "acme-api", Field: "env ACME_API_KEY",
		}}}
	}
}

// bodyTap records the receive-pack bodies the sandbox sent and the forge
// received.
type bodyTap struct {
	mu     sync.Mutex
	client [][]byte
	forge  [][]byte
}

func (b *bodyTap) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
			next.ServeHTTP(w, r)
			return
		}
		var buf bytes.Buffer
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, &buf), r.Body}
		gz := strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip")
		next.ServeHTTP(w, r)
		got := buf.Bytes()
		if gz {
			// The proxy forwards what it decompressed, so compare that.
			if zr, err := gzip.NewReader(bytes.NewReader(got)); err == nil {
				got, _ = io.ReadAll(zr)
			}
		}
		b.mu.Lock()
		b.client = append(b.client, append([]byte(nil), got...))
		b.mu.Unlock()
	})
}

type tapTransport struct {
	rt  http.RoundTripper
	tap *bodyTap
}

func (t tapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil || !strings.HasSuffix(req.URL.Path, "/git-receive-pack") {
		return t.rt.RoundTrip(req)
	}
	var buf bytes.Buffer
	req.Body = struct {
		io.Reader
		io.Closer
	}{io.TeeReader(req.Body, &buf), req.Body}
	resp, err := t.rt.RoundTrip(req)
	t.tap.mu.Lock()
	t.tap.forge = append(t.tap.forge, append([]byte(nil), buf.Bytes()...))
	t.tap.mu.Unlock()
	return resp, err
}

// withPushScan stands a proxy that scans with scan behind the harness's URL,
// over the harness's registry, tapping both legs of every push.
func (h *harness) withPushScan(t *testing.T, scan gitproxy.PushScanFunc) *bodyTap {
	t.Helper()
	tap := &bodyTap{}
	px, err := gitproxy.New(h.reg, gitproxy.Options{
		Transport: tapTransport{rt: h.forge.Client().Transport, tap: tap},
		PushScan:  scan,
	})
	if err != nil {
		t.Fatalf("gitproxy.New: %v", err)
	}
	h.setHandler(tap.wrap(px))
	return tap
}

// scanPolicy is the write-back policy with tags, so a tag push reaches the
// scan rather than the branch allowlist.
func scanPolicy() gitproxy.Policy {
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	pol.AllowedRefs = append(pol.AllowedRefs, "refs/tags/**")
	return pol
}

// assertRefusedForTheValue checks a push was refused by the scan, said so in
// git's output without the value, moved no ref, recorded why without the
// value, and left the forge without the objects it carried.
func (h *harness) assertRefusedForTheValue(t *testing.T, out string, pushErr error, ref, before string, objects ...string) gitproxy.Event {
	t.Helper()
	t.Logf("git push said:\n%s", out)
	if pushErr == nil {
		t.Fatalf("the push carrying the value succeeded:\n%s", out)
	}
	if !strings.Contains(out, "cloop git proxy refused this push") || !strings.Contains(out, "acme-api") {
		t.Fatalf("git's output does not explain the refusal:\n%s", out)
	}
	if strings.Contains(out, e2eSecret) {
		t.Fatalf("the refusal echoes the value:\n%s", out)
	}
	if sha, ok := h.upstreamSHA(t, ref); (before == "" && ok) || (before != "" && sha != before) {
		t.Fatalf("%s moved upstream to %q (was %q)", ref, sha, before)
	}
	for _, obj := range objects {
		if _, err := h.git(t, "", nil, "--git-dir="+h.bare, "cat-file", "-e", obj); err == nil {
			t.Errorf("the forge holds object %s from the refused push", obj)
		}
	}
	refusals := h.eventsOf(gitproxy.EventPushSecretRefused)
	if len(refusals) != 1 {
		t.Fatalf("got %d push_secret_refused events, want 1:%s", len(refusals), h.eventLog())
	}
	for _, e := range h.eventsOf(gitproxy.EventPushAllowed) {
		if !e.At.Before(refusals[0].At) && strings.Contains(strings.Join(e.Refs, ","), strings.TrimPrefix(ref, "refs/")) &&
			e.Detail == refusals[0].Detail {
			t.Fatalf("a refused push was also recorded as allowed: %s", e.String())
		}
	}
	if n := len(h.eventsOf(gitproxy.EventPushAllowed)); n > h.allowedBefore {
		t.Fatalf("a refused push was also recorded as allowed (%d rows, %d before it)", n, h.allowedBefore)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.events {
		if strings.Contains(e.String(), e2eSecret) || strings.Contains(strings.Join(e.Refs, ","), e2eSecret) {
			t.Fatalf("an event carries the value: %s", e.String())
		}
		for _, f := range e.Findings {
			if strings.Contains(f.Path+f.Tag+f.Ref, e2eSecret) {
				t.Fatalf("a finding carries the value: %+v", f)
			}
		}
	}
	return refusals[0]
}

func TestPushScanRefusesALeasedValueInAFile(t *testing.T) {
	h := newHarness(t)
	h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "deploy.env", "ACME_API_KEY="+e2eSecret+"\n")
	blob := strings.TrimSpace(h.mustGit(t, dir, nil, "rev-parse", "HEAD:deploy.env"))

	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1")
	ev := h.assertRefusedForTheValue(t, out, err, "refs/heads/cloop/task-1", "", sha, blob)
	if len(ev.Findings) == 0 || ev.Findings[0].Object != blob || ev.Findings[0].Path != "deploy.env" ||
		ev.Findings[0].Commit != sha || ev.Findings[0].Grant != "gr_e2e" {
		t.Fatalf("the refusal names %+v, want blob %s at deploy.env in commit %s from grant gr_e2e", ev.Findings, blob, sha)
	}
	if !strings.Contains(out, "deploy.env") {
		t.Errorf("git's output does not name the file:\n%s", out)
	}
}

func TestPushScanRefusesALeasedValueInACommitMessage(t *testing.T) {
	h := newHarness(t)
	h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("nothing secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, dir, nil, "add", "notes.txt")
	h.mustGit(t, dir, nil, append(identity(), "commit", "--no-gpg-sign", "-m", "use key "+e2eSecret+" for staging")...)
	sha := strings.TrimSpace(h.mustGit(t, dir, nil, "rev-parse", "HEAD"))

	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-2")
	ev := h.assertRefusedForTheValue(t, out, err, "refs/heads/cloop/task-2", "", sha)
	if f := ev.Findings[0]; f.Type != "commit" || f.Object != sha || f.Where != "message" {
		t.Fatalf("the refusal names %+v, want commit %s, in its message", f, sha)
	}
}

func TestPushScanRefusesALeasedValueInAnAnnotatedTag(t *testing.T) {
	h := newHarness(t)
	h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	h.mustGit(t, dir, nil, append(identity(), "tag", "-a", "v9.9", "-m", "release, key "+e2eSecret)...)
	tag := strings.TrimSpace(h.mustGit(t, dir, nil, "rev-parse", "v9.9"))

	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "refs/tags/v9.9")
	ev := h.assertRefusedForTheValue(t, out, err, "refs/tags/v9.9", "", tag)
	if f := ev.Findings[0]; f.Type != "tag" || f.Object != tag || f.Tag != "v9.9" {
		t.Fatalf("the refusal names %+v, want tag %s (v9.9)", f, tag)
	}
}

func TestPushScanRefusesAThinDeltaOfAFileTheForgeHas(t *testing.T) {
	h := newHarness(t)
	h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	// A long file the forge has, then one line added to it: git sends the
	// second version as a delta against the first.
	var long strings.Builder
	for i := 0; i < 300; i++ {
		long.WriteString("setting_" + strings.Repeat("x", i%7) + " = value of a long configuration\n")
	}
	first := h.commit(t, dir, "app.conf", long.String())
	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-3")
	if err != nil {
		t.Fatalf("the clean first push failed: %v\n%s", err, out)
	}
	if sha, _ := h.upstreamSHA(t, "refs/heads/cloop/task-3"); sha != first {
		t.Fatalf("the clean push did not land (%q, want %s)", sha, first)
	}
	second := h.commit(t, dir, "app.conf", long.String()+"api_key = "+e2eSecret+"\n")
	h.allowedBefore = len(h.eventsOf(gitproxy.EventPushAllowed))
	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-3")
	h.assertRefusedForTheValue(t, out, err, "refs/heads/cloop/task-3", first, second)
}

func TestPushScanAcceptsACleanPushByteIdentical(t *testing.T) {
	h := newHarness(t)
	tap := h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	h.commit(t, dir, "a.txt", strings.Repeat("all fine here\n", 2000))
	sha := h.commit(t, dir, "b.txt", "the value's grant name acme-api is not the value\n")
	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-4")
	if err != nil {
		t.Fatalf("a clean push was refused: %v\n%s%s", err, out, h.eventLog())
	}
	if got, _ := h.upstreamSHA(t, "refs/heads/cloop/task-4"); got != sha {
		t.Fatalf("upstream is at %q, want %s", got, sha)
	}
	tap.mu.Lock()
	defer tap.mu.Unlock()
	if len(tap.client) != 1 || len(tap.forge) != 1 {
		t.Fatalf("tapped %d client and %d forge bodies, want one each", len(tap.client), len(tap.forge))
	}
	if !bytes.Equal(tap.client[0], tap.forge[0]) {
		t.Fatalf("the forge received %d bytes that differ from the %d git sent", len(tap.forge[0]), len(tap.client[0]))
	}
	allowed := h.eventsOf(gitproxy.EventPushAllowed)
	if len(allowed) != 1 || !strings.Contains(allowed[0].Detail, "found none") {
		t.Fatalf("the allowed row does not record the scan: %+v", allowed)
	}
}

func TestPushScanOffForwardsThePackUnread(t *testing.T) {
	// The control for every refusal above: the same push lands with the scan
	// switched off, so what stopped it was the scan.
	h := newHarness(t)
	h.withPushScan(t, e2eScan(gitproxy.ScanOff))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "deploy.env", "ACME_API_KEY="+e2eSecret+"\n")
	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-5")
	if err != nil {
		t.Fatalf("with the scan off the push was refused: %v\n%s", err, out)
	}
	if got, _ := h.upstreamSHA(t, "refs/heads/cloop/task-5"); got != sha {
		t.Fatalf("upstream is at %q, want %s", got, sha)
	}
}

func TestPushScanMatchesTheSessionsOwnUpstreamToken(t *testing.T) {
	// No hook at all: the proxy still knows one value the run must not
	// publish — the forge token it holds for the session.
	h := newHarness(t)
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "leak.txt", "token="+forgePAT+"\n")
	out, err = h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-6")
	if err == nil || strings.Contains(out, forgePAT) {
		t.Fatalf("the push carrying the forge token: err %v\n%s", err, out)
	}
	if _, ok := h.upstreamSHA(t, "refs/heads/cloop/task-6"); ok {
		t.Fatalf("the ref was created for commit %s", sha)
	}
	if len(h.eventsOf(gitproxy.EventPushSecretRefused)) != 1 {
		t.Fatalf("no push_secret_refused row:%s", h.eventLog())
	}
}

func TestPushScanLetsADeleteThatSendsNoPackThrough(t *testing.T) {
	// git sends no pack at all for a push that only deletes; the scan reads
	// an empty body and lets it through, and the forge deletes the ref.
	h := newHarness(t)
	h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	pol := scanPolicy()
	pol.AllowDelete = true
	m := h.mint(t, pol, 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	h.commit(t, dir, "x.txt", "x\n")
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/doomed"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", ":refs/heads/cloop/doomed"); err != nil {
		t.Fatalf("a delete through the scanning proxy failed: %v\n%s%s", err, out, h.eventLog())
	}
	if _, ok := h.upstreamSHA(t, "refs/heads/cloop/doomed"); ok {
		t.Fatal("the deleted ref is still on the forge")
	}
}

func TestPushScanReadsPushOptions(t *testing.T) {
	// With push options the pack follows a section of its own; the scan
	// reads past it, so a push with an option lands — and one whose option
	// carries the value does not.
	h := newHarness(t)
	h.mustGit(t, "", nil, "--git-dir="+h.bare, "config", "receive.advertisePushOptions", "true")
	h.withPushScan(t, e2eScan(gitproxy.ScanValues))
	m := h.mint(t, scanPolicy(), 0)
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "opt.txt", "with an option\n")
	if out, err := h.git(t, dir, h.credEnv(m), "push", "-o", "ci.skip", "origin", "HEAD:refs/heads/cloop/opt"); err != nil {
		t.Fatalf("a clean push with a push option was refused: %v\n%s%s", err, out, h.eventLog())
	}
	if got, _ := h.upstreamSHA(t, "refs/heads/cloop/opt"); got != sha {
		t.Fatalf("upstream is at %q, want %s", got, sha)
	}
	h.commit(t, dir, "opt2.txt", "again\n")
	h.allowedBefore = len(h.eventsOf(gitproxy.EventPushAllowed))
	out, err = h.git(t, dir, h.credEnv(m), "push", "-o", "deploy.token="+e2eSecret, "origin", "HEAD:refs/heads/cloop/opt")
	ev := h.assertRefusedForTheValue(t, out, err, "refs/heads/cloop/opt", sha)
	if f := ev.Findings[0]; f.Where != "push option" {
		t.Fatalf("the refusal names %+v, want a push option", f)
	}
}
