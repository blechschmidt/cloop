package gitproxy

// Tests for the push scan's pack reader (Task 20436), against packs real git
// writes: `git pack-objects`, full and thin, with OFS_DELTA and REF_DELTA, for
// SHA-1 and SHA-256 repositories. The synthetic packs further down are for
// what git never writes — malformed input, and the residual this scan leaves.

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// testSecret is the value the run was "given". Built at run time, so no
// scanner of this repository's own pushes ever sees a credential-shaped
// literal in its source.
var testSecret = "cloop-" + strings.Repeat("Zq7", 3) + "-leased-" + hex.EncodeToString([]byte("Task20436"))

func testSecrets() []ScanSecret {
	return []ScanSecret{{Value: testSecret, Grant: "gr_test", Secret: "acme-prod", Field: "env API_KEY"}}
}

// --- git ------------------------------------------------------------------------

func needGit(t testing.TB) string {
	t.Helper()
	bin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git binary on PATH; these tests read packs git writes")
	}
	return bin
}

type gitRepo struct {
	t   testing.TB
	bin string
	dir string
}

func newGitRepo(t testing.TB, extraInit ...string) *gitRepo {
	t.Helper()
	r := &gitRepo{t: t, bin: needGit(t), dir: t.TempDir()}
	args := append([]string{"init", "-q"}, extraInit...)
	r.run(append(args, r.dir)...)
	return r
}

func (r *gitRepo) env() []string {
	return []string{
		"HOME=" + r.dir, "PATH=" + os.Getenv("PATH"), "LC_ALL=C",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=cloop", "GIT_AUTHOR_EMAIL=cloop@example.invalid",
		"GIT_COMMITTER_NAME=cloop", "GIT_COMMITTER_EMAIL=cloop@example.invalid",
		"GIT_AUTHOR_DATE=2026-10-16T00:00:00Z", "GIT_COMMITTER_DATE=2026-10-16T00:00:00Z",
	}
}

func (r *gitRepo) run(args ...string) string {
	r.t.Helper()
	return r.runIn("", args...)
}

func (r *gitRepo) runIn(stdin string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Dir = r.dir
	cmd.Env = r.env()
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return out.String()
}

func (r *gitRepo) write(name, content string) {
	r.t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *gitRepo) commit(msg string, files map[string]string) string {
	r.t.Helper()
	for name, content := range files {
		r.write(name, content)
		r.run("add", name)
	}
	r.run("commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", msg)
	return strings.TrimSpace(r.run("rev-parse", "HEAD"))
}

// pack writes a pack of what revs name, as send-pack asks pack-objects for
// one: --thin for a thin pack against the negated revisions, and
// --delta-base-offset as every modern client sends.
func (r *gitRepo) pack(thin bool, revs ...string) []byte {
	r.t.Helper()
	args := []string{"pack-objects", "--stdout", "--revs", "--delta-base-offset", "-q"}
	if thin {
		args = append(args, "--thin")
	}
	return []byte(r.runIn(strings.Join(revs, "\n")+"\n", args...))
}

func (r *gitRepo) revParse(rev string) string {
	r.t.Helper()
	return strings.TrimSpace(r.run("rev-parse", rev))
}

// --- running the scanner --------------------------------------------------------

type scanRun struct {
	sc        *packScanner
	err       error
	findings  []ScanFinding
	forwarded []byte
	refused   bool
}

// scanPack scans body as what follows a command section, the way
// runPushScan does, recording what would have been forwarded.
func scanPack(t testing.TB, body []byte, head *ReceivePack, secrets []ScanSecret, mode ScanMode, limits ScanLimits) scanRun {
	t.Helper()
	var run scanRun
	var fwd bytes.Buffer
	src := newPackSource(bytes.NewReader(body), func(b []byte) error {
		if !run.refused {
			fwd.Write(b)
		}
		return nil
	})
	if head == nil {
		head = &ReceivePack{Commands: []RefUpdate{{Old: zeroSHA, New: strings.Repeat("1", 40), Ref: "refs/heads/cloop/t"}}}
	}
	sc := newPackScanner(src, head.hashLen(), newMatcher(secrets), mode == ScanShapes, limits)
	sc.onRefuse = func() { run.refused = true }
	run.err = sc.scan(head)
	if run.err == nil && len(sc.findings) == 0 {
		if err := src.release(); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
	run.sc = sc
	run.findings = sc.report()
	run.forwarded = fwd.Bytes()
	return run
}

func (run scanRun) only(t testing.TB) ScanFinding {
	t.Helper()
	if run.err != nil {
		t.Fatalf("scan stopped: %v", run.err)
	}
	if len(run.findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(run.findings), run.findings)
	}
	return run.findings[0]
}

// assertNoValue fails if anything the scan would show or record carries the
// value or one of its encodings.
func assertNoValue(t testing.TB, run scanRun, secrets []ScanSecret) {
	t.Helper()
	m := newMatcher(secrets)
	for _, f := range run.findings {
		for _, s := range []string{f.summary(), f.Path, f.Tag, f.Ref, f.Field, findingsDetail(run.findings)} {
			if _, hit := m.contains([]byte(s)); hit {
				t.Fatalf("the report carries the value: %q", s)
			}
		}
	}
}

// --- what is found --------------------------------------------------------------

func TestScanFindsAValueInABlob(t *testing.T) {
	r := newGitRepo(t)
	base := r.commit("base", map[string]string{"README.md": "hello\n"})
	head := r.commit("add config", map[string]string{"config/app.env": "API_KEY=" + testSecret + "\n"})

	run := scanPack(t, r.pack(false, head, "^"+base), nil, testSecrets(), ScanValues, ScanLimits{})
	f := run.only(t)
	blob := r.revParse(head + ":config/app.env")
	if f.Type != "blob" || f.Object != blob {
		t.Errorf("finding names %s %s, want blob %s", f.Type, f.Object, blob)
	}
	if f.Path != "config/app.env" || f.PathPartial {
		t.Errorf("path = %q (partial %v), want config/app.env in full", f.Path, f.PathPartial)
	}
	if f.Commit != head {
		t.Errorf("commit = %q, want %s", f.Commit, head)
	}
	if f.Grant != "gr_test" || f.Secret != "acme-prod" || f.Field != "env API_KEY" || f.Form != formRaw {
		t.Errorf("provenance = %+v", f)
	}
	if !run.refused {
		t.Error("the gate was never told to refuse")
	}
	assertNoValue(t, run, testSecrets())
	// The forge never got the whole pack.
	if bytes.Equal(run.forwarded, r.pack(false, head, "^"+base)) {
		t.Error("the whole pack was forwarded")
	}
}

func TestScanFindsAValueInACommitMessage(t *testing.T) {
	r := newGitRepo(t)
	head := r.commit("deploy with token "+testSecret, map[string]string{"a.txt": "a\n"})
	run := scanPack(t, r.pack(false, head), nil, testSecrets(), ScanValues, ScanLimits{})
	f := run.only(t)
	if f.Type != "commit" || f.Object != head || f.Commit != head || f.Where != whereMessage {
		t.Errorf("finding = %+v, want commit %s in its message", f, head)
	}
	assertNoValue(t, run, testSecrets())
}

func TestScanFindsAValueInAnAnnotatedTag(t *testing.T) {
	r := newGitRepo(t)
	r.commit("base", map[string]string{"a.txt": "a\n"})
	r.run("tag", "-a", "v1.0", "-m", "release notes: "+testSecret)
	tag := r.revParse("v1.0")
	run := scanPack(t, r.pack(false, "v1.0"), nil, testSecrets(), ScanValues, ScanLimits{})
	f := run.only(t)
	if f.Type != "tag" || f.Object != tag || f.Tag != "v1.0" || f.Where != whereMessage {
		t.Errorf("finding = %+v, want tag %s (v1.0) in its message", f, tag)
	}
}

func TestScanFindsEncodedForms(t *testing.T) {
	embedded := func(prefix string) string {
		return base64.StdEncoding.EncodeToString([]byte(prefix + testSecret + "-trailing"))
	}
	cases := map[string]string{
		"base64 on its own":         base64.StdEncoding.EncodeToString([]byte(testSecret)),
		"base64 at offset one":      embedded("x"),
		"base64 at offset two":      embedded("xy"),
		"base64 in a larger blob":   embedded(`{"auths":{"r":{"auth":"`),
		"url-safe base64":           base64.URLEncoding.EncodeToString([]byte("??" + testSecret)),
		"percent-encoded userinfo":  "https://u:" + url.QueryEscape(testSecret+"/@:") + "@proxy:3128",
		"kubernetes secret":         "data:\n  token: " + base64.StdEncoding.EncodeToString([]byte(testSecret)) + "\n",
		"raw with crlf line ending": "TOKEN=" + testSecret + "\r\n",
	}
	secrets := testSecrets()
	secrets = append(secrets, ScanSecret{Value: testSecret + "/@:", Field: "env PROXY_PASSWORD"})
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			r := newGitRepo(t)
			head := r.commit("add", map[string]string{"f.txt": "x\n" + content + "\nmore\n"})
			run := scanPack(t, r.pack(false, head), nil, secrets, ScanValues, ScanLimits{})
			if run.err != nil || len(run.findings) == 0 {
				t.Fatalf("%s was not found (err %v)", name, run.err)
			}
			assertNoValue(t, run, secrets)
		})
	}
}

func TestScanFindsAValueInAThinDelta(t *testing.T) {
	r := newGitRepo(t)
	var body strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&body, "line %d of a long configuration file that the forge already has\n", i)
	}
	old := r.commit("base", map[string]string{"settings.conf": body.String()})
	oldBlob := r.revParse(old + ":settings.conf")
	head := r.commit("tweak", map[string]string{"settings.conf": body.String() + "token = " + testSecret + "\n"})

	pack := r.pack(true, head, "^"+old)
	run := scanPack(t, pack, nil, testSecrets(), ScanValues, ScanLimits{})
	if run.sc.typeCounts[objRefDelta] == 0 {
		t.Fatalf("git wrote no REF_DELTA, so this proves nothing about thin packs (types %v)", run.sc.typeCounts)
	}
	f := run.only(t)
	if f.Type != "delta" || f.Base != oldBlob || f.Where != whereInsert {
		t.Errorf("finding = %+v, want a delta against %s, in its inserted bytes", f, oldBlob)
	}
	// One commit in the push carries it, whatever the trees arrived as.
	if f.Commit != head {
		t.Errorf("commit = %q, want %s", f.Commit, head)
	}
}

func TestScanFindsAValueInAnOfsDelta(t *testing.T) {
	r := newGitRepo(t)
	var long strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&long, "entry %d: a line long enough for git to want a delta here\n", i)
	}
	all := long.String()
	// The newer version is the smaller one, so git keeps the older whole and
	// writes the newer — the one carrying the value — as a delta against it.
	first := r.commit("first", map[string]string{"data.txt": all})
	cut := all[:len(all)*3/4]
	head := r.commit("second", map[string]string{"data.txt": cut + "secret = " + testSecret + "\n"})

	run := scanPack(t, r.pack(false, head), nil, testSecrets(), ScanValues, ScanLimits{})
	if run.sc.typeCounts[objOfsDelta] == 0 {
		t.Fatalf("git wrote no OFS_DELTA (types %v)", run.sc.typeCounts)
	}
	f := run.only(t)
	firstBlob := r.revParse(first + ":data.txt")
	if f.Type != "delta" || f.Base != firstBlob {
		t.Errorf("finding = %+v, want a delta against %s", f, firstBlob)
	}
}

func TestScanFindsTheFileNameInAThinPush(t *testing.T) {
	r := newGitRepo(t)
	files := map[string]string{}
	for i := 0; i < 30; i++ {
		files[fmt.Sprintf("src/file%02d.go", i)] = fmt.Sprintf("package src // %d\n", i)
	}
	old := r.commit("base", files)
	head := r.commit("leak", map[string]string{"src/creds.env": "K=" + testSecret + "\n"})
	run := scanPack(t, r.pack(true, head, "^"+old), nil, testSecrets(), ScanValues, ScanLimits{})
	f := run.only(t)
	if f.Type != "blob" || f.Path == "" {
		t.Fatalf("finding = %+v, want a blob with a path", f)
	}
	// The trees above it arrived as deltas against the forge's; the inserted
	// entry still names it.
	if run.sc.typeCounts[objRefDelta] == 0 {
		t.Fatalf("git wrote no REF_DELTA tree (types %v), so the name came from somewhere else", run.sc.typeCounts)
	}
	if !strings.HasSuffix(f.Path, "creds.env") || !f.PathPartial {
		t.Errorf("path = %q (partial %v), want the name creds.env read from an inserted tree entry", f.Path, f.PathPartial)
	}
	t.Logf("named %q from a thin push of %v objects by type", f.Path, run.sc.typeCounts)
}

func TestScanCleanPackIsForwardedByteIdentical(t *testing.T) {
	r := newGitRepo(t)
	base := r.commit("base", map[string]string{"a.txt": strings.Repeat("abc\n", 1000)})
	head := r.commit("next", map[string]string{"a.txt": strings.Repeat("abc\n", 999) + "def\n", "b.txt": "b\n"})
	for name, pack := range map[string][]byte{
		"full": r.pack(false, head),
		"thin": r.pack(true, head, "^"+base),
	} {
		t.Run(name, func(t *testing.T) {
			run := scanPack(t, pack, nil, testSecrets(), ScanValues, ScanLimits{})
			if run.err != nil || len(run.findings) != 0 {
				t.Fatalf("a clean pack was refused: %v %+v", run.err, run.findings)
			}
			if !bytes.Equal(run.forwarded, pack) {
				t.Fatalf("forwarded %d bytes that differ from the %d git wrote", len(run.forwarded), len(pack))
			}
		})
	}
}

func TestScanHoldsTheChecksumBackUntilItEnds(t *testing.T) {
	r := newGitRepo(t)
	head := r.commit("one", map[string]string{"a.txt": "a\n"})
	pack := r.pack(false, head)

	var fwd bytes.Buffer
	src := newPackSource(bytes.NewReader(pack), func(b []byte) error { fwd.Write(b); return nil })
	sc := newPackScanner(src, 20, newMatcher(testSecrets()), false, ScanLimits{})
	if err := sc.scan(nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fwd.Bytes(), pack[:len(pack)-20]) {
		t.Fatalf("before the verdict the forge has %d bytes; want all but the 20-byte checksum of %d", fwd.Len(), len(pack))
	}
	if err := src.release(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fwd.Bytes(), pack) {
		t.Fatal("after release the forge does not have the whole pack")
	}
}

func TestScanRefusesBytesAfterTheChecksum(t *testing.T) {
	r := newGitRepo(t)
	pack := r.pack(false, r.commit("one", map[string]string{"a.txt": "a\n"}))
	run := scanPack(t, append(append([]byte(nil), pack...), "PACK"...), nil, testSecrets(), ScanValues, ScanLimits{})
	assertStop(t, run, stopUnreadable)
	// The checksum stayed held: the forge never had a pack it could accept,
	// however many bytes the sandbox sent after it.
	if bytes.Contains(run.forwarded, pack[len(pack)-20:]) {
		t.Fatal("the checksum was handed on although bytes followed it")
	}
}

func TestScanSHA256Repository(t *testing.T) {
	r := newGitRepo(t, "--object-format=sha256")
	head := r.commit("add", map[string]string{"k.txt": testSecret + "\n"})
	if len(head) != 64 {
		t.Skipf("git made a %d-digit commit id; this git cannot write SHA-256 repositories", len(head))
	}
	cmd := &ReceivePack{Commands: []RefUpdate{{Old: strings.Repeat("0", 64), New: head, Ref: "refs/heads/cloop/x"}}}
	run := scanPack(t, r.pack(false, head), cmd, testSecrets(), ScanValues, ScanLimits{})
	f := run.only(t)
	if f.Object != r.revParse(head+":k.txt") || f.Commit != head {
		t.Errorf("finding = %+v", f)
	}
}

// --- the command section ----------------------------------------------------------

func TestScanFindsAValueInARefNameAndNeverNamesIt(t *testing.T) {
	cmd := &ReceivePack{Commands: []RefUpdate{{Old: zeroSHA, New: strings.Repeat("2", 40), Ref: "refs/heads/cloop/" + testSecret}}}
	run := scanPack(t, nil, cmd, testSecrets(), ScanValues, ScanLimits{})
	f := run.only(t)
	if f.Where != whereRef || strings.Contains(f.Ref, testSecret) || !strings.Contains(f.Ref, "[redacted]") {
		t.Fatalf("finding = %+v, want the ref named with the value redacted", f)
	}
	assertNoValue(t, run, testSecrets())
}

func TestScanFindsAValueInAPushOption(t *testing.T) {
	var body bytes.Buffer
	_ = writePkt(&body, []byte("ci.variable=TOKEN="+testSecret))
	_ = writeFlush(&body)
	cmd := &ReceivePack{
		Commands:     []RefUpdate{{Old: zeroSHA, New: strings.Repeat("3", 40), Ref: "refs/heads/cloop/t"}},
		Capabilities: []string{"report-status", "push-options"},
	}
	run := scanPack(t, body.Bytes(), cmd, testSecrets(), ScanValues, ScanLimits{})
	if f := run.only(t); f.Where != wherePushOption {
		t.Fatalf("finding = %+v, want a push option", f)
	}
}

func TestScanPushOptionsShiftPackOffsets(t *testing.T) {
	// OFS_DELTA distances count from the pack, not from the body: with push
	// options in front, an offset taken from the body would put every base
	// out of bounds.
	r := newGitRepo(t)
	var long strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&long, "row %d of something git will delta\n", i)
	}
	r.commit("a", map[string]string{"d.txt": long.String()})
	head := r.commit("b", map[string]string{"d.txt": long.String()[:3000] + "changed\n"})
	var body bytes.Buffer
	_ = writePkt(&body, []byte("ci.skip"))
	_ = writeFlush(&body)
	body.Write(r.pack(false, head))
	cmd := &ReceivePack{
		Commands:     []RefUpdate{{Old: zeroSHA, New: head, Ref: "refs/heads/cloop/t"}},
		Capabilities: []string{"push-options"},
	}
	run := scanPack(t, body.Bytes(), cmd, testSecrets(), ScanValues, ScanLimits{})
	if run.err != nil || len(run.findings) != 0 {
		t.Fatalf("a clean push with options was refused: %v %+v", run.err, run.findings)
	}
	if !bytes.Equal(run.forwarded, body.Bytes()) {
		t.Fatal("the push options and pack were not forwarded as sent")
	}
}

// --- shapes -------------------------------------------------------------------------

func TestScanShapesModeFindsACredentialShapeOnlyWhenAskedTo(t *testing.T) {
	// A GitHub fine-grained token shape, assembled here so that no scanner of
	// this repository's own pushes sees one in its source.
	shaped := "github" + "_pat_" + strings.Repeat("A1b2C3d4E5", 2) + "_" + strings.Repeat("Zy9Xw8Vu7T", 6) + "s1"
	r := newGitRepo(t)
	head := r.commit("add", map[string]string{"ci.yml": "token: " + shaped + "\n"})
	pack := r.pack(false, head)

	if run := scanPack(t, pack, nil, testSecrets(), ScanValues, ScanLimits{}); run.err != nil || len(run.findings) != 0 {
		t.Fatalf("values mode refused a shape it was never given: %v %+v", run.err, run.findings)
	}
	run := scanPack(t, pack, nil, testSecrets(), ScanShapes, ScanLimits{})
	f := run.only(t)
	if f.Grant != "" || !strings.Contains(f.Field, "by its shape") {
		t.Fatalf("finding = %+v, want a shape with no grant", f)
	}
	if strings.Contains(f.summary(), shaped) {
		t.Fatal("the report carries the credential")
	}
}

// --- limits -------------------------------------------------------------------------

func TestScanLimitsRefuseNamingTheirSetting(t *testing.T) {
	r := newGitRepo(t)
	head := r.commit("big", map[string]string{"big.txt": strings.Repeat("0123456789", 30000)})
	pack := r.pack(false, head)
	cases := []struct {
		limits  ScanLimits
		setting string
	}{
		{ScanLimits{MaxObjectBytes: 1000}, SettingPushScanObjectMB},
		{ScanLimits{MaxPushBytes: 1000}, SettingPushScanPushMB},
		{ScanLimits{MaxDuration: time.Nanosecond}, SettingPushScanSeconds},
	}
	for _, c := range cases {
		t.Run(c.setting, func(t *testing.T) {
			run := scanPack(t, pack, nil, testSecrets(), ScanValues, c.limits)
			se := assertStop(t, run, stopLimit)
			if se.setting != c.setting || !strings.Contains(se.msg, c.setting) {
				t.Fatalf("limit error %q names %q, want %s", se.msg, se.setting, c.setting)
			}
		})
	}
}

func assertStop(t testing.TB, run scanRun, want scanStop) *scanError {
	t.Helper()
	se, ok := run.err.(*scanError)
	if !ok || se.stop != want {
		t.Fatalf("scan ended with %v (%T), want stop %d", run.err, run.err, want)
	}
	if !run.refused && (want == stopLimit || want == stopUnreadable) {
		// scanPack's refusal flag tracks onRefuse, which the scanner calls
		// for findings; runPushScan refuses on these errors itself.
		_ = run
	}
	return se
}

// --- synthetic packs ---------------------------------------------------------------

// testPack assembles a pack the way git lays one out, for input git never
// writes.
type testPack struct {
	objs  bytes.Buffer
	count uint32
	offs  []int64
}

func objHeader(typ int, size uint64) []byte {
	c := byte(typ<<4) | byte(size&15)
	size >>= 4
	var out []byte
	for size > 0 {
		out = append(out, c|0x80)
		c = byte(size & 0x7f)
		size >>= 7
	}
	return append(out, c)
}

func zlibBytes(b []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	_, _ = w.Write(b)
	_ = w.Close()
	return z.Bytes()
}

func (p *testPack) add(raw []byte) {
	p.offs = append(p.offs, int64(packHeaderLen+p.objs.Len()))
	p.objs.Write(raw)
	p.count++
}

func (p *testPack) whole(typ int, content []byte) {
	p.add(append(objHeader(typ, uint64(len(content))), zlibBytes(content)...))
}

func (p *testPack) refDelta(base []byte, delta []byte) {
	raw := append(objHeader(objRefDelta, uint64(len(delta))), base...)
	p.add(append(raw, zlibBytes(delta)...))
}

func ofsEncode(dist uint64) []byte {
	out := []byte{byte(dist & 127)}
	for dist >>= 7; dist > 0; dist >>= 7 {
		dist--
		out = append([]byte{byte(dist&127) | 128}, out...)
	}
	return out
}

func (p *testPack) ofsDelta(baseIndex int, delta []byte) {
	here := int64(packHeaderLen + p.objs.Len())
	raw := append(objHeader(objOfsDelta, uint64(len(delta))), ofsEncode(uint64(here-p.offs[baseIndex]))...)
	p.add(append(raw, zlibBytes(delta)...))
}

func (p *testPack) bytes() []byte {
	var out bytes.Buffer
	out.WriteString("PACK")
	_ = binary.Write(&out, binary.BigEndian, uint32(2))
	_ = binary.Write(&out, binary.BigEndian, p.count)
	out.Write(p.objs.Bytes())
	sum := sha1.Sum(out.Bytes())
	out.Write(sum[:])
	return out.Bytes()
}

func varint(n uint64) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

func deltaOf(src, dst uint64, instrs ...[]byte) []byte {
	out := append(varint(src), varint(dst)...)
	for _, in := range instrs {
		out = append(out, in...)
	}
	return out
}

func insertOp(b string) []byte { return append([]byte{byte(len(b))}, b...) }

func copyOp(off, size uint32) []byte {
	cmd := byte(0x80)
	var args []byte
	for i := 0; i < 4; i++ {
		if b := byte(off >> (8 * i)); b != 0 {
			cmd |= 1 << i
			args = append(args, b)
		}
	}
	for i := 0; i < 3; i++ {
		if b := byte(size >> (8 * i)); b != 0 {
			cmd |= 1 << (4 + i)
			args = append(args, b)
		}
	}
	return append([]byte{cmd}, args...)
}

func TestScanResidualAValueSplitAcrossACopyAndAnInsertIsNotFound(t *testing.T) {
	// The documented residual (docs/architecture/git-proxy.md, "Limits that
	// remain"): the first half of the value already sits in a base — on the
	// forge, or earlier in this pack — and the delta copies it, then inserts
	// the second half. Neither the base nor the insert holds the value whole,
	// and the scan reads inserts, not the objects git builds from them. This
	// test pins the boundary; if the scan ever closes it, the docs change
	// with it.
	half := len(testSecret) / 2
	base := []byte("prefix " + testSecret[:half])
	var p testPack
	baseID := sha1.Sum([]byte("whatever the forge holds"))
	p.refDelta(baseID[:], deltaOf(uint64(len(base)), uint64(len(base)+len(testSecret)-half),
		copyOp(0, uint32(len(base))), insertOp(testSecret[half:])))
	run := scanPack(t, p.bytes(), nil, testSecrets(), ScanValues, ScanLimits{})
	if run.err != nil {
		t.Fatalf("scan stopped: %v", run.err)
	}
	if len(run.findings) != 0 {
		t.Fatalf("the split value was found (%+v): the residual is closed — update the docs", run.findings)
	}

	// Whereas inserts on either side of nothing are one run, and found.
	var q testPack
	q.refDelta(baseID[:], deltaOf(4, uint64(len(testSecret)),
		insertOp(testSecret[:half]), insertOp(testSecret[half:])))
	if run := scanPack(t, q.bytes(), nil, testSecrets(), ScanValues, ScanLimits{}); len(run.findings) != 1 {
		t.Fatalf("a value split across two consecutive inserts was not found: %v %+v", run.err, run.findings)
	}
}

func TestScanInsertsAcrossACopyAreNotJoined(t *testing.T) {
	// The object git builds has the copied bytes between the two inserts, so
	// it never holds the value; joining the inserts would refuse a push that
	// publishes nothing.
	half := len(testSecret) / 2
	var p testPack
	id := sha1.Sum([]byte("base"))
	p.refDelta(id[:], deltaOf(64, uint64(len(testSecret)+8),
		insertOp(testSecret[:half]), copyOp(0, 8), insertOp(testSecret[half:])))
	if run := scanPack(t, p.bytes(), nil, testSecrets(), ScanValues, ScanLimits{}); run.err != nil || len(run.findings) != 0 {
		t.Fatalf("inserts separated by a copy were joined: %v %+v", run.err, run.findings)
	}
}

func TestScanRefusesWhatGitWouldNotRead(t *testing.T) {
	blob := []byte("hello world\n")
	good := func() *testPack {
		var p testPack
		p.whole(objBlob, blob)
		return &p
	}
	id := sha1.Sum([]byte("x"))
	cases := map[string][]byte{
		"not a pack": []byte("PUSH\x00\x00\x00\x02\x00\x00\x00\x01"),
		"version 4": func() []byte {
			b := good().bytes()
			b[7] = 4
			return b
		}(),
		"truncated object": func() []byte { b := good().bytes(); return b[:20] }(),
		"truncated checksum": func() []byte {
			b := good().bytes()
			return b[:len(b)-3]
		}(),
		"object type 5": func() []byte {
			var p testPack
			p.add(append(objHeader(5, uint64(len(blob))), zlibBytes(blob)...))
			return p.bytes()
		}(),
		"size larger than its data": func() []byte {
			var p testPack
			p.add(append(objHeader(objBlob, uint64(len(blob)+1)), zlibBytes(blob)...))
			return p.bytes()
		}(),
		"size smaller than its data": func() []byte {
			var p testPack
			p.add(append(objHeader(objBlob, uint64(len(blob)-1)), zlibBytes(blob)...))
			return p.bytes()
		}(),
		"corrupt zlib": func() []byte {
			var p testPack
			z := zlibBytes(blob)
			z[len(z)-1] ^= 0xff
			p.add(append(objHeader(objBlob, uint64(len(blob))), z...))
			return p.bytes()
		}(),
		"delta opcode zero": func() []byte {
			var p testPack
			p.refDelta(id[:], deltaOf(4, 1, []byte{0}))
			return p.bytes()
		}(),
		"delta copy past its base": func() []byte {
			var p testPack
			p.refDelta(id[:], deltaOf(4, 8, copyOp(0, 8)))
			return p.bytes()
		}(),
		"delta writes past its size": func() []byte {
			var p testPack
			p.refDelta(id[:], deltaOf(4, 2, insertOp("abc")))
			return p.bytes()
		}(),
		"delta writes short of its size": func() []byte {
			var p testPack
			p.refDelta(id[:], deltaOf(4, 9, insertOp("abc")))
			return p.bytes()
		}(),
		"ofs delta base before the pack": func() []byte {
			var p testPack
			p.whole(objBlob, blob)
			raw := append(objHeader(objOfsDelta, 3), ofsEncode(1<<20)...)
			p.add(append(raw, zlibBytes(deltaOf(1, 1, insertOp("a")))...))
			return p.bytes()
		}(),
		"header past 64 bits": func() []byte {
			var p testPack
			p.add(bytes.Repeat([]byte{0xff}, 12))
			return p.bytes()
		}(),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			run := scanPack(t, body, nil, testSecrets(), ScanValues, ScanLimits{})
			assertStop(t, run, stopUnreadable)
		})
	}
	// And the control: the good pack is read.
	if run := scanPack(t, good().bytes(), nil, testSecrets(), ScanValues, ScanLimits{}); run.err != nil {
		t.Fatalf("the control pack was refused: %v", run.err)
	}
}

func TestScanAPushThatSendsNoPack(t *testing.T) {
	cmd := &ReceivePack{Commands: []RefUpdate{{Old: strings.Repeat("4", 40), New: zeroSHA, Ref: "refs/heads/cloop/gone"}}}
	if run := scanPack(t, nil, cmd, testSecrets(), ScanValues, ScanLimits{}); run.err != nil || len(run.findings) != 0 {
		t.Fatalf("a delete-only push was refused: %v %+v", run.err, run.findings)
	}
}

// --- matching -----------------------------------------------------------------------

func TestValueFormsGuardTheMinimumLength(t *testing.T) {
	for _, v := range []string{"", "short", "1234567", "  1234567  ", "[redacted]", "<redacted:leased>"} {
		if f := valueForms(v); len(f) != 0 {
			t.Errorf("valueForms(%q) = %v, want nothing", v, f)
		}
	}
	if newMatcher([]ScanSecret{{Value: "tiny"}}) != nil {
		t.Error("a matcher over only short values exists")
	}
	if f := valueForms("12345678"); len(f) == 0 {
		t.Error("an eight-byte value is not matched")
	}
}

func TestMatcherFindsAValueAcrossEveryChunkBoundary(t *testing.T) {
	m := newMatcher(testSecrets())
	text := []byte("prefix bytes " + testSecret + " suffix")
	for cut := 0; cut <= len(text); cut++ {
		st := matchStream{m: m}
		found := 0
		hit := func(int, int64) bool { found++; return true }
		st.write(text[:cut], hit)
		st.write(text[cut:], hit)
		if found != 1 {
			t.Fatalf("split at %d: found %d times, want once", cut, found)
		}
	}
}

func TestBase64CoresMatchEveryAlignment(t *testing.T) {
	v := []byte(testSecret)
	cores := base64Cores(base64.StdEncoding, v)
	for shift := 0; shift < 3; shift++ {
		for tail := 0; tail < 3; tail++ {
			blob := append(append(bytes.Repeat([]byte{0xA5}, shift), v...), bytes.Repeat([]byte{0x5A}, tail)...)
			enc := base64.StdEncoding.EncodeToString(blob)
			if !strings.Contains(enc, cores[shift]) {
				t.Errorf("shift %d tail %d: %q not in %q", shift, tail, cores[shift], enc)
			}
		}
	}
}

func TestPEMPrivateKeyLinesAreMatchedAndCertificatesAreNot(t *testing.T) {
	body := strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ", 1)
	key := "-----BEGIN PRIVATE KEY-----\n" + body + "Q7x9\n" + body[:40] + "ZZ\n-----END PRIVATE KEY-----\n"
	lines := pemBodyLines(key)
	if len(lines) != 2 {
		t.Fatalf("pemBodyLines = %v, want two body lines", lines)
	}
	cert := strings.ReplaceAll(key, "PRIVATE KEY", "CERTIFICATE")
	if l := pemBodyLines(cert); len(l) != 0 {
		t.Fatalf("a certificate contributed lines %v", l)
	}
	// A key pasted into JSON with escaped newlines is the same key.
	if l := pemBodyLines(strings.ReplaceAll(key, "\n", `\n`)); len(l) != 2 {
		t.Fatalf("escaped newlines: %v", l)
	}
}

func TestStricterScanModeOnlyTightens(t *testing.T) {
	cases := []struct{ hub, project, want ScanMode }{
		{ScanValues, ScanOff, ScanValues},
		{ScanValues, ScanShapes, ScanShapes},
		{ScanOff, ScanValues, ScanValues},
		{ScanShapes, ScanOff, ScanShapes},
		{ScanOff, ScanOff, ScanOff},
		{"", ScanOff, ScanValues},
		{"bogus", ScanOff, ScanValues},
	}
	for _, c := range cases {
		if got := StricterScanMode(c.hub, c.project); got != c.want {
			t.Errorf("StricterScanMode(%q, %q) = %q, want %q", c.hub, c.project, got, c.want)
		}
	}
	for in, want := range map[string]ScanMode{"": ScanValues, "VALUES": ScanValues, " shapes ": ScanShapes, "off": ScanOff} {
		if got, err := ParseScanMode(in); err != nil || got != want {
			t.Errorf("ParseScanMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseScanMode("strict"); err == nil || !strings.Contains(err.Error(), SettingPushScan) {
		t.Errorf("ParseScanMode(strict) = %v, want an error naming the setting", err)
	}
}

func TestScanReportNamesAreBoundedAndPrintable(t *testing.T) {
	sc := newPackScanner(newPackSource(bytes.NewReader(nil), nil), 20, newMatcher(testSecrets()), false, ScanLimits{})
	got := sc.scrub("dir/\x1b[31mred\x07/" + strings.Repeat("é", 300) + "/" + testSecret)
	if strings.ContainsAny(got, "\x1b\x07") || !strings.Contains(got, "?[31mred?") {
		t.Errorf("control characters survived: %q", got)
	}
	if len(got) > 210 || !strings.HasSuffix(got, "…") || !utf8.ValidString(got) {
		t.Errorf("an over-long name was not cut at a rune boundary: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if strings.Contains(sc.scrub("x/"+testSecret), testSecret) {
		t.Error("a name carrying the value was not redacted")
	}
}

func TestAMalformedCommandNamingTheValueIsRefusedWithoutIt(t *testing.T) {
	forge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a malformed push reached the forge")
	}))
	defer forge.Close()
	proxySrv := httptest.NewUnstartedServer(nil)
	proxySrv.StartTLS()
	defer proxySrv.Close()
	reg, err := NewRegistry(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }
	px, err := New(reg, Options{Transport: forge.Client().Transport, PushScan: func(*Session) PushScan {
		return PushScan{Secrets: testSecrets()}
	}})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv.Config.Handler = px
	m, err := reg.Mint(MintRequest{Upstream: forge.URL + "/acme/tool.git",
		Credential: Credential{Username: "u", Password: "forge-token-0001"}, Policy: WriteBackPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	_ = writePkt(&body, []byte("refs/heads/cloop/"+testSecret+"\x00report-status\n"))
	_ = writeFlush(&body)
	req, _ := http.NewRequest(http.MethodPost, m.RepoURL+"/git-receive-pack", &body)
	req.SetBasicAuth(m.Session.ID, m.Token)
	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(string(out), testSecret) {
		t.Fatalf("status %d, body %q", resp.StatusCode, out)
	}
	for _, e := range events {
		if strings.Contains(e.String(), testSecret) {
			t.Fatalf("the refusal's row carries the value: %s", e.String())
		}
	}
}

// emptyBlobPack is a pack of n empty blobs: nine bytes each, nothing to
// inflate — the input the time limit used to miss, because it was only
// consulted when an object produced output.
func emptyBlobPack(n uint32) []byte {
	var p testPack
	obj := append(objHeader(objBlob, 0), zlibBytes(nil)...)
	for i := uint32(0); i < n; i++ {
		p.objs.Write(obj)
	}
	p.count = n
	return p.bytes()
}

func TestScanTimeLimitHoldsForObjectsThatInflateToNothing(t *testing.T) {
	pack := emptyBlobPack(1 << 20)
	run := scanPack(t, pack, nil, testSecrets(), ScanValues, ScanLimits{MaxDuration: time.Millisecond})
	se := assertStop(t, run, stopLimit)
	if se.setting != SettingPushScanSeconds {
		t.Fatalf("stopped at %q (%s), want the time limit", se.setting, se.msg)
	}
	if run.sc.objects >= 1<<20 {
		t.Fatal("every object was read before the limit was noticed")
	}
}

func TestScanTimeLimitHoldsInsideAnObjectOfEmptyBlocks(t *testing.T) {
	// One object whose zlib stream is a million empty stored blocks: a single
	// inflater read that consumes megabytes and produces nothing.
	var z bytes.Buffer
	z.Write([]byte{0x78, 0x01})
	for i := 0; i < 1<<20; i++ {
		z.Write([]byte{0x00, 0x00, 0x00, 0xff, 0xff})
	}
	z.Write([]byte{0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01})
	var p testPack
	p.add(append(objHeader(objBlob, 0), z.Bytes()...))
	run := scanPack(t, p.bytes(), nil, testSecrets(), ScanValues, ScanLimits{MaxDuration: time.Millisecond})
	if se := assertStop(t, run, stopLimit); se.setting != SettingPushScanSeconds {
		t.Fatalf("stopped at %q (%s), want the time limit", se.setting, se.msg)
	}
	// The control: with time to spare the same object reads clean.
	if run := scanPack(t, p.bytes(), nil, testSecrets(), ScanValues, ScanLimits{}); run.err != nil {
		t.Fatalf("the control was refused: %v", run.err)
	}
}

func TestScanStopsReadingPastTheSessionsByteLimit(t *testing.T) {
	pack := emptyBlobPack(10000)
	var fwd bytes.Buffer
	src := newPackSource(bytes.NewReader(pack), func(b []byte) error { fwd.Write(b); return nil })
	src.limit = 4096
	sc := newPackScanner(src, 20, newMatcher(testSecrets()), false, ScanLimits{})
	err := sc.scan(nil)
	se, ok := err.(*scanError)
	if !ok || se.stop != stopLimit || !strings.Contains(se.msg, "4096 bytes") {
		t.Fatalf("scan = %v, want the byte limit", err)
	}
}

func TestAtMostTwoScansRunPerSession(t *testing.T) {
	sess := &Session{ID: "s1"}
	r1, err1 := sess.acquireScan(context.Background())
	r2, err2 := sess.acquireScan(context.Background())
	if err1 != nil || err2 != nil {
		t.Fatalf("the first two scans waited: %v %v", err1, err2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := sess.acquireScan(ctx); err == nil {
		t.Fatal("a third scan ran beside two")
	}
	r1()
	r1() // releasing twice gives back one slot
	r3, err := sess.acquireScan(context.Background())
	if err != nil {
		t.Fatalf("a slot given back was not reusable: %v", err)
	}
	r2()
	r3()
}

// earlyAnswer is a forge leg that reads a little of the push, stops reading it
// — what a transport does once the forge has answered and gone — and answers
// 413.
type earlyAnswer struct{}

func (earlyAnswer) RoundTrip(req *http.Request) (*http.Response, error) {
	_, _ = io.ReadFull(req.Body, make([]byte, 1024))
	_ = req.Body.Close()
	return &http.Response{StatusCode: http.StatusRequestEntityTooLarge, Status: "413 Request Entity Too Large",
		Header: http.Header{}, Body: io.NopCloser(strings.NewReader("too large")), Request: req}, nil
}

func TestAPushTheForgeStoppedReadingIsNeitherAllowedNorRefused(t *testing.T) {
	// A forge leg that stops reading leaves the scan unfinished: no
	// push_allowed row may claim it found nothing, and the sandbox gets the
	// forge's answer.
	proxySrv := httptest.NewUnstartedServer(nil)
	proxySrv.StartTLS()
	defer proxySrv.Close()
	reg, err := NewRegistry(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []Event
	reg.OnEvent = func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() }
	px, err := New(reg, Options{Transport: earlyAnswer{}})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv.Config.Handler = px
	m, err := reg.Mint(MintRequest{Upstream: "https://forge.example.invalid/acme/tool.git",
		Credential: Credential{Username: "u", Password: "forge-token-0002"}, Policy: WriteBackPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 4<<20)
	for i := range big {
		big[i] = byte(i*7 + i>>9)
	}
	var p testPack
	p.whole(objBlob, big)
	var body bytes.Buffer
	_ = writePkt(&body, []byte(zeroSHA+" "+strings.Repeat("a", 40)+" refs/heads/cloop/big\x00report-status\n"))
	_ = writeFlush(&body)
	body.Write(p.bytes())
	req, _ := http.NewRequest(http.MethodPost, m.RepoURL+"/git-receive-pack", &body)
	req.SetBasicAuth(m.Session.ID, m.Token)
	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("the sandbox got %d, want the forge's 413", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	rejected := false
	for _, e := range events {
		if e.Kind == EventPushAllowed {
			t.Fatalf("a push the forge stopped reading was recorded as allowed: %s", e.String())
		}
		if e.Kind == EventRejected && strings.Contains(e.Detail, "not completed") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("no row says the push was not completed: %v", events)
	}
}
