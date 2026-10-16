package gitproxy

// The pack reader's fuzz target and benchmarks (Task 20436).

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// FuzzPackScan feeds the pack reader whatever the fuzzer makes of real and
// synthetic packs, and holds it to what the gate relies on:
//
//   - it never panics, and ends;
//   - what it hands the forge is always a prefix of what the sandbox sent;
//   - a clean verdict handed on every byte, the checksum included;
//   - any other verdict, for a pack read as far as its checksum, handed on
//     nothing from the checksum on, so the forge never holds a pack it could
//     accept. A pack the reader gave up on earlier is one git gives up on at
//     the same object — the reader follows index-pack's rules for exactly
//     that reason — so the prefix the forge got cannot complete it either;
//   - nothing it reports carries the value.
func FuzzPackScan(f *testing.F) {
	for _, seed := range fuzzSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			return
		}
		limits := ScanLimits{MaxObjectBytes: 8 << 20, MaxPushBytes: 32 << 20, MaxDuration: 30 * time.Second}
		run := scanPack(t, body, nil, testSecrets(), ScanValues, limits)
		if !bytes.HasPrefix(body, run.forwarded) {
			t.Fatalf("handed on %d bytes that are not a prefix of the %d sent", len(run.forwarded), len(body))
		}
		clean := run.err == nil && len(run.findings) == 0
		switch {
		case clean && len(body) > 0 && !bytes.Equal(run.forwarded, body):
			t.Fatalf("a clean verdict handed on %d of %d bytes", len(run.forwarded), len(body))
		case !clean && run.sc.src.heldFrom >= 0 && int64(len(run.forwarded)) > run.sc.src.heldFrom:
			t.Fatalf("a refused pack handed on %d bytes, past its checksum at %d", len(run.forwarded), run.sc.src.heldFrom)
		}
		assertNoValue(t, run, testSecrets())
	})
}

// fuzzSeeds are synthetic packs of every object kind, and real ones when git
// is installed.
func fuzzSeeds(f *testing.F) [][]byte {
	var seeds [][]byte
	var p testPack
	p.whole(objBlob, []byte("value "+testSecret+"\n"))
	p.whole(objTree, append([]byte("100644 a.env\x00"), bytes.Repeat([]byte{7}, 20)...))
	p.whole(objCommit, []byte("tree "+strings.Repeat("ab", 20)+"\nauthor a <a> 1 +0000\n\nmsg\n"))
	p.whole(objTag, []byte("object "+strings.Repeat("cd", 20)+"\ntype commit\ntag v1\n\nnotes\n"))
	p.ofsDelta(0, deltaOf(uint64(len("value "+testSecret+"\n")), 10, copyOp(0, 5), insertOp("abcde")))
	id := sha1.Sum([]byte("base"))
	p.refDelta(id[:], deltaOf(100, 3, insertOp("xyz")))
	seeds = append(seeds, p.bytes())

	var empty testPack
	seeds = append(seeds, empty.bytes(), nil, []byte("PACK"))

	if _, err := exec.LookPath("git"); err == nil {
		r := newGitRepo(f)
		var long strings.Builder
		for i := 0; i < 80; i++ {
			fmt.Fprintf(&long, "line %d of a file\n", i)
		}
		base := r.commit("base", map[string]string{"a.txt": long.String(), "dir/b.txt": "b\n"})
		head := r.commit("next", map[string]string{"a.txt": long.String() + "k=" + testSecret + "\n"})
		r.run("tag", "-a", "v1", "-m", "tag")
		seeds = append(seeds, r.pack(false, head), r.pack(true, head, "^"+base), r.pack(false, "v1"))
	}
	return seeds
}

// --- benchmarks ---------------------------------------------------------------------

var (
	benchPackOnce sync.Once
	benchPack     []byte
	benchPackErr  error
)

// benchmarkPack is a pack of about 100 MiB as git writes it: blobs of text
// that compresses as source code does, blobs of random bytes that do not, and
// later versions of some of the text as deltas. Built once per process with
// fast-import, so no working tree is written.
func benchmarkPack(b *testing.B) []byte {
	b.Helper()
	benchPackOnce.Do(func() {
		bin, err := exec.LookPath("git")
		if err != nil {
			benchPackErr = err
			return
		}
		dir, err := os.MkdirTemp("", "cloop-packscan-bench-*")
		if err != nil {
			benchPackErr = err
			return
		}
		defer os.RemoveAll(dir)
		env := []string{"HOME=" + dir, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
		run := func(stdin io.Reader, args ...string) ([]byte, error) {
			cmd := exec.Command(bin, args...)
			cmd.Dir, cmd.Env, cmd.Stdin = dir, env, stdin
			var out, errb bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errb
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, errb.String())
			}
			return out.Bytes(), nil
		}
		if _, benchPackErr = run(nil, "init", "-q", "--bare", "."); benchPackErr != nil {
			return
		}
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(writeBenchImport(pw)) }()
		if _, benchPackErr = run(pr, "fast-import", "--quiet"); benchPackErr != nil {
			return
		}
		benchPack, benchPackErr = run(strings.NewReader("refs/heads/main\n"),
			"pack-objects", "--stdout", "--revs", "--delta-base-offset", "-q")
	})
	if benchPackErr != nil {
		b.Skipf("cannot build the benchmark pack: %v", benchPackErr)
	}
	return benchPack
}

// writeBenchImport streams a fast-import of two commits: 40 MiB of random
// blobs and 140 MiB of text, then a second commit changing a third of the
// text files a little, which git writes as deltas — about 100 MiB of pack.
func writeBenchImport(w io.Writer) error {
	rng := rand.New(rand.NewSource(20436))
	words := strings.Fields("func return if else for range struct interface map chan go defer " +
		"package import var const type nil true false err context string int error byte")
	text := func(n int) []byte {
		var b bytes.Buffer
		for b.Len() < n {
			for i := 0; i < 12; i++ {
				b.WriteString(words[rng.Intn(len(words))])
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "// %d\n", rng.Intn(100000))
		}
		return b.Bytes()
	}
	random := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		return b
	}
	var files [][]byte
	var names []string
	for i := 0; i < 40; i++ {
		files = append(files, random(1<<20))
		names = append(names, fmt.Sprintf("assets/bin%02d.dat", i))
	}
	for i := 0; i < 280; i++ {
		files = append(files, text(512<<10))
		names = append(names, fmt.Sprintf("src/pkg%02d/file%03d.go", i/20, i))
	}
	mark := 1
	for _, body := range files {
		if _, err := fmt.Fprintf(w, "blob\nmark :%d\ndata %d\n", mark, len(body)); err != nil {
			return err
		}
		if _, err := w.Write(append(body, '\n')); err != nil {
			return err
		}
		mark++
	}
	fmt.Fprintf(w, "commit refs/heads/main\nmark :%d\ncommitter b <b@x> 1700000000 +0000\ndata 5\nfirst\n", mark)
	for i := range files {
		fmt.Fprintf(w, "M 100644 :%d %s\n", i+1, names[i])
	}
	w.Write([]byte("\n"))
	first := mark
	mark++
	// The second commit: every third text file with a few lines changed.
	var changed []int
	for i := 40; i < len(files); i += 3 {
		body := append([]byte(nil), files[i]...)
		copy(body[len(body)/2:], text(256))
		fmt.Fprintf(w, "blob\nmark :%d\ndata %d\n", mark, len(body))
		w.Write(append(body, '\n'))
		changed = append(changed, i)
		mark++
	}
	fmt.Fprintf(w, "commit refs/heads/main\nmark :%d\ncommitter b <b@x> 1700000100 +0000\ndata 6\nsecond\nfrom :%d\n", mark, first)
	for j, i := range changed {
		fmt.Fprintf(w, "M 100644 :%d %s\n", first+1+j, names[i])
	}
	_, err := w.Write([]byte("\n"))
	return err
}

// BenchmarkPushScanPack measures the scanner alone over the ~100 MiB pack, in
// each mode, against a few dozen values the run holds.
func BenchmarkPushScanPack(b *testing.B) {
	pack := benchmarkPack(b)
	secrets := testSecrets()
	for i := 0; i < 40; i++ {
		secrets = append(secrets, ScanSecret{Value: hex.EncodeToString([]byte(fmt.Sprintf("bench-value-%04d-%s", i, testSecret)))})
	}
	for _, mode := range []ScanMode{ScanValues, ScanShapes} {
		b.Run(string(mode), func(b *testing.B) {
			b.SetBytes(int64(len(pack)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				src := newPackSource(bytes.NewReader(pack), func([]byte) error { return nil })
				sc := newPackScanner(src, 20, newMatcher(secrets), mode == ScanShapes, ScanLimits{})
				if err := sc.scan(nil); err != nil || len(sc.findings) != 0 {
					b.Fatalf("scan: %v %d findings", err, len(sc.findings))
				}
				if i == 0 {
					b.ReportMetric(float64(sc.inflated)/(1<<20), "inflated-MiB")
					b.ReportMetric(float64(sc.objects), "objects")
				}
			}
		})
	}
}

// BenchmarkPushThroughTheProxy pushes the ~100 MiB pack through a real proxy to
// a forge that reads it and answers, with the scan off and on: the difference
// is what the scan costs a push.
func BenchmarkPushThroughTheProxy(b *testing.B) {
	pack := benchmarkPack(b)
	forge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", receiveResultMediaType)
		w.WriteHeader(http.StatusOK)
	}))
	defer forge.Close()

	var body bytes.Buffer
	_ = writePkt(&body, []byte(zeroSHA+" "+strings.Repeat("a", 40)+" refs/heads/cloop/bench\x00report-status side-band-64k"))
	_ = writeFlush(&body)
	body.Write(pack)

	for _, mode := range []ScanMode{ScanOff, ScanValues, ScanShapes} {
		b.Run(string(mode), func(b *testing.B) {
			proxySrv := httptest.NewUnstartedServer(nil)
			proxySrv.StartTLS()
			defer proxySrv.Close()
			reg, err := NewRegistry(proxySrv.URL)
			if err != nil {
				b.Fatal(err)
			}
			px, err := New(reg, Options{Transport: forge.Client().Transport, PushScan: func(*Session) PushScan {
				return PushScan{Mode: mode, Secrets: testSecrets()}
			}})
			if err != nil {
				b.Fatal(err)
			}
			proxySrv.Config.Handler = px
			m, err := reg.Mint(MintRequest{
				Upstream: forge.URL + "/acme/tool.git", Credential: Credential{Username: "u", Password: "forge-token-for-bench"},
				Policy: WriteBackPolicy(),
			})
			if err != nil {
				b.Fatal(err)
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			b.SetBytes(int64(body.Len()))
			for i := 0; i < b.N; i++ {
				req, _ := http.NewRequest(http.MethodPost, m.RepoURL+"/git-receive-pack", bytes.NewReader(body.Bytes()))
				req.SetBasicAuth(m.Session.ID, m.Token)
				req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
				resp, err := client.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					b.Fatalf("status %d", resp.StatusCode)
				}
			}
		})
	}
}
