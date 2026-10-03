package audit

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/env"
	"github.com/blechschmidt/cloop/pkg/redact/redacttest"
)

func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}

// TestLeakScanCatchesWhatAChunkBoundaryCuts: the history is scanned a window
// at a time so a large one cannot exhaust memory, which makes every window
// boundary a place a credential could hide in plain sight — half in one
// window, half in the next, matched by neither. The overlap exists to close
// that, and this places a token and a configured secret across the boundary
// at its first byte, its middle and its last.
func TestLeakScanCatchesWhatAChunkBoundaryCuts(t *testing.T) {
	r := rand.New(rand.NewPCG(redacttest.Seed, 3))
	tok := redacttest.GitHubLongFormToken(r, "ghs_", 0)
	const configured = "configured-secret-value-0123456789abcdef"

	for _, secret := range []string{tok, configured} {
		for _, into := range []int{1, len(secret) / 2, len(secret) - 1} {
			// The secret starts `into` bytes before the end of the first
			// window, so the boundary falls inside it.
			prefix := strings.Repeat("=", scanChunk-into-1) + " "
			stream := prefix + secret + " " + strings.Repeat("=", 4096)

			scan := newLeakScan([]string{configured})
			// A reader that hands over half of what is asked each time:
			// the boundary must not depend on reads arriving whole.
			if err := scan.readFrom(iotest.HalfReader(strings.NewReader(stream))); err != nil {
				t.Fatalf("readFrom: %v", err)
			}
			if !scan.found() {
				t.Errorf("a secret cut %d bytes into itself by the window boundary was not found", into)
			} else if secret == tok && !scan.detectors["github-token-long"] {
				t.Errorf("the long-form token cut %d bytes in was found, but not as one: %v", into, scan.names())
			}
		}
	}
}

// TestLeakScanOfOrdinaryHistoryIsClean: more than one window of ordinary diff
// output, so an overlap bug that re-joined text into a false shape would show.
// One boundary is enough to show it; each further window only costs time
// under -race.
func TestLeakScanOfOrdinaryHistoryIsClean(t *testing.T) {
	var b strings.Builder
	for b.Len() < scanChunk+4*scanOverlap {
		for _, n := range redacttest.Negatives() {
			b.WriteString(n.Text)
			b.WriteString("\n")
		}
	}
	scan := newLeakScan(nil)
	if err := scan.readFrom(strings.NewReader(b.String())); err != nil {
		t.Fatalf("readFrom: %v", err)
	}
	if scan.found() {
		t.Errorf("ordinary output was reported as a leak: %v", scan.labels())
	}
}

// TestArtifactScanReportsShapesAndConfiguredValuesSeparately: the two have
// different remedies, so one must not be folded into the other, and a symlink
// in an artifact directory must not make the audit read what it points at.
func TestArtifactScanReportsShapesAndConfiguredValuesSeparately(t *testing.T) {
	work := t.TempDir()
	tasks := filepath.Join(work, ".cloop", "tasks")
	live := filepath.Join(work, ".cloop", "artifacts")
	for _, d := range []string{tasks, live} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const envSecret = "env-secret-value-0123456789"
	if err := env.Save(work, []env.Var{{Key: "DEPLOY_TOKEN", Value: envSecret, Secret: true}}); err != nil {
		t.Fatalf("env.Save: %v", err)
	}

	pat := "cloop_pat_0123456789abcdef_" + strings.Repeat("ab", 32)
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(tasks, "7-call-the-hub.md"), "ran: curl -H 'Authorization: Bearer "+pat+"' https://hub/api/state\n")
	write(filepath.Join(live, "8_output.txt"), "exported DEPLOY_TOKEN="+envSecret+"\n")
	write(filepath.Join(live, "9_output.txt"), "all tests passed\n")

	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	write(outside, "ghp_"+strings.Repeat("Q1", 18)+"\n")
	if err := os.Symlink(outside, filepath.Join(tasks, "10-planted.md")); err != nil {
		t.Fatal(err)
	}

	var got []Finding
	checkSecretsInArtifacts(work, func(f Finding) { got = append(got, f) })

	byName := map[string]Finding{}
	for _, f := range got {
		byName[f.Name] = f
	}
	shapes, values := byName["Credentials in task artifacts"], byName["Env secrets in task artifacts"]
	if shapes.Level != Fail || !strings.Contains(shapes.Message, ".cloop/tasks/7-call-the-hub.md (cloop API token") {
		t.Errorf("credential shapes: %+v", shapes)
	}
	if values.Level != Fail || !strings.Contains(values.Message, ".cloop/artifacts/8_output.txt") ||
		strings.Contains(values.Message, "7-call-the-hub") {
		t.Errorf("configured values: %+v", values)
	}
	for _, f := range got {
		if strings.Contains(f.Message, "10-planted") {
			t.Errorf("the audit followed a symlink out of the artifact directory: %+v", f)
		}
		for _, leaked := range []string{pat, envSecret} {
			if strings.Contains(f.Message+f.Fix, leaked) {
				t.Errorf("a finding prints the credential it found: %+v", f)
			}
		}
	}
}

// TestArtifactScanReachesSubdirectories: task output can come to rest below
// the top of an artifact directory, and a scan of the top alone reported such
// a tree clean.
func TestArtifactScanReachesSubdirectories(t *testing.T) {
	work := t.TempDir()
	nested := filepath.Join(work, ".cloop", "artifacts", "feature-checkout", "logs")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	pat := "cloop_pat_0123456789abcdef_" + strings.Repeat("c4", 32)
	if err := os.WriteFile(filepath.Join(nested, "7_output.txt"), []byte("Authorization: Bearer "+pat+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var shapes Finding
	checkSecretsInArtifacts(work, func(f Finding) {
		if f.Name == "Credentials in task artifacts" {
			shapes = f
		}
	})
	if shapes.Level != Fail || !strings.Contains(shapes.Message, ".cloop/artifacts/feature-checkout/logs/7_output.txt") {
		t.Errorf("a credential in a nested artifact was not reported: %+v", shapes)
	}
}

// TestOpenArtifactRefusesWhatIsNotARegularFile: between the walk that found a
// regular file and the open, an agent that can write the directory can swap
// it for a FIFO, which would block the open until a writer came, or for a
// symlink, which would be followed out of the directory. The open refuses
// both, without blocking.
func TestOpenArtifactRefusesWhatIsNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("not an artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		done := make(chan error, 1)
		go func() {
			f, err := openArtifact(path)
			if err == nil {
				f.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("openArtifact(%s) opened what is not a regular file", filepath.Base(path))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("openArtifact(%s) blocked", filepath.Base(path))
		}
	}
	regular := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(regular, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openArtifact(regular)
	if err != nil {
		t.Fatalf("openArtifact refused a regular file: %v", err)
	}
	f.Close()
}
