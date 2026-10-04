package upgrade

// edge_test.go covers staging an edge build (Task 20376): what a device must
// prove before an "edge:<commit>" target leaves a binary on disk, and what the
// hub learns about a commit that has no build yet.
//
// The assets are served by httptest and verified by internal/cosigntest, a
// stand-in cosign whose verdict depends on the signer recorded in each bundle
// — so these tests can sign "as" edge.yml on main, release.yml on a tag, or a
// workflow on some other branch, and assert which ones are accepted.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/cosigntest"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

const (
	commitA = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"
	commitB = "f25fd6913d5cc2b0e3b8a9d1f0c4e7a2b6d8e0f1"
)

// tarGz builds an archive holding a "cloop" file with the given contents, the
// way scripts/build-release.sh does.
func tarGz(t *testing.T, binary string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{{"./cloop", binary}, {"./README.md", "readme"}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// edgeRelease is a stand-in for the edge release's download endpoint.
type edgeRelease struct {
	files map[string][]byte
	srv   *httptest.Server
}

func newEdgeRelease(t *testing.T) *edgeRelease {
	t.Helper()
	er := &edgeRelease{files: map[string][]byte{}}
	er.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := er.files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(er.srv.Close)
	return er
}

// publish puts commit's build up, every asset signed by san, the binary
// inside the archive reading binary. It returns the manifest it published.
func (er *edgeRelease) publish(t *testing.T, commit, san, binary string) EdgeManifest {
	t.Helper()
	archive := tarGz(t, binary)
	name := EdgeArchiveName(commit, runtime.GOOS, runtime.GOARCH)
	m := EdgeManifest{
		Schema: EdgeManifestSchema, Commit: commit, Version: EdgeVersion(commit), Protocol: 17,
		Archives: map[string]string{name: sha256Hex(archive)},
	}
	er.put(t, name, archive, san)
	er.putManifest(t, commit, m, san)
	return m
}

func (er *edgeRelease) putManifest(t *testing.T, commit string, m EdgeManifest, san string) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	er.put(t, EdgeManifestName(commit), data, san)
}

func (er *edgeRelease) put(t *testing.T, name string, data []byte, san string) {
	t.Helper()
	er.files[name] = data
	er.files[provenance.BundleNameFor(name)] = cosigntest.Bundle(san, data)
}

func (er *edgeRelease) opts(t *testing.T) Options {
	return Options{Verifier: &provenance.Verifier{Binary: cosigntest.Install(t)}, EdgeBaseURL: er.srv.URL}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestStageEdgeStagesAVerifiedBuild is the path that works: edge.yml on main
// signed everything, the manifest names the commit, the archive hashes to what
// it lists. The binary lands in destDir, and Staged says what it must report.
func TestStageEdgeStagesAVerifiedBuild(t *testing.T) {
	er := newEdgeRelease(t)
	m := er.publish(t, commitA, cosigntest.Edge, "the edge binary")

	dest := t.TempDir()
	staged, err := StageEdge(EdgeTarget(commitA), dest, er.opts(t), nil)
	if err != nil {
		t.Fatalf("StageEdge: %v", err)
	}
	got, err := os.ReadFile(staged.BinaryPath)
	if err != nil || string(got) != "the edge binary" {
		t.Fatalf("staged binary = %q, %v", got, err)
	}
	if !staged.ProvenanceVerified || staged.Channel != provenance.ChannelEdge {
		t.Errorf("staged = %+v, want verified on the edge channel", staged)
	}
	if staged.Version != m.Version || staged.Protocol != 17 || staged.Commit != commitA {
		t.Errorf("staged = %+v, want version %s, protocol 17, commit %s", staged, m.Version, commitA)
	}
	if staged.Tag != "edge:"+commitA {
		t.Errorf("staged.Tag = %q", staged.Tag)
	}
}

// TestStageEdgeRefusesEveryOtherSigner is the edge half of the identity
// matrix through the real staging path: only edge.yml on main may sign an edge
// build. A release signature, edge.yml on another branch or a tag, another
// workflow on main, and a fork are all refused — and nothing is staged.
func TestStageEdgeRefusesEveryOtherSigner(t *testing.T) {
	for name, san := range map[string]string{
		"release.yml on a tag": cosigntest.Release,
		"edge.yml on a branch": cosigntest.EdgeOtherBranch,
		"edge.yml on a tag":    cosigntest.EdgeOnTag,
		"ci.yml on main":       cosigntest.CIOnMain,
		"release.yml on main":  cosigntest.ReleaseOnMain,
		"a fork's edge.yml":    cosigntest.ForkEdge,
	} {
		t.Run(name, func(t *testing.T) {
			er := newEdgeRelease(t)
			er.publish(t, commitA, san, "binary")
			dest := t.TempDir()
			_, err := StageEdge(EdgeTarget(commitA), dest, er.opts(t), nil)
			if !errors.Is(err, provenance.ErrUnverified) {
				t.Fatalf("an edge build signed by %s gave %v, want ErrUnverified", name, err)
			}
			if entries, _ := os.ReadDir(dest); len(entries) != 0 {
				t.Errorf("something was staged despite the refusal: %v", entries)
			}
		})
	}
}

// TestStageReleaseRefusesAnEdgeSignature is the other half: the edge identity
// never vouches for a release target, so a release whose bundles were made by
// edge.yml is refused by the release path.
func TestStageReleaseRefusesAnEdgeSignature(t *testing.T) {
	archive := []byte("archive bytes")
	rel := releaseServing(t, map[string]string{
		testAsset:                           string(archive),
		provenance.BundleNameFor(testAsset): string(cosigntest.Bundle(cosigntest.Edge, archive)),
	})
	opts := Options{Verifier: &provenance.Verifier{Binary: cosigntest.Install(t)}}
	err := verifyArchiveProvenance(rel, testAsset, archive, opts, func(string) {})
	if !errors.Is(err, provenance.ErrUnverified) {
		t.Fatalf("a release signed by the edge workflow gave %v, want ErrUnverified", err)
	}

	// And the same archive signed by the release workflow is accepted, so the
	// refusal above is about the signer and nothing else.
	rel = releaseServing(t, map[string]string{
		testAsset:                           string(archive),
		provenance.BundleNameFor(testAsset): string(cosigntest.Bundle(cosigntest.Release, archive)),
	})
	if err := verifyArchiveProvenance(rel, testAsset, archive, opts, func(string) {}); err != nil {
		t.Fatalf("a release signed by release.yml on a tag was refused: %v", err)
	}
}

// TestStageEdgeRefusesAManifestForAnotherCommit: a genuine, signed manifest of
// commit B re-uploaded under commit A's name. The signature verifies — it is a
// real edge build — and the commit inside it is what refuses it.
func TestStageEdgeRefusesAManifestForAnotherCommit(t *testing.T) {
	er := newEdgeRelease(t)
	mB := er.publish(t, commitB, cosigntest.Edge, "binary B")
	er.putManifest(t, commitA, mB, cosigntest.Edge)

	_, err := StageEdge(EdgeTarget(commitA), t.TempDir(), er.opts(t), nil)
	if !errors.Is(err, ErrEdgeManifest) {
		t.Fatalf("commit B's manifest under A's name gave %v, want ErrEdgeManifest", err)
	}
}

// TestStageEdgeRefusesASwappedArchive: commit A's manifest, and in place of
// A's archive a genuine signed archive of an older build. Its signature is
// valid; the hash the signed manifest lists for A is what refuses it.
func TestStageEdgeRefusesASwappedArchive(t *testing.T) {
	er := newEdgeRelease(t)
	er.publish(t, commitA, cosigntest.Edge, "binary A")
	er.put(t, EdgeArchiveName(commitA, runtime.GOOS, runtime.GOARCH), tarGz(t, "older binary"), cosigntest.Edge)

	_, err := StageEdge(EdgeTarget(commitA), t.TempDir(), er.opts(t), nil)
	if !errors.Is(err, ErrEdgeManifest) {
		t.Fatalf("a swapped archive gave %v, want ErrEdgeManifest", err)
	}
}

// TestStageEdgeRefusals collects the remaining ways an edge target is refused
// before anything is staged.
func TestStageEdgeRefusals(t *testing.T) {
	t.Run("no bundle", func(t *testing.T) {
		er := newEdgeRelease(t)
		er.publish(t, commitA, cosigntest.Edge, "binary")
		delete(er.files, provenance.BundleNameFor(EdgeArchiveName(commitA, runtime.GOOS, runtime.GOARCH)))
		_, err := StageEdge(EdgeTarget(commitA), t.TempDir(), er.opts(t), nil)
		if !errors.Is(err, provenance.ErrBundleMissing) {
			t.Fatalf("got %v, want ErrBundleMissing", err)
		}
	})
	t.Run("not published", func(t *testing.T) {
		er := newEdgeRelease(t)
		_, err := StageEdge(EdgeTarget(commitA), t.TempDir(), er.opts(t), nil)
		if !errors.Is(err, ErrEdgeNotPublished) {
			t.Fatalf("got %v, want ErrEdgeNotPublished", err)
		}
	})
	t.Run("no build for this platform", func(t *testing.T) {
		er := newEdgeRelease(t)
		m := er.publish(t, commitA, cosigntest.Edge, "binary")
		m.Archives = map[string]string{EdgeArchiveName(commitA, "plan9", "mips"): strings.Repeat("0", 64)}
		er.putManifest(t, commitA, m, cosigntest.Edge)
		_, err := StageEdge(EdgeTarget(commitA), t.TempDir(), er.opts(t), nil)
		if !errors.Is(err, ErrEdgeNotPublished) || !strings.Contains(err.Error(), runtime.GOOS+"/"+runtime.GOARCH) {
			t.Fatalf("got %v, want a refusal naming this platform", err)
		}
	})
	t.Run("skip verify", func(t *testing.T) {
		er := newEdgeRelease(t)
		er.publish(t, commitA, cosigntest.Edge, "binary")
		opts := er.opts(t)
		opts.SkipVerify = true
		if _, err := StageEdge(EdgeTarget(commitA), t.TempDir(), opts, nil); err == nil {
			t.Fatal("an edge build was staged with verification switched off")
		}
	})
	t.Run("no cosign", func(t *testing.T) {
		er := newEdgeRelease(t)
		er.publish(t, commitA, cosigntest.Edge, "binary")
		opts := er.opts(t)
		opts.Verifier = &provenance.Verifier{Binary: t.TempDir() + "/not-installed"}
		_, err := StageEdge(EdgeTarget(commitA), t.TempDir(), opts, nil)
		if !errors.Is(err, provenance.ErrCosignMissing) {
			t.Fatalf("got %v, want ErrCosignMissing", err)
		}
	})
	t.Run("malformed target", func(t *testing.T) {
		for _, target := range []string{"v0.0.4", "edge:", "edge:xyz1234", "edge:abc", "edge:" + commitA + "0"} {
			if _, err := StageEdge(target, t.TempDir(), Options{}, nil); !errors.Is(err, ErrEdgeTarget) {
				t.Errorf("StageEdge(%q) = %v, want ErrEdgeTarget", target, err)
			}
		}
	})
}

// TestEdgeManifestValidate pins what a manifest must say.
func TestEdgeManifestValidate(t *testing.T) {
	good := EdgeManifest{
		Schema: 1, Commit: commitA, Version: "dev+ga0f3870", Protocol: 17,
		Archives: map[string]string{EdgeArchiveName(commitA, "linux", "amd64"): strings.Repeat("ab", 32)},
	}
	if err := good.Validate(commitA); err != nil {
		t.Fatalf("a good manifest was refused: %v", err)
	}
	longer := good
	longer.Version = "dev+ga0f38702"
	if err := longer.Validate(commitA); err != nil {
		t.Errorf("a longer abbreviation of the same commit was refused: %v", err)
	}
	for name, mutate := range map[string]func(*EdgeManifest){
		"schema":          func(m *EdgeManifest) { m.Schema = 2 },
		"other commit":    func(m *EdgeManifest) { m.Commit = commitB },
		"other version":   func(m *EdgeManifest) { m.Version = "dev+gf25fd69" },
		"release version": func(m *EdgeManifest) { m.Version = "v0.0.4" },
		"short version":   func(m *EdgeManifest) { m.Version = "dev+ga0f38" },
		"no protocol":     func(m *EdgeManifest) { m.Protocol = 0 },
		"no archives":     func(m *EdgeManifest) { m.Archives = nil },
		"foreign archive": func(m *EdgeManifest) {
			m.Archives = map[string]string{"cloop_linux_amd64.tar.gz": strings.Repeat("ab", 32)}
		},
		"no digest": func(m *EdgeManifest) {
			m.Archives = map[string]string{EdgeArchiveName(commitA, "linux", "amd64"): "abc"}
		},
	} {
		m := good
		m.Archives = map[string]string{}
		for k, v := range good.Archives {
			m.Archives[k] = v
		}
		mutate(&m)
		if err := m.Validate(commitA); !errors.Is(err, ErrEdgeManifest) {
			t.Errorf("%s: Validate = %v, want ErrEdgeManifest", name, err)
		}
	}
}

func TestParseEdgeTargetAndCommitHelpers(t *testing.T) {
	if c, err := ParseEdgeTarget("edge:A0F3870"); err != nil || c != "a0f3870" {
		t.Errorf("ParseEdgeTarget = %q, %v", c, err)
	}
	if c, ok := VersionCommit("dev+ga0f3870"); !ok || c != "a0f3870" {
		t.Errorf("VersionCommit = %q, %t", c, ok)
	}
	for _, v := range []string{"v0.0.4", "dev", "dev+ga0f3870.dirty", "dev+gxyz", ""} {
		if _, ok := VersionCommit(v); ok {
			t.Errorf("VersionCommit(%q) named a commit", v)
		}
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"dev+ga0f3870", commitA, true},
		{"dev+ga0f38702", "dev+ga0f3870", true},
		{"dev+ga0f3870", "dev+gf25fd69", false},
		{"a0f3870", commitA, true},
		{"a0f38", commitA, false},
		{"v0.0.4", "v0.0.4", false},
	} {
		if got := SameCommit(c.a, c.b); got != c.want {
			t.Errorf("SameCommit(%q, %q) = %t, want %t", c.a, c.b, got, c.want)
		}
	}
	if EdgeVersion(commitA) != "dev+ga0f3870" {
		t.Errorf("EdgeVersion = %q", EdgeVersion(commitA))
	}
}

// githubStandIn answers the two API calls ResolveEdgeBuild makes.
func githubStandIn(t *testing.T, commits map[string]string, runs []workflowRun) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/commits/"):
			short := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			for full := range commits {
				if strings.HasPrefix(full, short) {
					fmt.Fprint(w, full)
					return
				}
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
		case strings.HasSuffix(r.URL.Path, "/actions/runs"):
			if _, ok := commits[r.URL.Query().Get("head_sha")]; !ok {
				t.Errorf("runs were asked for an unknown commit: %s", r.URL.RawQuery)
			}
			var ci []workflowRun
			for _, run := range runs {
				if strings.Contains(run.Path, "ci.yml") {
					ci = append(ci, run)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": ci})
		case strings.HasSuffix(r.URL.Path, "/actions/workflows/edge.yml/runs"):
			var edge []workflowRun
			for _, run := range runs {
				if strings.Contains(run.Path, "edge.yml") {
					edge = append(edge, run)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": edge})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	prev := githubAPI
	githubAPI = srv.URL
	t.Cleanup(func() { githubAPI = prev })
}

// TestResolveEdgeBuildSaysWhyABuildIsNotOffered walks every status the Upgrade
// dialog distinguishes.
func TestResolveEdgeBuildSaysWhyABuildIsNotOffered(t *testing.T) {
	ci := func(status, conclusion string) workflowRun {
		return workflowRun{Path: ".github/workflows/ci.yml", Event: "push", HeadBranch: "main",
			Status: status, Conclusion: conclusion, HTMLURL: "https://github.com/x/ci"}
	}
	// Filed under whatever main's head was, and found by the title naming
	// the commit it built; another commit's run is listed first and ignored.
	edge := func(status, conclusion string) workflowRun {
		return workflowRun{Path: ".github/workflows/edge.yml", Event: "workflow_run", HeadBranch: "main",
			Status: status, Conclusion: conclusion, HTMLURL: "https://github.com/x/edge",
			DisplayTitle: "Edge build of " + commitA}
	}
	otherEdge := workflowRun{Path: ".github/workflows/edge.yml", Event: "workflow_run", HeadBranch: "main",
		Status: "completed", Conclusion: "failure", HTMLURL: "https://github.com/x/other",
		DisplayTitle: "Edge build of " + commitB}
	known := map[string]string{commitA: ""}
	for _, c := range []struct {
		name    string
		version string
		publish bool
		runs    []workflowRun
		want    EdgeStatus
		says    string
	}{
		{"published", "dev+ga0f3870", true, nil, EdgePublished, "speaks protocol v17"},
		{"unpushed", "dev+g1234567", false, nil, EdgeUnpushed, "never pushed"},
		{"dirty", "dev+ga0f3870.dirty", false, nil, EdgeDirty, "uncommitted"},
		{"release", "v0.0.4", false, nil, EdgeNoCommit, "names no commit"},
		{"no CI run", "dev+ga0f3870", false, nil, EdgeNoCI, "no CI run on main"},
		{"CI running", "dev+ga0f3870", false, []workflowRun{ci("in_progress", "")}, EdgeCIRunning, "still running"},
		{"CI failed", "dev+ga0f3870", false, []workflowRun{ci("completed", "failure")}, EdgeCIFailed, "CI failed"},
		{"publishing", "dev+ga0f3870", false, []workflowRun{otherEdge, edge("in_progress", ""), ci("completed", "success")}, EdgePublishing, "has not published it yet"},
		{"edge not started", "dev+ga0f3870", false, []workflowRun{otherEdge, ci("completed", "success")}, EdgePublishing, "has not published it yet"},
		{"publish failed", "dev+ga0f3870", false, []workflowRun{edge("completed", "failure"), ci("completed", "success")}, EdgePublishFailed, "failed"},
		{"pruned", "dev+ga0f3870", false, []workflowRun{edge("completed", "success"), ci("completed", "success")}, EdgePruned, "pruned"},
	} {
		t.Run(c.name, func(t *testing.T) {
			githubStandIn(t, known, c.runs)
			er := newEdgeRelease(t)
			if c.publish {
				er.publish(t, commitA, cosigntest.Edge, "binary")
			}
			b := resolveEdgeBuild(context.Background(), er.srv.URL+"/", c.version, "")
			if b.Status != c.want {
				t.Fatalf("status = %s (%v), want %s", b.Status, b.Err, c.want)
			}
			if !strings.Contains(b.Reason(), c.says) {
				t.Errorf("reason %q does not say %q", b.Reason(), c.says)
			}
			if c.want == EdgePublished && (b.Target() != "edge:"+commitA || b.Manifest.Protocol != 17) {
				t.Errorf("published build: target %q, protocol %d", b.Target(), b.Manifest.Protocol)
			}
		})
	}
}
