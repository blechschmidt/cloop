package container

// sandbox_test.go covers the per-project sandbox path: image override, digest
// pinning, derived-image builds, workspace-relative mounts, and the
// one-directional network narrowing.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// --- pure: request construction ----------------------------------------

func TestBuildRequest_SandboxMounts(t *testing.T) {
	// AllowRootUser only because the suite may run as root over a root-owned
	// t.TempDir(); the UID policy this waives is asserted in its own tests.
	ex := fakeExecutor(t, Options{AllowRootUser: true})
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, ".cache", "pip"))

	req, err := ex.buildRequest(executor.Spec{
		Argv:   []string{"/bin/true"},
		Mounts: []executor.SpecMount{{Source: ".cache/pip", Target: "/home/agent/.cache/pip", ReadOnly: true}},
	}, mustAbs(dir), nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if len(req.ExtraMounts) != 1 {
		t.Fatalf("ExtraMounts = %+v", req.ExtraMounts)
	}
	m := req.ExtraMounts[0]
	if !strings.HasSuffix(m.HostPath, filepath.Join(".cache", "pip")) {
		t.Errorf("HostPath = %q, want it under the workspace", m.HostPath)
	}
	if m.TargetPath != "/home/agent/.cache/pip" || !m.ReadOnly {
		t.Errorf("mount = %+v", m)
	}

	built, err := buildRunArgs(req)
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	if !argvHasPair(built.Args, "--volume", m.String()) {
		t.Fatalf("the mount did not reach argv: %v", built.Args)
	}
}

// TestBuildRequest_MountCannotEscapeViaSymlink is the check the syntactic
// validator cannot make: "cache" contains no "..", but if it is a symlink to
// /etc the resolved bind source is outside the project entirely.
func TestBuildRequest_MountCannotEscapeViaSymlink(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	dir := mustAbs(t.TempDir())
	outside := mustAbs(t.TempDir())
	if err := os.Symlink(outside, filepath.Join(dir, "cache")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := ex.buildRequest(executor.Spec{
		Argv:   []string{"/bin/true"},
		Mounts: []executor.SpecMount{{Source: "cache", Target: "/cache"}},
	}, dir, nil)
	if err == nil {
		t.Fatal("a symlink pointing out of the workspace was accepted as a mount source")
	}
	if !strings.Contains(err.Error(), "outside the project workspace") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

func TestBuildRequest_RejectsEscapingMounts(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	dir := mustAbs(t.TempDir())
	for name, m := range map[string]executor.SpecMount{
		"dotdot":   {Source: "../etc", Target: "/x"},
		"absolute": {Source: "/etc/shadow", Target: "/x"},
		"colon":    {Source: "a:b", Target: "/x"},
		"root":     {Source: "a", Target: "/"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ex.buildRequest(executor.Spec{Argv: []string{"/bin/true"},
				Mounts: []executor.SpecMount{m}}, dir, nil)
			if err == nil {
				t.Fatalf("buildRequest accepted %+v", m)
			}
		})
	}
}

// TestBuildRequest_DisableNetworkNarrowsOnly is the security property: a
// repo-committed spec may take the network away and can never add one.
func TestBuildRequest_DisableNetworkNarrowsOnly(t *testing.T) {
	t.Run("narrows a networked executor", func(t *testing.T) {
		ex := fakeExecutor(t, Options{Network: NetworkBridge, AllowHosts: []string{"a:10.0.0.1"}})
		req, err := ex.buildRequest(executor.Spec{Argv: []string{"/bin/true"}, DisableNetwork: true},
			mustAbs(t.TempDir()), nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.Network != NetworkNone {
			t.Errorf("Network = %q, want %q", req.Network, NetworkNone)
		}
		// --add-host pins names on an interface that no longer exists; both
		// runtimes reject the combination.
		if len(req.AddHosts) != 0 {
			t.Errorf("AddHosts = %v, want dropped alongside the network", req.AddHosts)
		}
	})

	// There is no field that turns the network on, so the strongest available
	// statement is that a no-network executor stays that way whatever a spec
	// carries. Requirements.RequireNetworkEgress is what refuses this at
	// placement instead.
	t.Run("cannot widen a confined executor", func(t *testing.T) {
		ex := fakeExecutor(t, Options{Network: NetworkNone})
		req, err := ex.buildRequest(executor.Spec{Argv: []string{"/bin/true"}}, mustAbs(t.TempDir()), nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.Network != NetworkNone {
			t.Fatalf("Network = %q, want it left confined", req.Network)
		}
	})
}

func TestBuildRequest_SandboxHashBecomesALabel(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	req, err := ex.buildRequest(executor.Spec{Argv: []string{"/bin/true"}, SandboxHash: "abc123"},
		mustAbs(t.TempDir()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Labels[LabelSandboxHash] != "abc123" {
		t.Fatalf("labels = %v, want %s=abc123", req.Labels, LabelSandboxHash)
	}
}

func TestCapabilities_AdvertisesSandboxSupport(t *testing.T) {
	caps := fakeExecutor(t, Options{}).Capabilities()
	if !caps.SupportsImageOverride || !caps.SupportsSandboxBuild || !caps.SupportsSandboxMounts {
		t.Fatalf("the container driver implements all three but advertises %+v", caps)
	}
}

func TestBuildNetwork(t *testing.T) {
	cases := map[string]struct {
		opt  string
		spec executor.Spec
		want string
	}{
		"confined executor":  {NetworkNone, executor.Spec{}, NetworkNone},
		"spec disables":      {NetworkBridge, executor.Spec{DisableNetwork: true}, NetworkNone},
		"operator's network": {NetworkBridge, executor.Spec{}, NetworkBridge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ex := fakeExecutor(t, Options{Network: tc.opt})
			if got := ex.buildNetwork(tc.spec); got != tc.want {
				t.Fatalf("buildNetwork = %q, want %q — a setup: step must not get "+
					"egress the run itself would not have", got, tc.want)
			}
		})
	}
}

// --- pure: derived image -------------------------------------------------

func TestRenderDockerfile(t *testing.T) {
	base := ImageIdentity{Ref: "alpine:3.20", ID: "sha256:abc"}
	df, err := renderDockerfile("sha256:abc", base, "deadbeef", []string{"apk add git", "echo done"})
	if err != nil {
		t.Fatalf("renderDockerfile: %v", err)
	}
	if !strings.HasPrefix(df, "FROM sha256:abc\n") {
		t.Fatalf("FROM is not first or not pinned:\n%s", df)
	}
	if !strings.Contains(df, "RUN apk add git\n") || !strings.Contains(df, "RUN echo done\n") {
		t.Fatalf("setup commands missing:\n%s", df)
	}
	// A repo cannot bake its own files, environment or user into a cached
	// image that later tasks inherit.
	for _, forbidden := range []string{"COPY", "ADD", "USER", "ENV", "ENTRYPOINT"} {
		if strings.Contains(df, forbidden) {
			t.Fatalf("generated Dockerfile contains %s:\n%s", forbidden, df)
		}
	}
}

func TestRenderDockerfile_RefusesInjection(t *testing.T) {
	base := ImageIdentity{Ref: "alpine:3.20", ID: "sha256:abc"}
	for name, cmd := range map[string]string{
		"newline":         "echo hi\nFROM evil",
		"carriage return": "echo hi\rFROM evil",
		"blank":           "   ",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderDockerfile("x", base, "k", []string{cmd}); err == nil {
				t.Fatalf("renderDockerfile accepted %q", cmd)
			}
		})
	}
}

// TestDerivedKey_TracksContentNotTags is why the base digest is resolved before
// the key is computed: if the key were the tag, a moved base would serve a
// stale derived image forever.
func TestDerivedKey_TracksContentNotTags(t *testing.T) {
	setup := []string{"apk add git"}
	a := derivedKey(ImageIdentity{Ref: "alpine:3.20", ID: "sha256:aaa"}, setup)
	b := derivedKey(ImageIdentity{Ref: "alpine:3.20", ID: "sha256:bbb"}, setup)
	if a == b {
		t.Fatal("the key did not change when the base image content did")
	}
	if c := derivedKey(ImageIdentity{Ref: "alpine:3.20", ID: "sha256:aaa"}, []string{"apk add curl"}); a == c {
		t.Fatal("the key did not change when the setup commands did")
	}
	if a != derivedKey(ImageIdentity{Ref: "alpine:3.20", ID: "sha256:aaa"}, setup) {
		t.Fatal("the key is not deterministic")
	}
}

func TestImageIdentity_Pinned(t *testing.T) {
	cases := map[string]struct {
		id   ImageIdentity
		want string
	}{
		"repo digest wins": {
			ImageIdentity{Ref: "alpine:3.20", RepoDigest: "alpine@sha256:aa", ID: "sha256:bb"},
			"alpine@sha256:aa",
		},
		// Not the bare ID: it resolves, but produces a container whose image
		// field is a hash with no repository, so nothing downstream can say
		// what ran.
		"falls back to the ref": {
			ImageIdentity{Ref: "localhost/cloop-sandbox:abc", ID: "sha256:bb"},
			"localhost/cloop-sandbox:abc",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.id.Pinned(); got != tc.want {
				t.Fatalf("Pinned() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- integration: needs a real runtime -----------------------------------

// TestInspectImage_ResolvesADigest proves the pin is real rather than echoed.
func TestInspectImage_ResolvesADigest(t *testing.T) {
	rt := requireRuntime(t)
	image := requireImage(t, rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	id, err := InspectImage(ctx, rt, image)
	if err != nil {
		t.Fatalf("InspectImage: %v", err)
	}
	if !strings.HasPrefix(id.ID, "sha256:") {
		t.Fatalf("ID = %q, want a sha256 content id", id.ID)
	}
	if id.RepoDigest != "" && !strings.Contains(id.RepoDigest, "@sha256:") {
		t.Fatalf("RepoDigest = %q, not a digest reference", id.RepoDigest)
	}
	// Whatever we got must still resolve to the same image.
	again, err := InspectImage(ctx, rt, id.Pinned())
	if err != nil {
		t.Fatalf("the pinned reference %q does not resolve: %v", id.Pinned(), err)
	}
	if again.ID != id.ID {
		t.Fatalf("the pin resolves to a different image: %q vs %q", again.ID, id.ID)
	}
}

func TestInspectImage_MissingImageNamesThePull(t *testing.T) {
	rt := requireRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := InspectImage(ctx, rt, "localhost/cloop-does-not-exist:v0")
	if err == nil {
		t.Fatal("InspectImage on a missing image = nil")
	}
	if !strings.Contains(err.Error(), "pull") {
		t.Fatalf("error does not name the fix: %v", err)
	}
}

// TestSandboxImage_PinsTheOverride: the spec names a tag, the handle records a
// digest. That difference is the whole reproducibility claim.
func TestSandboxImage_PinsTheOverride(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	image := requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	got, err := ex.sandboxImage(ctx, executor.Spec{Image: image})
	if err != nil {
		t.Fatalf("sandboxImage: %v", err)
	}
	if got.Ref != image {
		t.Fatalf("Ref = %q, want the requested %q", got.Ref, image)
	}
	if got.ID == "" {
		t.Fatal("no content id resolved")
	}
}

// TestSandboxImage_BuildsAndCachesSetup exercises the derived-image path end to
// end: the first call builds, the second must hit the cache rather than
// rebuilding, and the result must actually contain what setup installed.
func TestSandboxImage_BuildsAndCachesSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("builds an image; skipped under -short")
	}
	ex := newTestExecutor(t, "alpine:3.20", nil)
	image := requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// A setup step that needs no network, so the test does not depend on
	// egress — and neither does the build, which runs with --network none
	// because the spec asks for no egress.
	spec := executor.Spec{
		Image:         image,
		SetupCommands: []string{"mkdir -p /opt/marker && echo built-by-cloop > /opt/marker/id"},
	}

	built, err := ex.sandboxImage(ctx, spec)
	if err != nil {
		t.Fatalf("first sandboxImage (build): %v", err)
	}
	t.Cleanup(func() { ex.removeImage(context.Background(), built.Ref) })

	if !strings.HasPrefix(built.Ref, DerivedImagePrefix+":") {
		t.Fatalf("Ref = %q, want a %s tag", built.Ref, DerivedImagePrefix)
	}

	// Cache hit: same inputs, same tag, and fast.
	start := time.Now()
	again, err := ex.sandboxImage(ctx, spec)
	if err != nil {
		t.Fatalf("second sandboxImage (cache): %v", err)
	}
	if again.Ref != built.Ref || again.ID != built.ID {
		t.Fatalf("the cache produced a different image: %q/%q vs %q/%q",
			again.Ref, again.ID, built.Ref, built.ID)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("the cached lookup took %s — setup is being re-run per workload", elapsed)
	}

	// The setup actually ran, and Start uses the derived image.
	res, err := runInSandbox(t, ex, t.TempDir(), []string{"/bin/cat", "/opt/marker/id"}, nil)
	if err == nil {
		t.Fatal("the base image should not contain the marker; the test is not proving anything")
	}
	res, err = executor.Run(ctx, ex, executor.Spec{
		WorkDir:       t.TempDir(),
		Argv:          []string{"/bin/cat", "/opt/marker/id"},
		Image:         image,
		SetupCommands: spec.SetupCommands,
	})
	if err != nil {
		t.Fatalf("running under the derived image: %v (output %q)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "built-by-cloop") {
		t.Fatalf("setup output missing; got %q", res.Output)
	}
	// The handle names the derived image. Asserted by resolving it rather than
	// by prefix-matching the tag: podman gives a locally-built image a repo
	// digest, so Pinned() legitimately returns
	// "localhost/cloop-sandbox@sha256:…" instead of the tag — a stronger pin,
	// and one a prefix check would have called a failure.
	if !strings.HasPrefix(res.Handle.Image, DerivedImagePrefix) {
		t.Fatalf("Handle.Image = %q, want a %s reference", res.Handle.Image, DerivedImagePrefix)
	}
	ran, err := InspectImage(ctx, ex.rt, res.Handle.Image)
	if err != nil {
		t.Fatalf("the recorded image %q does not resolve: %v", res.Handle.Image, err)
	}
	if ran.ID != built.ID {
		t.Fatalf("the workload ran %q, not the image the setup built (%q)", ran.ID, built.ID)
	}
}

// TestStart_HandleRecordsThePin closes the loop the artifact depends on.
func TestStart_HandleRecordsThePin(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	image := requireImage(t, ex.rt, "alpine:3.20")

	res, err := runInSandbox(t, ex, t.TempDir(), []string{"/bin/true"}, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Handle.Image == "" {
		t.Fatal("Handle.Image is empty — the artifact would record no environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, err := InspectImage(ctx, ex.rt, image)
	if err != nil {
		t.Fatal(err)
	}
	if res.Handle.Image != want.Pinned() {
		t.Fatalf("Handle.Image = %q, want the pinned %q", res.Handle.Image, want.Pinned())
	}
}

// TestStart_SandboxMountIsVisible proves the mount reaches the workload rather
// than only reaching argv.
func TestStart_SandboxMountIsVisible(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "vendor"))
	if err := os.WriteFile(filepath.Join(dir, "vendor", "hello.txt"), []byte("mounted\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir: dir,
		Argv:    []string{"/bin/cat", "/opt/vendor/hello.txt"},
		Mounts:  []executor.SpecMount{{Source: "vendor", Target: "/opt/vendor", ReadOnly: true}},
	})
	if err != nil {
		t.Fatalf("run: %v (output %q)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "mounted") {
		t.Fatalf("the mount is not visible inside the sandbox; got %q", res.Output)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// argvHasPair reports whether argv contains flag immediately followed by value.
func argvHasPair(argv []string, flag, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == value {
			return true
		}
	}
	return false
}
