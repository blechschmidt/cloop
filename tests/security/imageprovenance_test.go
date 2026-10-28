package security

// Guarantee 9b: cloop's own images run only as a digest verified against the
// workflow that publishes them (Task 20453).
//
// The image nearly every sandbox runs is cloop's own — the default,
// ghcr.io/blechschmidt/cloop-harness:latest — and before this guarantee it was
// the one image nothing checked: the project policy governs what a repository
// names, and an operator's image, the default included, was exempt from it. So
// whoever could push to that package decided what ran beside every lease's
// credentials on every hub that kept the default.
//
// The property, asked of the production paths of every executor that runs an
// image: once verification is on — executors.image_provenance: required — no
// sandbox runs one of cloop's images by tag. It runs the digest cosign verified,
// or it does not start. And whatever the setting, a signature present and
// wrong never starts, and a verified image is dispatched by its digest.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

const cloopDigest = "sha256:" + "3ad7a636d68631752784810d823b827a1747022840f3c8877af15decc831b213"

// cosignStandIn answers one verdict for every digest; a tag is never verified,
// as cosign verifies only what it is given by digest.
type cosignStandIn struct{ status imagepolicy.ProvenanceStatus }

func (c cosignStandIn) VerifyProvenance(_ context.Context, ref string) imagepolicy.ProvenanceVerdict {
	if !strings.Contains(ref, "@sha256:") {
		return imagepolicy.ProvenanceVerdict{Status: imagepolicy.ProvenanceUnverifiable, Detail: "a tag"}
	}
	return imagepolicy.ProvenanceVerdict{Status: c.status, Detail: string(c.status) + " by the stand-in"}
}

func (cosignStandIn) TrustRoot() (string, string) {
	return provenance.DefaultIssuer, provenance.ImagesIdentityRegexp
}

// dispatch is what one executor did with one way of choosing cloop's image:
// the reference the sandbox runs, or the refusal.
type dispatch struct {
	name string
	ref  string
	prov *imagepolicy.Provenance
	err  error
}

// cloopImageDispatches drives every executor kind, every way a cloop image is
// chosen, through its production path, with cosign answering status.
func cloopImageDispatches(t *testing.T, status imagepolicy.ProvenanceStatus) []dispatch {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the runtime stand-in is a POSIX shell script")
	}
	verifier := cosignStandIn{status: status}
	tag := executor.DefaultHarnessImage
	pinned := "ghcr.io/blechschmidt/cloop-harness@" + cloopDigest
	var out []dispatch

	// The container executor, over a store holding the default as a pull of
	// the tag leaves it.
	rt := storeStandIn(t, map[string]string{tag: `["` + pinned + `"]`, pinned: `["` + pinned + `"]`})
	for name, c := range map[string]struct {
		opts container.Options
		spec executor.Spec
	}{
		"container: the default":          {container.Options{VerifyOwnImages: true}, executor.Spec{}},
		"container: configured by tag":    {container.Options{VerifyOwnImages: true, Image: tag}, executor.Spec{}},
		"container: configured by digest": {container.Options{VerifyOwnImages: true, Image: pinned}, executor.Spec{}},
		"container: named by a project":   {container.Options{VerifyOwnImages: true, Image: "ghcr.io/acme/base:1"}, executor.Spec{Image: tag}},
	} {
		ref, prov, err := container.AuditSandboxImage(context.Background(), c.opts, rt, c.spec, verifier)
		out = append(out, dispatch{name, ref, prov, err})
	}

	// The Kubernetes executor, as the hub configures it: no store of its own
	// to resolve a tag in, so it asks the registry (Task 20457) — a stand-in
	// for ghcr.io here, as for the device below.
	ghcr := deviceTagResolver{tag: cloopDigest, "ghcr.io/acme/base:1": allowedDigest}
	for name, c := range map[string]struct {
		opts kubernetes.Options
		spec executor.Spec
	}{
		"kubernetes: the default":          {kubernetes.Options{VerifyOwnImages: true}, executor.Spec{Argv: []string{"cloop", "run"}}},
		"kubernetes: configured by tag":    {kubernetes.Options{VerifyOwnImages: true, Image: tag}, executor.Spec{Argv: []string{"cloop", "run"}}},
		"kubernetes: configured by digest": {kubernetes.Options{VerifyOwnImages: true, Image: pinned}, executor.Spec{Argv: []string{"cloop", "run"}}},
		"kubernetes: named by a project": {kubernetes.Options{VerifyOwnImages: true, Image: "ghcr.io/acme/base:1"},
			executor.Spec{Argv: []string{"cloop", "run"}, Image: tag}},
	} {
		c.opts.ResolveTags, c.opts.ImageResolver = true, ghcr
		ref, prov, err := kubernetes.AuditPodProvenance(context.Background(), c.opts, c.spec, verifier)
		out = append(out, dispatch{name, ref, prov, err})
	}

	// A device, whose store the hub cannot read: the tag is resolved at the
	// registry, and the start frame is what the device runs.
	for name, c := range map[string]struct {
		sandbox executor.SandboxSettings
		image   string
	}{
		"device: the default":        {executor.SandboxSettings{Mode: executor.SandboxModeContainer}, ""},
		"device: its sandbox image":  {executor.SandboxSettings{Mode: executor.SandboxModeContainer, Image: tag}, ""},
		"device: named by a project": {executor.SandboxSettings{Mode: executor.SandboxModeContainer, Image: "ghcr.io/acme/base:1"}, tag},
	} {
		ref, prov, err := deviceDispatch(t, c.sandbox, c.image, verifier)
		out = append(out, dispatch{name, ref, prov, err})
	}
	return out
}

// TestNoSandboxRunsACloopImageByTag is the guarantee: under required, every
// executor either runs one of cloop's images as the verified digest or refuses.
// Every executor resolves a tag — from its store, or at the registry for a
// device and, since Task 20457, a Kubernetes Pod — so every one runs pinned.
func TestNoSandboxRunsACloopImageByTag(t *testing.T) {
	prev := executor.SetImageProvenanceRequired(true)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })
	t.Cleanup(imagepolicy.ResetRecentProvenance)

	started := map[string]int{}
	for _, d := range cloopImageDispatches(t, imagepolicy.ProvenanceVerified) {
		kind, _, _ := strings.Cut(d.name, ":")
		if d.err != nil {
			var denied *imagepolicy.DenyError
			if !errors.As(d.err, &denied) || denied.Rule != imagepolicy.RuleProvenance {
				t.Errorf("%s: refused, but not by the provenance check: %v", d.name, d.err)
			}
			continue
		}
		started[kind]++
		if !imagepolicy.IsOwnImage(d.ref) || !strings.Contains(d.ref, "@"+cloopDigest) {
			t.Errorf("%s: the sandbox runs %q — one of cloop's images not pinned to the digest verified", d.name, d.ref)
		}
		if !d.prov.Verified() {
			t.Errorf("%s: ran with provenance %+v, not a verified digest", d.name, d.prov)
		}
	}
	// Not vacuous: every executor kind ran something verified.
	for _, kind := range []string{"container", "kubernetes", "device"} {
		if started[kind] == 0 {
			t.Errorf("no %s dispatch started, so the guarantee was not asked of it", kind)
		}
	}
	if started["container"] != 4 || started["device"] != 3 || started["kubernetes"] != 4 {
		t.Errorf("started %v; want every container, device and Kubernetes dispatch", started)
	}
}

// TestAWronglySignedCloopImageNeverRuns: whatever the setting.
func TestAWronglySignedCloopImageNeverRuns(t *testing.T) {
	prev := executor.SetImageProvenanceRequired(false)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	for _, d := range cloopImageDispatches(t, imagepolicy.ProvenanceMismatch) {
		if d.name == "kubernetes: the default" || d.name == "kubernetes: named by a project" {
			// A tag there is never verified, so no signature is ever found
			// wrong: it runs unverified, with the warning, under warn.
			continue
		}
		var denied *imagepolicy.DenyError
		if !errors.As(d.err, &denied) || denied.Rule != imagepolicy.RuleProvenance {
			t.Errorf("%s: a wrongly signed image of cloop's = %q, %v; want a refusal", d.name, d.ref, d.err)
		}
	}
}

// storeStandIn writes a runtime CLI whose store holds images — each reference
// with the repo digests `{{json .RepoDigests}}` prints — and returns its path.
func storeStandIn(t *testing.T, images map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	var b strings.Builder
	for ref, digests := range images {
		b.WriteString(ref + "\t" + digests + "\n")
	}
	if err := os.WriteFile(store, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
if [ "$1" = image ] && [ "$2" = inspect ]; then
  ref=; for a in "$@"; do ref=$a; done
  line=$(awk -F '\t' -v r="$ref" '$1 == r { print $2; exit }' '` + store + `')
  [ -n "$line" ] || { echo "Error: No such image: $ref" >&2; exit 1; }
  printf '%s\037sha256:` + strings.Repeat("cd", 32) + `\037{}\n' "$line"
  exit 0
fi
exit 1
`
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// deviceDispatch starts a workload on a device whose sandbox is s, through a
// real remote executor over the in-memory pipe, and returns the image the start
// frame told the device to run — "" when it named none and the device runs its
// own configured image.
func deviceDispatch(t *testing.T, s executor.SandboxSettings, image string,
	v imagepolicy.ProvenanceVerifier) (string, *imagepolicy.Provenance, error) {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{
		ID: pinningAgentID, Name: "edge",
		Sandbox:         func() (executor.SandboxSettings, error) { return s, nil },
		ImagePolicy:     func() (imagepolicy.Policy, error) { return imagepolicy.Policy{}, nil },
		ImageResolver:   deviceTagResolver{executor.DefaultHarnessImage: cloopDigest},
		VerifyOwnImages: true, ProvenanceVerifier: v,
	})
	if err != nil {
		t.Fatal(err)
	}
	cp, dev := remote.NewPipe(64)
	agent := &hostileAgent{t: t, conn: dev}
	accepted := make(chan error, 1)
	go func() {
		_, err := remote.Accept(context.Background(), cp, remote.AcceptOptions{
			Agent: remote.AgentRecord{AgentID: pinningAgentID}, Executor: ex,
		})
		accepted <- err
	}()
	agent.send(remote.TypeHello, "hello", "", remote.HelloPayload{
		ProtocolVersion: remote.ProtocolVersion, AgentID: pinningAgentID, Name: "edge",
		Capabilities: remote.AgentCapabilities{OS: "linux", Arch: "amd64"},
	})
	if f := agent.next(); f.Type != remote.TypeWelcome {
		t.Fatalf("handshake answered with %s", f.Type)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	type result struct {
		h   executor.Handle
		err error
	}
	done := make(chan result, 1)
	go func() {
		h, err := ex.Start(context.Background(), executor.Spec{Argv: []string{"true"}, WorkDir: "/tmp/project", Image: image})
		done <- result{h, err}
	}()
	frames := make(chan remote.Frame, 8)
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			f, err := dev.ReadFrame(ctx)
			cancel()
			if err != nil {
				close(frames)
				return
			}
			frames <- f
		}
	}()
	for {
		select {
		case res := <-done:
			return "", res.h.ImageProvenance, res.err
		case f, ok := <-frames:
			if !ok {
				res := <-done
				return "", res.h.ImageProvenance, res.err
			}
			if f.Type != remote.TypeStart {
				continue
			}
			sent, err := remote.DecodeStart(f)
			if err != nil {
				t.Fatal(err)
			}
			agent.send(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{HandleID: f.Handle, StartedAt: time.Now()})
			res := <-done
			ref := sent.Spec.Image
			if ref == "" {
				ref = sent.Sandbox.Image
				if ref == "" {
					ref = executor.DefaultHarnessImage
				}
			}
			return ref, res.h.ImageProvenance, res.err
		}
	}
}
