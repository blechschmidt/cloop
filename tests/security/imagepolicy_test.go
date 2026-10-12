package security

// Guarantee 9: a project-supplied .cloop/sandbox.yaml cannot escape the
// operator's container image allowlist.
//
// This is the sibling of guarantee 8. That one says a spec can only make a run
// more confined; this one covers the field where "more confined" does not
// apply, because the image is not a knob on the sandbox — it is the sandbox.
// Its entrypoint, libraries and PATH are the environment the harness executes
// in, and every credential the hub injects at start is handed to it. A pull
// request that chooses the image has chosen what runs, and no amount of
// cap-dropping around it changes that.
//
// So the property is: for every reference a project can write, the run either
// uses an image the operator's policy admits, or does not start. The tests
// drive the real parser, the real policy and the real Pod builder.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/sandbox"
)

// hubPolicy is the posture the shipped Helm chart renders by default: one
// registry — the one the deployment's own image comes from — and digests only.
func hubPolicy() imagepolicy.Policy {
	return imagepolicy.Policy{
		AllowedRegistries: []string{"ghcr.io"},
		RequireDigest:     true,
	}
}

const allowedDigest = "sha256:" +
	"1a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f7890"

// checkProjectImage writes src as a project's sandbox.yaml, resolves it the way
// the control plane does, and returns the policy's verdict on whatever image it
// named. Nothing is stubbed: this is sandbox.Resolve reading a real file.
func checkProjectImage(t *testing.T, src string, p imagepolicy.Policy) error {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sandbox.FileName), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := sandbox.Resolve(dir)
	if err != nil {
		// A spec the parser refuses outright never gets an image at all, which
		// is a refusal for the purposes of this guarantee.
		return err
	}
	_, err = resolved.CheckImagePolicy(p)
	return err
}

// TestProjectSpecCannotEscapeTheImageAllowlist is the guarantee.
//
// Every entry is a way of writing "somewhere the operator did not allow" that
// looks, to a careless check, like somewhere they did.
func TestProjectSpecCannotEscapeTheImageAllowlist(t *testing.T) {
	escapes := map[string]string{
		// The two substring attacks. A strings.Contains allowlist admits both,
		// and both pull from evil.example.
		"allowed registry as a repository path": "image: evil.example/ghcr.io/tools@" + allowedDigest + "\n",
		"allowed registry as a domain prefix":   "image: ghcr.io.evil.example/tools@" + allowedDigest + "\n",
		"allowed registry as a domain suffix":   "image: notghcr.io/tools@" + allowedDigest + "\n",

		// Homographs. Each of these renders as "ghcr.io" in a pull request
		// diff, in a terminal and in the dashboard.
		"cyrillic es":       "image: ghсr.io/acme/tools@" + allowedDigest + "\n",
		"fullwidth solidus": "image: ghcr.io／acme/tools@" + allowedDigest + "\n",
		"zero-width space":  "image: ghcr​.io/acme/tools@" + allowedDigest + "\n",

		// Punycode: a real, distinct host that renders as a lookalike.
		"punycode lookalike": "image: xn--ghr-hnd.io/acme/tools@" + allowedDigest + "\n",

		// Provenance rather than location.
		"floating tag on an allowed registry": "image: ghcr.io/acme/tools:latest\n",
		"no tag at all":                       "image: ghcr.io/acme/tools\n",
		"unqualified name":                    "image: alpine:3.20\n",

		// A digest that is not one. "sha256:dead" is syntactically a digest
		// under the loose OCI grammar and names nothing.
		"truncated digest":         "image: ghcr.io/acme/tools@sha256:dead\n",
		"unknown digest algorithm": "image: ghcr.io/acme/tools@md5:d41d8cd98f00b204e9800998ecf8427e\n",

		// argv rather than a reference.
		"flag":       "image: \"--privileged\"\n",
		"whitespace": "image: \"ghcr.io/acme/tools:1 --network=host\"\n",
	}

	for name, src := range escapes {
		t.Run(name, func(t *testing.T) {
			err := checkProjectImage(t, src, hubPolicy())
			if err == nil {
				t.Fatalf("the hub accepted %q — a pull request chose what executes", strings.TrimSpace(src))
			}
			// A refusal nobody can act on becomes a request to disable the
			// policy, so the message is part of the guarantee.
			var denied *imagepolicy.DenyError
			if errors.As(err, &denied) {
				if denied.Rule == "" || denied.Remediation == "" {
					t.Errorf("denial carries no rule or remediation: %+v", denied)
				}
			} else if !errors.Is(err, sandbox.ErrInvalidSpec) {
				t.Errorf("refusal is neither a policy denial nor an invalid spec: %v", err)
			}
		})
	}

	// And the control: the one thing the policy exists to permit still works.
	if err := checkProjectImage(t, "image: ghcr.io/acme/tools@"+allowedDigest+"\n", hubPolicy()); err != nil {
		t.Fatalf("the allowed image was refused: %v", err)
	}
}

// TestProjectSpecCannotEscapeTheRepositoryAllowlist: an operator who narrowed
// to one org must not be widened by a name that shares its prefix.
func TestProjectSpecCannotEscapeTheRepositoryAllowlist(t *testing.T) {
	p := imagepolicy.Policy{
		AllowedRegistries: []string{"ghcr.io"},
		AllowedRepos:      []string{"ghcr.io/acme/*"},
		RequireDigest:     true,
	}
	for name, image := range map[string]string{
		"prefix-sharing org": "ghcr.io/acme-evil/tools",
		"sibling org":        "ghcr.io/other/tools",
		"org as a suffix":    "ghcr.io/evil/acme/tools",
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkProjectImage(t, "image: "+image+"@"+allowedDigest+"\n", p); err == nil {
				t.Fatalf("the hub accepted %q against an allowlist of ghcr.io/acme/*", image)
			}
		})
	}
	if err := checkProjectImage(t, "image: ghcr.io/acme/tools/nested@"+allowedDigest+"\n", p); err != nil {
		t.Fatalf("a repository under the allowed prefix was refused: %v", err)
	}
}

// TestNoPolicyIsNotSilentlyAPolicy: the escape hatch has to be an explicit
// decision. A hub that never configured a policy allows anything — and this
// test exists so that fact is asserted rather than assumed, because the day it
// changes silently in either direction is the day a deployment breaks or a
// guarantee evaporates.
func TestNoPolicyIsNotSilentlyAPolicy(t *testing.T) {
	if err := checkProjectImage(t, "image: evil.example/anything:latest\n", imagepolicy.Policy{}); err != nil {
		t.Fatalf("an unconfigured hub refused an image: %v", err)
	}
	// The moment any rule is set, deny-by-default applies to that dimension.
	if err := checkProjectImage(t, "image: evil.example/anything:latest\n",
		imagepolicy.Policy{AllowedRegistries: []string{"ghcr.io"}}); err == nil {
		t.Fatal("a configured allowlist admitted a registry that is not on it")
	}
}

// TestPolicyReachesTheExecutorThatRunsTheImage.
//
// The check in the sandbox layer is a courtesy: it produces a good error
// message. The check that matters is in the driver, because that is what turns
// a reference into a running process — and a future call path that skips the
// courtesy must still be refused. This drives the Kubernetes Pod builder
// directly, bypassing every layer above it.
func TestPolicyReachesTheExecutorThatRunsTheImage(t *testing.T) {
	opts := kubernetes.Options{
		Image:       "ghcr.io/acme/hub@" + allowedDigest,
		ImagePolicy: hubPolicy(),
	}
	ctx := context.Background()

	if got, err := kubernetes.AuditPodImage(ctx, opts, executor.Spec{
		Argv: []string{"cloop", "run"}, Image: "evil.example/backdoor@" + allowedDigest,
	}); err == nil {
		t.Fatalf("the Pod builder scheduled %q, which the policy forbids", got)
	}

	// The tag a project writes must not be what a kubelet resolves later: the
	// Pod has to carry the digest, or the artifact that runs is whatever the
	// tag points at by the time some node pulls it.
	got, err := kubernetes.AuditPodImage(ctx, opts, executor.Spec{
		Argv: []string{"cloop", "run"}, Image: "ghcr.io/acme/tools:1.79@" + allowedDigest,
	})
	if err != nil {
		t.Fatalf("the Pod builder refused an allowed image: %v", err)
	}
	if got != "ghcr.io/acme/tools@"+allowedDigest {
		t.Fatalf("Pod image = %q, want the canonical digest form", got)
	}
}

// TestChartDefaultPolicyIsRestrictive: the shipped Helm default must actually
// deny something. A default that admits everything is worse than none, because
// it reads as protection.
func TestChartDefaultPolicyIsRestrictive(t *testing.T) {
	// The values the chart renders with no overrides: the registry the hub's
	// own image comes from, and digests required.
	shipped := config.ImagePolicyConfig{
		AllowedRegistries: []string{"ghcr.io"},
		RequireDigest:     true,
	}
	p := shipped.Policy()
	if err := p.Validate(); err != nil {
		t.Fatalf("the shipped chart default is not a valid policy: %v", err)
	}
	if !p.Configured() {
		t.Fatal("the shipped chart default constrains nothing")
	}
	for _, ref := range []string{
		"docker.io/library/alpine@" + allowedDigest, // wrong registry
		"ghcr.io/acme/tools:latest",                 // right registry, no digest
	} {
		if _, err := p.Evaluate(ref); err == nil {
			t.Errorf("the shipped chart default admits %q", ref)
		}
	}
}

// TestSignatureRequirementNeverDegradesToASkip.
//
// The failure mode worth a test of its own: a hub configured to require signed
// images, on a host with no cosign, must refuse. A skip here is invisible —
// the hub starts, runs, and reports nothing wrong, while verifying nothing.
func TestSignatureRequirementNeverDegradesToASkip(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no cosign anywhere

	e := imagepolicy.Enforcer{
		Policy: imagepolicy.Policy{
			AllowedRegistries: []string{"ghcr.io"},
			RequireSignature:  true,
			CosignPublicKeys:  []string{"/etc/cloop/cosign.pub"},
		},
		Verifier: imagepolicy.NewCosignVerifier(),
	}
	_, err := e.Authorize(context.Background(), "ghcr.io/acme/tools@"+allowedDigest)
	if err == nil {
		t.Fatal("a hub with no cosign admitted an unverified image")
	}
	if !errors.Is(err, imagepolicy.ErrCosignMissing) {
		t.Errorf("error = %v, want it to name the missing binary", err)
	}

	// And with no verifier wired at all — the shape a partially-configured
	// deployment or a hand-built driver has.
	bare := imagepolicy.Enforcer{Policy: e.Policy}
	if _, err := bare.Authorize(context.Background(), "ghcr.io/acme/tools@"+allowedDigest); err == nil {
		t.Fatal("an enforcer with no verifier admitted an unverified image")
	}
}

// deviceTagResolver stands in for the registry the hub resolves a device's tag
// at: the digest each tag names.
type deviceTagResolver map[string]string

func (r deviceTagResolver) ResolveDigest(_ context.Context, ref string) (string, error) {
	if d, ok := r[ref]; ok {
		return d, nil
	}
	return "", errors.New("no such tag")
}

// TestADeviceRunsOnlyASignatureVerifiedImage is guarantee 9 on the device path
// (Task 20424). A device in container mode runs the image a project names, and
// its own container driver applies no policy: before this guarantee the hub
// checked such an image against the allowlists and the digest rule and never
// its signature, so require_signature held on the hub's executors and on no
// device. The hub now verifies it, and the device is sent the digest it
// verified — never the tag, which the device would resolve in a store the hub
// cannot see — or nothing at all.
//
// It drives a real remote executor over the in-memory pipe, against a stand-in
// cosign that accepts one digest, as cosign accepts only what an accepted key
// signed.
func TestADeviceRunsOnlyASignatureVerifiedImage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the cosign stand-in is a POSIX shell script")
	}
	signed := "sha256:" + strings.Repeat("5a", 32)
	unsigned := "sha256:" + strings.Repeat("0d", 32)
	cosign := filepath.Join(t.TempDir(), "cosign")
	script := "#!/bin/sh\nfor a in \"$@\"; do ref=$a; done\ncase \"$ref\" in *@" + signed +
		") exit 0 ;; esac\necho 'Error: no matching signatures' >&2\nexit 1\n"
	if err := os.WriteFile(cosign, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ex, err := remote.NewExecutor(remote.Options{
		ID: pinningAgentID, Name: "edge",
		Sandbox: func() (executor.SandboxSettings, error) {
			return executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil
		},
		ImagePolicy: func() (imagepolicy.Policy, error) {
			return imagepolicy.Policy{AllowedRegistries: []string{"ghcr.io"}, RequireSignature: true,
				CosignPublicKeys: []string{"/etc/cloop/cosign.pub"}}, nil
		},
		ImageResolver: deviceTagResolver{"ghcr.io/acme/tools:3.12": signed, "ghcr.io/acme/tools:3.13": unsigned},
		ImageVerifier: &imagepolicy.CosignVerifier{Binary: cosign},
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
	spec := func(image string) executor.Spec {
		return executor.Spec{Argv: []string{"true"}, WorkDir: "/tmp/project", Image: image}
	}

	// Unsigned — by tag, and by digest — is refused with nothing sent.
	for _, image := range []string{"ghcr.io/acme/tools:3.13", "ghcr.io/acme/tools@" + unsigned} {
		_, err := ex.Start(context.Background(), spec(image))
		var denied *imagepolicy.DenyError
		if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleSignature {
			t.Fatalf("Start(%s) = %v, want a signature denial", image, err)
		}
	}
	agent.send(remote.TypeHeartbeat, "hb", "", remote.HeartbeatPayload{Seq: 1})
	for f := agent.next(); f.Type != remote.TypeHeartbeatAck; f = agent.next() {
		if f.Type == remote.TypeStart {
			t.Fatal("a start frame reached the device for an unsigned image")
		}
	}

	// Signed: the device is told to run the digest the hub verified.
	type result struct {
		h   executor.Handle
		err error
	}
	done := make(chan result, 1)
	go func() {
		h, err := ex.Start(context.Background(), spec("ghcr.io/acme/tools:3.12"))
		done <- result{h, err}
	}()
	var sent remote.StartPayload
	for {
		f := agent.next()
		if f.Type != remote.TypeStart {
			continue
		}
		if sent, err = remote.DecodeStart(f); err != nil {
			t.Fatal(err)
		}
		agent.send(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{HandleID: f.Handle, StartedAt: time.Now()})
		break
	}
	if res := <-done; res.err != nil {
		t.Fatalf("Start of the signed image: %v", res.err)
	}
	if want := "ghcr.io/acme/tools@" + signed; sent.Spec.Image != want {
		t.Fatalf("the device was told to run %q, want the verified digest %q", sent.Spec.Image, want)
	}
}
