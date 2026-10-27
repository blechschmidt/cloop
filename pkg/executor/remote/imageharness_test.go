package remote_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// labelledResolver stands in for a registry that resolves tags and also
// serves each digest's labels, as imagepolicy.RegistryResolver does.
type labelledResolver struct {
	tagResolver
	labels   map[string]map[string]string // digest-pinned ref -> labels
	labelErr error
	asked    []string
}

func (r *labelledResolver) Labels(_ context.Context, ref string) (map[string]string, error) {
	r.asked = append(r.asked, ref)
	if r.labelErr != nil {
		return nil, r.labelErr
	}
	return r.labels[ref], nil
}

// copilotImageDevice is a container-mode device on a hub that requires signed
// images, whose registry labels the project's image as told.
func copilotImageDevice(t *testing.T, labels map[string]string, labelErr error) (*labelledResolver, func(refused bool) (*remoteStart, error)) {
	t.Helper()
	cosign, _ := stubCosign(t, signedDigest)
	resolver := &labelledResolver{
		tagResolver: tagResolver{digests: map[string]string{"ghcr.io/acme/tools:3.12": signedDigest}},
		labels:      map[string]map[string]string{"ghcr.io/acme/tools@" + signedDigest: labels},
		labelErr:    labelErr,
	}
	ex, p := imageDevice(t, containerMode, signaturePolicy("ghcr.io"), resolver,
		&imagepolicy.CosignVerifier{Binary: cosign})
	start := func(refused bool) (*remoteStart, error) {
		spec := plainSpec(t.TempDir())
		spec.Image = "ghcr.io/acme/tools:3.12"
		spec.Harness = "copilot"
		if refused {
			_, err := ex.Start(context.Background(), spec)
			noStartFrame(t, p, 200*time.Millisecond)
			return nil, err
		}
		sent := answerStart(t, p)
		_, err := ex.Start(context.Background(), spec)
		if err != nil {
			return nil, err
		}
		select {
		case payload := <-sent:
			return &remoteStart{image: payload.Spec.Image, harness: payload.Spec.Harness}, nil
		case <-time.After(10 * time.Second):
			t.Fatal("no start frame reached the device")
			return nil, nil
		}
	}
	return resolver, start
}

// remoteStart is what a start frame carried.
type remoteStart struct{ image, harness string }

// TestAProjectImageWithoutItsHarnessIsRefusedBeforeDispatch (Task 20450): under
// require_signature the hub has the image's manifest in hand, and a copilot
// project whose image's label lists claude, cloop and git is refused there —
// before anything is leased or sent — naming the image as the project wrote it
// and the published variant that carries copilot.
func TestAProjectImageWithoutItsHarnessIsRefusedBeforeDispatch(t *testing.T) {
	resolver, start := copilotImageDevice(t, map[string]string{imagepolicy.HarnessesLabel: "claude,cloop,git"}, nil)
	_, err := start(true)
	if !errors.Is(err, imagepolicy.ErrHarnessNotCarried) {
		t.Fatalf("Start = %v, want ErrHarnessNotCarried", err)
	}
	for _, want := range []string{"ghcr.io/acme/tools:3.12", "copilot", "claude, cloop, git",
		executor.HarnessImageFor("copilot"), ".cloop/sandbox.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}
	// The labels read are the verified digest's, never the tag's.
	if len(resolver.asked) != 1 || resolver.asked[0] != "ghcr.io/acme/tools@"+signedDigest {
		t.Errorf("labels were read for %q, want the verified digest only", resolver.asked)
	}
}

// TestAProjectImageCarryingItsHarnessIsDispatched: the same image labelled
// with copilot goes out, by its verified digest, and the start frame carries
// the harness, which the device's container driver checks against the image
// it actually runs.
func TestAProjectImageCarryingItsHarnessIsDispatched(t *testing.T) {
	_, start := copilotImageDevice(t, map[string]string{imagepolicy.HarnessesLabel: "claude,copilot,cloop,git"}, nil)
	got, err := start(false)
	if err != nil {
		t.Fatalf("Start of an image that carries copilot: %v", err)
	}
	if got.image != "ghcr.io/acme/tools@"+signedDigest || got.harness != "copilot" {
		t.Errorf("start frame = %+v, want the verified digest and the harness", got)
	}
}

// TestUnknownLabelsNeverRefuse: an unlabelled image, and a registry that will
// not serve the labels, both dispatch. Unknown is not no.
func TestUnknownLabelsNeverRefuse(t *testing.T) {
	_, start := copilotImageDevice(t, nil, nil)
	if _, err := start(false); err != nil {
		t.Errorf("an unlabelled image was refused: %v", err)
	}
	_, start = copilotImageDevice(t, nil, errors.New("registry unreachable"))
	if _, err := start(false); err != nil {
		t.Errorf("an image whose labels could not be read was refused: %v", err)
	}
}

// refuseStart answers the next start frame with a refusal the way an agent's
// container driver does when the image lacks the harness.
func refuseStart(t *testing.T, p *peer, refusal *remote.HarnessRefusal) {
	t.Helper()
	go func() {
		f := p.readUntil(remote.TypeStart)
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle, Error: "the device's own sentence", HarnessRefusal: refusal,
		})
		if err == nil {
			p.write(reply)
		}
	}()
}

// TestADevicesHarnessRefusalIsTheHubsRefusal (Task 20450): a device whose
// container driver read its image's label and refused — the device's default
// image, or a virtual executor's, which the hub never inspects — answers with
// what the label said, and the hub returns the same typed refusal its own
// container executor would, with the remedy naming the copilot image. A
// refusal the hub cannot repeat (an oversized one) is the device's plain
// error, never dropped.
func TestADevicesHarnessRefusalIsTheHubsRefusal(t *testing.T) {
	ex, p := deviceAt(t, containerMode, remote.ProtocolVersion)
	refuseStart(t, p, &remote.HarnessRefusal{Image: "ghcr.io/blechschmidt/cloop-harness:latest",
		Harness: "copilot", Carries: []string{"claude", "cloop", "git"}})
	spec := plainSpec(t.TempDir())
	spec.Harness = "copilot"
	_, err := ex.Start(context.Background(), spec)
	var missing *imagepolicy.MissingHarnessError
	if !errors.As(err, &missing) || missing.Harness != "copilot" || missing.Ref != "ghcr.io/blechschmidt/cloop-harness:latest" {
		t.Fatalf("Start = %v, want the device's refusal as a MissingHarnessError", err)
	}
	if !strings.Contains(missing.Remediation, executor.HarnessImageFor("copilot")) {
		t.Errorf("the remedy does not name the copilot image: %q", missing.Remediation)
	}

	ex2, p2 := deviceAt(t, containerMode, remote.ProtocolVersion)
	refuseStart(t, p2, &remote.HarnessRefusal{Image: strings.Repeat("x", imagepolicy.MaxRefLen+1), Harness: "copilot"})
	_, err = ex2.Start(context.Background(), spec)
	if err == nil || errors.As(err, &missing) || !strings.Contains(err.Error(), "the device's own sentence") {
		t.Errorf("an oversized refusal = %v, want the device's plain error", err)
	}
}

// TestLoopbackDeviceRefusesItsDefaultImageForAHarnessItLacks is the whole
// path with a real agent (Task 20450): a device in container mode whose
// default image — the published one, as the device's engine holds it — is
// labelled claude, cloop and git, and a copilot project. The hub checks
// nothing (there is no project image and no signature rule); the device's
// container driver reads the label before it runs anything, and the hub gets
// the typed refusal back. The engine is never asked to run a container.
func TestLoopbackDeviceRefusesItsDefaultImageForAHarnessItLacks(t *testing.T) {
	engine := newStandInEngine(t)
	engine.holdConfigured(t, executor.HarnessImages[0].Ref,
		`{"User":"65532:65532","Labels":{"org.cloop.harnesses":"claude,cloop,git"}}`)
	lb := newLoopbackHub(t, containerDevice)
	ex := lb.executor(t)

	spec := executor.Spec{WorkDir: deviceWorkDir(t, lb), Argv: []string{"/bin/sh", "-c", "true"}, Harness: "copilot"}
	_, err := ex.Start(context.Background(), spec)
	var missing *imagepolicy.MissingHarnessError
	if !errors.As(err, &missing) || missing.Harness != "copilot" || missing.Ref != executor.HarnessImages[0].Ref {
		t.Fatalf("Start = %v, want the device's harness refusal", err)
	}
	if runs := engine.ran(); len(runs) != 0 {
		t.Fatalf("the device's engine was asked to run %q for an image it refused", runs)
	}

	// The same device and image for a claude project start.
	spec.Harness = "claude"
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start of a claude project in an image that carries claude: %v", err)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = ex.Signal(sctx, h.ID, executor.SignalKill)
}
