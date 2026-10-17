package remote_test

// The hub side of the git proxy's CA on a device (Task 20409): an agent too old
// to honour Spec.GitCA is refused a workload that would talk to the proxy,
// naming the upgrade, and is still sent everything else — without the CA.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func proxyGitCA(t *testing.T) *executor.GitCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "cloop hub CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &executor.GitCA{URLs: []string{"https://hub.internal:8443/"},
		PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// guardedSpec is a workload whose lease rewrote GitHub to the hub's proxy.
func guardedSpec(t *testing.T) executor.Spec {
	spec := plainSpec(t.TempDir())
	spec.Env = append(spec.Env, "CLOOP_GIT_PROXY_URL=https://hub.internal:8443",
		"CLOOP_GIT_PROXY_SESSION=gps_test")
	spec.GitCA = proxyGitCA(t)
	return spec
}

// TestAnOlderAgentIsRefusedTheProxysCA: the refusal names both protocols and
// the upgrade, and nothing about it falls back to a forge credential.
func TestAnOlderAgentIsRefusedTheProxysCA(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	old := remote.MinGitCAVersion - 1
	ex, _ := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, old)
	_, err := ex.Start(context.Background(), guardedSpec(t))
	if !errors.Is(err, remote.ErrGitCAUnsupported) {
		t.Fatalf("Start on a v%d agent = %v, want ErrGitCAUnsupported", old, err)
	}
	want := executor.ProtocolShortfall("agent agent-1 (edge-1)", old, remote.MinGitCAVersion,
		"to have this workload's git trust the certificate the hub issued its git proxy (executors.git_proxy.tls: auto)")
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal = %v\nwant it to carry %q", err, want)
	}
	if !strings.Contains(err.Error(), executor.AgentUpgradePath(old, remote.MinGitCAVersion)) {
		t.Errorf("refusal does not name the upgrade: %v", err)
	}
}

// TestAnOlderAgentStillRunsWhatNeedsNoCA: a workload that never reaches the
// proxy is dispatched to an older device as before — without the CA.
func TestAnOlderAgentStillRunsWhatNeedsNoCA(t *testing.T) {
	ex, p := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.MinGitCAVersion-1)
	sent := answerStart(t, p)
	spec := plainSpec(t.TempDir())
	spec.GitCA = proxyGitCA(t)
	if _, err := ex.Start(context.Background(), spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := (<-sent).Spec.GitCA; got != nil {
		t.Errorf("an older device was sent a CA it did not need: %+v", got.URLs)
	}
}

// TestACurrentAgentIsSentTheCA: the bundle rides the start frame's Spec, with
// nothing in it but the certificate.
func TestACurrentAgentIsSentTheCA(t *testing.T) {
	ex, p := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.ProtocolVersion)
	sent := answerStart(t, p)
	spec := guardedSpec(t)
	if _, err := ex.Start(context.Background(), spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := (<-sent).Spec.GitCA
	if got == nil || string(got.PEM) != string(spec.GitCA.PEM) || len(got.URLs) != 1 {
		t.Fatalf("the start frame carried %+v, want the CA for the proxy's URL", got)
	}
	if strings.Contains(string(got.PEM), "PRIVATE KEY") {
		t.Fatal("a private key travelled to the device")
	}
	if remote.ProtocolVersion < remote.MinGitCAVersion {
		t.Fatalf("this build speaks v%d, below the v%d its own hub needs", remote.ProtocolVersion, remote.MinGitCAVersion)
	}
}

// relaySpec is a workload whose harness talks to the hub's model relay on the
// git proxy's listener (Task 20435): nothing git, the CA for Node.
func relaySpec(t *testing.T) executor.Spec {
	spec := plainSpec(t.TempDir())
	spec.Env = append(spec.Env, "ANTHROPIC_BASE_URL=https://hub.internal:8443/_anthropic")
	spec.GitCA = proxyGitCA(t)
	spec.GitCA.Node = true
	return spec
}

// TestAnAgentBeforeNodeCAIsRefusedARelayedRun: the hub decides before dispatch
// not to relay a run to a device that cannot hand its harness the CA; should a
// spec asking for it reach the driver anyway, it is refused naming the
// upgrade, never sent with the field silently ignored.
func TestAnAgentBeforeNodeCAIsRefusedARelayedRun(t *testing.T) {
	old := remote.MinNodeCAVersion - 1
	ex, _ := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, old)
	_, err := ex.Start(context.Background(), relaySpec(t))
	if !errors.Is(err, remote.ErrNodeCAUnsupported) {
		t.Fatalf("Start on a v%d agent = %v, want ErrNodeCAUnsupported", old, err)
	}
	if !strings.Contains(err.Error(), executor.AgentUpgradePath(old, remote.MinNodeCAVersion)) {
		t.Errorf("refusal does not name the upgrade: %v", err)
	}
}

// TestACurrentAgentIsSentTheCAForNode: the bundle travels with Node set, even
// though nothing in the workload is git.
func TestACurrentAgentIsSentTheCAForNode(t *testing.T) {
	ex, p := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.ProtocolVersion)
	sent := answerStart(t, p)
	if _, err := ex.Start(context.Background(), relaySpec(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := (<-sent).Spec.GitCA
	if got == nil || !got.Node {
		t.Fatalf("the start frame carried %+v, want the CA with Node set", got)
	}
	if remote.ProtocolVersion < remote.MinNodeCAVersion {
		t.Fatalf("this build speaks v%d, below the v%d its own hub needs", remote.ProtocolVersion, remote.MinNodeCAVersion)
	}
}

// rotationRelaySpec is relaySpec while the hub's CA is being rotated: the
// bundle holds both CAs (Task 20438).
func rotationRelaySpec(t *testing.T) executor.Spec {
	spec := relaySpec(t)
	spec.GitCA.PEM = append(append([]byte(nil), spec.GitCA.PEM...), proxyGitCA(t).PEM...)
	return spec
}

// TestAnAgentBeforeV25IsNeverSentTwoCAsForNode: an agent before protocol v25
// would refuse a Node bundle of two certificates at its own validation. The
// hub hands it the active CA alone; should a spec with both reach the driver
// anyway, it is refused naming the upgrade rather than sent to fail there.
func TestAnAgentBeforeV25IsNeverSentTwoCAsForNode(t *testing.T) {
	old := remote.MinNodeCABundleVersion - 1
	ex, _ := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, old)
	_, err := ex.Start(context.Background(), rotationRelaySpec(t))
	if !errors.Is(err, remote.ErrNodeCABundleUnsupported) {
		t.Fatalf("Start on a v%d agent = %v, want ErrNodeCABundleUnsupported", old, err)
	}
	if !strings.Contains(err.Error(), executor.AgentUpgradePath(old, remote.MinNodeCABundleVersion)) {
		t.Errorf("refusal does not name the upgrade: %v", err)
	}
	// One CA for Node is still what such an agent takes.
	ex, p := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, old)
	sent := answerStart(t, p)
	if _, err := ex.Start(context.Background(), relaySpec(t)); err != nil {
		t.Fatalf("Start with one CA on a v%d agent: %v", old, err)
	}
	<-sent
}

// TestACurrentAgentIsSentBothCAsForNode: during a rotation a current agent is
// sent the two CAs, and its own validation — the code the agent runs — takes
// them.
func TestACurrentAgentIsSentBothCAsForNode(t *testing.T) {
	ex, p := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.ProtocolVersion)
	sent := answerStart(t, p)
	if _, err := ex.Start(context.Background(), rotationRelaySpec(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := (<-sent).Spec.GitCA
	if got == nil || !got.Node || got.CertCount() != 2 {
		t.Fatalf("the start frame carried %+v, want both CAs with Node set", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("the agent's validation refuses what it was sent: %v", err)
	}
}
