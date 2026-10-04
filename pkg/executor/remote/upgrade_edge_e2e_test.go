package remote_test

// The edge channel end to end (Task 20376): a real hub asks a real agent, on a
// device staged the way `cloop executor agent install` lays one out, to move
// to an edge build. The agent — unprivileged, as installed — accepts and files
// the request; the root helper's code path takes it, fetches the build from a
// stand-in edge release, verifies it with the stand-in cosign against the edge
// workflow's identity, and installs it with install.Upgrade: identify, atomic
// rename, cloop.prev kept, drop-ins untouched, the agent restarted.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/cosigntest"
	"github.com/blechschmidt/cloop/internal/edgetest"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

func TestLoopbackUpgradesAnEdgeDeviceToTheHubsBuild(t *testing.T) {
	dev := edgetest.NewDevice(t, "dev+g06e06ed", 16, provenance.ChannelEdge)
	rel := edgetest.NewRelease(t)
	rel.Publish(t, edgeCommit, cosigntest.Edge, 17, "EDGE BUILD")
	// The agent checks cosign is there before it says yes.
	t.Setenv("PATH", filepath.Dir(cosigntest.Install(t))+string(os.PathListSeparator)+os.Getenv("PATH"))

	dropIns := map[string]string{}
	for _, p := range []string{dev.Spec.PacketFilterDropInPath(), dev.Spec.ChannelDropInPath()} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		dropIns[p] = string(b)
	}

	lb := newLoopback(t, func(c *agent.Config) {
		c.Channel = provenance.ChannelEdge
		c.InstallTarget = dev.Target
	})
	ex := lb.executor(t)
	if got := ex.UpdateChannel(); got != "edge" {
		t.Fatalf("the hub sees channel %q", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := ex.RequestUpgrade(ctx, remote.UpgradeRequest{TargetVersion: "edge:" + edgeCommit, TargetProtocol: 17})
	if err != nil || !out.Accepted {
		t.Fatalf("RequestUpgrade = %+v, %v", out, err)
	}

	// The agent filed the request for the helper.
	waitFor(t, 10*time.Second, func() bool {
		_, err := os.Stat(dev.Spec.UpgradeRequestPath())
		return err == nil
	}, "the agent should file the upgrade request")

	// The root helper's half.
	inst, cmds := edgetest.Recorder()
	req, res, staged, err := agent.ApplyUpgradeRequest(dev.Spec, install.OutputSystemd, agent.ApplyOptions{
		Installer: inst, Fetch: rel.Options(t),
	})
	if err != nil {
		t.Fatalf("the helper's upgrade failed: %v", err)
	}
	if req.TargetVersion != "edge:"+edgeCommit || req.Reason != "requested by the control plane" {
		t.Errorf("request = %+v", req)
	}
	if !staged.ProvenanceVerified || staged.Channel != provenance.ChannelEdge || staged.Version != "dev+ga0f3870" {
		t.Errorf("staged = %+v", staged)
	}
	if cur, prev := dev.Installed(t); cur != "EDGE BUILD" || prev != "INSTALLED" {
		t.Errorf("installed %q, kept for rollback %q", cur, prev)
	}
	if !res.Verified || res.StagedBuild.Version != "dev+ga0f3870" || res.StagedBuild.Protocol != 17 {
		t.Errorf("the staged binary was not identified before it was installed: %+v", res.StagedBuild)
	}
	for p, want := range dropIns {
		if got, _ := os.ReadFile(p); string(got) != want {
			t.Errorf("%s changed across the upgrade", p)
		}
	}
	if !strings.Contains(strings.Join(cmds(), "\n"), "systemctl try-restart cloop-executor.service") {
		t.Errorf("the agent was not restarted: %v", cmds())
	}
}

// TestLoopbackNeverSendsMainToAStableDevice: the same device on the stable
// channel is refused by the hub, before a frame is sent — and the device's
// own refusal stands behind it (TestAgentRefusesEdgeTargetsWithoutOptIn).
func TestLoopbackNeverSendsMainToAStableDevice(t *testing.T) {
	dev := edgetest.NewDevice(t, "dev+g06e06ed", 16, provenance.ChannelStable)
	lb := newLoopback(t, func(c *agent.Config) { c.InstallTarget = dev.Target })
	ex := lb.executor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := ex.RequestUpgrade(ctx, remote.UpgradeRequest{TargetVersion: "edge:" + edgeCommit, TargetProtocol: 17, Force: true})
	if !errors.Is(err, remote.ErrUpgradeChannel) {
		t.Fatalf("err = %v, want ErrUpgradeChannel", err)
	}
	if _, err := os.Stat(dev.Spec.UpgradeRequestPath()); err == nil {
		t.Error("a request was filed")
	}
}
