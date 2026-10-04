package remote_test

// The secret_refresh frame pair against scripted agents (Task 20375): a v17
// agent is sent the files and its report is the answer; an older one is never
// sent a frame it has no handler for, and the report says why.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func refreshRequest(leaseID string) executor.SecretRefreshRequest {
	return executor.SecretRefreshRequest{
		LeaseID: leaseID,
		Reason:  "test",
		Files: []executor.SecretFile{{
			LeaseID: leaseID, GrantID: "grant_1", Dir: "/run/cloop/cloop-lease-refresh",
			Name: "github-token", Mode: 0o600, Content: []byte("ghs_refreshed_token_for_test\n"),
		}},
	}
}

// TestRefreshIsSentToACurrentAgent: the hub sends the files and reports what
// the agent says it rewrote.
func TestRefreshIsSentToACurrentAgent(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()
	startLeased(t, ex, p, "lease_refresh")
	if !ex.SupportsSecretRefresh() || ex.SecretRefreshShortfall() != "" {
		t.Fatalf("a v%d agent is reported unable to take a refresh: %q", remote.ProtocolVersion, ex.SecretRefreshShortfall())
	}

	got := make(chan remote.SecretRefreshPayload, 1)
	go func() {
		f := p.readUntil(remote.TypeSecretRefresh)
		payload, err := remote.DecodeSecretRefresh(f)
		if err != nil {
			t.Errorf("decode secret_refresh: %v", err)
			close(got)
			return
		}
		got <- payload
		reply, _ := remote.NewFrame(remote.TypeSecretRefreshed, f.ID, "", remote.SecretRefreshedPayload{
			LeaseID: payload.LeaseID, Known: true, FilesRewritten: 1, Handles: []string{"h1"},
		})
		p.write(reply)
	}()

	rep := ex.RefreshSecretFiles(context.Background(), refreshRequest("lease_refresh"))
	if !rep.Delivered() || rep.FilesRewritten != 1 || !rep.Known {
		t.Fatalf("report = %+v; want the agent's answer: one file rewritten", rep)
	}
	select {
	case payload := <-got:
		if payload.LeaseID != "lease_refresh" || len(payload.Files) != 1 || payload.Files[0].Name != "github-token" ||
			string(payload.Files[0].Content) != "ghs_refreshed_token_for_test\n" {
			t.Fatalf("the frame carried %v; want the lease's one token file", payload)
		}
		if strings.Contains(payload.String(), "ghs_refreshed") {
			t.Fatal("the payload's String() prints the credential")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no secret_refresh frame reached the agent")
	}
}

// TestRefreshDegradesOnAnOlderAgent: a v16 agent has no handler for the frame,
// so it is never sent one; the report says Unsupported and names the protocol
// the hub needs, through the shared helper.
func TestRefreshDegradesOnAnOlderAgent(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.MinSecretRefreshVersion-1), nil)
	defer sess.Close()
	startLeased(t, ex, p, "lease_old")

	if ex.SupportsSecretRefresh() {
		t.Fatal("a v16 agent is reported able to take a refresh")
	}
	why := ex.SecretRefreshShortfall()
	if !strings.Contains(why, "v16") || !strings.Contains(why, "v17") {
		t.Fatalf("shortfall %q should name both protocols", why)
	}
	rep := ex.RefreshSecretFiles(context.Background(), refreshRequest("lease_old"))
	if rep.Delivered() || !rep.Unsupported || !strings.Contains(rep.Error, "needs v17") {
		t.Fatalf("report = %+v; want Unsupported, naming v17", rep)
	}
	// Nothing was written to the agent: the next frame it sees is whatever
	// the test sends, not a refresh it would drop.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for {
		f, err := p.conn.ReadFrame(ctx)
		if err != nil {
			break
		}
		if f.Type == remote.TypeSecretRefresh {
			t.Fatal("a secret_refresh frame was sent to a v16 agent")
		}
	}
}

// TestRefreshOfALeaseTheDeviceDoesNotHold: nothing to do is not a failure.
func TestRefreshOfALeaseTheDeviceDoesNotHold(t *testing.T) {
	ex := newTestExecutor(t, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()
	rep := ex.RefreshSecretFiles(context.Background(), refreshRequest("lease_elsewhere"))
	if rep.Known || rep.Error != "" {
		t.Fatalf("report = %+v; want Known false, no error", rep)
	}
}

// TestDecodeSecretRefreshRefusesAForeignFile: a file attributed to another
// lease is refused at decode, before a byte of it reaches the device's disk.
func TestDecodeSecretRefreshRefusesAForeignFile(t *testing.T) {
	payload := remote.NewSecretRefreshPayload(refreshRequest("lease_a"))
	payload.Files[0].LeaseID = "lease_b"
	f, err := remote.NewFrame(remote.TypeSecretRefresh, "id", "", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.DecodeSecretRefresh(f); err == nil {
		t.Fatal("a refresh carrying another lease's file was accepted")
	}
	payload = remote.NewSecretRefreshPayload(refreshRequest("lease_a"))
	payload.Files[0].Name = "../../etc/passwd"
	f, _ = remote.NewFrame(remote.TypeSecretRefresh, "id", "", payload)
	if _, err := remote.DecodeSecretRefresh(f); err == nil {
		t.Fatal("a refresh naming a path outside the lease directory was accepted")
	}
}
