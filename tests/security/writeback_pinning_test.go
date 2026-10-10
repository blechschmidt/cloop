package security

// Guarantee: a compromised edge agent cannot pin the hub's memory through the
// frames that return a run's work (Task 20399).
//
// Every other remote-agent guarantee in this suite is about what the hub sends
// *to* a device. This one is about what a device sends back and the hub keeps:
// a write-back bundle, streamed as result chunks, and a seeded run's
// project-state document, both held in hub memory until collected. A device is
// the least trusted party in the system — it runs model-authored code on a
// machine the hub does not control — and before this guarantee one compromised
// agent could pin the hard 128 MiB bundle ceiling on every handle the hub
// tracked for it, 256 finished ones included: 32 GiB per device per hub
// process, enough for one device to take the hub down for every tenant.
//
// The test drives a real hub executor over the in-memory pipe with a
// hand-written agent sending exactly the frames an honest agent never would,
// against a small injected budget, and asserts what the hub holds after each.
// The rules it checks are each refused or released on the hub side, so no
// agent behaviour is trusted: an honest agent sends chunks, then the result,
// then the final status, and nothing after.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// pinningAgentID is the hostile device.
const pinningAgentID = "agent-hostile"

// pinningStore enrols one agent, so the hub restores its executor and can
// revoke it. Everything else is emptyStore's.
type pinningStore struct {
	emptyStore
	revoked bool
}

func (s *pinningStore) record() remote.AgentRecord {
	rec := remote.AgentRecord{AgentID: pinningAgentID, Name: "hostile", SecretHash: strings.Repeat("0", 64)}
	if s.revoked {
		rec.RevokedAt = time.Now()
	}
	return rec
}

func (s *pinningStore) ListAgents() ([]remote.AgentRecord, error) {
	return []remote.AgentRecord{s.record()}, nil
}

func (s *pinningStore) GetAgent(agentID string) (remote.AgentRecord, error) {
	if agentID != pinningAgentID {
		return s.emptyStore.GetAgent(agentID)
	}
	return s.record(), nil
}

func (s *pinningStore) RevokeAgent(string, time.Time) error {
	s.revoked = true
	return nil
}

// hostileAgent is the device side of one connection.
type hostileAgent struct {
	t    *testing.T
	conn remote.Conn
}

func (a *hostileAgent) send(typ remote.FrameType, id, handle string, payload any) {
	a.t.Helper()
	f, err := remote.NewFrame(typ, id, handle, payload)
	if err != nil {
		a.t.Fatalf("build %s: %v", typ, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.conn.WriteFrame(ctx, f); err != nil {
		a.t.Fatalf("write %s: %v", typ, err)
	}
}

func (a *hostileAgent) next() remote.Frame {
	a.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, err := a.conn.ReadFrame(ctx)
	if err != nil {
		a.t.Fatalf("read: %v", err)
	}
	return f
}

// start has the hub dispatch spec and answers the start, returning the handle.
func (a *hostileAgent) start(ex *remote.Executor, spec executor.Spec) string {
	a.t.Helper()
	type started struct {
		h   executor.Handle
		err error
	}
	ch := make(chan started, 1)
	go func() {
		h, err := ex.Start(context.Background(), spec)
		ch <- started{h, err}
	}()
	for {
		f := a.next()
		if f.Type != remote.TypeStart {
			continue
		}
		a.send(remote.TypeStarted, f.ID, f.Handle,
			remote.StartedPayload{HandleID: f.Handle, PID: 7, StartedAt: time.Now()})
		break
	}
	res := <-ch
	if res.err != nil {
		a.t.Fatalf("Start: %v", res.err)
	}
	return res.h.ID
}

// chunks streams data for handle in 256-byte slices from offset 0.
func (a *hostileAgent) chunks(handle string, data []byte) {
	for off := 0; off < len(data); off += 256 {
		end := min(off+256, len(data))
		a.send(remote.TypeResultChunk, "", handle,
			remote.ResultChunkPayload{Offset: int64(off), Data: data[off:end]})
	}
}

// settled returns once the hub has handled every frame sent before it, with
// the codes of the frames it refused. A heartbeat is the barrier: frames are
// handled in order and a beat is acknowledged. running names the handles the
// device still runs, so the beat does not resolve them.
func (a *hostileAgent) settled(running ...string) []string {
	a.t.Helper()
	a.send(remote.TypeHeartbeat, "hb", "", remote.HeartbeatPayload{Seq: 1, ActiveHandles: running})
	var codes []string
	for {
		f := a.next()
		switch f.Type {
		case remote.TypeHeartbeatAck:
			return codes
		case remote.TypeError:
			e, err := remote.DecodeError(f)
			if err != nil {
				a.t.Fatalf("decode error frame: %v", err)
			}
			codes = append(codes, e.Message)
		}
	}
}

// bundleDispatch asks for a bundle write-back of at most maxBytes.
func bundleDispatch(maxBytes int64) executor.Spec {
	return executor.Spec{
		Argv:    []string{"true"},
		WorkDir: "/tmp/project",
		Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit, Repo: "https://example.invalid/acme/widgets.git",
			Ref: strings.Repeat("b", 40),
		},
		WriteBack: executor.WriteBack{
			Mode: executor.WriteBackBundle, Branch: "cloop/task-20399", MaxBundleBytes: maxBytes,
		},
	}
}

func TestHostileAgentCannotPinHubMemoryThroughWriteBack(t *testing.T) {
	t.Parallel()

	// What a 1 KiB bundle in 256-byte chunks counts: its bytes, and the
	// overhead of each chunk that holds them. The executor's budget is two.
	bundle := int64(1024 + 4*remote.ResultChunkOverhead)
	budget := remote.NewResultBudget(2*bundle, 1<<20)
	store := &pinningStore{}
	hub, err := remote.NewHub(remote.HubOptions{Store: store, Registry: executor.NewRegistry(), ResultBudget: budget})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	if err := hub.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	ex, ok := hub.Executor(pinningAgentID)
	if !ok {
		t.Fatal("the enrolled agent has no executor")
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
		ProtocolVersion: remote.ProtocolVersion, AgentID: pinningAgentID, Name: "hostile",
		Capabilities: remote.AgentCapabilities{OS: "linux", Arch: "amd64"},
	})
	if f := agent.next(); f.Type != remote.TypeWelcome {
		t.Fatalf("handshake answered with %s", f.Type)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("Accept: %v", err)
	}

	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	held := func(want int64, what string) {
		t.Helper()
		if got := ex.PinnedResultBytes(); got != want {
			t.Fatalf("%s: the hub holds %d bytes of this device's returned work, want %d", what, got, want)
		}
		if got := budget.Usage().Pinned; got != want {
			t.Fatalf("%s: the process budget counts %d bytes, want %d", what, got, want)
		}
	}

	// A handle that asked for no write-back takes no bundle.
	none := agent.start(ex, executor.Spec{Argv: []string{"true"}, WorkDir: "/tmp/project"})
	agent.chunks(none, data)
	if refused := agent.settled(none); len(refused) != 4 {
		t.Fatalf("a handle that asked for no write-back took %d of 4 chunks", 4-len(refused))
	}
	held(0, "chunks for a handle that asked for no write-back")

	// A handle takes no more than its own spec's cap — not the hard ceiling.
	capped := agent.start(ex, bundleDispatch(512))
	agent.chunks(capped, data)
	if refused := agent.settled(none, capped); len(refused) != 2 || !strings.Contains(refused[0], "512-byte cap") {
		t.Fatalf("a bundle past its spec's 512-byte cap was refused %d times: %v", len(refused), refused)
	}
	held(0, "a bundle past its spec's cap")

	// Handles share their executor's budget: two 1 KiB bundles fill it, and
	// a third's first chunk is refused.
	first, second, third := agent.start(ex, bundleDispatch(0)), agent.start(ex, bundleDispatch(0)),
		agent.start(ex, bundleDispatch(0))
	agent.chunks(first, data)
	agent.chunks(second, data)
	agent.chunks(third, data[:256])
	refused := agent.settled(none, capped, first, second, third)
	if len(refused) != 1 || !strings.Contains(refused[0], "max_pinned_writeback_bytes") {
		t.Fatalf("a third bundle past the executor's budget: refusals %v", refused)
	}
	held(2*bundle, "two bundles that fill the executor's budget")

	// Nothing after the final status: the old way to refill a collected bundle.
	sum := sha256.Sum256(data)
	agent.send(remote.TypeResult, "", first, remote.ResultPayload{Result: executor.WriteBackResult{
		Mode: executor.WriteBackBundle, Branch: "cloop/task-20399", CommitSHA: strings.Repeat("c", 40),
		BundleBytes: int64(len(data)), BundleSHA256: hex.EncodeToString(sum[:]),
	}})
	agent.send(remote.TypeStatus, "", first, remote.StatusPayload{Status: executor.Status{
		HandleID: first, State: executor.StateExited, FinishedAt: time.Now(),
	}})
	agent.settled(none, capped, second, third)
	if got, err := ex.WriteBackBundle(first); err != nil || len(got) != len(data) {
		t.Fatalf("collecting the verified bundle: %d bytes, %v", len(got), err)
	}
	held(bundle, "after collecting one bundle")
	agent.chunks(first, data)
	if refused := agent.settled(none, capped, second, third); len(refused) != 4 {
		t.Fatalf("a finished handle took %d of 4 chunks sent after its final status", 4-len(refused))
	}
	held(bundle, "chunks sent after the final status")

	// Revoking the device lets go of everything its handles hold.
	if err := hub.Revoke(pinningAgentID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	held(0, "after the device was revoked")
}
