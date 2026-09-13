package remote_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// connectRecord is one OnConnect callback.
type connectRecord struct {
	agentID string
	version string
	cpus    int
}

// hubHarness is a hub whose enrollment and connect callbacks are recorded.
//
// Deliberately not the loopback harness from e2e_test.go: that one runs a real
// agent, so a reconnect has to be provoked by killing the link and waiting out
// the agent's ~1s jittered backoff. Speaking the protocol directly makes the
// reconnect a function call, which is what this test is about — it must be able
// to assert *which* callbacks fire on a second connect, with no timing in play.
type hubHarness struct {
	t      *testing.T
	server *httptest.Server
	token  string

	mu       sync.Mutex
	enrolls  []string
	connects []connectRecord
}

func newHubHarness(t *testing.T) *hubHarness {
	t.Helper()
	h := &hubHarness{t: t}

	store := newMemStore()
	hub, err := remote.NewHub(remote.HubOptions{
		Store: store,
		// A private registry: the process-wide default is shared with every
		// other test in this binary.
		Registry: executor.NewRegistry(),
		OnEnroll: func(agent remote.AgentRecord, _ remote.AgentCapabilities) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.enrolls = append(h.enrolls, agent.AgentID)
		},
		OnConnect: func(agent remote.AgentRecord, caps remote.AgentCapabilities, agentVersion string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.connects = append(h.connects, connectRecord{
				agentID: agent.AgentID, version: agentVersion, cpus: caps.CPUs,
			})
		},
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}

	h.server = httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	t.Cleanup(h.server.Close)

	token, _, err := remote.Mint(store, remote.MintOptions{
		Name:        "edge-1",
		TTL:         5 * time.Minute,
		WorkDirRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.token = token
	return h
}

// dial completes one handshake and returns the credential the hub issued (empty
// on a non-enrolling connect) plus a close func.
func (h *hubHarness) dial(token string, hello remote.HelloPayload) (string, func()) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.server.URL, "http"),
		&websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
		})
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	conn := remote.NewWSConn(ws)

	frame, err := remote.NewFrame(remote.TypeHello, "hello", "", hello)
	if err != nil {
		h.t.Fatalf("build hello: %v", err)
	}
	if err := conn.WriteFrame(ctx, frame); err != nil {
		h.t.Fatalf("write hello: %v", err)
	}

	// Read until welcome: the hub may interleave other frames, and the
	// credential is carried on the welcome.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, rErr := conn.ReadFrame(ctx)
		if rErr != nil {
			h.t.Fatalf("read welcome: %v", rErr)
		}
		if got.Type != remote.TypeWelcome {
			continue
		}
		welcome, dErr := remote.DecodeWelcome(got)
		if dErr != nil {
			h.t.Fatalf("decode welcome: %v", dErr)
		}
		return welcome.Credential, func() { _ = conn.Close("test done") }
	}
	h.t.Fatal("no welcome frame before the deadline")
	return "", func() {}
}

func (h *hubHarness) snapshot() ([]string, []connectRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.enrolls...), append([]connectRecord(nil), h.connects...)
}

// waitConnects blocks until at least n OnConnect callbacks have landed.
//
// OnConnect fires on the hub's request goroutine just after the handshake, so it
// is ordered after the welcome the client already read — but not synchronised
// with it. Polling is the honest way to wait for that rather than sleeping a
// guessed interval.
func (h *hubHarness) waitConnects(n int) []connectRecord {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, connects := h.snapshot(); len(connects) >= n {
			return connects
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, connects := h.snapshot()
	h.t.Fatalf("only %d OnConnect callbacks after 5s, want %d", len(connects), n)
	return nil
}

// TestOnConnectFiresOnEveryConnectNotJustEnrollment is the regression test for
// the architectural half of this fix.
//
// Capabilities and build version used to be recorded from OnEnroll alone, which
// fires exactly once in a device's life. Since an upgrade is precisely the event
// that changes those facts, the stored inventory was frozen at each device's
// join date: a device upgraded a year later went on being reported as the build
// it arrived with. That reproduced, in the database, the same staleness the
// hardcoded agent version produced on the wire.
func TestOnConnectFiresOnEveryConnectNotJustEnrollment(t *testing.T) {
	h := newHubHarness(t)

	// First connect: redeems the enrollment token. The device reports an old
	// build.
	first := defaultHello()
	first.AgentID = "" // a freshly enrolling agent does not know its ID yet
	first.AgentVersion = "v0.1.0"
	credential, closeFirst := h.dial(h.token, first)
	if strings.TrimSpace(credential) == "" {
		t.Fatal("enrollment did not issue a credential")
	}
	connects := h.waitConnects(1)
	if connects[0].version != "v0.1.0" {
		t.Errorf("first connect reported version %q, want v0.1.0", connects[0].version)
	}
	enrolls, _ := h.snapshot()
	if len(enrolls) != 1 {
		t.Fatalf("OnEnroll fired %d times on enrollment, want 1", len(enrolls))
	}
	agentID := connects[0].agentID
	closeFirst()

	// Second connect: the device has been upgraded and reconnects with its
	// long-lived credential, reporting a newer build and more cores.
	second := defaultHello()
	second.AgentID = agentID
	second.AgentVersion = "v0.9.9"
	second.Capabilities.CPUs = 16
	_, closeSecond := h.dial(credential, second)
	defer closeSecond()

	connects = h.waitConnects(2)
	if got := connects[1].version; got != "v0.9.9" {
		t.Errorf("reconnect reported version %q, want v0.9.9 — an upgraded device's "+
			"build must be visible without re-enrolling", got)
	}
	if got := connects[1].cpus; got != 16 {
		t.Errorf("reconnect reported %d CPUs, want 16 — refreshed capabilities must "+
			"reach the recorder too", got)
	}

	// And enrollment must NOT have fired again: it is an auditable one-time
	// event that also establishes CreatedAt and the minting token, which a
	// reconnect has no business re-asserting.
	enrolls, _ = h.snapshot()
	if len(enrolls) != 1 {
		t.Errorf("OnEnroll fired %d times across two connects, want 1", len(enrolls))
	}
}

// TestOnConnectCarriesLegacyPlaceholderVerbatim: the hub must pass through
// whatever the device said, including the old hardcoded "1", rather than
// normalising it. Classification is the reader's job, and a hub that rewrote
// "1" to "unknown" would destroy the distinction between "an old build" and "a
// build that said nothing".
func TestOnConnectCarriesLegacyPlaceholderVerbatim(t *testing.T) {
	h := newHubHarness(t)

	hello := defaultHello()
	hello.AgentID = ""
	hello.AgentVersion = "1"
	_, closeConn := h.dial(h.token, hello)
	defer closeConn()

	connects := h.waitConnects(1)
	if connects[0].version != "1" {
		t.Errorf("OnConnect version = %q, want the verbatim %q", connects[0].version, "1")
	}
}
