package hubcluster_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
)

// peerServer is a member's HTTP side: it verifies peer claims the way pkg/ui
// does and reports what it saw.
func peerServer(t *testing.T, n **hubcluster.Node) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		pc, err := (*n).VerifyPeer(r)
		out := map[string]any{
			"host":   r.Host,
			"cookie": r.Header.Get("Cookie"),
			"query":  r.URL.RawQuery,
		}
		if err != nil {
			out["peer_error"] = err.Error()
		} else {
			out["from"] = pc.From.ID
			out["client_ip"] = pc.ClientIP
		}
		body, _ := io.ReadAll(r.Body)
		out["body"] = string(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/rpc", func(w http.ResponseWriter, r *http.Request) {
		if _, err := (*n).VerifyPeer(r); err != nil {
			http.Error(w, `{"error":"not a peer"}`, http.StatusForbidden)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		_ = json.NewEncoder(w).Encode(map[string]string{"echo": in["say"]})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if _, err := (*n).VerifyPeer(r); err != nil {
			http.Error(w, "not a peer", http.StatusForbidden)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, msg, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, append([]byte("owner:"), msg...)); err != nil {
				return
			}
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pair builds two members whose advertise URLs point at test servers.
func pair(t *testing.T) (a, b *hubcluster.Node, srvB *httptest.Server) {
	t.Helper()
	path := dbPath(t)
	var nb *hubcluster.Node
	srvB = peerServer(t, &nb)
	optsA := fastOpts(path)
	optsA.AdvertiseURL = "http://127.0.0.1:1" // a is never the target here
	a = join(t, optsA)
	optsB := fastOpts(path)
	optsB.AdvertiseURL = srvB.URL
	b = join(t, optsB)
	nb = b
	eventually(t, "a to see b", func() bool { return a.IsAlive(b.ID()) })
	return a, b, srvB
}

func memberOf(t *testing.T, n *hubcluster.Node, id string) hubcluster.Member {
	t.Helper()
	m, ok := n.Member(id)
	if !ok {
		t.Fatalf("member %s unknown to %s", id, n.ID())
	}
	return m
}

// TestForwardCarriesTheRequestAndProvesTheSender: the owner sees the client's
// credentials and Host, and can verify the forwarder is a member.
func TestForwardCarriesTheRequestAndProvesTheSender(t *testing.T) {
	a, b, _ := pair(t)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = a.Forward(w, r, memberOf(t, a, b.ID()), "203.0.113.9")
	}))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/echo?project_idx=2", strings.NewReader("payload"))
	req.Host = "cloop.example.com"
	req.Header.Set("Cookie", "cloop_session=abc")
	// A client pretending to be a peer: the forwarder must strip this.
	req.Header.Set(hubcluster.HeaderPeer, "hub_forged")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["peer_error"] != "" {
		t.Fatalf("owner could not verify the forwarder: %s", got["peer_error"])
	}
	if got["from"] != a.ID() || got["client_ip"] != "203.0.113.9" {
		t.Fatalf("peer claim = from %q ip %q", got["from"], got["client_ip"])
	}
	if got["host"] != "cloop.example.com" || got["cookie"] != "cloop_session=abc" ||
		got["query"] != "project_idx=2" || got["body"] != "payload" {
		t.Fatalf("forwarded request lost something: %+v", got)
	}
}

func TestForgedAndReplayedPeerClaimsAreRefused(t *testing.T) {
	a, b, srvB := pair(t)

	// No claim at all is an ordinary client.
	plain, _ := http.NewRequest(http.MethodGet, srvB.URL+"/echo", nil)
	if _, err := b.VerifyPeer(plain); !errors.Is(err, hubcluster.ErrNotPeer) {
		t.Fatalf("plain request = %v, want ErrNotPeer", err)
	}

	// A claim with a made-up signature.
	forged, _ := http.NewRequest(http.MethodGet, srvB.URL+"/echo", nil)
	forged.Header.Set(hubcluster.HeaderPeer, a.ID())
	forged.Header.Set(hubcluster.HeaderPeerTime, "1")
	forged.Header.Set(hubcluster.HeaderPeerNonce, "n")
	forged.Header.Set(hubcluster.HeaderPeerSig, "00")
	if _, err := b.VerifyPeer(forged); err == nil || errors.Is(err, hubcluster.ErrNotPeer) {
		t.Fatalf("forged claim = %v, want a refusal", err)
	}

	// Capture a genuine forwarded request and replay it.
	var captured *http.Request
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(context.Background())
		if _, err := b.VerifyPeer(r); err != nil {
			t.Errorf("first delivery refused: %v", err)
		}
	}))
	defer capture.Close()
	target := memberOf(t, a, b.ID())
	target.AdvertiseURL = capture.URL
	front := httptest.NewRecorder()
	a.Forward(front, httptest.NewRequest(http.MethodPost, "/api/stop?project_idx=1", nil), target, "198.51.100.1")
	if captured == nil {
		t.Fatal("nothing was forwarded")
	}
	if _, err := b.VerifyPeer(captured); err == nil {
		t.Fatal("a replayed peer request was accepted")
	}

	// A genuine claim for a different URI than the one signed.
	tampered := captured.Clone(context.Background())
	tampered.URL.RawQuery = "project_idx=9"
	tampered.Header.Set(hubcluster.HeaderPeerNonce, "fresh-nonce")
	if _, err := b.VerifyPeer(tampered); err == nil {
		t.Fatal("a request whose URI differs from the signed one was accepted")
	}
}

// TestAPeerRequestIsGoodOnlyAtItsRecipient: nonces are remembered per member,
// so a forwarded request captured on its way to one member must not be
// accepted — not even once — by another, as it is or readdressed.
func TestAPeerRequestIsGoodOnlyAtItsRecipient(t *testing.T) {
	path := dbPath(t)
	a := join(t, fastOpts(path))
	b := join(t, fastOpts(path))
	c := join(t, fastOpts(path))
	eventually(t, "the members to see each other", func() bool {
		return b.IsAlive(a.ID()) && c.IsAlive(a.ID()) && a.IsAlive(b.ID())
	})

	var captured *http.Request
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(context.Background())
	}))
	defer capture.Close()
	target := memberOf(t, a, b.ID())
	target.AdvertiseURL = capture.URL
	a.Forward(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/stop?project_idx=1", nil), target, "198.51.100.1")
	if captured == nil {
		t.Fatal("nothing was forwarded")
	}

	if _, err := c.VerifyPeer(captured.Clone(context.Background())); err == nil {
		t.Fatal("a request signed for one member was accepted by another")
	}
	readdressed := captured.Clone(context.Background())
	readdressed.Header.Set(hubcluster.HeaderPeerTo, c.ID())
	if _, err := c.VerifyPeer(readdressed); err == nil {
		t.Fatal("a request readdressed to another member was accepted there")
	}
	if _, err := b.VerifyPeer(captured); err != nil {
		t.Fatalf("its recipient refused it: %v", err)
	}
}

func TestCallRoundTripsJSON(t *testing.T) {
	a, b, _ := pair(t)
	var out map[string]string
	if err := a.Call(context.Background(), memberOf(t, a, b.ID()), http.MethodPost, "/rpc",
		map[string]string{"say": "hi"}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out["echo"] != "hi" {
		t.Fatalf("reply = %v", out)
	}
	err := a.Call(context.Background(), memberOf(t, a, b.ID()), http.MethodGet, "/missing", nil, nil)
	var ce *hubcluster.CallError
	if !errors.As(err, &ce) || ce.Status != http.StatusNotFound {
		t.Fatalf("Call to a missing path = %v, want a CallError 404", err)
	}
}

// TestForwardUpgradesWebSockets: attach and the dashboard socket are
// WebSockets; the channel must carry the upgrade through.
func TestForwardUpgradesWebSockets(t *testing.T) {
	a, b, _ := pair(t)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = a.Forward(w, r, memberOf(t, a, b.ID()), "")
	}))
	defer front.Close()
	ctx := context.Background()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(front.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("dial through the forwarder: %v", err)
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "owner:ping" {
		t.Fatalf("got %q", msg)
	}
}

func TestForwardToAnUnreachableMemberIsA502(t *testing.T) {
	a, b, _ := pair(t)
	m := memberOf(t, a, b.ID())
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	m.AdvertiseURL = "http://" + ln.Addr().String()
	ln.Close() // nothing listens there now
	rec := httptest.NewRecorder()
	err := a.Forward(rec, httptest.NewRequest(http.MethodGet, "/x", nil), m, "")
	if err == nil || rec.Code != http.StatusBadGateway {
		t.Fatalf("Forward = %v with %d, want a 502", err, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), b.ID()) {
		t.Fatalf("the 502 should name the member: %s", rec.Body.String())
	}

	m.AdvertiseURL = ""
	rec = httptest.NewRecorder()
	if err := a.Forward(rec, httptest.NewRequest(http.MethodGet, "/x", nil), m, ""); !errors.Is(err, hubcluster.ErrNoRoute) {
		t.Fatalf("Forward with no advertise URL = %v, want ErrNoRoute", err)
	}
}
