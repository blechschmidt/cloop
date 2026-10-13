package auditforward

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The address rule is applied to the address a socket connects to: a cloud
// metadata service is refused for every sink, in every spelling a resolver
// could hand back, and a plaintext sink reaches loopback and nothing else.
func TestTheDialerRefusesMetadataAndPlaintextOffHost(t *testing.T) {
	for _, c := range []struct {
		addr      string
		plaintext bool
		want      error
	}{
		{"169.254.169.254:443", false, ErrMetadataAddress},
		{"[::ffff:169.254.169.254]:443", false, ErrMetadataAddress},
		{"[64:ff9b::a9fe:a9fe]:443", false, ErrMetadataAddress},       // NAT64 of 169.254.169.254
		{"[2002:a9fe:a9fe::1]:443", false, ErrMetadataAddress},        // 6to4 of it
		{"100.100.100.200:443", false, ErrMetadataAddress},            // Alibaba Cloud
		{"[fd00:ec2::254]:443", false, ErrMetadataAddress},            // AWS over IPv6
		{"168.63.129.16:443", false, ErrMetadataAddress},              // Azure WireServer
		{"10.20.30.40:6514", false, nil},                              // a SIEM on a private network
		{"203.0.113.9:443", false, nil},                               // a SIEM on the Internet
		{"127.0.0.1:514", true, nil},                                  // a local collector
		{"[::1]:514", true, nil},                                      //
		{"10.20.30.40:514", true, ErrPlaintextOffHost},                // plaintext off the host
		{"[::ffff:10.20.30.40]:514", true, ErrPlaintextOffHost},       //
		{"169.254.169.254:80", true, ErrMetadataAddress},              // both, and metadata wins
		{"[::ffff:127.0.0.1]:514", true, nil},                         // loopback, mapped
		{"[64:ff9b::7f00:1]:514", true, ErrPlaintextOffHost},          // 127.0.0.1 behind a NAT64 gateway is off the host
		{"[2606:4700::6810:84e5]:443", false, nil},                    // public v6
		{"[fe80::a9fe:a9fe]:80", false, ErrMetadataAddress},           // OpenStack over v6
		{"[::169.254.169.254]:443", false, ErrMetadataAddress},        // IPv4-compatible spelling
		{"[::ffff:0:a9fe:a9fe]:443", false, ErrMetadataAddress},       // IPv4-translatable spelling
		{"[64:ff9b:1:a9fe:a9:fe00::]:443", false, ErrMetadataAddress}, // NAT64 local-use
	} {
		err := checkDialAddress(c.addr, c.plaintext)
		switch {
		case c.want == nil && err != nil:
			t.Errorf("%s (plaintext %v): refused: %v", c.addr, c.plaintext, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s (plaintext %v): got %v, want %v", c.addr, c.plaintext, err, c.want)
		}
	}
}

// End to end: an https sink aimed at a metadata address fails at the dial,
// before a byte of the trail — or its token — leaves.
func TestAnHTTPSSinkNeverConnectsToAMetadataService(t *testing.T) {
	tr, err := newTransport(config.AuditForwardSink{
		Name: "meta", Type: config.AuditSinkHTTPS, URL: "https://169.254.169.254/latest", Timeout: "2s",
	}, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	err = tr.send(context.Background(), []message{{id: 1, data: []byte(`{}`)}})
	if !errors.Is(err, ErrMetadataAddress) {
		t.Fatalf("send = %v, want the metadata refusal", err)
	}
}

// A redirect is a failed send: the rows, and the token with them, never go to
// wherever a 3xx points.
func TestTheHTTPSSinkFollowsNoRedirect(t *testing.T) {
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the redirect target received a %s with Authorization %q", r.Method, r.Header.Get("Authorization"))
	}))
	defer elsewhere.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	tr, err := newTransport(config.AuditForwardSink{
		Name: "redir", Type: config.AuditSinkHTTPS, URL: redirector.URL, CAFile: caFileFor(t, redirector), TokenSecret: "tok",
	}, func(string) ([]byte, error) { return []byte("token"), nil }, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	err = tr.send(context.Background(), []message{{id: 1, data: []byte(`{}`)}})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("send = %v, want a refused redirect", err)
	}
}

// The forwarder refuses a plaintext sink off the host when it builds the
// transport, whatever got it past loading: the rule holds where it is
// enforced, not only where it was checked.
func TestTheTransportRefusesPlaintextOffHost(t *testing.T) {
	for _, s := range []config.AuditForwardSink{
		{Name: "a", Type: config.AuditSinkSyslog, Address: "10.0.0.5:514", Transport: "tcp", AllowPlaintextLoopback: true},
		{Name: "b", Type: config.AuditSinkHTTPS, URL: "http://siem.example.com/ingest", AllowPlaintextLoopback: true},
	} {
		if _, err := newTransport(s, nil, "test"); err == nil || !strings.Contains(err.Error(), "not a loopback") {
			t.Errorf("%s: newTransport = %v, want the plaintext refusal", s.Name, err)
		}
	}
	// To loopback, acknowledged, it is allowed.
	if _, err := newTransport(config.AuditForwardSink{
		Name: "c", Type: config.AuditSinkSyslog, Address: "127.0.0.1:514", Transport: "tcp", AllowPlaintextLoopback: true,
	}, nil, "test"); err != nil {
		t.Errorf("a plaintext sink to an acknowledged loopback collector was refused: %v", err)
	}
}

// A file sink appends what it is sent, fsynced, and will not write inside a
// .cloop directory even through a symlink.
func TestTheFileSinkKeepsItsCopyOutsideCloop(t *testing.T) {
	hubDir, cp := chainDir(t)
	appendRows(t, cp, 8)
	out := filepath.Join(t.TempDir(), "trail.jsonl")
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "copy", Type: config.AuditSinkFile, Path: out, BatchSize: 3,
	}}})
	h.start(Hooks{})
	waitForLogged(t, h, "the file to hold the chain", 10*time.Second, func() bool {
		return cursorOf(t, cp, "copy", cp).AckedID == maxID(t, cp)
	})
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if v := chainVerdict(t, verify(t, string(b)), SourceControlPlane, hubDir); !v.OK() || v.LastID != maxID(t, cp) {
		t.Fatalf("the file does not hold the chain: %+v", v)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("the copy is mode %o, want 0600", fi.Mode().Perm())
	}

	// A symlink walking the copy back beside the database is refused.
	link := filepath.Join(t.TempDir(), "sneaky.jsonl")
	if err := os.Symlink(filepath.Join(hubDir, ".cloop", "copy.jsonl"), link); err != nil {
		t.Fatal(err)
	}
	ft := &fileTransport{path: link}
	if err := ft.send(context.Background(), []message{{id: 1, data: []byte(`{}`)}}); err == nil ||
		!strings.Contains(err.Error(), ".cloop") {
		t.Fatalf("a symlink into .cloop was written through: %v", err)
	}
}

// A row too large for the syslog sink's message size goes with its payload
// left out — saying so, with the payload's length and digest — rather than
// cut mid-record by a collector.
func TestAnOversizedRowIsSentWithItsPayloadLeftOut(t *testing.T) {
	enc := &encoder{cfg: config.AuditForwardSink{Name: "s", Type: config.AuditSinkSyslog, MaxMessageBytes: 2048}, hub: "h", version: "t"}
	var ev statedb.AuditEvent
	ev.ID, ev.Timestamp, ev.Actor, ev.EventType = 7, time.Now().UTC(), "a", "task.upsert"
	ev.Payload = `{"big":"` + strings.Repeat("y", 10000) + `"}`
	ev.PrevHash, ev.RowHash = strings.Repeat("0", 64), strings.Repeat("1", 64)
	m, err := enc.encode(ev, Chain{Source: SourceProject, Dir: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.truncated || len(m.data) > 2048 {
		t.Fatalf("message of %d bytes, truncated %v; want at most 2048 and marked", len(m.data), m.truncated)
	}
	for _, want := range []string{`"payload_truncated":true`, `"payload_bytes":10010`, `"payload_sha256":"`, `"row_hash":"1111`} {
		if !strings.Contains(string(m.data), want) {
			t.Errorf("the message does not carry %s:\n%s", want, m.data)
		}
	}
}
