package agent

// Cross-version enrollment: the frame an agent sends before any version exists
// to send it at (Task 20312).

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestHelloEnvelopeIsStampedAtTheProtocolFloor is a cross-version regression
// test, and it is here because the failure it prevents was found by shipping a
// protocol bump and watching a real device fail to enroll.
//
// A receiver validates a frame's envelope version against its own supported
// range before it decodes the payload. So a newer agent greeting an older hub
// with an envelope stamped at its own maximum is rejected at the transport —
// "frame version 9 not in [1,8]" — and NegotiateVersion, whose entire premise
// is "the peer is newer, ask it to drop to our maximum", never runs. Every
// protocol bump then becomes a hard requirement to upgrade every hub before any
// agent, which is the opposite of what the version ladder is for.
//
// The invariant: the envelope rides at the floor so anyone can parse it, and
// the build's real version travels in the payload, which is what the hub
// negotiates against.
func TestHelloEnvelopeIsStampedAtTheProtocolFloor(t *testing.T) {
	a, conns := newScriptedAgent(t, filepath.Join(t.TempDir(), "agent.json"), t.TempDir())
	go func() { _ = a.Run(t.Context()) }()

	cp := <-conns
	f := cp.readUntil(remote.TypeHello, 5*time.Second)

	if f.V != remote.MinProtocolVersion {
		t.Errorf("hello envelope version = %d, want the floor %d; a hub whose maximum is "+
			"below %d would reject this frame before negotiating",
			f.V, remote.MinProtocolVersion, f.V)
	}
	hello, err := remote.DecodeHello(f)
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}
	if hello.ProtocolVersion != remote.ProtocolVersion {
		t.Errorf("hello payload advertises v%d, want this build's v%d; the floor belongs on "+
			"the envelope only, or the hub negotiates down to v%d forever",
			hello.ProtocolVersion, remote.ProtocolVersion, remote.MinProtocolVersion)
	}
}
