package security

// Guarantee 6: the remote agent protocol survives a hostile peer.
//
// This is the one boundary in cloop where the code on the other end is not
// cloop's. A remote executor agent runs on an edge device the operator may not
// physically control, reached over a link an attacker may sit on, and it
// speaks directly to the control plane's session loop. Every byte the hub
// parses here is attacker-influenced.
//
// The hazards, in the order they bite:
//
//   - unbounded reads: a peer that announces a huge frame makes the hub
//     allocate for it, and one connection OOMs the control plane for every
//     tenant on it;
//   - truncation: a frame cut mid-structure must produce an error, not a
//     half-populated struct that later code treats as authoritative;
//   - malformed bodies: a decoder that panics on bad input turns a crafted
//     frame into a denial of service, since a panic in a session goroutine
//     takes the process with it unless something recovers.
//
// Fuzzing is the right tool because the input is a grammar an attacker
// controls completely, and the interesting inputs are the ones no one thought
// to write down.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// decodeAll runs every exported payload decoder against a frame.
//
// The decoders are called regardless of the frame's declared type on purpose:
// a hostile peer picks the type byte, so "DecodeStart on a frame claiming to
// be a heartbeat" is a reachable state and must not panic.
func decodeAll(f remote.Frame) {
	_, _ = remote.DecodeHello(f)
	_, _ = remote.DecodeWelcome(f)
	_, _ = remote.DecodeHeartbeat(f)
	_, _ = remote.DecodeHeartbeatAck(f)
	_, _ = remote.DecodeStart(f)
	_, _ = remote.DecodeStarted(f)
	_, _ = remote.DecodeSignal(f)
	_, _ = remote.DecodeLogChunk(f)
	_, _ = remote.DecodeLogAck(f)
	_, _ = remote.DecodeStatus(f)
	_, _ = remote.DecodeBye(f)
	_, _ = remote.DecodeError(f)
}

// FuzzFrameDecoding is the main target: arbitrary bytes off the wire, through
// the same unmarshal-then-validate path the session loop uses, then through
// every payload decoder.
//
// The assertion is mostly "does not panic", which sounds weak and is not. The
// session goroutine that calls these decoders handles one agent's connection;
// a panic there is a crash the peer chose, and this is the cheapest possible
// way to prove no crafted frame can cause one.
func FuzzFrameDecoding(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`null`,
		`[]`,
		`"just a string"`,
		`{"v":1,"type":"hello"}`,
		`{"v":1,"type":"start","handle":"h1","payload":{"spec":{"argv":["/bin/true"]}}}`,
		`{"v":1,"type":"log","handle":"h1","payload":{"stream":"stdout","text":"x","seq":1}}`,
		`{"v":0,"type":"hello"}`,
		`{"v":999999,"type":"hello"}`,
		`{"v":-1,"type":""}`,
		`{"v":1,"type":"start"}`,                        // handle-scoped frame with no handle
		`{"v":1,"type":"log","handle":"h","payload":1}`, // payload of the wrong JSON kind
		`{"v":1,"type":"status","handle":"h","payload":{"exit_code":-9223372036854775808}}`,
		`{"v":1,"type":"log","handle":"h","payload":{"seq":18446744073709551615}}`,
		`{"v":1,"type":"hello","payload":{"labels":{"a":"` + strings.Repeat("x", 1024) + `"}}}`,
		"{\"v\":1,\"type\":\"hello\",\"payload\":{\"name\":\"\x00\xff\xfe\"}}",
		`{"v":1,"type":"start","handle":"h","payload":{"spec":{"env":["NOEQUALS"]}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var frame remote.Frame
		if err := json.Unmarshal(data, &frame); err != nil {
			return // not a frame at all; the session loop rejects it here
		}

		if err := frame.Validate(); err != nil {
			// Rejected frames must never be decoded further, but the
			// decoders must still be panic-free if someone gets the order
			// wrong — defense in depth against a future refactor.
			decodeAll(frame)
			return
		}

		// A frame that Validate accepted must satisfy the bounds Validate
		// claims to enforce. This is the assertion that catches a validator
		// whose checks drift out of agreement with its documentation.
		if len(frame.Payload) > remote.MaxFrameBytes {
			t.Fatalf("Validate accepted a %d-byte payload, above the %d-byte cap",
				len(frame.Payload), remote.MaxFrameBytes)
		}
		if strings.TrimSpace(string(frame.Type)) == "" {
			t.Fatal("Validate accepted a frame with no type")
		}
		decodeAll(frame)
	})
}

// FuzzFrameTruncation feeds prefixes of well-formed frames.
//
// Truncation is its own hazard because it is the one an ordinary network
// produces by accident — a dropped connection mid-write — as well as one an
// attacker produces on purpose. The failure to avoid is a decoder that reads
// a partial structure, returns no error, and hands downstream code a struct
// whose zero fields look like real values.
func FuzzFrameTruncation(f *testing.F) {
	whole := []string{
		`{"v":1,"type":"hello","payload":{"name":"edge-01","version":"1"}}`,
		`{"v":1,"type":"start","handle":"h1","payload":{"spec":{"argv":["/bin/true"],"work_dir":"/w"}}}`,
		`{"v":1,"type":"log","handle":"h1","payload":{"stream":"stdout","text":"hello","seq":7}}`,
		`{"v":1,"type":"status","handle":"h1","payload":{"state":"exited","exit_code":0}}`,
	}
	for _, s := range whole {
		for _, cut := range []int{1, len(s) / 4, len(s) / 2, len(s) - 1} {
			if cut > 0 && cut < len(s) {
				f.Add(s, cut)
			}
		}
	}

	f.Fuzz(func(t *testing.T, body string, cut int) {
		if len(body) == 0 {
			return
		}
		if cut < 0 {
			cut = -cut
		}
		cut %= len(body)
		truncated := body[:cut]

		var frame remote.Frame
		if err := json.Unmarshal([]byte(truncated), &frame); err != nil {
			return // the expected outcome for a cut structure
		}
		// If it did parse (a prefix can be valid JSON, e.g. a bare number),
		// validation and decoding must still be safe.
		_ = frame.Validate()
		decodeAll(frame)
	})
}

// TestOversizedFrameIsRejected pins the memory bound at the two places it is
// expressed: the payload check inside Validate, and the constant the
// connection's read limit is set from.
func TestOversizedFrameIsRejected(t *testing.T) {
	// A payload one byte over the cap must be refused. Building it as raw
	// JSON rather than marshalling a struct keeps the test's memory use
	// proportional to the cap and not to a Go value's overhead.
	oversized := make([]byte, remote.MaxFrameBytes+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	frame := remote.Frame{
		V:       1,
		Type:    remote.TypeLogChunk,
		Handle:  "h1",
		Payload: json.RawMessage(`"` + string(oversized) + `"`),
	}
	if err := frame.Validate(); err == nil {
		t.Fatalf("a %d-byte payload passed validation; the cap is %d and a peer "+
			"could make the hub allocate without bound",
			len(frame.Payload), remote.MaxFrameBytes)
	}

	// And a payload comfortably under it must pass, or the cap is not a cap
	// but an outage.
	small := remote.Frame{
		V: 1, Type: remote.TypeLogChunk, Handle: "h1",
		Payload: json.RawMessage(`{"stream":"stdout","text":"ok","seq":1}`),
	}
	if err := small.Validate(); err != nil {
		t.Fatalf("an ordinary frame was rejected: %v", err)
	}
}

// TestFrameSizeCapIsSane guards the constant itself. A cap raised to
// something like 1 GiB "to fix a truncation bug" would silently reintroduce
// the memory-exhaustion vector the cap exists to close, and no functional test
// would notice.
func TestFrameSizeCapIsSane(t *testing.T) {
	const (
		floor   = 64 << 10 // below this, ordinary log chunks would not fit
		ceiling = 16 << 20 // above this, a handful of peers can exhaust the hub
	)
	if remote.MaxFrameBytes < floor || remote.MaxFrameBytes > ceiling {
		t.Errorf("MaxFrameBytes = %d, outside the sane range [%d, %d]. "+
			"Too small breaks legitimate log frames; too large lets a few "+
			"hostile peers exhaust the control plane's memory.",
			remote.MaxFrameBytes, floor, ceiling)
	}
}

// TestHandleScopedFramesRequireAHandle covers the confused-deputy shape. A
// frame that acts on a workload but names none would, if accepted, make
// downstream code operate on an empty handle ID — which is at best a lookup
// miss and at worst a match against an unkeyed default.
func TestHandleScopedFramesRequireAHandle(t *testing.T) {
	for _, typ := range []remote.FrameType{
		remote.TypeStart, remote.TypeSignal, remote.TypeLogChunk, remote.TypeStatus,
	} {
		t.Run(string(typ), func(t *testing.T) {
			f := remote.Frame{V: 1, Type: typ, Payload: json.RawMessage(`{}`)}
			if err := f.Validate(); err == nil {
				t.Errorf("a %s frame with no handle was accepted; downstream "+
					"code would act on an empty handle ID", typ)
			}
		})
	}
}

// TestFrameVersionIsBounded checks the negotiated-version window. Accepting an
// arbitrary version number is how a peer talks a hub into a code path meant
// for a protocol it does not actually implement.
func TestFrameVersionIsBounded(t *testing.T) {
	for _, v := range []int{-1, 0, 1 << 30, -(1 << 30)} {
		f := remote.Frame{V: v, Type: remote.TypeHeartbeat}
		if err := f.Validate(); err == nil {
			t.Errorf("frame version %d was accepted; the version window must be "+
				"closed at both ends", v)
		}
	}
}
