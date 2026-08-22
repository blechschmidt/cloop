package gitproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// pktEncode frames payloads the way a git client would, so a test can describe
// a stream by the lines it carries rather than by a hex literal.
func pktEncode(payloads ...string) string {
	var b strings.Builder
	for _, p := range payloads {
		fmt.Fprintf(&b, "%04x%s", len(p)+pktHeaderLen, p)
	}
	return b.String()
}

// decodedPkt is one line as the reader handed it back.
type decodedPkt struct {
	typ     pktType
	payload string
}

// decodeAllPkts reads until EOF or the first failure. EOF is the normal end of
// a stream and is reported as success, so a table can describe both halves.
func decodeAllPkts(in string, budget int64) ([]decodedPkt, error) {
	pr := newPktReader(strings.NewReader(in), budget)
	var out []decodedPkt
	for {
		typ, payload, err := pr.next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, decodedPkt{typ: typ, payload: string(payload)})
	}
}

func TestPktReaderDecodesTheFourLineKinds(t *testing.T) {
	maximal := strings.Repeat("x", maxPayloadLen)

	tests := []struct {
		name string
		in   string
		want []decodedPkt
	}{
		{
			name: "one data line",
			in:   pktEncode("hello\n"),
			want: []decodedPkt{{pktData, "hello\n"}},
		},
		{
			// "0004" is a data line with nothing in it, not a flush. Collapsing
			// the two would let a client end a section the parser never saw end.
			name: "empty data line is not a flush",
			in:   "0004",
			want: []decodedPkt{{pktData, ""}},
		},
		{
			name: "flush",
			in:   "0000",
			want: []decodedPkt{{pktFlush, ""}},
		},
		{
			name: "delim",
			in:   "0001",
			want: []decodedPkt{{pktDelim, ""}},
		},
		{
			name: "response end",
			in:   "0002",
			want: []decodedPkt{{pktResponseEnd, ""}},
		},
		{
			name: "mixed stream keeps wire order",
			in:   pktEncode("a") + "0000" + pktEncode("b") + "0001" + "0002",
			want: []decodedPkt{
				{pktData, "a"}, {pktFlush, ""},
				{pktData, "b"}, {pktDelim, ""}, {pktResponseEnd, ""},
			},
		},
		{
			name: "data after a flush is still readable",
			in:   "0000" + pktEncode("PACK"),
			want: []decodedPkt{{pktFlush, ""}, {pktData, "PACK"}},
		},
		{
			// maxPktLen exactly. One byte more is the rejection case below.
			name: "maximal line",
			in:   pktEncode(maximal),
			want: []decodedPkt{{pktData, maximal}},
		},
		{
			// git's own packet_length() reads the prefix with hexval(), which
			// takes either case, so accepting it here keeps the proxy's idea of
			// a line boundary identical to the server's.
			name: "uppercase hex length",
			in:   "000Ahello!",
			want: []decodedPkt{{pktData, "hello!"}},
		},
		{
			name: "empty input decodes to nothing",
			in:   "",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeAllPkts(tc.in, 0)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("decoded %d lines, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("line %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestPktReaderRejectsMalformedFraming(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantMsg string
	}{
		{
			name:    "non-hex length",
			in:      "zzzzhello",
			wantMsg: "is not hex",
		},
		{
			name: "length 0003 is unassigned",
			// 1 and 2 are special-cased above; 3 would describe a line shorter
			// than its own header, and a decoder that accepted it could be
			// walked backwards through the stream.
			in:      "0003x",
			wantMsg: "below the 4-byte header",
		},
		{
			name:    "length above the maximum",
			in:      "fff1" + strings.Repeat("x", 100),
			wantMsg: "exceeds the 65520-byte maximum",
		},
		{
			name:    "truncated payload",
			in:      "0009he",
			wantMsg: "reading 5-byte payload",
		},
		{
			name:    "truncated header",
			in:      "00",
			wantMsg: "reading length prefix",
		},
		{
			name:    "header truncated mid-stream",
			in:      pktEncode("a") + "00",
			wantMsg: "reading length prefix",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAllPkts(tc.in, 0)
			if err == nil {
				t.Fatal("want a parse error, got nil")
			}
			if !errors.Is(err, errBadPktLine) {
				t.Fatalf("want errBadPktLine, got %v", err)
			}
			// A truncated stream must not read as a clean end: callers branch on
			// io.EOF to mean "the client stopped between lines".
			if errors.Is(err, io.EOF) {
				t.Errorf("a malformed line must not surface as EOF: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should mention %q", err, tc.wantMsg)
			}
		})
	}
}

// TestPktReaderReportsEOFBetweenLines: an exhausted stream is not an error, and
// ParseReceivePack relies on telling it apart from a malformed one.
func TestPktReaderReportsEOFBetweenLines(t *testing.T) {
	pr := newPktReader(strings.NewReader("0000"), 0)
	if _, _, err := pr.next(); err != nil {
		t.Fatalf("first line: %v", err)
	}
	_, _, err := pr.next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF at the end of the stream, got %v", err)
	}
}

// TestPktReaderStopsAtBudget is the memory bound: a body that never sends a
// flush must not be able to make the hub allocate without limit.
func TestPktReaderStopsAtBudget(t *testing.T) {
	// Data lines with no flush, forever.
	var stream strings.Builder
	for i := 0; i < 100; i++ {
		stream.WriteString(pktEncode("cccc")) // 8 bytes on the wire each
	}

	_, err := decodeAllPkts(stream.String(), 32)
	if err == nil {
		t.Fatal("want the budget to stop the read, got nil")
	}
	if !errors.Is(err, errBadPktLine) {
		t.Fatalf("want errBadPktLine, got %v", err)
	}
	if !strings.Contains(err.Error(), "without a flush") {
		t.Errorf("error %q should say what the budget was for", err)
	}

	t.Run("budget is exact", func(t *testing.T) {
		// Four 8-byte lines fit in 32 bytes; the fifth header does not.
		pr := newPktReader(strings.NewReader(stream.String()), 32)
		for i := 0; i < 4; i++ {
			if _, _, err := pr.next(); err != nil {
				t.Fatalf("line %d should fit in the budget: %v", i, err)
			}
		}
		if _, _, err := pr.next(); err == nil {
			t.Fatal("the line past the budget should have been refused")
		}
	})

	t.Run("zero budget is unlimited", func(t *testing.T) {
		got, err := decodeAllPkts(stream.String(), 0)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 100 {
			t.Errorf("decoded %d lines, want 100", len(got))
		}
	})
}

// TestPktReaderReplaysExactlyWhatItConsumed is the property the whole design
// rests on: the bytes forwarded upstream are the bytes that were inspected,
// not a re-encoding of the parse.
func TestPktReaderReplaysExactlyWhatItConsumed(t *testing.T) {
	// Longer than bufio's default buffer, so the reader has certainly read
	// ahead past the lines it decoded and tail() has to hand back the buffered
	// reader rather than the caller's.
	tailBytes := strings.Repeat("PACKDATA", 2048)
	in := pktEncode("first\n", "second\n") + "0000" + tailBytes

	pr := newPktReader(strings.NewReader(in), 0)
	for {
		typ, _, err := pr.next()
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if typ == pktFlush {
			break
		}
	}

	got, err := io.ReadAll(pr.tail(nil))
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if string(got) != in {
		t.Fatalf("replay differs from the input:\n got %d bytes\nwant %d bytes", len(got), len(in))
	}

	// The consumed half must stop at the flush: anything more would mean the
	// parser had swallowed pack bytes into its decision buffer.
	if want := pktEncode("first\n", "second\n") + "0000"; string(pr.raw) != want {
		t.Errorf("raw = %q, want %q", pr.raw, want)
	}
}

// TestPktReaderReusesABufferedReader: newPktReader must not wrap a *bufio.Reader
// in another one, or the outer buffer would strand bytes the inner one already
// read and the replay would lose them.
func TestPktReaderReusesABufferedReader(t *testing.T) {
	in := pktEncode("line\n") + "0000tail"
	br := bufio.NewReader(strings.NewReader(in))
	pr := newPktReader(br, 0)
	if pr.br != br {
		t.Fatal("an existing *bufio.Reader should be used as-is")
	}
	for {
		typ, _, err := pr.next()
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if typ == pktFlush {
			break
		}
	}
	got, err := io.ReadAll(pr.tail(nil))
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if string(got) != in {
		t.Errorf("replay = %q, want %q", got, in)
	}
}

func TestWritePktRoundTrip(t *testing.T) {
	payloads := []string{"", "x", "unpack ok\n", strings.Repeat("y", 1000), strings.Repeat("z", maxPayloadLen)}

	var buf bytes.Buffer
	for _, p := range payloads {
		if err := writePkt(&buf, []byte(p)); err != nil {
			t.Fatalf("writePkt(%d bytes): %v", len(p), err)
		}
	}
	if err := writeFlush(&buf); err != nil {
		t.Fatalf("writeFlush: %v", err)
	}

	got, err := decodeAllPkts(buf.String(), 0)
	if err != nil {
		t.Fatalf("decode what we wrote: %v", err)
	}
	if len(got) != len(payloads)+1 {
		t.Fatalf("decoded %d lines, want %d", len(got), len(payloads)+1)
	}
	for i, p := range payloads {
		if got[i].typ != pktData || got[i].payload != p {
			t.Errorf("line %d = (%v, %d bytes), want data with %d bytes",
				i, got[i].typ, len(got[i].payload), len(p))
		}
	}
	if last := got[len(got)-1]; last.typ != pktFlush {
		t.Errorf("last line = %v, want a flush", last.typ)
	}

	t.Run("header is lowercase hex of the total length", func(t *testing.T) {
		var b bytes.Buffer
		if err := writePkt(&b, []byte("abc")); err != nil {
			t.Fatalf("writePkt: %v", err)
		}
		if b.String() != "0007abc" {
			t.Errorf("framed = %q, want %q", b.String(), "0007abc")
		}
	})
}

func TestWritePktRejectsOversizePayload(t *testing.T) {
	var buf bytes.Buffer
	err := writePkt(&buf, make([]byte, maxPayloadLen+1))
	if err == nil {
		t.Fatal("want an error for a payload that cannot be framed, got nil")
	}
	if buf.Len() != 0 {
		t.Errorf("a refused write must emit nothing, wrote %d bytes", buf.Len())
	}
}

// TestWriteSidebandSplitsLargePayloads: every fragment has to carry the channel
// byte, because a client demultiplexes on it and a fragment that lost it would
// be parsed as pack data.
func TestWriteSidebandSplitsLargePayloads(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		channel   byte
		wantLines int
	}{
		{"empty payload writes nothing", 0, sidebandProgress, 0},
		{"short payload", 10, sidebandProgress, 1},
		{"exactly one full packet", sidebandMaxPayload, sidebandData, 1},
		{"one byte over", sidebandMaxPayload + 1, sidebandData, 2},
		{"two and a bit packets", 2*sidebandMaxPayload + 7, sidebandError, 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte('a' + i%26)
			}

			var buf bytes.Buffer
			if err := writeSideband(&buf, tc.channel, payload); err != nil {
				t.Fatalf("writeSideband: %v", err)
			}

			got, err := decodeAllPkts(buf.String(), 0)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != tc.wantLines {
				t.Fatalf("wrote %d packets, want %d", len(got), tc.wantLines)
			}

			var rejoined []byte
			for i, line := range got {
				if line.typ != pktData {
					t.Fatalf("packet %d is %v, want a data line", i, line.typ)
				}
				if line.payload[0] != tc.channel {
					t.Errorf("packet %d starts with channel %d, want %d", i, line.payload[0], tc.channel)
				}
				if n := len(line.payload) - 1; n > sidebandMaxPayload {
					t.Errorf("packet %d carries %d payload bytes, at most %d fit", i, n, sidebandMaxPayload)
				}
				rejoined = append(rejoined, line.payload[1:]...)
			}
			if !bytes.Equal(rejoined, payload) {
				t.Errorf("rejoined payload is %d bytes, want the original %d", len(rejoined), len(payload))
			}
		})
	}
}
