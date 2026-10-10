package resultframe

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const testTag = "k-0123456789ab"

func payloadOf(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func frameText(t testing.TB, tag string, kind Kind, payload []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, tag, kind, payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

// scan feeds text in chunks of size n (the whole text when n <= 0) and closes
// the stream, returning the transcript and the scanner.
func scan(t testing.TB, tag, text string, n int) (string, *Scanner) {
	t.Helper()
	s, err := NewScanner(tag)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if n <= 0 {
		n = len(text) + 1
	}
	for i := 0; i < len(text); i += n {
		end := i + n
		if end > len(text) {
			end = len(text)
		}
		out.WriteString(s.Feed(text[i:end]))
	}
	out.WriteString(s.Close())
	return out.String(), s
}

func wantErr(t *testing.T, s *Scanner, class error) {
	t.Helper()
	f, err := s.Result()
	if err == nil {
		t.Fatalf("accepted a %d-byte frame; want %v", len(f.Payload), class)
	}
	if !errors.Is(err, class) {
		t.Fatalf("err = %v, want %v", err, class)
	}
	if _, err := s.Take(); err == nil {
		t.Fatal("Take handed out a frame Result refused")
	}
}

// TestRoundTrip is the contract: what Write renders, a scanner gives back
// byte for byte — whatever the stream's chunking — and leaves the transcript
// around it untouched.
func TestRoundTrip(t *testing.T) {
	for _, size := range []int{1, 2, 3, dataChunkBytes - 1, dataChunkBytes, dataChunkBytes + 1,
		5*dataChunkBytes + 17, executor.MaxProjectResultBytes} {
		payload := payloadOf(t, size)
		before := "working…\nTASK_DONE\n"
		after := "a line printed after the frame\n"
		text := before + frameText(t, testTag, KindResult, payload) + after
		for _, chunk := range []int{0, 1, 7, 4096, 65536} {
			if size == executor.MaxProjectResultBytes && chunk == 1 {
				continue // a million single-byte feeds prove nothing chunk 7 does not
			}
			t.Run(fmt.Sprintf("%d/%d", size, chunk), func(t *testing.T) {
				transcript, s := scan(t, testTag, text, chunk)
				if want := before + "\n" + after; transcript != want {
					t.Errorf("transcript = %q, want %q", clip(transcript), clip(want))
				}
				f, err := s.Take()
				if err != nil {
					t.Fatalf("Take: %v", err)
				}
				if f.Kind != KindResult || !bytes.Equal(f.Payload, payload) {
					t.Fatalf("got a %s frame of %d bytes, want the %d written", f.Kind, len(f.Payload), size)
				}
				if cap(f.Payload) != len(f.Payload) {
					t.Errorf("payload cap %d over len %d: a retained frame must hold exactly what was declared",
						cap(f.Payload), len(f.Payload))
				}
				if _, err := s.Take(); !errors.Is(err, ErrTaken) {
					t.Errorf("second Take: %v, want ErrTaken", err)
				}
			})
		}
	}
}

func TestErrorFrameRoundTrip(t *testing.T) {
	reason := []byte("the workload removed the project it was sent")
	_, s := scan(t, testTag, frameText(t, testTag, KindError, reason), 3)
	f, err := s.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if f.Kind != KindError || string(f.Payload) != string(reason) {
		t.Fatalf("got %s %q", f.Kind, f.Payload)
	}
}

// TestFrameSurvivesForeignLinesBetweenItsOwn: a container runtime merges stdout
// and stderr line by line, so the wrapper's own stderr — or a background
// process's — can land between two of the frame's lines. Whole foreign lines
// are transcript and leave the frame intact.
func TestFrameSurvivesForeignLinesBetweenItsOwn(t *testing.T) {
	payload := payloadOf(t, 3*dataChunkBytes)
	lines := strings.SplitAfter(frameText(t, testTag, KindResult, payload), "\n")
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(l)
		if i > 0 && l != "" {
			fmt.Fprintf(&b, "writeback: stderr line %d\n", i)
		}
	}
	transcript, s := scan(t, testTag, b.String(), 11)
	f, err := s.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatal("payload differs")
	}
	if !strings.Contains(transcript, "writeback: stderr line 2\n") || strings.Contains(transcript, Marker) {
		t.Errorf("transcript = %q", clip(transcript))
	}
}

// TestOtherTagsAreTranscript: a frame tagged for another run — a fixture the
// workload printed, a nested run's — is somebody else's text.
func TestOtherTagsAreTranscript(t *testing.T) {
	other := frameText(t, "k-ffffffffffff", KindResult, payloadOf(t, 100))
	// A tag that merely starts with ours is another tag too.
	longer := frameText(t, testTag+"0", KindResult, payloadOf(t, 100))
	transcript, s := scan(t, testTag, other+longer, 5)
	if transcript != other+longer {
		t.Errorf("another tag's frame was not passed through intact")
	}
	wantErr(t, s, ErrNoFrame)
}

func TestTruncated(t *testing.T) {
	text := frameText(t, testTag, KindResult, payloadOf(t, 4*dataChunkBytes))
	lines := strings.SplitAfter(text, "\n")
	cases := map[string]string{
		// No end line: the stream stopped after the last data line.
		"no end": strings.Join(lines[:len(lines)-2], ""),
		// Cut in the middle of a data line.
		"mid line": text[:len(text)/2],
		// An end line arrived, but a data line before it did not.
		"missing data": strings.Join(append(append([]string{}, lines[:3]...), lines[4:]...), ""),
		// Only the begin.
		"begin only": strings.Join(lines[:2], ""),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, s := scan(t, testTag, in, 64)
			wantErr(t, s, ErrTruncated)
		})
	}
}

// TestInterleavedAndDuplicated: two frames bearing the tag can only mean one
// was not the wrapper's. Neither is believed.
func TestInterleavedAndDuplicated(t *testing.T) {
	a := frameText(t, testTag, KindResult, payloadOf(t, 2*dataChunkBytes))
	b := frameText(t, testTag, KindResult, payloadOf(t, 2*dataChunkBytes))
	al, bl := strings.SplitAfter(a, "\n"), strings.SplitAfter(b, "\n")
	var interleaved strings.Builder
	for i := range al {
		interleaved.WriteString(al[i])
		if i < len(bl) {
			interleaved.WriteString(bl[i])
		}
	}
	afterEnd := strings.SplitAfter(a, "\n")
	cases := map[string]string{
		"twice":            a + a,
		"forged then real": b + a,
		"interleaved":      interleaved.String(),
		// A begin while the first frame is open.
		"nested": strings.Join(al[:3], "") + b + strings.Join(al[3:], ""),
		// A stray data line after the frame closed.
		"data after end": a + afterEnd[2],
		// A trailing line bearing the tag that never ends.
		"unfinished line after end": a + Marker + " " + testTag + " data AAAA",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, s := scan(t, testTag, in, 97)
			wantErr(t, s, ErrDuplicate)
		})
	}
}

func TestUnframedAndMalformed(t *testing.T) {
	payload := payloadOf(t, 300)
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	p := Marker + " " + testTag + " "
	data := p + "data " + base64.StdEncoding.EncodeToString(payload) + "\n"
	begin := func(kind, n, digest string) string { return p + "begin " + kind + " " + n + " " + digest + "\n" }
	n := strconv.Itoa(len(payload))
	cases := map[string]string{
		"data without begin":     data + p + "end\n",
		"end without begin":      p + "end\n",
		"unknown verb":           p + "hello\n",
		"bare tag":               Marker + " " + testTag + "\n",
		"unknown kind":           begin("bundle", n, hexSum) + data + p + "end\n",
		"bad length":             begin("result", "-1", hexSum) + data + p + "end\n",
		"leading zero":           begin("result", "0"+n, hexSum) + data + p + "end\n",
		"zero length":            begin("result", "0", hexSum) + p + "end\n",
		"short digest":           begin("result", n, hexSum[:10]) + data + p + "end\n",
		"upper-case digest":      begin("result", n, strings.ToUpper(hexSum)) + data + p + "end\n",
		"extra begin field":      p + "begin result " + n + " " + hexSum + " x\n" + data + p + "end\n",
		"checksum mismatch":      begin("result", n, strings.Repeat("0", 64)) + data + p + "end\n",
		"not base64":             begin("result", n, hexSum) + p + "data !!!!\n" + p + "end\n",
		"ragged base64":          begin("result", n, hexSum) + p + "data QUJD" + "QQ\n" + p + "end\n",
		"cr inside data":         begin("result", n, hexSum) + p + "data QU\rJD\n" + p + "end\n",
		"more than declared":     begin("result", "3", hexSum) + data + p + "end\n",
		"end with arguments":     begin("result", n, hexSum) + data + p + "end now\n",
		"overlong line":          begin("result", n, hexSum) + p + "data " + strings.Repeat("A", maxLineBytes) + "\n",
		"over the result limit":  begin("result", strconv.Itoa(executor.MaxProjectResultBytes+1), hexSum),
		"over the error limit":   begin("error", strconv.Itoa(executor.MaxProjectResultErrBytes+1), hexSum),
		"absurd declared length": begin("result", "999999999999", hexSum),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			for _, chunk := range []int{0, 1, 13} {
				transcript, s := scan(t, testTag, in, chunk)
				if _, err := s.Result(); err == nil || errors.Is(err, ErrNoFrame) {
					t.Fatalf("chunk %d: Result = %v, want a refusal", chunk, err)
				}
				if strings.Contains(transcript, Marker+" "+testTag+" ") {
					t.Errorf("chunk %d: a line of frame protocol reached the transcript: %q", chunk, clip(transcript))
				}
			}
		})
	}
}

// TestRefusalIsFinal: once a frame is refused, a well-formed one after it is
// not accepted either — otherwise a workload could break the wrapper's frame
// and follow it with its own.
func TestRefusalIsFinal(t *testing.T) {
	broken := Marker + " " + testTag + " data AAAA\n"
	good := frameText(t, testTag, KindResult, payloadOf(t, 50))
	_, s := scan(t, testTag, broken+good, 0)
	wantErr(t, s, ErrMalformed)
}

// TestOrdinaryOutputIsNotHeld pins the latency and memory bound: a line that
// cannot be a frame line is forwarded the moment it diverges from the marker,
// and a workload printing without newlines costs nothing.
func TestOrdinaryOutputIsNotHeld(t *testing.T) {
	s, err := NewScanner(testTag)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("compiling a very long line without any newline ", 20_000)
	if got := s.Feed(long); got != long {
		t.Fatal("ordinary output was not forwarded as it arrived")
	}
	if s.Buffered() != 0 {
		t.Fatalf("buffered %d bytes of ordinary output", s.Buffered())
	}
	// The start of the marker is held until the line says what it is…
	if got := s.Feed("\n##cloop-pro"); got != "\n" {
		t.Fatalf("Feed = %q", got)
	}
	if s.Buffered() == 0 {
		t.Fatal("a possible frame line was not held")
	}
	// …and released as soon as it diverges.
	if got := s.Feed("gress: 50%\n"); got != "##cloop-progress: 50%\n" {
		t.Fatalf("Feed = %q", got)
	}
	// A line bearing the tag that never ends is bounded too.
	s.Feed(Marker + " " + testTag + " data ")
	s.Feed(strings.Repeat("A", 3*maxLineBytes))
	if s.Buffered() > maxLineBytes {
		t.Fatalf("buffered %d bytes of one line", s.Buffered())
	}
	if got := s.Feed("AAAA\nafter\n"); got != "after\n" {
		t.Fatalf("the rest of an overlong frame line leaked, or the next line was lost: %q", got)
	}
	wantErr(t, s, ErrMalformed)
}

// TestCloseReleasesAHeldNonFrameLine: a last line that never ended and turned
// out not to be protocol is transcript, not lost.
func TestCloseReleasesAHeldNonFrameLine(t *testing.T) {
	transcript, s := scan(t, testTag, "done\n##cloop-project-result-v1##", 0)
	if transcript != "done\n##cloop-project-result-v1##" {
		t.Errorf("transcript = %q", transcript)
	}
	wantErr(t, s, ErrNoFrame)
	if got := s.Feed("after close\n"); got != "after close\n" {
		t.Errorf("Feed after Close = %q", got)
	}
}

func TestCarriageReturnLineEndings(t *testing.T) {
	payload := payloadOf(t, 2*dataChunkBytes+5)
	crlf := strings.ReplaceAll(frameText(t, testTag, KindResult, payload), "\n", "\r\n")
	_, s := scan(t, testTag, crlf, 9)
	f, err := s.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatal("payload differs")
	}
}

func TestDrop(t *testing.T) {
	_, s := scan(t, testTag, frameText(t, testTag, KindResult, payloadOf(t, 900)), 0)
	if n := s.Drop("evicted to make room"); n != 900 {
		t.Fatalf("Drop released %d bytes, want 900", n)
	}
	if _, err := s.Take(); !errors.Is(err, ErrDropped) || !strings.Contains(err.Error(), "evicted") {
		t.Fatalf("Take after Drop: %v", err)
	}
	if n := s.Drop("again"); n != 0 {
		t.Fatalf("a second Drop released %d bytes", n)
	}
}

func TestWriteRefusesWhatNoScannerAccepts(t *testing.T) {
	var buf bytes.Buffer
	for name, err := range map[string]error{
		"bad tag":      Write(&buf, "has space", KindResult, []byte("x")),
		"empty tag":    Write(&buf, "", KindResult, []byte("x")),
		"unknown kind": Write(&buf, testTag, Kind("bundle"), []byte("x")),
		"empty":        Write(&buf, testTag, KindResult, nil),
		"too large":    Write(&buf, testTag, KindResult, make([]byte, executor.MaxProjectResultBytes+1)),
		"error too large": Write(&buf, testTag, KindError,
			make([]byte, executor.MaxProjectResultErrBytes+1)),
	} {
		if err == nil {
			t.Errorf("%s: Write accepted it", name)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("a refused Write wrote %d bytes", buf.Len())
	}
	if _, err := NewScanner("no/slash"); err == nil {
		t.Error("NewScanner accepted an invalid tag")
	}
}

// TestEveryLineIsOneAtomicWrite: the property that lets a frame share a pipe
// with other writers. Each Write call is a whole line under PIPE_BUF.
func TestEveryLineIsOneAtomicWrite(t *testing.T) {
	var w recordingWriter
	if err := Write(&w, strings.Repeat("t", maxTagLen), KindResult, payloadOf(t, 10*dataChunkBytes)); err != nil {
		t.Fatal(err)
	}
	for i, call := range w.calls {
		if !strings.HasSuffix(call, "\n") || strings.Count(call, "\n") != 1 {
			t.Fatalf("write %d is not exactly one line: %q", i, clip(call))
		}
		if len(call) >= maxLineBytes {
			t.Fatalf("write %d is %d bytes, not under %d", i, len(call), maxLineBytes)
		}
	}
}

type recordingWriter struct{ calls []string }

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.calls = append(w.calls, string(p))
	return len(p), nil
}

// failingWriter fails after n writes.
type failingWriter struct{ n int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("broken pipe")
	}
	w.n--
	return len(p), nil
}

// TestCutOffWriteIsNeverAccepted: a frame whose writer failed part way is one
// a scanner refuses.
func TestCutOffWriteIsNeverAccepted(t *testing.T) {
	payload := payloadOf(t, 4*dataChunkBytes)
	var rec recordingWriter
	_ = Write(&rec, testTag, KindResult, payload)
	for cut := 1; cut < len(rec.calls); cut++ {
		if err := Write(&failingWriter{n: cut}, testTag, KindResult, payload); err == nil {
			t.Fatalf("Write ignored a failed write after %d lines", cut)
		}
		_, s := scan(t, testTag, strings.Join(rec.calls[:cut], ""), 0)
		if _, err := s.Result(); err == nil {
			t.Fatalf("a frame cut off after %d of %d lines was accepted", cut, len(rec.calls))
		}
	}
}

// --- fuzzing ----------------------------------------------------------

// FuzzScanner feeds arbitrary bytes, cut at an arbitrary stride, and checks
// what must hold for every input: no panic, a bounded buffer, a decision that
// does not depend on the chunking, no frame protocol in the transcript, and an
// untouched transcript for any input that never mentions the marker.
func FuzzScanner(f *testing.F) {
	good := frameText(f, testTag, KindResult, []byte("a small project result"))
	f.Add([]byte(good), uint16(1))
	f.Add([]byte("noise\n"+good+good), uint16(3))
	f.Add([]byte(strings.ReplaceAll(good, "end", "end ")), uint16(5))
	f.Add([]byte(good[:len(good)/2]), uint16(7))
	f.Add([]byte(Marker+" "+testTag+" data AAAA\n"), uint16(2))
	f.Add([]byte(Marker+" "+testTag+"\r"), uint16(1))
	f.Add([]byte("plain transcript\nwith lines\r\n"), uint16(4))
	f.Fuzz(func(t *testing.T, in []byte, stride uint16) {
		text := string(in)
		whole, ws := scan(t, testTag, text, 0)
		n := int(stride%97) + 1
		cut, cs := scanBounded(t, text, n)

		if whole != cut {
			t.Fatalf("transcript depends on chunking (stride %d):\nwhole %q\ncut   %q", n, clip(whole), clip(cut))
		}
		wf, werr := ws.Result()
		cf, cerr := cs.Result()
		if (werr == nil) != (cerr == nil) || !bytes.Equal(wf.Payload, cf.Payload) || wf.Kind != cf.Kind {
			t.Fatalf("decision depends on chunking (stride %d): %v / %v", n, werr, cerr)
		}
		if werr == nil {
			if len(wf.Payload) == 0 || len(wf.Payload) > wf.Kind.Limit() {
				t.Fatalf("accepted a %s frame of %d bytes", wf.Kind, len(wf.Payload))
			}
		}
		for _, l := range strings.Split(whole, "\n") {
			if ws.isFrameLine(l) {
				t.Fatalf("a frame line reached the transcript: %q", clip(l))
			}
		}
		if !strings.Contains(text, "##") && whole != text {
			t.Fatalf("an input with no marker came out changed: %q -> %q", clip(text), clip(whole))
		}
	})
}

// scanBounded is scan with a check after every chunk that the scanner never
// holds more than one frame line's worth of an unfinished line.
func scanBounded(t *testing.T, text string, n int) (string, *Scanner) {
	t.Helper()
	s, err := NewScanner(testTag)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for i := 0; i < len(text); i += n {
		end := i + n
		if end > len(text) {
			end = len(text)
		}
		out.WriteString(s.Feed(text[i:end]))
		if b := s.Buffered(); b > maxLineBytes {
			t.Fatalf("holding %d bytes of an unfinished line", b)
		}
	}
	out.WriteString(s.Close())
	return out.String(), s
}

// FuzzRoundTrip checks the other direction: any payload Write accepts comes
// back exactly, through any chunking, past transcript that does not bear the
// tag at a line start.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("x"), []byte("before\n"), uint16(1), true)
	f.Add(bytes.Repeat([]byte{0, 1, 2}, 3000), []byte("no newline at the end"), uint16(50), false)
	f.Add([]byte("reason"), []byte(Marker+" k-other begin result 1 00\n"), uint16(3), false)
	f.Fuzz(func(t *testing.T, payload, noise []byte, stride uint16, result bool) {
		kind := KindError
		if result {
			kind = KindResult
		}
		if len(payload) == 0 || len(payload) > kind.Limit() {
			return
		}
		// Transcript that bears the tag at a line start is protocol by
		// definition and is FuzzScanner's business.
		for _, l := range strings.Split(string(noise), "\n") {
			if strings.HasPrefix(l, Marker+" "+testTag) {
				return
			}
		}
		text := string(noise) + frameText(t, testTag, kind, payload)
		transcript, s := scanBounded(t, text, int(stride%113)+1)
		got, err := s.Take()
		if err != nil {
			t.Fatalf("Take: %v", err)
		}
		if got.Kind != kind || !bytes.Equal(got.Payload, payload) {
			t.Fatalf("got %s %d bytes, want %s %d", got.Kind, len(got.Payload), kind, len(payload))
		}
		if transcript != string(noise)+"\n" {
			t.Fatalf("transcript = %q, want %q", clip(transcript), clip(string(noise)+"\n"))
		}
	})
}
