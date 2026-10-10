// Package resultframe carries a seeded run's project result out of a sandbox
// whose only channel home is its own output stream (Task 20402).
//
// # Why the log
//
// A Kubernetes Pod built by the kubernetes driver has no ServiceAccount token
// and nothing mounted that leads back to the hub, so it cannot tell anybody
// anything — and by the time the driver could read a file out of it, the
// emptyDir holding the file is gone with the Pod. Its log stream is the one
// channel that survives, which is also how the write-back report comes home
// (executor.WriteBackSentinel). The project result is a different shape of
// thing — up to executor.MaxProjectResultBytes of compressed bytes rather than
// one line of JSON — so it travels as a frame: a block of lines the wrapper
// prints last, after the harness has exited, and the driver lifts back out of
// the stream before anybody reads it as a transcript.
//
// # The wire format
//
// Every line of a frame starts with Marker, then the frame's tag, then a verb:
//
//	##cloop-project-result-v1## <tag> begin <kind> <length> <sha256>
//	##cloop-project-result-v1## <tag> data <base64>
//	…
//	##cloop-project-result-v1## <tag> end
//
// The tag is chosen by the driver — the handle ID — and handed to the wrapper,
// so a line naming another tag is somebody else's text and passes through as
// transcript. That is what keeps a run that prints this package's own test
// fixtures, or a nested run's frame, from being mistaken for its own result.
// The tag is not a secret and is not meant to be one: see "Trust" below.
//
// Each line is written with a single write(2) of at most maxLineBytes, under
// the kernel's PIPE_BUF, so a line can be preceded or followed by another
// process's line in the stream but never cut by one. Lines that are not the
// frame's may sit between the frame's own: in a container log stdout and
// stderr are merged line by line by the runtime, and the wrapper's own stderr
// is one of them. They are not part of the frame and do not disturb it.
//
// # What is refused
//
// A frame is accepted only whole: declared length and SHA-256 both match what
// arrived, an end line closed it, and nothing else bearing its tag was seen
// before or after. Anything else yields an error and no bytes — a truncated
// frame (the stream ended inside it), an interleaved one (a second begin while
// the first was open), a duplicated one (a second frame, or a line of one,
// after the first ended), an unframed one (data or end with no begin) and an
// oversized one (more than the kind's ceiling declared or delivered). There is
// no partial result to be had from this package, which is the property the
// hub's merge depends on: half a project result merged would be a run's
// outcomes recorded for some of its tasks and not others.
//
// # Trust
//
// The workload shares the stream and can print anything, including a frame
// bearing the right tag. That is contained the same way on every transport:
//
//   - it cannot make a frame larger than a device's project_result frame could
//     be — the ceilings are executor.MaxProjectResultBytes for a result and
//     executor.MaxProjectResultErrBytes for a reason, checked before a byte is
//     kept;
//   - it cannot make the hub take a forged frame over the real one: the
//     wrapper's frame always follows the harness's exit, so a forged frame is
//     always followed by a second one and the pair is refused as duplicated —
//     a workload can deny itself its own result, which corrupting its own
//     database would do just as well;
//   - and the content of a result is the workload's to decide anyway. A
//     device reads the result out of the database the workload wrote, so a
//     result the workload forged in full claims nothing a result it shaped by
//     writing its database could not. The hub's merge (projectseed.Merge) is
//     where what a result may change is decided, and it treats every result as
//     the least trusted party's account.
package resultframe

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Marker begins every line of a frame. The version is in the marker so that a
// different format can never be read as this one.
const Marker = "##cloop-project-result-v1##"

// Kind is what a frame carries.
type Kind string

const (
	// KindResult carries the compressed project result document
	// (projectseed.Harvest's output).
	KindResult Kind = "result"
	// KindError carries the wrapper's reason for having no document: the
	// workload removed its project, the database would not open. Plain text.
	KindError Kind = "error"
)

// Limit is the most bytes a frame of kind k may carry, or 0 for a kind this
// package does not know.
func (k Kind) Limit() int {
	switch k {
	case KindResult:
		return executor.MaxProjectResultBytes
	case KindError:
		return executor.MaxProjectResultErrBytes
	}
	return 0
}

const (
	// dataChunkBytes is the payload carried by one data line: 2304 bytes, which
	// base64 renders as exactly 3072 characters.
	dataChunkBytes = 2304
	// maxTagLen bounds a tag. A handle ID is far shorter.
	maxTagLen = 64
	// maxLineBytes bounds a frame line, newline included. Every line Write
	// produces is shorter — the marker, a tag, a verb and 3072 characters of
	// base64 come to under 3.2 KiB — and this is under PIPE_BUF (4096 on
	// Linux), which is what makes each line a single atomic write.
	maxLineBytes = 4096
)

// Errors a scanner reports. Each is wrapped with a sentence saying what was
// seen; errors.Is matches the class.
var (
	// ErrNoFrame: the stream carried no frame with this scanner's tag.
	ErrNoFrame = errors.New("no project result frame")
	// ErrTruncated: a frame began and the stream ended, or its end line
	// arrived, before every byte it declared.
	ErrTruncated = errors.New("the project result frame was cut off")
	// ErrDuplicate: a second frame, or a line of one, bearing the same tag —
	// before the first ended (interleaved) or after it (duplicated).
	ErrDuplicate = errors.New("more than one project result frame")
	// ErrMalformed: a line bearing the tag that is not a valid frame line, a
	// data or end line with no frame open, or a payload whose length or
	// checksum is not the one declared.
	ErrMalformed = errors.New("malformed project result frame")
	// ErrTaken: the frame was accepted and has already been handed out.
	ErrTaken = errors.New("the project result frame was already collected")
	// ErrDropped: the frame was accepted and then let go before it was
	// collected (see Scanner.Drop).
	ErrDropped = errors.New("the project result frame was dropped before it was collected")
)

// ValidTag reports whether tag can label a frame: 1–64 characters of letters,
// digits, '.', '_' and '-' — a single field on a space-separated line, and
// nothing a terminal or a log viewer would interpret.
func ValidTag(tag string) bool {
	if tag == "" || len(tag) > maxTagLen {
		return false
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// Write renders payload as one frame tagged tag onto w.
//
// Every line goes out in a single Write call, which for a pipe is a single
// write(2) under PIPE_BUF and therefore atomic. The frame is preceded by an
// empty line: the workload may have left a line unfinished on the same stream,
// and a begin line appended to it would not start a line and would not be
// recognised. The cost is one blank line in the transcript.
//
// An error describes the input (Write refuses a frame no scanner would accept)
// or the first failed write; a frame cut off by a failed write is one the
// scanner will refuse as truncated, never one it will accept.
func Write(w io.Writer, tag string, kind Kind, payload []byte) error {
	if !ValidTag(tag) {
		return fmt.Errorf("resultframe: invalid tag %q", tag)
	}
	limit := kind.Limit()
	switch {
	case limit == 0:
		return fmt.Errorf("resultframe: unknown kind %q", kind)
	case len(payload) == 0:
		return fmt.Errorf("resultframe: a %s frame needs a payload", kind)
	case len(payload) > limit:
		return fmt.Errorf("resultframe: a %s frame carries at most %d bytes, and this one is %d",
			kind, limit, len(payload))
	}
	sum := sha256.Sum256(payload)
	prefix := Marker + " " + tag + " "

	writeLine := func(line string) error {
		_, err := io.WriteString(w, line)
		return err
	}
	if err := writeLine("\n"); err != nil {
		return err
	}
	if err := writeLine(prefix + "begin " + string(kind) + " " + strconv.Itoa(len(payload)) + " " +
		hex.EncodeToString(sum[:]) + "\n"); err != nil {
		return err
	}
	for off := 0; off < len(payload); off += dataChunkBytes {
		end := off + dataChunkBytes
		if end > len(payload) {
			end = len(payload)
		}
		if err := writeLine(prefix + "data " + base64.StdEncoding.EncodeToString(payload[off:end]) + "\n"); err != nil {
			return err
		}
	}
	return writeLine(prefix + "end\n")
}

// Frame is a frame a scanner accepted.
type Frame struct {
	Kind Kind
	// Payload is exactly the bytes that were declared, length and checksum
	// verified. It is the scanner's own allocation, sized to the declared
	// length, so retaining it retains nothing else.
	Payload []byte
}

// state is where a scanner's frame stands.
type state int

const (
	stateIdle     state = iota // no line bearing the tag seen yet
	stateOpen                  // a begin was accepted; data is arriving
	stateComplete              // an end closed a frame whose bytes checked out
	stateBroken                // a frame was refused; nothing will be accepted
)

// lineMode is how the scanner treats the bytes it is about to see.
type lineMode int

const (
	// modeStart: at the start of a line, holding what has arrived of it while
	// it could still be a frame line.
	modeStart lineMode = iota
	// modePass: this line is transcript and has been forwarded; forward the
	// rest of it as it arrives.
	modePass
	// modeDiscard: this line bears the tag and has grown past any frame line;
	// swallow the rest of it.
	modeDiscard
)

// Scanner separates one tag's frame from the stream it is embedded in.
//
// Feed it the stream in whatever chunks it arrives; it returns the transcript —
// every byte that is not a line of the frame, in order — and keeps the frame.
// Only an unfinished line that could still become a frame line is held back,
// so ordinary output is forwarded as soon as it diverges from the marker, and
// a workload printing gigabytes without a newline costs nothing.
//
// It is safe for concurrent use. The zero value is not usable; call NewScanner.
type Scanner struct {
	tag    string
	prefix string // Marker + " " + tag

	mu      sync.Mutex
	mode    lineMode
	partial []byte
	// confirmed records that partial is known to start with the prefix and a
	// space — it is a frame line unless it runs too long — so the bytes that
	// follow need no re-examination. Without it every chunk would re-check
	// the whole held line, and a stream that arrives a byte at a time would
	// cost the square of each line's length.
	confirmed bool
	closed    bool

	state  state
	kind   Kind
	want   int
	digest [sha256.Size]byte
	buf    []byte
	err    error
	frame  *Frame
	taken  bool

	// lines counts the frame-protocol lines withheld from the transcript.
	lines int
}

// NewScanner returns a scanner for frames tagged tag.
func NewScanner(tag string) (*Scanner, error) {
	if !ValidTag(tag) {
		return nil, fmt.Errorf("resultframe: invalid tag %q", tag)
	}
	return &Scanner{tag: tag, prefix: Marker + " " + tag}, nil
}

// Tag reports the tag this scanner reads.
func (s *Scanner) Tag() string { return s.tag }

// Feed consumes one chunk of the stream and returns the part of it that is
// transcript. After Close every byte is transcript.
func (s *Scanner) Feed(chunk string) string {
	if chunk == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return chunk
	}
	var out strings.Builder
	for chunk != "" {
		nl := strings.IndexByte(chunk, '\n')
		switch s.mode {
		case modePass:
			if nl < 0 {
				out.WriteString(chunk)
				return out.String()
			}
			out.WriteString(chunk[:nl+1])
			chunk = chunk[nl+1:]
			s.mode = modeStart
			continue
		case modeDiscard:
			if nl < 0 {
				return out.String()
			}
			chunk = chunk[nl+1:]
			s.mode = modeStart
			continue
		}

		// modeStart.
		if nl < 0 {
			s.partial = append(s.partial, chunk...)
			if !s.confirmed {
				switch s.classifyPartial() {
				case partialRejected:
					out.Write(s.partial)
					s.partial = s.partial[:0]
					s.mode = modePass
					return out.String()
				case partialConfirmed:
					s.confirmed = true
				}
			}
			if s.confirmed && len(s.partial) >= maxLineBytes {
				// It bears the tag and is already as long as no frame line
				// is, so it is one nothing will accept. Swallowed rather
				// than forwarded: it is protocol, and the transcript is no
				// place for a broken frame.
				s.lines++
				s.overlong()
				s.partial = s.partial[:0]
				s.confirmed = false
				s.mode = modeDiscard
			}
			return out.String()
		}
		line := chunk[:nl]
		if len(s.partial) > 0 {
			line = string(s.partial) + line
			s.partial = s.partial[:0]
		}
		s.confirmed = false
		chunk = chunk[nl+1:]
		if s.isFrameLine(line) {
			s.lines++
			if len(line) >= maxLineBytes {
				// The same refusal the unfinished-line path above makes,
				// whichever chunk the newline happened to arrive in: what a
				// scanner decides must not depend on how the stream was cut.
				s.overlong()
				continue
			}
			s.consume(line)
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// Close marks the end of the stream and returns whatever the scanner was still
// holding that turned out to be transcript — the start of a last line that
// never ended and never became a frame line. A frame still open is truncated.
// Close is idempotent.
func (s *Scanner) Close() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	s.closed = true
	rest := ""
	if s.mode == modeStart && len(s.partial) > 0 {
		if s.isFrameLine(string(s.partial)) {
			// A frame line the stream ended in the middle of.
			s.lines++
			if s.state == stateOpen || s.state == stateIdle {
				s.fail(fmt.Errorf("%w: the stream ended in the middle of a frame line", ErrTruncated))
			} else {
				s.fail(fmt.Errorf("%w: the stream ended in the middle of a line bearing tag %s after "+
					"the frame had closed", ErrDuplicate, s.tag))
			}
		} else {
			rest = string(s.partial)
		}
	}
	s.partial = nil
	s.confirmed = false
	if s.state == stateOpen {
		s.fail(fmt.Errorf("%w: the stream ended after %d of the %d bytes the frame declared",
			ErrTruncated, len(s.buf), s.want))
	}
	return rest
}

// Result reports the frame without handing it out: what Take would return now,
// except that the frame stays. For a summary line, say.
func (s *Scanner) Result() (Frame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resultLocked()
}

func (s *Scanner) resultLocked() (Frame, error) {
	switch {
	case s.state == stateBroken:
		return Frame{}, s.err
	case s.state == stateOpen:
		return Frame{}, fmt.Errorf("%w: %d of the %d bytes the frame declared have arrived",
			ErrTruncated, len(s.buf), s.want)
	case s.state == stateIdle:
		return Frame{}, ErrNoFrame
	case s.taken:
		return Frame{}, ErrTaken
	case s.frame == nil:
		return Frame{}, s.err
	}
	return *s.frame, nil
}

// Take returns the accepted frame once and lets go of it: a second call reports
// ErrTaken. A result is handed out once because merging the same run twice
// would book its spend twice.
func (s *Scanner) Take() (Frame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.resultLocked()
	if err != nil {
		return Frame{}, err
	}
	s.taken = true
	s.frame = nil
	return f, nil
}

// Drop lets go of an accepted frame that has not been collected, so a holder
// with a memory budget can evict it. A later Take reports ErrDropped with why.
// It reports how many bytes were released.
func (s *Scanner) Drop(why string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frame == nil || s.taken {
		return 0
	}
	n := len(s.frame.Payload)
	s.frame = nil
	s.err = fmt.Errorf("%w: %s", ErrDropped, why)
	return n
}

// WithheldLines reports how many lines of frame protocol the scanner kept out
// of the transcript.
func (s *Scanner) WithheldLines() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lines
}

// Buffered reports how many bytes of an unfinished line the scanner is holding,
// so a test can pin the bound.
func (s *Scanner) Buffered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.partial)
}

// partialClass is what the start of a line is known to be so far.
type partialClass int

const (
	// partialUndecided: it may yet turn out to be a frame line or not.
	partialUndecided partialClass = iota
	// partialRejected: it is not one of this tag's frame lines.
	partialRejected
	// partialConfirmed: it starts with the prefix and a space, so it is a
	// frame line however it ends.
	partialConfirmed
)

// classifyPartial says what s.partial, the start of a line, is. s.mu is held.
//
// It must never reject the start of a line isFrameLine would accept, because a
// rejected line is forwarded on the spot: that is the whole of what keeps the
// scanner's decisions independent of where the stream was cut.
func (s *Scanner) classifyPartial() partialClass {
	b, p := s.partial, s.prefix
	if len(b) <= len(p) {
		if strings.HasPrefix(p, string(b)) {
			return partialUndecided
		}
		return partialRejected
	}
	if string(b[:len(p)]) != p {
		return partialRejected
	}
	switch b[len(p)] {
	case ' ':
		return partialConfirmed
	case '\r':
		// Only as the line's last byte: prefix + "\r" is a frame line
		// (a malformed one), prefix + "\r" + anything is transcript.
		if len(b) == len(p)+1 {
			return partialUndecided
		}
	}
	return partialRejected
}

// overlong refuses the frame over a line bearing the tag that is as long as no
// frame line is. s.mu is held.
func (s *Scanner) overlong() {
	s.fail(fmt.Errorf("%w: a line bearing tag %s ran to %d bytes or more, longer than any frame line",
		ErrMalformed, s.tag, maxLineBytes))
}

// isFrameLine reports whether line — complete, newline stripped — is one of
// this tag's frame lines: the marker, the tag as a whole field, and then a
// space or nothing.
func (s *Scanner) isFrameLine(line string) bool {
	rest, ok := strings.CutPrefix(line, s.prefix)
	return ok && (rest == "" || rest[0] == ' ' || rest == "\r")
}

// consume applies one frame line to the state machine. s.mu is held.
func (s *Scanner) consume(line string) {
	rest := strings.TrimPrefix(line, s.prefix)
	rest = strings.TrimSuffix(rest, "\r")
	rest = strings.TrimPrefix(rest, " ")
	verb, args, _ := strings.Cut(rest, " ")

	if s.state == stateBroken {
		// Nothing is accepted after a refusal, and nothing more needs saying.
		return
	}
	switch verb {
	case "begin":
		switch s.state {
		case stateOpen:
			s.fail(fmt.Errorf("%w: a second frame began while the first was still open (interleaved)",
				ErrDuplicate))
			return
		case stateComplete:
			s.fail(fmt.Errorf("%w: a second frame began after the first had ended", ErrDuplicate))
			return
		}
		kind, want, digest, err := parseBegin(args)
		if err != nil {
			s.fail(err)
			return
		}
		s.state, s.kind, s.want, s.digest = stateOpen, kind, want, digest
		// Sized to the declaration, which is already bounded by the kind's
		// ceiling: the payload never reallocates, and the slice handed out
		// holds exactly the bytes that were declared.
		s.buf = make([]byte, 0, want)

	case "data":
		if !s.expectOpen("a data line") {
			return
		}
		if strings.ContainsAny(args, "\r ") {
			// The base64 decoder skips carriage returns, so a line carrying
			// one would decode to something other than what it shows.
			s.fail(fmt.Errorf("%w: a data line carries a space or a carriage return", ErrMalformed))
			return
		}
		if len(args) == 0 || len(args)%4 != 0 {
			s.fail(fmt.Errorf("%w: a data line carries %d characters of base64, not a whole number "+
				"of 4-character groups", ErrMalformed, len(args)))
			return
		}
		n := base64.StdEncoding.DecodedLen(len(args))
		if len(s.buf)+n-2 > s.want {
			// DecodedLen overstates by up to two bytes of padding, so this
			// refuses only lines that cannot fit whatever their padding.
			s.fail(fmt.Errorf("%w: the frame's data runs past the %d bytes it declared", ErrMalformed, s.want))
			return
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(args)
		if err != nil {
			s.fail(fmt.Errorf("%w: a data line is not base64: %v", ErrMalformed, err))
			return
		}
		if len(s.buf)+len(decoded) > s.want {
			s.fail(fmt.Errorf("%w: the frame's data runs past the %d bytes it declared", ErrMalformed, s.want))
			return
		}
		s.buf = append(s.buf, decoded...)

	case "end":
		if !s.expectOpen("an end line") {
			return
		}
		if args != "" {
			s.fail(fmt.Errorf("%w: the end line carries %q", ErrMalformed, clip(args)))
			return
		}
		if len(s.buf) != s.want {
			s.fail(fmt.Errorf("%w: the frame ended after %d of the %d bytes it declared",
				ErrTruncated, len(s.buf), s.want))
			return
		}
		if got := sha256.Sum256(s.buf); !bytes.Equal(got[:], s.digest[:]) {
			s.fail(fmt.Errorf("%w: the payload's SHA-256 is %x, and the frame declared %x",
				ErrMalformed, got[:6], s.digest[:6]))
			return
		}
		s.state = stateComplete
		s.frame = &Frame{Kind: s.kind, Payload: s.buf}
		s.buf = nil

	default:
		s.fail(fmt.Errorf("%w: unknown verb %q on a line bearing tag %s", ErrMalformed, clip(verb), s.tag))
	}
}

// expectOpen fails the frame unless one is open, naming what arrived. s.mu is
// held.
func (s *Scanner) expectOpen(what string) bool {
	switch s.state {
	case stateOpen:
		return true
	case stateComplete:
		s.fail(fmt.Errorf("%w: %s arrived after the frame had ended", ErrDuplicate, what))
	default:
		s.fail(fmt.Errorf("%w: %s arrived with no frame begun (unframed)", ErrMalformed, what))
	}
	return false
}

// fail refuses the frame for good, letting go of everything it held. The first
// reason is the one reported. s.mu is held.
func (s *Scanner) fail(err error) {
	if s.state != stateBroken {
		s.err = err
	}
	s.state = stateBroken
	s.buf = nil
	s.frame = nil
}

// parseBegin reads a begin line's arguments: kind, length, SHA-256.
func parseBegin(args string) (Kind, int, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	fields := strings.Split(args, " ")
	if len(fields) != 3 {
		return "", 0, digest, fmt.Errorf("%w: a begin line needs a kind, a length and a SHA-256, and "+
			"carries %d field(s)", ErrMalformed, len(fields))
	}
	kind := Kind(fields[0])
	limit := kind.Limit()
	if limit == 0 {
		return "", 0, digest, fmt.Errorf("%w: unknown frame kind %q", ErrMalformed, clip(fields[0]))
	}
	want, ok := parseLength(fields[1])
	switch {
	case !ok:
		return "", 0, digest, fmt.Errorf("%w: the declared length %q is not a positive decimal number",
			ErrMalformed, clip(fields[1]))
	case want > limit:
		// Refused on the declaration, before a byte is kept: the workload
		// controls this stream and must not get to claim more than a device's
		// project_result frame could carry.
		return "", 0, digest, fmt.Errorf("%w: the frame declares %d bytes, over the %d a %s frame may carry",
			ErrMalformed, want, limit, kind)
	}
	if len(fields[2]) != 2*sha256.Size || !isLowerHex(fields[2]) {
		return "", 0, digest, fmt.Errorf("%w: the declared SHA-256 %q is not 64 lowercase hex digits",
			ErrMalformed, clip(fields[2]))
	}
	if _, err := hex.Decode(digest[:], []byte(fields[2])); err != nil {
		return "", 0, digest, fmt.Errorf("%w: the declared SHA-256 does not decode: %v", ErrMalformed, err)
	}
	return kind, want, digest, nil
}

// parseLength reads a length written the way Write writes one: decimal digits,
// no sign, no leading zero, at least 1. Anything else is not a length this
// package produced. Bounded at nine digits, far above any kind's limit, so the
// conversion cannot overflow.
func parseLength(s string) (int, bool) {
	if s == "" || len(s) > 9 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// clip bounds a piece of the stream quoted into an error, which ends up in the
// project's journal: the workload chose these bytes.
func clip(s string) string {
	const max = 40
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
