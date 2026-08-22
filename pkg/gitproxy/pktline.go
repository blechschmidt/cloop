package gitproxy

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Git's packet line framing, which is the whole reason this package can make a
// decision about a push at all.
//
// A pkt-line is four hex digits giving the length of the line *including* those
// four bytes, followed by that many bytes minus four of payload. Three lengths
// are special and carry no payload: "0000" ends a section, "0001" delimits one
// (protocol v2), and "0002" ends a response. Lengths 1 through 3 cannot occur —
// there is no room for the header itself — and a decoder that accepts them is
// one an attacker can walk backwards through the stream.
const (
	// pktHeaderLen is the width of the length prefix.
	pktHeaderLen = 4
	// maxPktLen is the largest legal line, header included. Git's own limit.
	maxPktLen = 65520
	// maxPayloadLen is the largest payload one line can carry.
	maxPayloadLen = maxPktLen - pktHeaderLen
)

// The three payload-less lines, as they appear on the wire.
var (
	flushPkt       = []byte("0000")
	delimPkt       = []byte("0001")
	responseEndPkt = []byte("0002")
)

// pktType distinguishes a data line from the three special ones.
type pktType int

const (
	pktData pktType = iota
	pktFlush
	pktDelim
	pktResponseEnd
)

// errBadPktLine is the parse failure. It is deliberately one error rather than
// a family: every variant means "this is not a git request", and the handler
// answers all of them the same way. Callers that want the detail read the
// wrapped text; callers that want to branch use errors.Is.
var errBadPktLine = errors.New("malformed pkt-line")

// pktReader decodes a pkt-line stream while remembering the exact bytes it
// consumed.
//
// The raw copy is not a debugging convenience. What this proxy forwards
// upstream must be byte-identical to what the sandbox sent: re-encoding the
// command list from the parsed struct would mean the bytes the policy inspected
// and the bytes the remote applies were produced by different code, and any
// disagreement between them — a capability dropped, a trailing LF normalised —
// is a hole shaped exactly like the check. So the parser reads, decides, and
// then replays the original bytes verbatim.
type pktReader struct {
	br  *bufio.Reader
	raw []byte // every byte consumed so far, in order
	// budget caps how much this reader will consume before giving up, so a
	// body that never sends a flush cannot be used to exhaust hub memory.
	budget int64
}

func newPktReader(r io.Reader, budget int64) *pktReader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &pktReader{br: br, budget: budget}
}

// next returns the next line's type and payload. The payload aliases a fresh
// slice, never the reader's internal buffer.
func (p *pktReader) next() (pktType, []byte, error) {
	head := make([]byte, pktHeaderLen)
	if _, err := io.ReadFull(p.br, head); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("%w: reading length prefix: %v", errBadPktLine, err)
	}
	if err := p.consume(head); err != nil {
		return 0, nil, err
	}

	switch {
	case string(head) == string(flushPkt):
		return pktFlush, nil, nil
	case string(head) == string(delimPkt):
		return pktDelim, nil, nil
	case string(head) == string(responseEndPkt):
		return pktResponseEnd, nil, nil
	}

	var lenBuf [2]byte
	if _, err := hex.Decode(lenBuf[:], head); err != nil {
		return 0, nil, fmt.Errorf("%w: length prefix %q is not hex", errBadPktLine, head)
	}
	total := int(lenBuf[0])<<8 | int(lenBuf[1])
	switch {
	case total < pktHeaderLen:
		// 0001 and 0002 were handled above; 0003 and below are unassigned and
		// would describe a line shorter than its own header.
		return 0, nil, fmt.Errorf("%w: length %d is below the %d-byte header", errBadPktLine, total, pktHeaderLen)
	case total > maxPktLen:
		return 0, nil, fmt.Errorf("%w: length %d exceeds the %d-byte maximum", errBadPktLine, total, maxPktLen)
	}

	payload := make([]byte, total-pktHeaderLen)
	if _, err := io.ReadFull(p.br, payload); err != nil {
		return 0, nil, fmt.Errorf("%w: reading %d-byte payload: %v", errBadPktLine, len(payload), err)
	}
	if err := p.consume(payload); err != nil {
		return 0, nil, err
	}
	return pktData, payload, nil
}

// consume records bytes into the raw replay buffer and enforces the budget.
func (p *pktReader) consume(b []byte) error {
	if p.budget > 0 && int64(len(p.raw))+int64(len(b)) > p.budget {
		return fmt.Errorf("%w: command section exceeds %d bytes without a flush", errBadPktLine, p.budget)
	}
	p.raw = append(p.raw, b...)
	return nil
}

// tail returns a reader over everything the request still holds: the bytes
// already consumed, followed by whatever has not been read yet. bufio may have
// read ahead, so the buffered reader itself has to be the second half rather
// than the caller's original io.Reader.
func (p *pktReader) tail(rest io.Reader) io.Reader {
	if rest == nil {
		rest = p.br
	}
	return io.MultiReader(bytes.NewReader(p.raw), rest)
}

// --- encoding ---------------------------------------------------------------

// writePkt frames one payload as a pkt-line.
func writePkt(w io.Writer, payload []byte) error {
	if len(payload) > maxPayloadLen {
		return fmt.Errorf("pkt-line payload is %d bytes, at most %d fit", len(payload), maxPayloadLen)
	}
	total := len(payload) + pktHeaderLen
	if _, err := fmt.Fprintf(w, "%04x", total); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// writeFlush writes the section terminator.
func writeFlush(w io.Writer) error {
	_, err := w.Write(flushPkt)
	return err
}

// sidebandMux wraps payloads in the side-band-64k framing, where the first
// payload byte is a channel number: 1 is pack data, 2 is progress shown to the
// user, 3 is a fatal error that aborts the client.
//
// The proxy only ever writes on this channel set when the client asked for it.
// Sending unframed report-status to a client expecting side-band leaves git
// parsing a length byte as a status line, which surfaces as a corrupt-stream
// error instead of the refusal reason — the one thing this path exists to
// deliver legibly.
const (
	sidebandData     = 1
	sidebandProgress = 2
	sidebandError    = 3
	// sidebandMaxPayload leaves room for the one-byte channel marker.
	sidebandMaxPayload = maxPayloadLen - 1
)

func writeSideband(w io.Writer, channel byte, payload []byte) error {
	for len(payload) > 0 {
		n := len(payload)
		if n > sidebandMaxPayload {
			n = sidebandMaxPayload
		}
		framed := make([]byte, 0, n+1)
		framed = append(framed, channel)
		framed = append(framed, payload[:n]...)
		if err := writePkt(w, framed); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}
