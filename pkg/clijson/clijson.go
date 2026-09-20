// Package clijson frames a machine-readable JSON payload so it survives a
// transport that also carries human-readable diagnostics.
//
// # Why this exists
//
// The Web UI runs `cloop <subcommand> --json` through pkg/executor and parses
// the result. Every driver hands back one merged stream: localprocess tags its
// output executor.StreamCombined, and a container or remote agent reads a
// single log pipe it cannot split either. So stdout and stderr arrive
// interleaved in one buffer, and "the whole buffer is the JSON document" is a
// contract the sub-binary cannot actually keep — anything that writes a
// diagnostic breaks the feature, however unrelated it is.
//
// That is not hypothetical. It has broken the suggest panel twice: once when
// the command printed a coloured banner before the payload (Task 20133), and
// again when a schema-divergence warning from statedb landed on stderr during
// startup, so the UI reported
//
//	could not parse suggestions: invalid character 'w' looking for beginning of value
//
// where the 'w' was the first letter of "warning:" (Task 20325). Silencing each
// writer in turn treats the symptom: the diagnostics are legitimate, and the
// next one to be added reopens the bug. Framing the payload fixes the class —
// the reader can find the document no matter what shares the stream.
//
// # The frame
//
// Emit brackets the JSON with sentinels on their own lines:
//
//	<<<cloop-json:begin>>>
//	{"summary":"...","suggestions":[...]}
//	<<<cloop-json:end>>>
//
// Extract recovers the payload from between them and ignores everything else.
// The markers are deliberately not valid JSON and not plausible prose, so a
// diagnostic cannot be mistaken for a frame.
package clijson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Frame markers. Each occupies its own line so a reader scanning text can see
// them, and neither is valid JSON so neither can be confused with a payload.
//
// Changing these is a wire-format break between a hub and any differently
// versioned cloop binary it invokes — see Extract, which falls back to the
// unframed heuristic so the break degrades instead of failing.
const (
	BeginMarker = "<<<cloop-json:begin>>>"
	EndMarker   = "<<<cloop-json:end>>>"
)

// ErrNoPayload reports that buf held no JSON document: neither a frame nor
// anything the unframed fallback could recognise. Callers use errors.Is to
// tell "the command produced no result" from "the result would not parse".
var ErrNoPayload = errors.New("clijson: no JSON payload in output")

// Emit writes v to w as a framed JSON document.
//
// The payload is marshalled fully before anything is written, then handed to w
// in a single Write. That matters because stdout and stderr are usually the
// same pipe by the time this runs: a multi-call encoder can have a concurrent
// diagnostic interleaved between its writes, landing inside the document.
// One write cannot be split that way for payloads up to PIPE_BUF, and is
// materially harder to split above it.
func Emit(w io.Writer, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("clijson: marshalling payload: %w", err)
	}

	var out bytes.Buffer
	// A leading newline so the frame starts on a line of its own even when
	// something already wrote a partial line to the shared stream.
	out.WriteString("\n" + BeginMarker + "\n")
	out.Write(body)
	out.WriteString("\n" + EndMarker + "\n")

	if _, err := w.Write(out.Bytes()); err != nil {
		return fmt.Errorf("clijson: writing payload: %w", err)
	}
	return nil
}

// Extract recovers the JSON document from buf, which may also contain
// diagnostics written to a stream merged with the payload's.
//
// A framed payload is preferred. When no frame is present Extract falls back
// to the pre-framing heuristic — the span from the first '{' to the last '}'
// — so a hub still reads a result from an older binary that predates Emit.
// The fallback is the fragile behaviour this package exists to replace, and is
// only ever reached when the frame is genuinely absent.
//
// On failure the error quotes the leading output, because the operator's next
// question is always "then what did it print instead?" and the raw decoder
// error ("invalid character 'w'") does not answer it.
func Extract(buf []byte) ([]byte, error) {
	// Last frame wins. A diagnostic that quotes the marker — this package's
	// own doc comment, say, echoed by some command — can only ever precede
	// the real payload, which Emit writes last.
	if begin := bytes.LastIndex(buf, []byte(BeginMarker)); begin >= 0 {
		rest := buf[begin+len(BeginMarker):]
		end := bytes.Index(rest, []byte(EndMarker))
		if end < 0 {
			return nil, fmt.Errorf("clijson: output ends mid-payload — the command was killed or its output was truncated%s", snippet(buf))
		}
		payload := bytes.TrimSpace(rest[:end])
		if len(payload) == 0 {
			return nil, fmt.Errorf("%w: the frame was empty%s", ErrNoPayload, snippet(buf))
		}
		return payload, nil
	}

	// A frame that was cut off at the head: the tail survived the output cap
	// but the opening marker did not. Say so rather than falling through to
	// the heuristic, which would silently parse a partial document.
	if bytes.Contains(buf, []byte(EndMarker)) {
		return nil, fmt.Errorf("clijson: output begins mid-payload — it was truncated%s", snippet(buf))
	}

	start := bytes.IndexByte(buf, '{')
	stop := bytes.LastIndexByte(buf, '}')
	if start < 0 || stop <= start {
		return nil, fmt.Errorf("%w%s", ErrNoPayload, snippet(buf))
	}
	return buf[start : stop+1], nil
}

// Unmarshal extracts the payload from buf and decodes it into v.
//
// The decode error is wrapped with the leading output for the same reason
// Extract's is: a bare json error names a byte offset into a buffer the
// operator cannot see.
func Unmarshal(buf []byte, v any) error {
	payload, err := Extract(buf)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, v); err != nil {
		// The payload, not buf: the document is what failed to decode, and
		// quoting the surrounding diagnostics here would bury it.
		return fmt.Errorf("clijson: decoding payload: %w%s", err, snippet(payload))
	}
	return nil
}

// snippetLimit bounds how much of the offending output an error quotes. Long
// enough to show a warning line or a stack frame, short enough that the string
// stays readable in a browser toast and in a log line.
const snippetLimit = 300

// snippet renders the leading output for an error message, or "" when there
// was none. The leading edge is the useful end: whatever displaced the payload
// — a warning, a usage message, a panic banner — printed first.
func snippet(buf []byte) string {
	s := strings.TrimSpace(string(buf))
	if s == "" {
		return " (the command produced no output)"
	}
	truncated := false
	if len(s) > snippetLimit {
		s = s[:snippetLimit]
		truncated = true
	}
	// Collapse to a single line so the quoted output cannot forge extra lines
	// in whatever log or toast renders the error.
	s = strings.Join(strings.Fields(s), " ")
	if truncated {
		s += "…"
	}
	return fmt.Sprintf(" (the command printed: %q)", s)
}
