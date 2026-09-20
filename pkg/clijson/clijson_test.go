package clijson

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type payload struct {
	Summary string   `json:"summary"`
	Items   []string `json:"items"`
}

func sample() payload {
	return payload{Summary: "two ideas", Items: []string{"a", "b"}}
}

// emitted returns the bytes Emit writes for sample().
func emitted(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Emit(&buf, sample()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	return buf.Bytes()
}

func TestEmitThenUnmarshalRoundTrips(t *testing.T) {
	var got payload
	if err := Unmarshal(emitted(t), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Summary != "two ideas" || len(got.Items) != 2 {
		t.Fatalf("round trip lost data: %+v", got)
	}
}

// The regression this package exists for: a diagnostic on the merged stream
// ahead of the payload. Before framing this produced
// "invalid character 'w' looking for beginning of value" (Task 20325).
func TestUnmarshalIgnoresLeadingWarning(t *testing.T) {
	warning := `warning: schema version 37 was applied from "0037_project_members.sql", ` +
		`but this build embeds "0037_secret_grant_requests.sql" for that version.` + "\n"

	var got payload
	if err := Unmarshal(append([]byte(warning), emitted(t)...), &got); err != nil {
		t.Fatalf("Unmarshal with leading warning: %v", err)
	}
	if got.Summary != "two ideas" {
		t.Fatalf("payload not recovered: %+v", got)
	}
}

// Diagnostics that contain JSON punctuation are what defeats the unframed
// "first { to last }" heuristic. The frame must not care.
func TestUnmarshalIgnoresNoiseContainingBraces(t *testing.T) {
	for _, noise := range []string{
		`{"level":"warn","msg":"structured log line"}` + "\n",
		"panic: map[a:1] {unexpected}\n",
		"warning: config max_parallel: value 99 outside [1, 64]\n",
	} {
		var got payload
		in := append([]byte(noise), emitted(t)...)
		if err := Unmarshal(in, &got); err != nil {
			t.Fatalf("noise %q: %v", noise, err)
		}
		if got.Summary != "two ideas" {
			t.Fatalf("noise %q: payload not recovered: %+v", noise, got)
		}
	}
}

// Trailing diagnostics are as likely as leading ones: a deferred cleanup that
// fails prints after the payload is already on the stream.
func TestUnmarshalIgnoresTrailingNoise(t *testing.T) {
	var got payload
	in := append(emitted(t), []byte("\nwarning: could not remove temp dir\n")...)
	if err := Unmarshal(in, &got); err != nil {
		t.Fatalf("Unmarshal with trailing noise: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("payload not recovered: %+v", got)
	}
}

// A binary that predates Emit writes a bare document. A hub must still read it
// rather than refusing outright.
func TestExtractFallsBackToUnframedPayload(t *testing.T) {
	bare, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	var got payload
	if err := Unmarshal(bare, &got); err != nil {
		t.Fatalf("unframed fallback: %v", err)
	}
	if got.Summary != "two ideas" {
		t.Fatalf("unframed fallback lost data: %+v", got)
	}
}

// The last frame wins, so output that quotes the marker before the real
// payload cannot displace it.
func TestExtractPrefersTheLastFrame(t *testing.T) {
	decoy := "see " + BeginMarker + "\n{\"summary\":\"decoy\"}\n" + EndMarker + "\n"
	var got payload
	if err := Unmarshal(append([]byte(decoy), emitted(t)...), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Summary != "two ideas" {
		t.Fatalf("decoy frame won: %+v", got)
	}
}

// Truncation must be named, not silently parsed as a short document. Run's
// output cap keeps the tail, so the head is what goes missing.
func TestExtractReportsTruncation(t *testing.T) {
	full := emitted(t)

	head := full[:len(full)-len(EndMarker)-5]
	if _, err := Extract(head); err == nil || !strings.Contains(err.Error(), "mid-payload") {
		t.Fatalf("truncated tail: want a mid-payload error, got %v", err)
	}

	tail := full[bytes.Index(full, []byte(BeginMarker))+len(BeginMarker)+2:]
	if _, err := Extract(tail); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated head: want a truncation error, got %v", err)
	}
}

func TestExtractReportsMissingPayload(t *testing.T) {
	_, err := Extract([]byte("warning: something went wrong\nno result here\n"))
	if !errors.Is(err, ErrNoPayload) {
		t.Fatalf("want ErrNoPayload, got %v", err)
	}
	// The operator's next question is "what did it print instead?".
	if !strings.Contains(err.Error(), "something went wrong") {
		t.Fatalf("error should quote the output, got %q", err)
	}
}

func TestExtractReportsEmptyOutput(t *testing.T) {
	_, err := Extract(nil)
	if !errors.Is(err, ErrNoPayload) {
		t.Fatalf("want ErrNoPayload, got %v", err)
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Fatalf("error should say the command was silent, got %q", err)
	}
}

// A decode failure must be distinguishable from an absent payload, and must
// still show the operator the surrounding output.
func TestUnmarshalReportsMalformedPayload(t *testing.T) {
	in := []byte("\n" + BeginMarker + "\n{\"summary\": \n" + EndMarker + "\n")
	var got payload
	err := Unmarshal(in, &got)
	if err == nil {
		t.Fatal("want an error for a malformed payload")
	}
	if errors.Is(err, ErrNoPayload) {
		t.Fatalf("malformed is not absent: %v", err)
	}
	if !strings.Contains(err.Error(), "decoding payload") {
		t.Fatalf("want a decode error, got %q", err)
	}
	// The document is what failed, so it is what the error must quote.
	if !strings.Contains(err.Error(), `{\"summary\":`) {
		t.Fatalf("error should quote the payload, got %q", err)
	}
}

// The snippet is bounded and single-line so it cannot forge log lines or
// flood a browser toast.
func TestSnippetIsBoundedAndSingleLine(t *testing.T) {
	noisy := strings.Repeat("warning: line\n", 200)
	_, err := Extract([]byte(noisy))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Fatalf("snippet must be single-line, got %q", err)
	}
	if len(err.Error()) > snippetLimit+120 {
		t.Fatalf("snippet unbounded: %d bytes", len(err.Error()))
	}
}

// Emit must reach the writer in one call: stdout and stderr are usually the
// same pipe, and a multi-write encoder can have a diagnostic interleaved into
// the middle of the document.
func TestEmitWritesExactlyOnce(t *testing.T) {
	c := &countingWriter{}
	if err := Emit(c, sample()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if c.writes != 1 {
		t.Fatalf("want 1 write, got %d", c.writes)
	}
}

func TestEmitReportsUnmarshalableValue(t *testing.T) {
	var buf bytes.Buffer
	if err := Emit(&buf, make(chan int)); err == nil {
		t.Fatal("want an error for an unmarshalable value")
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing should be written on failure, got %q", buf.String())
	}
}

type countingWriter struct {
	writes int
	buf    bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}
