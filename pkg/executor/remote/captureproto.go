package remote

// captureproto.go lets the hub ask a device for a project's working copy
// (Task 20495, protocol v29): the source half of a project move whose project
// runs on a device, a virtual executor on one, or an executor pool's runner.
//
// The hub cannot read a device's working copy, so it asks the device's agent
// to do what the hub does for a project in its own tree: record the
// uncommitted state on a hidden ref, bundle every local branch and tag and
// the features' working copies, and tar the .cloop files a move delivers —
// or, for a preflight, only to say what the working copy holds. The agent
// works inside the working copies the request names, under its own trees
// root, and nowhere else (pkg/executor/movecapture says how).
//
// The answer comes back the way a write-back does (Task 20399), in chunks the
// hub holds in memory until the caller collects them, and is refused the same
// way: a part the request did not ask for, a chunk past the part's cap, bytes
// past the executor's or the process's budget, a chunk for a capture that has
// closed or was never asked for — each is refused before anything is kept.
// What is held is let go of when the caller collects it, when the capture is
// cancelled or fails, when the session it was asked on ends before the
// answer, and when the executor is revoked or deregistered.
//
//	capture_req     hub → agent   {capture_id, mode, move_id, work_dir, features, tenant, limits}
//	capture_chunk   agent → hub   handle = capture_id {part, offset, data}
//	capture_result  agent → hub   reply to capture_req {capture_id, error, parts[{part, bytes, sha256}]}
//	capture_cancel  hub → agent   handle = capture_id {reason}

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// TypeCaptureReq (control plane → agent) asks for a project's working
	// copy. Added in v29.
	TypeCaptureReq FrameType = "capture_req"
	// TypeCaptureChunk (agent → control plane) carries one slice of one part
	// of the answer.
	TypeCaptureChunk FrameType = "capture_chunk"
	// TypeCaptureResult (agent → control plane) closes the answer: each
	// part's size and digest, or why there is none.
	TypeCaptureResult FrameType = "capture_result"
	// TypeCaptureCancel (control plane → agent) stops a capture the hub no
	// longer wants.
	TypeCaptureCancel FrameType = "capture_cancel"
)

// MinProjectCaptureVersion is the first protocol whose agents answer a
// capture request.
//
// Gated on the hub's side, and refused rather than degraded: an older agent
// has no case for the frame and would never answer, and a move that went
// ahead without the device's working copy would lose whatever it holds. The
// move's preflight says so, naming the upgrade, before anything is stopped.
const MinProjectCaptureVersion = 29

// SupportsProjectCapture reports whether an agent speaking this protocol
// version answers a capture request.
func SupportsProjectCapture(version int) bool { return version >= MinProjectCaptureVersion }

// Capture modes.
const (
	// CaptureInspect asks what the working copy holds; only the document
	// comes back.
	CaptureInspect = "inspect"
	// CaptureFull asks for the capture itself: the document, the bundle and
	// the tar.
	CaptureFull = "capture"
)

// Capture parts.
const (
	// CapturePartDocument is the JSON document describing the rest
	// (movecapture.Document).
	CapturePartDocument = "document"
	// CapturePartBundle is the git bundle.
	CapturePartBundle = "bundle"
	// CapturePartFiles is the tar of .cloop files.
	CapturePartFiles = "files"
)

// Ceilings no request may raise a part past.
const (
	// MaxCaptureDocumentBytes bounds the document.
	MaxCaptureDocumentBytes int64 = 16 << 20
	// MaxCaptureChunkBytes bounds one chunk, like a result chunk.
	MaxCaptureChunkBytes = MaxResultChunkBytes
)

// CaptureLimits caps each part of an answer: what the hub will hold of it.
// Zero refuses the part.
type CaptureLimits struct {
	Document int64 `json:"document"`
	Bundle   int64 `json:"bundle,omitempty"`
	Files    int64 `json:"files,omitempty"`
}

// of returns the cap of part, and whether the part is one the protocol knows.
func (l CaptureLimits) of(part string) (int64, bool) {
	switch part {
	case CapturePartDocument:
		return l.Document, true
	case CapturePartBundle:
		return l.Bundle, true
	case CapturePartFiles:
		return l.Files, true
	}
	return 0, false
}

// CaptureFeature is one of the project's features: its slug and the directory
// its working copy has under the agent's trees root.
type CaptureFeature struct {
	Slug string `json:"slug"`
	Dir  string `json:"dir"`
}

// CaptureRequestPayload asks for a project's working copy.
type CaptureRequestPayload struct {
	// CaptureID names the answer's chunks (their frames' handle).
	CaptureID string `json:"capture_id"`
	Mode      string `json:"mode"`
	// MoveID names the hidden refs a capture writes; empty for an inspection.
	MoveID string `json:"move_id,omitempty"`
	// WorkDir is the project's working copy: one directory under the agent's
	// trees root, executor.DeviceWorkDir of the project's path.
	WorkDir  string           `json:"work_dir"`
	Features []CaptureFeature `json:"features,omitempty"`
	// Tenant is, for an executor pool's runner, the tenant whose data its
	// volume must hold: a runner holding another's, or nothing, refuses.
	// Empty for any other device.
	Tenant string        `json:"tenant,omitempty"`
	Limits CaptureLimits `json:"limits"`
}

// CaptureChunkPayload is one slice of one part.
type CaptureChunkPayload struct {
	Part   string `json:"part"`
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

// End is the offset just past this chunk.
func (p CaptureChunkPayload) End() int64 { return p.Offset + int64(len(p.Data)) }

// CapturePartDigest is one part's size and SHA-256, as the agent sent it.
type CapturePartDigest struct {
	Part   string `json:"part"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Capture refusal codes, for the hub to tell an agent that will not from one
// that cannot.
const (
	// CaptureCodeBusy: the agent is answering another capture.
	CaptureCodeBusy = "busy"
	// CaptureCodeRefused: the agent will not answer this one — a runner
	// whose volume does not hold the tenant, a request it cannot accept.
	CaptureCodeRefused = "refused"
	// CaptureCodeTooLarge: a part would be larger than its cap.
	CaptureCodeTooLarge = "too_large"
	// CaptureCodeFailed: the capture itself failed.
	CaptureCodeFailed = "failed"
)

// CaptureResultPayload closes an answer.
type CaptureResultPayload struct {
	CaptureID string `json:"capture_id"`
	// Code and Error say why there is no answer; empty when there is one.
	Code  string              `json:"code,omitempty"`
	Error string              `json:"error,omitempty"`
	Parts []CapturePartDigest `json:"parts,omitempty"`
}

// CaptureCancelPayload stops a capture.
type CaptureCancelPayload struct {
	Reason string `json:"reason,omitempty"`
}

// maxCaptureFeatures bounds the features one request names.
const maxCaptureFeatures = 256

// validCaptureID reports whether id can name a capture: what a handle may be.
func validCaptureID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// validFeatureSlug reports whether s can name a feature.
func validFeatureSlug(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// validDirName reports whether s is one plain directory name.
func validDirName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 || strings.ContainsAny(s, "/\\\x00") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Check validates a request: both sides hold it to the same rules.
func (p CaptureRequestPayload) Check() error {
	if !validCaptureID(p.CaptureID) {
		return fmt.Errorf("%w: capture id %q", ErrProtocol, p.CaptureID)
	}
	switch p.Mode {
	case CaptureInspect:
		if p.Limits.Bundle != 0 || p.Limits.Files != 0 {
			return fmt.Errorf("%w: an inspection asks for a bundle or a tar", ErrProtocol)
		}
	case CaptureFull:
		if p.MoveID == "" || !validCaptureID(p.MoveID) {
			return fmt.Errorf("%w: a capture names no move", ErrProtocol)
		}
	default:
		return fmt.Errorf("%w: capture mode %q", ErrProtocol, p.Mode)
	}
	if !validDirName(p.WorkDir) {
		return fmt.Errorf("%w: %q is not one directory name", ErrProtocol, p.WorkDir)
	}
	if len(p.Features) > maxCaptureFeatures {
		return fmt.Errorf("%w: %d features, at most %d", ErrProtocol, len(p.Features), maxCaptureFeatures)
	}
	for _, f := range p.Features {
		if !validFeatureSlug(f.Slug) || !validDirName(f.Dir) || f.Dir == p.WorkDir {
			return fmt.Errorf("%w: feature %q at %q", ErrProtocol, f.Slug, f.Dir)
		}
	}
	if len(p.Tenant) > 64 {
		return fmt.Errorf("%w: tenant %q", ErrProtocol, p.Tenant)
	}
	if p.Limits.Document <= 0 || p.Limits.Document > MaxCaptureDocumentBytes ||
		p.Limits.Bundle < 0 || p.Limits.Files < 0 {
		return fmt.Errorf("%w: capture limits %+v", ErrProtocol, p.Limits)
	}
	return nil
}

// DecodeCaptureRequest decodes and validates a capture request.
func DecodeCaptureRequest(f Frame) (CaptureRequestPayload, error) {
	var p CaptureRequestPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if p.CaptureID != f.Handle {
		return p, fmt.Errorf("%w: a capture request's handle is not its capture id", ErrProtocol)
	}
	return p, p.Check()
}

// DecodeCaptureChunk decodes and bounds one chunk.
func DecodeCaptureChunk(f Frame) (CaptureChunkPayload, error) {
	var p CaptureChunkPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if !validCaptureID(f.Handle) {
		return p, fmt.Errorf("%w: a capture chunk names no capture", ErrProtocol)
	}
	if _, ok := (CaptureLimits{}).of(p.Part); !ok {
		return p, fmt.Errorf("%w: capture part %q", ErrProtocol, p.Part)
	}
	switch {
	case p.Offset < 0:
		return p, fmt.Errorf("%w: a capture chunk at offset %d", ErrProtocol, p.Offset)
	case len(p.Data) == 0:
		return p, fmt.Errorf("%w: an empty capture chunk", ErrProtocol)
	case len(p.Data) > MaxCaptureChunkBytes:
		return p, fmt.Errorf("%w: a capture chunk of %d bytes, at most %d", ErrProtocol, len(p.Data), MaxCaptureChunkBytes)
	}
	return p, nil
}

// DecodeCaptureResult decodes and bounds a result.
func DecodeCaptureResult(f Frame) (CaptureResultPayload, error) {
	var p CaptureResultPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if !validCaptureID(f.Handle) || p.CaptureID != f.Handle {
		return p, fmt.Errorf("%w: a capture result names no capture", ErrProtocol)
	}
	p.Code = boundText(p.Code, 32)
	p.Error = clipCaptureText(p.Error)
	if len(p.Parts) > 3 {
		return p, fmt.Errorf("%w: a capture result names %d parts", ErrProtocol, len(p.Parts))
	}
	seen := map[string]bool{}
	for _, part := range p.Parts {
		if _, ok := (CaptureLimits{}).of(part.Part); !ok || seen[part.Part] {
			return p, fmt.Errorf("%w: capture part %q", ErrProtocol, part.Part)
		}
		seen[part.Part] = true
		if part.Bytes < 0 || len(part.SHA256) != 64 {
			return p, fmt.Errorf("%w: capture part %s's size or digest", ErrProtocol, part.Part)
		}
	}
	return p, nil
}

// clipCaptureText bounds a device's prose.
func clipCaptureText(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > maxReturnedTextBytes {
		cut := maxReturnedTextBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + " …[truncated by the hub]"
	}
	return s
}
