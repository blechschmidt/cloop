package agent

// capture.go answers the hub's capture requests (Task 20495, protocol v29):
// a project move whose project runs here asks for the project's working copy,
// which only this device can read.
//
// The work itself is pkg/executor/movecapture's, which reads only the working
// copies the request names, under this agent's trees root and through an
// os.Root. What stays here is the device's part: which directories those are,
// what the run homes and lease directories are, which tenant a runner's volume
// holds, where the scratch goes, and how the answer reaches the hub — in
// capture_chunk frames, each part checked against the cap the request set
// before any of it is sent.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor/movecapture"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// captureSlot is the agent's one capture in flight, and how to stop it. One
// at a time: a capture reads a whole repository and writes a bundle of it,
// and two at once on an edge device would double both for no one's benefit.
// Its zero value is ready.
type captureSlot struct {
	mu     sync.Mutex
	id     string
	cancel context.CancelFunc
}

// begin takes the slot for id, reporting false while another capture holds it.
func (s *captureSlot) begin(id string, cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id != "" {
		return false
	}
	s.id, s.cancel = id, cancel
	return true
}

func (s *captureSlot) end(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == id {
		s.id, s.cancel = "", nil
	}
}

// stop cancels capture id if it is the one in flight.
func (s *captureSlot) stop(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id != id || s.cancel == nil {
		return false
	}
	s.cancel()
	return true
}

// handleCaptureReq answers one capture request. Its own goroutine: a capture
// reads and bundles a repository, and the frame loop carries every other
// handle's traffic.
func (a *Agent) handleCaptureReq(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	id := frame.Handle
	answer := func(code, msg string) {
		a.reply(ctx, sess, remote.TypeCaptureResult, frame.ID, id,
			remote.CaptureResultPayload{CaptureID: id, Code: code, Error: msg})
	}
	defer func() {
		if r := recover(); r != nil {
			answer(remote.CaptureCodeFailed, fmt.Sprintf("the agent failed capturing: %v", r))
		}
	}()
	req, err := remote.DecodeCaptureRequest(frame)
	if err != nil {
		if id != "" {
			answer(remote.CaptureCodeRefused, err.Error())
		} else {
			a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		}
		return
	}
	cctx, cancel := context.WithTimeout(ctx, remote.CaptureTimeout)
	defer cancel()
	slot := &a.capture
	if !slot.begin(id, cancel) {
		answer(remote.CaptureCodeBusy, deviceName()+" is answering another capture; ask again once it has")
		return
	}
	defer slot.end(id)
	if refusal := a.admitCaptureTenant(req.Tenant); refusal != "" {
		a.cfg.logf("capture %s refused: %s", id, refusal)
		answer(remote.CaptureCodeRefused, refusal)
		return
	}

	scratch := filepath.Join(a.root, ".cloop-capture-"+id)
	defer os.RemoveAll(scratch)
	mreq := movecapture.Request{
		Root: a.treesRoot(), WorkDir: req.WorkDir, Mode: req.Mode, MoveID: req.MoveID,
		Exclude: a.captureExcludes(req.WorkDir), Scratch: scratch,
		MaxBundleBytes: req.Limits.Bundle, MaxFilesBytes: req.Limits.Files,
	}
	for _, f := range req.Features {
		mreq.Features = append(mreq.Features, movecapture.Feature{Slug: f.Slug, Dir: f.Dir})
	}
	a.cfg.logf("capture %s: %s of %s", id, req.Mode, req.WorkDir)

	var (
		doc         movecapture.Document
		bundle, tar string
	)
	switch req.Mode {
	case remote.CaptureInspect:
		doc, err = movecapture.Inspect(cctx, mreq)
	default:
		var res movecapture.Result
		res, err = movecapture.Capture(cctx, mreq)
		doc, bundle, tar = res.Doc, res.BundlePath, res.TarPath
	}
	if err != nil {
		code := remote.CaptureCodeFailed
		switch {
		case errors.Is(err, movecapture.ErrConfinement), errors.Is(err, movecapture.ErrInvalidRequest):
			code = remote.CaptureCodeRefused
		case cctx.Err() != nil:
			err = fmt.Errorf("the capture was stopped: %w", cctx.Err())
		}
		a.cfg.logf("capture %s failed: %v", id, err)
		answer(code, err.Error())
		return
	}
	raw, err := doc.Encode()
	if err != nil {
		answer(remote.CaptureCodeFailed, err.Error())
		return
	}
	docFile := filepath.Join(scratch, "document.json")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		answer(remote.CaptureCodeFailed, err.Error())
		return
	}
	if err := os.WriteFile(docFile, raw, 0o600); err != nil {
		answer(remote.CaptureCodeFailed, err.Error())
		return
	}
	parts := []struct{ name, path string }{{remote.CapturePartDocument, docFile}}
	if bundle != "" {
		parts = append(parts, struct{ name, path string }{remote.CapturePartBundle, bundle})
	}
	if tar != "" {
		parts = append(parts, struct{ name, path string }{remote.CapturePartFiles, tar})
	}
	// Every part against its cap before any of it is sent: the hub would
	// refuse the first chunk past it, and the device should say why itself.
	for _, p := range parts {
		info, err := os.Stat(p.path)
		if err != nil {
			answer(remote.CaptureCodeFailed, err.Error())
			return
		}
		if limit := captureLimit(req.Limits, p.name); info.Size() > limit {
			answer(remote.CaptureCodeTooLarge, fmt.Sprintf("the %s is %d bytes, more than the %d the hub asked for at most",
				p.name, info.Size(), limit))
			return
		}
	}
	var digests []remote.CapturePartDigest
	for _, p := range parts {
		d, err := a.sendCapturePart(cctx, sess, id, p.name, p.path)
		if err != nil {
			a.cfg.logf("capture %s: sending the %s: %v", id, p.name, err)
			answer(remote.CaptureCodeFailed, fmt.Sprintf("the %s could not be sent: %v", p.name, err))
			return
		}
		digests = append(digests, d)
	}
	a.cfg.logf("capture %s: sent %d part(s)", id, len(digests))
	a.reply(ctx, sess, remote.TypeCaptureResult, frame.ID, id, remote.CaptureResultPayload{CaptureID: id, Parts: digests})
}

// handleCaptureCancel stops a capture the hub no longer wants.
func (a *Agent) handleCaptureCancel(frame remote.Frame) {
	if a.capture.stop(frame.Handle) {
		a.cfg.logf("capture %s cancelled by the control plane", frame.Handle)
	}
}

// captureLimit is a part's cap from the request.
func captureLimit(l remote.CaptureLimits, part string) int64 {
	switch part {
	case remote.CapturePartDocument:
		return l.Document
	case remote.CapturePartBundle:
		return l.Bundle
	case remote.CapturePartFiles:
		return l.Files
	}
	return 0
}

// sendCapturePart streams one part as capture_chunk frames and returns its
// size and digest.
func (a *Agent) sendCapturePart(ctx context.Context, sess *deviceSession, id, part, path string) (remote.CapturePartDigest, error) {
	f, err := os.Open(path)
	if err != nil {
		return remote.CapturePartDigest{}, err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, remote.MaxCaptureChunkBytes)
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return remote.CapturePartDigest{}, err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			frame, err := sess.frame(remote.TypeCaptureChunk, "", id,
				remote.CaptureChunkPayload{Part: part, Offset: offset, Data: buf[:n]})
			if err != nil {
				return remote.CapturePartDigest{}, err
			}
			// Written directly, not through reply, which swallows a failure: a
			// lost chunk is a part with a hole.
			if err := sess.write(ctx, frame); err != nil {
				return remote.CapturePartDigest{}, fmt.Errorf("chunk at offset %d: %w", offset, err)
			}
			offset += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return remote.CapturePartDigest{}, readErr
		}
	}
	return remote.CapturePartDigest{Part: part, Bytes: offset, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// admitCaptureTenant is admitTenant's rule for a capture: a runner whose
// volume holds one project's data answers only a capture of that project, and
// a runner whose volume holds nothing answers none that names a project — what
// it would capture is not the project's. A device that is no runner answers
// only a capture naming no tenant.
func (a *Agent) admitCaptureTenant(tenant string) string {
	holds := strings.TrimSpace(a.cfg.Holds)
	tenant = strings.TrimSpace(tenant)
	switch {
	case tenant == holds:
		return ""
	case holds == "" && a.cfg.Ephemeral:
		return "this runner's volume holds nothing of any project — it is fresh or was wiped — so it has no working copy of the project to capture"
	case holds == "":
		return "this device is not an executor pool's runner, and the capture names a pool tenant"
	case tenant == "":
		return fmt.Sprintf("this runner's volume holds a project's data (tenant %s), and the capture names no project's tenant", holds)
	default:
		return fmt.Sprintf("this runner's volume holds another project's data (tenant %s), not the data of the project being captured (tenant %s)", holds, tenant)
	}
}

// captureExcludes names what a capture of the working copy workDir must never
// read that could lie inside it: the run's home directory and the lease
// directories credentials are written to. By construction neither does — a
// home is beside its tree or under --home-root, leases are on a tmpfs — but
// a capture does not rely on how they happen to be configured.
func (a *Agent) captureExcludes(workDir string) []string {
	dir := filepath.Join(a.treesRoot(), workDir)
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		rel, err := filepath.Rel(dir, filepath.Clean(p))
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return
		}
		out = append(out, filepath.ToSlash(rel))
	}
	if home, _ := a.payloadHome(dir); home != "" {
		add(home)
	}
	add(a.homeRoot)
	add(a.secretBase())
	return out
}
