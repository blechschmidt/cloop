package ui

// projectmove_capture.go captures a project whose working copy is not on the
// hub's filesystem (Task 20495): a device's, a virtual executor's on one, or
// an executor pool runner's volume.
//
// The device's agent does the capture (pkg/executor/movecapture, over the
// protocol's capture frames) and streams the answer back; this file asks for
// it on the hub member holding the device's connection, writes what comes
// back into the move's directory in the move store, checks every part against
// the digests the device reported and the manifest against what a capture
// writes, and scans the bundle and the .cloop files for the credentials the
// project's runs are given — the values a lease of the project on the source
// delivers, re-derived from its grants — so none of them leaves the device in
// the capture. A capture that carries one fails, before anything switches,
// and its store is emptied.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/movecapture"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
)

// captureAnswer is a device's verified answer to a capture, held for the hub
// until it is released: *remote.Captured.
type captureAnswer interface {
	WriteTo(part string, w io.Writer) (int64, error)
	Release()
}

// projectCapturer is what a device's working copy can be asked of.
type projectCapturer interface {
	captureWorkingCopy(ctx context.Context, req remote.CaptureRequest) (captureAnswer, error)
	CaptureVersion() (int, bool)
}

// remoteProjectCapturer is a remote executor, or a virtual executor on one.
type remoteProjectCapturer interface {
	CaptureProject(ctx context.Context, req remote.CaptureRequest) (*remote.Captured, error)
	CaptureVersion() (int, bool)
}

var (
	_ remoteProjectCapturer = (*remote.Executor)(nil)
	_ remoteProjectCapturer = (*remote.Virtual)(nil)
)

// remoteCapturer asks a device over the agent protocol.
type remoteCapturer struct{ c remoteProjectCapturer }

func (r remoteCapturer) captureWorkingCopy(ctx context.Context, req remote.CaptureRequest) (captureAnswer, error) {
	got, err := r.c.CaptureProject(ctx, req)
	if err != nil {
		return nil, err
	}
	return got, nil
}

func (r remoteCapturer) CaptureVersion() (int, bool) { return r.c.CaptureVersion() }

// capturerOf is what ex's working copy can be asked through: the agent
// protocol for a remote or virtual executor, or the executor itself when it
// answers captures in-process (a test's device).
func capturerOf(ex executor.Executor) (projectCapturer, bool) {
	if c, ok := ex.(projectCapturer); ok {
		return c, true
	}
	if c, ok := ex.(remoteProjectCapturer); ok {
		return remoteCapturer{c: c}, true
	}
	return nil, false
}

// remoteCaptureMaxBytes bounds what one capture from a device carries, its
// bundle and its files together: the answer is held in the hub's memory,
// counted against the executor's budget for returned work, until it is
// written into the move store. A move onto a device carries no more anyway —
// the carrier is a shipped branch.
const remoteCaptureMaxBytes = executor.MaxBranchBundleBytes

// moveInspectTimeout bounds asking a device what its working copy holds, for a
// preflight a person is waiting on.
var moveInspectTimeout = 2 * time.Minute

// sourceEndpoint is where the move's preflight found the project's work.
func sourceEndpoint(m projectmove.Move) projectmove.Endpoint {
	if m.Detail.Preflight != nil {
		return m.Detail.Preflight.Source
	}
	return projectmove.Endpoint{Binding: m.Source}
}

// deviceOfExecutor is the device a virtual executor runs on, or ex itself.
func deviceOfExecutor(ex executor.Executor) executor.Executor {
	if v, ok := ex.(*remote.Virtual); ok && v.Parent() != nil {
		return v.Parent()
	}
	if p, ok := ex.(interface{ ParentID() string }); ok {
		if id := strings.TrimSpace(p.ParentID()); id != "" {
			if parent, err := executor.Get(id); err == nil {
				return parent
			}
		}
	}
	return ex
}

// sourceCapturer resolves a device source: the executor the project is bound
// to, what to ask, and the device holding the connection.
func sourceCapturer(id string) (executor.Executor, projectCapturer, executor.Executor, error) {
	ex, err := executor.Get(id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the source executor %s is not registered on this hub: %w", id, err)
	}
	c, ok := capturerOf(ex)
	if !ok {
		return nil, nil, nil, fmt.Errorf("executor %s (%s) keeps no working copy the hub can ask a device for", id, ex.Kind())
	}
	return ex, c, deviceOfExecutor(ex), nil
}

// captureFeatures names the project's features as a device keeps their
// working copies: each in a directory of its own beside the project's. A list
// the hub cannot read fails the capture: the features' work would be left
// behind without a word.
func captureFeatures(project string) ([]remote.CaptureFeature, error) {
	infos, err := feature.List(project)
	if err != nil {
		return nil, fmt.Errorf("list the project's features: %w", err)
	}
	var out []remote.CaptureFeature
	for _, in := range infos {
		slug := ""
		if in.Meta != nil {
			slug = in.Meta.Slug
		}
		if slug == "" {
			_, slug, _ = feature.ParentOf(in.Path)
		}
		if slug == "" {
			continue
		}
		out = append(out, remote.CaptureFeature{Slug: slug, Dir: executor.DeviceWorkDir(in.Path)})
	}
	return out, nil
}

// agentUpgradeError is the preflight's answer for an agent too old to ask.
func agentUpgradeError(device executor.Executor, have int) *projectmove.AgentUpgradeError {
	subject := fmt.Sprintf("Device %s's agent", device.ID())
	return &projectmove.AgentUpgradeError{
		Device: device.ID(), Have: have, Need: remote.MinProjectCaptureVersion,
		Message: executor.ProtocolShortfall(subject, have, remote.MinProjectCaptureVersion,
			"to capture a project's working copy for a move"),
		Remedy: executor.AgentUpgradePath(have, remote.MinProjectCaptureVersion),
	}
}

// readCaptured reads and checks an answer's document.
func readCaptured(got captureAnswer, mode, moveID string) (movecapture.Document, error) {
	var raw bytes.Buffer
	if _, err := got.WriteTo(remote.CapturePartDocument, &raw); err != nil {
		return movecapture.Document{}, err
	}
	return movecapture.DecodeDocument(raw.Bytes(), mode, moveID)
}

// inspectDevice asks a device what the project's working copy holds, for a
// preflight.
func (s *Server) inspectDevice(ctx context.Context, p projectmove.Project, src projectmove.Endpoint) (projectmove.Tree, error) {
	_, c, device, err := sourceCapturer(src.ExecutorID)
	if err != nil {
		return projectmove.Tree{}, projectmove.ErrUnseen
	}
	if _, held := s.agentHeldByPeer(device); held {
		return projectmove.Tree{}, projectmove.ErrUnseen
	}
	v, connected := c.CaptureVersion()
	if !connected {
		return projectmove.Tree{}, fmt.Errorf("device %s is not connected", device.ID())
	}
	if !remote.SupportsProjectCapture(v) {
		return projectmove.Tree{}, agentUpgradeError(device, v)
	}
	features, err := captureFeatures(p.Path)
	if err != nil {
		return projectmove.Tree{}, err
	}
	ictx, cancel := context.WithTimeout(ctx, moveInspectTimeout)
	defer cancel()
	got, err := c.captureWorkingCopy(ictx, remote.CaptureRequest{Mode: remote.CaptureInspect,
		WorkDir: executor.DeviceWorkDir(p.Path), Features: features})
	if errors.Is(err, remote.ErrCaptureUnsupported) {
		return projectmove.Tree{}, agentUpgradeError(device, v)
	}
	if err != nil {
		return projectmove.Tree{}, err
	}
	defer got.Release()
	doc, err := readCaptured(got, movecapture.ModeInspect, "")
	if err != nil {
		return projectmove.Tree{}, err
	}
	if !doc.Present {
		return projectmove.Tree{Absent: true}, nil
	}
	return projectmove.Tree{Git: doc.Inspection.Git, Files: doc.Inspection.Files, FeatureFiles: doc.Inspection.FeatureFiles}, nil
}

// captureFromDevice captures the project from the device it is bound to,
// into rec's store.
func (d *moveDriver) captureFromDevice(ctx context.Context, m projectmove.Move, rec *projectmove.CaptureRecord) error {
	src := sourceEndpoint(m)
	id := src.ExecutorID
	if id == "" {
		id = m.Source
	}
	ex, c, device, err := sourceCapturer(id)
	if err != nil {
		return err
	}
	if _, held := d.s.agentHeldByPeer(device); held {
		return errMoveElsewhere
	}
	// A hub that restarted part-way through the move resumes it before the
	// device's agent has reconnected (Task 20497).
	if err := waitForAgent(ctx, device, func() bool { _, held := d.s.agentHeldByPeer(device); return held }); err != nil {
		return err
	}
	rec.From = "device " + device.ID()
	if ex.ID() != device.ID() {
		rec.From += " (virtual executor " + ex.ID() + ")"
	}
	features, err := captureFeatures(m.Project.Path)
	if err != nil {
		return err
	}
	req := remote.CaptureRequest{Mode: remote.CaptureFull, MoveID: m.ID, WorkDir: executor.DeviceWorkDir(m.Project.Path),
		Features: features}
	return d.collectCapture(ctx, m, rec, c, req, captureScope{executor: ex})
}

// captureScope is whose grants the capture is scanned for: the executor the
// project's runs were dispatched to, or a pool's runners'.
type captureScope struct {
	executor executor.Executor
	// poolLabels are the pool's labels, for a pool source: a label grant
	// reaches its runners when the labels hold its selector.
	poolLabels map[string]string
}

// collectCapture asks c for the capture, writes the answer into rec's store,
// checks it and scans it. Whatever it wrote into the store is removed again
// when it fails.
func (d *moveDriver) collectCapture(ctx context.Context, m projectmove.Move, rec *projectmove.CaptureRecord,
	c projectCapturer, req remote.CaptureRequest, scope captureScope) (err error) {
	limit := remoteCaptureMaxBytes
	req.Limits = remote.CaptureLimits{Document: remote.MaxCaptureDocumentBytes, Bundle: limit, Files: limit}
	if req.Mode == "" {
		req.Mode = remote.CaptureFull
	}
	// The answer is written here, and the bundle read into a repository
	// beside it to be checked: nothing is asked for that would take the hub
	// below its free-space floor.
	free, err := diskusage.FreeBytes(rec.Store)
	if err != nil {
		return err
	}
	floorMB, _ := d.s.hubFloorMB()
	floor := int64(floorMB) << 20
	if need := 3*limit + remote.MaxCaptureDocumentBytes; free-need < floor {
		return fmt.Errorf("the hub has %s free where the move store is, a capture from a device may need up to %s, and the hub keeps %s free; free some space, then move the project again",
			humanMiB(free), humanMiB(need), humanMiB(floor))
	}
	// What the capture is scanned for is settled before the device is
	// asked: a hub that cannot draw up the values does not take it.
	scan, err := captureScanFor(m, scope)
	if err != nil {
		return err
	}
	rec.Scan = scan.record
	defer func() {
		if err != nil {
			d.discardCapture(rec)
		}
	}()
	v, _ := c.CaptureVersion()
	got, err := captureWhenFree(ctx, c, req)
	if err != nil {
		if errors.Is(err, remote.ErrCaptureUnsupported) {
			return fmt.Errorf("%w; %s", err, executor.AgentUpgradePath(v, remote.MinProjectCaptureVersion))
		}
		return fmt.Errorf("capture the working copy from %s: %w", rec.From, err)
	}
	defer got.Release()
	doc, err := readCaptured(got, movecapture.ModeCapture, m.ID)
	if err != nil {
		return err
	}
	// Nothing the device wrote is recorded, or shown, before it is scanned.
	if where, found := documentCarries(doc, scan.push); found {
		scan.record.Result = gitproxy.ScanResultSecret
		return fmt.Errorf("the capture's record of the working copy may not leave the source: its %s carries a credential the project's runs are given; take it out of the working copy's repository on the source, then move the project again",
			where)
	}
	rec.WorkDir = doc.WorkDir
	tarPath := filepath.Join(rec.Store, projectmove.CarrierFiles)
	if !doc.Present {
		// Nothing to carry: an empty tar keeps the seeds' shape.
		rec.Git = movegit.Manifest{Version: movegit.ManifestVersion, MoveID: m.ID, Branches: []movegit.Ref{}}
		_, _, sum, err := projectmove.PackFileSets(tarPath, 0)
		if err != nil {
			return err
		}
		rec.FilesTar, rec.TarSum, rec.Bytes = projectmove.CarrierFiles, &sum, sum.Bytes
		rec.Notes = append(rec.Notes, "the source holds no working copy of the project at "+doc.WorkDir+": nothing was captured")
		return nil
	}
	man := *doc.Manifest
	if man.Repository {
		bundle := filepath.Join(rec.Store, projectmove.CarrierBundle)
		rec.Bundle = projectmove.CarrierBundle
		if err := writePart(got, remote.CapturePartBundle, bundle); err != nil {
			return err
		}
		if err := movegit.VerifyFile(bundle, *man.Bundle); err != nil {
			return fmt.Errorf("the bundle the device sent does not match its manifest: %w", err)
		}
		rec.Bytes += man.Bundle.Bytes
	}
	rec.FilesTar = projectmove.CarrierFiles
	if err := writePart(got, remote.CapturePartFiles, tarPath); err != nil {
		return err
	}
	if err := movegit.VerifyFile(tarPath, *doc.FilesTar); err != nil {
		return fmt.Errorf("the files the device sent do not match its record of them: %w", err)
	}
	got.Release()
	rec.Git, rec.Files, rec.TarSum = man, doc.Files, doc.FilesTar
	rec.Bytes += doc.FilesTar.Bytes
	for _, it := range doc.Kept {
		it.Detail = "stays on the source, which keeps it: " + it.Detail
		rec.KeptOnHub = append(rec.KeptOnHub, it)
	}
	rec.Notes = append(rec.Notes, doc.Notes...)
	if len(doc.Excluded) > 0 {
		rec.Notes = append(rec.Notes, "left out of the capture: "+strings.Join(doc.Excluded, ", "))
	}
	if rec.Bytes > limit {
		return fmt.Errorf("the working copy and its .cloop files come to %s, more than a capture from a device carries (%s)",
			humanMiB(rec.Bytes), humanMiB(limit))
	}
	return d.checkCapture(ctx, rec, scan)
}

// Tunables, variables so tests can shorten them.
var (
	// moveCaptureBusyWait bounds how long a capture waits for a device busy
	// with another capture — another project's move — and
	// moveCaptureBusyPoll how often it asks again.
	moveCaptureBusyWait = 10 * time.Minute
	moveCaptureBusyPoll = 5 * time.Second
)

// captureWhenFree asks c for the capture, asking again while the device is
// answering another one: an agent captures one working copy at a time.
func captureWhenFree(ctx context.Context, c projectCapturer, req remote.CaptureRequest) (captureAnswer, error) {
	deadline := time.Now().Add(moveCaptureBusyWait)
	for {
		got, err := c.captureWorkingCopy(ctx, req)
		if !errors.Is(err, remote.ErrCaptureBusy) || time.Now().After(deadline) {
			return got, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(moveCaptureBusyPoll):
		}
	}
}

// writePart writes one part of an answer to path, through a temporary file
// beside it.
func writePart(got captureAnswer, part, path string) error {
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write the capture's %s: %w", part, err)
	}
	if _, err := got.WriteTo(part, f); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write the capture's %s: %w", part, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write the capture's %s: %w", part, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// captureScan is what a capture from a device is scanned for, and the record
// of it the move keeps.
type captureScan struct {
	push   gitproxy.PushScan
	record *projectmove.ScanRecord
}

// captureScanFor settles what the capture is scanned for: the values the
// project's runs on the source are given, in values mode at least.
//
// The scan is the git proxy's (pkg/gitproxy), in values mode at least,
// whatever the hub's push_scan says: a value in a capture would travel to an
// executor its grant may not reach, which no setting about pushes speaks to.
// A hub or project asking for shapes gets shapes.
func captureScanFor(m projectmove.Move, scope captureScope) (captureScan, error) {
	secrets, grants, err := captureScanSecrets(m.Project.Path, scope)
	if err != nil {
		return captureScan{}, err
	}
	mode, limits := gitproxy.ScanValues, gitproxy.ScanLimits{}
	if cfg, err := controlPlaneConfig(); err == nil && cfg != nil {
		mode = gitproxy.StricterScanMode(mode, cfg.Executors.GitProxy.PushScanMode())
		limits = cfg.Executors.GitProxy.PushScanLimits()
	}
	if pm, ok := projectPushScanMode(m.Project.Path); ok {
		mode = gitproxy.StricterScanMode(mode, pm)
	}
	return captureScan{
		push:   gitproxy.PushScan{Mode: mode, Secrets: secrets, Limits: limits},
		record: &projectmove.ScanRecord{Grants: grants, Values: len(secrets), Mode: string(mode), Result: gitproxy.ScanResultClean},
	}, nil
}

// checkCapture checks what a device sent and scans it, before anything reads
// it as the project's: every object of the bundle, read back whole from a
// scratch repository the bundle is held to its manifest in — so a value a
// delta assembles from copied parts is found as well as one written whole —
// and its trees held to what the hub keeps of .cloop; then every file of the
// tar, and the tar to its record. A capture that carries a value the
// project's runs are given, or that cannot be scanned whole, is refused.
func (d *moveDriver) checkCapture(ctx context.Context, rec *projectmove.CaptureRecord, scan captureScan) error {
	sr := scan.record
	if rec.Bundle != "" {
		objects := gitproxy.NewObjectScan(scan.push)
		err := movegit.CheckBundle(ctx, movegit.BundleCheck{BundlePath: filepath.Join(rec.Store, rec.Bundle),
			Manifest: rec.Git, Scratch: rec.Store, Reserve: &projectmove.HubTreeReserved, Object: objects.Object,
			Locate: objects.Unnamed, Located: objects.Locate})
		if res := objects.Result(); res.Refused() {
			sr.Result = res.Result
			return fmt.Errorf("the capture's repository may not leave the source: %s; take it out of the working copy on the source (and out of any commit that holds it), then move the project again",
				res.Summary())
		}
		switch {
		case errors.Is(err, movegit.ErrForbiddenPath):
			return fmt.Errorf("the capture's repository may not be restored: %w; take the file out of the repository on the source (git rm --cached, then commit), then move the project again", err)
		case err != nil:
			return fmt.Errorf("the repository the device sent is not the one its manifest describes: %w", err)
		}
	}
	if rec.FilesTar != "" {
		path := filepath.Join(rec.Store, rec.FilesTar)
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		res := gitproxy.ScanFiles(f, scan.push)
		f.Close()
		if res.Refused() {
			sr.Result = res.Result
			return fmt.Errorf("the capture's .cloop files may not leave the source: %s; take it out of the working copy on the source, then move the project again",
				res.Summary())
		}
		if err := projectmove.VerifyFilesTar(path, rec.Files); err != nil {
			return fmt.Errorf("the files the device sent are not the ones it recorded: %w", err)
		}
	}
	return nil
}

// documentCarries reports where in a device's document — any string it
// holds, at any depth, map keys too — the scan finds a value, by the
// document's JSON field names; never the value.
func documentCarries(doc movecapture.Document, scan gitproxy.PushScan) (string, bool) {
	var texts, where []string
	collectStrings(reflect.ValueOf(doc), "", &texts, &where)
	if hits := gitproxy.ScanStrings(texts, scan); len(hits) > 0 {
		return where[hits[0]], true
	}
	return "", false
}

// collectStrings appends every string v holds to texts, and where it is to
// where.
func collectStrings(v reflect.Value, path string, texts, where *[]string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			collectStrings(v.Elem(), path, texts, where)
		}
	case reflect.String:
		if v.Len() > 0 {
			*texts, *where = append(*texts, v.String()), append(*where, path)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			if path != "" {
				name = path + "." + name
			}
			collectStrings(v.Field(i), name, texts, where)
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Kind() == reflect.Slice && v.Len() > 0 {
				*texts, *where = append(*texts, string(v.Bytes())), append(*where, path)
			}
			return
		}
		for i := 0; i < v.Len(); i++ {
			collectStrings(v.Index(i), fmt.Sprintf("%s[%d]", path, i), texts, where)
		}
	case reflect.Map:
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for i, k := range keys {
			// A key is named by its place: it is the device's, and could
			// itself be what the scan finds.
			at := fmt.Sprintf("%s[key %d]", path, i)
			collectStrings(k, at, texts, where)
			collectStrings(v.MapIndex(k), at+" value", texts, where)
		}
	}
}

// discardCapture removes what a capture wrote into the store.
func (d *moveDriver) discardCapture(rec *projectmove.CaptureRecord) {
	for _, name := range []string{rec.Bundle, rec.FilesTar} {
		if name != "" {
			_ = os.Remove(filepath.Join(rec.Store, name))
			_ = os.Remove(filepath.Join(rec.Store, name) + ".part")
		}
	}
	rec.Bundle, rec.FilesTar, rec.TarSum, rec.Bytes = "", "", nil, 0
}

// captureScanSecrets re-derives the values the project's grants deliver to a
// run of it on scope's executor — or on a pool's runners — and reports how
// many grants it drew values from. A grant in force that the hub cannot open
// refuses the capture, as does a control plane database it cannot read: a
// scan without their values would pass what it exists to stop. Only a hub
// with no control plane database at all has made no grant.
//
// A grant that lapsed — revoked, expired or suspended — within
// captureLapsedGrantWindow is scanned for too, where its secret can still be
// opened: the runs it served may have left its value in the working copy.
func captureScanSecrets(project string, scope captureScope) ([]gitproxy.ScanSecret, int, error) {
	if scope.executor == nil {
		return nil, 0, errors.New("the capture names no executor whose grants its scan could be drawn from")
	}
	dbPath := state.DBPath(controlPlaneDir())
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		// No control plane database: no grant was ever made.
		return nil, 0, nil
	}
	bs, err := openBrokersAt(controlPlaneDir())
	if err != nil {
		return nil, 0, fmt.Errorf("the hub cannot read its grants, so it cannot scan the capture for the credentials they deliver: %w", err)
	}
	defer bs.close()
	store, err := secretstore.New(bs.db)
	if err != nil {
		return nil, 0, err
	}
	grants, err := store.ListGrants()
	if err != nil {
		return nil, 0, err
	}
	// The executor as the hub records it: its labels decide which label
	// grants reach it.
	req, err := leaseRequester(bs.db, project, scope.executor, "", nil)
	if err != nil {
		return nil, 0, err
	}
	now := time.Now()
	var active, lapsed []string
	for _, g := range grants {
		reaches := g.Subject.Matches(req)
		if !reaches && scope.poolLabels != nil && g.Subject.Type == secretbroker.SubjectLabel {
			reaches = labelsHold(g.Subject.Labels, scope.poolLabels)
		}
		if !reaches {
			continue
		}
		switch {
		case g.Active(now):
			active = append(active, g.ID)
		case grantLapsedSince(g, now.Add(-captureLapsedGrantWindow)):
			lapsed = append(lapsed, g.ID)
		}
	}
	if len(active)+len(lapsed) == 0 {
		return nil, 0, nil
	}
	if bs.secret == nil {
		if len(active) == 0 {
			return nil, 0, nil
		}
		return nil, len(active), fmt.Errorf("%d of the project's grants reach the source, and the hub cannot open its secret store (%s), so it cannot scan the capture for the credentials they deliver; %s",
			len(active), bs.status.Reason, bs.status.Remediation)
	}
	creds, opened := bs.secret.GrantCredentials(active, req)
	if opened < len(active) {
		return nil, len(active), fmt.Errorf("%d of the %d grants that reach the source could not be opened, so the capture cannot be scanned for what they deliver; check the hub's log for the secret store's error, then move the project again",
			len(active)-opened, len(active))
	}
	if len(lapsed) > 0 {
		// Best effort: a lapsed grant's secret may be gone.
		more, n := bs.secret.GrantCredentials(lapsed, req)
		creds = append(creds, more...)
		opened += n
	}
	return scanSecrets(creds), opened, nil
}

// captureLapsedGrantWindow is how far back a lapsed grant is still scanned
// for.
const captureLapsedGrantWindow = 90 * 24 * time.Hour

// grantLapsedSince reports whether a grant that is not in force stopped being
// after since: revoked, expired, or suspended then.
func grantLapsedSince(g secretbroker.Grant, since time.Time) bool {
	var at time.Time
	for _, t := range []time.Time{g.RevokedAt, g.ExpiresAt, g.SuspendedAt} {
		if !t.IsZero() && (at.IsZero() || t.Before(at)) {
			at = t
		}
	}
	return !at.IsZero() && at.After(since)
}
