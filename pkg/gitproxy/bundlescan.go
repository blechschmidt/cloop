package gitproxy

// bundlescan.go scans what a project move carries off a device (Task 20495)
// with the push scan's own matcher.
//
// A move's capture is a push in all but name: a bundle of the commits a
// working copy holds, and its uncommitted files on a hidden ref, leaving the
// device for the hub and then for wherever the project goes next. A value the
// project's runs were given — an env secret, a token in a kubeconfig — that a
// run wrote into the tree would leave with it, to an executor the grant may
// not reach. So the hub scans it as the proxy scans a push, and more closely:
// the hub has the capture whole before anything reads it, so it reads every
// object back whole from a repository the bundle was indexed into
// (ObjectScan) — a value a delta assembles from copied parts is found, which
// a push's scan of each delta's inserts cannot promise — and the .cloop files
// beside it, which are not git objects, as plain content (ScanFiles), and the
// strings of its record (ScanStrings). A scan that cannot finish refuses the
// capture as a push's would.

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// ContentScan is what a scan of a capture's objects or of its files found.
type ContentScan struct {
	// Result is one of the ScanResult* labels.
	Result string
	// Findings name where a value was found, never the value.
	Findings []ScanFinding
	// Reason says why a scan that could not finish stopped.
	Reason   string
	Objects  uint32
	Inflated int64
}

// Refused reports whether what was scanned may not travel: it carries a
// value, or it could not be read whole.
func (c ContentScan) Refused() bool { return c.Result != ScanResultClean }

// Summary renders a refusal in one sentence, naming places and provenance
// and never a value.
func (c ContentScan) Summary() string {
	switch {
	case len(c.Findings) > 0:
		var parts []string
		for i, f := range c.Findings {
			if i == 4 {
				parts = append(parts, fmt.Sprintf("and %d more", len(c.Findings)-i))
				break
			}
			parts = append(parts, f.summary())
		}
		return "it carries a credential the project's runs are given: " + strings.Join(parts, "; ")
	case c.Result == ScanResultClean:
		return "nothing found"
	default:
		return "it could not be scanned whole: " + c.Reason
	}
}

// ScanFiles scans every regular file of a tar — the .cloop files a capture
// carries — for what scan names, as content. Findings name the file in Path.
func ScanFiles(r io.Reader, scan PushScan) ContentScan {
	m := newMatcher(scan.Secrets, scan.Tokens...)
	shapes := scan.Mode.Normalize() == ScanShapes
	limits := scan.Limits.withDefaults()
	tr := tar.NewReader(r)
	out := ContentScan{Result: ScanResultClean}
	ms := matchStream{m: m}
	win := shapeWindow{on: shapes}
	buf := make([]byte, scanInflateChunk)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ContentScan{Result: ScanResultUnreadable, Reason: "the tar could not be read: " + err.Error(), Findings: out.Findings}
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > limits.MaxObjectBytes {
			return ContentScan{Result: ScanResultLimit, Findings: out.Findings,
				Reason: fmt.Sprintf(".cloop/%s is larger than %d bytes, the most %s allows", hdr.Name, limits.MaxObjectBytes, SettingPushScanObjectMB)}
		}
		ms.reset()
		win.reset()
		name := hdr.Name
		found := map[string]bool{}
		hit := func(pi int, _ int64) bool {
			p := m.pats[pi]
			key := fmt.Sprint(p.secret, "/", p.form)
			if found[key] {
				return true
			}
			found[key] = true
			sec := m.secrets[p.secret]
			out.Findings = append(out.Findings, ScanFinding{Type: "file", Where: whereContent, Path: ".cloop/" + name,
				Grant: sec.Grant, Secret: sec.Secret, Field: sec.Field, Form: p.form})
			return len(out.Findings) < maxPushScanFindings
		}
		shapeHit := func(label string) {
			if !found["shape/"+label] && len(out.Findings) < maxPushScanFindings {
				found["shape/"+label] = true
				out.Findings = append(out.Findings, ScanFinding{Type: "file", Where: whereContent, Path: ".cloop/" + name,
					Field: label + " (recognised by its shape)"})
			}
		}
		for {
			n, err := tr.Read(buf)
			if n > 0 {
				out.Inflated += int64(n)
				if out.Inflated > limits.MaxPushBytes {
					return ContentScan{Result: ScanResultLimit, Findings: out.Findings,
						Reason: fmt.Sprintf("the files are larger than %d bytes, the most %s allows", limits.MaxPushBytes, SettingPushScanPushMB)}
				}
				ms.write(buf[:n], hit)
				win.write(buf[:n], shapeHit)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return ContentScan{Result: ScanResultUnreadable, Reason: "the tar could not be read: " + err.Error(), Findings: out.Findings}
			}
		}
		win.flush(shapeHit)
		out.Objects++
		// A file named after a value carries it too.
		if pi, ok := m.contains([]byte(name)); ok {
			p := m.pats[pi]
			sec := m.secrets[p.secret]
			out.Findings = append(out.Findings, ScanFinding{Type: "file", Where: whereEntryName, Path: ".cloop/" + m.redact(name),
				Grant: sec.Grant, Secret: sec.Secret, Field: sec.Field, Form: p.form})
		} else if shapes && len(redact.Find(name)) > 0 {
			out.Findings = append(out.Findings, ScanFinding{Type: "file", Where: whereEntryName, Path: ".cloop/…",
				Field: redact.Find(name)[0].Label + " (recognised by its shape)"})
		}
	}
	if len(out.Findings) > 0 {
		out.Result = ScanResultSecret
	}
	// Nothing a report names may carry the value.
	for i := range out.Findings {
		out.Findings[i].Path = m.redact(out.Findings[i].Path)
	}
	return out
}

// ScanStrings reports which of texts carry a value scan names, or, in shapes
// mode, a credential's shape: the indexes, never the values. A capture's
// manifest carries strings that are not git objects — a remote's URL, a
// worktree's path — and a seed writes some of them into the target's git
// configuration.
func ScanStrings(texts []string, scan PushScan) []int {
	m := newMatcher(scan.Secrets, scan.Tokens...)
	shapes := scan.Mode.Normalize() == ScanShapes
	var out []int
	for i, t := range texts {
		if _, ok := m.contains([]byte(t)); ok {
			out = append(out, i)
			continue
		}
		if shapes && len(redact.Find(t)) > 0 {
			out = append(out, i)
		}
	}
	return out
}

// ObjectScan scans whole objects one at a time, for a caller that can resolve
// every delta against its base — a capture the hub holds whole, read back
// object by object — so a value a delta built from copied parts is found.
// Findings name the object by type and id, never the value.
type ObjectScan struct {
	m       *matcher
	shapes  bool
	limits  ScanLimits
	started time.Time
	ms      matchStream
	win     shapeWindow
	buf     []byte
	out     ContentScan
}

// NewObjectScan starts a scan for what scan names.
func NewObjectScan(scan PushScan) *ObjectScan {
	m := newMatcher(scan.Secrets, scan.Tokens...)
	shapes := scan.Mode.Normalize() == ScanShapes
	return &ObjectScan{m: m, shapes: shapes, limits: scan.Limits.withDefaults(), started: time.Now(),
		ms: matchStream{m: m}, win: shapeWindow{on: shapes}, buf: make([]byte, scanInflateChunk),
		out: ContentScan{Result: ScanResultClean}}
}

// errObjectScanStop ends a scan that has decided.
var errObjectScanStop = errors.New("gitproxy: the object scan has decided")

// Object scans one object. It returns an error once the scan has decided — a
// finding past the most a report names, or a limit — so the caller stops
// reading objects.
func (o *ObjectScan) Object(kind, id string, size int64, r io.Reader) error {
	if o.out.Result != ScanResultClean && o.out.Result != ScanResultSecret {
		return errObjectScanStop
	}
	if size > o.limits.MaxObjectBytes {
		o.out.Result = ScanResultLimit
		o.out.Reason = fmt.Sprintf("object %s is larger than %d bytes, the most %s allows", abbreviate(id), o.limits.MaxObjectBytes, SettingPushScanObjectMB)
		return errObjectScanStop
	}
	o.ms.reset()
	o.win.reset()
	found := map[string]bool{}
	add := func(f ScanFinding) bool {
		if len(o.out.Findings) >= maxPushScanFindings {
			return false
		}
		o.out.Findings = append(o.out.Findings, f)
		o.out.Result = ScanResultSecret
		return true
	}
	hit := func(pi int, _ int64) bool {
		p := o.m.pats[pi]
		key := fmt.Sprint(p.secret, "/", p.form)
		if found[key] {
			return true
		}
		found[key] = true
		sec := o.m.secrets[p.secret]
		return add(ScanFinding{Object: id, Type: kind, Where: whereContent, Grant: sec.Grant, Secret: sec.Secret, Field: sec.Field, Form: p.form})
	}
	shapeHit := func(label string) {
		if !found["shape/"+label] {
			found["shape/"+label] = true
			add(ScanFinding{Object: id, Type: kind, Where: whereContent, Field: label + " (recognised by its shape)"})
		}
	}
	for {
		n, err := r.Read(o.buf)
		if n > 0 {
			o.out.Inflated += int64(n)
			if o.out.Inflated > o.limits.MaxPushBytes {
				o.out.Result = ScanResultLimit
				o.out.Reason = fmt.Sprintf("the capture inflates to more than %d bytes, the most %s allows", o.limits.MaxPushBytes, SettingPushScanPushMB)
				return errObjectScanStop
			}
			o.ms.write(o.buf[:n], hit)
			o.win.write(o.buf[:n], shapeHit)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	o.win.flush(shapeHit)
	o.out.Objects++
	if time.Since(o.started) > o.limits.MaxDuration {
		o.out.Result = ScanResultLimit
		o.out.Reason = fmt.Sprintf("scanning it took longer than %s, the most %s allows", o.limits.MaxDuration.Round(time.Second), SettingPushScanSeconds)
		return errObjectScanStop
	}
	if len(o.out.Findings) >= maxPushScanFindings {
		return errObjectScanStop
	}
	return nil
}

// Result is what the scan found. A caller that stopped reading objects on
// Object's error has the reason here.
func (o *ObjectScan) Result() ContentScan { return o.out }

// Unnamed lists the objects findings name that no path names yet.
func (o *ObjectScan) Unnamed() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range o.out.Findings {
		if f.Path == "" && f.Object != "" && !seen[f.Object] {
			seen[f.Object] = true
			out = append(out, f.Object)
		}
	}
	return out
}

// Locate names object id's findings by path: where a commit holds it. The
// path is redacted of every value the scan looks for, since it could itself
// carry one.
func (o *ObjectScan) Locate(id, path string) {
	for i := range o.out.Findings {
		if f := &o.out.Findings[i]; f.Object == id && f.Path == "" {
			f.Path = o.m.redact(path)
			if o.shapes && len(redact.Find(path)) > 0 {
				f.Path = "…"
			}
		}
	}
}

// Stopped reports whether err is Object deciding, rather than a failure to
// read the objects.
func (o *ObjectScan) Stopped(err error) bool { return errors.Is(err, errObjectScanStop) }
