package gitproxy

// packscan.go reads a push's pack as it streams through the proxy and finds
// the run's credentials in it (Task 20436). See pushscan.go for why.
//
// # The pack format, as git reads it
//
// "PACK", a version (2 or 3), an object count, then that many objects, then
// the checksum of everything before it. Each object is a varint header — a
// type and the inflated size — then, for an OFS_DELTA the distance back to its
// base and for a REF_DELTA the base's object id, then one zlib stream. The
// parser here follows index-pack's rules wherever they decide what the forge
// will see — header widths, the bounds on a base offset, a zlib stream ending
// exactly where zlib says it does, the inflated size matching the header,
// patch_delta's rules for a delta's instructions — because a pack this parser
// read differently from git is a pack in which it scanned bytes the forge does
// not store and skipped bytes it does. Anything it cannot read is refused.
//
// # What it keeps
//
// Nothing of the content: every object is inflated through a fixed buffer and
// forgotten. What it keeps is the shape a refusal names — object ids, the
// entries of the trees and the root trees of the commits in the pack — in maps
// whose size is bounded, so a pack of a million objects degrades the report
// rather than the hub.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// Object types, as the pack header encodes them.
const (
	objCommit   = 1
	objTree     = 2
	objBlob     = 3
	objTag      = 4
	objOfsDelta = 6
	objRefDelta = 7
)

func objTypeName(t int) string {
	switch t {
	case objCommit:
		return "commit"
	case objTree:
		return "tree"
	case objBlob:
		return "blob"
	case objTag:
		return "tag"
	case objOfsDelta, objRefDelta:
		return "delta"
	}
	return "unknown"
}

// Bounds on what the scanner remembers for its report. Past them it stops
// remembering, and a refusal names less.
const (
	scanMaxIDs       = 1 << 18
	scanMaxLinks     = 1 << 18
	scanMaxNames     = 1 << 16
	scanMaxCommits   = 1 << 16
	scanMaxTags      = 1 << 12
	scanMaxTreeEntry = 4096
	scanMaxNameLen   = 256
	scanMaxNameBytes = 16 << 20
	scanHeaderBytes  = 64 << 10
	scanNameRunBytes = 64 << 10
	scanNameDeltaMax = 16 << 20
	scanSourceBuffer = 64 << 10
	scanInflateChunk = 64 << 10
	scanMaxPushOpts  = 64 << 10
	shapeWindowSize  = 64 << 10
	shapeOverlap     = 8 << 10
	packHeaderLen    = 12
)

// --- errors -------------------------------------------------------------------

// scanStop classifies why a scan ended without saying the push is clean.
type scanStop int

const (
	// stopUnreadable: the pack could not be read, so nothing can be said about
	// what it carries.
	stopUnreadable scanStop = iota + 1
	// stopLimit: a configured limit was reached.
	stopLimit
	// stopClient: the sandbox's body failed before it ended.
	stopClient
	// stopUpstream: the forge stopped reading.
	stopUpstream
)

// scanError is a scan that stopped short. Its message is what a refusal says,
// and never carries pack content.
type scanError struct {
	stop    scanStop
	msg     string
	setting string
	err     error
}

func (e *scanError) Error() string { return e.msg }
func (e *scanError) Unwrap() error { return e.err }

func unreadable(format string, a ...any) *scanError {
	return &scanError{stop: stopUnreadable, msg: fmt.Sprintf(format, a...)}
}

// --- the byte source ------------------------------------------------------------

// packSource is what the parser reads the push's body through. It counts the
// bytes the parser has consumed and records how long it waited on the sandbox
// or the forge, so the scan's time limit measures work rather than the network.
//
// It hands a byte on to the forge (tee) only once the parser has consumed it,
// never on reading it, so the forge is never ahead of the scan; and from
// startHolding on it keeps consumed bytes back instead, which is how the
// pack's checksum waits for the verdict. Holding the last bytes *read* would
// not do: a sandbox that sent anything after the checksum would push it out
// of the held window and complete the pack upstream.
//
// It implements io.ByteReader, which is what lets compress/flate stop at the
// end of each object's zlib stream instead of reading ahead into the next.
type packSource struct {
	r   io.Reader
	tee func([]byte) error
	// idle, when set, is called before every read from the sandbox — the
	// proxy pushes the connection's read deadline out with it.
	idle func()
	// budget, when set, is asked before every read whether the scan may go
	// on — how the time limit holds however little an object inflates to.
	budget func() error
	// limit bounds the bytes read from the sandbox, gzip-decoded: the
	// session's MaxPackBytes caps what arrived on the wire, and a gzipped
	// body could otherwise expand without end.
	limit int64

	buf      []byte
	pos, end int
	// fwd is where in buf the bytes consumed but not yet handed on start.
	fwd     int
	holding bool
	held    []byte
	// heldFrom is the offset holding started at, -1 until it does: the pack's
	// checksum, for a pack read to its end.
	heldFrom int64
	off      int64
	read     int64
	wait     time.Duration
	pending  error
	err      error
}

func newPackSource(r io.Reader, tee func([]byte) error) *packSource {
	return &packSource{r: r, tee: tee, buf: make([]byte, scanSourceBuffer), heldFrom: -1}
}

// handOn passes the bytes consumed since the last hand-on to the forge, or
// keeps them back while holding.
func (s *packSource) handOn() error {
	if s.fwd >= s.pos {
		return nil
	}
	b := s.buf[s.fwd:s.pos]
	s.fwd = s.pos
	if s.holding {
		s.held = append(s.held, b...)
		return nil
	}
	if s.tee == nil {
		return nil
	}
	t := time.Now()
	err := s.tee(b)
	s.wait += time.Since(t)
	if err != nil {
		s.err = err
	}
	return err
}

// startHolding hands on everything consumed so far and keeps back what is
// consumed from here on, until release.
func (s *packSource) startHolding() error {
	if err := s.handOn(); err != nil {
		return err
	}
	s.holding = true
	s.heldFrom = s.off
	return nil
}

// release hands on what was held back.
func (s *packSource) release() error {
	if err := s.handOn(); err != nil {
		return err
	}
	s.holding = false
	if len(s.held) == 0 || s.tee == nil {
		return nil
	}
	held := s.held
	s.held = nil
	t := time.Now()
	err := s.tee(held)
	s.wait += time.Since(t)
	return err
}

func (s *packSource) fill() error {
	if s.err != nil {
		return s.err
	}
	if err := s.handOn(); err != nil {
		return err
	}
	if s.pending != nil {
		s.err = s.pending
		return s.err
	}
	if s.budget != nil {
		if err := s.budget(); err != nil {
			s.err = err
			return err
		}
	}
	if s.limit > 0 && s.read >= s.limit {
		s.err = &scanError{stop: stopLimit,
			msg: fmt.Sprintf("the push runs past the %d bytes a session may send in one push", s.limit)}
		return s.err
	}
	for empty := 0; ; empty++ {
		if s.idle != nil {
			s.idle()
		}
		t0 := time.Now()
		n, err := s.r.Read(s.buf)
		s.wait += time.Since(t0)
		if n > 0 {
			s.read += int64(n)
			s.pos, s.end, s.fwd = 0, n, 0
			s.pending = classifySourceErr(err)
			return nil
		}
		if err != nil {
			s.err = classifySourceErr(err)
			return s.err
		}
		if empty > 100 {
			s.err = io.ErrNoProgress
			return s.err
		}
	}
}

// classifySourceErr turns a failed read from the sandbox's body into what the
// scan reports: the end of the body stays io.EOF, a body past the session's
// size cap is a limit, anything else is the sandbox gone.
func classifySourceErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	var se *scanError
	if errors.As(err, &se) {
		return err
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return &scanError{stop: stopLimit, err: err,
			msg: fmt.Sprintf("the push is larger than the %d bytes a session may send in one request", mbe.Limit)}
	}
	return &scanError{stop: stopClient, msg: "the push's body could not be read: " + err.Error(), err: err}
}

func (s *packSource) ReadByte() (byte, error) {
	if s.pos == s.end {
		if err := s.fill(); err != nil {
			return 0, err
		}
	}
	c := s.buf[s.pos]
	s.pos++
	s.off++
	return c, nil
}

func (s *packSource) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.pos == s.end {
		if err := s.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, s.buf[s.pos:s.end])
	s.pos += n
	s.off += int64(n)
	return n, nil
}

// drain reads the sandbox's body to its end without parsing it, so the
// sandbox's git finishes sending and reads the refusal. What it reads goes
// nowhere: the gate discards everything once a push is refused.
func (s *packSource) drain() {
	s.holding = false
	s.held = nil
	// Reading out the rest is not scanning, so the scan's clock no longer
	// applies; the byte limit still does.
	s.budget = nil
	for {
		s.pos = s.end
		if err := s.fill(); err != nil {
			return
		}
	}
}

// --- the scanner ------------------------------------------------------------------

// objectID is an object name, SHA-1 or SHA-256; hashLen says how much of it
// is used.
type objectID [32]byte

type treeLink struct {
	parent objectID
	name   string
}

type tagInfo struct {
	name string
}

// rawFinding is a match before the report resolves paths and commits, which
// may need objects later in the pack.
type rawFinding struct {
	where  string
	typ    int
	id     objectID
	hasID  bool
	base   string
	ref    string
	secret int // index into the matcher's secrets; -1 for a shape
	form   string
	shape  string
}

// curObject is the object being scanned.
type curObject struct {
	typ       int
	headerEnd int64 // commit and tag: offset of the blank line; -1 until seen
	seen      map[int]bool
	shaped    bool
	findings  []rawFinding
	base      string
}

// packScanner scans one push.
type packScanner struct {
	src     *packSource
	hashLen int
	m       *matcher
	shapes  bool
	limits  ScanLimits
	started time.Time
	// onRefuse is called once, the moment the scan knows it will refuse —
	// the first finding, a limit, an unreadable pack — so the forge's request
	// is aborted then rather than when the scan has also finished reporting.
	onRefuse func()
	refused  bool

	zr     io.ReadCloser
	hasher hash.Hash
	chunk  []byte

	inflated int64
	objects  uint32
	// typeCounts counts the objects of each type the pack held, deltas by
	// kind: what a test asks to know it exercised the path it meant to.
	typeCounts [8]int
	// packStart is where "PACK" starts in what the source has consumed —
	// after the push options, when there are any. Object offsets, and the
	// distances an OFS_DELTA counts back, are measured from it.
	packStart int64
	ms        matchStream
	win       shapeWindow
	cur       curObject

	findings     []rawFinding
	stopMatching bool

	ids   map[int64]objectID
	links map[objectID]treeLink
	// nameBytes counts the entry names links keeps, against scanMaxNameBytes.
	nameBytes int
	names     map[objectID]string
	roots     map[objectID][]objectID
	commits   []objectID
	tags      map[objectID]tagInfo
	tips      []RefUpdate

	// nameRun collects a delta's inserts for the tree-entry names they may
	// carry; nameRunOn says the current delta is small enough to look.
	nameRun   []byte
	nameRunOn bool
}

func newPackScanner(src *packSource, hashLen int, m *matcher, shapes bool, limits ScanLimits) *packScanner {
	s := &packScanner{
		src:     src,
		hashLen: hashLen,
		m:       m,
		shapes:  shapes,
		limits:  limits.withDefaults(),
		started: time.Now(),
		chunk:   make([]byte, scanInflateChunk),
		ids:     map[int64]objectID{},
		links:   map[objectID]treeLink{},
		names:   map[objectID]string{},
		roots:   map[objectID][]objectID{},
		tags:    map[objectID]tagInfo{},
	}
	if hashLen == sha256.Size {
		s.hasher = sha256.New()
	} else {
		s.hashLen = sha1.Size
		s.hasher = sha1.New()
	}
	s.ms.m = m
	s.win.on = shapes
	// The clock is asked on every read from the sandbox too, so an object
	// that inflates to nothing — or a pack of millions of them — cannot run
	// past the limit between two chunks of output.
	src.budget = s.checkTime
	return s
}

// refuse records that the push will be refused and tells the gate, once.
func (s *packScanner) refuse() {
	if s.refused {
		return
	}
	s.refused = true
	if s.onRefuse != nil {
		s.onRefuse()
	}
}

// work is the time spent scanning, net of waiting on either side.
func (s *packScanner) work() time.Duration {
	w := time.Since(s.started) - s.src.wait
	if w < 0 {
		return 0
	}
	return w
}

func (s *packScanner) checkTime() error {
	if s.work() <= s.limits.MaxDuration {
		return nil
	}
	return &scanError{stop: stopLimit, setting: SettingPushScanSeconds,
		msg: fmt.Sprintf("scanning it took longer than %s, the most %s allows",
			s.limits.MaxDuration.Round(time.Second), SettingPushScanSeconds)}
}

// scanCommands scans what the command section and the push options carry:
// ref names are published with the ref, and push options reach the forge's
// hooks.
func (s *packScanner) scanCommands(head *ReceivePack) {
	if head == nil {
		return
	}
	for _, c := range head.Commands {
		if !c.IsDelete() {
			s.tips = append(s.tips, c)
		}
		if pi, ok := s.m.contains([]byte(c.Ref)); ok {
			p := s.m.pats[pi]
			s.addFinding(rawFinding{where: whereRef, ref: c.Ref, secret: p.secret, form: p.form})
		} else if s.shapes {
			for _, d := range redact.Find(c.Ref) {
				s.addFinding(rawFinding{where: whereRef, ref: c.Ref, secret: -1, shape: d.Label})
				break
			}
		}
	}
}

// scan reads what follows the command section: the push options when the
// client negotiated them, then the pack, then nothing.
func (s *packScanner) scan(head *ReceivePack) error {
	s.scanCommands(head)
	if head != nil && head.HasCapability("push-options") {
		if err := s.scanPushOptions(); err != nil {
			return err
		}
	}
	s.packStart = s.src.off
	var hdr [packHeaderLen]byte
	n, err := io.ReadFull(s.src, hdr[:])
	switch {
	case n == 0 && errors.Is(err, io.EOF):
		// No pack: a push that only deletes sends none.
		return nil
	case err != nil:
		return s.sourceErr(err, "the pack's header")
	}
	if !bytes.Equal(hdr[:4], []byte("PACK")) {
		return unreadable("its pack does not start with a pack header")
	}
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != 2 && version != 3 {
		return unreadable("its pack is version %d; git writes 2 or 3", version)
	}
	count := binary.BigEndian.Uint32(hdr[8:12])
	for i := uint32(0); i < count; i++ {
		if err := s.checkTime(); err != nil {
			return err
		}
		if err := s.object(i); err != nil {
			return err
		}
		s.objects++
	}
	// The checksum is what completes the pack for the forge: from here on
	// nothing is handed on until the verdict.
	if err := s.src.startHolding(); err != nil {
		return s.sourceErr(err, "the pack's checksum")
	}
	trailer := make([]byte, s.hashLen)
	if _, err := io.ReadFull(s.src, trailer); err != nil {
		return s.sourceErr(err, "the pack's checksum")
	}
	if _, err := s.src.ReadByte(); err == nil {
		return unreadable("bytes follow its pack's checksum")
	} else if !errors.Is(err, io.EOF) {
		return s.sourceErr(err, "the end of the body")
	}
	return nil
}

// sourceErr turns a read failure while reading what into a scan error.
func (s *packScanner) sourceErr(err error, what string) error {
	var se *scanError
	if errors.As(err, &se) {
		return se
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return unreadable("the push ends inside %s", what)
	}
	return &scanError{stop: stopClient, msg: "the push's body could not be read: " + err.Error(), err: err}
}

// scanPushOptions reads the push-options section: pkt-lines up to a flush.
func (s *packScanner) scanPushOptions() error {
	var total int
	for {
		var head [pktHeaderLen]byte
		if _, err := io.ReadFull(s.src, head[:]); err != nil {
			return s.sourceErr(err, "its push options")
		}
		if string(head[:]) == string(flushPkt) {
			return nil
		}
		var lenBuf [2]byte
		if _, err := hex.Decode(lenBuf[:], head[:]); err != nil {
			return unreadable("its push options are not pkt-lines")
		}
		size := int(lenBuf[0])<<8 | int(lenBuf[1])
		if size <= pktHeaderLen || size > maxPktLen {
			return unreadable("its push options carry a pkt-line of length %d", size)
		}
		total += size
		if total > scanMaxPushOpts {
			return unreadable("its push options run past %d bytes", scanMaxPushOpts)
		}
		payload := make([]byte, size-pktHeaderLen)
		if _, err := io.ReadFull(s.src, payload); err != nil {
			return s.sourceErr(err, "its push options")
		}
		if pi, ok := s.m.contains(payload); ok {
			p := s.m.pats[pi]
			s.addFinding(rawFinding{where: wherePushOption, secret: p.secret, form: p.form})
		}
		if s.shapes {
			for _, d := range redact.Find(string(payload)) {
				s.addFinding(rawFinding{where: wherePushOption, secret: -1, shape: d.Label})
				break
			}
		}
	}
}

// object scans the next object in the pack.
func (s *packScanner) object(index uint32) error {
	off := s.src.off - s.packStart
	c, err := s.src.ReadByte()
	if err != nil {
		return s.sourceErr(err, fmt.Sprintf("the header of object %d", index+1))
	}
	typ := int(c>>4) & 7
	s.typeCounts[typ]++
	size := uint64(c & 15)
	shift := uint(4)
	for c&0x80 != 0 {
		if shift >= 64 {
			return unreadable("object %d at pack offset %d has a header longer than git reads", index+1, off)
		}
		if c, err = s.src.ReadByte(); err != nil {
			return s.sourceErr(err, fmt.Sprintf("the header of object %d", index+1))
		}
		size |= uint64(c&0x7f) << shift
		shift += 7
	}
	if size > uint64(s.limits.MaxObjectBytes) {
		return &scanError{stop: stopLimit, setting: SettingPushScanObjectMB,
			msg: fmt.Sprintf("object %d inflates to %d bytes, more than the %d MiB %s lets the proxy scan",
				index+1, size, s.limits.MaxObjectBytes/pushScanMiB, SettingPushScanObjectMB)}
	}

	switch typ {
	case objCommit, objTree, objBlob, objTag:
		return s.wholeObject(index, typ, size, off)
	case objOfsDelta:
		dist, err := s.ofsDistance(index)
		if err != nil {
			return err
		}
		// index-pack: the base must start inside the pack and before this
		// object.
		if dist == 0 || dist >= uint64(off) || off-int64(dist) < packHeaderLen {
			return unreadable("object %d at pack offset %d is a delta whose base offset is out of bounds", index+1, off)
		}
		baseOff := off - int64(dist)
		base := "the object at pack offset " + strconv.FormatInt(baseOff, 10)
		if id, ok := s.ids[baseOff]; ok {
			base = hex.EncodeToString(id[:s.hashLen])
		}
		return s.deltaObject(index, typ, size, base)
	case objRefDelta:
		raw := make([]byte, s.hashLen)
		if _, err := io.ReadFull(s.src, raw); err != nil {
			return s.sourceErr(err, fmt.Sprintf("the base of object %d", index+1))
		}
		return s.deltaObject(index, typ, size, hex.EncodeToString(raw))
	default:
		return unreadable("object %d at pack offset %d has type %d, which git does not write", index+1, off, typ)
	}
}

// ofsDistance reads an OFS_DELTA's distance back to its base, as index-pack
// does: each continuation adds one before shifting, and a value that would
// overflow is refused.
func (s *packScanner) ofsDistance(index uint32) (uint64, error) {
	c, err := s.src.ReadByte()
	if err != nil {
		return 0, s.sourceErr(err, fmt.Sprintf("the base offset of object %d", index+1))
	}
	dist := uint64(c & 127)
	for c&128 != 0 {
		dist++
		if dist == 0 || dist>>(64-7) != 0 {
			return 0, unreadable("object %d has a delta base offset that overflows", index+1)
		}
		if c, err = s.src.ReadByte(); err != nil {
			return 0, s.sourceErr(err, fmt.Sprintf("the base offset of object %d", index+1))
		}
		dist = dist<<7 | uint64(c&127)
	}
	return dist, nil
}

// resetZlib points the inflater at the next object's zlib stream.
func (s *packScanner) resetZlib() error {
	if s.zr == nil {
		zr, err := zlib.NewReader(s.src)
		if err != nil {
			return err
		}
		s.zr = zr
		return nil
	}
	return s.zr.(zlib.Resetter).Reset(s.src, nil)
}

// inflate inflates the current object's zlib stream, handing each chunk to
// emit, and holds it to its declared size and the limits.
func (s *packScanner) inflate(index uint32, size uint64, emit func([]byte) error) error {
	if err := s.resetZlib(); err != nil {
		return s.inflateErr(err, index)
	}
	var got uint64
	for {
		n, err := s.zr.Read(s.chunk)
		if n > 0 {
			got += uint64(n)
			if got > size {
				return unreadable("object %d inflates past the %d bytes its header declares", index+1, size)
			}
			s.inflated += int64(n)
			if s.inflated > s.limits.MaxPushBytes {
				return &scanError{stop: stopLimit, setting: SettingPushScanPushMB,
					msg: fmt.Sprintf("its objects inflate to more than %d MiB, the most %s lets the proxy scan",
						s.limits.MaxPushBytes/pushScanMiB, SettingPushScanPushMB)}
			}
			if e := emit(s.chunk[:n]); e != nil {
				return e
			}
			if e := s.checkTime(); e != nil {
				return e
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s.inflateErr(err, index)
		}
	}
	if got != size {
		return unreadable("object %d inflates to %d bytes, and its header declares %d", index+1, got, size)
	}
	return nil
}

func (s *packScanner) inflateErr(err error, index uint32) error {
	var se *scanError
	if errors.As(err, &se) {
		return se
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return unreadable("the push ends inside object %d", index+1)
	}
	return unreadable("object %d does not inflate: %v", index+1, err)
}

// beginObject starts the bookkeeping for one object.
func (s *packScanner) beginObject(typ int, base string) {
	s.cur = curObject{typ: typ, headerEnd: -1, base: base}
	s.ms.reset()
	s.win.reset()
}

// wholeObject scans a commit, tree, blob or tag and computes its id.
func (s *packScanner) wholeObject(index uint32, typ int, size uint64, off int64) error {
	s.beginObject(typ, "")
	s.hasher.Reset()
	s.hasher.Write([]byte(objTypeName(typ) + " " + strconv.FormatUint(size, 10) + "\x00"))

	var (
		tree    treeParser
		entries []treeEntry
		header  []byte
	)
	tree.hashLen = s.hashLen
	tree.onEntry = func(e treeEntry) {
		if len(s.links)+len(entries) >= scanMaxLinks || s.nameBytes >= scanMaxNameBytes {
			return
		}
		if len(e.name) > scanMaxNameLen {
			e.name = e.name[:scanMaxNameLen] + "…"
		}
		s.nameBytes += len(e.name)
		entries = append(entries, e)
	}
	err := s.inflate(index, size, func(chunk []byte) error {
		s.hasher.Write(chunk)
		switch typ {
		case objTree:
			tree.feed(chunk)
		case objCommit, objTag:
			if s.cur.headerEnd < 0 && len(header) < scanHeaderBytes {
				header = append(header, chunk...)
				if i := bytes.Index(header, []byte("\n\n")); i >= 0 {
					s.cur.headerEnd = int64(i + 1)
				}
			}
		}
		s.matchChunk(chunk)
		return nil
	})
	if err != nil {
		return err
	}
	s.flushShapes()

	var id objectID
	copy(id[:], s.hasher.Sum(nil))
	if len(s.ids) < scanMaxIDs {
		s.ids[off] = id
	}
	switch typ {
	case objTree:
		for _, e := range entries {
			s.links[e.id] = treeLink{parent: id, name: e.name}
		}
	case objCommit:
		if root, ok := headerObject(header, "tree ", s.hashLen); ok && len(s.commits) < scanMaxCommits {
			s.roots[root] = append(s.roots[root], id)
			s.commits = append(s.commits, id)
		}
	case objTag:
		if len(s.tags) < scanMaxTags {
			s.tags[id] = tagInfo{name: headerValue(header, "tag ")}
		}
	}
	s.endObject(id, true)
	return nil
}

// deltaObject scans a delta's inserted bytes.
func (s *packScanner) deltaObject(index uint32, typ int, size uint64, base string) error {
	s.beginObject(typ, base)
	s.nameRun = s.nameRun[:0]
	s.nameRunOn = false
	dp := deltaParser{
		onHeader: func(_, dst uint64) {
			s.nameRunOn = dst <= scanNameDeltaMax
		},
		onInsert: func(b []byte) {
			s.matchChunk(b)
			if s.nameRunOn && len(s.nameRun)+len(b) <= scanNameRunBytes {
				s.nameRun = append(s.nameRun, b...)
			}
		},
		onCopy: func() {
			// A copy ends the run of inserted bytes: what follows is not
			// contiguous with what came before it in the object git builds.
			s.ms.reset()
			s.flushShapes()
			s.win.reset()
			s.endNameRun()
		},
	}
	err := s.inflate(index, size, func(chunk []byte) error {
		if e := dp.feed(chunk); e != nil {
			return unreadable("object %d is a delta git would not apply: %v", index+1, e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if e := dp.finish(); e != nil {
		return unreadable("object %d is a delta git would not apply: %v", index+1, e)
	}
	s.flushShapes()
	s.endNameRun()
	s.endObject(objectID{}, false)
	return nil
}

// matchChunk scans one chunk of the current segment.
func (s *packScanner) matchChunk(chunk []byte) {
	if s.stopMatching {
		return
	}
	s.ms.write(chunk, s.onHit)
	if s.shapes {
		s.win.write(chunk, s.onShape)
	}
}

func (s *packScanner) onHit(pi int, end int64) bool {
	p := s.m.pats[pi]
	if s.cur.seen == nil {
		s.cur.seen = map[int]bool{}
	}
	if s.cur.seen[p.secret] {
		return true
	}
	s.cur.seen[p.secret] = true
	s.cur.findings = append(s.cur.findings, rawFinding{
		where: s.whereAt(end), typ: s.cur.typ, base: s.cur.base, secret: p.secret, form: p.form,
	})
	s.refuse()
	if len(s.findings)+len(s.cur.findings) >= maxPushScanFindings {
		s.stopMatching = true
		return false
	}
	return true
}

func (s *packScanner) onShape(label string) {
	if s.stopMatching {
		return
	}
	// One shape per object: detectors overlap — a token inside a "token:"
	// field is both — and the first, the most specific, says enough.
	if s.cur.shaped {
		return
	}
	s.cur.shaped = true
	s.cur.findings = append(s.cur.findings, rawFinding{
		where: s.whereAt(-1), typ: s.cur.typ, base: s.cur.base, secret: -1, shape: label,
	})
	s.refuse()
	if len(s.findings)+len(s.cur.findings) >= maxPushScanFindings {
		s.stopMatching = true
	}
}

// whereAt names the part of the current object a match ending at end lies in;
// end < 0 is unknown.
func (s *packScanner) whereAt(end int64) string {
	switch s.cur.typ {
	case objCommit, objTag:
		if end >= 0 && s.cur.headerEnd >= 0 && end > s.cur.headerEnd {
			return whereMessage
		}
		if end < 0 {
			return whereContent
		}
		return "headers"
	case objTree:
		return whereEntryName
	case objOfsDelta, objRefDelta:
		return whereInsert
	}
	return whereContent
}

func (s *packScanner) flushShapes() {
	if s.shapes {
		s.win.flush(s.onShape)
	}
}

// endObject files the current object's findings under its id.
func (s *packScanner) endObject(id objectID, hasID bool) {
	for _, f := range s.cur.findings {
		f.id, f.hasID = id, hasID
		s.addFinding(f)
	}
	s.cur = curObject{}
}

func (s *packScanner) addFinding(f rawFinding) {
	if len(s.findings) >= maxPushScanFindings {
		return
	}
	s.findings = append(s.findings, f)
	s.refuse()
	if len(s.findings) >= maxPushScanFindings {
		s.stopMatching = true
	}
}

// endNameRun reads tree entries out of the inserts just collected: a delta of
// a tree that gained an entry inserts the entry, its name included, and that
// is the only place the name of an object in a thin push is written down.
func (s *packScanner) endNameRun() {
	if len(s.nameRun) == 0 {
		return
	}
	scanTreeEntries(s.nameRun, s.hashLen, func(name string, raw []byte) {
		if len(s.names) >= scanMaxNames {
			return
		}
		var id objectID
		copy(id[:], raw)
		if _, ok := s.names[id]; !ok {
			s.names[id] = name
		}
	})
	s.nameRun = s.nameRun[:0]
}

// --- tree, commit and tag content ----------------------------------------------

type treeEntry struct {
	id   objectID
	name string
}

// treeParser reads "<mode> <name>\0<id>" entries from a tree's content as it
// streams. A tree it cannot read stops being parsed; its bytes are scanned all
// the same.
type treeParser struct {
	hashLen int
	pending []byte
	bad     bool
	onEntry func(treeEntry)
}

func (p *treeParser) feed(b []byte) {
	if p.bad {
		return
	}
	p.pending = append(p.pending, b...)
	for {
		nul := bytes.IndexByte(p.pending, 0)
		if nul < 0 {
			if len(p.pending) > scanMaxTreeEntry {
				p.bad = true
				p.pending = nil
			}
			return
		}
		if len(p.pending) < nul+1+p.hashLen {
			return
		}
		sp := bytes.IndexByte(p.pending[:nul], ' ')
		if sp <= 0 {
			p.bad = true
			p.pending = nil
			return
		}
		var e treeEntry
		e.name = string(p.pending[sp+1 : nul])
		copy(e.id[:], p.pending[nul+1:nul+1+p.hashLen])
		if p.onEntry != nil {
			p.onEntry(e)
		}
		p.pending = p.pending[nul+1+p.hashLen:]
	}
}

// treeModes are the modes git writes in a tree, as the bytes they start an
// entry with.
var treeModes = [][]byte{
	[]byte("100644 "), []byte("100755 "), []byte("120000 "),
	[]byte("40000 "), []byte("160000 "), []byte("100664 "),
}

// scanTreeEntries finds what look like tree entries in a fragment of bytes —
// a delta's inserts — and reports each name with the raw id after it. It is a
// heuristic for naming objects in a report and decides nothing.
func scanTreeEntries(b []byte, hashLen int, record func(name string, raw []byte)) {
	for start := 0; start < len(b); {
		nul := bytes.IndexByte(b[start:], 0)
		if nul < 0 {
			return
		}
		nul += start
		if nul+1+hashLen > len(b) {
			return
		}
		// The entry's mode: the closest known one before the NUL whose name
		// holds no NUL or slash.
		from := nul - 256
		if from < start {
			from = start
		}
		best := -1
		var bestMode []byte
		for _, mode := range treeModes {
			if i := bytes.LastIndex(b[from:nul], mode); i >= 0 && from+i > best {
				best = from + i
				bestMode = mode
			}
		}
		if best >= 0 {
			name := b[best+len(bestMode) : nul]
			if len(name) > 0 && bytes.IndexByte(name, '/') < 0 {
				record(string(name), b[nul+1:nul+1+hashLen])
			}
		}
		start = nul + 1
	}
}

// headerObject reads the object id after key ("tree ", "object ") in a
// commit's or tag's header block.
func headerObject(header []byte, key string, hashLen int) (objectID, bool) {
	v := headerValue(header, key)
	raw, err := hex.DecodeString(v)
	if err != nil || len(raw) != hashLen {
		return objectID{}, false
	}
	var id objectID
	copy(id[:], raw)
	return id, true
}

// headerValue returns the value of the first header line starting with key.
func headerValue(header []byte, key string) string {
	end := bytes.Index(header, []byte("\n\n"))
	if end < 0 {
		end = len(header)
	}
	for _, line := range strings.Split(string(header[:end]), "\n") {
		if v, ok := strings.CutPrefix(line, key); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// --- deltas ---------------------------------------------------------------------

// deltaParser reads a delta's instruction stream as it inflates, by
// patch_delta's rules: two size varints, then copy instructions (high bit set,
// offset and size bytes as the low bits say, a size of zero meaning 0x10000)
// and insert instructions (one to 127 literal bytes); opcode zero, a copy past
// the base's end, or an instruction writing past the result's declared size is
// a delta git refuses.
type deltaParser struct {
	onHeader func(src, dst uint64)
	onInsert func([]byte)
	onCopy   func()

	state      int
	varint     uint64
	shift      uint
	src, dst   uint64
	remaining  uint64
	cmd        byte
	argBit     uint
	cpOff      uint64
	cpSize     uint64
	insertLeft int
}

const (
	deltaSrcSize = iota
	deltaDstSize
	deltaCmd
	deltaCopyArgs
	deltaInsert
)

func (p *deltaParser) feed(b []byte) error {
	for len(b) > 0 {
		switch p.state {
		case deltaSrcSize, deltaDstSize:
			c := b[0]
			b = b[1:]
			if p.shift >= 64 {
				return errors.New("a size in its header overflows")
			}
			p.varint |= uint64(c&0x7f) << p.shift
			p.shift += 7
			if c&0x80 != 0 {
				continue
			}
			if p.state == deltaSrcSize {
				p.src = p.varint
				p.state = deltaDstSize
			} else {
				p.dst = p.varint
				p.remaining = p.dst
				p.state = deltaCmd
				if p.onHeader != nil {
					p.onHeader(p.src, p.dst)
				}
			}
			p.varint, p.shift = 0, 0
		case deltaCmd:
			c := b[0]
			b = b[1:]
			switch {
			case c&0x80 != 0:
				p.cmd, p.argBit, p.cpOff, p.cpSize = c, 0, 0, 0
				p.state = deltaCopyArgs
				// A copy whose bits ask for no bytes is complete now; one
				// that asks for some finishes as they arrive.
				if _, err := p.copyArgsFrom(nil); err != nil {
					return err
				}
			case c != 0:
				if uint64(c) > p.remaining {
					return errors.New("an insert writes past the size its header declares")
				}
				p.insertLeft = int(c)
				p.remaining -= uint64(c)
				p.state = deltaInsert
			default:
				return errors.New("opcode zero")
			}
		case deltaCopyArgs:
			n, err := p.copyArgsFrom(b)
			if err != nil {
				return err
			}
			b = b[n:]
		case deltaInsert:
			n := p.insertLeft
			if n > len(b) {
				n = len(b)
			}
			if p.onInsert != nil {
				p.onInsert(b[:n])
			}
			b = b[n:]
			p.insertLeft -= n
			if p.insertLeft == 0 {
				p.state = deltaCmd
			}
		}
	}
	return nil
}

// copyArgsFrom consumes the bytes the current copy's bits ask for, and returns
// how many it used.
func (p *deltaParser) copyArgsFrom(b []byte) (int, error) {
	used := 0
	for p.argBit < 7 {
		bit := byte(1) << p.argBit
		if p.cmd&bit == 0 {
			p.argBit++
			continue
		}
		if used == len(b) {
			return used, nil
		}
		v := uint64(b[used])
		used++
		if p.argBit < 4 {
			p.cpOff |= v << (8 * p.argBit)
		} else {
			p.cpSize |= v << (8 * (p.argBit - 4))
		}
		p.argBit++
	}
	if p.cpSize == 0 {
		p.cpSize = 0x10000
	}
	if p.cpOff+p.cpSize > p.src || p.cpOff+p.cpSize < p.cpOff {
		return used, errors.New("a copy reaches past the end of its base")
	}
	if p.cpSize > p.remaining {
		return used, errors.New("a copy writes past the size its header declares")
	}
	p.remaining -= p.cpSize
	p.state = deltaCmd
	if p.onCopy != nil {
		p.onCopy()
	}
	return used, nil
}

// finish checks the delta ended where an instruction did, having written the
// size it declared.
func (p *deltaParser) finish() error {
	switch {
	case p.state == deltaSrcSize || p.state == deltaDstSize:
		return errors.New("it ends inside its header")
	case p.state != deltaCmd:
		return errors.New("it ends inside an instruction")
	case p.remaining != 0:
		return fmt.Errorf("it writes %d bytes fewer than its header declares", p.remaining)
	}
	return nil
}

// --- shapes ---------------------------------------------------------------------

// shapeWindow runs pkg/redact's credential registry over a segment in
// overlapping windows: the registry matches whole strings, and a credential
// straddling two windows is inside the overlap of one of them.
type shapeWindow struct {
	on    bool
	buf   []byte
	fresh int
}

func (w *shapeWindow) reset() {
	w.buf = w.buf[:0]
	w.fresh = 0
}

func (w *shapeWindow) write(p []byte, hit func(label string)) {
	if !w.on {
		return
	}
	for len(p) > 0 {
		room := shapeWindowSize - len(w.buf)
		take := len(p)
		if take > room {
			take = room
		}
		w.buf = append(w.buf, p[:take]...)
		w.fresh += take
		p = p[take:]
		if len(w.buf) == shapeWindowSize {
			w.scan(hit)
			copy(w.buf, w.buf[len(w.buf)-shapeOverlap:])
			w.buf = w.buf[:shapeOverlap]
			w.fresh = 0
		}
	}
}

func (w *shapeWindow) flush(hit func(label string)) {
	if !w.on || w.fresh == 0 {
		return
	}
	w.scan(hit)
	w.fresh = 0
}

func (w *shapeWindow) scan(hit func(label string)) {
	for _, m := range redact.Find(string(w.buf)) {
		hit(m.Label)
	}
}

// --- the report -------------------------------------------------------------------

// report resolves the findings into what a refusal names.
func (s *packScanner) report() []ScanFinding {
	out := make([]ScanFinding, 0, len(s.findings))
	for _, f := range s.findings {
		sf := ScanFinding{Where: f.where, Form: f.form}
		if f.secret >= 0 {
			sec := s.m.secrets[f.secret]
			sf.Grant, sf.Secret, sf.Field = sec.Grant, sec.Secret, sec.Field
		} else {
			sf.Field = f.shape + " (recognised by its shape)"
		}
		switch f.where {
		case whereRef:
			sf.Ref = f.ref
		case wherePushOption:
		default:
			sf.Type = objTypeName(f.typ)
			if f.typ == objOfsDelta || f.typ == objRefDelta {
				sf.Base = f.base
			}
			if f.hasID {
				sf.Object = hex.EncodeToString(f.id[:s.hashLen])
				s.place(&sf, f)
			}
			if sf.Commit == "" && f.typ != objCommit && f.typ != objTag {
				if len(s.commits) == 1 {
					sf.Commit = hex.EncodeToString(s.commits[0][:s.hashLen])
				} else if len(s.tips) > 0 {
					sf.Ref = s.tips[0].Ref
				}
			}
		}
		// Nothing the report names may carry the value: a directory, a tag
		// or a branch can be named after it.
		sf.Path = s.scrub(sf.Path)
		sf.Tag = s.scrub(sf.Tag)
		sf.Ref = s.scrub(sf.Ref)
		out = append(out, sf)
	}
	return out
}

// place fills in where a whole object sits: its path and commit, or itself.
func (s *packScanner) place(sf *ScanFinding, f rawFinding) {
	switch f.typ {
	case objCommit:
		sf.Commit = sf.Object
		return
	case objTag:
		sf.Tag = s.tags[f.id].name
		return
	}
	var parts []string
	cur := f.id
	for depth := 0; depth < 256; depth++ {
		l, ok := s.links[cur]
		if !ok {
			break
		}
		parts = append(parts, l.name)
		cur = l.parent
	}
	commits := s.roots[cur]
	switch {
	case len(parts) > 0:
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		sf.Path = strings.Join(parts, "/")
		if len(commits) == 0 {
			// The walk stopped at a tree no commit in the pack names as its
			// root: a directory whose own tree arrived as a delta.
			if name, ok := s.names[cur]; ok {
				sf.Path = name + "/" + sf.Path
			}
			sf.Path = "…/" + sf.Path
			sf.PathPartial = true
		}
	default:
		if name, ok := s.names[f.id]; ok {
			sf.Path = name
			sf.PathPartial = true
		}
	}
	if len(commits) > 0 {
		sf.Commit = hex.EncodeToString(commits[0][:s.hashLen])
	}
}

// scrub takes the run's values, and in shapes mode credential shapes, out of a
// string the report is about to name — a name the pack chose, so it is also
// cut to a length a line can carry and kept to printable characters, since it
// reaches the sandbox's terminal and the dashboard.
func (s *packScanner) scrub(v string) string {
	if v == "" {
		return v
	}
	v = s.m.redact(v)
	if s.shapes {
		v = redact.Scrub(v)
	}
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, v)
	const maxName = 200
	if len(v) > maxName {
		cut := maxName
		for cut > 0 && !utf8.RuneStart(v[cut]) {
			cut--
		}
		v = v[:cut] + "…"
	}
	return v
}
