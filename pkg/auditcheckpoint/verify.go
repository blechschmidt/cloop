package auditcheckpoint

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Result is what one record says about the chain it names.
type Result string

const (
	// ResultConsistent: the chain still holds the row the record saw.
	ResultConsistent Result = "consistent"
	// ResultPruned: the row was removed by a prune (Task 20218), and the
	// archive its anchor sealed holds it as the record saw it.
	ResultPruned Result = "pruned"
	// ResultPrunedUnverified: a prune anchor covers the row, but its archive
	// cannot be read here (moved to cold storage, say) to confirm it.
	ResultPrunedUnverified Result = "pruned-unverified"
	// ResultTruncated: the chain ends before the row the record saw, and
	// nothing has been appended since — its tail was deleted.
	ResultTruncated Result = "truncated"
	// ResultRestored: the chain no longer has the row the record saw, and
	// has been written to since — the database was restored from a backup
	// taken before the record (or rewound and appended to).
	ResultRestored Result = "restored"
	// ResultRewritten: the chain holds a different row under the id the
	// record saw, timestamped no later than the record — history was
	// rewritten and re-hashed.
	ResultRewritten Result = "rewritten"
	// ResultDeleted: the row is missing from inside the chain's range.
	ResultDeleted Result = "deleted"
	// ResultAnchorMissing: the record saw a prune anchor the database no
	// longer has.
	ResultAnchorMissing Result = "anchor-missing"
	// ResultAnchorRewritten: the anchor the record saw has been altered.
	ResultAnchorRewritten Result = "anchor-rewritten"
	// ResultArchiveMismatch: the archive a prune anchor sealed no longer
	// matches the digest the anchor recorded, or is not the intact chain the
	// anchor's boundary says it ends in.
	ResultArchiveMismatch Result = "archive-mismatch"
	// ResultPruneUnproven: a prune anchor covers the row, no trusted
	// checkpoint ever saw that anchor, and its archive cannot be read here.
	// Rows deleted and an anchor written over them look exactly like this, so
	// it fails until the archive is checked.
	ResultPruneUnproven Result = "prune-unproven"
	// ResultRefused: the record's seal does not verify; it was not used.
	ResultRefused Result = "refused"
)

// Failing reports whether the result is a finding against the chain (or, for
// ResultRefused, against the checkpoint file).
func (r Result) Failing() bool {
	switch r {
	case ResultConsistent, ResultPruned, ResultPrunedUnverified:
		return false
	}
	return true
}

// Checked is one record and its verdict.
type Checked struct {
	Located
	Seal   SealStatus
	Result Result
	Detail string
}

// ChainReport is a chain checked against its records.
type ChainReport struct {
	Path  string
	Chain string

	// Records counts what was checked, by seal and by result.
	Records          int
	Valid            int
	Unsigned         int
	Unchecked        int
	ForeignKey       int
	Refused          int
	Consistent       int
	Pruned           int
	PrunedUnverified int

	// Newest is the newest record used; nil when none was.
	Newest *Checked
	// Failures lists every failing record, oldest first.
	Failures []Checked
	// Finding names what the earliest failure means for the chain, in one
	// sentence; "" when there is none. Hint adds the reading it cannot rule
	// out, where there is one.
	Finding string
	Hint    string
}

// OK reports whether no record found anything against the chain.
func (r ChainReport) OK() bool { return len(r.Failures) == 0 }

// VerifyChain checks db's audit chain against recs, the records that name it,
// sealed under key (nil when this process has no CLOOP_SECRET_KEY).
//
// Each record is judged on its own and the earliest failure is named, because
// it is where history first stops agreeing with what was seen. A record with a
// bad seal is refused rather than judged — it would otherwise be a way to make
// the chain look like something it is not. Records sealed under another key,
// or that cannot be checked here, are still judged for what they say against
// the chain: their seal is not what makes a head they saw wrong. But only a
// trusted record — sealed under the key when there is one — vouches for
// anything, which matters for prunes: see checkArchive.
func VerifyChain(db *statedb.DB, path, chain string, recs []Located, key *Key) (ChainReport, error) {
	rep := ChainReport{Path: path, Chain: chain}
	recs = append([]Located(nil), recs...)
	sortRecords(recs)

	v := &verifier{db: db, key: key}
	if err := v.load(); err != nil {
		return rep, err
	}

	checked := make([]Checked, 0, len(recs))
	pruned := map[int64][]int{} // anchor id -> indexes into checked
	for _, r := range recs {
		c := Checked{Located: r, Seal: Check(r.Record, key)}
		rep.Records++
		switch c.Seal {
		case SealValid:
			rep.Valid++
		case SealUnsigned:
			rep.Unsigned++
		case SealUnchecked:
			rep.Unchecked++
		case SealForeignKey:
			rep.ForeignKey++
		case SealBad:
			rep.Refused++
			c.Result = ResultRefused
			c.Detail = fmt.Sprintf("the record on line %d claims key %s and its seal does not verify under it: "+
				"the checkpoint file was edited, or the record forged", r.Line, orDash(r.KeyFingerprint))
			checked = append(checked, c)
			continue
		}
		anchor, err := v.judge(&c)
		if err != nil {
			return rep, err
		}
		if c.Result == ResultPruned {
			pruned[anchor.ID] = append(pruned[anchor.ID], len(checked))
		}
		checked = append(checked, c)
	}

	vouched := v.vouchedAnchors(checked)
	for id, idx := range pruned {
		a := v.byID[id]
		checkArchive(a, v.boundaryBefore(a), vouched[id], checked, idx)
	}

	for i := range checked {
		c := checked[i]
		switch c.Result {
		case ResultConsistent:
			rep.Consistent++
		case ResultPruned:
			rep.Pruned++
		case ResultPrunedUnverified:
			rep.PrunedUnverified++
		}
		if c.Result != ResultRefused {
			cc := c
			rep.Newest = &cc
		}
		if c.Result.Failing() {
			rep.Failures = append(rep.Failures, c)
		}
	}
	rep.Finding, rep.Hint = name(rep, checked, v.head)
	return rep, nil
}

// verifier is one chain's state, read once and re-read at most once.
type verifier struct {
	db        *statedb.DB
	key       *Key
	head      statedb.AuditHead
	anchors   []statedb.AuditAnchor
	byID      map[int64]statedb.AuditAnchor
	refreshed bool
}

func (v *verifier) load() error {
	head, err := v.db.AuditHead()
	if err != nil {
		return err
	}
	anchors, err := v.db.ListAuditAnchors()
	if err != nil {
		return err
	}
	v.head, v.anchors = head, anchors
	v.byID = make(map[int64]statedb.AuditAnchor, len(anchors))
	for _, a := range anchors {
		v.byID[a.ID] = a
	}
	return nil
}

// refresh re-reads the head and anchors once. A prune that commits while the
// records are being judged removes rows the first read did not know were
// going; reading again before calling a row deleted keeps a concurrent
// `cloop hub audit prune` from reading as tampering.
func (v *verifier) refresh() (bool, error) {
	if v.refreshed {
		return false, nil
	}
	v.refreshed = true
	return true, v.load()
}

// trusted reports whether a record may vouch for something, not merely be
// judged: sealed under the key when there is one, not refused when there is
// none.
func (v *verifier) trusted(s SealStatus) bool {
	if v.key != nil {
		return s == SealValid
	}
	return s != SealBad
}

// judge decides what one record says. It returns the anchor covering the row
// when the verdict is ResultPruned, for the archive check that follows.
func (v *verifier) judge(c *Checked) (statedb.AuditAnchor, error) {
	r := c.Record
	at := FormatTime(r.At())

	if r.AnchorID > 0 {
		a, ok := v.byID[r.AnchorID]
		switch {
		case !ok:
			c.Result = ResultAnchorMissing
			c.Detail = fmt.Sprintf("the checkpoint at %s saw prune anchor #%d (through id %d), which the database "+
				"no longer holds: it was restored from a backup older than that, or its anchors were deleted",
				at, r.AnchorID, r.AnchorThroughID)
			return statedb.AuditAnchor{}, nil
		case !sameHash(a.AnchorHash, r.AnchorHash):
			c.Result = ResultAnchorRewritten
			c.Detail = fmt.Sprintf("prune anchor #%d is not the one the checkpoint at %s saw "+
				"(anchor hash %s then, %s now)", r.AnchorID, at, short(r.AnchorHash), short(a.AnchorHash))
			return statedb.AuditAnchor{}, nil
		}
	}

	if r.LastID <= 0 {
		c.Result = ResultConsistent
		c.Detail = "the chain was empty"
		return statedb.AuditAnchor{}, nil
	}

	row, found, err := v.db.AuditRowAt(r.LastID)
	if err != nil {
		return statedb.AuditAnchor{}, err
	}
	switch {
	case found && sameHash(row.RowHash, r.LastRowHash):
		c.Result = ResultConsistent
		c.Detail = fmt.Sprintf("the chain holds id %d as the checkpoint at %s saw it", r.LastID, at)
		return statedb.AuditAnchor{}, nil
	case found && row.Timestamp.After(r.At()):
		c.Result = ResultRestored
		c.Detail = fmt.Sprintf("id %d now names a row written at %s, after the checkpoint at %s saw a different one there",
			r.LastID, FormatTime(row.Timestamp), at)
		return statedb.AuditAnchor{}, nil
	case found:
		c.Result = ResultRewritten
		c.Detail = fmt.Sprintf("row %d no longer matches the checkpoint at %s (it saw hash %s, the chain holds %s)",
			r.LastID, at, short(r.LastRowHash), short(row.RowHash))
		return statedb.AuditAnchor{}, nil
	}

	if a, ok := covering(v.anchors, r.LastID); ok {
		c.Result = ResultPruned
		c.Detail = fmt.Sprintf("id %d was pruned under anchor #%d", r.LastID, a.ID)
		return a, nil
	}
	if again, err := v.refresh(); err != nil {
		return statedb.AuditAnchor{}, err
	} else if again {
		return v.judge(c)
	}
	switch {
	case r.LastID > v.head.LastID && v.head.LastTimestamp.After(r.At()):
		c.Result = ResultRestored
		c.Detail = fmt.Sprintf("the chain ends at id %d, before the id %d the checkpoint at %s saw, "+
			"and its newest row was written at %s, after that checkpoint",
			v.head.LastID, r.LastID, at, FormatTime(v.head.LastTimestamp))
	case r.LastID > v.head.LastID:
		c.Result = ResultTruncated
		c.Detail = fmt.Sprintf("the chain ends at id %d, before the id %d the checkpoint at %s saw",
			v.head.LastID, r.LastID, at)
	default:
		c.Result = ResultDeleted
		c.Detail = fmt.Sprintf("row %d, which the checkpoint at %s saw, is missing from the chain", r.LastID, at)
	}
	return statedb.AuditAnchor{}, nil
}

// vouchedAnchors are the prune anchors a trusted checkpoint records the hub
// having verified: their archive read, re-hashed into the chain the anchor ends
// in, by the hub itself, before the archive went anywhere. That a sealed record
// merely saw an anchor proves nothing — the hub seals whatever anchor is newest
// in its database, and whoever deleted rows could have put it there.
func (v *verifier) vouchedAnchors(checked []Checked) map[int64]bool {
	out := map[int64]bool{}
	for _, c := range checked {
		if c.Result == ResultRefused || !v.trusted(c.Seal) || c.AnchorID <= 0 || !c.AnchorVerified {
			continue
		}
		if a, ok := v.byID[c.AnchorID]; ok && sameHash(a.AnchorHash, c.AnchorHash) {
			out[a.ID] = true
		}
	}
	return out
}

// boundaryBefore is the hash the first row a's archive holds must link to:
// the previous anchor's boundary, or genesis for the first.
func (v *verifier) boundaryBefore(a statedb.AuditAnchor) string { return boundaryBefore(v.anchors, a) }

func boundaryBefore(anchors []statedb.AuditAnchor, a statedb.AuditAnchor) string {
	prev := statedb.AuditGenesisHash
	for _, b := range anchors {
		if b.PrunedThroughID < a.PrunedThroughID {
			prev = b.BoundaryHash
		}
	}
	return prev
}

// VerifyAnchor reads the archive anchor a sealed and reports why it is not the
// intact chain a describes — unreadable, not matching its digest, or rows that
// do not re-hash and link from the boundary before it (anchors is every anchor
// the chain holds) to a's own. The checkpoint writer calls it once per new
// anchor and records the answer under its seal.
func VerifyAnchor(anchors []statedb.AuditAnchor, a statedb.AuditAnchor) error {
	_, digest, chainErr, err := readArchive(a, boundaryBefore(anchors, a), nil)
	switch {
	case err != nil:
		return err
	case !sameHash(digest, a.ExportSHA256):
		return fmt.Errorf("archive %s does not match the anchor's digest (sha256 %s, file %s)",
			a.ExportPath, short(a.ExportSHA256), short(digest))
	case chainErr != nil:
		return fmt.Errorf("archive %s is not the chain anchor #%d ends in: %w", a.ExportPath, a.ID, chainErr)
	}
	return nil
}

// covering returns the anchor whose pruned range holds id.
func covering(anchors []statedb.AuditAnchor, id int64) (statedb.AuditAnchor, bool) {
	for _, a := range anchors {
		if id >= a.PrunedFirstID && id <= a.PrunedThroughID {
			return a, true
		}
	}
	return statedb.AuditAnchor{}, false
}

// checkArchive confirms that the archive anchor a sealed still holds the rows
// the records at idx saw.
//
// The archive must match the digest the anchor recorded, and must itself be
// the intact chain the anchor describes: every row re-hashed, linked from prev
// (the boundary before it) to the anchor's own boundary. An anchor lives in the
// database, so whoever can delete rows can write one, with a digest of
// whatever file they like; only a file that re-hashes into the real chain —
// one that still holds the history — makes a prune a prune.
//
// An archive that cannot be read here (moved to cold storage) is accepted as
// unverified only if a trusted checkpoint vouched for the anchor. Otherwise
// nothing outside the database says the prune ever happened, and it fails.
func checkArchive(a statedb.AuditAnchor, prev string, vouched bool, checked []Checked, idx []int) {
	want := map[int64]bool{}
	for _, i := range idx {
		want[checked[i].LastID] = true
	}
	hashes, digest, chainErr, err := readArchive(a, prev, want)
	if err != nil {
		for _, i := range idx {
			c := &checked[i]
			if vouched {
				c.Result = ResultPrunedUnverified
				c.Detail = fmt.Sprintf("id %d was pruned under anchor #%d, whose archive a checkpoint records the hub "+
					"verifying; %s cannot be read here now: %v", c.LastID, a.ID, a.ExportPath, err)
				continue
			}
			c.Result = ResultPruneUnproven
			c.Detail = fmt.Sprintf("id %d, which the checkpoint at %s saw, is covered by prune anchor #%d, whose "+
				"archive no trusted checkpoint records the hub verifying, and %s cannot be read here (%v): a prune "+
				"nothing outside the database vouches for cannot be told from rows deleted and an anchor written over them",
				c.LastID, FormatTime(c.At()), a.ID, a.ExportPath, err)
		}
		return
	}
	if !sameHash(digest, a.ExportSHA256) || chainErr != nil {
		why := fmt.Sprintf("does not match the digest the anchor recorded (sha256 %s, file %s)",
			short(a.ExportSHA256), short(digest))
		if chainErr == nil {
			// digest mismatch: the reason above stands
		} else if sameHash(digest, a.ExportSHA256) {
			why = "matches the anchor's digest but is not the chain the anchor's boundary ends in: " + chainErr.Error()
		}
		for _, i := range idx {
			checked[i].Result = ResultArchiveMismatch
			checked[i].Detail = fmt.Sprintf("the archive anchor #%d sealed (%s) %s", a.ID, a.ExportPath, why)
		}
		return
	}
	for _, i := range idx {
		c := &checked[i]
		got, ok := hashes[c.LastID]
		switch {
		case !ok:
			c.Result = ResultRewritten
			c.Detail = fmt.Sprintf("the archive anchor #%d sealed does not hold row %d, which the checkpoint at %s saw",
				a.ID, c.LastID, FormatTime(c.At()))
		case !sameHash(got, c.LastRowHash):
			c.Result = ResultRewritten
			c.Detail = fmt.Sprintf("the archive anchor #%d sealed holds a different row %d than the checkpoint at %s saw "+
				"(hash %s then, %s sealed)", a.ID, c.LastID, FormatTime(c.At()), short(c.LastRowHash), short(got))
		default:
			c.Detail = fmt.Sprintf("id %d was pruned under anchor #%d, and its archive holds it as the checkpoint at %s saw it",
				c.LastID, a.ID, FormatTime(c.At()))
		}
	}
}

// maxArchiveLine bounds one row of an archive: a task.upsert payload carries
// a task description, never a step's output.
const maxArchiveLine = 64 << 20

// archiveRow is one line of the JSONL pkg/auditretention seals.
type archiveRow struct {
	ID         int64           `json:"id"`
	Timestamp  string          `json:"timestamp"`
	Actor      string          `json:"actor"`
	EventType  string          `json:"event_type"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	Payload    json.RawMessage `json:"payload"`
	PrevHash   string          `json:"prev_hash"`
	RowHash    string          `json:"row_hash"`
}

// readArchive streams the archive anchor a sealed: its digest, the row hashes
// of the ids in want, and chainErr when its rows are not the chain from prev
// to the anchor's boundary. err means it could not be read at all. Only a
// regular file is read — the path comes from the database, and /dev/zero or a
// FIFO must not be a way to hang or exhaust a verifier — and it is streamed,
// never held in memory whole.
func readArchive(a statedb.AuditAnchor, prev string, want map[int64]bool) (hashes map[int64]string, digest string, chainErr, err error) {
	if a.ExportPath == "" {
		return nil, "", nil, errors.New("the anchor records no archive path")
	}
	// The kernel's own filesystems hold files that report as regular and block
	// a reader forever (/proc/kmsg, tracefs's trace_pipe); no archive lives
	// there, and no sealed archive is empty.
	clean := filepath.Clean(a.ExportPath)
	for _, special := range []string{"/proc", "/sys", "/dev"} {
		if clean == special || strings.HasPrefix(clean, special+"/") {
			return nil, "", nil, fmt.Errorf("%s is not a regular file", a.ExportPath)
		}
	}
	fi, err := os.Stat(a.ExportPath)
	if err != nil {
		return nil, "", nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, "", nil, fmt.Errorf("%s is not a regular file", a.ExportPath)
	}
	if fi.Size() == 0 {
		return nil, "", nil, fmt.Errorf("%s is empty", a.ExportPath)
	}
	f, err := os.Open(a.ExportPath)
	if err != nil {
		return nil, "", nil, err
	}
	defer f.Close()

	h := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(f, h), 64<<10)
	var body io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			chainErr = fmt.Errorf("not a readable gzip stream: %w", gerr)
		} else {
			defer gz.Close()
			body = gz
		}
	}

	hashes = map[int64]string{}
	if chainErr == nil {
		chainErr = walkArchive(body, a, prev, want, hashes)
	}
	// The digest covers the file as written, so the rest of it is read through
	// the hash whether or not its rows made sense.
	if _, err := io.Copy(io.Discard, br); err != nil {
		return nil, "", nil, err
	}
	return hashes, hex.EncodeToString(h.Sum(nil)), chainErr, nil
}

// walkArchive checks the archive's rows are the chain from prev through the
// anchor's boundary, collecting the hashes of the ids in want.
func walkArchive(body io.Reader, a statedb.AuditAnchor, prev string, want map[int64]bool, hashes map[int64]string) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), maxArchiveLine)
	next, link := a.PrunedFirstID, prev
	var last string
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row archiveRow
		if err := json.Unmarshal(line, &row); err != nil {
			return fmt.Errorf("row after id %d does not decode: %v", next-1, err)
		}
		if row.ID != next {
			return fmt.Errorf("expected id %d, found %d", next, row.ID)
		}
		if !sameHash(row.PrevHash, link) {
			return fmt.Errorf("row %d does not link to the row before it", row.ID)
		}
		if !archiveRowHashes(row) {
			return fmt.Errorf("row %d does not hash to the row_hash it carries", row.ID)
		}
		if want[row.ID] && hashes != nil {
			hashes[row.ID] = row.RowHash
		}
		next, link, last = row.ID+1, row.RowHash, row.RowHash
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading rows: %v", err)
	}
	if next-1 != a.PrunedThroughID || !sameHash(last, a.BoundaryHash) {
		return fmt.Errorf("it ends at id %d, not at the anchor's boundary %d", next-1, a.PrunedThroughID)
	}
	return nil
}

// archiveRowHashes recomputes a sealed row's hash. The export writes a
// payload verbatim when it is JSON and quoted when it is not, so both
// readings are tried.
func archiveRowHashes(row archiveRow) bool {
	ts, err := time.Parse(time.RFC3339Nano, row.Timestamp)
	if err != nil {
		return false
	}
	// Filled in field by field: this is a sealed row read back to recompute
	// its hash, never an event emitted into a chain, and an AuditEvent
	// literal is what tests/arch reads as an emission site.
	var ev statedb.AuditEvent
	ev.ID, ev.Timestamp, ev.Actor = row.ID, ts, row.Actor
	ev.EventType, ev.EntityType, ev.EntityID = row.EventType, row.EntityType, row.EntityID
	ev.Payload, ev.PrevHash, ev.RowHash = string(row.Payload), row.PrevHash, row.RowHash
	if _, ok := statedb.AuditChainLink(ev); ok {
		return true
	}
	var unquoted string
	if len(row.Payload) > 0 && row.Payload[0] == '"' && json.Unmarshal(row.Payload, &unquoted) == nil {
		ev.Payload = unquoted
		_, ok := statedb.AuditChainLink(ev)
		return ok
	}
	return false
}

// name turns the earliest failure into the sentence the report leads with.
func name(rep ChainReport, checked []Checked, head statedb.AuditHead) (string, string) {
	if len(rep.Failures) == 0 {
		return "", ""
	}
	first := rep.Failures[0]
	r := first.Record
	at := FormatTime(r.At())

	// The newest record before the failure that the chain still agrees with:
	// where a restored backup's history and the real one part.
	var agreed *Checked
	for i := range checked {
		c := checked[i]
		if c.Line == first.Line && c.Path == first.Path {
			break
		}
		if !c.Result.Failing() && c.At().Before(first.At()) && c.LastID > 0 {
			cc := c
			agreed = &cc
		}
	}

	switch first.Result {
	case ResultTruncated:
		return fmt.Sprintf("tail truncated after id %d although a checkpoint at %s saw id %d",
				head.LastID, at, r.LastID),
			"the database was restored from a backup taken before then, and nothing has been written since"
	case ResultRestored, ResultAnchorMissing:
		msg := fmt.Sprintf("the database was restored from a backup older than %s", at)
		if agreed != nil {
			msg += fmt.Sprintf(": it still agrees with the checkpoint at %s (id %d), and has been written to since",
				FormatTime(agreed.At()), agreed.LastID)
		}
		hint := "its tail was deleted while the hub kept writing; either way, history after that point was replaced"
		if first.Result == ResultAnchorMissing {
			hint = first.Detail
		}
		return msg, hint
	case ResultRewritten:
		return first.Detail, "the chain verifies only because every hash after the change was recomputed"
	case ResultRefused:
		return fmt.Sprintf("checkpoint refused: %s", first.Detail), ""
	}
	return first.Detail, ""
}

// sameHash compares two hex hashes. Neither is secret — they are public row
// and archive hashes — so this is an ordinary comparison under a name that
// says what it compares.
func sameHash(a, b string) bool { return a == b }

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Newest returns the newest record in recs, by time.
func Newest(recs []Located) (Located, bool) {
	if len(recs) == 0 {
		return Located{}, false
	}
	sorted := append([]Located(nil), recs...)
	sortRecords(sorted)
	return sorted[len(sorted)-1], true
}

// Paths lists the distinct database paths recs name, sorted.
func Paths(recs []Located) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range recs {
		if !seen[r.Path] {
			seen[r.Path] = true
			out = append(out, r.Path)
		}
	}
	sort.Strings(out)
	return out
}

// maxFutureSkew is how far ahead of the verifier's clock a record may be
// dated and still count.
const maxFutureSkew = 5 * time.Minute

// Usable returns the records that may vouch for anything — that checkpoints
// are being written, that the chain agrees with them: sealed under key when
// there is one, any that is not refused when there is none, and none dated
// more than a few minutes after now. Anybody able to append to the file can
// add a record; under a key, only the hub can add one that counts.
func Usable(recs []Located, key *Key, now time.Time) []Located {
	var out []Located
	for _, r := range recs {
		seal := Check(r.Record, key)
		if seal == SealBad || (key != nil && seal != SealValid) {
			continue
		}
		if at := r.At(); at.IsZero() || at.After(now.Add(maxFutureSkew)) {
			continue
		}
		out = append(out, r)
	}
	sortRecords(out)
	return out
}

// Age is how long ago the newest of recs was written, relative to now.
func Age(recs []Located, now time.Time) (time.Duration, bool) {
	n, ok := Newest(recs)
	if !ok || n.At().IsZero() {
		return 0, false
	}
	return now.Sub(n.At()), true
}
