package auditforward

// verify.go: what a receiver can prove about the rows it was sent.
//
// Every forwarded record carries its row_hash and prev_hash, so the stream a
// sink holds is the chain itself, checkable without the hub: each record must
// hash to its row_hash, and link by prev_hash to the record before it. The hash
// is SHA-256 over
//
//	"v1" TAB prev_hash TAB id TAB timestamp TAB actor TAB event_type TAB
//	entity_type TAB entity_id TAB payload
//
// with the timestamp exactly as the record writes it and the payload as the
// chain holds it: the record's payload field verbatim when that is JSON, or the
// string it holds when it is a JSON string (statedb.AuditChainLink computes it).
//
// Delivery is at-least-once, so a stream repeats rows — after a leader change,
// after a send whose acknowledgement was lost — and a repeat carries the same
// row_hash: it is counted, not reported. Two rows with one id and different
// hashes are not a repeat: that is the chain changing under the forwarder (a
// truncation the hub then wrote past, a restore, a rewrite), and it is the
// evidence the off-box copy exists for.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxStreamLine bounds one line of a received stream.
const maxStreamLine = 64 << 20

// streamRecord is one forwarded record, or a HEC envelope holding one.
type streamRecord struct {
	ID               int64           `json:"id"`
	Timestamp        string          `json:"timestamp"`
	Actor            string          `json:"actor"`
	EventType        string          `json:"event_type"`
	EntityType       string          `json:"entity_type"`
	EntityID         string          `json:"entity_id"`
	Payload          json.RawMessage `json:"payload"`
	PrevHash         string          `json:"prev_hash"`
	RowHash          string          `json:"row_hash"`
	PayloadTruncated bool            `json:"payload_truncated"`
	Source           string          `json:"source"`
	Dir              string          `json:"dir"`
	Hub              string          `json:"hub"`
	Event            json.RawMessage `json:"event"`
}

// IDRange is an inclusive run of ids.
type IDRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// ChainVerdict is what a received stream proves about one chain.
type ChainVerdict struct {
	Source string   `json:"source"`
	Dir    string   `json:"dir"`
	Hubs   []string `json:"hubs,omitempty"`

	FirstID int64 `json:"first_id"`
	LastID  int64 `json:"last_id"`
	// Rows counts distinct rows; Duplicates the records that repeated one.
	Rows       int `json:"rows"`
	Duplicates int `json:"duplicates"`

	// Gaps are ids between FirstID and LastID the stream does not hold.
	Gaps []IDRange `json:"gaps,omitempty"`
	// Forks are ids held with more than one row_hash.
	Forks []int64 `json:"forks,omitempty"`
	// BadHashes are records whose content does not hash to their row_hash.
	BadHashes []int64 `json:"bad_hashes,omitempty"`
	// BrokenLinks are records whose prev_hash is not the row_hash of the
	// record before them — or, for id 1, not genesis.
	BrokenLinks []int64 `json:"broken_links,omitempty"`
	// Unverified are records sent with their payload left out, whose hash
	// cannot be recomputed; their links are still checked.
	Unverified []int64 `json:"unverified,omitempty"`
}

// OK reports whether the chain arrived whole and unaltered.
func (v ChainVerdict) OK() bool {
	return len(v.Gaps) == 0 && len(v.Forks) == 0 && len(v.BadHashes) == 0 && len(v.BrokenLinks) == 0
}

// StreamReport is VerifyStream's result.
type StreamReport struct {
	Chains []ChainVerdict `json:"chains"`
	// Lines counts the lines read; Skipped those that held no record, and
	// Malformed those that started one and did not decode.
	Lines     int   `json:"lines"`
	Skipped   int   `json:"skipped"`
	Malformed []int `json:"malformed,omitempty"`
}

// OK reports whether every chain arrived whole and unaltered.
func (r StreamReport) OK() bool {
	for _, c := range r.Chains {
		if !c.OK() {
			return false
		}
	}
	return len(r.Malformed) == 0
}

type receivedRow struct {
	prev, hash string
	hashOK     bool
	truncated  bool
}

type chainAcc struct {
	source, dir string
	hubs        map[string]bool
	rows        map[int64][]receivedRow
	dups        int
}

// VerifyStream reads a received stream — one record per line: the JSON a
// file sink or an NDJSON collector holds, a HEC event, or a syslog line with
// the record after its header — and verifies every chain in it.
func VerifyStream(r io.Reader) (StreamReport, error) {
	var rep StreamReport
	chains := map[string]*chainAcc{}
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readStreamLine(br)
		if len(line) > 0 || err == nil {
			rep.Lines++
			if !consumeLine(line, rep.Lines, chains, &rep) {
				rep.Skipped++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return rep, fmt.Errorf("auditforward: read stream: %w", err)
		}
	}
	keys := make([]string, 0, len(chains))
	for k := range chains {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rep.Chains = append(rep.Chains, verdictFor(chains[k]))
	}
	return rep, nil
}

func readStreamLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > maxStreamLine {
			return nil, fmt.Errorf("a line is longer than %d bytes", maxStreamLine)
		}
		line = append(line, frag...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return bytes.TrimRight(line, "\r\n"), err
	}
}

// consumeLine files the record on one line, reporting whether it held one.
func consumeLine(line []byte, n int, chains map[string]*chainAcc, rep *StreamReport) bool {
	i := bytes.IndexByte(line, '{')
	if i < 0 {
		return false
	}
	var rec streamRecord
	if err := json.Unmarshal(bytes.TrimSpace(line[i:]), &rec); err != nil {
		if bytes.Contains(line, []byte(`"row_hash"`)) {
			rep.Malformed = append(rep.Malformed, n)
			return true
		}
		return false
	}
	if rec.RowHash == "" && len(rec.Event) > 0 {
		var inner streamRecord
		if err := json.Unmarshal(rec.Event, &inner); err != nil {
			rep.Malformed = append(rep.Malformed, n)
			return true
		}
		rec = inner
	}
	if rec.RowHash == "" {
		return false
	}
	key := rec.Source + "\x00" + rec.Dir
	acc := chains[key]
	if acc == nil {
		acc = &chainAcc{source: rec.Source, dir: rec.Dir, hubs: map[string]bool{}, rows: map[int64][]receivedRow{}}
		chains[key] = acc
	}
	if rec.Hub != "" {
		acc.hubs[rec.Hub] = true
	}
	for _, have := range acc.rows[rec.ID] {
		if have.hash == rec.RowHash {
			acc.dups++
			return true
		}
	}
	acc.rows[rec.ID] = append(acc.rows[rec.ID], receivedRow{
		prev: rec.PrevHash, hash: rec.RowHash, truncated: rec.PayloadTruncated,
		hashOK: !rec.PayloadTruncated && recordHashes(rec),
	})
	return true
}

// recordHashes recomputes a record's row_hash, reading its payload verbatim
// and then, when it is a JSON string, as the string it holds.
func recordHashes(rec streamRecord) bool {
	ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp)
	if err != nil {
		return false
	}
	// Field by field: a received record rebuilt to recompute its hash is not
	// an event emitted into a chain.
	var ev statedb.AuditEvent
	ev.ID, ev.Timestamp, ev.Actor = rec.ID, ts, rec.Actor
	ev.EventType, ev.EntityType, ev.EntityID = rec.EventType, rec.EntityType, rec.EntityID
	ev.Payload, ev.PrevHash, ev.RowHash = string(rec.Payload), rec.PrevHash, rec.RowHash
	if _, ok := statedb.AuditChainLink(ev); ok {
		return true
	}
	var unquoted string
	if len(rec.Payload) > 0 && rec.Payload[0] == '"' && json.Unmarshal(rec.Payload, &unquoted) == nil {
		ev.Payload = unquoted
		_, ok := statedb.AuditChainLink(ev)
		return ok
	}
	return false
}

func verdictFor(acc *chainAcc) ChainVerdict {
	v := ChainVerdict{Source: acc.source, Dir: acc.dir, Duplicates: acc.dups}
	for h := range acc.hubs {
		v.Hubs = append(v.Hubs, h)
	}
	sort.Strings(v.Hubs)
	ids := make([]int64, 0, len(acc.rows))
	for id, rows := range acc.rows {
		ids = append(ids, id)
		v.Rows += len(rows)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) == 0 {
		return v
	}
	v.FirstID, v.LastID = ids[0], ids[len(ids)-1]
	for i, id := range ids {
		rows := acc.rows[id]
		if len(rows) > 1 {
			v.Forks = append(v.Forks, id)
		}
		for _, r := range rows {
			switch {
			case r.truncated:
				v.Unverified = append(v.Unverified, id)
			case !r.hashOK:
				v.BadHashes = append(v.BadHashes, id)
			}
		}
		if i > 0 && ids[i-1] != id-1 {
			v.Gaps = append(v.Gaps, IDRange{From: ids[i-1] + 1, To: id - 1})
		}
		// Links are judged only where there is one row each side to judge
		// them by; a fork is reported as a fork.
		if len(rows) != 1 {
			continue
		}
		switch {
		case id == 1:
			if !strings.EqualFold(rows[0].prev, statedb.AuditGenesisHash) {
				v.BrokenLinks = append(v.BrokenLinks, id)
			}
		case i > 0 && ids[i-1] == id-1:
			prev := acc.rows[id-1]
			if len(prev) == 1 && prev[0].hash != rows[0].prev {
				v.BrokenLinks = append(v.BrokenLinks, id)
			}
		}
	}
	v.Unverified = dedupIDs(v.Unverified)
	v.BadHashes = dedupIDs(v.BadHashes)
	return v
}

func dedupIDs(ids []int64) []int64 {
	if len(ids) < 2 {
		return ids
	}
	out := ids[:1]
	for _, id := range ids[1:] {
		if id != out[len(out)-1] {
			out = append(out, id)
		}
	}
	return out
}
