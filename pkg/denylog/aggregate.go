package denylog

import (
	"net/netip"
	"sort"
	"time"
)

// aggregate.go counts one run's refusals, within a fixed budget.
//
// The budget is the point. A sandbox chooses every packet it sends, so a
// workload that wants to can send each one to a new address, port and
// protocol; an aggregate keyed by those grows by one entry per packet unless
// something stops it. MaxEntriesPerRun stops it: past the cap, the entry with
// the fewest packets — the longest-unseen of those — makes room, and its
// unreported packets are counted as unitemised. So a run that hits one blocked
// endpoint fourteen times keeps that line through any amount of spraying,
// while the spray itself becomes a number.
//
// Counts are reported as deltas and taken back if a report fails, so the
// accounting is exact across retries: every refusal observed is reported once,
// either on its entry or as unitemised.

// aggKey identifies one entry.
type aggKey struct {
	dst   netip.Addr
	port  uint16
	proto Proto
	rule  string
}

// aggEntry is one entry's state.
type aggEntry struct {
	count    uint64 // packets observed while the entry has existed
	reported uint64 // of those, reported or in flight
	first    time.Time
	last     time.Time
}

// aggregate is one run's refusals. Not safe for concurrent use; the monitor
// holds its lock.
type aggregate struct {
	entries    map[aggKey]*aggEntry
	unitemised uint64 // unreported refusals no entry holds
	max        int
}

func newAggregate(max int) *aggregate {
	if max <= 0 {
		max = MaxEntriesPerRun
	}
	return &aggregate{entries: make(map[aggKey]*aggEntry), max: max}
}

// add records one refusal.
func (a *aggregate) add(k aggKey, at time.Time) {
	if e := a.entries[k]; e != nil {
		e.count++
		if at.After(e.last) {
			e.last = at
		}
		if at.Before(e.first) {
			e.first = at
		}
		return
	}
	if len(a.entries) >= a.max {
		a.evict()
	}
	a.entries[k] = &aggEntry{count: 1, first: at, last: at}
}

// evict removes the entry seen least, keeping its unreported packets as a
// count. A linear scan: the table is at most a few dozen entries, and only a
// packet for a new key in a full table pays for it.
func (a *aggregate) evict() {
	var victim aggKey
	var v *aggEntry
	for k, e := range a.entries {
		if v == nil || e.count < v.count || e.count == v.count && e.last.Before(v.last) {
			victim, v = k, e
		}
	}
	if v == nil {
		return
	}
	a.unitemised += v.count - v.reported
	delete(a.entries, victim)
}

// take returns what has not been reported yet and marks it reported. A failed
// report is handed back with putBack.
func (a *aggregate) take() Batch {
	var b Batch
	for k, e := range a.entries {
		d := e.count - e.reported
		if d == 0 {
			continue
		}
		b.Entries = append(b.Entries, Entry{
			Dst: k.dst, Port: k.port, Proto: k.proto.String(), Rule: k.rule,
			Count: d, First: e.first, Last: e.last,
		})
		e.reported = e.count
	}
	b.Unitemised, a.unitemised = a.unitemised, 0
	// Deterministic order, most packets first: what a reader cut off at the
	// top of a list should keep.
	sort.Slice(b.Entries, func(i, j int) bool {
		x, y := b.Entries[i], b.Entries[j]
		if x.Count != y.Count {
			return x.Count > y.Count
		}
		return x.key() < y.key()
	})
	return b
}

// putBack undoes a take whose report did not arrive. An entry that made room
// for another in the meantime hands its share to the unitemised count, which
// is where take would have put it.
func (a *aggregate) putBack(b Batch) {
	for _, e := range b.Entries {
		k, ok := keyOf(e)
		if cur := a.entries[k]; ok && cur != nil && cur.reported >= e.Count {
			cur.reported -= e.Count
			continue
		}
		a.unitemised += e.Count
	}
	a.unitemised += b.Unitemised
}

// pending reports whether anything is waiting to be reported.
func (a *aggregate) pending() bool {
	if a.unitemised > 0 {
		return true
	}
	for _, e := range a.entries {
		if e.count > e.reported {
			return true
		}
	}
	return false
}

func keyOf(e Entry) (aggKey, bool) {
	p, ok := protoByName(e.Proto)
	if !ok {
		return aggKey{}, false
	}
	return aggKey{dst: e.Dst, port: e.Port, proto: p, rule: e.Rule}, true
}

// protoByName maps an entry's protocol back to its number. "other" maps to a
// number no named protocol has, which is all keyOf needs: an entry is keyed by
// the name it was reported under.
func protoByName(s string) (Proto, bool) {
	for _, p := range []Proto{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6, ProtoSCTP, ProtoUDPLite} {
		if p.String() == s {
			return p, true
		}
	}
	if s == "other" {
		return protoOther, true
	}
	return 0, false
}

// protoOther is how the aggregate keys every protocol an entry calls "other",
// so a run spraying 250 protocol numbers holds one entry, not 250.
const protoOther Proto = 255

// normalizeProto folds every unnamed protocol onto protoOther.
func normalizeProto(p Proto) Proto {
	if p.String() == "other" {
		return protoOther
	}
	return p
}
