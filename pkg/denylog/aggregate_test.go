package denylog

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func key(dst string, port uint16, rule string) aggKey {
	return aggKey{dst: netip.MustParseAddr(dst), port: port, proto: ProtoTCP, rule: rule}
}

func total(b Batch) uint64 { return b.Total() }

// TestAggregateCountsAndDeltas: repeated refusals are one entry with a count,
// and each report carries only what the last one did not.
func TestAggregateCountsAndDeltas(t *testing.T) {
	a := newAggregate(8)
	for i := 0; i < 14; i++ {
		a.add(key("203.0.113.7", 443, "default"), t0.Add(time.Duration(i)*time.Second))
	}
	a.add(key("10.0.0.5", 5432, "block:10.0.0.0/8"), t0)
	b := a.take()
	if len(b.Entries) != 2 || b.Entries[0].Count != 14 || b.Entries[0].Dst.String() != "203.0.113.7" {
		t.Fatalf("first report = %+v", b)
	}
	if e := b.Entries[0]; !e.First.Equal(t0) || !e.Last.Equal(t0.Add(13*time.Second)) {
		t.Errorf("first/last = %v/%v", e.First, e.Last)
	}
	if a.pending() {
		t.Error("pending after a take with nothing new")
	}
	if b := a.take(); !b.Empty() {
		t.Errorf("second report repeats the first: %+v", b)
	}
	a.add(key("203.0.113.7", 443, "default"), t0.Add(time.Minute))
	if b := a.take(); len(b.Entries) != 1 || b.Entries[0].Count != 1 || !b.Entries[0].First.Equal(t0) {
		t.Errorf("delta report = %+v", b)
	}
}

// TestAggregateCapsAHostileWorkload is the bound: a workload spraying new
// destinations cannot grow the table past its cap, every refusal is still
// counted exactly once (itemised or not), and a destination it keeps hitting
// survives the spray.
func TestAggregateCapsAHostileWorkload(t *testing.T) {
	const max = 16
	a := newAggregate(max)
	var observed, reported uint64
	heavy := key("203.0.113.7", 443, "default")
	for i := 0; i < 5; i++ {
		a.add(heavy, t0)
		observed++
	}
	for i := 0; i < 10000; i++ {
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], 0xc6336400+uint32(i))
		a.add(aggKey{dst: netip.AddrFrom4(ip), port: uint16(i), proto: ProtoUDP, rule: "default"}, t0.Add(time.Duration(i)))
		observed++
		if len(a.entries) > max {
			t.Fatalf("table grew to %d entries, cap %d", len(a.entries), max)
		}
		if i%997 == 0 {
			reported += total(a.take())
		}
	}
	b := a.take()
	reported += total(b)
	if reported != observed {
		t.Errorf("reported %d refusals of %d observed", reported, observed)
	}
	if a.entries[heavy] == nil {
		t.Error("the destination hit five times was evicted by ones hit once")
	}
	if len(b.Entries) > MaxEntriesPerRun {
		t.Errorf("a report of %d entries", len(b.Entries))
	}
}

// TestAggregatePutBackKeepsTheAccountExact: a report that never arrived is
// handed back, including for an entry that made room in the meantime.
func TestAggregatePutBackKeepsTheAccountExact(t *testing.T) {
	a := newAggregate(2)
	a.add(key("192.0.2.1", 1, "default"), t0)
	a.add(key("192.0.2.2", 2, "default"), t0)
	lost := a.take()                                           // never delivered
	a.add(key("192.0.2.3", 3, "default"), t0.Add(time.Second)) // evicts one of the first two
	a.putBack(lost)
	b := a.take()
	if got := total(b); got != 3 {
		t.Errorf("after put-back, %d refusals reported, want 3: %+v", got, b)
	}
	if !a.take().Empty() {
		t.Error("the put-back report was reported twice")
	}
}

// ─── the monitor, over a fake source ────────────────────────────────────────

// fakeSource feeds buffers to the monitor as the socket would.
type fakeSource struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeSource() *fakeSource {
	return &fakeSource{ch: make(chan []byte, 64), closed: make(chan struct{})}
}

func (f *fakeSource) read(buf []byte) (int, error) {
	select {
	case b := <-f.ch:
		return copy(buf, b), nil
	case <-time.After(20 * time.Millisecond):
		return 0, errRetry
	case <-f.closed:
		return 0, errors.New("closed")
	}
}
func (f *fakeSource) group() uint16 { return 27437 }
func (f *fakeSource) close() error  { f.once.Do(func() { close(f.closed) }); return nil }

// nflogMsg builds one NFLOG packet message as the kernel would.
func nflogMsg(prefix string, indev uint32, payload []byte) []byte {
	var attrs []byte
	add := func(typ uint16, v []byte) {
		n := nlaHdrLen + len(v)
		a := make([]byte, align4(n))
		binary.NativeEndian.PutUint16(a[0:2], uint16(n))
		binary.NativeEndian.PutUint16(a[2:4], typ)
		copy(a[4:], v)
		attrs = append(attrs, a...)
	}
	add(nfulaPacketHdr, []byte{0x08, 0x00, 2, 0})
	add(nfulaIfindexIn, binary.BigEndian.AppendUint32(nil, indev))
	add(nfulaPrefix, append([]byte(prefix), 0))
	add(nfulaPayload, payload)
	body := append([]byte{2, 0, 0x6b, 0x2d}, attrs...) // AF_INET, v0, group 27437
	msg := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(msg[4:6], nfnlSubsysLog<<8|nfulnlMsgPacket)
	return append(msg, body...)
}

func tcpPacket(src, dst string, port uint16) []byte {
	b := ipv4(6, 20, 0, ports(port))
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	return b
}

type sinkRec struct {
	mu   sync.Mutex
	got  []Batch
	runs []Run
	fail bool
}

func (s *sinkRec) sink(r Run, b Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("link down")
	}
	s.got = append(s.got, b)
	s.runs = append(s.runs, r)
	return nil
}

func (s *sinkRec) snapshot() []Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Batch(nil), s.got...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func withFastFlush(t *testing.T) {
	t.Helper()
	pf, ps, pl := FlushInterval, settle, linger
	FlushInterval, settle, linger = 20*time.Millisecond, 30*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { FlushInterval, settle, linger = pf, ps, pl })
}

// TestMonitorAttributesByBridgeAndSource: a packet belongs to the run whose
// sandbox has its source address on the bridge it arrived from — not to a run
// with the same address on another bridge — and one that arrives before its
// run is tracked is held for it.
func TestMonitorAttributesByBridgeAndSource(t *testing.T) {
	withFastFlush(t)
	src := newFakeSource()
	rec := &sinkRec{}
	m := newMonitor(src, rec.sink, nil)
	defer m.Close()

	// Early: the container sent before the driver read its address back.
	src.ch <- nflogMsg("cloop:0123456789ab:default", 7, tcpPacket("172.20.0.2", "203.0.113.7", 443))
	waitFor(t, "the early packet", func() bool { return m.Stats().Packets == 1 })
	if err := m.Track(Run{ID: "h1", Executor: "ex"}, "0123456789ab", 7, []netip.Addr{netip.MustParseAddr("172.20.0.2")}); err != nil {
		t.Fatal(err)
	}
	// Same address on another bridge: another sandbox's.
	if err := m.Track(Run{ID: "h2", Executor: "ex"}, "fedcba987654", 9, []netip.Addr{netip.MustParseAddr("172.20.0.2")}); err != nil {
		t.Fatal(err)
	}
	src.ch <- append(nflogMsg("cloop:0123456789ab:deny:203.0.113.0/24", 7, tcpPacket("172.20.0.2", "203.0.113.9", 22)),
		nflogMsg("cloop:fedcba987654:default", 9, tcpPacket("172.20.0.2", "198.51.100.1", 80))...)
	// Foreign and malformed lines are counted and dropped.
	src.ch <- nflogMsg("ulogd: something else", 7, tcpPacket("172.20.0.2", "198.51.100.1", 80))
	src.ch <- nflogMsg("cloop:0123456789ab:default", 7, []byte{0x45, 0})

	waitFor(t, "both runs' reports", func() bool {
		got := map[string]uint64{}
		rec.mu.Lock()
		for i, b := range rec.got {
			got[rec.runs[i].ID] += b.Total()
		}
		rec.mu.Unlock()
		return got["h1"] == 2 && got["h2"] == 1
	})
	st := m.Stats()
	if st.Foreign != 1 || st.Malformed != 1 {
		t.Errorf("stats = %+v", st)
	}
	for i, b := range rec.snapshot() {
		if r := rec.runs[i]; r.ID == "h2" && (b.Fingerprint != "fedcba987654" || b.Entries[0].Dst.String() != "198.51.100.1") {
			t.Errorf("h2's report = %+v", b)
		}
	}
}

// TestFlushFinalWaitsForTheKernelAndForgets: the final report comes after the
// lines still queued, carries Final, and the run is gone afterwards; a final
// report that fails is kept for the next attempt.
func TestFlushFinalWaitsForTheKernelAndForgets(t *testing.T) {
	withFastFlush(t)
	src := newFakeSource()
	rec := &sinkRec{}
	m := newMonitor(src, rec.sink, nil)
	defer m.Close()
	addr := []netip.Addr{netip.MustParseAddr("172.20.0.3")}
	if err := m.Track(Run{ID: "h3"}, "0123456789ab", 7, addr); err != nil {
		t.Fatal(err)
	}
	m.Release("h3")
	// A line the kernel still held when the sandbox exited: attributed
	// during linger.
	src.ch <- nflogMsg("cloop:0123456789ab:default", 7, tcpPacket("172.20.0.3", "203.0.113.7", 443))
	waitFor(t, "the late line", func() bool { return m.Stats().Packets == 1 })

	rec.mu.Lock()
	rec.fail = true
	rec.mu.Unlock()
	if err := m.FlushFinal(context.Background(), "h3"); err == nil {
		t.Fatal("a final report that failed reported success")
	}
	if !m.Tracked("h3") {
		t.Fatal("a run whose final report failed was forgotten")
	}
	rec.mu.Lock()
	rec.fail = false
	rec.mu.Unlock()
	if err := m.FlushFinal(context.Background(), "h3"); err != nil {
		t.Fatal(err)
	}
	if m.Tracked("h3") {
		t.Error("the run was kept after its final report")
	}
	var final *Batch
	var sum uint64
	for _, b := range rec.snapshot() {
		sum += b.Total()
		if b.Final {
			b := b
			final = &b
		}
	}
	if final == nil || sum != 1 {
		t.Errorf("reports %+v: want one refusal in all and a final one", rec.snapshot())
	}
	if err := m.FlushFinal(context.Background(), "h3"); err != nil {
		t.Errorf("FlushFinal of a forgotten run: %v", err)
	}
}

// TestMonitorBoundsUnclaimedAndRuns: packets nobody claims are bounded and
// expire; the run table is bounded.
func TestMonitorBoundsUnclaimedAndRuns(t *testing.T) {
	withFastFlush(t)
	src := newFakeSource()
	m := newMonitor(src, (&sinkRec{}).sink, nil)
	defer m.Close()
	var buf []byte
	for i := 0; i < maxPending+50; i++ {
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], 0x0a000000+uint32(i))
		buf = append(buf, nflogMsg("cloop:0123456789ab:default", 3, tcpPacket(netip.AddrFrom4(ip).String(), "203.0.113.7", 1))...)
	}
	src.ch <- buf
	waitFor(t, "the spray", func() bool { return m.Stats().Packets == maxPending+50 })
	m.mu.Lock()
	n := len(m.pending)
	m.mu.Unlock()
	if n > maxPending {
		t.Errorf("%d unclaimed packets held, cap %d", n, maxPending)
	}
	if st := m.Stats(); st.Unattributed < 50 {
		t.Errorf("the overflow was not counted: %+v", st)
	}

	for i := 0; i < MaxRuns; i++ {
		if err := m.Track(Run{ID: "r" + string(rune(i))}, "", 1, []netip.Addr{netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if err := m.Track(Run{ID: "one-too-many"}, "", 1, []netip.Addr{netip.MustParseAddr("10.2.0.1")}); err == nil {
		t.Error("tracked a run past MaxRuns")
	}
}

func TestBatchValidate(t *testing.T) {
	ok := Entry{Dst: netip.MustParseAddr("203.0.113.7"), Port: 443, Proto: "tcp", Rule: "default", Count: 3, First: t0, Last: t0}
	if err := (Batch{Fingerprint: "0123456789ab", Entries: []Entry{ok}}).Validate(); err != nil {
		t.Fatalf("a good batch: %v", err)
	}
	mut := func(f func(*Entry)) Batch { e := ok; f(&e); return Batch{Entries: []Entry{e}} }
	bad := map[string]Batch{
		"fingerprint":     {Fingerprint: "XYZ"},
		"zone":            mut(func(e *Entry) { e.Dst = netip.MustParseAddr("fe80::1%eth0") }),
		"mapped":          mut(func(e *Entry) { e.Dst = netip.MustParseAddr("::ffff:1.2.3.4") }),
		"invalid dst":     mut(func(e *Entry) { e.Dst = netip.Addr{} }),
		"proto":           mut(func(e *Entry) { e.Proto = "tcp<script>" }),
		"port on icmp":    mut(func(e *Entry) { e.Proto = "icmp" }),
		"rule":            mut(func(e *Entry) { e.Rule = "allow:1.1.1.1/32" }),
		"rule spelling":   mut(func(e *Entry) { e.Rule = "deny:203.0.113.7/24" }),
		"zero count":      mut(func(e *Entry) { e.Count = 0 }),
		"huge count":      mut(func(e *Entry) { e.Count = 1 << 50 }),
		"backwards":       mut(func(e *Entry) { e.Last = t0.Add(-time.Second) }),
		"no time":         mut(func(e *Entry) { e.First = time.Time{} }),
		"duplicate":       {Entries: []Entry{ok, ok}},
		"too many":        {Entries: make([]Entry, MaxEntriesPerRun+1)},
		"huge unitemised": {Unitemised: 1 << 50},
	}
	for name, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	e := ok
	e.First, e.Last = t0.Add(-time.Hour), t0.Add(time.Hour)
	e.Clamp(t0.Add(-time.Minute), t0)
	if !e.First.Equal(t0.Add(-time.Minute)) || !e.Last.Equal(t0) {
		t.Errorf("Clamp = %v..%v", e.First, e.Last)
	}
	if got := ok.Describe(); got != "203.0.113.7:443/tcp" {
		t.Errorf("Describe = %q", got)
	}
	v6 := Entry{Dst: netip.MustParseAddr("2001:db8::7"), Port: 443, Proto: "tcp"}
	if got := v6.Describe(); got != "[2001:db8::7]:443/tcp" {
		t.Errorf("Describe = %q", got)
	}
	icmp := Entry{Dst: netip.MustParseAddr("203.0.113.7"), Proto: "icmp"}
	if got := icmp.Describe(); got != "203.0.113.7/icmp" {
		t.Errorf("Describe = %q", got)
	}
}

// TestABridgeClaimsWhatNoAddressDoes: a sandbox that exited before its
// address could be read is tracked by its bridge alone, and gets that
// bridge's unattributed refusals — only while it is the one run there.
func TestABridgeClaimsWhatNoAddressDoes(t *testing.T) {
	withFastFlush(t)
	src := newFakeSource()
	rec := &sinkRec{}
	m := newMonitor(src, rec.sink, nil)
	defer m.Close()

	// Logged before the driver had anything to say about the sandbox.
	src.ch <- nflogMsg("cloop:0123456789ab:default", 11, tcpPacket("172.30.0.2", "203.0.113.7", 443))
	waitFor(t, "the early packet", func() bool { return m.Stats().Packets == 1 })
	if err := m.Track(Run{ID: "short"}, "0123456789ab", 11, nil); err != nil {
		t.Fatal(err)
	}
	m.Release("short")
	if err := m.FlushFinal(context.Background(), "short"); err != nil {
		t.Fatal(err)
	}
	var got uint64
	for _, b := range rec.snapshot() {
		got += b.Total()
	}
	if got != 1 {
		t.Fatalf("the bridge's only run got %d refusals, want its 1", got)
	}

	// Two runs on one bridge, one known only by the bridge: a packet from an
	// address neither claims is nobody's provably.
	if err := m.Track(Run{ID: "known"}, "", 12, []netip.Addr{netip.MustParseAddr("172.31.0.2")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Track(Run{ID: "wide"}, "", 12, nil); err != nil {
		t.Fatal(err)
	}
	src.ch <- nflogMsg("cloop:0123456789ab:default", 12, tcpPacket("172.31.0.9", "203.0.113.7", 443))
	src.ch <- nflogMsg("cloop:0123456789ab:default", 12, tcpPacket("172.31.0.2", "203.0.113.7", 443))
	reported := func(id string) bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		for _, r := range rec.runs {
			if r.ID == id {
				return true
			}
		}
		return false
	}
	// The flush loop reports what is attributed; the known address's packet
	// is, by the time its report arrives both packets have been read.
	waitFor(t, "the known run's report", func() bool { return reported("known") })
	waitFor(t, "both packets", func() bool { return m.Stats().Packets == 3 })
	m.mu.Lock()
	wide, held := m.runs["wide"].agg.pending(), len(m.pending)
	m.mu.Unlock()
	if wide || reported("wide") || held != 1 {
		t.Errorf("wide claimed=%v reported=%v held=%d: the unknown source must stay unattributed",
			wide, reported("wide"), held)
	}
}
