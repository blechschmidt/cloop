package hubca

// trust.go is what a hub process knows about the control plane's CAs (Task
// 20438): which one it signs leaves with, and which ones it tells a sandbox to
// trust.
//
// Before rotation there was one CA, opened once and kept for the process's
// life. Now there can be two — the active CA and either the one staged to
// replace it or the one it replaced — and which is which changes under a
// running hub, by a step another process took. So a process holds a Trust and
// re-reads it (Refresh): every minute, and as soon as the cluster bus says a
// step was taken. The CAs and their certificates are read from hub_tls; only
// the active CA's key is opened, and only when the active CA changed.

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Slot names one of the CA rows.
type Slot string

const (
	// SlotActive is the CA leaves are issued from.
	SlotActive Slot = "active"
	// SlotNext is a CA staged to replace it.
	SlotNext Slot = "next"
	// SlotPrevious is the CA an activation replaced, trusted until retired.
	SlotPrevious Slot = "previous"
)

// Phase is where the control plane is in a rotation.
type Phase string

const (
	// PhaseNone: no CA has been minted — tls: auto has never run here.
	PhaseNone Phase = "none"
	// PhaseSteady: one CA, which signs and which sandboxes trust.
	PhaseSteady Phase = "steady"
	// PhaseStaged: a second CA is staged. Sandboxes dispatched from now on
	// trust both; leaves still come from the first.
	PhaseStaged Phase = "staged"
	// PhaseActivated: leaves come from the new CA; the one it replaced is
	// still trusted, until it is retired.
	PhaseActivated Phase = "activated"
)

// CAInfo is one CA as anybody may read it: the certificate, never the key.
type CAInfo struct {
	Slot        Slot      `json:"slot"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	// Names are the names the CA's X.509 name constraints permit; empty for a
	// CA without constraints, which may vouch for any name.
	Names    []string          `json:"names,omitempty"`
	IssuedAt time.Time         `json:"issued_at,omitzero"`
	IssuedBy string            `json:"issued_by,omitempty"`
	Cert     *x509.Certificate `json:"-"`
	PEM      []byte            `json:"-"`
}

func caInfo(slot Slot, row statedb.HubTLSRow) (*CAInfo, error) {
	cert, err := ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("hubca: the %s hub CA's certificate: %w", slot, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("hubca: the %s hub CA's certificate is not a CA certificate", slot)
	}
	return &CAInfo{
		Slot: slot, Serial: strings.ToLower(row.Serial), Fingerprint: certFingerprint(cert),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Names: ConstraintNames(cert),
		IssuedAt: row.IssuedAt, IssuedBy: row.IssuedBy, Cert: cert, PEM: []byte(row.CertPEM),
	}, nil
}

// State is the control plane's CAs and the rotation under way, read without
// opening a key.
type State struct {
	Active   *CAInfo `json:"active,omitempty"`
	Next     *CAInfo `json:"next,omitempty"`
	Previous *CAInfo `json:"previous,omitempty"`
	// Rotation is the rotation under way, nil when there is none.
	Rotation *statedb.HubCARotationRow `json:"-"`
}

// Phase says where the control plane is in a rotation.
func (s State) Phase() Phase {
	switch {
	case s.Active == nil:
		return PhaseNone
	case s.Next != nil:
		return PhaseStaged
	case s.Previous != nil:
		return PhaseActivated
	}
	return PhaseSteady
}

// Trusted lists the CAs a sandbox dispatched now is told to trust, the active
// one first.
func (s State) Trusted() []*CAInfo {
	var out []*CAInfo
	for _, c := range []*CAInfo{s.Active, s.Next, s.Previous} {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// Bundle is the PEM of every trusted CA, the active one first: what git's
// sslCAInfo, a kubeconfig's certificate-authority-data and Node's
// NODE_EXTRA_CA_CERTS are given. Public.
func (s State) Bundle() []byte {
	var b bytes.Buffer
	for _, c := range s.Trusted() {
		b.Write(bytes.TrimSpace(c.PEM))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Serials are the trusted CAs' serials, the active one first.
func (s State) Serials() []string {
	var out []string
	for _, c := range s.Trusted() {
		out = append(out, c.Serial)
	}
	return out
}

// Generation identifies this set of CAs and which of them signs: it changes
// with every step of a rotation and with nothing else.
func (s State) Generation() string {
	if s.Active == nil {
		return ""
	}
	parts := []string{"active=" + s.Active.Serial}
	if s.Next != nil {
		parts = append(parts, "next="+s.Next.Serial)
	}
	if s.Previous != nil {
		parts = append(parts, "previous="+s.Previous.Serial)
	}
	return strings.Join(parts, ",")
}

// ByIssuer returns the trusted CA whose key signed cert, or nil.
func (s State) ByIssuer(cert *x509.Certificate) *CAInfo {
	if cert == nil {
		return nil
	}
	for _, c := range s.Trusted() {
		if cert.CheckSignatureFrom(c.Cert) == nil {
			return c
		}
	}
	return nil
}

// ReadState reads the CAs and the rotation under way. A control plane that
// has never minted a CA reads as PhaseNone, not as an error.
func ReadState(s *Store) (State, error) {
	if s == nil {
		return State{}, errors.New("hubca: no store")
	}
	rows, err := s.db.ListHubTLS()
	if err != nil {
		return State{}, err
	}
	var st State
	for _, row := range rows {
		if row.Kind != "ca" {
			continue
		}
		var slot Slot
		switch row.ID {
		case statedb.HubCAActive:
			slot = SlotActive
		case statedb.HubCANext:
			slot = SlotNext
		case statedb.HubCAPrevious:
			slot = SlotPrevious
		default:
			continue
		}
		info, err := caInfo(slot, row)
		if err != nil {
			return State{}, err
		}
		switch slot {
		case SlotActive:
			st.Active = info
		case SlotNext:
			st.Next = info
		case SlotPrevious:
			st.Previous = info
		}
	}
	rot, ok, err := s.db.CurrentHubCARotation()
	if err != nil {
		return State{}, err
	}
	if ok {
		st.Rotation = &rot
	}
	return st, nil
}

// Trust is a hub process's view of the control plane's CAs: the State it last
// read, and the active CA opened for signing. Safe for concurrent use.
type Trust struct {
	store  *Store
	sealer Sealer
	opts   Options

	mu  sync.Mutex // serialises Refresh
	cur atomic.Pointer[trustView]
}

type trustView struct {
	state     State
	authority *Authority
	adoptedAt time.Time
}

// OpenTrust opens the control plane's CAs, minting the first one when no hub
// process has yet (OpenAuthority).
func OpenTrust(s *Store, sealer Sealer, o Options) (*Trust, error) {
	if _, err := OpenAuthority(s, sealer, o); err != nil {
		return nil, err
	}
	t := &Trust{store: s, sealer: sealer, opts: o}
	if _, err := t.Refresh(); err != nil {
		return nil, err
	}
	return t, nil
}

// StaticTrust is a Trust over one opened CA and nothing else, never refreshed:
// for a caller that holds an Authority rather than a store.
func StaticTrust(a *Authority) *Trust {
	t := &Trust{}
	info := &CAInfo{Slot: SlotActive, Serial: a.Serial(), Fingerprint: certFingerprint(a.cert),
		NotBefore: a.cert.NotBefore, NotAfter: a.cert.NotAfter, Names: ConstraintNames(a.cert),
		Cert: a.cert, PEM: a.CertPEM()}
	t.cur.Store(&trustView{state: State{Active: info}, authority: a})
	return t
}

// Refresh re-reads the CAs, opening the active one's key when it changed, and
// reports whether anything a sandbox would be told changed. On an error the
// view it had is kept: a hub that cannot read its database keeps serving what
// it served.
func (t *Trust) Refresh() (bool, error) {
	if t.store == nil {
		return false, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st, err := ReadState(t.store)
	if err != nil {
		return false, err
	}
	if st.Active == nil {
		return false, fmt.Errorf("hubca: the control plane holds no active hub CA")
	}
	now := t.opts.now()
	prev := t.cur.Load()
	auth := (*Authority)(nil)
	if prev != nil && prev.authority != nil && prev.authority.Serial() == st.Active.Serial {
		auth = prev.authority
	} else {
		row, err := t.store.db.GetHubTLS(statedb.HubCAActive)
		if err != nil {
			return false, fmt.Errorf("hubca: read the active hub CA: %w", err)
		}
		if strings.ToLower(row.Serial) != st.Active.Serial {
			// A step landed between the two reads; the next refresh sees it whole.
			return false, fmt.Errorf("%w: the active hub CA changed while it was being opened", statedb.ErrHubCARotationConflict)
		}
		if auth, err = openAuthorityRow(t.sealer, row, now); err != nil {
			return false, err
		}
	}
	changed := prev == nil || prev.state.Generation() != st.Generation()
	adopted := now
	if !changed {
		adopted = prev.adoptedAt
	}
	t.cur.Store(&trustView{state: st, authority: auth, adoptedAt: adopted})
	return changed, nil
}

func (t *Trust) view() *trustView {
	if t == nil {
		return nil
	}
	return t.cur.Load()
}

// Authority is the CA leaves are issued from.
func (t *Trust) Authority() *Authority {
	if v := t.view(); v != nil {
		return v.authority
	}
	return nil
}

// State is the CAs as last read.
func (t *Trust) State() State {
	if v := t.view(); v != nil {
		return v.state
	}
	return State{}
}

// Bundle is the PEM a sandbox dispatched now is told to trust.
func (t *Trust) Bundle() []byte { return t.State().Bundle() }

// Serials are the serials of the CAs in Bundle, the active one first.
func (t *Trust) Serials() []string { return t.State().Serials() }

// AdoptedAt is when this process started handing out the current bundle.
func (t *Trust) AdoptedAt() time.Time {
	if v := t.view(); v != nil {
		return v.adoptedAt
	}
	return time.Time{}
}

// Snapshot is the trust one dispatch is given: read once, so every path that
// hands a sandbox the hub's CA — git, a kubeconfig, Node — hands it the same
// set, and the dispatch can record which.
type Snapshot struct {
	Bundle  []byte
	Serials []string
}

// Snapshot reads the current bundle and serials together.
func (t *Trust) Snapshot() Snapshot {
	st := t.State()
	return Snapshot{Bundle: st.Bundle(), Serials: st.Serials()}
}

// ActiveOnly is the bundle reduced to the active CA: what a receiver that
// cannot hold two is given (an agent before protocol v25 placing a bundle
// for Node, Task 20438).
func (s Snapshot) ActiveOnly() Snapshot {
	if len(s.Serials) <= 1 {
		return s
	}
	return Snapshot{Bundle: FirstPEM(s.Bundle), Serials: s.Serials[:1]}
}

// Trusts reports whether the snapshot holds the CA with serial.
func (s Snapshot) Trusts(serial string) bool {
	for _, x := range s.Serials {
		if x == strings.ToLower(serial) {
			return true
		}
	}
	return false
}

// Label renders serials the way a dispatch records them
// (executor.LabelHubCATrust): sorted, comma-separated.
func Label(serials []string) string {
	out := append([]string(nil), serials...)
	for i := range out {
		out[i] = strings.ToLower(strings.TrimSpace(out[i]))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// ParseLabel reads a recorded trust label back.
func ParseLabel(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Report records what this process signs with, hands out and serves, under
// its cluster member id: what a rotation's step reads to tell whether every
// member has caught up (statedb.HubCAMemberRow). servers are the process's
// monitor certificates; a nil one is skipped.
func (t *Trust) Report(instanceID string, servers ...*Server) error {
	if t == nil || t.store == nil || strings.TrimSpace(instanceID) == "" {
		return nil
	}
	st := t.State()
	if st.Active == nil {
		return nil
	}
	leaves := map[string]statedb.HubCALeafAck{}
	for _, s := range servers {
		if s == nil {
			continue
		}
		l := s.Current()
		if l == nil {
			continue
		}
		ack := statedb.HubCALeafAck{Serial: l.Serial, NotAfter: l.Cert.NotAfter}
		if ca := st.ByIssuer(l.Cert); ca != nil {
			ack.Issuer = ca.Serial
		}
		leaves[string(s.Monitor())] = ack
	}
	return t.store.db.PutHubCAMember(statedb.HubCAMemberRow{
		InstanceID: instanceID, Active: st.Active.Serial, Trusts: st.Serials(), Leaves: leaves,
		AdoptedAt: t.AdoptedAt(), SeenAt: t.opts.now(),
	})
}

// Withdraw removes this process's report: it runs no monitor under tls: auto
// any more, so a rotation has nothing of it to wait for.
func (t *Trust) Withdraw(instanceID string) error {
	if t == nil || t.store == nil || strings.TrimSpace(instanceID) == "" {
		return nil
	}
	return t.store.db.DeleteHubCAMember(instanceID)
}
