package hubca

// server.go serves one monitor's leaf to its listener and keeps it current.
//
// # Who replaces a leaf, and when
//
// The cluster leader, once less than RenewWithin of the leaf's life remains
// (Renew), so a sandbox sees the new leaf two days before the old one stops
// verifying. Every member re-reads the stored leaf every minute (Refresh) and
// starts serving whichever one the store holds; a member replaces it itself
// only when it is within EmergencyWithin of expiry — a leader that has been
// gone for two days — or when it does not carry a name this member's
// sandboxes reach it at. A process starting up (NewServer) applies the
// leader's rule, so a hub that was down for a while comes back with a leaf
// that has its whole life ahead of it.
//
// The same split holds when a rotation activates a new CA (Task 20438). The
// leader reissues the leaf from the new CA as soon as it sees the activation;
// a member keeps serving the old CA's leaf meanwhile — every sandbox
// dispatched since the stage trusts both — and replaces it itself only once
// the activation is ActivationGrace old and the leader still has not.
//
// A replacement never interrupts anything. The listener asks for its
// certificate per handshake (GetCertificate), so a connection already open —
// a push half-way through its pack — keeps the leaf it was handed, and the
// next connection gets the new one, which verifies against the same CA or,
// across an activation, against the other CA the sandbox trusts.
//
// # Names
//
// A replacement carries the names of the leaf it replaces as well as this
// member's own, up to MaxSANs, so two members whose sandboxes reach the hub by
// different names cannot take turns issuing a leaf that leaves the other's out.
// A CA with name constraints signs only the names they permit; a name they
// refuse is left out of the leaf and reported (Refused), and only a rotation
// to a CA that permits it can serve it.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// ActivationGrace is how long after an activation a member that is not the
// leader waits for the leader to reissue a leaf from the new CA before it
// does so itself.
const ActivationGrace = 3 * time.Minute

// Reasons a leaf is issued, on Issued.Reason and in the hub_ca.leaf_issued row.
const (
	ReasonFirst      = "first"      // no leaf was stored
	ReasonRenewal    = "renewal"    // the stored one was near the end of its life
	ReasonNames      = "names"      // it lacked a name sandboxes reach the monitor at
	ReasonActivation = "activation" // it came from a CA that no longer signs
	ReasonUnreadable = "unreadable" // it could not be read or did not verify
)

// ServerConfig describes one monitor's certificate.
type ServerConfig struct {
	Monitor Monitor
	Store   *Store
	Sealer  Sealer
	// Trust is the process's view of the control plane's CAs, which a
	// rotation changes under a running server. Authority instead pins one CA
	// for the server's life: a caller without a store.
	Trust     *Trust
	Authority *Authority
	// Want are the names the monitor's sandboxes reach it at: SANsFor.
	Want    []string
	Options Options
	// Logf receives one line per certificate issued. Nil discards them.
	Logf func(format string, args ...any)
}

// Server is one monitor's certificate, as its listener serves it.
type Server struct {
	cfg   ServerConfig
	trust *Trust
	mu    sync.Mutex
	cur   atomic.Pointer[Leaf]
	// refused is the last list of wanted names the active CA may not vouch
	// for, reported once per change.
	refused atomic.Pointer[[]string]
}

// NewServer settles the monitor's leaf — the stored one, or a new one when it
// is missing, near the end of its life, or misses a name — and returns a
// server for it.
func NewServer(cfg ServerConfig) (*Server, error) {
	if !cfg.Monitor.Valid() {
		return nil, fmt.Errorf("hubca: %q is not a monitor this hub issues for", cfg.Monitor)
	}
	if cfg.Store == nil || cfg.Sealer == nil || (cfg.Trust == nil && cfg.Authority == nil) {
		return nil, errors.New("hubca: a store, a sealer and the hub CA are required")
	}
	want, err := NormalizeSANs(cfg.Want)
	if err != nil {
		return nil, err
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("hubca: the %s has no name a sandbox reaches it at", cfg.Monitor.Label())
	}
	cfg.Want = want
	s := &Server{cfg: cfg, trust: cfg.Trust}
	if s.trust == nil {
		s.trust = StaticTrust(cfg.Authority)
	}
	if _, err := s.ensure(RenewWithin, true); err != nil {
		return nil, err
	}
	return s, nil
}

// GetCertificate is tls.Config.GetCertificate.
func (s *Server) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l := s.cur.Load()
	if l == nil {
		return nil, fmt.Errorf("hubca: the %s has no certificate", s.cfg.Monitor.Label())
	}
	return &l.pair, nil
}

// TLSConfig is the listener's configuration: the hub's TLS parameters around
// this server's certificate.
func (s *Server) TLSConfig(minVersion string) (*tls.Config, error) {
	return tlsconf.ServerConfigFor(s.GetCertificate, minVersion)
}

// Monitor names what this server's certificate is for.
func (s *Server) Monitor() Monitor { return s.cfg.Monitor }

// Want returns the names this member asked for.
func (s *Server) Want() []string { return append([]string(nil), s.cfg.Want...) }

// Refused returns the names this member wants that the active CA's name
// constraints do not permit: names its leaf does not carry.
func (s *Server) Refused() []string {
	if p := s.refused.Load(); p != nil {
		return append([]string(nil), (*p)...)
	}
	return nil
}

// Current returns the leaf being served.
func (s *Server) Current() *Leaf { return s.cur.Load() }

// Trust is the view of the CAs this server issues and judges leaves by.
func (s *Server) Trust() *Trust { return s.trust }

// CAPEM returns what sandboxes are told to trust: every CA the control plane
// currently trusts, the active one first. Public.
func (s *Server) CAPEM() []byte { return s.trust.Bundle() }

// Renew replaces the leaf when less than RenewWithin of its life remains, or
// when it was not issued by the active CA. It is the cluster leader's duty,
// and reports whether a leaf was issued.
func (s *Server) Renew() (bool, error) { return s.ensure(RenewWithin, true) }

// Refresh starts serving the leaf the store holds now, replacing it only when
// it is within EmergencyWithin of expiry, misses a name this member needs, or
// was issued by a CA that no longer signs and the leader has not replaced it
// within ActivationGrace. Every member runs it.
func (s *Server) Refresh() (bool, error) { return s.ensure(EmergencyWithin, false) }

// settleAttempts bounds how many times one ensure re-reads after another
// process replaced the leaf first.
const settleAttempts = 3

func (s *Server) ensure(margin time.Duration, leader bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The CAs first: a leaf judged against a CA another process has since
	// replaced would be reissued from the replaced one.
	_, _ = s.trust.Refresh()
	for attempt := 0; attempt < settleAttempts; attempt++ {
		now := s.cfg.Options.now()
		st := s.trust.State()
		ca := s.trust.Authority()
		if ca == nil {
			return false, errors.New("hubca: no hub CA is open to issue from")
		}
		want, refused := Permitted(ca.cert, s.cfg.Want)
		s.noteRefused(refused)
		if len(want) == 0 {
			return false, fmt.Errorf("hubca: the hub CA's name constraints permit none of the names the %s is "+
				"reached at (%s) — rotate the CA with `cloop hub ca rotate --stage --name %s`",
				s.cfg.Monitor.Label(), strings.Join(s.cfg.Want, ", "), s.cfg.Want[0])
		}
		stored, serial, err := loadLeaf(s.cfg.Store, s.cfg.Sealer, s.cfg.Monitor)
		if err != nil && serial == "" {
			return false, err
		}
		reason := ReasonFirst
		switch {
		case err != nil:
			reason = ReasonUnreadable
		case stored != nil:
			issuer := st.ByIssuer(stored.Cert)
			fromActive := issuer != nil && issuer.Serial == ca.Serial()
			switch {
			case issuer == nil && stored.usable(ca, nil, now, 0):
				// Signed by the CA this process has open but not by any CA the
				// store lists: a static trust (tests, a caller without a
				// store) or a view a moment behind. Judged as the active CA's.
				fromActive = true
			case issuer == nil:
				// Signed by a CA no longer trusted at all: a retired one.
				reason = ReasonActivation
			}
			acceptable := fromActive
			if !fromActive && issuer != nil && !leader && !s.activationOverdue(st, now) {
				// The previous CA's leaf, while the leader has yet to replace
				// it: every sandbox that could reach this member trusts both.
				acceptable = true
			}
			if acceptable && stored.usableUnder(issuer, ca, want, now, margin) {
				s.adopt(stored)
				return false, nil
			}
			switch {
			case reason == ReasonUnreadable:
			case !fromActive:
				reason = ReasonActivation
			case !Covers(stored.Cert, want):
				reason = ReasonNames
			default:
				reason = ReasonRenewal
			}
		}
		var have []string
		if err == nil && stored != nil && stored.usable(ca, nil, now, 0) {
			// Still valid under the active CA: keep the names it serves, as
			// far as the CA permits them.
			have, _ = Permitted(ca.cert, stored.SANs())
		}
		leaf, ok, ierr := issueLeaf(s.cfg.Store, s.cfg.Sealer, ca, s.cfg.Monitor, union(have, want), serial, reason, s.cfg.Options)
		if ierr != nil {
			return false, ierr
		}
		if ok {
			s.adopt(leaf)
			s.logf("hubca: issued the %s's certificate %s from the hub CA %s for %s, valid until %s (%s)",
				s.cfg.Monitor.Label(), shortSerial(leaf.Serial), shortSerial(ca.Serial()),
				strings.Join(leaf.SANs(), ", "), leaf.Cert.NotAfter.UTC().Format(time.RFC3339), reason)
			return true, nil
		}
		// Another process stored one first; read it back and judge it.
		_, _ = s.trust.Refresh()
	}
	// Serving what we have is better than serving nothing; the next refresh
	// tries again.
	if s.cur.Load() != nil {
		return false, nil
	}
	return false, fmt.Errorf("hubca: could not settle the %s's certificate: other hub processes kept replacing it",
		s.cfg.Monitor.Label())
}

// activationOverdue reports whether the activation the state records is
// older than ActivationGrace: the leader should have reissued by now.
func (s *Server) activationOverdue(st State, now time.Time) bool {
	r := st.Rotation
	if r == nil || r.ActivatedAt.IsZero() {
		// No record of when: an activation seen without one is old enough.
		return true
	}
	return now.Sub(r.ActivatedAt) > ActivationGrace
}

func (s *Server) noteRefused(refused []string) {
	prev := s.refused.Load()
	if prev != nil && strings.Join(*prev, ",") == strings.Join(refused, ",") {
		return
	}
	cp := append([]string(nil), refused...)
	s.refused.Store(&cp)
	if len(refused) > 0 {
		s.logf("hubca: the hub CA's name constraints do not permit %s, which the %s is reached at; its "+
			"certificate leaves them out, and sandboxes reaching it by them will refuse it — rotate the CA "+
			"with `cloop hub ca rotate --stage --name %s`", strings.Join(refused, ", "), s.cfg.Monitor.Label(),
			refused[0])
	}
}

func (s *Server) adopt(l *Leaf) {
	if prev := s.cur.Load(); prev != nil && prev.Serial == l.Serial {
		return
	}
	s.cur.Store(l)
}

func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

func shortSerial(serial string) string {
	if len(serial) > 12 {
		return serial[:12]
	}
	return serial
}

// usableUnder is usable judged against the CA that signed the leaf, issuer —
// the active one or, until the leader replaces the leaf, the previous one.
func (l *Leaf) usableUnder(issuer *CAInfo, active *Authority, want []string, now time.Time, margin time.Duration) bool {
	if issuer == nil || issuer.Serial == active.Serial() {
		return l.usable(active, want, now, margin)
	}
	if l == nil || l.Cert == nil {
		return false
	}
	if now.Before(l.Cert.NotBefore) || !now.Add(margin).Before(l.Cert.NotAfter) || !Covers(l.Cert, want) {
		return false
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer.Cert)
	_, err := l.Cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}
