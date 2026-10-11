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
// A replacement never interrupts anything. The listener asks for its
// certificate per handshake (GetCertificate), so a connection already open —
// a push half-way through its pack — keeps the leaf it was handed, and the
// next connection gets the new one, which verifies against the same CA.
//
// # Names
//
// A replacement carries the names of the leaf it replaces as well as this
// member's own, up to MaxSANs, so two members whose sandboxes reach the hub by
// different names cannot take turns issuing a leaf that leaves the other's out.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// ServerConfig describes one monitor's certificate.
type ServerConfig struct {
	Monitor   Monitor
	Store     *Store
	Sealer    Sealer
	Authority *Authority
	// Want are the names the monitor's sandboxes reach it at: SANsFor.
	Want    []string
	Options Options
	// Logf receives one line per certificate issued. Nil discards them.
	Logf func(format string, args ...any)
}

// Server is one monitor's certificate, as its listener serves it.
type Server struct {
	cfg ServerConfig
	mu  sync.Mutex
	cur atomic.Pointer[Leaf]
}

// NewServer settles the monitor's leaf — the stored one, or a new one when it
// is missing, near the end of its life, or misses a name — and returns a
// server for it.
func NewServer(cfg ServerConfig) (*Server, error) {
	if !cfg.Monitor.Valid() {
		return nil, fmt.Errorf("hubca: %q is not a monitor this hub issues for", cfg.Monitor)
	}
	if cfg.Store == nil || cfg.Sealer == nil || cfg.Authority == nil {
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
	s := &Server{cfg: cfg}
	if _, err := s.ensure(RenewWithin); err != nil {
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

// Current returns the leaf being served.
func (s *Server) Current() *Leaf { return s.cur.Load() }

// CAPEM returns the CA certificate sandboxes are told to trust. Public.
func (s *Server) CAPEM() []byte { return s.cfg.Authority.CertPEM() }

// Renew replaces the leaf when less than RenewWithin of its life remains. It
// is the cluster leader's duty, and reports whether a leaf was issued.
func (s *Server) Renew() (bool, error) { return s.ensure(RenewWithin) }

// Refresh starts serving the leaf the store holds now, replacing it only when
// it is within EmergencyWithin of expiry or misses a name this member needs.
// Every member runs it.
func (s *Server) Refresh() (bool, error) { return s.ensure(EmergencyWithin) }

// settleAttempts bounds how many times one ensure re-reads after another
// process replaced the leaf first.
const settleAttempts = 3

func (s *Server) ensure(margin time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ca := s.cfg.Authority
	for attempt := 0; attempt < settleAttempts; attempt++ {
		now := s.cfg.Options.now()
		stored, serial, err := loadLeaf(s.cfg.Store, s.cfg.Sealer, s.cfg.Monitor)
		if err != nil && serial == "" {
			return false, err
		}
		if err == nil && stored.usable(ca, s.cfg.Want, now, margin) {
			s.adopt(stored)
			return false, nil
		}
		var have []string
		if err == nil && stored != nil && stored.usable(ca, nil, now, 0) {
			// Still valid under this CA: keep the names it serves.
			have = stored.SANs()
		}
		leaf, ok, ierr := issueLeaf(s.cfg.Store, s.cfg.Sealer, ca, s.cfg.Monitor, union(have, s.cfg.Want), serial, s.cfg.Options)
		if ierr != nil {
			return false, ierr
		}
		if ok {
			s.adopt(leaf)
			s.logf("hubca: issued the %s's certificate %s for %s, valid until %s",
				s.cfg.Monitor.Label(), shortSerial(leaf.Serial), strings.Join(leaf.SANs(), ", "),
				leaf.Cert.NotAfter.UTC().Format(time.RFC3339))
			return true, nil
		}
		// Another process stored one first; read it back and judge it.
	}
	// Serving what we have is better than serving nothing; the next refresh
	// tries again.
	if s.cur.Load() != nil {
		return false, nil
	}
	return false, fmt.Errorf("hubca: could not settle the %s's certificate: other hub processes kept replacing it",
		s.cfg.Monitor.Label())
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
