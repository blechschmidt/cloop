package ui

// The hub's key-management service, while it serves (Task 20433).
//
// `cloop ui` resolves secrets.kms at startup — refusing to start on a KMS it
// cannot reach — and pins the roots it resolved for every keyring the process
// opens (secretbroker.PinRoots). What is left for the serving hub is to keep
// an eye on the KMS:
//
//   - Every member polls its KMS's status, every minute while it is healthy
//     and every ten seconds while it is not, as kube-apiserver polls a KMS v2
//     plugin. Each poll is a call, so cloop_kms_requests_total and the latency
//     histogram record the KMS's health continuously, not only when a key is
//     opened — which, with keys held in memory, may be once a process. A
//     member whose KMS becomes unreachable keeps serving the keys it holds,
//     and says so in its log, once per change.
//   - The cluster leader follows a rotation of the KMS key: when the key the
//     KMS reports differs from the one a live key-encryption key was wrapped
//     under, it rewraps that key in place (secretbroker.Keyring.RewrapKMS) and
//     records sealing_key.kms_rewrapped. One member, so a rotation is followed
//     once; the rewrap is a compare-and-swap, so a leader change mid-way does
//     no harm either.
//   - The leader also scrubs the KMS ciphertext off retired keys, as `cloop
//     ui` does at start (ScrubRetiredKMSKeys). Retiring a key destroys it, but
//     a build from before this task, which retires a KMS-held key by blanking
//     only the columns it knows, leaves behind what the KMS would unwrap.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// How often a member asks its KMS for its status.
const (
	kmsPollHealthy   = time.Minute
	kmsPollUnhealthy = 10 * time.Second
)

// hubKMS is what this process knows of its KMS.
type hubKMS struct {
	mu        sync.Mutex
	providers []kms.Provider
	last      map[string]KMSPoll // provider name -> last poll
}

// KMSPoll is one provider's last status poll.
type KMSPoll struct {
	Status kms.Status
	Err    string
	At     time.Time
}

// SetKMS gives the server the KMS providers `cloop ui` resolved, current root
// first. Nil or empty means the hub runs without a KMS.
func (s *Server) SetKMS(providers []kms.Provider) {
	if len(providers) == 0 {
		s.kms = nil
		return
	}
	s.kms = &hubKMS{providers: append([]kms.Provider(nil), providers...), last: map[string]KMSPoll{}}
}

// KMSHealth reports each provider's last poll, by name.
func (s *Server) KMSHealth() map[string]KMSPoll {
	if s.kms == nil {
		return nil
	}
	s.kms.mu.Lock()
	defer s.kms.mu.Unlock()
	out := make(map[string]KMSPoll, len(s.kms.last))
	for k, v := range s.kms.last {
		out[k] = v
	}
	return out
}

// watchKMS is the poll loop every member runs.
func (s *Server) watchKMS(ctx context.Context) {
	if s.kms == nil {
		return
	}
	defer recoverGoroutine("kms status")
	for {
		healthy := s.pollKMS(ctx)
		wait := kmsPollHealthy
		if !healthy {
			wait = kmsPollUnhealthy
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// pollKMS asks every provider for its status once, logs a change of health,
// and — on the leader — rewraps keys the current KMS has rotated away from. It
// reports whether every provider answered healthy.
func (s *Server) pollKMS(ctx context.Context) bool {
	healthy := true
	var current kms.Status
	currentOK := false
	for i, p := range s.kms.providers {
		st, err := p.Status(ctx)
		h := KMSPoll{Status: st, At: time.Now().UTC()}
		if err != nil {
			h.Err = err.Error()
			healthy = false
		} else if i == 0 {
			current, currentOK = st, true
		}
		s.kms.mu.Lock()
		prev, seen := s.kms.last[p.Name()]
		s.kms.last[p.Name()] = h
		s.kms.mu.Unlock()
		switch {
		case err != nil && (!seen || prev.Err == ""):
			fmt.Fprintf(os.Stderr, "ui: the KMS %s is not answering: %v — keys already opened keep "+
				"working; a key not yet opened, or minted elsewhere, cannot be until it is back\n", p.Name(), err)
		case err == nil && seen && prev.Err != "":
			fmt.Fprintf(os.Stderr, "ui: the KMS %s is answering again\n", p.Name())
		}
	}
	if s.isLeader() {
		s.tendKMSKeys(ctx, current.KeyID, currentOK)
	}
	return healthy
}

// tendKMSKeys is the leader's share of a poll. It scrubs the KMS ciphertext
// off keys a build from before Task 20433 retired (ScrubRetiredKMSKeys) and,
// when the current KMS has answered, rewraps the live keys it holds under a
// key other than the one it now encrypts under.
func (s *Server) tendKMSKeys(ctx context.Context, currentKey string, answered bool) {
	db, closeDB, err := s.openControlPlaneDB()
	if err != nil {
		return
	}
	defer closeDB()
	ScrubRetiredKMSKeys(db, "ui")
	if answered {
		followKMSRotation(ctx, db, currentKey)
	}
}

// ScrubRetiredKMSKeys destroys the KMS ciphertext retired keys still carry
// (statedb.ScrubRetiredKEKs), saying so on stderr under prefix. A build from
// before Task 20433 leaves it behind when it retires a KMS-held key, so
// `cloop ui` runs this at start — with or without a KMS now, since the key may
// have been retired part-way through a move off one — and the leader at each
// poll.
func ScrubRetiredKMSKeys(db *statedb.DB, prefix string) {
	n, err := db.ScrubRetiredKEKs()
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "%s: retired sealing keys may still carry their KMS ciphertext: %v\n", prefix, err)
	case n > 0:
		fmt.Fprintf(os.Stderr, "%s: destroyed the KMS ciphertext %d retired sealing key(s) still carried — a build "+
			"from before Task 20433 retired them and left it\n", prefix, n)
	}
}

// followKMSRotation rewraps every live key the current KMS root holds under a
// KMS key other than currentKey. Leader only.
func followKMSRotation(ctx context.Context, db *statedb.DB, currentKey string) {
	if currentKey == "" {
		return
	}
	store, err := secretstore.New(db)
	if err != nil {
		return
	}
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringActor("hub"), secretbroker.WithoutKeyCreation())
	if err != nil || kr.CurrentKMS() == nil {
		return
	}
	if len(kr.StaleKMSKeys(currentKey)) == 0 {
		return
	}
	rep, err := kr.RewrapKMS(ctx)
	recordKMSRewraps(db, "hub", "leader", rep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: following the rotation of the KMS %s to %s: %v\n", rep.KMS, currentKey, err)
		return
	}
	if rep.Rewrapped > 0 {
		fmt.Fprintf(os.Stderr, "ui: rewrapped %d sealing key(s) onto the KMS key %s\n", rep.Rewrapped, currentKey)
	}
}

// recordKMSRewraps writes sealing_key.kms_rewrapped for every key a rewrap
// moved.
func recordKMSRewraps(db *statedb.DB, actor, via string, rep secretbroker.KMSRewrapReport) {
	for _, k := range rep.Keys {
		if k.ToKey == "" {
			continue
		}
		blob, err := json.Marshal(map[string]any{
			"key_id": k.ID, "kms": rep.KMS, "from_kms_key": k.FromKey, "to_kms_key": k.ToKey, "via": via,
		})
		if err != nil {
			continue
		}
		if err := db.AppendAuditEvent(&statedb.AuditEvent{
			Timestamp: time.Now().UTC(), Actor: actor, EventType: string(auditaction.ActionSealingKeyKMSRewrapped),
			EntityType: "sealing_key", EntityID: k.ID, Payload: string(blob),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "ui: %s for %s not written to the audit trail: %v\n",
				auditaction.ActionSealingKeyKMSRewrapped, k.ID, err)
		}
	}
}

// kmsStoreReason is what the Secrets panel says when the store will not open
// because of its KMS: unreachable, or refusing the hub. ok is false for any
// other failure.
func kmsStoreReason(err error) (reason, remedy string, ok bool) {
	switch {
	case err == nil:
		return "", "", false
	case errors.Is(err, secretbroker.ErrKMSUnavailable):
		return "the key-management service holding the secret store's keys cannot be reached: " + err.Error(),
			"Check the KMS plugin sidecar or the Vault server secrets.kms names; `cloop hub doctor` reports " +
				"the KMS's own error under secrets.kms. Keys this hub opened before keep working; nothing is " +
				"sealed under anything else in the meantime.", true
	case strings.Contains(err.Error(), "refused this hub's identity"):
		return "the key-management service holding the secret store's keys refuses this hub: " + err.Error(),
			"The hub's identity lost, or never had, encrypt and decrypt on the KMS key: grant them again " +
				"(the Key Vault role, the Vault policy) and restart the hub.", true
	}
	return "", "", false
}
