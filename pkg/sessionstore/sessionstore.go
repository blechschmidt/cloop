// Package sessionstore persists cloop dashboard sessions in the hub's own
// state database, sealing the one piece of credential material a session holds
// (Task 20176).
//
// It is the SQLite half of the split described in pkg/oidcauth: that package
// owns the policy — two clocks, revocation, IdP revalidation — and is
// stdlib-only, while this one owns the storage and the crypto. The seam is
// oidcauth.SessionStore, and it is the same shape as
// secretbroker.Store/secretstore.
//
// # What is encrypted, and what happens without a key
//
// A session row holds a subject, some claims, two timestamps, and a refresh
// token. Only the last of those is a credential: presented to the identity
// provider it yields fresh tokens for the user, so it is sealed with the same
// AES-256-GCM construction as a brokered secret, under the same
// CLOOP_SECRET_KEY.
//
// When no key is configured, the store keeps working and simply does not
// retain refresh tokens. That is a deliberate degradation rather than a
// failure, and the alternatives are worse: writing a live credential in
// plaintext trades a strong property for a weak one, and refusing to open the
// store would mean a hub with no key cannot sign anyone in at all. The cost is
// bounded and visible — Available() reports it, the Active Sessions panel says
// so, and sessions still end on both timeouts and on explicit revocation. Only
// the IdP-initiated channel is lost.
package sessionstore

import (
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store is the statedb-backed oidcauth.SessionStore.
type Store struct {
	db *statedb.DB

	// cipher seals refresh tokens. Nil when the hub has no encryption key; see
	// the package comment.
	cipher *secretbroker.Cipher
}

// New adapts a control-plane database.
//
// Which database matters, and it is the same rule as API tokens and executor
// bindings: sessions belong in the *hub's* own state, never a managed
// project's. A tenant able to write to the file holding the session table
// could mint itself a session for any subject, which is a complete
// authentication bypass dressed up as a file write.
//
// A missing or unusable encryption key is not an error here — it disables
// refresh-token retention and nothing else.
func New(db *statedb.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("sessionstore: nil database")
	}
	s := &Store{db: db}
	if meta, err := secretstore.New(db); err == nil {
		if c, cerr := secretbroker.NewCipher(meta); cerr == nil {
			s.cipher = c
		}
	}
	return s, nil
}

// Available reports whether refresh tokens can be sealed, and therefore
// whether IdP-side revocation is armed on this hub.
func (s *Store) Available() bool { return s != nil && s.cipher != nil }

// Put writes a new session.
func (s *Store) Put(rec oidcauth.SessionRecord) error {
	sealed, err := s.seal(rec.RefreshToken)
	if err != nil {
		return err
	}
	return s.db.PutSession(statedb.SessionRow{
		ID:               rec.ID,
		Subject:          rec.Identity.Sub,
		Email:            rec.Identity.Email,
		DisplayName:      rec.Identity.Name,
		OwnerKey:         rec.Identity.OwnerKey(),
		Groups:           rec.Identity.Groups,
		Roles:            rec.Identity.Roles,
		IP:               rec.IP,
		UserAgent:        rec.UserAgent,
		IssuedAt:         rec.IssuedAt,
		LastSeen:         rec.LastSeen,
		ExpiresAt:        rec.ExpiresAt,
		RefreshSealed:    sealed,
		RefreshCheckedAt: rec.RefreshCheckedAt,
	})
}

// Get returns one session, translating the storage sentinel into the one
// oidcauth understands.
func (s *Store) Get(id string) (oidcauth.SessionRecord, error) {
	row, err := s.db.GetSession(id)
	if err != nil {
		if errors.Is(err, statedb.ErrSessionNotFound) {
			return oidcauth.SessionRecord{}, oidcauth.ErrSessionNotFound
		}
		return oidcauth.SessionRecord{}, err
	}
	return s.toRecord(row), nil
}

func (s *Store) List() ([]oidcauth.SessionRecord, error) {
	rows, err := s.db.ListSessions()
	if err != nil {
		return nil, err
	}
	return s.toRecords(rows), nil
}

func (s *Store) Touch(id string, t time.Time) error {
	return s.db.TouchSession(id, t)
}

func (s *Store) Delete(id string) (bool, error) {
	return s.db.DeleteSession(id)
}

func (s *Store) DeleteBySubject(subject, keepID string) ([]oidcauth.SessionRecord, error) {
	rows, err := s.db.DeleteSessionsBySubject(subject, keepID)
	if err != nil {
		return nil, err
	}
	return s.toRecords(rows), nil
}

func (s *Store) DeleteExpired(absoluteCutoff, idleCutoff time.Time) ([]oidcauth.SessionRecord, error) {
	rows, err := s.db.DeleteExpiredSessions(absoluteCutoff, idleCutoff)
	if err != nil {
		return nil, err
	}
	return s.toRecords(rows), nil
}

func (s *Store) DueForRefresh(cutoff time.Time, limit int) ([]oidcauth.SessionRecord, error) {
	rows, err := s.db.SessionsDueForRefresh(cutoff, limit)
	if err != nil {
		return nil, err
	}
	return s.toRecords(rows), nil
}

func (s *Store) SetRefresh(id, refreshToken string, checkedAt time.Time) error {
	sealed, err := s.seal(refreshToken)
	if err != nil {
		return err
	}
	if err := s.db.UpdateSessionRefresh(id, sealed, checkedAt); err != nil {
		if errors.Is(err, statedb.ErrSessionNotFound) {
			return oidcauth.ErrSessionNotFound
		}
		return err
	}
	return nil
}

// ── crypto ──────────────────────────────────────────────────────────────────

// seal encrypts a refresh token, returning nil when there is nothing to store
// or no key to store it under.
func (s *Store) seal(refreshToken string) ([]byte, error) {
	if refreshToken == "" || s.cipher == nil {
		return nil, nil
	}
	out, err := s.cipher.Seal([]byte(refreshToken))
	if err != nil {
		return nil, fmt.Errorf("sessionstore: seal refresh token: %w", err)
	}
	return out, nil
}

// unseal decrypts a stored refresh token.
//
// A failure returns the empty string rather than an error, on purpose. The
// realistic cause is a rotated or lost CLOOP_SECRET_KEY, and every session
// predating the rotation would then be undecryptable. Treating that as "this
// session has no refresh token" costs the IdP-revocation channel for those
// sessions; treating it as an error would either fail every read — signing the
// whole fleet out — or, worse, look like a refusal from the provider and
// terminate them as if the users had been disabled.
func (s *Store) unseal(sealed []byte) string {
	if len(sealed) == 0 || s.cipher == nil {
		return ""
	}
	plain, err := s.cipher.Unseal(sealed)
	if err != nil {
		return ""
	}
	return string(plain)
}

// ── translation ─────────────────────────────────────────────────────────────

func (s *Store) toRecord(row statedb.SessionRow) oidcauth.SessionRecord {
	return oidcauth.SessionRecord{
		ID: row.ID,
		Identity: oidcauth.Identity{
			Sub:    row.Subject,
			Email:  row.Email,
			Name:   row.DisplayName,
			Groups: row.Groups,
			Roles:  row.Roles,
		},
		IP:               row.IP,
		UserAgent:        row.UserAgent,
		IssuedAt:         row.IssuedAt,
		LastSeen:         row.LastSeen,
		ExpiresAt:        row.ExpiresAt,
		RefreshToken:     s.unseal(row.RefreshSealed),
		RefreshCheckedAt: row.RefreshCheckedAt,
	}
}

func (s *Store) toRecords(rows []statedb.SessionRow) []oidcauth.SessionRecord {
	out := make([]oidcauth.SessionRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.toRecord(row))
	}
	return out
}
