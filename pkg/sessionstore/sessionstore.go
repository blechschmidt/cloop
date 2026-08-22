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

	// keyring seals refresh tokens under envelope encryption, sharing the
	// hub's KEK registry with the secret broker (Task 20181). Nil when the hub
	// has no encryption key; see the package comment.
	//
	// Sharing the registry rather than keeping a second one is what makes
	// `cloop hub key rotate` mean "rotate everything": a hub with two
	// registries would have a rotation command that quietly covered half the
	// sealed material, which is worse than having none, because it reports
	// success.
	keyring *secretbroker.Keyring

	// keyErr records a keyring that failed for a reason other than "no key
	// configured". It is surfaced on every write rather than degraded away —
	// see New.
	keyErr error
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
	if ks, err := secretstore.New(db); err == nil {
		kr, kerr := secretbroker.OpenKeyring(ks)
		switch {
		case kerr == nil:
			s.keyring = kr
		case errors.Is(kerr, secretbroker.ErrNoKey):
			// The documented degradation: no key configured, so refresh tokens
			// are not retained. Sessions still work; only the IdP-initiated
			// revocation channel is lost.
		default:
			// Anything else — a passphrase that cannot derive the live keys, a
			// corrupt registry — is a misconfiguration, not a deployment
			// choice. Swallowing it would silently disable sealing *and* let
			// SetRefresh blank tokens that were perfectly fine, which is data
			// loss dressed up as graceful degradation.
			s.keyErr = kerr
		}
	}
	return s, nil
}

// WithKeyring reuses an already-opened keyring instead of deriving one.
//
// Key derivation is 200 000 SHA-256 rounds per KEK. A hub that opens the
// broker and the session store separately pays it twice at every start for
// no benefit, and the two would silently diverge if one were opened before a
// rotation and the other after.
func (s *Store) WithKeyring(kr *secretbroker.Keyring) *Store {
	if s != nil && kr != nil {
		s.keyring = kr
		s.keyErr = nil
	}
	return s
}

// SealedSetName identifies sessions in rotation reports and namespaces every
// sealed refresh token's associated data.
func (s *Store) SealedSetName() string { return secretbroker.SetSessions }

// CountSealedByKey groups sessions holding a refresh token by sealing key.
func (s *Store) CountSealedByKey() (map[string]int, error) {
	return s.db.CountSessionsByKey()
}

// ListSealedNotUnder returns sessions whose refresh token is sealed under some
// other key. A session's associated data is its own ID, matching what seal
// bound it with.
func (s *Store) ListSealedNotUnder(keyID string, limit int) ([]secretbroker.SealedRow, error) {
	rows, err := s.db.ListSessionsNotUnderKey(keyID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]secretbroker.SealedRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, secretbroker.SealedRow{
			ID:  row.ID,
			AAD: secretbroker.AADFor(secretbroker.SetSessions, row.ID),
			Env: secretbroker.Envelope{
				KeyID:      row.KeyID,
				WrappedDEK: row.WrappedDEK,
				Ciphertext: row.Ciphertext,
			},
		})
	}
	return out, nil
}

// ReplaceSealed swaps a session's sealed refresh token under compare-and-swap.
func (s *Store) ReplaceSealed(id string, expect, next secretbroker.Envelope) (bool, error) {
	return s.db.ReplaceSessionSealed(id,
		statedb.SealedRow{KeyID: expect.KeyID, WrappedDEK: expect.WrappedDEK, Ciphertext: expect.Ciphertext},
		statedb.SealedRow{KeyID: next.KeyID, WrappedDEK: next.WrappedDEK, Ciphertext: next.Ciphertext})
}

var _ secretbroker.SealedSet = (*Store)(nil)

// Available reports whether refresh tokens can be sealed, and therefore
// whether IdP-side revocation is armed on this hub.
func (s *Store) Available() bool { return s != nil && s.keyring != nil && s.keyErr == nil }

// Put writes a new session.
func (s *Store) Put(rec oidcauth.SessionRecord) error {
	env, err := s.seal(rec.ID, rec.RefreshToken)
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
		RefreshSealed:     env.Ciphertext,
		RefreshKeyID:      env.KeyID,
		RefreshWrappedDEK: env.WrappedDEK,
		RefreshCheckedAt:  rec.RefreshCheckedAt,
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
	env, err := s.seal(id, refreshToken)
	if err != nil {
		// Returning here rather than writing an empty envelope is the point: a
		// nil sealed value clears the column, so a transient sealing failure
		// would destroy a token that was still valid and turn the next
		// revalidation into a spurious "the IdP revoked this user".
		return err
	}
	if err := s.db.UpdateSessionRefresh(id, env.KeyID, env.WrappedDEK, env.Ciphertext, checkedAt); err != nil {
		if errors.Is(err, statedb.ErrSessionNotFound) {
			return oidcauth.ErrSessionNotFound
		}
		return err
	}
	return nil
}

// ── crypto ──────────────────────────────────────────────────────────────────

// seal encrypts a refresh token under a fresh per-session data key, returning
// an empty envelope when there is nothing to store or no key to store it
// under.
//
// The session ID is the associated data, so a sealed token authenticates only
// against the row it was written for. Without that binding, anyone able to
// write the sessions table could copy an administrator's sealed refresh token
// into their own row and have the hub present it to the IdP on their behalf.
func (s *Store) seal(sessionID, refreshToken string) (secretbroker.Envelope, error) {
	if refreshToken == "" {
		return secretbroker.Envelope{}, nil
	}
	if s.keyErr != nil {
		return secretbroker.Envelope{}, fmt.Errorf("sessionstore: sealing key unusable: %w", s.keyErr)
	}
	if s.keyring == nil {
		return secretbroker.Envelope{}, nil
	}
	env, err := s.keyring.SealFor(secretbroker.AADFor(secretbroker.SetSessions, sessionID), []byte(refreshToken))
	if err != nil {
		return secretbroker.Envelope{}, fmt.Errorf("sessionstore: seal refresh token: %w", err)
	}
	return env, nil
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
func (s *Store) unseal(row statedb.SessionRow) string {
	if len(row.RefreshSealed) == 0 || s.keyring == nil {
		return ""
	}
	plain, err := s.keyring.OpenEnvelope(
		secretbroker.AADFor(secretbroker.SetSessions, row.ID), secretbroker.Envelope{
		KeyID:      row.RefreshKeyID,
		WrappedDEK: row.RefreshWrappedDEK,
		Ciphertext: row.RefreshSealed,
	})
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
		RefreshToken:     s.unseal(row),
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
