package provision

// The SCIM bearer credential: what an identity provider presents to
// /scim/v2, and nothing else accepts.
//
//	cloop_scim_<id>_<secret>
//
// The same construction as an API token (pkg/apitoken): a public id that is
// the row's key, 256 secret bits that authenticate, and an HMAC of the secret
// as the only thing stored. The prefix differs so that neither credential can
// be mistaken for the other: the hub's token chain does not recognise this
// one, and the SCIM routes recognise nothing else — not an API token, not the
// static admin token, not a session. A credential that provisions the
// directory is a credential that can deactivate every administrator on the
// hub, and it should not double as anything.
//
// Rotation keeps the id, so the credential's name, its place in the trail
// (scim:<name>) and the Settings row stay put while the secret changes. The
// secret it replaced can be honoured for a grace period, long enough to paste
// the new one into the identity provider without a failed cycle in between.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// CredentialPrefix starts every SCIM credential. Exported so a scanner and the
// redaction registry have one constant to match.
const CredentialPrefix = "cloop_scim_"

const (
	credentialIDBytes     = 8
	credentialSecretBytes = 32
)

// MaxGrace bounds how long a rotated-out secret may stay valid.
const MaxGrace = 7 * 24 * time.Hour

// Credential errors. Every one of them is the same 401 to a client.
var (
	ErrNoCredential  = errors.New("provision: not a SCIM credential")
	ErrBadCredential = errors.New("provision: unknown or wrong SCIM credential")
	ErrRevoked       = errors.New("provision: the SCIM credential was revoked")
)

var credentialName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidCredentialName reports whether name may name a credential: it becomes
// part of the audit actor, scim:<name>, so it is short and plain.
func ValidCredentialName(name string) error {
	if !credentialName.MatchString(name) {
		return fmt.Errorf("%w: a SCIM credential name is 1-64 letters, digits, '.', '_' or '-', "+
			"starting with a letter or digit (got %q)", ErrInvalid, name)
	}
	return nil
}

// Minted is a credential and, once, its plaintext.
type Minted struct {
	Row       statedb.SCIMCredentialRow
	Plaintext string
}

// AdminContext is who administers a credential or a hold, for the trail.
type AdminContext struct {
	Actor  string
	Reason string
	// Via is cli or ui; OSUser the shell user for a CLI change.
	Via    string
	OSUser string
}

func (c AdminContext) payload(m map[string]any) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	if c.Reason != "" {
		m["reason"] = c.Reason
	}
	if c.Via != "" {
		m["via"] = c.Via
	}
	if c.OSUser != "" {
		m["os_user"] = c.OSUser
	}
	return m
}

func (c AdminContext) actor() string {
	if strings.TrimSpace(c.Actor) == "" {
		return "system"
	}
	return c.Actor
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// MintCredential creates a credential. The plaintext is returned here and
// never again.
func MintCredential(db *statedb.DB, name string, ac AdminContext, now time.Time) (Minted, error) {
	name = strings.TrimSpace(name)
	if err := ValidCredentialName(name); err != nil {
		return Minted{}, err
	}
	id, err := randomHex(credentialIDBytes)
	if err != nil {
		return Minted{}, fmt.Errorf("provision: generate id: %w", err)
	}
	secret, err := randomHex(credentialSecretBytes)
	if err != nil {
		return Minted{}, fmt.Errorf("provision: generate secret: %w", err)
	}
	hash, err := apitoken.DeriveHash(secret)
	if err != nil {
		return Minted{}, err
	}
	row := statedb.SCIMCredentialRow{
		ID: id, Name: name, SecretHash: hash, CreatedAt: now.UTC(), CreatedBy: ac.actor(),
	}
	ev, err := auditEvent(ac.actor(), auditaction.ActionSCIMCredentialCreate, "scim_credential", id,
		ac.payload(map[string]any{"id": id, "name": name}), now)
	if err != nil {
		return Minted{}, err
	}
	if err := db.InsertSCIMCredential(row, ev); err != nil {
		var c *statedb.SCIMConflict
		if errors.As(err, &c) {
			return Minted{}, fmt.Errorf("%w: a live SCIM credential is already named %q (%s); rotate it, "+
				"or revoke it first", ErrInvalid, name, c.OtherID)
		}
		return Minted{}, err
	}
	return Minted{Row: row, Plaintext: CredentialPrefix + id + "_" + secret}, nil
}

// FindCredential resolves a credential by id, or by the name of a live one.
func FindCredential(db *statedb.DB, ref string) (statedb.SCIMCredentialRow, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return statedb.SCIMCredentialRow{}, fmt.Errorf("%w: name a SCIM credential", ErrInvalid)
	}
	if c, err := db.GetSCIMCredential(ref); err == nil {
		return c, nil
	} else if !errors.Is(err, statedb.ErrSCIMNotFound) {
		return statedb.SCIMCredentialRow{}, err
	}
	all, err := db.ListSCIMCredentials()
	if err != nil {
		return statedb.SCIMCredentialRow{}, err
	}
	for _, c := range all {
		if c.Name == ref && !c.Revoked() {
			return c, nil
		}
	}
	return statedb.SCIMCredentialRow{}, fmt.Errorf("%w: no live SCIM credential %q", statedb.ErrSCIMNotFound, ref)
}

// RotateCredential replaces a live credential's secret. The secret it
// replaces stays valid for grace — zero ends it now.
func RotateCredential(db *statedb.DB, ref string, grace time.Duration, ac AdminContext, now time.Time) (Minted, error) {
	if grace < 0 || grace > MaxGrace {
		return Minted{}, fmt.Errorf("%w: the grace period is between 0 and %s", ErrInvalid, MaxGrace)
	}
	c, err := FindCredential(db, ref)
	if err != nil {
		return Minted{}, err
	}
	if c.Revoked() {
		return Minted{}, fmt.Errorf("%w: SCIM credential %s was revoked; mint a new one", ErrInvalid, c.Name)
	}
	secret, err := randomHex(credentialSecretBytes)
	if err != nil {
		return Minted{}, fmt.Errorf("provision: generate secret: %w", err)
	}
	hash, err := apitoken.DeriveHash(secret)
	if err != nil {
		return Minted{}, err
	}
	var until time.Time
	if grace > 0 {
		until = now.Add(grace).UTC()
	}
	payload := map[string]any{"id": c.ID, "name": c.Name, "grace_seconds": int64(grace / time.Second)}
	if !until.IsZero() {
		payload["previous_valid_until"] = until.Format(time.RFC3339)
	}
	ev, err := auditEvent(ac.actor(), auditaction.ActionSCIMCredentialRotate, "scim_credential", c.ID, ac.payload(payload), now)
	if err != nil {
		return Minted{}, err
	}
	if err := db.RotateSCIMCredential(c.ID, hash, c.SecretHash, until, now, ac.actor(), ev); err != nil {
		return Minted{}, err
	}
	c.SecretHash, c.RotatedAt, c.RotatedBy = hash, now.UTC(), ac.actor()
	c.PreviousExpiresAt = until
	return Minted{Row: c, Plaintext: CredentialPrefix + c.ID + "_" + secret}, nil
}

// RevokeCredential revokes a credential, both its secrets at once. A
// credential already revoked is reported, not an error.
func RevokeCredential(db *statedb.DB, ref string, ac AdminContext, now time.Time) (statedb.SCIMCredentialRow, bool, error) {
	c, err := FindCredential(db, ref)
	if err != nil {
		return statedb.SCIMCredentialRow{}, false, err
	}
	ev, err := auditEvent(ac.actor(), auditaction.ActionSCIMCredentialRevoke, "scim_credential", c.ID,
		ac.payload(map[string]any{"id": c.ID, "name": c.Name}), now)
	if err != nil {
		return c, false, err
	}
	changed, err := db.RevokeSCIMCredential(c.ID, now, ac.actor(), ev)
	if err != nil {
		return c, false, err
	}
	if changed {
		c.RevokedAt, c.RevokedBy = now.UTC(), ac.actor()
	}
	return c, changed, nil
}

// ParseCredential splits a credential into its id and secret without touching
// storage; ok is false for anything not shaped like one.
func ParseCredential(raw string) (id, secret string, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, CredentialPrefix) {
		return "", "", false
	}
	rest := raw[len(CredentialPrefix):]
	id, secret, found := strings.Cut(rest, "_")
	if !found || len(id) != credentialIDBytes*2 || len(secret) != credentialSecretBytes*2 {
		return "", "", false
	}
	if !lowerHex(id) || !lowerHex(secret) {
		return "", "", false
	}
	return id, secret, true
}

func lowerHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Verifier checks presented credentials, recording uses at most once a
// minute per credential.
type Verifier struct {
	DB  *statedb.DB
	Now func() time.Time

	mu      sync.Mutex
	touched map[string]time.Time
}

// Verified is a credential that authenticated a request.
type Verified struct {
	Actor Actor
	// Previous reports that the secret presented is the one a rotation
	// replaced, still inside its grace period.
	Previous bool
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify authenticates a presented credential.
//
// The secret is compared before revocation is consulted, so a caller without
// the secret cannot learn that an id exists, or that it was revoked.
func (v *Verifier) Verify(raw string) (Verified, error) {
	id, secret, ok := ParseCredential(raw)
	if !ok {
		return Verified{}, ErrNoCredential
	}
	c, err := v.DB.GetSCIMCredential(id)
	if err != nil {
		if errors.Is(err, statedb.ErrSCIMNotFound) {
			return Verified{}, ErrBadCredential
		}
		return Verified{}, err
	}
	now := v.now()
	current := apitoken.VerifyHash(c.SecretHash, secret)
	previous := !current && c.PreviousHash != "" && now.Before(c.PreviousExpiresAt) &&
		apitoken.VerifyHash(c.PreviousHash, secret)
	if !current && !previous {
		return Verified{}, ErrBadCredential
	}
	if c.Revoked() {
		return Verified{}, ErrRevoked
	}
	v.touch(c.ID, now)
	return Verified{Actor: Actor{CredentialID: c.ID, Name: c.Name}, Previous: previous}, nil
}

func (v *Verifier) touch(id string, now time.Time) {
	v.mu.Lock()
	if v.touched == nil {
		v.touched = map[string]time.Time{}
	}
	last, seen := v.touched[id]
	if seen && now.Sub(last) < time.Minute {
		v.mu.Unlock()
		return
	}
	v.touched[id] = now
	v.mu.Unlock()
	// Advisory: the request is authenticated either way.
	_ = v.DB.TouchSCIMCredential(id, now)
}
