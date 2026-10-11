// Package statictoken holds what the hub, the CLI and `cloop hub doctor` must
// agree on about the static admin token (Task 20406): how it is named without
// being stored, and when retiring it would leave a hub with no way in.
//
// The static --token / CLOOP_UI_TOKEN is the deployment's own secret: a
// request presenting it is an administrator outside RBAC, and it never
// expires. Since Task 20406 it can be retired at runtime — every hub member
// refuses it within seconds, and nothing it opened stays open — and its last
// use is reported. Both are keyed by its fingerprint, which is what this
// package computes.
//
// The comparison of a presented value against the token is not here. It is
// one function in pkg/ui (Server.checkStaticToken), the only code that holds
// the value, and tests/arch keeps it the only one.
package statictoken

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
)

// fingerprintDomain separates a static token's fingerprint from a plain
// SHA-256 of the same bytes, so a precomputed table of digests of common
// passwords does not name a weak token for whoever can read the table.
const fingerprintDomain = "cloop static admin token v1\x00"

// Fingerprint names a static token without being it: the hex SHA-256 of the
// value under this package's domain. Deterministic, so a retirement written
// by one process names the token every other process holds.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(fingerprintDomain + value))
	return hex.EncodeToString(sum[:])
}

// ShortLen is how many hex characters of a fingerprint are shown to people:
// 48 bits, enough to tell two tokens apart on one hub.
const ShortLen = 12

// Short is the prefix of fp shown on the Settings card and by the CLI.
func Short(fp string) string {
	if len(fp) <= ShortLen {
		return fp
	}
	return fp[:ShortLen]
}

// Valid reports whether fp has the shape Fingerprint produces.
func Valid(fp string) bool {
	if len(fp) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(fp)
	return err == nil && strings.ToLower(fp) == fp
}

// ReportInterval is how often a hub process holding a static token reports
// it, with its last use, and re-reads the retirements.
const ReportInterval = 30 * time.Second

// HeldWithin is how recently a hub process must have reported a token for it
// to count as held by a running hub: several reports, so one slow flush does
// not make a running hub's token look abandoned.
const HeldWithin = 3 * time.Minute

// Held reports whether a token last reported at heldAt is held by a running
// hub at now.
func Held(heldAt, now time.Time) bool {
	return !heldAt.IsZero() && now.Sub(heldAt) <= HeldWithin
}

// ActiveAdminTokens counts the API tokens that can administer a hub on their
// own: active, ordinary (a display-glasses link is confined to the glasses
// views), carrying the admin role, and bound to no owner — an owner-bound
// token's authority is intersected with its owner's, which a hub without
// single sign-on cannot vouch for.
func ActiveAdminTokens(tokens []apitoken.Token, now time.Time) int {
	n := 0
	for i := range tokens {
		t := &tokens[i]
		if !t.Active(now) || t.Kind != "" || t.Owner != nil || t.OwnerUnreadable {
			continue
		}
		for _, r := range t.ParsedRoles() {
			if r == authz.RoleAdmin {
				n++
				break
			}
		}
	}
	return n
}

// ErrWouldStrand is CheckRetire's refusal: retiring the static token would
// leave the hub with no way in.
var ErrWouldStrand = errors.New("retiring the static token would leave this hub with no way in")

// CheckRetire refuses a retirement that would strand the hub: one with no
// single sign-on and no active admin API token, where the static token is the
// only credential that can administer anything. force overrides it — the
// operator at the hub's shell can always mint an admin token afterwards with
// `cloop hub token create --role admin`, and sometimes locking the door first
// is the point.
func CheckRetire(sso bool, adminTokens int, force bool) error {
	if sso || adminTokens > 0 || force {
		return nil
	}
	return fmt.Errorf("%w: it has no single sign-on and no active admin API token, so nobody could "+
		"administer it afterwards. Mint one first (cloop hub token create break-glass --role admin "+
		"--expires-in 30d), configure ui.oidc, or retire it anyway with --force (Settings: Retire anyway)",
		ErrWouldStrand)
}

// Instead says what a caller presenting a retired token should use instead.
func Instead(sso bool) string {
	if sso {
		return "Sign in through single sign-on, or present a scoped API token (cloop hub token create)."
	}
	return "Present a scoped API token (cloop hub token create), or this hub's new static token if one was deployed."
}
