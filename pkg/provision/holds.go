package provision

// Legal holds: an identity whose stored credentials an offboarding must keep,
// whoever starts it (Task 20415).
//
// `cloop hub user offboard --keep-credentials` is a hold for one run, given by
// the operator running it. Provisioning added offboardings nobody runs by hand
// — the identity provider deleting the account, offboard_after_days running
// out — and they need to know about a hold before they start, so a hold is
// now also a row: placed on an identity, honoured by every offboarding of it
// until it is released. Under a hold access is severed exactly as without
// one; the personal secrets and Claude Code homes are kept.

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// HoldIdentity reads the identity a hold is placed on: an email, lowercased,
// or a subject, as sub:<subject>. A bare value with no "@" is a subject.
func HoldIdentity(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "" || raw == "sub:":
		return "", fmt.Errorf("%w: name the identity — an email address or sub:<subject>", ErrInvalid)
	case strings.HasPrefix(raw, "sub:"):
		return raw, nil
	case strings.Contains(raw, "@"):
		return strings.ToLower(raw), nil
	}
	return "sub:" + raw, nil
}

// PlaceHold places a legal hold on identity, or restates the reason of one
// already placed.
func PlaceHold(db *statedb.DB, identity, holdReason string, ac AdminContext, now time.Time) (statedb.LegalHoldRow, error) {
	key, err := HoldIdentity(identity)
	if err != nil {
		return statedb.LegalHoldRow{}, err
	}
	holdReason = strings.TrimSpace(holdReason)
	if len(holdReason) < 4 {
		return statedb.LegalHoldRow{}, fmt.Errorf("%w: a hold needs a reason — the matter it is for", ErrInvalid)
	}
	h := statedb.LegalHoldRow{Identity: key, Reason: holdReason, PlacedAt: now.UTC(), PlacedBy: ac.actor()}
	if prev, ok, err := db.LegalHoldFor([]string{key}); err == nil && ok {
		h.PlacedAt = prev.PlacedAt
	}
	ev, err := auditEvent(ac.actor(), auditaction.ActionUserHoldPlace, "user", key, ac.payload(map[string]any{
		"identity": key, "hold_reason": holdReason, "placed_at": h.PlacedAt.Format(time.RFC3339),
	}), now)
	if err != nil {
		return statedb.LegalHoldRow{}, err
	}
	if err := db.PutLegalHold(h, ev); err != nil {
		return statedb.LegalHoldRow{}, err
	}
	return h, nil
}

// ReleaseHold releases the hold on identity, reporting whether one was placed.
func ReleaseHold(db *statedb.DB, identity string, ac AdminContext, now time.Time) (statedb.LegalHoldRow, bool, error) {
	key, err := HoldIdentity(identity)
	if err != nil {
		return statedb.LegalHoldRow{}, false, err
	}
	prev, ok, err := db.LegalHoldFor([]string{key})
	if err != nil || !ok {
		return statedb.LegalHoldRow{}, false, err
	}
	ev, err := auditEvent(ac.actor(), auditaction.ActionUserHoldRelease, "user", key, ac.payload(map[string]any{
		"identity": key, "hold_reason": prev.Reason, "placed_at": prev.PlacedAt.Format(time.RFC3339),
		"placed_by": prev.PlacedBy,
	}), now)
	if err != nil {
		return prev, false, err
	}
	released, err := db.DeleteLegalHold(key, ev)
	return prev, released, err
}
