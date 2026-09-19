package authz

// audience_test.go covers the gate predicate (Task 20310).
//
// The cases that matter are the ones where being wrong is a security bug
// rather than a usability one: an empty list must admit (or every existing
// deployment breaks), a non-empty list must not admit a stranger, and a value
// this binary cannot interpret must restrict rather than permit.

import "testing"

func TestAudienceEmptyListAdmitsEveryone(t *testing.T) {
	// The opt-in property the whole feature rests on. An executor nobody has
	// restricted behaves exactly as it did before audiences existed.
	if !Admits(nil, &Subject{Sub: "anyone"}) {
		t.Error("a nil audience denied a subject; it must admit everyone")
	}
	if !Admits([]AudienceMember{}, &Subject{Sub: "anyone"}) {
		t.Error("an empty audience denied a subject; it must admit everyone")
	}
	// Including a caller with no identity at all, which is every request on a
	// hub that has no identity provider configured.
	if !Admits(nil, nil) {
		t.Error("a nil audience denied a nil subject; a hub without OIDC must keep working")
	}
}

func TestAudienceNonEmptyListDeniesANilSubject(t *testing.T) {
	// The direction a gate must fail in. A restricted executor on a hub where
	// the caller has no identity is unreachable, not open.
	members := []AudienceMember{{Kind: ClaimGroup, Value: "platform"}}
	if Admits(members, nil) {
		t.Error("a restricted executor admitted a caller with no identity")
	}
}

func TestAudienceMatchesGroupsInEitherSpelling(t *testing.T) {
	// Keycloak emits group paths as "/platform"; other providers emit the bare
	// name. An admin types whichever their IdP shows them, and both must work —
	// in both directions, because the stored value and the token value can each
	// be in either form.
	cases := []struct {
		name          string
		stored, token string
	}{
		{"bare stored, bare token", "platform", "platform"},
		{"bare stored, path token", "platform", "/platform"},
		{"path stored, path token", "/platform", "/platform"},
		{"path stored, bare token", "/platform", "platform"},
		{"case-insensitive", "Platform", "/platform"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := AudienceMemberFor("group", tc.stored)
			if !Admits([]AudienceMember{m}, &Subject{Groups: []string{tc.token}}) {
				t.Errorf("stored %q did not admit a member of %q", tc.stored, tc.token)
			}
		})
	}
}

func TestAudienceDeniesANonMember(t *testing.T) {
	members := []AudienceMember{{Kind: ClaimGroup, Value: "platform"}}
	if Admits(members, &Subject{Groups: []string{"contractors"}, Email: "x@example.com"}) {
		t.Error("a member of an unlisted group was admitted")
	}
}

func TestAudienceUserKindSplitsOnEmail(t *testing.T) {
	// An admin pastes either an email or an opaque subject into one field, and
	// which one it is has to be inferred. The "@" rule is the whole inference.
	email := AudienceMemberFor("user", "dev@example.com")
	if email.Kind != ClaimEmail {
		t.Errorf("a value containing @ became %q, want %q", email.Kind, ClaimEmail)
	}
	if !Admits([]AudienceMember{email}, &Subject{Email: "DEV@example.com"}) {
		t.Error("email matching should be case-insensitive, as it is for bindings")
	}

	sub := AudienceMemberFor("user", "a1b2c3")
	if sub.Kind != ClaimSub {
		t.Errorf("a value with no @ became %q, want %q", sub.Kind, ClaimSub)
	}
	if !Admits([]AudienceMember{sub}, &Subject{Sub: "a1b2c3"}) {
		t.Error("subject matching failed on an exact value")
	}
	// Subjects are opaque identifiers, so unlike email they compare exactly.
	if Admits([]AudienceMember{sub}, &Subject{Sub: "A1B2C3"}) {
		t.Error("subject matching was case-insensitive; it must be exact")
	}
}

func TestAudienceUnknownKindMatchesNothing(t *testing.T) {
	// A row written by a newer binary, or a typo that reached storage. It must
	// restrict rather than permit: a gate that admits on "I do not understand
	// this rule" is not a gate.
	m := AudienceMemberFor("wardrobe", "narnia")
	if m.Value != "" {
		t.Fatalf("an unknown kind produced a usable member: %+v", m)
	}
	if Admits([]AudienceMember{{Kind: "wardrobe", Value: "narnia"}},
		&Subject{Sub: "narnia", Groups: []string{"narnia"}}) {
		t.Error("a member of an unrecognised kind admitted a subject")
	}
}

func TestAudienceEmptyValueIsNotAMember(t *testing.T) {
	// Guards the worst version of the bug: a blank value that matched a subject
	// with a blank claim would turn "restricted" into "admits anyone whose IdP
	// omits that claim".
	if m := AudienceMemberFor("group", "   "); m.Value != "" {
		t.Errorf("a whitespace value produced a usable member: %+v", m)
	}
	if Admits([]AudienceMember{{Kind: ClaimGroup, Value: ""}}, &Subject{Groups: []string{""}}) {
		t.Error("an empty audience value matched an empty group claim")
	}
	if Admits([]AudienceMember{{Kind: ClaimSub, Value: ""}}, &Subject{Sub: ""}) {
		t.Error("an empty audience value matched an empty subject")
	}
}

func TestAudienceAdmitsOnAnyMatchingEntry(t *testing.T) {
	// The list is a union: an identity matching any one entry is admitted.
	members := []AudienceMember{
		{Kind: ClaimGroup, Value: "platform"},
		{Kind: ClaimEmail, Value: "oncall@example.com"},
	}
	if !Admits(members, &Subject{Email: "oncall@example.com"}) {
		t.Error("the second entry did not admit")
	}
	if !Admits(members, &Subject{Groups: []string{"platform"}}) {
		t.Error("the first entry did not admit")
	}
}
