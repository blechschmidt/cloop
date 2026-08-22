package oidcauth

import (
	"encoding/json"
	"strings"
	"testing"
)

// Group and role claims have no interoperable standard: IdPs emit arrays,
// bare strings, comma- or space-separated strings, and Keycloak nests roles
// under realm_access/resource_access. These tests pin the shapes cloop
// accepts, because a claim that fails to parse silently costs a user every
// permission their groups were supposed to grant.

func TestStringListClaimShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		json string
		want []string
	}{
		{"array of strings", `["a","b","c"]`, []string{"a", "b", "c"}},
		{"empty array", `[]`, nil},
		{"single bare string", `"admins"`, []string{"admins"}},
		{"comma separated", `"admins,engineers"`, []string{"admins", "engineers"}},
		{"comma space separated", `"admins, engineers"`, []string{"admins", "engineers"}},
		{"space separated", `"admins engineers"`, []string{"admins", "engineers"}},
		{"empty string", `""`, nil},
		{"whitespace only", `"   "`, nil},
		// A malformed optional claim must not reject an otherwise valid
		// token — it must simply grant nothing.
		{"number", `42`, nil},
		{"object", `{"nested":"value"}`, nil},
		{"null", `null`, nil},
		{"array with an empty entry", `["a","","b"]`, []string{"a", "", "b"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got stringListClaim
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("UnmarshalJSON(%s) returned an error: %v — "+
					"a malformed optional claim must never fail the token", tc.json, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v (%d entries), want %v (%d)", []string(got), len(got), tc.want, len(tc.want))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestClaimsGroupAndRoleExtraction covers the spellings cloop reads,
// including Keycloak's two nested locations, and the de-duplication that
// keeps a user in the same group twice from producing a doubled list.
func TestClaimsGroupAndRoleExtraction(t *testing.T) {
	t.Parallel()

	const clientID = "cloop-dashboard"

	cases := []struct {
		name       string
		payload    string
		wantGroups []string
		wantRoles  []string
	}{
		{
			name:       "no group or role claims at all",
			payload:    `{"sub":"u1"}`,
			wantGroups: nil,
			wantRoles:  nil,
		},
		{
			name:       "plain groups array",
			payload:    `{"sub":"u1","groups":["cloop-admins","engineering"]}`,
			wantGroups: []string{"cloop-admins", "engineering"},
		},
		{
			name:      "top-level roles array",
			payload:   `{"sub":"u1","roles":["maintainer"]}`,
			wantRoles: []string{"maintainer"},
		},
		{
			name:      "keycloak realm_access roles",
			payload:   `{"sub":"u1","realm_access":{"roles":["realm-admin"]}}`,
			wantRoles: []string{"realm-admin"},
		},
		{
			name: "keycloak resource_access roles for this client",
			payload: `{"sub":"u1","resource_access":{"cloop-dashboard":{"roles":["client-operator"]},` +
				`"other-app":{"roles":["should-not-appear"]}}}`,
			wantRoles: []string{"client-operator"},
		},
		{
			name: "all role spellings merge",
			payload: `{"sub":"u1","roles":["a"],"realm_access":{"roles":["b"]},` +
				`"resource_access":{"cloop-dashboard":{"roles":["c"]}}}`,
			wantRoles: []string{"a", "b", "c"},
		},
		{
			name:      "duplicates are collapsed case-insensitively",
			payload:   `{"sub":"u1","roles":["Admin","admin","/admin"],"realm_access":{"roles":["ADMIN"]}}`,
			wantRoles: []string{"Admin"},
		},
		{
			name:       "group paths are preserved verbatim for the resolver to normalize",
			payload:    `{"sub":"u1","groups":["/cloop-admins"]}`,
			wantGroups: []string{"/cloop-admins"},
		},
		{
			name:       "single-string groups claim",
			payload:    `{"sub":"u1","groups":"solo-group"}`,
			wantGroups: []string{"solo-group"},
		},
		{
			name:       "blank entries are dropped",
			payload:    `{"sub":"u1","groups":["  ","valid",""]}`,
			wantGroups: []string{"valid"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c idClaims
			if err := json.Unmarshal([]byte(tc.payload), &c); err != nil {
				t.Fatalf("parse claims: %v", err)
			}
			assertList(t, "groups", c.groupValues(), tc.wantGroups)
			assertList(t, "roles", c.roleValues(clientID), tc.wantRoles)
		})
	}
}

// TestUnknownClaimShapeDoesNotBreakTokenParsing is the resilience check: an
// IdP that emits an unexpected type for groups must still produce a usable
// identity with the rest of its claims intact.
func TestUnknownClaimShapeDoesNotBreakTokenParsing(t *testing.T) {
	t.Parallel()

	payload := `{"sub":"u1","email":"a@b.com","name":"A","groups":{"unexpected":"object"},"roles":99}`
	var c idClaims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("a token with oddly-shaped group claims must still parse, got: %v", err)
	}
	if c.Sub != "u1" || c.Email != "a@b.com" || c.Name != "A" {
		t.Errorf("core claims were lost: sub=%q email=%q name=%q", c.Sub, c.Email, c.Name)
	}
	if len(c.groupValues()) != 0 || len(c.roleValues("x")) != 0 {
		t.Error("unparseable group/role claims should yield empty lists, not garbage")
	}
}

// TestIdentityCarriesClaimsForAuthz checks the field plumbing the resolver
// depends on, and that OwnerKey/DisplayName still behave with the new
// fields present.
func TestIdentityCarriesClaimsForAuthz(t *testing.T) {
	t.Parallel()

	id := &Identity{
		Sub:    "sub-1",
		Email:  "user@example.com",
		Name:   "User",
		Groups: []string{"engineering"},
		Roles:  []string{"operator"},
	}
	if got := id.OwnerKey(); got != "user@example.com" {
		t.Errorf("OwnerKey() = %q, want the lowercased email", got)
	}
	if got := id.DisplayName(); got != "User" {
		t.Errorf("DisplayName() = %q, want %q", got, "User")
	}

	// Groups and roles must round-trip through JSON, since the identity is
	// what the session stores.
	blob, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	var back Identity
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal identity: %v", err)
	}
	if strings.Join(back.Groups, ",") != "engineering" || strings.Join(back.Roles, ",") != "operator" {
		t.Errorf("claims did not round-trip: groups=%v roles=%v", back.Groups, back.Roles)
	}

	// An identity with no claims must omit both fields from the wire.
	bare, err := json.Marshal(&Identity{Sub: "s"})
	if err != nil {
		t.Fatalf("marshal bare identity: %v", err)
	}
	if strings.Contains(string(bare), "groups") || strings.Contains(string(bare), "roles") {
		t.Errorf("empty claim lists should be omitted, got %s", bare)
	}
}

func assertList(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v (%d entries), want %v (%d)", label, got, len(got), want, len(want))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", label, i, got[i], want[i])
		}
	}
}
