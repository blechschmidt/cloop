package scim

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func mustDecode(t *testing.T, s string) map[string]any {
	t.Helper()
	obj, err := Decode([]byte(s))
	if err != nil {
		t.Fatalf("Decode(%s): %v", s, err)
	}
	return obj
}

func mustNormalize(t *testing.T, s string, kind Kind) map[string]any {
	t.Helper()
	obj, err := Normalize(mustDecode(t, s), kind)
	if err != nil {
		t.Fatalf("Normalize(%s): %v", s, err)
	}
	return obj
}

func scimErr(t *testing.T, err error) *Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected a SCIM error, got nil")
	}
	se, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	return se
}

// ── filters ─────────────────────────────────────────────────────────────────

func TestFilterProvidersLookups(t *testing.T) {
	user := mustNormalize(t, `{"userName":"Alice@Example.com","externalId":"00uABC",
		"emails":[{"value":"alice@example.com","type":"work","primary":true}],
		"name":{"givenName":"Alice"},"active":true,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Eng"}}`, KindUser)
	cases := []struct {
		filter string
		want   bool
	}{
		// Entra ID and Okta: userName, not case-exact.
		{`userName eq "alice@example.com"`, true},
		{`USERNAME Eq "ALICE@EXAMPLE.COM"`, true},
		{`userName eq "bob@example.com"`, false},
		// externalId is case-exact.
		{`externalId eq "00uABC"`, true},
		{`externalId eq "00uabc"`, false},
		{`emails[type eq "work" and value co "@example.com"]`, true},
		{`emails.value eq "alice@example.com"`, true},
		{`emails eq "alice@example.com"`, true},
		{`name.givenName sw "Ali"`, true},
		{`active eq true`, true},
		{`active eq false`, false},
		{`not (active eq false)`, true},
		{`userName pr and (externalId eq "x" or name.givenName eq "alice")`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "eng"`, true},
		{`title pr`, false},
	}
	for _, c := range cases {
		f, err := ParseFilter(c.filter, KindUser)
		if err != nil {
			t.Errorf("ParseFilter(%s): %v", c.filter, err)
			continue
		}
		if got := f.Matches(user); got != c.want {
			t.Errorf("%s = %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestFilterEqualityIsWhatAStoreCanIndex(t *testing.T) {
	for _, c := range []struct {
		filter, attr, value string
		ok                  bool
	}{
		{`userName eq "Alice"`, "userName", "Alice", true},
		{`username EQ "Alice"`, "userName", "Alice", true},
		{`externalId eq "x"`, "externalId", "x", true},
		{`userName eq "a" or userName eq "b"`, "", "", false},
		{`emails.value eq "a"`, "", "", false},
		{`userName ne "a"`, "", "", false},
		{`nickName eq "x"`, "nickName", "x", true},
	} {
		f, err := ParseFilter(c.filter, KindUser)
		if err != nil {
			t.Fatalf("ParseFilter(%s): %v", c.filter, err)
		}
		attr, value, ok := f.Equality()
		if ok != c.ok || attr != c.attr || value != c.value {
			t.Errorf("%s: Equality() = %q %q %v, want %q %q %v", c.filter, attr, value, ok, c.attr, c.value, c.ok)
		}
	}
}

// TestFilterRefusesWhatItCannotRead: a filter misread as "everything" would
// hand a provider the directory where it asked for one account.
func TestFilterRefusesWhatItCannotRead(t *testing.T) {
	for _, bad := range []string{
		``,
		`userName`,
		`userName eq`,
		`userName equals "x"`,
		`userName eq "unterminated`,
		`(userName eq "x"`,
		`userName eq "x")`,
		`emails[type eq "work"`,
		`userName eq "x" and`,
		`active gt true`,
		`userName eq x`,
		`1bad eq "x"`,
		strings.Repeat("(", 64) + `userName eq "x"` + strings.Repeat(")", 64),
		`userName eq "` + strings.Repeat("a", 5000) + `"`,
	} {
		_, err := ParseFilter(bad, KindUser)
		se := scimErr(t, err)
		if se.Status != http.StatusBadRequest || se.Type != ErrInvalidFilter && se.Type != ErrInvalidPath {
			t.Errorf("ParseFilter(%.40q) = %v, want a 400 invalidFilter", bad, se)
		}
	}
}

// ── normalising ─────────────────────────────────────────────────────────────

func TestNormalizeSpeaksBothDialects(t *testing.T) {
	obj := mustNormalize(t, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"id":"client-chosen","meta":{"resourceType":"User"},
		"UserName":"alice","Active":"False","password":"hunter2",
		"groups":[{"value":"g1"}],
		"emails":[{"Value":"a@example.com","Primary":"True","type":"work"}],
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:user":{"Department":"Eng"},
		"inventedByAValidator":{"x":1}}`, KindUser)
	for _, gone := range []string{"id", "meta", "schemas", "password", "groups"} {
		if _, ok := obj[gone]; ok {
			t.Errorf("%s survived normalising: %v", gone, obj)
		}
	}
	if obj["userName"] != "alice" {
		t.Errorf("userName not canonicalised: %v", obj)
	}
	if obj["active"] != false {
		t.Errorf(`active "False" is not false: %#v`, obj["active"])
	}
	em := obj["emails"].([]any)[0].(map[string]any)
	if em["value"] != "a@example.com" || em["primary"] != true {
		t.Errorf("emails not normalised: %#v", em)
	}
	ext, ok := obj[SchemaEnterpriseUser].(map[string]any)
	if !ok || ext["department"] != "Eng" {
		t.Errorf("enterprise extension not canonicalised: %#v", obj)
	}
	if _, ok := obj["inventedByAValidator"]; !ok {
		t.Error("an attribute nobody defined was dropped; a validator expects it back")
	}

	if _, err := Normalize(mustDecode(t, `{"userName":"a","USERNAME":"b"}`), KindUser); err == nil {
		t.Error("an attribute given twice in different case was accepted")
	}
	if _, err := Normalize(mustDecode(t, `{"userName":"a","active":"maybe"}`), KindUser); err == nil {
		t.Error(`active "maybe" was accepted`)
	}
}

func TestReadUserPicksTheAccountsEmail(t *testing.T) {
	cases := []struct {
		body, want string
	}{
		{`{"userName":"x","emails":[{"value":"Home@x.com","type":"home"},{"value":"Work@x.com","type":"work"},{"value":"P@x.com","primary":true}]}`, "p@x.com"},
		{`{"userName":"x","emails":[{"value":"Home@x.com","type":"home"},{"value":"Work@x.com","type":"work"}]}`, "work@x.com"},
		{`{"userName":"x","emails":[{"value":"Only@x.com"}]}`, "only@x.com"},
		{`{"userName":"Alice@Contoso.onmicrosoft.com"}`, "alice@contoso.onmicrosoft.com"},
		{`{"userName":"alice"}`, ""},
	}
	for _, c := range cases {
		u, err := ReadUser(mustNormalize(t, c.body, KindUser))
		if err != nil {
			t.Fatalf("ReadUser(%s): %v", c.body, err)
		}
		if u.Email != c.want {
			t.Errorf("%s: Email = %q, want %q", c.body, u.Email, c.want)
		}
	}
	u, err := ReadUser(mustNormalize(t, `{"userName":"x"}`, KindUser))
	if err != nil || u.Active != nil {
		t.Errorf("a user that does not say whether it is active read as %v (%v)", u.Active, err)
	}
	if _, err := ReadUser(mustNormalize(t, `{"displayName":"x"}`, KindUser)); err == nil {
		t.Error("a user without userName was accepted")
	}
}

// ── PATCH ───────────────────────────────────────────────────────────────────

func patch(t *testing.T, obj map[string]any, kind Kind, id, body string) error {
	t.Helper()
	ops, err := ParsePatch([]byte(body))
	if err != nil {
		return err
	}
	return ApplyPatch(obj, kind, id, ops)
}

func activeOf(t *testing.T, obj map[string]any) bool {
	t.Helper()
	u, err := ReadUser(obj)
	if err != nil {
		t.Fatal(err)
	}
	if u.Active == nil {
		t.Fatal("active is unset")
	}
	return *u.Active
}

// TestPatchDeactivationInEveryDialect: Entra's non-compliant form, its
// compliant form, the RFC's own, and Okta's.
func TestPatchDeactivationInEveryDialect(t *testing.T) {
	for name, body := range map[string]string{
		"entra legacy":    `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`,
		"entra compliant": `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`,
		"rfc":             `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`,
		"okta":            `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`,
		"lowercase keys":  `{"operations":[{"OP":"REPLACE","PATH":"active","VALUE":"false"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			obj := mustNormalize(t, `{"userName":"alice","active":true}`, KindUser)
			if err := patch(t, obj, KindUser, "u1", body); err != nil {
				t.Fatalf("patch: %v", err)
			}
			if activeOf(t, obj) {
				t.Fatal("the user is still active")
			}
			// And back.
			if err := patch(t, obj, KindUser, "u1",
				strings.NewReplacer("False", "True", "false", "true").Replace(body)); err != nil {
				t.Fatalf("reactivate: %v", err)
			}
			if !activeOf(t, obj) {
				t.Fatal("the user is still inactive")
			}
		})
	}
}

func TestPatchEntraAttributeUpdates(t *testing.T) {
	obj := mustNormalize(t, `{"userName":"alice","name":{"givenName":"A","familyName":"B"},
		"emails":[{"value":"home@x.com","type":"home"}]}`, KindUser)
	// Replacing the work address of a user who has none creates it.
	if err := patch(t, obj, KindUser, "u1", `{"Operations":[
		{"op":"Replace","path":"emails[type eq \"work\"].value","value":"Work@X.com"},
		{"op":"Replace","path":"name.familyName","value":"C"},
		{"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"m-1"},
		{"op":"Replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber","value":"42"}]}`); err != nil {
		t.Fatalf("patch: %v", err)
	}
	u, _ := ReadUser(obj)
	if u.Email != "work@x.com" {
		t.Errorf("work email = %q (emails %v)", u.Email, obj["emails"])
	}
	if obj["name"].(map[string]any)["familyName"] != "C" || obj["name"].(map[string]any)["givenName"] != "A" {
		t.Errorf("name = %v", obj["name"])
	}
	ext := obj[SchemaEnterpriseUser].(map[string]any)
	if ext["manager"] == nil || ext["employeeNumber"] != "42" {
		t.Errorf("enterprise extension = %v", ext)
	}
	// Remove the manager.
	if err := patch(t, obj, KindUser, "u1", `{"Operations":[{"op":"Remove",
		"path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager"}]}`); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj[SchemaEnterpriseUser].(map[string]any)["manager"]; ok {
		t.Error("manager survived its removal")
	}
	// Entra's compliant form: path-less, keys are paths.
	if err := patch(t, obj, KindUser, "u1", `{"Operations":[{"op":"replace","value":{
		"displayName":"Alice B","name.givenName":"Alicia",
		"emails[type eq \"work\"].value":"new@x.com",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":"Ops"}}]}`); err != nil {
		t.Fatalf("compliant patch: %v", err)
	}
	u, _ = ReadUser(obj)
	if u.DisplayName != "Alice B" || u.Email != "new@x.com" ||
		obj["name"].(map[string]any)["givenName"] != "Alicia" ||
		obj[SchemaEnterpriseUser].(map[string]any)["department"] != "Ops" {
		t.Errorf("compliant patch applied wrongly: %v", obj)
	}
}

func TestPatchGroupMembersInEveryDialect(t *testing.T) {
	g := mustNormalize(t, `{"displayName":"eng","members":[{"value":"u1"},{"value":"u2"}]}`, KindGroup)
	steps := []struct {
		body string
		want []string
	}{
		// Entra adds with a $ref of null; a repeat adds nothing.
		{`{"Operations":[{"op":"Add","path":"members","value":[{"$ref":null,"value":"u3"}]}]}`, []string{"u1", "u2", "u3"}},
		{`{"Operations":[{"op":"Add","path":"members","value":[{"value":"u3"}]}]}`, []string{"u1", "u2", "u3"}},
		// Entra's legacy removal names the members to remove in the value —
		// read by the letter of the RFC it would empty the group.
		{`{"Operations":[{"op":"Remove","path":"members","value":[{"$ref":null,"value":"u1"}]}]}`, []string{"u2", "u3"}},
		// The compliant and Okta form: a value path.
		{`{"Operations":[{"op":"remove","path":"members[value eq \"u2\"]"}]}`, []string{"u3"}},
		// Removing somebody who is not a member — a retry, or a reorder.
		{`{"Operations":[{"op":"remove","path":"members[value eq \"u9\"]"}]}`, []string{"u3"}},
		// Okta's add.
		{`{"Operations":[{"op":"add","path":"members","value":[{"value":"u4","display":"d@x.com"}]}]}`, []string{"u3", "u4"}},
		// A replace of the whole list.
		{`{"Operations":[{"op":"replace","path":"members","value":[{"value":"u5"}]}]}`, []string{"u5"}},
	}
	for i, st := range steps {
		if err := patch(t, g, KindGroup, "g1", st.body); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if got := MemberIDs(g); !reflect.DeepEqual(got, st.want) {
			t.Fatalf("step %d: members %v, want %v", i, got, st.want)
		}
	}
	// Okta renames repeating the group's own id; another id is refused.
	if err := patch(t, g, KindGroup, "g1", `{"Operations":[{"op":"replace","value":{"id":"g1","displayName":"platform"}}]}`); err != nil {
		t.Fatalf("Okta rename: %v", err)
	}
	if gf, _ := ReadGroup(g); gf.DisplayName != "platform" {
		t.Errorf("rename did not apply: %v", g)
	}
	se := scimErr(t, patch(t, g, KindGroup, "g1", `{"Operations":[{"op":"replace","value":{"id":"other"}}]}`))
	if se.Type != ErrMutability {
		t.Errorf("changing id: %v", se)
	}
}

func TestPatchRefusals(t *testing.T) {
	user := func() map[string]any { return mustNormalize(t, `{"userName":"alice"}`, KindUser) }
	for _, c := range []struct {
		body, typ string
	}{
		{`{"Operations":[{"op":"remove"}]}`, ErrNoTarget},
		{`{"Operations":[{"op":"move","path":"x"}]}`, ErrInvalidSyntax},
		{`{"Operations":[]}`, ErrInvalidSyntax},
		{`{"schemas":[]}`, ErrInvalidSyntax},
		{`{"Operations":[{"op":"replace","path":"id","value":"x"}]}`, ErrMutability},
		{`{"Operations":[{"op":"add","path":"groups","value":[{"value":"g"}]}]}`, ErrMutability},
		{`{"Operations":[{"op":"replace","path":"active","value":"perhaps"}]}`, ErrInvalidValue},
		{`{"Operations":[{"op":"replace","path":"emails[type eq \"work\"","value":"x"}]}`, ErrInvalidPath},
		{`{"Operations":[{"op":"replace","path":"userName"}]}`, ErrInvalidValue},
	} {
		se := scimErr(t, patch(t, user(), KindUser, "u1", c.body))
		if se.Type != c.typ {
			t.Errorf("%s: got %v, want %s", c.body, se, c.typ)
		}
	}
	// A password is accepted and discarded.
	obj := user()
	if err := patch(t, obj, KindUser, "u1", `{"Operations":[{"op":"replace","value":{"password":"hunter2"}}]}`); err != nil {
		t.Fatalf("a password change was refused: %v", err)
	}
	if strings.Contains(Describe(obj), "hunter2") {
		t.Fatalf("a password was stored: %v", obj)
	}
}

// ── rendering, paging, projection ───────────────────────────────────────────

func TestRenderAndProject(t *testing.T) {
	stored := mustNormalize(t, `{"userName":"alice","name":{"givenName":"A","familyName":"B"},
		"emails":[{"value":"a@x.com","type":"work"}],
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Eng"}}`, KindUser)
	res := Render(stored, KindUser, "u1", Meta{Version: 3, Location: "https://hub/scim/v2/Users/u1"})
	if res["id"] != "u1" {
		t.Fatalf("id = %v", res["id"])
	}
	if got := res["schemas"].([]any); len(got) != 2 || got[1] != SchemaEnterpriseUser {
		t.Errorf("schemas = %v", got)
	}
	meta := res["meta"].(map[string]any)
	if meta["version"] != `W/"3"` || meta["resourceType"] != "User" {
		t.Errorf("meta = %v", meta)
	}
	if _, ok := stored["id"]; ok {
		t.Error("Render wrote into the stored object")
	}

	p, err := ParseProjection(url.Values{"attributes": {"emails.value,name.givenName"}}, KindUser)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Apply(res, KindUser)
	if _, ok := got["userName"]; !ok {
		t.Error("userName is always returned")
	}
	if got["name"].(map[string]any)["familyName"] != nil {
		t.Errorf("projection kept familyName: %v", got)
	}
	if _, ok := got[SchemaEnterpriseUser]; ok {
		t.Errorf("projection kept the extension: %v", got)
	}
	p, _ = ParseProjection(url.Values{"excludedAttributes": {"emails,userName"}}, KindUser)
	got = p.Apply(res, KindUser)
	if _, ok := got["emails"]; ok {
		t.Error("emails was not excluded")
	}
	if _, ok := got["userName"]; !ok {
		t.Error("userName cannot be excluded")
	}
}

func TestParsePage(t *testing.T) {
	for _, c := range []struct {
		q          string
		start, cnt int
	}{
		{"", 1, DefaultPageSize},
		{"startIndex=0&count=-5", 1, 0},
		{"startIndex=3&count=10", 3, 10},
		{"count=100000", 1, MaxPageSize},
	} {
		q, _ := url.ParseQuery(c.q)
		p, err := ParsePage(q)
		if err != nil || p.StartIndex != c.start || p.Count != c.cnt {
			t.Errorf("%q: %+v %v", c.q, p, err)
		}
	}
	if _, err := ParsePage(url.Values{"count": {"ten"}}); err == nil {
		t.Error("a non-numeric count was accepted")
	}
	items := []int{1, 2, 3, 4, 5}
	if got := Paginate(items, Page{StartIndex: 4, Count: 10}); !reflect.DeepEqual(got, []int{4, 5}) {
		t.Errorf("Paginate = %v", got)
	}
	if got := Paginate(items, Page{StartIndex: 9, Count: 10}); len(got) != 0 {
		t.Errorf("past the end = %v", got)
	}
}

func TestErrorDocument(t *testing.T) {
	b, err := json.Marshal(Conflict("userName %q is taken", "alice"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	if doc["status"] != "409" || doc["scimType"] != "uniqueness" ||
		doc["schemas"].([]any)[0] != SchemaError {
		t.Errorf("error document = %s", b)
	}
	if !MatchesETag(`W/"4"`, 4) || !MatchesETag(`"4", W/"5"`, 5) || MatchesETag(`W/"4"`, 5) || !MatchesETag("", 9) {
		t.Error("ETag matching is wrong")
	}
}

func TestDiscoveryDocumentsDescribeTheHub(t *testing.T) {
	spc := ServiceProviderConfig("https://hub.example.com/scim/v2/")
	if spc["patch"].(map[string]any)["supported"] != true || spc["bulk"].(map[string]any)["supported"] != false {
		t.Errorf("ServiceProviderConfig = %v", spc)
	}
	if loc := spc["meta"].(map[string]any)["location"]; loc != "https://hub.example.com/scim/v2/ServiceProviderConfig" {
		t.Errorf("location = %v", loc)
	}
	if _, ok := FindByID(ResourceTypes("x"), "user"); !ok {
		t.Error("no User resource type")
	}
	if d, ok := FindByID(Schemas("x"), SchemaEnterpriseUser); !ok || d["name"] != "EnterpriseUser" {
		t.Error("no enterprise schema")
	}
	b, err := json.Marshal(Schemas("x"))
	if err != nil || !strings.Contains(string(b), `"caseExact":true`) {
		t.Errorf("schemas do not marshal: %v", err)
	}
}
