package ui

// Recorded identity-provider conversations, replayed against a real hub (Task
// 20415).
//
// testdata/scim holds the request sequences Microsoft Entra ID's provisioning
// service, its SCIM Validator, and Okta send a SCIM application — each request
// as the provider writes it, quirks included, and what the provider needs back.
// A replay is the compatibility claim in executable form: every step is sent
// with the hub's SCIM credential, and its status, the parts of its body the
// provider reads, the attributes that must never come back (a password), and
// the deny bindings the hub must or must not hold afterwards are checked.
//
// Placeholders {{name}} are filled from earlier responses (capture), so the
// sequences carry no ids of their own.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type scimReplay struct {
	Name       string           `json:"name"`
	Source     string           `json:"source"`
	MatchClaim string           `json:"match_claim"`
	Steps      []scimReplayStep `json:"steps"`
}

type scimReplayStep struct {
	Name   string            `json:"name"`
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Header map[string]string `json:"header"`
	Body   json.RawMessage   `json:"body"`
	Status int               `json:"status"`
	// Expect is a subset of the response body: every key given must be
	// there with that value; a list must match element by element as far
	// as it goes, and an empty list must be empty.
	Expect json.RawMessage `json:"expect"`
	// Absent are slash-separated paths that must not be in the response.
	Absent []string `json:"absent"`
	// Capture names a value from the response for later steps.
	Capture map[string]string `json:"capture"`
	// Denies and NoDenies are claim=value deny bindings the hub must, and
	// must not, hold after the step.
	Denies   []string `json:"denies"`
	NoDenies []string `json:"noDenies"`
}

func TestSCIM_ReplaysRecordedProvisioningSequences(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "scim", "*.json"))
	if err != nil || len(files) < 3 {
		t.Fatalf("recorded sequences: %v %v", files, err)
	}
	for _, file := range files {
		file := file
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var seq scimReplay
		if err := json.Unmarshal(raw, &seq); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			f := newSCIMFixtureWith(t, authz.Config{}, config.SCIMConfig{MatchClaim: seq.MatchClaim})
			vars := map[string]string{}
			fill := func(s string) string {
				for k, v := range vars {
					s = strings.ReplaceAll(s, "{{"+k+"}}", v)
				}
				return s
			}
			for i, st := range seq.Steps {
				label := fmt.Sprintf("step %d %q", i+1, st.Name)
				hdr := bearerHeader(f.token)
				for k, v := range st.Header {
					hdr.Set(k, v)
				}
				body := ""
				if len(st.Body) > 0 {
					body = fill(string(st.Body))
				}
				status, got, _ := f.scimDo(t, st.Method, fill(st.Path), body, hdr)
				if status != st.Status {
					t.Fatalf("%s: %s %s answered %d, want %d: %v", label, st.Method, fill(st.Path), status, st.Status, got)
				}
				if len(st.Expect) > 0 {
					var want any
					if err := json.Unmarshal([]byte(fill(string(st.Expect))), &want); err != nil {
						t.Fatalf("%s: expect: %v", label, err)
					}
					if diffs := subsetDiff("", want, any(got)); len(diffs) > 0 {
						t.Fatalf("%s: the response differs from what the provider reads:\n  %s\nresponse: %v",
							label, strings.Join(diffs, "\n  "), got)
					}
				}
				for _, p := range st.Absent {
					if _, found := atPath(got, p); found {
						t.Fatalf("%s: %s is in the response: %v", label, p, got)
					}
				}
				for name, p := range st.Capture {
					v, found := atPath(got, p)
					s, isString := v.(string)
					if !found || !isString || s == "" {
						t.Fatalf("%s: nothing to capture at %s: %v", label, p, got)
					}
					vars[name] = s
				}
				if len(st.Denies) > 0 || len(st.NoDenies) > 0 {
					denies := f.denyBindings(t)
					for _, d := range st.Denies {
						if !denies[d] {
							t.Fatalf("%s: no deny binding %s; the hub holds %v", label, d, denies)
						}
					}
					for _, d := range st.NoDenies {
						if denies[d] {
							t.Fatalf("%s: deny binding %s is still in force", label, d)
						}
					}
				}
			}
		})
	}
}

// denyBindings is every deny binding in force, as claim=value.
func (f *scimFixture) denyBindings(t *testing.T) map[string]bool {
	t.Helper()
	db, closer, err := f.srv.openControlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	rows, err := db.ListRoleBindings()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r.Effect == statedb.RoleEffectDeny {
			out[r.Claim+"="+r.Value] = true
		}
	}
	return out
}

// subsetDiff reports where got does not contain want.
func subsetDiff(path string, want, got any) []string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want an object, got %v", orRoot(path), got)}
		}
		var out []string
		for k, wv := range w {
			gv, present := g[k]
			if !present {
				out = append(out, fmt.Sprintf("%s/%s: missing", path, k))
				continue
			}
			out = append(out, subsetDiff(path+"/"+k, wv, gv)...)
		}
		return out
	case []any:
		g, ok := got.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want a list, got %v", orRoot(path), got)}
		}
		if len(w) == 0 && len(g) != 0 {
			return []string{fmt.Sprintf("%s: want an empty list, got %v", orRoot(path), g)}
		}
		if len(g) < len(w) {
			return []string{fmt.Sprintf("%s: want at least %d elements, got %d: %v", orRoot(path), len(w), len(g), g)}
		}
		var out []string
		for i := range w {
			out = append(out, subsetDiff(path+"/"+strconv.Itoa(i), w[i], g[i])...)
		}
		return out
	}
	if !reflect.DeepEqual(want, got) {
		return []string{fmt.Sprintf("%s: want %v, got %v", orRoot(path), want, got)}
	}
	return nil
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// atPath reads a slash-separated path: object keys and list indexes.
func atPath(v any, path string) (any, bool) {
	cur := v
	for _, part := range strings.Split(path, "/") {
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// TestSCIM_ReplayTheRecordedDialects names each provider quirk the corpus
// carries, so deleting one from a recording fails here rather than quietly
// narrowing what the replay proves.
func TestSCIM_ReplayCorpusCarriesEachQuirk(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("testdata", "scim", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	entra, validator, okta := read("entra-provisioning.json"), read("entra-validator.json"), read("okta-provisioning.json")
	for what, quirk := range map[string]struct{ in, needle string }{
		"Entra's string False":            {entra, `"value": "False"`},
		"Entra's capitalised ops":         {entra, `"op": "Replace"`},
		"Entra's member removal by value": {entra, `"op": "Remove", "path": "members", "value": [`},
		"Entra's ADSCIM group schema":     {entra, `ADSCIM/2.0/Group`},
		"Entra's path-keyed replace":      {entra, `"name.givenName":`},
		"Entra's manager as a bare id":    {entra, `"value": "OriginalManagerId"`},
		"the validator's invented fields": {validator, `"nickName"`},
		"the validator's filtered add":    {validator, `phoneNumbers[type eq \"mobile\"].value`},
		"the validator's attributes=":     {validator, `?attributes=`},
		"Okta's password":                 {okta, `"password"`},
		"Okta's path-less deactivation":   {okta, `"value": {"active": false}`},
		"Okta's PUT deactivation":         {okta, `"active": false` + "\n      },"},
		"Okta's id-repeating rename":      {okta, `"value": {"id": "{{group}}"`},
	} {
		if !strings.Contains(quirk.in, quirk.needle) {
			t.Errorf("the corpus no longer carries %s (%s)", what, quirk.needle)
		}
	}
}
