package confluence

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/knowledge"
)

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// TestConfigValidation: what a configuration may say, for the production
// connector — https only, nothing it can be talked into reaching it should
// not — and what each refusal tells the person who wrote it.
func TestConfigValidation(t *testing.T) {
	c := New(Options{})
	cloud := map[string]any{"base_url": "https://corp.atlassian.net/wiki", "email": "bot@corp.example", "spaces": []string{"ENG"}}
	with := func(base map[string]any, kv ...any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(out, kv[i].(string))
				continue
			}
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	dc := map[string]any{"deployment": "datacenter", "base_url": "https://wiki.corp.example/confluence", "cql": `label = "kb"`}
	cases := []struct {
		name    string
		config  map[string]any
		scope   string
		wantErr string
		check   func(t *testing.T, s settings)
	}{
		{name: "cloud, inferred from the host, email and token", config: cloud, check: func(t *testing.T, s settings) {
			if s.deployment != DeploymentCloud || s.auth != AuthBasic || !s.v2() || s.base.String() != "https://corp.atlassian.net/wiki" {
				t.Fatalf("settings = %+v", s)
			}
		}},
		{name: "cloud base without /wiki gets it", config: with(cloud, "base_url", "https://corp.atlassian.net/"),
			check: func(t *testing.T, s settings) {
				if s.base.Path != "/wiki" {
					t.Fatalf("path = %q", s.base.Path)
				}
			}},
		{name: "cloud through the OAuth gateway, bearer", config: map[string]any{
			"base_url": "https://api.atlassian.com/ex/confluence/1a2b3c4d-0000-1111-2222-333344445555/wiki", "cql": "space = ENG"},
			check: func(t *testing.T, s settings) {
				if s.auth != AuthBearer || s.v2() || !s.cloud() {
					t.Fatalf("settings = %+v", s)
				}
			}},
		{name: "datacenter with a context path and a CQL scope", config: dc, check: func(t *testing.T, s settings) {
			if s.deployment != DeploymentDataCenter || s.auth != AuthBearer || s.base.Path != "/confluence" || s.cql == "" {
				t.Fatalf("settings = %+v", s)
			}
		}},
		{name: "server reads as datacenter", config: with(dc, "deployment", "Server"), check: func(t *testing.T, s settings) {
			if s.deployment != DeploymentDataCenter {
				t.Fatalf("deployment = %q", s.deployment)
			}
		}},
		{name: "no base url", config: with(cloud, "base_url", nil), wantErr: "base_url is required"},
		{name: "http", config: with(cloud, "base_url", "http://corp.atlassian.net/wiki"), wantErr: "must be https"},
		{name: "credentials in the url", config: with(cloud, "base_url", "https://bot:hunter2@corp.atlassian.net/wiki"),
			wantErr: "may not hold a user name or password"},
		{name: "a query in the url", config: with(cloud, "base_url", "https://corp.atlassian.net/wiki?x=1"), wantErr: "query"},
		{name: "dot dot", config: with(dc, "base_url", "https://wiki.corp.example/a/../confluence"), wantErr: ". or .."},
		{name: "a cloud url that is a page", config: with(cloud, "base_url", "https://corp.atlassian.net/wiki/spaces/ENG"),
			wantErr: "the site's /wiki"},
		{name: "an unknown host needs a deployment", config: with(dc, "deployment", nil), wantErr: "not an Atlassian Cloud address"},
		{name: "an unknown deployment", config: with(dc, "deployment", "onprem"), wantErr: "not \"onprem\""},
		{name: "an unknown key", config: with(cloud, "space", "ENG"), wantErr: "unknown field"},
		{name: "neither spaces nor cql", config: with(cloud, "spaces", nil), wantErr: "scope the source"},
		{name: "both spaces and cql", config: with(cloud, "cql", "space = ENG"), wantErr: "not both"},
		{name: "a space key with a quote", config: with(cloud, "spaces", []string{`ENG") or ("x`}), wantErr: "not a space key"},
		{name: "too many spaces", config: with(cloud, "spaces", manyKeys(maxSpaces+1)), wantErr: "at most 100 spaces"},
		{name: "personal space keys are keys", config: with(cloud, "spaces", []string{"~557058:0f3a", "~jsmith"})},
		{name: "cql with order by", config: with(dc, "cql", "label = kb ORDER BY title"), wantErr: "ORDER BY"},
		{name: "cql that closes the connector's parenthesis", config: with(dc, "cql", `label = kb) or (space = HR`),
			wantErr: "closes nothing"},
		{name: "cql with an open quote", config: with(dc, "cql", `title ~ "plan`), wantErr: "never closed"},
		{name: "a parenthesis in a string is text", config: with(dc, "cql", `title ~ "plan (draft"`)},
		{name: "basic without an email", config: with(cloud, "email", nil, "auth", "basic"), wantErr: "set email"},
		{name: "basic on datacenter", config: with(dc, "email", "a@b.example", "auth", "basic"), wantErr: "personal access token"},
		{name: "bearer with an email", config: with(cloud, "auth", "bearer"), wantErr: "only for basic auth"},
		{name: "a malformed email", config: with(cloud, "email", "bot at corp"), wantErr: "not an email address"},
		{name: "an unknown auth", config: with(cloud, "auth", "ntlm"), wantErr: "not \"ntlm\""},
		{name: "localhost", config: with(dc, "base_url", "https://localhost:8090"), scope: knowledge.ScopeOrg,
			wantErr: "this machine"},
		{name: "loopback", config: with(dc, "base_url", "https://127.0.0.1:8090"), scope: knowledge.ScopeOrg,
			wantErr: "loopback"},
		{name: "loopback in IPv6 clothing", config: with(dc, "base_url", "https://[::ffff:127.0.0.1]:8090"),
			scope: knowledge.ScopeOrg, wantErr: "loopback"},
		{name: "the metadata service", config: with(dc, "base_url", "https://169.254.169.254"), scope: knowledge.ScopeOrg,
			wantErr: "metadata"},
		{name: "a private address for an org's data center", config: with(dc, "base_url", "https://10.20.0.5/confluence"),
			scope: knowledge.ScopeOrg},
		{name: "a private address for a personal source", config: with(dc, "base_url", "https://10.20.0.5/confluence"),
			scope: knowledge.ScopePersonal, wantErr: "private address"},
		{name: "a private address for a cloud source", config: map[string]any{"deployment": "cloud",
			"base_url": "https://192.168.1.10/wiki", "cql": "space = ENG"}, scope: knowledge.ScopeOrg, wantErr: "private address"},
		{name: "carrier-grade NAT for a personal source", config: with(dc, "base_url", "https://100.100.1.1"),
			scope: knowledge.ScopePersonal, wantErr: "private address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := tc.scope
			if scope == "" {
				scope = knowledge.ScopeOrg
			}
			s, err := c.parseConfig(mustJSON(tc.config), scope)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("config = %v, want an error naming %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("config = %v", err)
			}
			if tc.check != nil {
				tc.check(t, s)
			}
		})
	}
}

func manyKeys(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "K" + strings.Repeat("X", i%5) + string(rune('A'+i%26)) + string(rune('A'+i/26))
	}
	return out
}

// TestValidateGoesThroughTheFramework: the framework's own refusal of a
// credential in a configuration stands in front of the connector's checks,
// and the connector's are reported as invalid input.
func TestValidateGoesThroughTheFramework(t *testing.T) {
	c := New(Options{})
	err := c.Validate(knowledge.ValidateRequest{Scope: knowledge.ScopePersonal,
		Config: mustJSON(map[string]any{"deployment": "datacenter", "base_url": "https://10.0.0.9", "spaces": []string{"ENG"}})})
	if err == nil || !strings.Contains(err.Error(), "private address") {
		t.Fatalf("validate a personal source on a private address = %v", err)
	}
	if err := c.ValidateQuery(nil, "label = x ORDER BY created"); err == nil {
		t.Fatal("a binding query with ORDER BY validated")
	}
	if err := c.ValidateQuery(nil, `label = "kb" and space = ENG`); err != nil {
		t.Fatalf("a binding query = %v", err)
	}
}
