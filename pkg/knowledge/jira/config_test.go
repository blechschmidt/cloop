package jira

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
	cloud := map[string]any{"base_url": "https://corp.atlassian.net", "email": "bot@corp.example", "jql": "project = ENG"}
	dc := map[string]any{"deployment": "datacenter", "base_url": "https://jira.corp.example/jira", "projects": []string{"eng", "OPS"}}
	gateway := map[string]any{"base_url": "https://api.atlassian.com/ex/jira/0a1b2c3d-9e8f-4a5b-8c7d-6e5f4a3b2c1d",
		"jql": "project = ENG"}
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
	cases := []struct {
		name    string
		config  map[string]any
		scope   string
		wantErr string
		check   func(t *testing.T, s settings)
	}{
		{name: "cloud, inferred from the host, email and token", config: cloud, check: func(t *testing.T, s settings) {
			if !s.cloud() || s.gateway() || s.auth != AuthBasic || s.base.String() != "https://corp.atlassian.net" ||
				s.api() != "/rest/api/3" || s.scopeJQL() != "(project = ENG)" {
				t.Fatalf("settings = %+v", s)
			}
		}},
		{name: "a trailing slash is dropped", config: with(cloud, "base_url", "https://CORP.atlassian.net/"),
			check: func(t *testing.T, s settings) {
				if s.base.String() != "https://corp.atlassian.net" {
					t.Fatalf("base = %s", s.base)
				}
			}},
		{name: "the API gateway, OAuth bearer", config: gateway, check: func(t *testing.T, s settings) {
			if !s.cloud() || !s.gateway() || s.auth != AuthBearer {
				t.Fatalf("settings = %+v", s)
			}
		}},
		{name: "the API gateway, a scoped API token", config: with(gateway, "email", "bot@corp.example")},
		{name: "data center, projects", config: dc, check: func(t *testing.T, s settings) {
			if s.cloud() || s.auth != AuthBearer || s.api() != "/rest/api/2" || s.scopeJQL() != `(project in ("ENG", "OPS"))` {
				t.Fatalf("settings = %+v", s)
			}
		}},
		{name: "server reads as data center", config: with(dc, "deployment", "server")},
		{name: "an org data center source on a private address", config: with(dc, "base_url", "https://10.0.0.9/jira"),
			check: func(t *testing.T, s settings) {
				if !s.policy.AllowPrivate {
					t.Fatal("an org data center source may not reach its own network")
				}
			}},
		{name: "secured issues, by choice", config: with(dc, "include_secured", true), check: func(t *testing.T, s settings) {
			if !s.includeSecured {
				t.Fatal("include_secured was dropped")
			}
		}},

		{name: "http", config: with(dc, "base_url", "http://jira.corp.example"), wantErr: "must be https"},
		{name: "a password in the URL", config: with(dc, "base_url", "https://bot:hunter2@jira.corp.example"), wantErr: "user name or password"},
		{name: "a query in the URL", config: with(dc, "base_url", "https://jira.corp.example/?os_authType=basic"), wantErr: "query"},
		{name: "a Cloud URL with a path", config: with(cloud, "base_url", "https://corp.atlassian.net/wiki"), wantErr: "the site itself"},
		{name: "a gateway URL that is not Jira's", config: with(gateway, "base_url", "https://api.atlassian.com/ex/confluence/abc"),
			wantErr: "/ex/jira/<cloud id>"},
		{name: "Cloud called data center", config: with(cloud, "deployment", "datacenter", "email", nil), wantErr: "is Jira Cloud"},
		{name: "an unknown host, no deployment", config: with(dc, "deployment", nil), wantErr: "say which it is"},
		{name: "an unknown deployment", config: with(dc, "deployment", "onprem"), wantErr: "not \"onprem\""},
		{name: "a misspelt key", config: with(dc, "project", "ENG"), wantErr: "unknown field"},
		{name: "basic without an email", config: with(cloud, "email", nil, "auth", "basic"), wantErr: "set email"},
		{name: "basic on data center", config: with(dc, "email", "bot@corp.example"), wantErr: "personal access token"},
		{name: "an email with bearer", config: with(cloud, "auth", "bearer"), wantErr: "only for basic auth"},
		{name: "an email that is not one", config: with(cloud, "email", "bot at corp"), wantErr: "not an email address"},
		{name: "no scope", config: with(dc, "projects", nil), wantErr: "scope the source"},
		{name: "both scopes", config: with(dc, "jql", "project = ENG"), wantErr: "not both"},
		{name: "a project key that is not one", config: with(dc, "projects", []string{`ENG") OR (project = "HR`}), wantErr: "not a project key"},
		{name: "an unbalanced query", config: with(cloud, "jql", "project = ENG) OR (project = HR"), wantErr: "closes nothing"},
		{name: "a query that orders itself", config: with(cloud, "jql", "project = ENG ORDER BY created"), wantErr: "ORDER BY"},
		{name: "a query too long", config: with(cloud, "jql", "summary ~ \""+strings.Repeat("x", 2100)+"\""), wantErr: "at most"},
		{name: "this machine", config: with(dc, "base_url", "https://localhost:8443"), wantErr: "this machine"},
		{name: "a metadata service", config: with(dc, "base_url", "https://169.254.169.254"), wantErr: "metadata"},
		{name: "a personal source on a private address", config: with(dc, "base_url", "https://10.0.0.9"),
			scope: knowledge.ScopePersonal, wantErr: "private address"},
		{name: "a Cloud source on a private address", config: with(cloud, "deployment", "cloud", "base_url", "https://10.0.0.9"),
			wantErr: "private address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := tc.scope
			if scope == "" {
				scope = knowledge.ScopeOrg
			}
			s, err := c.parseConfig(mustJSON(tc.config), scope)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("parse: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("parse = %v, want an error with %q", err, tc.wantErr)
			case tc.wantErr == "" && tc.check != nil:
				tc.check(t, s)
			}
		})
	}
	if _, err := c.parseConfig(json.RawMessage(`{"base_url":"https://corp.atlassian.net","jql":"x"} {}`), knowledge.ScopeOrg); err == nil {
		t.Fatal("two objects were taken for one configuration")
	}
}

// TestValidateGoesThroughTheFramework: Validate and ValidateQuery are what
// pkg/knowledge asks before a source or a binding is stored.
func TestValidateGoesThroughTheFramework(t *testing.T) {
	c := New(Options{})
	err := c.Validate(knowledge.ValidateRequest{Scope: knowledge.ScopePersonal,
		Config: mustJSON(map[string]any{"deployment": "datacenter", "base_url": "https://10.0.0.9", "projects": []string{"ENG"}})})
	if err == nil || !strings.Contains(err.Error(), "private address") {
		t.Fatalf("validate a personal source on a private address = %v", err)
	}
	for q, want := range map[string]string{
		"labels = x ORDER BY created": "ORDER BY", "(labels = x": "never closed", "  ": "required",
	} {
		if err := c.ValidateQuery(nil, q); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateQuery(%q) = %v, want %q", q, err, want)
		}
	}
	if err := c.ValidateQuery(nil, `labels = "runbook" AND component = Web`); err != nil {
		t.Fatalf("a binding query = %v", err)
	}
}
