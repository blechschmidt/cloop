package atlassian

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestTheDialerChecksTheAddressItConnectsTo: whatever name a source
// configured, the connection itself is refused at an address the policy
// forbids — the defence against a name that resolves, or is rebound, to one.
// Every Atlassian connector dials through this one check.
func TestTheDialerChecksTheAddressItConnectsTo(t *testing.T) {
	cases := []struct {
		addr   string
		policy Policy
		want   string
	}{
		{addr: "127.0.0.1:443", want: "loopback"},
		{addr: "[::1]:443", want: "loopback"},
		{addr: "[::ffff:127.0.0.1]:443", want: "loopback"},
		{addr: "[64:ff9b::7f00:1]:443", want: "loopback"},
		{addr: "169.254.169.254:80", want: "metadata"},
		{addr: "[fd00:ec2::254]:80", policy: Policy{AllowPrivate: true}, want: "metadata"},
		{addr: "100.100.100.200:80", policy: Policy{AllowPrivate: true}, want: "metadata"},
		{addr: "[fe80::1%25eth0]:443", want: "link-local"},
		{addr: "0.0.0.0:443", want: "unspecified"},
		{addr: "224.0.0.1:443", want: "multicast"},
		{addr: "10.1.2.3:443", want: "private"},
		{addr: "100.64.0.9:443", want: "private"},
		{addr: "[fd12::1]:443", want: "private"},
		{addr: "10.1.2.3:443", policy: Policy{AllowPrivate: true}},
		{addr: "104.192.141.1:443"},
		{addr: "wiki.corp.example:443", want: "not an IP address"},
	}
	for _, tc := range cases {
		err := CheckDialAddress(strings.Replace(tc.addr, "%25", "%", 1), tc.policy)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.addr, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, ErrBlockedAddress)):
			t.Errorf("%s = %v, want a refusal naming %q", tc.addr, err, tc.want)
		}
	}

	// And on a real connection: the production transport, asked to reach a
	// server on loopback, refuses before a byte is sent — for a GET and for
	// the POST a Jira search is.
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(srv.Close)
	cl, err := NewClient(Config{Product: "jira", Base: mustURL(t, srv.URL), Auth: AuthBearer},
		knowledge.NewCredential([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	for _, call := range []func() error{
		func() error { return cl.Get(context.Background(), "/rest/api/space", &v) },
		func() error {
			return cl.Post(context.Background(), "/rest/api/2/search", map[string]any{"jql": "x"}, &v)
		},
	} {
		err := call()
		if !errors.Is(err, ErrBlockedAddress) || !strings.Contains(err.Error(), "loopback") || hits != 0 {
			t.Fatalf("a request to loopback = %v (%d reached the server)", err, hits)
		}
	}
	if addr, perr := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "https://")); perr != nil || !addr.Addr().IsLoopback() {
		t.Fatalf("the test server is not on loopback: %s", srv.URL)
	}
}

// TestHostsAreCheckedAsWritten: a configuration naming this machine, or an
// address literal the policy forbids, is refused before anything resolves.
func TestHostsAreCheckedAsWritten(t *testing.T) {
	for host, want := range map[string]string{
		"localhost": "this machine", "api.localhost": "this machine", "127.0.0.1": "loopback",
		"169.254.169.254": "metadata", "10.0.0.8": "private", "::1": "loopback",
	} {
		if err := (Policy{}).CheckHost(host); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("host %s = %v, want %q", host, err, want)
		}
	}
	for _, host := range []string{"corp.atlassian.net", "jira.corp.example", "104.192.141.1"} {
		if err := (Policy{}).CheckHost(host); err != nil {
			t.Errorf("host %s: %v", host, err)
		}
	}
	if err := (Policy{AllowPrivate: true}).CheckHost("10.0.0.8"); err != nil {
		t.Errorf("a private address for an org Data Center source: %v", err)
	}
	if err := (Policy{Insecure: true}).CheckHost("127.0.0.1"); err != nil {
		t.Errorf("the test policy: %v", err)
	}
}

// TestErrorMessage: a refusal's own words, in each product's error body.
func TestErrorMessage(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"statusCode":400,"message":"Could not parse cql : x"}`, "Could not parse cql : x"},
		{`{"errors":[{"title":"Invalid","detail":"limit must be positive"}]}`, "Invalid limit must be positive"},
		{`{"data":{"errors":[{"message":{"translation":"No space","key":"k"}}]}}`, "No space"},
		{`{"errorMessages":["Error in the JQL Query: Expecting ')' before the end of the query."],"errors":{}}`,
			"Error in the JQL Query: Expecting ')' before the end of the query."},
		{`{"errorMessages":[],"errors":{"jql":"The value 'NOPE' does not exist for the field 'project'.","b":"x"}}`,
			"b: x; jql: The value 'NOPE' does not exist for the field 'project'."},
		{"plain text refusal", "plain text refusal"},
		{"<html><body>Bad gateway</body></html>", ""},
		{`{"message": "` + strings.Repeat("long ", 200) + `"}`, "…"},
	}
	for _, c := range cases {
		got := ErrorMessage(strings.NewReader(c.body))
		if !strings.Contains(got, c.want) || (c.want == "" && got != "") {
			t.Errorf("ErrorMessage(%.60q) = %q, want %q", c.body, got, c.want)
		}
		if len(got) > 404 {
			t.Errorf("ErrorMessage is not bounded: %d bytes", len(got))
		}
	}
}

// TestCheckQuery: a query that would escape the parentheses a connector wraps
// it in, or order the listing itself, is refused before it is stored.
func TestCheckQuery(t *testing.T) {
	for _, q := range []string{
		`project = ENG`, `project in ("ENG", "OPS") AND labels = "a)b"`, `summary ~ "\"quoted\" (x"`,
		"project = ENG\nAND status = Done", `text ~ 'it''s'`,
	} {
		if err := CheckQuery(q, 2048); err != nil {
			t.Errorf("CheckQuery(%q): %v", q, err)
		}
	}
	for q, want := range map[string]string{
		`project = ENG) OR (project = HR`: "closes nothing",
		`(project = ENG`:                  "never closed",
		`summary ~ "open`:                 "never closed",
		`project = ENG ORDER BY created`:  "ORDER BY",
		`project = ENG order  by key`:     "ORDER BY",
		"project = ENG\x00":               "control",
		strings.Repeat("a", 2049):         "at most",
		"project = \xff":                  "UTF-8",
	} {
		if err := CheckQuery(q, 2048); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckQuery(%.40q) = %v, want %q", q, err, want)
		}
	}
	if got := OneLineQuery("a\n\tb\r\nc"); got != "a b c" {
		t.Errorf("OneLineQuery = %q", got)
	}
}

// TestPostSendsJSONAndRetries: a POST read sends its body as JSON on every
// attempt, is retried like a GET, and its refusal names the method.
func TestPostSendsJSONAndRetries(t *testing.T) {
	var bodies []string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.Method+" "+r.Header.Get("Content-Type")+" "+string(b))
		switch calls {
		case 1:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errorMessages":["Error in the JQL Query"]}`))
		}
	}))
	t.Cleanup(srv.Close)
	var waits []time.Duration
	cl, err := NewClient(Config{Product: "jira", Base: mustURL(t, srv.URL), Auth: AuthBearer, Retries: 3,
		Policy: Policy{Insecure: true}, Sleep: func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		}}, knowledge.NewCredential([]byte("tok")))
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ OK bool }
	if err := cl.Post(context.Background(), "/rest/api/3/search/jql", map[string]any{"jql": "project = ENG"}, &v); err != nil || !v.OK {
		t.Fatalf("post = %v, %+v", err, v)
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] || !strings.HasPrefix(bodies[0], `POST application/json {"jql":"project = ENG"}`) {
		t.Fatalf("requests = %q", bodies)
	}
	if len(waits) != 1 || waits[0] != time.Second {
		t.Fatalf("waits = %v, want the site's 1s", waits)
	}
	err = cl.Post(context.Background(), "/rest/api/3/search/jql", map[string]any{"jql": "("}, &v)
	if !IsStatus(err, http.StatusBadRequest) || !strings.Contains(err.Error(), "POST /rest/api/3/search/jql: 400") ||
		!strings.Contains(err.Error(), "Error in the JQL Query") {
		t.Fatalf("a refused post = %v", err)
	}
	big := map[string]string{"jql": strings.Repeat("x", maxRequestBytes)}
	if err := cl.Post(context.Background(), "/x", big, &v); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("an oversized request = %v", err)
	}
}

// TestCleanRemovesEveryFormOfTheCredential: the token, its basic-auth
// encoding and the header are scrubbed out of an error, which still reports
// its status.
func TestCleanRemovesEveryFormOfTheCredential(t *testing.T) {
	token := "secret-token-" + strings.Repeat("Q9", 10)
	cl, err := NewClient(Config{Product: "jira", Base: mustURL(t, "https://corp.atlassian.net"), Auth: AuthBasic,
		Email: "bot@corp.example"}, knowledge.NewCredential([]byte(token)))
	if err != nil {
		t.Fatal(err)
	}
	raw := &APIError{Status: http.StatusUnauthorized, Path: "/rest/api/3/myself", Msg: "Received: " + cl.auth + " and " + token}
	clean := cl.Clean(raw)
	if strings.Contains(clean.Error(), token) || strings.Contains(clean.Error(), strings.TrimPrefix(cl.auth, "Basic ")) {
		t.Fatalf("the cleaned error carries the credential: %v", clean)
	}
	if !IsStatus(clean, http.StatusUnauthorized) || !strings.Contains(clean.Error(), "refused the credential") {
		t.Fatalf("the cleaned error lost its status: %v", clean)
	}
	if cl.Clean(clean) != clean {
		t.Fatal("cleaning twice wraps twice")
	}
	if _, err := NewClient(Config{Product: "jira", Base: mustURL(t, "https://x.example"), Auth: AuthBearer},
		knowledge.NewCredential([]byte("a\nb"))); err == nil {
		t.Fatal("a token with a line break was accepted")
	}
	if _, err := NewClient(Config{Product: "jira", Base: mustURL(t, "https://x.example"), Auth: AuthBearer},
		knowledge.Credential{}); err == nil || !strings.Contains(err.Error(), "a jira source signs in with a secret") {
		t.Fatalf("no credential = %v", err)
	}
}
