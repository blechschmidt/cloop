package claudeproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAllowsPath_OnlyTheMessagesSurface(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method, path string
		want         DenyReason // "" means allowed
	}{
		{"POST", "/v1/messages", ""},
		{"POST", "/v1/messages/count_tokens", ""},
		{"GET", "/v1/models", ""},
		{"GET", "/v1/models/claude-sonnet-4-6", ""},

		// Wrong method on a known path.
		{"GET", "/v1/messages", DenyMethodNotAllowd},
		{"DELETE", "/v1/messages", DenyMethodNotAllowd},
		{"POST", "/v1/models", DenyMethodNotAllowd},

		// The rest of the API is not lent out. Batches and files create
		// state that outlives the job and is billed to the hub's account;
		// the organization endpoints are account administration.
		{"POST", "/v1/messages/batches", DenyPathNotAllowed},
		{"GET", "/v1/messages/batches", DenyPathNotAllowed},
		{"POST", "/v1/files", DenyPathNotAllowed},
		{"GET", "/v1/organizations/users", DenyPathNotAllowed},
		{"POST", "/v1/complete", DenyPathNotAllowed},
		{"GET", "/", DenyPathNotAllowed},
		{"GET", "/v1", DenyPathNotAllowed},

		// Traversal and doubled separators must be normalised before the
		// match, or a path that reaches an endpoint could dodge the check
		// that guards it.
		{"POST", "/v1/messages/../messages", ""},
		{"POST", "//v1/messages", ""},
		{"POST", "/v1/models/../../v1/messages", ""},
		{"POST", "/v1/messages/../batches", DenyPathNotAllowed},
		{"POST", "/v1/../v1/files", DenyPathNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			t.Parallel()
			d := AllowsPath(tc.method, tc.path)
			switch {
			case tc.want == "" && d != nil:
				t.Fatalf("refused a permitted request: %v", d)
			case tc.want != "" && d == nil:
				t.Fatalf("permitted a request it must refuse")
			case tc.want != "" && d.Reason != tc.want:
				t.Errorf("reason = %q, want %q", d.Reason, tc.want)
			}
		})
	}
}

func TestPolicy_AllowsModel(t *testing.T) {
	t.Parallel()
	p := Policy{Models: []string{"claude-sonnet-4-*", "claude-haiku-4-5-20251001"}}
	for _, tc := range []struct {
		model string
		want  bool
	}{
		{"claude-sonnet-4-6", true},
		{"claude-haiku-4-5-20251001", true},
		{"claude-opus-4-8", false},
		{"", false},
	} {
		if got := p.AllowsModel(tc.model); got != tc.want {
			t.Errorf("AllowsModel(%q) = %v, want %v", tc.model, got, tc.want)
		}
	}
	if (Policy{}).AllowsModel("claude-sonnet-4-6") {
		t.Error("an empty allowlist admitted a model")
	}
}

func TestDecideMessages(t *testing.T) {
	t.Parallel()
	p := Policy{Models: []string{"claude-sonnet-4-6"}, MaxOutputTokens: 1000}

	t.Run("permitted model passes through byte for byte", func(t *testing.T) {
		t.Parallel()
		in := []byte(`{"model":"claude-sonnet-4-6","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`)
		out, req, d := p.DecideMessages(in)
		if d != nil {
			t.Fatalf("refused: %v", d)
		}
		if string(out) != string(in) {
			t.Errorf("body was rewritten when it did not need to be:\n got %s\nwant %s", out, in)
		}
		if req.Model != "claude-sonnet-4-6" {
			t.Errorf("Model = %q", req.Model)
		}
	})

	t.Run("model outside the allowlist is refused", func(t *testing.T) {
		t.Parallel()
		_, _, d := p.DecideMessages([]byte(`{"model":"claude-opus-4-8","max_tokens":10}`))
		if d == nil || d.Reason != DenyModelNotAllowed {
			t.Fatalf("denial = %v, want %q", d, DenyModelNotAllowed)
		}
		if d.Status != 403 {
			t.Errorf("status = %d, want 403", d.Status)
		}
	})

	t.Run("max_tokens over the cap is clamped, not refused", func(t *testing.T) {
		t.Parallel()
		out, req, d := p.DecideMessages([]byte(
			`{"model":"claude-sonnet-4-6","max_tokens":999999,"messages":[{"role":"user","content":"hi"}]}`))
		if d != nil {
			t.Fatalf("refused a request it should have clamped: %v", d)
		}
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("rewritten body is not JSON: %v", err)
		}
		if got["max_tokens"] != float64(1000) {
			t.Errorf("max_tokens = %v, want 1000", got["max_tokens"])
		}
		if req.MaxTokens == nil || *req.MaxTokens != 1000 {
			t.Errorf("reported MaxTokens = %v, want 1000", req.MaxTokens)
		}
		// The rest of the request must survive the rewrite untouched.
		msgs, ok := got["messages"].([]any)
		if !ok || len(msgs) != 1 {
			t.Errorf("messages were lost in the rewrite: %v", got["messages"])
		}
	})

	t.Run("absent max_tokens is left absent", func(t *testing.T) {
		t.Parallel()
		// count_tokens requests carry no max_tokens. Inserting one would
		// change a request the client did not make.
		in := []byte(`{"model":"claude-sonnet-4-6","messages":[]}`)
		out, _, d := p.DecideMessages(in)
		if d != nil {
			t.Fatalf("refused: %v", d)
		}
		if strings.Contains(string(out), "max_tokens") {
			t.Errorf("max_tokens was inserted into a body that had none: %s", out)
		}
	})

	t.Run("malformed bodies are refused", func(t *testing.T) {
		t.Parallel()
		for _, body := range []string{``, `not json`, `[]`, `{"max_tokens":1}`} {
			_, _, d := p.DecideMessages([]byte(body))
			if d == nil {
				t.Errorf("accepted %q", body)
				continue
			}
			if d.Reason != DenyBodyMalformed {
				t.Errorf("%q: reason = %q, want %q", body, d.Reason, DenyBodyMalformed)
			}
		}
	})
}

func TestPolicy_Defaults(t *testing.T) {
	t.Parallel()
	if got := (Policy{}).OutputCap(); got != DefaultMaxOutputTokens {
		t.Errorf("OutputCap() = %d, want %d", got, DefaultMaxOutputTokens)
	}
	if got := (Policy{}).BodyCap(); got != DefaultMaxBodyBytes {
		t.Errorf("BodyCap() = %d, want %d", got, DefaultMaxBodyBytes)
	}
}

func TestUpstream_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		up   Upstream
		want string
	}{
		{"no credential", Upstream{}, "no upstream"},
		{"both credentials", Upstream{APIKey: "k", AuthToken: "t"}, "exactly one"},
		{"plaintext upstream", Upstream{APIKey: "k", BaseURL: "http://api.example.com"}, "must use https"},
		{"upstream with a path", Upstream{APIKey: "k", BaseURL: "https://api.example.com/v1"}, "no path"},
		{"not a URL", Upstream{APIKey: "k", BaseURL: "://"}, "is not a URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.up.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	for _, ok := range []Upstream{
		{APIKey: "k"},
		{AuthToken: "t"},
		{APIKey: "k", BaseURL: "https://gateway.example.com"},
		{APIKey: "k", BaseURL: "http://127.0.0.1:9999"}, // loopback is exempt
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", ok, err)
		}
	}
}

func TestUpstream_RedactedNeverLeaksTheCredential(t *testing.T) {
	t.Parallel()
	const secret = "sk-ant-super-secret-value"
	for _, up := range []Upstream{{APIKey: secret}, {AuthToken: secret}} {
		if strings.Contains(up.Redacted(), secret) {
			t.Errorf("Redacted() leaked the credential: %q", up.Redacted())
		}
	}
	if got := (Upstream{}).Redacted(); got != "none" {
		t.Errorf("Redacted() = %q, want %q", got, "none")
	}
}
