package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// echoProvider returns a fixed response, the way a harness that printed a
// credential it was lent does.
type echoProvider struct{ out string }

func (e echoProvider) Name() string         { return "echo-redaction-order" }
func (e echoProvider) DefaultModel() string { return "m" }
func (e echoProvider) Complete(_ context.Context, _ string, opts Options) (*Result, error) {
	if opts.OnToken != nil {
		opts.OnToken(e.out)
	}
	return &Result{Output: e.out, Provider: e.Name()}, nil
}

// TestTheProviderAuditLogRecordsTheScrubbedResponse: what the audit decorator
// writes into provider_calls is the response after redaction. Until Task
// 20378 redaction wrapped the decorator, so the caller saw a clean response
// and the audit row kept the credential — an egress session's proxy URL,
// found there by the container end-to-end test.
func TestTheProviderAuditLogRecordsTheScrubbedResponse(t *testing.T) {
	const secret = "http://sess_0123:0123456789abcdef0123456789abcdef@host.containers.internal:41000"
	lent := redact.NewLive([]string{redact.EnvKey + "=HTTPS_PROXY", "HTTPS_PROXY=" + secret})
	prevRedactor, prevAudit := buildRedactor, auditDecorator
	t.Cleanup(func() { buildRedactor, auditDecorator = prevRedactor, prevAudit })
	buildRedactor = func() *redact.Live { return lent }

	var recorded []string
	RegisterAuditDecorator(func(p Provider) Provider { return recordingProvider{inner: p, out: &recorded} })
	Register("echo-redaction-order", func(ProviderConfig) (Provider, error) {
		return echoProvider{out: "the proxy is " + secret}, nil
	})
	t.Cleanup(func() { delete(registry, "echo-redaction-order") })

	p, err := Build(ProviderConfig{Name: "echo-redaction-order"})
	if err != nil {
		t.Fatal(err)
	}
	var streamed strings.Builder
	res, err := p.Complete(context.Background(), "go", Options{OnToken: func(s string) { streamed.WriteString(s) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 {
		t.Fatalf("the audit decorator saw %d calls", len(recorded))
	}
	for what, text := range map[string]string{
		"the audit row": recorded[0], "the response": res.Output, "the stream": streamed.String(),
	} {
		if strings.Contains(text, secret) || strings.Contains(text, "0123456789abcdef0123456789abcdef") {
			t.Errorf("%s carries the lent credential: %q", what, text)
		}
		if !strings.Contains(text, redact.Marker) && what != "the stream" {
			t.Errorf("%s was not scrubbed: %q", what, text)
		}
	}
}

// recordingProvider stands in for the provider audit log.
type recordingProvider struct {
	inner Provider
	out   *[]string
}

func (r recordingProvider) Name() string         { return r.inner.Name() }
func (r recordingProvider) DefaultModel() string { return r.inner.DefaultModel() }
func (r recordingProvider) Complete(ctx context.Context, prompt string, opts Options) (*Result, error) {
	res, err := r.inner.Complete(ctx, prompt, opts)
	if res != nil {
		*r.out = append(*r.out, res.Output)
	}
	return res, err
}
