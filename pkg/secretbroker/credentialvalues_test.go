package secretbroker

// Tests for the values a lease's pushes are scanned for (Task 20436).

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func mintKind(t *testing.T, b *Broker, name string, kind Kind, payload string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{Name: name, Kind: kind, Payload: []byte(payload), Actor: "test"})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s
}

// valuesByField indexes CredentialValues for assertions.
func valuesByField(cs []CredentialValue) map[string]CredentialValue {
	out := map[string]CredentialValue{}
	for _, c := range cs {
		out[c.Field] = c
	}
	return out
}

// TestCredentialValuesAreTheCredentialsALeaseDelivered builds a real lease of
// every credential-bearing kind and holds CredentialValues to the credentials
// in it: each value once, named by its grant and secret, and nothing that is
// only a constraint echo or a public part of a credential.
func TestCredentialValuesAreTheCredentialsALeaseDelivered(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	const project = "project:/srv/app"

	env := mintKind(t, b, "acme-env", KindEnv, `{"ACME_API_KEY":"acme-key-value-0001","REGION_NOTE":"short"}`)
	grantTo(t, b, env.ID, project, Constraints{}, time.Hour)

	pat := mintGitHub(t, b, "acme-pat", "ghp_credentialvaluespat000000000001")
	grantTo(t, b, pat.ID, project, Constraints{Repos: []string{"org/*"}}, time.Hour)

	clientKey := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\n"
	kube := "apiVersion: v1\nkind: Config\ncurrent-context: ci\n" +
		"clusters:\n- name: c\n  cluster:\n    server: https://k8s.example.invalid\n    certificate-authority-data: Q0EtUFVCTElDLURBVEE=\n" +
		"contexts:\n- name: ci\n  context:\n    cluster: c\n    user: ci-user\n" +
		"users:\n- name: ci-user\n  user:\n    token: kube-bearer-token-0001\n" +
		"    client-certificate-data: Q0VSVC1QVUJMSUMtREFUQQ==\n" +
		"    client-key-data: " + base64.StdEncoding.EncodeToString([]byte(clientKey)) + "\n" +
		"    exec:\n      env:\n      - name: AWS_REGION\n        value: eu-central-1\n      - name: AWS_SECRET_ACCESS_KEY\n        value: exec-env-secret-0001\n"
	kc := mintKind(t, b, "acme-kube", KindKubeconfig, kube)
	// Every verb: a grant narrower than that is delivered only through the
	// Kubernetes monitor, which this broker has none of.
	grantTo(t, b, kc.ID, project, Constraints{Contexts: []string{"ci"}, Verbs: append([]string(nil), kubeVerbOrder...)}, time.Hour)

	auth := base64.StdEncoding.EncodeToString([]byte("robot:registry-password-0001"))
	reg := mintKind(t, b, "acme-registry", KindRegistry,
		`{"auths":{"ghcr.io":{"auth":"`+auth+`","identitytoken":"registry-identity-0001"}}}`)
	grantTo(t, b, reg.ID, project, Constraints{Registries: []string{"ghcr.io"}}, time.Hour)

	eg := mintKind(t, b, "acme-egress", KindEgressProxy, "http://proxyuser:egress-pass%40word-0001@proxy.example.invalid:3128")
	grantTo(t, b, eg.ID, project, Constraints{Hosts: []string{"example.com"}}, time.Hour)

	lease, err := b.LeaseFor(context.Background(), Requester{ExecutorID: "exec-1", ProjectID: "/srv/app"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	got := lease.CredentialValues()
	if len(lease.Refused) != 0 {
		t.Fatalf("the lease refused %+v", lease.Refused)
	}
	all := map[string]CredentialValue{}
	for _, c := range got {
		if _, dup := all[c.Value]; dup {
			t.Errorf("value delivered twice is listed twice: %s", c.Field)
		}
		all[c.Value] = c
	}
	want := map[string]string{
		"acme-key-value-0001":                 "acme-env",
		"short":                               "acme-env",
		"ghp_credentialvaluespat000000000001": "acme-pat",
		"kube-bearer-token-0001":              "acme-kube",
		clientKey:                             "acme-kube",
		"exec-env-secret-0001":                "acme-kube",
		auth:                                  "acme-registry",
		"registry-password-0001":              "acme-registry",
		"registry-identity-0001":              "acme-registry",
		"egress-pass@word-0001":               "acme-egress",
	}
	for v, secret := range want {
		c, ok := all[strings.TrimSpace(v)]
		if !ok {
			t.Errorf("CredentialValues lacks the credential from %s (%q)", secret, v[:min(len(v), 24)])
			continue
		}
		if c.SecretName != secret || c.GrantID == "" || c.Field == "" {
			t.Errorf("value from %s is named %+v", secret, c)
		}
	}
	for _, public := range []string{"https://k8s.example.invalid", "Q0EtUFVCTElDLURBVEE=", "Q0VSVC1QVUJMSUMtREFUQQ==",
		"eu-central-1", "org/*", "example.com"} {
		if _, ok := all[public]; ok {
			t.Errorf("CredentialValues lists %q, which is no credential", public)
		}
	}
	for v, c := range all {
		if strings.Contains(c.Field, v) {
			t.Errorf("the field name %q carries the value", c.Field)
		}
	}
}

// TestCredentialValuesUnderTheGitProxyIncludeTheSessionToken: a guarded
// GitHub delivery hands the sandbox a proxy session's token, which is a
// credential the run holds, and the hub keeps the PAT itself, which is
// matched too.
func TestCredentialValuesUnderTheGitProxyIncludeTheSessionToken(t *testing.T) {
	mat := Material{
		GrantID: "gr_1", SecretName: "pat", Kind: KindGitHubPAT, Env: map[string]string{
			"CLOOP_GITHUB_REPO_ALLOWLIST": "org/*",
		},
		githubToken: "ghp_heldonthehub000000000000000000001",
		Files: []File{
			{Name: proxyCredentialName, Content: []byte("username=sess_1\npassword=proxy-session-token-0001\n")},
			{Name: credentialHelperName, Content: []byte("#!/bin/sh\necho generic helper\n")},
		},
	}
	got := valuesByField(mat.credentialValues())
	if got["the git proxy session token"].Value != "proxy-session-token-0001" {
		t.Errorf("session token missing: %+v", got)
	}
	if got["the GitHub token"].Value != "ghp_heldonthehub000000000000000000001" {
		t.Errorf("hub-held PAT missing: %+v", got)
	}
	for _, c := range got {
		if strings.Contains(c.Value, "generic helper") || c.Value == "org/*" {
			t.Errorf("a non-credential was listed: %+v", c)
		}
	}
}

// TestRedactionCredentialsNameWhatRedactionValuesReturns: an adopted run's
// pushes are scanned with exactly what its output is scrubbed with.
func TestRedactionCredentialsNameWhatRedactionValuesReturns(t *testing.T) {
	setup, store, _, clock := newTestBroker(t)
	env := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-delivered-value-0007","OTHER":"withheld-0007"}`)
	grantTo(t, setup, env.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)
	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "ui")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := holderBroker(t, store, clock, "hub_b")
	if _, err := b.Restore(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	creds := b.RedactionCredentials(lease.ID)
	values := b.RedactionValues(lease.ID)
	if len(creds) != 1 || len(values) != 1 || creds[0].Value != values[0] {
		t.Fatalf("credentials %+v, values %v", creds, values)
	}
	if c := creds[0]; c.SecretName != "claude" || c.Field != "env CLAUDE_CODE_OAUTH_TOKEN" || c.GrantID == "" {
		t.Fatalf("provenance = %+v", c)
	}
}
