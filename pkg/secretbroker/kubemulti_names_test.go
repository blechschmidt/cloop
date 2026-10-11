package secretbroker

import (
	"strings"
	"testing"
)

// TestKubeNamesAreSafeAndUnique pins the names a merged kubeconfig gives its
// entries: typed on a command line, joined with commas into CLOOP_K8S_CONTEXTS
// and quoted in a prompt, so nothing but lower-case letters, digits and '-';
// unique within a list however the secrets were named; and bounded.
func TestKubeNamesAreSafeAndUnique(t *testing.T) {
	for in, want := range map[string]string{
		"prod":                   "prod",
		"Prod.Kube_Config":       "prod-kube-config",
		"--a..b--":               "a-b",
		"kubernetes-admin@kind":  "kubernetes-admin-kind",
		"ünïcode":                "n-code",
		"___":                    "",
		strings.Repeat("x", 100): strings.Repeat("x", maxKubeStem),
		strings.Repeat("y", maxKubeStem-1) + "-z": strings.Repeat("y", maxKubeStem-1),
	} {
		if got := sanitizeKubeName(in, maxKubeStem); got != want {
			t.Errorf("sanitizeKubeName(%q) = %q, want %q", in, got, want)
		}
	}

	names := kubeNames{}
	for i, want := range []string{"prod", "prod-2", "prod-3"} {
		if got := names.claim("prod"); got != want {
			t.Errorf("claim %d = %q, want %q", i, got, want)
		}
	}
	// A secret literally named like a suffixed one does not take it twice.
	if got := names.claim("prod-2"); got != "prod-2-2" {
		t.Errorf("claim(prod-2) after three prods = %q", got)
	}
	long := strings.Repeat("a", maxKubeName)
	if got := names.claim(long); got != long {
		t.Errorf("claim(long) = %q", got)
	}
	if got := names.claim(long); len(got) > maxKubeName || !strings.HasSuffix(got, "-2") {
		t.Errorf("a second %d-character name became %q (%d)", maxKubeName, got, len(got))
	}
	for name := range names {
		if strings.ContainsAny(name, ",=\"' $") {
			t.Errorf("unsafe name %q", name)
		}
	}
}
