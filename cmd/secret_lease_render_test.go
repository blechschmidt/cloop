package cmd

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// TestSecretLeaseShowsWhatTheWorkloadIsHanded: `cloop secret lease` lists each
// grant's own files, and for two kubeconfig grants that is "kubeconfig" twice —
// while the workload is handed one merged document (Task 20413). The dry run
// says so, and says nothing extra for a lease whose materials render as they
// are.
func TestSecretLeaseShowsWhatTheWorkloadIsHanded(t *testing.T) {
	grant := func(name, ns string) secretbrokertest.KubeGrant {
		return secretbrokertest.KubeGrant{Secret: name,
			Kubeconfig:  secretbrokertest.Kubeconfig("https://"+name+".example.test", name+"-token-0123", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{ns}}}
	}
	_, two := secretbrokertest.KubeLease(t, nil, grant("alpha", "team-a"), grant("beta", "team-b"))
	out, err := captureStdout(t, func() error { return printRenderedLease(two) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"delivered as one directory", "files:       kubeconfig\n",
		secretbroker.KubeContextsEnvKey, secretbroker.KubeGrantsEnvKey, "KUBECONFIG"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run of two kubeconfig grants lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "token-0123") {
		t.Errorf("the dry run printed a credential:\n%s", out)
	}

	_, one := secretbrokertest.KubeLease(t, nil, grant("alpha", "team-a"))
	if out, _ := captureStdout(t, func() error { return printRenderedLease(one) }); out != "" {
		t.Errorf("one grant renders as itself, and the dry run added:\n%s", out)
	}
}
