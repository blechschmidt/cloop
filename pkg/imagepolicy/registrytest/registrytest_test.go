package registrytest_test

import (
	"net"
	"testing"

	"github.com/blechschmidt/cloop/pkg/imagepolicy/registrytest"
)

// TestAClosedRegistryKeepsItsPort: a closed registry stays unreachable until
// the test ends. Its port is never free for another listener to take, so
// nothing can answer where a test expects nothing to — the way a later
// httptest server, presenting the certificate the registry's client trusts,
// once answered 404 in TestAnUnreachableRegistryInEachMode. A connection kept
// alive from before Close does not outlive it either.
func TestAClosedRegistryKeepsItsPort(t *testing.T) {
	reg := registrytest.New(t)
	manifest := reg.URL() + "/v2/acme/rust/manifests/1"
	resp, err := reg.Client().Head(manifest)
	if err != nil {
		t.Fatalf("the open registry: %v", err)
	}
	_ = resp.Body.Close()

	reg.Close()
	if ln, err := net.Listen("tcp", reg.Host()); err == nil {
		_ = ln.Close()
		t.Fatalf("another listener took %s after Close", reg.Host())
	}
	for i := 0; i < 3; i++ {
		resp, err := reg.Client().Head(manifest)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("request %d after Close was answered: %s", i, resp.Status)
		}
	}
}
