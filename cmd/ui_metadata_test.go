package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// TestUIRefusesToStartOnAMetadataExposureInForce: an egress_filter allowlist
// that contains a cloud metadata service without naming it stops `cloop ui`
// before it touches the control plane, every such list named (Task 20397); one
// in a switched-off section is a warning, because it confines nothing either
// way and refusing over it would be an outage with no security in it.
func TestUIRefusesToStartOnAMetadataExposureInForce(t *testing.T) {
	cfg := &config.Config{}
	cfg.Executors.Container.Enabled = true
	cfg.Executors.Container.EgressFilter = config.ContainerEgressFilterConfig{Enabled: true,
		AllowCIDRs: []string{"169.254.169.0/24", "100.64.0.0/10"}, AllowPorts: []int{80}}
	cfg.Executors.Kubernetes.EgressFilter = config.KubernetesEgressFilterConfig{CIDRs: []string{"fc00::/7"},
		Ports: []int{443}}

	var warn bytes.Buffer
	err := refuseMetadataExposures(cfg, &warn)
	if err == nil {
		t.Fatal("cloop ui would start with an allowlist in force that contains a metadata service")
	}
	for _, want := range []string{"refusing to start", "100.64.0.0/10 contains the cloud metadata service at 100.100.100.200",
		"169.254.169.0/24 contains 2 cloud metadata services"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "fc00::/7") {
		t.Error("a switched-off section was made fatal")
	}
	if w := warn.String(); !strings.Contains(w, "executors.kubernetes.egress_filter.cidrs: fc00::/7") ||
		!strings.Contains(w, "will refuse to start once it is switched on") {
		t.Errorf("the switched-off section was not warned about: %q", w)
	}

	cfg.Executors.Container.EgressFilter.AllowCIDRs = []string{"169.254.169.254/32", "100.64.0.0/16"}
	warn.Reset()
	if err := refuseMetadataExposures(cfg, &warn); err != nil {
		t.Errorf("a named service must not stop the start: %v", err)
	}
}
