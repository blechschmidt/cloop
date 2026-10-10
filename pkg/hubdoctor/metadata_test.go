package hubdoctor

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestAMetadataContainingAllowlistInForceFails: `cloop ui` refuses to start on
// it, so the doctor fails it, naming the key, the service and the way out —
// and only warns about one in a section that is switched off (Task 20397).
func TestAMetadataContainingAllowlistInForceFails(t *testing.T) {
	dir, cfg := loadedHub(t, `provider: claudecode
executors:
  allow_host_process: false
  container:
    enabled: true
    network: bridge
    egress_filter:
      enabled: true
      allow_cidrs: ["169.254.0.0/16"]
      allow_ports: [80]
      resolvers: ["1.1.1.1"]
  kubernetes:
    egress_filter:
      cidrs: ["fc00::/7"]
      ports: [443]
`)
	got := findingsFor(t, dir, cfg, Options{Offline: true})[metadataCheck]
	if len(got) != 2 {
		t.Fatalf("findings = %+v, want one per allowlist", got)
	}
	var fail, warn *Finding
	for i := range got {
		switch got[i].Severity {
		case SeverityFail:
			fail = &got[i]
		case SeverityWarn:
			warn = &got[i]
		}
	}
	if fail == nil || !strings.Contains(fail.Message, "executors.container.egress_filter.allow_cidrs: 169.254.0.0/16 contains 6") ||
		!strings.Contains(fail.Remediation, "refuses to start") {
		t.Errorf("the in-force allowlist is not a failure naming it: %+v", fail)
	}
	if warn == nil || !strings.Contains(warn.Message, "executors.kubernetes.egress_filter.cidrs: fc00::/7") ||
		!strings.Contains(warn.Message, "switched off") {
		t.Errorf("the switched-off allowlist is not a warning naming it: %+v", warn)
	}
}

// TestStoredRuleSetsThatContainAServiceAreListed: rule sets and grants saved
// before the rule keep loading and keep the service closed, so they are warned
// about — each by where it is and what it contains — rather than failed.
func TestStoredRuleSetsThatContainAServiceAreListed(t *testing.T) {
	dir, cfg := loadedHub(t, "provider: claudecode\nexecutors:\n  allow_host_process: false\n")
	mustInitStateDB(t, dir)
	db, err := statedb.Open(dir + "/.cloop/state.db")
	if err != nil {
		t.Fatal(err)
	}
	// Written below the API, the way a rule set saved before Task 20397 is
	// in the table: Normalize accepts it, and nothing else ran.
	if err := db.SetExecutorFirewall("sgx", executor.FirewallRules{AllowCIDRs: []string{"100.64.0.0/10"},
		AllowPorts: []int{443}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProjectFirewall("/srv/app", executor.FirewallRules{AllowCIDRs: []string{"fd00:ec2::/32"}},
		"maintainer"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: "sgx", Name: "sgx", Kind: executor.KindRemoteAgent}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateVirtualExecutor(statedb.VirtualExecutor{ID: "vx-abcdefghij", ParentID: "sgx", Name: "Lab",
		Spec: executor.VirtualSpec{Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer},
			Firewall: &executor.FirewallRules{AllowCIDRs: []string{"168.63.0.0/16"}}}}); err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutGrant(egressbroker.Grant{ID: "egress_old", CIDRs: []string{"169.254.169.0/24"}, Ports: []int{80},
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	got := findingsFor(t, dir, cfg, Options{Offline: true})[metadataCheck]
	want := map[string]string{
		"device sgx's firewall":                           "100.100.100.200 (Alibaba Cloud",
		"project /srv/app's firewall":                     "fd00:ec2::254 (AWS",
		"virtual executor vx-abcdefghij (Lab)'s firewall": "168.63.129.16 (Azure WireServer)",
		"egress grant egress_old":                         "169.254.169.254 (instance metadata",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %+v, want %d", got, len(want))
	}
	for _, f := range got {
		if f.Severity != SeverityWarn {
			t.Errorf("%q is %s; a stored rule set keeps the service closed, so it is a warning", f.Message, f.Severity)
		}
		matched := false
		for where, svc := range want {
			if strings.HasPrefix(f.Message, where+": ") && strings.Contains(f.Message, svc) {
				matched = true
			}
		}
		if !matched || f.Remediation == "" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
}

func TestNoMetadataExposurePasses(t *testing.T) {
	dir, cfg := loadedHub(t, "provider: claudecode\nexecutors:\n  allow_host_process: false\n")
	mustInitStateDB(t, dir)
	got := only(t, findingsFor(t, dir, cfg, Options{Offline: true}), metadataCheck)
	if got.Severity != SeverityPass {
		t.Errorf("a hub with no allowlist is %s: %s", got.Severity, got.Message)
	}
}
