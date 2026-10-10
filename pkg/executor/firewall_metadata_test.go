package executor

import (
	"errors"
	"strings"
	"testing"
)

// TestStoredContainingRulesStillNormalize: Normalize is how a stored rule set
// is read back, so one saved before the containment rule (Task 20397) has to
// keep loading — the filters keep the service closed, and the card says what
// is wrong. Refusing it here would turn every sandbox under it into an
// "unreadable rules" refusal instead.
func TestStoredContainingRulesStillNormalize(t *testing.T) {
	stored := FirewallRules{AllowCIDRs: []string{"169.254.0.0/16", "fc00::/7"}, AllowPorts: []int{443}}
	n, err := stored.Normalize()
	if err != nil {
		t.Fatalf("a stored rule set with a containing allowlist no longer loads: %v", err)
	}
	if len(n.MetadataFindings()) != 2 {
		t.Errorf("findings = %v, want one per containing entry", n.MetadataFindings())
	}
}

// TestCheckMetadataIsTheSaveRule: refused with ErrInvalidSpec — a 400 at every
// API that saves a rule set — naming the entry, the service and both explicit
// alternatives; accepted once the service is named or denied.
func TestCheckMetadataIsTheSaveRule(t *testing.T) {
	err := FirewallRules{AllowCIDRs: []string{"100.64.0.0/10"}}.CheckMetadata()
	if !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("CheckMetadata = %v, want ErrInvalidSpec", err)
	}
	for _, want := range []string{"allow_cidrs", "100.64.0.0/10 contains the cloud metadata service at 100.100.100.200 (Alibaba Cloud",
		"Add 100.100.100.200/32 to the allowlist if a sandbox should reach it, or to the denylist so it stays closed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q lacks %q", err, want)
		}
	}
	for name, r := range map[string]FirewallRules{
		"named":           {AllowCIDRs: []string{"100.64.0.0/10", "100.100.100.200"}},
		"denied":          {AllowCIDRs: []string{"100.64.0.0/10"}, DenyCIDRs: []string{"100.100.100.200"}},
		"denied by range": {AllowCIDRs: []string{"100.64.0.0/10"}, DenyCIDRs: []string{"100.100.0.0/16"}},
		"nothing inside":  {AllowCIDRs: []string{"100.64.0.0/16"}},
		"public only":     {AllowPublicInternet: true},
	} {
		if err := r.CheckMetadata(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestMetadataNotesSayWhatBecomesOfAStoredRuleSet: the card's sentence for a
// rule set saved before the rule — what it contains, that it stays closed, and
// what a save has to say.
func TestMetadataNotesSayWhatBecomesOfAStoredRuleSet(t *testing.T) {
	notes := FirewallRules{AllowCIDRs: []string{"fd00:ec2::/32"}}.MetadataNotes()
	if len(notes) != 1 {
		t.Fatalf("notes = %v", notes)
	}
	for _, want := range []string{"fd00:ec2::/32 contains 2 cloud metadata services", "fd00:ec2::23", "fd00:ec2::254",
		"They stay closed", "drops them ahead of the allow", "to the denylist so they stay closed"} {
		if !strings.Contains(notes[0], want) {
			t.Errorf("note %q lacks %q", notes[0], want)
		}
	}
}

// TestVirtualSpecCheckMetadataNamesTheField: the virtual-executor form puts its
// rules under "firewall", and the refusal says so.
func TestVirtualSpecCheckMetadataNamesTheField(t *testing.T) {
	spec := VirtualSpec{Sandbox: SandboxSettings{Mode: SandboxModeContainer},
		Firewall: &FirewallRules{AllowCIDRs: []string{"168.63.0.0/16"}}}
	if _, err := spec.Normalize(); err != nil {
		t.Fatalf("Normalize must accept a stored configuration: %v", err)
	}
	err := spec.CheckMetadata()
	if !errors.Is(err, ErrInvalidSpec) || !strings.Contains(err.Error(), "firewall: ") ||
		!strings.Contains(err.Error(), "168.63.129.16 (Azure WireServer)") {
		t.Errorf("CheckMetadata = %v", err)
	}
	if err := (VirtualSpec{Sandbox: SandboxSettings{Mode: SandboxModeContainer}}).CheckMetadata(); err != nil {
		t.Errorf("no firewall, nothing to check: %v", err)
	}
}
