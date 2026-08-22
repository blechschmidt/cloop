package kubernetes

import (
	"strings"
	"testing"
)

func TestValidateNamespace(t *testing.T) {
	valid := []string{"cloop", "cloop-jobs", "a", "a.b", "team-1.prod", strings.Repeat("a", 253)}
	for _, ns := range valid {
		if err := ValidateNamespace(ns); err != nil {
			t.Errorf("ValidateNamespace(%q) = %v, want nil", ns, err)
		}
	}

	invalid := map[string]string{
		"":                       "empty",
		"Cloop":                  "lowercase",
		"cloop_jobs":             "lowercase",
		"-cloop":                 "begin and end",
		"cloop-":                 "begin and end",
		"cloop jobs":             "lowercase",
		strings.Repeat("a", 254): "exceeds",
		"kube-system":            "reserved",
		"kube-public":            "reserved",
		"kube-node-lease":        "reserved",
	}
	for ns, want := range invalid {
		err := ValidateNamespace(ns)
		if err == nil {
			t.Errorf("ValidateNamespace(%q) = nil, want an error", ns)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateNamespace(%q) = %q, want it to mention %q", ns, err, want)
		}
	}
}

// TestValidateNamespace_RejectsClusterNamespaces is called out separately
// because it is a security rule, not a syntax one: a Pod in kube-system
// frequently inherits privileged PodSecurity exemptions and sits next to the
// cluster's own control plane.
func TestValidateNamespace_RejectsClusterNamespaces(t *testing.T) {
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease"} {
		err := ValidateNamespace(ns)
		if err == nil {
			t.Fatalf("namespace %q was accepted for untrusted workloads", ns)
		}
		if !strings.Contains(err.Error(), "dedicated namespace") {
			t.Errorf("error %q does not say what to do instead", err)
		}
	}
}

func TestValidateImageRef(t *testing.T) {
	valid := []string{
		"cloop:latest",
		"ghcr.io/blechschmidt/cloop-harness:v1.2.3",
		"ghcr.io/x/y@sha256:" + strings.Repeat("a", 64),
		"registry.example:5000/team/harness:2024-01",
	}
	for _, ref := range valid {
		if err := ValidateImageRef(ref); err != nil {
			t.Errorf("ValidateImageRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := map[string]string{
		"":                       "empty",
		"  padded  ":             "whitespace",
		"-rm":                    "must not begin with '-'",
		"img; rm -rf /":          "not valid",
		"img$(whoami)":           "not valid",
		"img\nother":             "not valid",
		"ghcr.io/x/y:":           "empty tag or digest",
		"ghcr.io/x/y@":           "empty tag or digest",
		strings.Repeat("a", 600): "not a reference",
	}
	for ref, want := range invalid {
		err := ValidateImageRef(ref)
		if err == nil {
			t.Errorf("ValidateImageRef(%q) = nil, want an error", ref)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateImageRef(%q) = %q, want it to mention %q", ref, err, want)
		}
	}
}

// TestImageWarnings: a floating tag is a bad idea for an execution sandbox
// (the code you audited and the code you run become different artefacts) but
// not an error, because plenty of deployments track a tag on purpose.
func TestImageWarnings(t *testing.T) {
	pinned := "ghcr.io/x/y@sha256:" + strings.Repeat("a", 64)
	if got := ImageWarnings(pinned); len(got) != 0 {
		t.Errorf("a digest-pinned image warned: %v", got)
	}
	for _, floating := range []string{"cloop:latest", "cloop", "cloop:main", "ghcr.io/x/y:edge"} {
		got := ImageWarnings(floating)
		if len(got) == 0 {
			t.Errorf("ImageWarnings(%q) = none, want a floating-tag warning", floating)
			continue
		}
		if !strings.Contains(got[0], "digest") {
			t.Errorf("warning %q does not say to pin by digest", got[0])
		}
	}
	// The built-in default is a placeholder and must say so.
	got := ImageWarnings(DefaultImage)
	joined := strings.Join(got, " | ")
	if !strings.Contains(joined, "built-in default") {
		t.Errorf("ImageWarnings(DefaultImage) = %v, want it to flag the placeholder", got)
	}
	if len(ImageWarnings("")) != 0 {
		t.Error("an empty image should produce no warnings; Normalize substitutes the default first")
	}
}

func TestValidateQuantity(t *testing.T) {
	valid := []string{"", "1", "2", "500m", "1500m", "512Mi", "4Gi", "10Gi", "1Ti", "1.5", "100k", "2G"}
	for _, q := range valid {
		if err := ValidateQuantity(q); err != nil {
			t.Errorf("ValidateQuantity(%q) = %v, want nil", q, err)
		}
	}

	invalid := map[string]string{
		"4 gigs":  "whitespace",
		"gigs":    "no numeric value",
		"4gigs":   "unknown suffix",
		"-1":      "no numeric value",
		"0":       "greater than zero",
		"0Mi":     "greater than zero",
		"1e9":     "unknown suffix",
		"4 Gi":    "whitespace",
		" 4Gi":    "whitespace",
		"1.2.3Mi": "not a number",
		"1MB":     "unknown suffix",
	}
	for q, want := range invalid {
		err := ValidateQuantity(q)
		if err == nil {
			t.Errorf("ValidateQuantity(%q) = nil, want an error", q)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateQuantity(%q) = %q, want it to mention %q", q, err, want)
		}
	}
}

func TestValidateDNSSubdomain(t *testing.T) {
	if err := validateDNSSubdomain("cloop-runner", "service_account"); err != nil {
		t.Errorf("valid name rejected: %v", err)
	}
	err := validateDNSSubdomain("Cloop Runner", "service_account")
	if err == nil {
		t.Fatal("a name with spaces and capitals was accepted")
	}
	if !strings.Contains(err.Error(), "service_account") {
		t.Errorf("error %q does not name the field", err)
	}
}
