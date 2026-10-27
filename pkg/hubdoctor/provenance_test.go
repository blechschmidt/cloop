package hubdoctor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// provenanceFindings runs the images.provenance check alone.
func provenanceFindings(t *testing.T, cfg *config.Config, opts Options) []Finding {
	t.Helper()
	var out []Finding
	checkImageProvenance(t.TempDir(), cfg, opts, func(f Finding) { out = append(out, f) })
	for _, f := range out {
		if f.Check != "images.provenance" {
			t.Errorf("finding under %q, want images.provenance: %+v", f.Check, f)
		}
	}
	return out
}

func noCosign(string) (string, error) { return "", errors.New("not found") }

func provenanceMode(t *testing.T, required bool) {
	t.Helper()
	prev := executor.SetImageProvenanceRequired(required)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })
}

// TestImageProvenanceWithoutCosign: nothing needs cosign on a hub that runs no
// image of cloop's; one whose container executor runs the default warns that
// it runs unverified, and fails when executors.image_provenance is required —
// naming the remedy either way.
func TestImageProvenanceWithoutCosign(t *testing.T) {
	provenanceMode(t, false)
	imagepolicy.ResetRecentProvenance()
	t.Cleanup(imagepolicy.ResetRecentProvenance)

	got := provenanceFindings(t, hubCfg(), Options{LookPath: noCosign})
	if len(got) != 1 || got[0].Severity != SeverityPass {
		t.Fatalf("a hub running no image of cloop's: %+v", got)
	}

	cfg := hubCfg()
	cfg.Executors.Container.Enabled = true
	got = provenanceFindings(t, cfg, Options{LookPath: noCosign})
	if got[0].Severity != SeverityWarn || !strings.Contains(got[0].Message, "run unverified") ||
		!strings.Contains(got[0].Remediation, "bundles it") {
		t.Errorf("warn: %+v", got[0])
	}

	cfg.Executors.ImageProvenance = executor.ImageProvenancePolicyRequired
	got = provenanceFindings(t, cfg, Options{LookPath: noCosign})
	if got[0].Severity != SeverityFail || !strings.Contains(got[0].Message, "refused") {
		t.Errorf("required: %+v", got[0])
	}
	if got[0].Details["image_provenance"] != executor.ImageProvenancePolicyRequired {
		t.Errorf("the setting is not in the details: %+v", got[0].Details)
	}
}

// TestImageProvenanceReportsWhatDispatchesFound: each recorded verdict for an
// image in use, at the severity its status and the setting call for.
func TestImageProvenanceReportsWhatDispatchesFound(t *testing.T) {
	provenanceMode(t, false)
	imagepolicy.ResetRecentProvenance()
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	cfg := hubCfg()
	cfg.Executors.Container.Enabled = true
	id := containerID(cfg)
	digest := "sha256:" + strings.Repeat("ab", 32)
	record := func(s imagepolicy.ProvenanceStatus, detail string) {
		imagepolicy.RecordProvenance(id, imagepolicy.Provenance{Image: executor.DefaultHarnessImage,
			Ref: "ghcr.io/blechschmidt/cloop-harness@" + digest, Digest: digest, Status: s, Detail: detail,
			CheckedAt: time.Now()})
	}
	byStatus := func() Finding {
		t.Helper()
		got := provenanceFindings(t, cfg, Options{LookPath: noCosign})
		if len(got) != 2 {
			t.Fatalf("want the cosign finding and the image's, got %+v", got)
		}
		return got[1]
	}

	record(imagepolicy.ProvenanceVerified, "ok")
	if f := byStatus(); f.Severity != SeverityPass || !strings.Contains(f.Message, "verified") {
		t.Errorf("verified: %+v", f)
	}
	record(imagepolicy.ProvenanceUnsigned, "Error: no signatures found")
	if f := byStatus(); f.Severity != SeverityWarn || !strings.Contains(f.Message, "no signature") ||
		!strings.Contains(f.Remediation, "verify-image") {
		t.Errorf("unsigned: %+v", f)
	}
	cfg.Executors.ImageProvenance = executor.ImageProvenancePolicyRequired
	if f := byStatus(); f.Severity != SeverityFail || !strings.Contains(f.Message, "refused") {
		t.Errorf("unsigned under required: %+v", f)
	}
	record(imagepolicy.ProvenanceMismatch, "no matching CertificateIdentity found")
	cfg.Executors.ImageProvenance = ""
	if f := byStatus(); f.Severity != SeverityFail || !strings.Contains(f.Message, "not from the workflow") {
		t.Errorf("mismatch: %+v", f)
	}
}

// TestImageProvenanceSaysAKubernetesTagCannotBeChecked: no dispatch needed to
// know it.
func TestImageProvenanceSaysAKubernetesTagCannotBeChecked(t *testing.T) {
	provenanceMode(t, false)
	imagepolicy.ResetRecentProvenance()
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	cfg := hubCfg()
	cfg.Executors.Kubernetes.Enabled = true
	got := provenanceFindings(t, cfg, Options{LookPath: noCosign})
	var tag *Finding
	for i := range got {
		if strings.Contains(got[i].Message, "a tag") {
			tag = &got[i]
		}
	}
	if tag == nil || tag.Severity != SeverityWarn || !strings.Contains(tag.Remediation, "by digest") {
		t.Fatalf("a Kubernetes tag: %+v", got)
	}

	// By digest there is nothing to say until a dispatch has checked it.
	cfg.Executors.Kubernetes.Image = "ghcr.io/blechschmidt/cloop-harness@sha256:" + strings.Repeat("cd", 32)
	for _, f := range provenanceFindings(t, cfg, Options{LookPath: noCosign})[1:] {
		if f.Severity != SeverityPass || strings.Contains(f.Message, "a tag") {
			t.Errorf("a digest: %+v", f)
		}
	}
}

// TestImageProvenanceReportsCosignsVersion: read from the binary's build
// information, not by running it, and an old one is warned about.
func TestImageProvenanceReportsCosignsVersion(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go toolchain to build a stand-in cosign")
	}
	provenanceMode(t, false)
	imagepolicy.ResetRecentProvenance()
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	build := func(version string) string {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/cosign\n\ngo 1.21\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { panic(\"executed\") }\n"), 0o644)
		out := filepath.Join(dir, "cosign")
		cmd := exec.Command(gobin, "build", "-ldflags", "-X sigs.k8s.io/release-utils/version.gitVersion="+version, "-o", out, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build: %v\n%s", err, b)
		}
		return out
	}
	current := build("v3.1.4")
	got := provenanceFindings(t, hubCfg(), Options{LookPath: func(string) (string, error) { return current, nil }})
	if got[0].Severity != SeverityPass || !strings.Contains(got[0].Message, "cosign v3.1.4") ||
		got[0].Details["cosign_version"] != "v3.1.4" {
		t.Errorf("current cosign: %+v", got[0])
	}
	old := build("v2.2.4")
	got = provenanceFindings(t, hubCfg(), Options{LookPath: func(string) (string, error) { return old, nil }})
	if got[0].Severity != SeverityWarn || !strings.Contains(got[0].Message, "older than") {
		t.Errorf("old cosign: %+v", got[0])
	}
}
