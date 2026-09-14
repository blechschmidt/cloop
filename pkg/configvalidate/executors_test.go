package configvalidate

// The third entry point into executor validation.
//
// `cloop config set` rejects a bad executor value and config.Load repairs one,
// but this command — the one an operator runs to ask "is my config good?" —
// did not look at the executors section at all. A hand-edited container
// runtime, Kubernetes namespace or egress filter was reported clean here and
// refused by the driver at the first dispatch.
//
// The table mirrors pkg/config's, deliberately: the same inputs through the
// third door, so a check that is ever added to one path and not the others
// fails here rather than looking complete.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	return dir
}

// containerConfig renders a container executor carrying the given
// egress_filter body.
func containerConfig(filterYAML string) string {
	return "executors:\n" +
		"  container:\n" +
		"    enabled: true\n" +
		"    network: bridge\n" +
		"    image: ghcr.io/blechschmidt/cloop-harness:v1\n" +
		"    egress_filter:\n" +
		"      " + filterYAML + "\n"
}

func TestValidateReportsBadContainerEgressFilter(t *testing.T) {
	cases := []struct {
		name   string
		filter string
		want   string
	}{
		{
			// Switched off, so nothing else in the system looks at it: the
			// driver's Validate returns early and the clamp leaves the
			// executor registered. This command is the only one that can tell
			// the operator before they flip the boolean.
			name:   "disabled section with a mistyped CIDR",
			filter: "enabled: false\n      allow_cidrs: [\"10.8.0.0\"]\n      allow_ports: [443]",
			want:   "allow_cidrs[0]",
		},
		{
			name:   "internal-only filter with an out-of-range port",
			filter: "enabled: true\n      internal: true\n      allow_ports: [99999]",
			want:   "allow_ports[0]",
		},
		{
			name:   "destinations allowed on no ports",
			filter: "enabled: true\n      internal: true\n      allow_cidrs: [\"10.8.0.0/24\"]",
			want:   "no ports",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeConfig(t, containerConfig(tc.filter))

			rep, err := Run(context.Background(), dir, ValidateOptions{})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !rep.HasErrors() {
				t.Fatalf("reported no error for a filter the driver cannot compile:\n%+v", rep.Findings)
			}

			var found bool
			for _, f := range rep.Findings {
				if f.Field == "config.executors" && strings.Contains(f.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no config.executors finding naming %q; findings: %+v", tc.want, rep.Findings)
			}
		})
	}

	t.Run("control: the recommended filter is reported clean", func(t *testing.T) {
		dir := writeConfig(t, containerConfig("enabled: true\n      internal: true"))
		rep, err := Run(context.Background(), dir, ValidateOptions{})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for _, f := range rep.Findings {
			if f.Field == "config.executors" {
				t.Errorf("valid executor section reported as a problem: %+v", f)
			}
		}
	})
}

// TestValidateReportsOtherExecutorProblems guards the wider closure. The
// egress filter is what prompted checkExecutors, but the gap was the whole
// section being unvalidated here, and a regression that narrowed the check
// back to the filter alone would otherwise pass.
func TestValidateReportsOtherExecutorProblems(t *testing.T) {
	dir := writeConfig(t, "executors:\n  container:\n    enabled: true\n    runtime: containerd\n")

	rep, err := Run(context.Background(), dir, ValidateOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Field == "config.executors" && strings.Contains(f.Message, "runtime") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unsupported container runtime was reported clean; findings: %+v", rep.Findings)
	}
}
