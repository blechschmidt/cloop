package config

import (
	"strings"
	"testing"
)

// TestHostSandboxOptOutIsValidatedAndMatched (Task 20500): an opt-out names
// projects by absolute path, never the filesystem's root, and matches a
// project however the path is spelled lexically.
func TestHostSandboxOptOutIsValidatedAndMatched(t *testing.T) {
	ok := HostSandboxConfig{OptOut: []string{"/srv/projects/infra", " /srv/projects/web/ "}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid opt-out: %v", err)
	}
	for _, bad := range []string{"relative/project", "/", " / ", ""} {
		err := HostSandboxConfig{OptOut: []string{bad}}.Validate()
		if err == nil || !strings.Contains(err.Error(), "executors.host_sandbox.opt_out") {
			t.Errorf("opt_out %q: %v, want a refusal naming the key", bad, err)
		}
	}
	for _, p := range []string{"/srv/projects/infra", "/srv/projects/infra/", "/srv/projects/./web"} {
		if !ok.OptedOut(p) {
			t.Errorf("%s is not opted out", p)
		}
	}
	for _, p := range []string{"/srv/projects", "/srv/projects/infra/sub", "/srv/projects/api", "", "."} {
		if ok.OptedOut(p) {
			t.Errorf("%s is opted out", p)
		}
	}
}
