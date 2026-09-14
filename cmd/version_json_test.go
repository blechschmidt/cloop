package cmd

// Gates on `cloop version --json` (Task 20252).
//
// This output is not cosmetic: `cloop executor agent install --upgrade` execs
// the binary it is about to install and reads this JSON to decide whether the
// replacement is safe. Rename a field and the installer silently falls back to
// scraping the text form, which carries no protocol numbers — so the check that
// refuses a binary the hub would no longer talk to stops firing, and nothing
// fails until a device drops out of a fleet.
//
// The probe also has to be *cheap and side-effect free*. cloop's root pre-run
// loads the project config of whatever directory it starts in, applies retention
// policy, reconciles executors and may open a database. `version` opts out of all
// of it, and that opt-out is asserted here rather than assumed, because the
// failure it prevents — a verification probe that migrates a database as a side
// effect of being asked its version — would be found the hard way.

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// runVersion drives the command body and returns what it printed.
//
// RunE directly, which is this package's pattern: versionCmd.Execute() would
// resolve to the *root* command and re-parse the test binary's own os.Args.
func runVersion(t *testing.T, asJSON bool) []byte {
	t.Helper()
	var out bytes.Buffer
	versionCmd.SetOut(&out)
	if err := versionCmd.Flags().Set("json", strconv.FormatBool(asJSON)); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	t.Cleanup(func() {
		versionCmd.SetOut(nil)
		_ = versionCmd.Flags().Set("json", "false")
	})
	if err := versionCmd.RunE(versionCmd, nil); err != nil {
		t.Fatalf("cloop version (json=%v): %v", asJSON, err)
	}
	return out.Bytes()
}

// TestVersionJSONCarriesWhatTheInstallerReads pins the field names and the
// values behind them.
func TestVersionJSONCarriesWhatTheInstallerReads(t *testing.T) {
	out := runVersion(t, true)

	// Decoded into the same shape the installer declares, so a renamed field
	// fails here rather than degrading silently there.
	var got struct {
		Version     string `json:"version"`
		Go          string `json:"go"`
		OS          string `json:"os"`
		Arch        string `json:"arch"`
		Protocol    int    `json:"protocol"`
		MinProtocol int    `json:"min_protocol"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("the report is not valid JSON (%v): %s", err, out)
	}

	if got.Version == "" {
		t.Error("version is empty; the installer refuses a binary that will not identify itself")
	}
	if got.Version != Version() {
		t.Errorf("version = %q, want %q", got.Version, Version())
	}
	if got.Protocol != remote.ProtocolVersion {
		t.Errorf("protocol = %d, want %d", got.Protocol, remote.ProtocolVersion)
	}
	if got.MinProtocol != remote.MinProtocolVersion {
		t.Errorf("min_protocol = %d, want %d", got.MinProtocol, remote.MinProtocolVersion)
	}
	if got.OS == "" || got.Arch == "" {
		t.Errorf("platform is unreported (%q/%q); the installer uses it to catch a binary "+
			"that runs but is for another machine", got.OS, got.Arch)
	}
	if got.Go == "" {
		t.Error("go toolchain is unreported")
	}
}

// TestVersionTextStillLeadsWithTheCloopPrefix guards the fallback path. A binary
// predating --json is identified solely by its first line reading "cloop
// <version>", and that prefix is the whole identity check for it.
func TestVersionTextStillLeadsWithTheCloopPrefix(t *testing.T) {
	out := runVersion(t, false)
	if !bytes.HasPrefix(out, []byte("cloop "+Version())) {
		t.Errorf("the first line must read %q for an older-binary probe to parse it; got:\n%s",
			"cloop "+Version(), out)
	}
}

// TestVersionSkipsTheRootPreRun asserts the opt-out that makes this command
// usable as a probe. Cobra runs the *closest* PersistentPreRunE in the chain, so
// the check is that versionCmd defines its own.
func TestVersionSkipsTheRootPreRun(t *testing.T) {
	if versionCmd.PersistentPreRunE == nil {
		t.Fatal("version inherits the root pre-run, which loads config, applies retention " +
			"policy and reconciles executors — none of which a version probe may do")
	}
	// It must also be total: an error here would make the probe fail on a
	// machine where everything about the binary is fine.
	if err := versionCmd.PersistentPreRunE(versionCmd, nil); err != nil {
		t.Errorf("version's pre-run can fail: %v", err)
	}
}
