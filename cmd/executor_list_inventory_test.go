package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestPrintAgentInventoryShowsTheSequence: `cloop executor list --inventory`
// names each device's place on main (Task 20380) — the order its installer
// holds every upgrade to — and says nothing about one whose build carries none.
func TestPrintAgentInventoryShowsTheSequence(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevNoColor := color.Output, color.NoColor
	color.Output, color.NoColor = &buf, true
	t.Cleanup(func() { color.Output, color.NoColor = prevOut, prevNoColor })

	inv := statedb.ExecutorInventory{AgentVersion: "dev+g5facde4", OS: "linux", Arch: "amd64"}
	printAgentInventory(color.New(color.Faint), inv, 925)
	if !strings.Contains(buf.String(), "sequence:  925 on main") {
		t.Errorf("no sequence line:\n%s", buf.String())
	}
	buf.Reset()
	printAgentInventory(color.New(color.Faint), inv, 0)
	if strings.Contains(buf.String(), "sequence") {
		t.Errorf("a build without a sequence got a line:\n%s", buf.String())
	}
}
