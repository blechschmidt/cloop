package caps

import (
	"os/exec"
	"strings"
	"testing"
)

const sampleStatus = `Name:	cloop
Umask:	0077
State:	S (sleeping)
Uid:	995	995	995	995
CapInh:	0000000000001000
CapPrm:	0000000000001000
CapEff:	0000000000001000
CapBnd:	0000000000001000
CapAmb:	0000000000001000
NoNewPrivs:	1
`

func TestParseStatus(t *testing.T) {
	s, err := ParseStatus(sampleStatus)
	if err != nil {
		t.Fatalf("ParseStatus: %v", err)
	}
	for name, set := range map[string]uint64{
		"inheritable": s.Inheritable, "permitted": s.Permitted, "effective": s.Effective,
		"bounding": s.Bounding, "ambient": s.Ambient,
	} {
		if !Has(set, NetAdmin) || set != 1<<12 {
			t.Errorf("%s = %#x, want exactly CAP_NET_ADMIN", name, set)
		}
	}

	// A kernel older than 4.3 prints no CapAmb line; that is still an answer.
	old := strings.Replace(sampleStatus, "CapAmb:\t0000000000001000\n", "", 1)
	if s, err := ParseStatus(old); err != nil || s.Ambient != 0 || s.Permitted != 1<<12 {
		t.Errorf("status without CapAmb: %+v, %v", s, err)
	}

	for name, body := range map[string]string{
		"no capability lines": "Name:\tcloop\nState:\tS\n",
		"a mask that is not hex": strings.Replace(sampleStatus,
			"CapPrm:\t0000000000001000", "CapPrm:\tzz", 1),
	} {
		if _, err := ParseStatus(body); err == nil {
			t.Errorf("%s: parsed without an error", name)
		}
	}
}

func TestCapString(t *testing.T) {
	if got := NetAdmin.String(); got != "CAP_NET_ADMIN" {
		t.Errorf("NetAdmin = %q", got)
	}
	if got := Cap(21).String(); got != "capability 21" {
		t.Errorf("Cap(21) = %q", got)
	}
	if Has(1<<12, 70) {
		t.Error("Has accepted a capability number outside the mask")
	}
}

// TestConfineIsANoOpWithoutCapabilitiesToPassOn: every ordinary cloop
// invocation calls Confine first, so for a process with nothing inheritable it
// must succeed without doing anything a test could notice.
func TestConfineIsANoOpWithoutCapabilitiesToPassOn(t *testing.T) {
	if err := Confine(); err != nil {
		t.Fatalf("Confine: %v", err)
	}
	if err := Confine(); err != nil {
		t.Fatalf("second Confine: %v", err)
	}
}

// TestGrantAsksForNothingItCannotHave: a process that does not hold a
// capability — or root, whose children need no grant — must leave the command
// exactly as it was, or its exec would fail on a grant the kernel refuses.
func TestGrantAsksForNothingItCannotHave(t *testing.T) {
	cmd := exec.Command("true")
	granted := Grant(cmd, NetAdmin)
	if !granted {
		if cmd.SysProcAttr != nil {
			t.Errorf("Grant declined but still set SysProcAttr: %+v", cmd.SysProcAttr)
		}
		return
	}
	if !Holds(NetAdmin) {
		t.Error("Grant asked for CAP_NET_ADMIN, which this process does not hold")
	}
}
