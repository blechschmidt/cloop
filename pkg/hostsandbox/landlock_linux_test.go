//go:build linux

package hostsandbox

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// TestABIErrorNamesTheSeccompFilterOnEPERM: EPERM is not an answer the version
// query itself has — asking which Landlock ABI a kernel speaks takes no
// privilege — so it means the call was stopped before the kernel saw it. A
// seccomp filter is what does that, and on every cloop executor device it is
// systemd's: the unit the installer rendered before Task 49 allowed
// @system-service, which does not cover the Landlock calls, with
// SystemCallErrorNumber=EPERM beside it. The agent then reported that it could
// not confine a payload, and the hub refused every run of every project that
// shared the device.
//
// The reported reason has to name that, because the alternative is what
// actually happened: "query the Landlock ABI: operation not permitted", three
// error wrappings down, on a kernel that speaks Landlock ABI 5 perfectly well.
func TestABIErrorNamesTheSeccompFilterOnEPERM(t *testing.T) {
	err := abiError(syscall.EPERM)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("EPERM is not reported as unsupported: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"seccomp", "SystemCallFilter", "@system-service",
		"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the EPERM reason does not mention %q: %s", want, msg)
		}
	}
	// And it must not blame the kernel, which is what sent an operator looking
	// for a boot parameter or a newer kernel on a machine that needed neither.
	for _, wrong := range []string{"lsm=", "CONFIG_SECURITY_LANDLOCK"} {
		if strings.Contains(msg, wrong) {
			t.Errorf("the EPERM reason blames the kernel (%q): %s", wrong, msg)
		}
	}
}

// TestABIErrorKeepsTheKernelCases: the two errnos that really do mean "this
// kernel has no Landlock" still say so, each naming its own remedy, and
// anything else is reported as itself rather than guessed at.
func TestABIErrorKeepsTheKernelCases(t *testing.T) {
	cases := []struct {
		errno syscall.Errno
		want  string
	}{
		{syscall.ENOSYS, "CONFIG_SECURITY_LANDLOCK"},
		{syscall.EOPNOTSUPP, "lsm= boot parameter"},
		{syscall.EACCES, "query the Landlock ABI"},
	}
	for _, c := range cases {
		err := abiError(c.errno)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%v is not reported as unsupported: %v", c.errno, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v reported as %q, want it to mention %q", c.errno, err, c.want)
		}
	}
}

// TestAvailableOnThisKernelDoesNotReportEPERM is the regression this is really
// about, in the only place a test can see it: the test binary runs under no
// seccomp filter, so a kernel with Landlock must answer the version query. A
// failure here with EPERM would mean the query had started needing a privilege
// the agent does not have.
func TestAvailableOnThisKernelDoesNotReportEPERM(t *testing.T) {
	_, err := ABI()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "EPERM") || strings.Contains(err.Error(), "blocked before it reaches") {
		t.Fatalf("the Landlock version query was refused in an unfiltered process: %v", err)
	}
	t.Logf("this kernel has no Landlock, which is a property of the machine: %v", err)
}
