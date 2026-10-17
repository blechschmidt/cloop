package isolationprobe

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// GVisorBuildString is the kernel build string gVisor's Sentry reports as
// uname -v, in every release: the Sentry is not a Linux build and stamps the
// same one regardless of the release it claims to be.
const GVisorBuildString = "#1 SMP Sun Jan 10 15:06:54 PST 2016"

// gVisorBootLine is the first line of the boot log the Sentry synthesises,
// which syslog(2) returns to any process in the sandbox. A Linux kernel's
// boot log never contains it, and a container on one is refused the read
// without CAP_SYSLOG anyway.
const gVisorBootLine = "Starting gVisor"

// The paths the probe reads. They are kernel interfaces, mounted by the
// runtime over whatever the image has at those paths.
const (
	pathProcVersion    = "/proc/version"
	pathBootID         = "/proc/sys/kernel/random/boot_id"
	pathUptime         = "/proc/uptime"
	pathCPUInfo        = "/proc/cpuinfo"
	pathCmdline        = "/proc/cmdline"
	pathHypervisorType = "/sys/hypervisor/type"
	pathDMIVendor      = "/sys/class/dmi/id/sys_vendor"
	pathDMIProduct     = "/sys/class/dmi/id/product_name"
)

// readLimit bounds each file read. /proc/cpuinfo is the largest the probe
// reads — about 1.5 KiB per CPU — and the flags it needs are in its first
// processor block.
const readLimit = 1 << 20

// source is where collect reads from: the running kernel in production, a
// table of captured files in tests.
type source interface {
	uname() (release, version, machine string, err error)
	readFile(path string) ([]byte, error)
	// syslog returns the kernel's boot log, or an error when the reader may
	// not see it — which is the normal answer in a container on Linux.
	syslog() ([]byte, error)
}

// Collect gathers the evidence the running kernel gives this process.
func Collect() Evidence {
	return collect(hostSource{})
}

func collect(src source) Evidence {
	e := Evidence{Schema: Schema}
	unreadable := func(what string, err error) {
		e.Unreadable = append(e.Unreadable, what+": "+errText(err))
	}

	if rel, ver, mach, err := src.uname(); err != nil {
		unreadable("uname", err)
	} else {
		e.Release, e.Version, e.Machine = rel, ver, mach
	}
	if b, err := src.readFile(pathProcVersion); err != nil {
		unreadable(pathProcVersion, err)
	} else {
		e.ProcVersion = firstLine(b)
	}
	if b, err := src.readFile(pathBootID); err != nil {
		unreadable(pathBootID, err)
	} else {
		e.BootID = firstLine(b)
	}
	if b, err := src.readFile(pathUptime); err == nil {
		if f := strings.Fields(firstLine(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				e.UptimeSeconds = v
			}
		}
	}
	if b, err := src.readFile(pathCPUInfo); err == nil {
		e.Hypervisor = cpuFlag(b, "hypervisor")
	}
	// Absent on most kernels, so absence is not recorded as unreadable.
	if b, err := src.readFile(pathHypervisorType); err == nil {
		e.HypervisorType = firstLine(b)
	}
	if b, err := src.readFile(pathDMIVendor); err == nil {
		e.DMIVendor = firstLine(b)
	}
	if b, err := src.readFile(pathDMIProduct); err == nil {
		e.DMIProduct = firstLine(b)
	}

	// gVisor's markers. Any one is enough for Classify, and all are recorded
	// so a reader can see what the verdict rested on.
	if strings.Contains(strings.ToLower(e.Release), "gvisor") {
		e.GVisor = append(e.GVisor, "kernel release "+e.Release)
	}
	if e.Version == GVisorBuildString {
		e.GVisor = append(e.GVisor, "gVisor's kernel build string")
	}
	if b, err := src.readFile(pathCmdline); err == nil &&
		strings.Contains(strings.ToLower(firstLine(b)), "gvisor") {
		e.GVisor = append(e.GVisor, "kernel command line "+firstLine(b))
	}
	if b, err := src.syslog(); err == nil && bytes.Contains(b, []byte(gVisorBootLine)) {
		e.GVisor = append(e.GVisor, "boot log \""+gVisorBootLine+"...\"")
	}
	return e.Sanitize()
}

// cpuFlag reports whether the first "flags" line of a /proc/cpuinfo lists flag.
// Every processor block lists the same flags; the first is enough.
func cpuFlag(cpuinfo []byte, flag string) bool {
	sc := bufio.NewScanner(bytes.NewReader(cpuinfo))
	sc.Buffer(make([]byte, 0, 8192), readLimit)
	for sc.Scan() {
		name, value, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(name) != "flags" {
			continue
		}
		for _, f := range strings.Fields(value) {
			if f == flag {
				return true
			}
		}
		return false
	}
	return false
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// errText renders a read error without the path, which the caller names.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// readBounded reads at most readLimit bytes of path.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, readLimit))
}
