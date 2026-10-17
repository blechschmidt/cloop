// Package isolationprobe verifies what a sandbox runtime is from what the
// kernel serving a workload says about itself (Task 20439).
//
// executor.IsVirtualizedRuntime and IsUserspaceKernelRuntime read a runtime's
// *name*, and placement honoured a project's demand for a virtual machine or a
// userspace kernel on that name alone. A daemon.json alias, or a RuntimeClass
// whose handler is runc, ran such a project on the host kernel with nothing to
// say so. This package is the half that looks: the probe a sandbox runs under
// the runtime it claims, and the rules that turn what the probe saw into a
// verdict.
//
// # The probe
//
// `cloop isolation-probe` reads, from inside the sandbox, what only the kernel
// serving it can answer: uname(2), /proc/version, the boot ID that kernel drew
// when it booted, its uptime, the CPU's hypervisor flag, the machine's DMI vendor
// and product, and gVisor's markers — its fixed kernel build and the boot log
// only the Sentry writes. The binary is the hub's or the agent's own, bound into
// the sandbox read-only, so an image cannot substitute a probe that says what it
// likes: the image supplies a root filesystem, and nothing the probe reads comes
// from it.
//
// # The verdict
//
// Classify compares that evidence with the executing host's own kernel, which
// the hub reads directly for its own container executor and an agent reports
// for its device. The boot ID settles most cases outright: a runc container
// reads its host's, because there is only one kernel, while a VM and a gVisor
// sandbox each draw their own. What a different kernel is — a VM's or gVisor's —
// is then read from markers neither can hide, and anything else is "unknown",
// which is never mistaken for isolation.
//
// A hypervisor flag or a cloud vendor's DMI string is not evidence on its own.
// Both hosts this was built against are virtual machines themselves, so a runc
// container on either shows both, and only the comparison with the host's own
// kernel tells that container from a Kata guest.
package isolationprobe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Schema is the version of Evidence this build writes. A reader accepts any
// version it can decode; fields are only ever added.
const Schema = 1

// Arg is the argument that puts the cloop binary into probe mode:
// `cloop isolation-probe`. main dispatches on it before anything else in the
// binary runs, so the probe needs no configuration, no home directory and no
// writable filesystem — a sandbox gives it none of those.
const Arg = "isolation-probe"

// outputKey marks the probe's line on stdout, so a reader can find it in output
// a runtime or a shell may have written around it.
const outputKey = "cloop_isolation_probe"

// MaxOutput bounds how much of a probe's output a reader takes. Evidence is a
// few hundred bytes; the bound is for a sandbox that prints something else.
const MaxOutput = 64 << 10

// Field bounds, applied by Sanitize. Evidence crosses a trust boundary — a
// sandbox prints it, a device reports it — and is rendered in the dashboard.
const (
	maxField = 512
	maxList  = 8
)

// Evidence is what one kernel says about itself: read by the probe from inside
// a sandbox, or by a hub or an agent about the kernel it runs on.
type Evidence struct {
	// Schema is the version of this struct the writer knew.
	Schema int `json:"schema"`
	// Release, Version and Machine are uname(2)'s fields: "6.8.0-79-generic",
	// "#79-Ubuntu SMP PREEMPT_DYNAMIC Tue Aug 12 14:42:46 UTC 2025", "x86_64".
	Release string `json:"release,omitempty"`
	Version string `json:"version,omitempty"`
	Machine string `json:"machine,omitempty"`
	// ProcVersion is /proc/version, which names the compiler and the builder
	// as well — two kernels can share a release and differ here.
	ProcVersion string `json:"proc_version,omitempty"`
	// BootID is /proc/sys/kernel/random/boot_id: a random UUID a Linux kernel
	// draws once per boot. A container sharing its host's kernel reads the
	// host's; a VM's guest kernel and gVisor's Sentry each draw their own.
	BootID string `json:"boot_id,omitempty"`
	// UptimeSeconds is /proc/uptime's first field: how long the kernel serving
	// the reader has been up. A sandbox's own kernel was booted for it.
	UptimeSeconds float64 `json:"uptime_seconds,omitempty"`
	// Hypervisor reports whether /proc/cpuinfo's flags include "hypervisor",
	// the CPUID bit a hypervisor sets for its guests. A guest of any VM sets
	// it — including a runc container on a host that is itself a cloud VM.
	Hypervisor bool `json:"hypervisor,omitempty"`
	// HypervisorType is /sys/hypervisor/type ("xen") where the kernel has one.
	HypervisorType string `json:"hypervisor_type,omitempty"`
	// DMIVendor and DMIProduct are /sys/class/dmi/id/sys_vendor and
	// product_name: "QEMU" and "Standard PC (Q35 + ICH9, 2009)" in a QEMU
	// guest, "Cloud Hypervisor", or the cloud's name on a cloud VM.
	DMIVendor  string `json:"dmi_vendor,omitempty"`
	DMIProduct string `json:"dmi_product,omitempty"`
	// GVisor names the gVisor markers the probe found: gVisor's fixed kernel
	// build string, a release naming it, a command line naming it, and the
	// boot log only the Sentry writes ("Starting gVisor...").
	GVisor []string `json:"gvisor,omitempty"`
	// Unreadable lists what the probe could not read and why, for the
	// essential fields only — a sandbox that hides its kernel says so.
	Unreadable []string `json:"unreadable,omitempty"`
}

// IsZero reports whether the evidence names no kernel at all.
func (e Evidence) IsZero() bool {
	return e.Release == "" && e.Version == "" && e.ProcVersion == "" && e.BootID == ""
}

// Kernel renders the kernel the evidence names, as uname -rv would.
func (e Evidence) Kernel() string {
	k := strings.TrimSpace(e.Release + " " + e.Version)
	if k == "" {
		k = e.ProcVersion
	}
	if k == "" {
		return "an unnamed kernel"
	}
	return k
}

// Sanitize bounds every field and drops control characters, so evidence a
// device or a sandbox wrote cannot carry more than it describes into the
// database or the dashboard.
func (e Evidence) Sanitize() Evidence {
	out := Evidence{
		Schema:         e.Schema,
		Release:        clean(e.Release),
		Version:        clean(e.Version),
		Machine:        clean(e.Machine),
		ProcVersion:    clean(e.ProcVersion),
		BootID:         clean(e.BootID),
		Hypervisor:     e.Hypervisor,
		HypervisorType: clean(e.HypervisorType),
		DMIVendor:      clean(e.DMIVendor),
		DMIProduct:     clean(e.DMIProduct),
		GVisor:         cleanList(e.GVisor),
		Unreadable:     cleanList(e.Unreadable),
	}
	// Uptime is a measurement, not a string, but a negative or absurd one is
	// still not something to compare against.
	if e.UptimeSeconds > 0 && e.UptimeSeconds < 1e10 {
		out.UptimeSeconds = e.UptimeSeconds
	}
	return out
}

// clean trims s, replaces control characters and invalid UTF-8 with spaces,
// collapses runs of whitespace and bounds the result.
func clean(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
		if b.Len() >= maxField {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > maxField {
		out = out[:maxField]
		for !utf8.ValidString(out) {
			out = out[:len(out)-1]
		}
	}
	return out
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if c := clean(s); c != "" {
			out = append(out, c)
		}
		if len(out) == maxList {
			break
		}
	}
	return out
}

// line is the probe's output: one JSON object on one line.
type line struct {
	Probe    int      `json:"cloop_isolation_probe"`
	Evidence Evidence `json:"evidence"`
}

// Encode renders evidence as the probe's output line, newline included.
func Encode(e Evidence) ([]byte, error) {
	b, err := json.Marshal(line{Probe: 1, Evidence: e.Sanitize()})
	if err != nil {
		return nil, fmt.Errorf("isolationprobe: encode evidence: %w", err)
	}
	return append(b, '\n'), nil
}

// ErrNoEvidence is returned by Decode when the output holds no probe line.
var ErrNoEvidence = errors.New("isolationprobe: the probe printed no evidence")

// Decode finds the probe's line in a sandbox's output and returns the
// evidence on it, sanitized. Only the first MaxOutput bytes are read.
//
// The last probe line wins, and anything around it is ignored: a runtime may
// write a warning to the same stream, and a probe that cannot run at all —
// "exec format error", a cloop too old to know the mode — prints none, which
// the error then quotes so the reader learns which.
func Decode(out []byte) (Evidence, error) {
	if len(out) > MaxOutput {
		out = out[:MaxOutput]
	}
	var (
		found bool
		ev    Evidence
	)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), MaxOutput)
	for sc.Scan() {
		t := bytes.TrimSpace(sc.Bytes())
		if !bytes.HasPrefix(t, []byte(`{"`+outputKey+`"`)) {
			continue
		}
		var l line
		if err := json.Unmarshal(t, &l); err != nil || l.Probe < 1 {
			continue
		}
		ev, found = l.Evidence, true
	}
	if !found {
		if snippet := clean(string(out)); snippet != "" {
			if len(snippet) > 200 {
				snippet = snippet[:200] + "…"
			}
			return Evidence{}, fmt.Errorf("%w; it printed %q", ErrNoEvidence, snippet)
		}
		return Evidence{}, fmt.Errorf("%w; it printed nothing", ErrNoEvidence)
	}
	return ev.Sanitize(), nil
}
