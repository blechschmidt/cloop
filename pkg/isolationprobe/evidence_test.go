package isolationprobe

import (
	"bytes"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	f := loadFixture(t, "sgx-docker-runsc.json")
	out, err := Encode(f.Probe)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(out, []byte("\n")) != 1 || !bytes.HasSuffix(out, []byte("\n")) {
		t.Fatalf("Encode must write exactly one line, got %q", out)
	}
	// Runtimes and shells write around the probe; the last probe line wins.
	noisy := append([]byte("runsc: warning: something\n{\"not\":\"it\"}\n"), out...)
	noisy = append(noisy, []byte("trailing noise\n")...)
	got, err := Decode(noisy)
	if err != nil {
		t.Fatal(err)
	}
	if got.Release != f.Probe.Release || got.BootID != f.Probe.BootID || len(got.GVisor) != len(f.Probe.GVisor) {
		t.Fatalf("Decode lost evidence: %+v", got)
	}
}

func TestDecodeWithoutEvidenceQuotesTheOutput(t *testing.T) {
	_, err := Decode([]byte("exec /.cloop-isolation-probe/cloop: exec format error\n"))
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("err = %v, want ErrNoEvidence", err)
	}
	if !strings.Contains(err.Error(), "exec format error") {
		t.Errorf("error %q should quote what the sandbox printed", err)
	}
	if _, err := Decode(nil); !errors.Is(err, ErrNoEvidence) || !strings.Contains(err.Error(), "nothing") {
		t.Errorf("empty output: err = %v", err)
	}
	if _, err := Decode([]byte(`{"cloop_isolation_probe":1,"evidence":{"release":` + "\n")); !errors.Is(err, ErrNoEvidence) {
		t.Errorf("a truncated line must not decode: err = %v", err)
	}
}

// TestSanitizeBoundsWhatADeviceCanSend: evidence arrives from devices and
// sandboxes and is stored and rendered, so every field is bounded and stripped
// of control characters.
func TestSanitizeBoundsWhatADeviceCanSend(t *testing.T) {
	long := strings.Repeat("é", 2000)
	e := Evidence{
		Release:       "6.8\x1b[31m\n-evil",
		Version:       long,
		BootID:        "\x00id",
		GVisor:        []string{"a", "", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
		UptimeSeconds: -5,
	}.Sanitize()
	if strings.ContainsAny(e.Release, "\x1b\n") || e.Release != "6.8 [31m -evil" {
		t.Errorf("Release = %q", e.Release)
	}
	if len(e.Version) > maxField || !strings.HasPrefix(e.Version, "é") {
		t.Errorf("Version is %d bytes, want at most %d", len(e.Version), maxField)
	}
	if e.BootID != "id" {
		t.Errorf("BootID = %q", e.BootID)
	}
	if len(e.GVisor) != maxList {
		t.Errorf("GVisor has %d entries, want %d", len(e.GVisor), maxList)
	}
	if e.UptimeSeconds != 0 {
		t.Errorf("a negative uptime must not survive: %v", e.UptimeSeconds)
	}
	// A line far beyond MaxOutput is not read past the bound.
	huge := append(bytes.Repeat([]byte("x"), MaxOutput+10), []byte("\n")...)
	if _, err := Decode(huge); !errors.Is(err, ErrNoEvidence) {
		t.Errorf("oversized output: err = %v", err)
	}
}

// fakeSource is a captured kernel for collect.
type fakeSource struct {
	release, version, machine string
	files                     map[string]string
	log                       string
}

func (f fakeSource) uname() (string, string, string, error) {
	return f.release, f.version, f.machine, nil
}

func (f fakeSource) readFile(path string) ([]byte, error) {
	if s, ok := f.files[path]; ok {
		return []byte(s), nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

func (f fakeSource) syslog() ([]byte, error) {
	if f.log == "" {
		return nil, fs.ErrPermission
	}
	return []byte(f.log), nil
}

// TestCollectReadsGVisorsMarkers: the files and boot log a gVisor sandbox on
// sgx served, through collect.
func TestCollectReadsGVisorsMarkers(t *testing.T) {
	e := collect(fakeSource{
		release: "4.19.0-gvisor", version: GVisorBuildString, machine: "x86_64",
		files: map[string]string{
			pathProcVersion: "Linux version 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016\n",
			pathBootID:      "e4bdf59a-6ddf-4e29-912c-36f0bd406295\n",
			pathUptime:      "0.04 0.00\n",
			pathCPUInfo:     "processor\t: 0\nmodel name\t: unknown\nflags\t\t: fpu vme hypervisor lahf_lm\n",
			pathCmdline:     "BOOT_IMAGE=/vmlinuz-4.19.0-gvisor quiet\n",
			pathDMIProduct:  "Alibaba Cloud ECS\n",
		},
		log: "[   0.000000] Starting gVisor...\n[   2.1] Ready!\n",
	})
	if len(e.GVisor) != 4 {
		t.Fatalf("GVisor markers = %q, want all four", e.GVisor)
	}
	if !e.Hypervisor || e.DMIProduct != "Alibaba Cloud ECS" || e.DMIVendor != "" {
		t.Errorf("collect = %+v", e)
	}
	if e.UptimeSeconds != 0.04 || e.BootID == "" || e.Schema != Schema {
		t.Errorf("collect = %+v", e)
	}
	if len(e.Unreadable) != 0 {
		t.Errorf("nothing essential was missing, but Unreadable = %q", e.Unreadable)
	}
}

// TestCollectSaysWhatItCouldNotRead: a sandbox that hides the kernel's
// identity is recorded as hiding it.
func TestCollectSaysWhatItCouldNotRead(t *testing.T) {
	e := collect(fakeSource{release: "6.8.0", version: "#1"})
	if len(e.Unreadable) != 2 {
		t.Fatalf("Unreadable = %q, want /proc/version and the boot ID", e.Unreadable)
	}
	if !strings.Contains(strings.Join(e.Unreadable, ";"), "boot_id") {
		t.Errorf("Unreadable = %q", e.Unreadable)
	}
	if cpuFlag([]byte("flags : fpu vme\nflags : hypervisor\n"), "hypervisor") {
		t.Error("only the first flags line is read")
	}
}

// TestCollectReadsThisKernel runs the real collector on the machine running
// the test.
func TestCollectReadsThisKernel(t *testing.T) {
	if runtime.GOOS != "linux" {
		e := Collect()
		if !e.IsZero() || len(e.Unreadable) == 0 {
			t.Fatalf("off Linux, Collect = %+v, want nothing and a reason", e)
		}
		return
	}
	e := Collect()
	if e.Release == "" || e.Version == "" || e.ProcVersion == "" || e.BootID == "" {
		t.Fatalf("Collect = %+v", e)
	}
	// The host is its own reference: the same kernel instance.
	if v := Classify(e, Reference{Kernel: &e, Source: SourceHub, EngineKernel: e.Release}); v.Kind != KindHostKernel {
		t.Fatalf("Classify(self, self) = %s (%s)", v.Kind, v.Detail)
	}
}

func TestProbeMode(t *testing.T) {
	for _, args := range [][]string{
		{"cloop", "isolation-probe"},
		{"/.cloop-isolation-probe/cloop", "isolation-probe"},
	} {
		if !IsInvocation(args) {
			t.Errorf("IsInvocation(%q) = false", args)
		}
	}
	for _, args := range [][]string{
		{"cloop"}, {"cloop", "isolation-probe", "--x"}, {"cloop", "run"}, {"cloop", "--isolation-probe"},
	} {
		if IsInvocation(args) {
			t.Errorf("IsInvocation(%q) = true", args)
		}
	}
	var out, errOut bytes.Buffer
	if code := Main(&out, &errOut); code != 0 {
		t.Fatalf("Main = %d: %s", code, errOut.String())
	}
	if _, err := Decode(out.Bytes()); err != nil && runtime.GOOS == "linux" {
		t.Fatalf("Main's output does not decode: %v", err)
	}
}
