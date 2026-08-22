package config

// kata_test.go covers the config surface for VM-isolated executors: the two
// new keys, and the clamp behaviour that must not quietly weaken a sandbox.

import (
	"strings"
	"testing"
)

func TestContainerExecutorDriverOptionsCarriesOCIRuntime(t *testing.T) {
	c := ContainerExecutorConfig{Enabled: true, OCIRuntime: "  kata-qemu  "}
	opts, err := c.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if opts.OCIRuntime != "kata-qemu" {
		t.Errorf("OCIRuntime = %q, want the trimmed name reaching the driver", opts.OCIRuntime)
	}
}

func TestContainerExecutorDriverOptionsRejectsRuntimePath(t *testing.T) {
	c := ContainerExecutorConfig{Enabled: true, OCIRuntime: "/usr/bin/kata-runtime"}
	if _, err := c.DriverOptions(); err == nil {
		t.Error("DriverOptions accepted a path as oci_runtime — config must not be able " +
			"to name a binary that dockerd will execute as root")
	}
}

func TestValidateContainerExecutorOCIRuntime(t *testing.T) {
	t.Run("accepts a kata name", func(t *testing.T) {
		if err := ValidateContainerExecutor(ContainerExecutorConfig{Enabled: true, OCIRuntime: "kata"}); err != nil {
			t.Errorf("ValidateContainerExecutor rejected oci_runtime=kata: %v", err)
		}
	})
	t.Run("accepts empty", func(t *testing.T) {
		if err := ValidateContainerExecutor(ContainerExecutorConfig{Enabled: true}); err != nil {
			t.Errorf("ValidateContainerExecutor rejected an unset oci_runtime: %v", err)
		}
	})
	t.Run("rejects a path", func(t *testing.T) {
		err := ValidateContainerExecutor(ContainerExecutorConfig{Enabled: true, OCIRuntime: "./kata"})
		if err == nil {
			t.Fatal("ValidateContainerExecutor accepted a path as oci_runtime")
		}
		if !strings.Contains(err.Error(), "oci_runtime") {
			t.Errorf("error %q does not name the offending key", err)
		}
	})
}

// TestClampContainerExecutorDisablesOnBadOCIRuntime is the important one.
//
// Every other clamp in clampContainerExecutor resets to the zero value,
// because for every other field the driver default confines at least as much
// as the value being rejected. oci_runtime inverts that: its zero value is
// runc, so blanking a malformed Kata name would leave the executor running
// happily with a *container* sandbox while the operator's config — and their
// mental model — says VM.
//
// So the executor is disabled instead. A hub with one fewer executor is a
// visible failure an operator can act on; a hub whose sandbox is weaker than
// its config describes is not.
func TestClampContainerExecutorDisablesOnBadOCIRuntime(t *testing.T) {
	c := ContainerExecutorConfig{Enabled: true, OCIRuntime: "/usr/bin/kata-runtime"}
	changed := clampContainerExecutor(&c)

	if c.Enabled {
		t.Error("a malformed oci_runtime left the executor enabled; it would run with the " +
			"default runtime while the config asks for a VM")
	}
	if c.OCIRuntime == "" {
		t.Error("oci_runtime was blanked — the value must be preserved so the warning and " +
			"the config still agree about what was asked for")
	}
	if len(changed) == 0 {
		t.Fatal("clamp reported no change, so Load would warn about nothing")
	}
	joined := strings.Join(changed, "\n")
	if !strings.Contains(joined, "oci_runtime") {
		t.Errorf("warning does not name the key:\n%s", joined)
	}
	if !strings.Contains(joined, "disabled") {
		t.Errorf("warning does not say the executor was disabled, so an operator would not "+
			"know why it is missing:\n%s", joined)
	}
}

// TestClampContainerExecutorKeepsValidOCIRuntime is the other half: a correct
// Kata configuration must survive the clamp untouched.
func TestClampContainerExecutorKeepsValidOCIRuntime(t *testing.T) {
	c := ContainerExecutorConfig{Enabled: true, OCIRuntime: "kata-qemu"}
	changed := clampContainerExecutor(&c)

	if !c.Enabled {
		t.Error("a valid kata configuration was disabled by the clamp")
	}
	if c.OCIRuntime != "kata-qemu" {
		t.Errorf("OCIRuntime = %q, want it left alone", c.OCIRuntime)
	}
	for _, msg := range changed {
		if strings.Contains(msg, "oci_runtime") {
			t.Errorf("clamp warned about a valid oci_runtime: %s", msg)
		}
	}
}

// --- kubernetes ----------------------------------------------------------

func TestKubernetesExecutorDriverOptionsCarriesRuntimeClass(t *testing.T) {
	k := KubernetesExecutorConfig{Enabled: true, Namespace: "cloop", RuntimeClass: "  kata-qemu  "}
	opts, err := k.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if opts.RuntimeClass != "kata-qemu" {
		t.Errorf("RuntimeClass = %q, want the trimmed name reaching the driver", opts.RuntimeClass)
	}
}

func TestValidateKubernetesExecutorRuntimeClass(t *testing.T) {
	t.Run("accepts a kata class", func(t *testing.T) {
		k := KubernetesExecutorConfig{Enabled: true, Namespace: "cloop", RuntimeClass: "kata-qemu"}
		if err := ValidateKubernetesExecutor(k); err != nil {
			t.Errorf("ValidateKubernetesExecutor rejected runtime_class=kata-qemu: %v", err)
		}
	})
	t.Run("rejects a non-RFC1123 name", func(t *testing.T) {
		k := KubernetesExecutorConfig{Enabled: true, Namespace: "cloop", RuntimeClass: "Kata Qemu"}
		err := ValidateKubernetesExecutor(k)
		if err == nil {
			t.Fatal("ValidateKubernetesExecutor accepted a RuntimeClass the API server would reject")
		}
		if !strings.Contains(err.Error(), "runtime_class") {
			t.Errorf("error %q does not name the offending key", err)
		}
	})
}

// TestClampKubernetesExecutorDisablesOnBadRuntimeClass mirrors the container
// case. It goes through the section's existing catch-all rather than a
// dedicated check, but the outcome that matters is the same: never silently
// fall back to the cluster default runtime when a Kata class was requested.
func TestClampKubernetesExecutorDisablesOnBadRuntimeClass(t *testing.T) {
	k := KubernetesExecutorConfig{Enabled: true, Namespace: "cloop", RuntimeClass: "Kata Qemu"}
	changed := clampKubernetesExecutor(&k)

	if k.Enabled {
		t.Error("a malformed runtime_class left the executor enabled; every Pod it created " +
			"would run on the cluster default runtime instead of kata")
	}
	if len(changed) == 0 {
		t.Fatal("clamp reported no change, so Load would warn about nothing")
	}
	if !strings.Contains(strings.Join(changed, "\n"), "kubernetes") {
		t.Errorf("warning does not name the section:\n%s", strings.Join(changed, "\n"))
	}
}
