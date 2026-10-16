package config

import (
	"strings"
	"testing"
)

// TestConfiguredExecutorLabels (Task 20432): the labels a configured executor
// carries for label grants are its section's, keyed by its registry ID, for
// the executors the configuration enables.
func TestConfiguredExecutorLabels(t *testing.T) {
	var e ExecutorsConfig
	if got := e.ConfiguredExecutorLabels(); len(got) != 0 {
		t.Errorf("nothing enabled = %v", got)
	}
	e.Container = ContainerExecutorConfig{Enabled: true, Labels: map[string]string{" region ": " eu "}}
	e.Kubernetes = KubernetesExecutorConfig{Enabled: true, ID: "k8s-prod", Labels: map[string]string{"tier": "prod"}}
	got := e.ConfiguredExecutorLabels()
	if got["container"]["region"] != "eu" || got["k8s-prod"]["tier"] != "prod" || len(got) != 2 {
		t.Errorf("ConfiguredExecutorLabels = %v", got)
	}
	// Two sections claiming one ID label nothing.
	e.Kubernetes.ID = "container"
	if got := e.ConfiguredExecutorLabels(); len(got) != 0 {
		t.Errorf("a shared ID = %v, want no labels for it", got)
	}
}

// TestExecutorLabelsAreValidatedAndRepaired: a label no selector could match
// is refused where it is typed and dropped, with a warning, on load.
func TestExecutorLabelsAreValidatedAndRepaired(t *testing.T) {
	c := ContainerExecutorConfig{Labels: map[string]string{"region": "eu,us"}}
	if err := ValidateContainerExecutor(c); err == nil || !strings.Contains(err.Error(), "executors.container.labels") {
		t.Errorf("ValidateContainerExecutor = %v, want the labels refused", err)
	}
	k := KubernetesExecutorConfig{Labels: map[string]string{"bad key": "x"}}
	if err := ValidateKubernetesExecutor(k); err == nil || !strings.Contains(err.Error(), "executors.kubernetes.labels") {
		t.Errorf("ValidateKubernetesExecutor = %v, want the labels refused", err)
	}

	c = ContainerExecutorConfig{Labels: map[string]string{"region": "eu,us", "tier": " prod "}}
	changed := clampContainerExecutor(&c)
	if c.Labels["tier"] != "prod" || len(c.Labels) != 1 {
		t.Errorf("repaired labels = %v, want the matchable one kept, trimmed", c.Labels)
	}
	if len(changed) == 0 || !strings.Contains(strings.Join(changed, "\n"), `dropped "region"`) {
		t.Errorf("repairs = %v, want the dropped label named", changed)
	}
	k = KubernetesExecutorConfig{Labels: map[string]string{"a,b": "x"}}
	clampKubernetesExecutor(&k)
	if k.Labels != nil {
		t.Errorf("an all-invalid label set = %v, want none", k.Labels)
	}
}
