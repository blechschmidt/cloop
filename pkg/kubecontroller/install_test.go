package kubecontroller

// Tests for the install commands the hub hands an administrator (Task 20486):
// the plan is validated as the controller would validate the pool it
// creates, its values reach the chart as written, and the credential never
// becomes a helm value.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func goodPlan() InstallPlan {
	return InstallPlan{Chart: "https://hub.example.com" + ChartArchivePath, PoolName: "gpu",
		HubURL: "https://hub.example.com", HubCAPin: "sha256:" + strings.Repeat("A", 43) + "=", ImageTag: "edge",
		MaxRunners: 4}.Normalize()
}

func TestInstallPlanDefaultsAndValidation(t *testing.T) {
	p := goodPlan()
	if p.Release != "gpu" || p.Namespace != "cloop-gpu" || p.CredentialSecret != "gpu-pool-credential" {
		t.Fatalf("defaults: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("a good plan: %v", err)
	}
	long := strings.Repeat("a", 63)
	if got := (InstallPlan{PoolName: long}).Normalize(); len(got.Release) > 53 || len(got.Namespace) > 63 {
		t.Fatalf("a long pool's names: %q %q", got.Release, got.Namespace)
	}
	bad := map[string]func(*InstallPlan){
		"a plaintext hub":             func(p *InstallPlan) { p.HubURL = "http://hub.example.com" },
		"a namespace that is not one": func(p *InstallPlan) { p.Namespace = "Runners_1" },
		"a release that is too long":  func(p *InstallPlan) { p.Release = strings.Repeat("r", 54) },
		"min above max":               func(p *InstallPlan) { p.MinRunners = 5 },
		"no runners at all":           func(p *InstallPlan) { p.MaxRunners = 0 },
		"a pin that is not one":       func(p *InstallPlan) { p.HubCAPin = "sha256:short" },
		"a size that is no quantity":  func(p *InstallPlan) { p.Persistence = &InstallPersistence{Size: "big", ReclaimPolicy: ReclaimDelete} },
		"a volume under minFree":      func(p *InstallPlan) { p.Persistence = &InstallPersistence{Size: "1Gi", ReclaimPolicy: ReclaimDelete} },
		"an unknown reclaim policy":   func(p *InstallPlan) { p.Persistence = &InstallPersistence{Size: "20Gi", ReclaimPolicy: "Recycle"} },
		"a storage class that is not one": func(p *InstallPlan) {
			p.Persistence = &InstallPersistence{Size: "20Gi", StorageClass: "Fast SSD", ReclaimPolicy: ReclaimDelete}
		},
		"an image tag with a space": func(p *InstallPlan) { p.ImageTag = "v1 2" },
		"a chart of two words":      func(p *InstallPlan) { p.Chart = "a b" },
	}
	for name, mutate := range bad {
		p := goodPlan()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

func TestInstallScriptKeepsTheCredentialInASecret(t *testing.T) {
	p := goodPlan()
	p.HubCAPin = "sha256:" + strings.Repeat("A", 43) + "=,sha256:" + strings.Repeat("B", 43) + "="
	p.Persistence = &InstallPersistence{Size: "50Gi", StorageClass: "fast", ReclaimPolicy: ReclaimRetain}
	cred := "cloop_pool1_AAAAAAAAAAAAAAAA.it's-secret"
	script := p.Script(cred)
	for _, want := range []string{
		"kubectl apply --server-side -f - <<'EOF'\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: cloop-gpu\n" +
			"  labels:\n    pod-security.kubernetes.io/enforce: restricted\nEOF\n",
		"--dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -\n",
		"kubectl -n cloop-gpu create secret generic gpu-pool-credential",
		`--from-literal=credential='cloop_pool1_AAAAAAAAAAAAAAAA.it'\''s-secret'`,
		"helm install gpu https://hub.example.com/charts/cloop-executor-controller.tgz",
		// A comma in a pin list is escaped from --set's own list syntax, and
		// the backslash quoted from the shell.
		`--set-string 'pool.hubCAPin=sha256:` + strings.Repeat("A", 43) + `=\,sha256:`,
		"--set-string pool.persistence.reclaimPolicy=Retain",
		"--set-string image.tag=edge",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script lacks %q:\n%s", want, script)
		}
	}
	if strings.Count(script, cred[:20]) != 1 || strings.Contains(script, "credential.value") {
		t.Errorf("the credential is somewhere besides the Secret:\n%s", script)
	}
	if rot := p.RotationScript(cred); !strings.Contains(rot, "create secret generic gpu-pool-credential") ||
		strings.Contains(rot, "helm") {
		t.Errorf("the rotation script:\n%s", rot)
	}
	if up := p.UpgradeCommand(); up != "helm upgrade gpu https://hub.example.com/charts/cloop-executor-controller.tgz "+
		"-n cloop-gpu --reuse-values --set-string image.tag=edge\n" {
		t.Errorf("the upgrade command: %q", up)
	}
}

func TestControllerImageTagFollowsTheHubsBuild(t *testing.T) {
	if tag, note := ControllerImageTag("v0.0.9"); tag != "0.0.9" || note != "" {
		t.Errorf("a release: %q %q", tag, note)
	}
	for _, v := range []string{"dev", "dev+g1a2b3c4", "", "v0.0.9+g1a2b3c4"} {
		if tag, note := ControllerImageTag(v); tag != "edge" || !strings.Contains(note, "edge") {
			t.Errorf("%q: %q %q", v, tag, note)
		}
	}
}

// TestInstallPlanRendersThePoolItSays renders the plan's own helm arguments
// with the chart and reads back the ExecutorPool: the values reach the chart
// as the plan says, and the pool is one the controller accepts.
func TestInstallPlanRendersThePoolItSays(t *testing.T) {
	helm := helmBinary(t)
	p := goodPlan()
	p.MinRunners = 1
	p.Persistence = &InstallPersistence{Size: "50Gi", StorageClass: "fast", ReclaimPolicy: ReclaimRetain}
	args := p.HelmArgs()
	var set []string
	for i := 0; i < len(args); i += 2 {
		switch args[i] {
		case "-n":
		case "--set", "--set-string":
			set = append(set, args[i]+"="+args[i+1])
		default:
			t.Fatalf("an argument the test cannot replay: %s", args[i])
		}
	}
	out, err := helmTemplateArgs(t, helm, set)
	if err != nil {
		t.Fatalf("the chart refused the plan's values: %v", err)
	}
	var pool *ExecutorPool
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var m map[string]any
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode the rendered chart: %v", err)
		}
		if chartObject(m).kind() == "ExecutorPool" {
			pool = &ExecutorPool{}
			chartObject(m).into(t, pool)
		}
	}
	if pool == nil {
		t.Fatalf("no ExecutorPool rendered:\n%s", out)
	}
	s := pool.Spec.Normalize()
	if pool.Metadata.Name != "gpu" || s.HubURL != p.HubURL || s.HubCAPin != p.HubCAPin ||
		s.PoolCredentialSecretRef.Name != "gpu-pool-credential" || s.MaxRunners != 4 || s.MinRunners != 1 {
		t.Errorf("the rendered pool: %+v", pool)
	}
	if s.Persistence == nil || !s.Persistence.Enabled || s.Persistence.Size != "50Gi" ||
		s.Persistence.StorageClassName != "fast" || s.Persistence.ReclaimPolicy != ReclaimRetain {
		t.Errorf("the rendered pool's volumes: %+v", s.Persistence)
	}
	if problems := s.Validate(); len(problems) > 0 {
		t.Errorf("the controller would refuse the rendered pool: %v", problems)
	}
	if !strings.Contains(string(out), ":edge") {
		t.Errorf("the controller's image is not the plan's tag")
	}
}

// helmTemplateArgs is helmTemplate for arguments given as flag=value, so a
// --set-string survives as one.
func helmTemplateArgs(t *testing.T, helm string, flags []string) ([]byte, error) {
	t.Helper()
	var set []string
	var str []string
	for _, f := range flags {
		switch {
		case strings.HasPrefix(f, "--set-string="):
			str = append(str, strings.TrimPrefix(f, "--set-string="))
		case strings.HasPrefix(f, "--set="):
			set = append(set, strings.TrimPrefix(f, "--set="))
		}
	}
	return helmTemplateStrings(t, helm, set, str)
}

// helmTemplateStrings renders the chart with --set and --set-string values,
// in Helm state directories of the test's own.
func helmTemplateStrings(t *testing.T, helm string, set, setString []string) ([]byte, error) {
	t.Helper()
	args := []string{"template", "ctl", chartDir(t), "--namespace", chartNamespace}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	for _, s := range setString {
		args = append(args, "--set-string", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, helm, args...)
	tmp := t.TempDir()
	cmd.Env = append(os.Environ(), "HELM_CACHE_HOME="+filepath.Join(tmp, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(tmp, "config"), "HELM_DATA_HOME="+filepath.Join(tmp, "data"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(strings.TrimSpace(err.Error() + "\n" + stderr.String()))
	}
	return out, nil
}
