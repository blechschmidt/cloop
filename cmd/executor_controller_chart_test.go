package cmd

// executor_controller_chart_test.go: the Helm chart in
// deploy/helm/cloop-executor-controller (Task 20485) starts
// `cloop executor controller` with flags of its own choosing. This renders
// the chart and parses its arguments with a copy of the command's own flag
// set, and checks what runExecutorController checks before it reaches the
// cluster — so a renamed or retyped flag fails here instead of as a Pod that
// crash-loops. pkg/kubecontroller/helm_test.go checks the rest of the chart.
// It skips without helm; CI's deployment-artifacts job is the gate either
// way, since it installs the chart and waits for both replicas to be ready,
// which they are only once `cloop executor controller` has accepted these
// flags.

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// copyFlags builds a fresh flag set with the same names, types and defaults,
// so parsing in a test leaves the command's own flags untouched.
func copyFlags(t *testing.T, sets ...*pflag.FlagSet) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("executor controller", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, src := range sets {
		src.VisitAll(func(f *pflag.Flag) {
			if fs.Lookup(f.Name) != nil {
				return
			}
			switch f.Value.Type() {
			case "string":
				fs.String(f.Name, f.DefValue, f.Usage)
			case "bool":
				fs.Bool(f.Name, f.DefValue == "true", f.Usage)
			case "int":
				n, _ := strconv.Atoi(f.DefValue)
				fs.Int(f.Name, n, f.Usage)
			case "duration":
				d, _ := time.ParseDuration(f.DefValue)
				fs.Duration(f.Name, d, f.Usage)
			default:
				t.Fatalf("--%s is a %s flag, which this test cannot copy; teach copyFlags it", f.Name, f.Value.Type())
			}
		})
	}
	return fs
}

func TestTheControllerChartPassesFlagsTheCommandAccepts(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CLOOP_REQUIRE_HELM") != "" {
			t.Fatalf("CLOOP_REQUIRE_HELM is set but helm is not on PATH: %v", err)
		}
		t.Skip("helm is not on PATH, so the executor controller chart cannot be rendered")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	chart := filepath.Join(filepath.Dir(wd), "deploy", "helm", "cloop-executor-controller")

	for _, tc := range []struct {
		name string
		set  []string
	}{
		{"defaults", nil},
		{"one replica without leader election", []string{"replicaCount=1", "leaderElection.enabled=false"}},
		{"pinned images and required provenance", []string{"requireDigest=true",
			"image.digest=sha256:" + strings.Repeat("3", 64), "controller.imageProvenance=required",
			"controller.resync=90s", "controller.workers=4", "controller.healthPort=9090"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"template", "ctl", chart, "--namespace", "runners",
				"--show-only", "templates/deployment.yaml"}
			for _, s := range tc.set {
				args = append(args, "--set", s)
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
				t.Fatalf("helm %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
			}
			var dep struct {
				Spec struct {
					Template struct {
						Spec struct {
							Containers []struct {
								Args  []string `yaml:"args"`
								Ports []struct {
									ContainerPort int `yaml:"containerPort"`
								} `yaml:"ports"`
							} `yaml:"containers"`
						} `yaml:"spec"`
					} `yaml:"template"`
				} `yaml:"spec"`
			}
			if err := yaml.Unmarshal(out, &dep); err != nil {
				t.Fatalf("decode the Deployment: %v\n%s", err, out)
			}
			if len(dep.Spec.Template.Spec.Containers) != 1 {
				t.Fatalf("the Deployment has %d containers", len(dep.Spec.Template.Spec.Containers))
			}
			c := dep.Spec.Template.Spec.Containers[0]
			if len(c.Args) < 2 || c.Args[0] != "executor" || c.Args[1] != "controller" {
				t.Fatalf("args %v do not run `cloop executor controller`", c.Args)
			}
			if executorControllerCmd.Name() != "controller" || executorControllerCmd.Parent() != executorCmd {
				t.Fatal("`cloop executor controller` is not where the chart runs it")
			}

			fs := copyFlags(t, executorControllerCmd.LocalFlags(), executorControllerCmd.InheritedFlags())
			if err := fs.Parse(c.Args[2:]); err != nil {
				t.Fatalf("`cloop executor controller` refuses the chart's flags %v: %v", c.Args[2:], err)
			}
			if rest := fs.Args(); len(rest) != 0 {
				t.Fatalf("the command takes no arguments; the chart passes %v", rest)
			}
			// What runExecutorController checks before it reaches a cluster.
			prov, _ := fs.GetString("image-provenance")
			if prov != "warn" && prov != "required" {
				t.Errorf("--image-provenance=%q", prov)
			}
			if resync, _ := fs.GetDuration("resync"); resync < 30*time.Second {
				t.Errorf("--resync=%s is under the command's 30s floor", resync)
			}
			if ns, _ := fs.GetString("namespace"); ns != "runners" {
				t.Errorf("--namespace=%q, want the release namespace", ns)
			}
			if all, _ := fs.GetBool("all-namespaces"); all {
				t.Error("--all-namespaces needs a ClusterRole, which the chart never grants")
			}
			addr, _ := fs.GetString("health-addr")
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("--health-addr=%q: %v", addr, err)
			}
			if len(c.Ports) != 1 || strconv.Itoa(c.Ports[0].ContainerPort) != port {
				t.Errorf("the health endpoint listens on %s but the container declares %+v", port, c.Ports)
			}
			le, _ := fs.GetBool("leader-elect")
			name, _ := fs.GetString("leader-election-name")
			if le && name == "" {
				t.Error("leader election with no Lease name")
			}
			digest, _ := fs.GetBool("require-image-digest")
			if want := strings.Contains(strings.Join(tc.set, " "), "requireDigest=true"); digest != want {
				t.Errorf("--require-image-digest=%v with requireDigest=%v", digest, want)
			}
		})
	}
}
