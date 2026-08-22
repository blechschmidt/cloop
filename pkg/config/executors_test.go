package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

func TestParseMemoryMB(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "512m", want: 512},
		{in: "512M", want: 512},
		{in: "2g", want: 2048},
		{in: "2G", want: 2048},
		{in: "1t", want: 1024 * 1024},
		{in: "1048576k", want: 1024},
		{in: "1024k", want: 1},
		{in: "536870912b", want: 512},
		// A bare integer means megabytes. The runtimes read it as *bytes*,
		// which would turn "512" into half a kilobyte and an
		// instantly-OOMing sandbox.
		{in: "512", want: 512},
		{in: "  1g  ", want: 1024},
		// Sub-megabyte requests round up rather than collapsing to 0, which
		// would read as "no limit".
		{in: "1b", want: 1},
		{in: "1k", want: 1},
		{in: "0", want: 0},

		{in: "abc", wantErr: true},
		{in: "-5m", wantErr: true},
		{in: "m", wantErr: true},
		{in: "1.5g", wantErr: true},
		{in: "9999999t", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseMemoryMB(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseMemoryMB(%q) = %d, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMemoryMB(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseMemoryMB(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateContainerExecutor(t *testing.T) {
	valid := map[string]ContainerExecutorConfig{
		"empty":          {},
		"podman":         {Runtime: "podman"},
		"docker":         {Runtime: "docker"},
		"limits":         {CPUs: 2, Memory: "1g", PIDsLimit: 512},
		"unlimited pids": {PIDsLimit: -1},
		"bridge":         {Network: "bridge"},
		"named network":  {Network: "cloop-egress", AllowHosts: []string{"api.example.com:10.0.0.5"}},
		"selinux":        {SELinuxLabel: "z"},
		"extra args":     {ExtraArgs: []string{"--dns=10.0.0.53"}},
		"custom image":   {Image: "ghcr.io/example/harness:v1"},
	}
	for name, cfg := range valid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateContainerExecutor(cfg); err != nil {
				t.Fatalf("ValidateContainerExecutor(%+v) = %v, want nil", cfg, err)
			}
		})
	}

	invalid := map[string]struct {
		cfg  ContainerExecutorConfig
		want string
	}{
		"unknown runtime":      {ContainerExecutorConfig{Runtime: "containerd"}, "runtime must be"},
		"arbitrary binary":     {ContainerExecutorConfig{Runtime: "bash"}, "runtime must be"},
		"negative cpus":        {ContainerExecutorConfig{CPUs: -1}, "cpus must be >= 0"},
		"absurd cpus":          {ContainerExecutorConfig{CPUs: 100000}, "cpus must be <="},
		"unparsable memory":    {ContainerExecutorConfig{Memory: "lots"}, "not a size"},
		"tiny memory":          {ContainerExecutorConfig{Memory: "8m"}, "at least"},
		"bad pids":             {ContainerExecutorConfig{PIDsLimit: -5}, "pids_limit"},
		"huge pids":            {ContainerExecutorConfig{PIDsLimit: 1 << 20}, "pids_limit"},
		"bad selinux":          {ContainerExecutorConfig{SELinuxLabel: "q"}, "selinux_label"},
		"host network":         {ContainerExecutorConfig{Network: "host"}, "not permitted"},
		"privileged extra arg": {ContainerExecutorConfig{ExtraArgs: []string{"--privileged"}}, "not allowed"},
		"positional extra arg": {ContainerExecutorConfig{ExtraArgs: []string{"evil/image"}}, "must be a flag"},
		"bad image":            {ContainerExecutorConfig{Image: "-rm"}, "image reference"},
		"allow_hosts no net":   {ContainerExecutorConfig{AllowHosts: []string{"a:1.2.3.4"}}, "allow_hosts"},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			err := ValidateContainerExecutor(tc.cfg)
			if err == nil {
				t.Fatalf("ValidateContainerExecutor(%+v) = nil, want an error", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestValidateContainerExecutor_RunsWhenDisabled: a disabled-but-broken
// config should be reported when it is written, not discovered months later
// at the moment someone flips enabled to true.
func TestValidateContainerExecutor_RunsWhenDisabled(t *testing.T) {
	cfg := ContainerExecutorConfig{Enabled: false, ExtraArgs: []string{"--privileged"}}
	if err := ValidateContainerExecutor(cfg); err == nil {
		t.Fatal("a disabled executor with a dangerous flag must still be rejected")
	}
}

func TestDriverOptions(t *testing.T) {
	cfg := ContainerExecutorConfig{
		ID:           "sandbox",
		Runtime:      "podman",
		Image:        "ghcr.io/example/harness:v1",
		CPUs:         1.5,
		Memory:       "2g",
		PIDsLimit:    256,
		Network:      "cloop-egress",
		AllowHosts:   []string{"api.example.com:10.0.0.5"},
		ExtraArgs:    []string{"--dns=10.0.0.53"},
		SELinuxLabel: "z",
	}
	opts, err := cfg.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if opts.ID != "sandbox" || opts.Runtime != "podman" || opts.Image != "ghcr.io/example/harness:v1" {
		t.Fatalf("identity fields not carried through: %+v", opts)
	}
	if opts.CPUs != 1.5 || opts.MemoryMB != 2048 || opts.PIDsLimit != 256 {
		t.Fatalf("limits not carried through: %+v", opts)
	}
	if opts.Network != "cloop-egress" || len(opts.AllowHosts) != 1 {
		t.Fatalf("network settings not carried through: %+v", opts)
	}
	if opts.SELinuxLabel != "z" {
		t.Fatalf("selinux label not carried through: %+v", opts)
	}
}

func TestDriverOptions_DefaultsAreConfined(t *testing.T) {
	// An empty config must not produce a permissive executor.
	opts, err := ContainerExecutorConfig{}.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if opts.Network != container.NetworkNone {
		t.Errorf("default network = %q, want %q", opts.Network, container.NetworkNone)
	}
	if opts.Image != container.DefaultImage {
		t.Errorf("default image = %q, want %q", opts.Image, container.DefaultImage)
	}
	if opts.PIDsLimit <= 0 {
		t.Errorf("default PIDsLimit = %d, want a positive process cap", opts.PIDsLimit)
	}
}

// TestClampContainerExecutor checks the defensive Load() path: a hand-edited
// YAML must be repaired to the driver's conservative defaults rather than
// honoured or fatal.
func TestClampContainerExecutor(t *testing.T) {
	cases := []struct {
		name   string
		in     ContainerExecutorConfig
		verify func(*testing.T, ContainerExecutorConfig)
	}{
		{
			name: "unknown runtime is cleared",
			in:   ContainerExecutorConfig{Runtime: "containerd"},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if c.Runtime != "" {
					t.Errorf("Runtime = %q, want cleared", c.Runtime)
				}
			},
		},
		{
			name: "out-of-range cpus is cleared",
			in:   ContainerExecutorConfig{CPUs: 1e9},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if c.CPUs != 0 {
					t.Errorf("CPUs = %v, want 0", c.CPUs)
				}
			},
		},
		{
			name: "unparsable memory is cleared",
			in:   ContainerExecutorConfig{Memory: "banana"},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if c.Memory != "" {
					t.Errorf("Memory = %q, want cleared", c.Memory)
				}
			},
		},
		{
			name: "host network is cleared, not honoured",
			in:   ContainerExecutorConfig{Network: "host"},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if c.Network != "" {
					t.Errorf("Network = %q, want cleared so the driver default (none) applies", c.Network)
				}
			},
		},
		{
			name: "dangerous extra args are dropped wholesale",
			in:   ContainerExecutorConfig{ExtraArgs: []string{"--dns=1.1.1.1", "--privileged"}},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if len(c.ExtraArgs) != 0 {
					t.Errorf("ExtraArgs = %v, want empty — a partially-applied flag list is nobody's intent", c.ExtraArgs)
				}
			},
		},
		{
			name: "allow_hosts without a network is dropped",
			in:   ContainerExecutorConfig{AllowHosts: []string{"a:1.2.3.4"}},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if len(c.AllowHosts) != 0 {
					t.Errorf("AllowHosts = %v, want empty", c.AllowHosts)
				}
			},
		},
		{
			name: "valid config is untouched",
			in:   ContainerExecutorConfig{Runtime: "podman", CPUs: 2, Memory: "1g", Network: "bridge", PIDsLimit: 512},
			verify: func(t *testing.T, c ContainerExecutorConfig) {
				if c.Runtime != "podman" || c.CPUs != 2 || c.Memory != "1g" || c.Network != "bridge" || c.PIDsLimit != 512 {
					t.Errorf("a valid config was modified: %+v", c)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.in
			changed := clampContainerExecutor(&cfg)
			tc.verify(t, cfg)
			// Whatever the input, the result must now be valid — otherwise
			// Load() would hand the runtime a config it cannot use.
			if err := ValidateContainerExecutor(cfg); err != nil {
				t.Fatalf("clamped config is still invalid: %v (changes: %v)", err, changed)
			}
		})
	}
}

// TestClampNeverWidensConfinement is the property that matters: every repair
// must leave the sandbox at least as confined as before.
func TestClampNeverWidensConfinement(t *testing.T) {
	hostile := []ContainerExecutorConfig{
		{Network: "host"},
		{Network: "container:victim"},
		{ExtraArgs: []string{"--privileged"}},
		{ExtraArgs: []string{"--cap-add=SYS_ADMIN"}},
		{ExtraArgs: []string{"--volume=/:/host"}},
		{ExtraArgs: []string{"--user=0:0"}},
		{PIDsLimit: -99},
		{Image: "-rm"},
	}
	for _, cfg := range hostile {
		in := cfg
		clampContainerExecutor(&cfg)
		opts, err := cfg.DriverOptions()
		if err != nil {
			t.Fatalf("clamped %+v still cannot build driver options: %v", in, err)
		}
		if opts.Network != container.NetworkNone {
			t.Errorf("clamping %+v left network %q; a repair must never grant egress", in, opts.Network)
		}
		if err := container.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			t.Errorf("clamping %+v left dangerous extra args: %v", in, err)
		}
		if opts.PIDsLimit == 0 {
			t.Errorf("clamping %+v removed the process cap entirely", in)
		}
	}
}

// TestLoadClampsContainerExecutor exercises the whole path: a YAML file with
// a dangerous value must load successfully with the value repaired, because a
// long-running server cannot be allowed to fail closed on config reload.
func TestLoadClampsContainerExecutor(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `provider: claudecode
executors:
  container:
    enabled: true
    runtime: containerd
    network: host
    cpus: 999999
    memory: banana
    extra_args:
      - --privileged
`
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load must not fail on a repairable config: %v", err)
	}
	c := cfg.Executors.Container
	if !c.Enabled {
		t.Error("enabled should survive clamping; only the invalid fields are repaired")
	}
	if c.Runtime != "" || c.Network != "" || c.CPUs != 0 || c.Memory != "" || len(c.ExtraArgs) != 0 {
		t.Fatalf("dangerous values survived Load: %+v", c)
	}
	if err := cfg.ValidateNumeric(); err != nil {
		t.Fatalf("a loaded config must pass strict validation: %v", err)
	}
}

func TestValidateNumericIncludesContainerExecutor(t *testing.T) {
	cfg := &Config{}
	cfg.Executors.Container.ExtraArgs = []string{"--privileged"}
	if err := cfg.ValidateNumeric(); err == nil {
		t.Fatal("ValidateNumeric must reject a dangerous container extra_arg")
	}
}

// ── executors.allow_host_process (Task 20160) ───────────────────────────────

// TestHostProcessAllowed_DefaultsPermissive pins the back-compat contract: an
// existing single-machine install that upgrades into a cloop with this setting
// must keep running, so absent means allowed.
func TestHostProcessAllowed_DefaultsPermissive(t *testing.T) {
	var e ExecutorsConfig
	if !e.HostProcessAllowed() {
		t.Error("an absent executors.allow_host_process must default to true — " +
			"otherwise upgrading breaks every existing install")
	}
	if e.HostProcessExplicit() {
		t.Error("an absent setting must not report as an explicit operator decision")
	}
}

func TestHostProcessAllowed_ExplicitValues(t *testing.T) {
	for _, want := range []bool{true, false} {
		var e ExecutorsConfig
		e.SetHostProcessAllowed(want)
		if got := e.HostProcessAllowed(); got != want {
			t.Errorf("HostProcessAllowed after Set(%v) = %v", want, got)
		}
		if !e.HostProcessExplicit() {
			t.Errorf("Set(%v) must record the decision as explicit", want)
		}
	}
}

// TestHostProcessAllowed_ExplicitFalseSurvivesSave is the reason the field is a
// *bool. With a plain `bool` and `omitempty`, an explicit false marshals to
// nothing and the next Load reads it back as the permissive default — silently
// re-enabling host execution on a hardened deployment the first time anything
// writes the config.
func TestHostProcessAllowed_ExplicitFalseSurvivesSave(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.Executors.SetHostProcessAllowed(false)
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "allow_host_process: false") {
		t.Fatalf("explicit false was not written to disk:\n%s", raw)
	}

	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.Executors.HostProcessAllowed() {
		t.Error("executors.allow_host_process: false did not survive a Save/Load round trip — " +
			"a hardened control plane would silently re-open host execution")
	}
	if !reloaded.Executors.HostProcessExplicit() {
		t.Error("the explicit decision was lost across a round trip")
	}
}

func TestHostProcessAllowed_ExplicitTrueSurvivesSave(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.Executors.SetHostProcessAllowed(true)
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reloaded.Executors.HostProcessExplicit() {
		t.Error("an explicit true must round-trip as explicit, not collapse into the default — " +
			"the UI banner distinguishes 'decided' from 'nobody has decided'")
	}
}

// TestValidateExecutors_StrictModeWithNoAlternativesIsNotFatal locks in a
// deliberate choice: hardening the control plane before any device has
// enrolled is a legitimate intermediate state, and making it a fatal config
// error would mean a hardened deployment refuses to boot until a device
// happens to be online — backwards for a security control.
func TestValidateExecutors_StrictModeWithNoAlternativesIsNotFatal(t *testing.T) {
	var e ExecutorsConfig
	e.SetHostProcessAllowed(false)
	if err := ValidateExecutors(e); err != nil {
		t.Fatalf("ValidateExecutors = %v, want nil: strict mode before enrollment must load", err)
	}
	warnings := ExecutorWarnings(e)
	if len(warnings) == 0 {
		t.Fatal("strict mode with no configured executor produces no warning — " +
			"the operator gets no signal that nothing can run")
	}
	if !strings.Contains(warnings[0], "allow_host_process") {
		t.Errorf("warning %q does not name the setting responsible", warnings[0])
	}
}

// TestValidateExecutors_StillCatchesContainerProblems: the new field must not
// have shadowed the existing container validation.
func TestValidateExecutors_StillCatchesContainerProblems(t *testing.T) {
	e := ExecutorsConfig{Container: ContainerExecutorConfig{ExtraArgs: []string{"--privileged"}}}
	e.SetHostProcessAllowed(false)
	if err := ValidateExecutors(e); err == nil {
		t.Fatal("ValidateExecutors accepted a container section with --privileged")
	}
}

func TestExecutorWarnings_QuietWhenCoherent(t *testing.T) {
	// Strict mode with a container executor configured: nothing to warn about.
	strictAndSandboxed := ExecutorsConfig{Container: ContainerExecutorConfig{Enabled: true}}
	strictAndSandboxed.SetHostProcessAllowed(false)
	if w := ExecutorWarnings(strictAndSandboxed); len(w) != 0 {
		t.Errorf("a coherent hardened config produced warnings: %v", w)
	}

	// Plain single-machine default: also nothing to warn about. Nagging the
	// laptop case would train operators to ignore the warnings that matter.
	if w := ExecutorWarnings(ExecutorsConfig{}); len(w) != 0 {
		t.Errorf("the zero-config default produced warnings: %v", w)
	}
}

// TestExecutorWarnings_SandboxConfiguredButNotEnforced catches the
// half-hardened config: an operator who enabled the container executor but
// never flipped allow_host_process still runs unbound projects on the host,
// which is exactly the state they believed they had left.
func TestExecutorWarnings_SandboxConfiguredButNotEnforced(t *testing.T) {
	e := ExecutorsConfig{Container: ContainerExecutorConfig{Enabled: true}}
	w := ExecutorWarnings(e)
	if len(w) == 0 {
		t.Fatal("a container executor with host execution still permitted produced no warning")
	}
	if !strings.Contains(w[0], "allow_host_process") {
		t.Errorf("warning %q does not name the setting to flip", w[0])
	}
}

// TestExecutorWarnings_InClusterWithoutANamespace: the in-cluster fallback is
// the *hub's own* namespace, which puts model-authored workloads next to the
// control plane's Secrets and its ServiceAccount token. That is a materially
// worse default than the brokered-kubeconfig one, so it gets its own warning
// rather than sharing the generic "namespace is unset" text.
func TestExecutorWarnings_InClusterWithoutANamespace(t *testing.T) {
	e := ExecutorsConfig{Kubernetes: KubernetesExecutorConfig{Enabled: true, InCluster: true}}
	e.SetHostProcessAllowed(false)

	var found string
	for _, w := range ExecutorWarnings(e) {
		if strings.Contains(w, "in_cluster") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("in-cluster mode with no namespace produced no warning: %v", ExecutorWarnings(e))
	}
	if !strings.Contains(found, "own namespace") {
		t.Errorf("warning %q does not say where the Pods actually land", found)
	}

	// With a namespace set, the warning goes away.
	e.Kubernetes.Namespace = "cloop-workloads"
	for _, w := range ExecutorWarnings(e) {
		if strings.Contains(w, "in_cluster") {
			t.Errorf("still warned after a namespace was set: %q", w)
		}
	}
}

// --- kubernetes executor (Task 20161) ---------------------------------

func TestValidateKubernetesExecutor(t *testing.T) {
	valid := map[string]KubernetesExecutorConfig{
		"empty":       {},
		"namespace":   {Namespace: "cloop-jobs"},
		"quantities":  {CPURequest: "250m", CPULimit: "2", MemoryRequest: "512Mi", MemoryLimit: "4Gi"},
		"scheduling":  {NodeSelector: map[string]string{"pool": "untrusted"}, Tolerations: []kubernetes.Toleration{{Key: "k", Operator: "Exists"}}},
		"deadlines":   {ActiveDeadlineSeconds: 3600, TerminationGracePeriodSeconds: 45, KillGracePeriodSeconds: 5},
		"pull config": {ImagePullPolicy: "IfNotPresent", ImagePullSecrets: []string{"ghcr-auth"}},
		"identity":    {ServiceAccount: "cloop-runner", RunAsUser: 1000, RunAsGroup: 1000},
		"concurrency": {MaxConcurrent: 8},
		"secret ref":  {KubeconfigSecret: "prod-kubeconfig", Context: "prod"},
		"in cluster":  {InCluster: true, Namespace: "cloop-workloads"},
	}
	for name, cfg := range valid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateKubernetesExecutor(cfg); err != nil {
				t.Fatalf("ValidateKubernetesExecutor(%+v) = %v, want nil", cfg, err)
			}
		})
	}

	invalid := map[string]struct {
		cfg  KubernetesExecutorConfig
		want string
	}{
		"reserved namespace":   {KubernetesExecutorConfig{Namespace: "kube-system"}, "reserved"},
		"bad namespace":        {KubernetesExecutorConfig{Namespace: "Prod Cluster"}, "RFC 1123"},
		"bad image":            {KubernetesExecutorConfig{Image: "-rm"}, "must not begin with '-'"},
		"bad pull policy":      {KubernetesExecutorConfig{ImagePullPolicy: "whenever"}, "image_pull_policy"},
		"bad quantity":         {KubernetesExecutorConfig{MemoryLimit: "4 gigs"}, "memory_limit"},
		"zero quantity":        {KubernetesExecutorConfig{CPULimit: "0"}, "greater than zero"},
		"negative deadline":    {KubernetesExecutorConfig{ActiveDeadlineSeconds: -1}, "active_deadline_seconds"},
		"absurd deadline":      {KubernetesExecutorConfig{ActiveDeadlineSeconds: 1 << 40}, "active_deadline_seconds"},
		"negative grace":       {KubernetesExecutorConfig{KillGracePeriodSeconds: -5}, "kill_grace_period_seconds"},
		"negative uid":         {KubernetesExecutorConfig{RunAsUser: -1}, "run_as_user"},
		"absurd concurrency":   {KubernetesExecutorConfig{MaxConcurrent: 1 << 20}, "max_concurrent"},
		"negative concurrency": {KubernetesExecutorConfig{MaxConcurrent: -1}, "max_concurrent"},
		"bad toleration":       {KubernetesExecutorConfig{Tolerations: []kubernetes.Toleration{{Operator: "Matches"}}}, "tolerations[0]"},
		"bad pull secret":      {KubernetesExecutorConfig{ImagePullSecrets: []string{"Bad Name"}}, "image_pull_secrets"},
		// Two credential sources is an ambiguity about which identity ran a
		// workload, and that question has to have one answer in an audit log.
		"two credential sources": {
			KubernetesExecutorConfig{InCluster: true, KubeconfigSecret: "prod-kubeconfig"},
			"mutually exclusive",
		},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			err := ValidateKubernetesExecutor(tc.cfg)
			if err == nil {
				t.Fatalf("ValidateKubernetesExecutor(%+v) = nil, want an error", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestValidateKubernetesExecutor_RunsWhenDisabled: same rule as the container
// section — a disabled-but-broken config is reported when it is written.
func TestValidateKubernetesExecutor_RunsWhenDisabled(t *testing.T) {
	cfg := KubernetesExecutorConfig{Enabled: false, Namespace: "kube-system"}
	if err := ValidateKubernetesExecutor(cfg); err == nil {
		t.Fatal("a disabled executor pointed at kube-system must still be rejected")
	}
}

func TestKubernetesDriverOptions(t *testing.T) {
	cfg := KubernetesExecutorConfig{
		ID:                            "prod-k8s",
		Namespace:                     "cloop-jobs",
		Image:                         "ghcr.io/example/harness:v1",
		ImagePullPolicy:               "IfNotPresent",
		ImagePullSecrets:              []string{"ghcr-auth"},
		ServiceAccount:                "cloop-runner",
		CPURequest:                    "250m",
		CPULimit:                      "2",
		MemoryRequest:                 "512Mi",
		MemoryLimit:                   "4Gi",
		EphemeralStorageLimit:         "10Gi",
		WorkspaceSizeLimit:            "5Gi",
		NodeSelector:                  map[string]string{"cloop.dev/pool": "untrusted"},
		Tolerations:                   []kubernetes.Toleration{{Key: "cloop.dev/untrusted", Operator: "Exists", Effect: "NoSchedule"}},
		ActiveDeadlineSeconds:         3600,
		TerminationGracePeriodSeconds: 45,
		KillGracePeriodSeconds:        3,
		OrphanGracePeriodSeconds:      120,
		RunAsUser:                     1000,
		RunAsGroup:                    1000,
		KeepCompletedPods:             true,
		MaxConcurrent:                 8,
	}
	opts, err := cfg.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if opts.ID != "prod-k8s" || opts.Namespace != "cloop-jobs" || opts.Image != "ghcr.io/example/harness:v1" {
		t.Fatalf("identity fields not carried through: %+v", opts)
	}
	if opts.CPULimit != "2" || opts.MemoryLimit != "4Gi" || opts.EphemeralStorageLimit != "10Gi" {
		t.Fatalf("limits not carried through: %+v", opts)
	}
	if opts.ActiveDeadlineSeconds != 3600 {
		t.Fatalf("active_deadline_seconds = %d", opts.ActiveDeadlineSeconds)
	}
	if opts.TerminationGracePeriod != 45*time.Second || opts.KillGracePeriod != 3*time.Second ||
		opts.OrphanGracePeriod != 120*time.Second {
		t.Fatalf("durations not converted: %+v", opts)
	}
	if opts.MaxConcurrent != 8 || !opts.KeepCompletedPods {
		t.Fatalf("flags not carried through: %+v", opts)
	}
	if len(opts.Tolerations) != 1 || opts.Tolerations[0].Key != "cloop.dev/untrusted" {
		t.Fatalf("tolerations not carried through: %+v", opts.Tolerations)
	}
	// Credentials must be nil: only a caller holding a broker can supply
	// them, and a config validator must not need a decryption key.
	if opts.Credentials != nil {
		t.Fatal("DriverOptions supplied a credential source; that is the CLI's job, not config's")
	}
}

func TestKubernetesDriverOptions_DefaultsAreConfined(t *testing.T) {
	opts, err := KubernetesExecutorConfig{}.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if opts.ID != kubernetes.DefaultID || opts.Image != kubernetes.DefaultImage {
		t.Errorf("defaults = %s/%s", opts.ID, opts.Image)
	}
	if opts.TerminationGracePeriod != kubernetes.DefaultTerminationGracePeriod {
		t.Errorf("termination grace = %v", opts.TerminationGracePeriod)
	}
	if opts.KillGracePeriod != kubernetes.DefaultKillGracePeriod {
		t.Errorf("kill grace = %v", opts.KillGracePeriod)
	}
	if opts.OrphanGracePeriod != kubernetes.DefaultOrphanGracePeriod {
		t.Errorf("orphan grace = %v", opts.OrphanGracePeriod)
	}
	// Unbounded by default: cloop runs are long-lived by design (Task 20148).
	if opts.ActiveDeadlineSeconds != 0 {
		t.Errorf("active_deadline_seconds defaulted to %d, want unbounded", opts.ActiveDeadlineSeconds)
	}
}

// TestClampKubernetesExecutor is the defensive Load() path: a hand-edited
// YAML must be repaired to the driver's conservative defaults rather than
// honoured or fatal.
func TestClampKubernetesExecutor(t *testing.T) {
	cases := []struct {
		name   string
		in     KubernetesExecutorConfig
		verify func(*testing.T, KubernetesExecutorConfig)
	}{
		{
			name: "reserved namespace is cleared, not honoured",
			in:   KubernetesExecutorConfig{Namespace: "kube-system"},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if c.Namespace != "" {
					t.Errorf("Namespace = %q, want cleared so the driver default applies", c.Namespace)
				}
			},
		},
		{
			name: "out-of-range deadline is cleared",
			in:   KubernetesExecutorConfig{ActiveDeadlineSeconds: 1 << 40},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if c.ActiveDeadlineSeconds != 0 {
					t.Errorf("ActiveDeadlineSeconds = %d, want 0", c.ActiveDeadlineSeconds)
				}
			},
		},
		{
			name: "unparsable quantity is cleared",
			in:   KubernetesExecutorConfig{MemoryLimit: "four gigs"},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if c.MemoryLimit != "" {
					t.Errorf("MemoryLimit = %q, want cleared", c.MemoryLimit)
				}
			},
		},
		{
			name: "bad image is cleared",
			in:   KubernetesExecutorConfig{Image: "-rm"},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if c.Image != "" {
					t.Errorf("Image = %q, want cleared", c.Image)
				}
			},
		},
		{
			name: "bad pull policy is cleared",
			in:   KubernetesExecutorConfig{ImagePullPolicy: "whenever"},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if c.ImagePullPolicy != "" {
					t.Errorf("ImagePullPolicy = %q, want cleared", c.ImagePullPolicy)
				}
			},
		},
		{
			name: "bad tolerations are dropped wholesale",
			in: KubernetesExecutorConfig{Tolerations: []kubernetes.Toleration{
				{Key: "good", Operator: "Exists"},
				{Operator: "Matches"},
			}},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if len(c.Tolerations) != 0 {
					t.Errorf("Tolerations = %v, want empty — a half-applied toleration set schedules "+
						"onto a node pool nobody chose", c.Tolerations)
				}
			},
		},
		{
			name: "negative uid is cleared to the non-root default",
			in:   KubernetesExecutorConfig{RunAsUser: -5},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if c.RunAsUser != 0 {
					t.Errorf("RunAsUser = %d, want 0 so the driver's non-root default applies", c.RunAsUser)
				}
			},
		},
		{
			name: "a good config is untouched",
			in: KubernetesExecutorConfig{
				Enabled: true, Namespace: "cloop-jobs", CPULimit: "2", MemoryLimit: "4Gi",
			},
			verify: func(t *testing.T, c KubernetesExecutorConfig) {
				if !c.Enabled || c.Namespace != "cloop-jobs" || c.CPULimit != "2" || c.MemoryLimit != "4Gi" {
					t.Errorf("a valid config was modified: %+v", c)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.in
			changed := clampKubernetesExecutor(&cfg)
			if tc.name != "a good config is untouched" && len(changed) == 0 {
				t.Fatalf("clampKubernetesExecutor(%+v) reported no changes", tc.in)
			}
			tc.verify(t, cfg)
			// Whatever survives clamping must validate, or Load would produce
			// a config that `cloop config set` would reject.
			if err := ValidateKubernetesExecutor(cfg); err != nil {
				t.Errorf("clamped config still fails validation: %v", err)
			}
		})
	}
}

// TestKubernetesEgressFilter_Validation: the filter is compiled at validation
// time by the same function that renders the NetworkPolicy at Start, so a
// section that loads is one that can actually produce a firewall.
func TestKubernetesEgressFilter_Validation(t *testing.T) {
	valid := map[string]KubernetesEgressFilterConfig{
		"absent":          {},
		"cidrs and ports": {Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{443, 6443}},
		"public internet": {Enabled: true, AllowPublicInternet: true, Ports: []int{443}},
		"resolvers":       {Enabled: true, Resolvers: []string{"10.96.0.10", "10.96.0.11:53"}},
		// Enabled with nothing allowed is a legitimate configuration: it denies
		// every packet, which is what a hub running untrusted code that needs no
		// network wants.
		"deny all": {Enabled: true},
	}
	for name, filter := range valid {
		t.Run(name, func(t *testing.T) {
			cfg := KubernetesExecutorConfig{Namespace: "cloop-jobs", EgressFilter: filter}
			if err := ValidateKubernetesExecutor(cfg); err != nil {
				t.Fatalf("ValidateKubernetesExecutor(%+v) = %v, want nil", filter, err)
			}
		})
	}

	invalid := map[string]struct {
		filter KubernetesEgressFilterConfig
		want   string
	}{
		"bad cidr":  {KubernetesEgressFilterConfig{Enabled: true, CIDRs: []string{"10.8.0.0"}, Ports: []int{443}}, "cidrs[0]"},
		"bad port":  {KubernetesEgressFilterConfig{Enabled: true, CIDRs: []string{"10.8.0.0/24"}, Ports: []int{0}}, "ports[0]"},
		"no ports":  {KubernetesEgressFilterConfig{Enabled: true, CIDRs: []string{"10.8.0.0/24"}}, "no ports"},
		"resolver":  {KubernetesEgressFilterConfig{Enabled: true, Resolvers: []string{"dns.example.com"}}, "resolvers[0]"},
		"full zero": {KubernetesEgressFilterConfig{Enabled: true, CIDRs: []string{"0.0.0.0/0"}, Ports: []int{443}}, "not an allowlist entry"},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			cfg := KubernetesExecutorConfig{Namespace: "cloop-jobs", EgressFilter: tc.filter}
			err := ValidateKubernetesExecutor(cfg)
			if err == nil {
				t.Fatalf("ValidateKubernetesExecutor(%+v) = nil, want an error", tc.filter)
			}
			if !strings.Contains(err.Error(), "egress_filter") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name executors.kubernetes.egress_filter and %q", err, tc.want)
			}
		})
	}
}

// TestKubernetesEgressFilter_DriverOptions: the section reaches the driver
// intact. A field dropped here is a filter the operator wrote and the cluster
// never sees.
func TestKubernetesEgressFilter_DriverOptions(t *testing.T) {
	off := false
	cfg := KubernetesExecutorConfig{
		Namespace: "cloop-jobs",
		EgressFilter: KubernetesEgressFilterConfig{
			Enabled:             true,
			CIDRs:               []string{"10.8.0.0/24"},
			Ports:               []int{443},
			AllowPublicInternet: true,
			Resolvers:           []string{"10.96.0.10"},
			AllowClusterDNS:     &off,
		},
	}
	opts, err := cfg.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	f := opts.EgressFilter
	if !f.Enabled || !f.AllowPublicInternet || len(f.CIDRs) != 1 || len(f.Ports) != 1 || len(f.Resolvers) != 1 {
		t.Fatalf("egress filter not carried through: %+v", f)
	}
	if f.ClusterDNSAllowed() {
		t.Error("allow_cluster_dns=false did not survive; the pointer's tri-state is the point of it")
	}

	// Absent means no filtering at all, which is what keeps an upgrade from
	// firewalling a deployment that never asked for it.
	plain, err := KubernetesExecutorConfig{}.DriverOptions()
	if err != nil {
		t.Fatalf("DriverOptions: %v", err)
	}
	if plain.EgressFilter.Enabled {
		t.Error("an absent egress_filter section enabled filtering")
	}
	if !plain.EgressFilter.ClusterDNSAllowed() {
		t.Error("an unset allow_cluster_dns must read as true, or a default-deny policy breaks DNS")
	}
}

// TestKubernetesEgressFilter_YAMLKeys pins the key names an operator writes and
// the Helm chart renders. A struct tag renamed without the chart is a config
// file that loads with the filter silently off.
func TestKubernetesEgressFilter_YAMLKeys(t *testing.T) {
	const doc = `
executors:
  kubernetes:
    enabled: true
    namespace: cloop-jobs
    egress_filter:
      enabled: true
      cidrs: ["10.8.0.0/24"]
      ports: [443]
      allow_public_internet: true
      resolvers: ["10.96.0.10:53"]
      allow_cluster_dns: false
`
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := cfg.Executors.Kubernetes.EgressFilter
	if !f.Enabled || !f.AllowPublicInternet {
		t.Fatalf("egress_filter did not parse: %+v", f)
	}
	if len(f.CIDRs) != 1 || f.CIDRs[0] != "10.8.0.0/24" || len(f.Ports) != 1 || f.Ports[0] != 443 {
		t.Fatalf("allowlist did not parse: %+v", f)
	}
	if len(f.Resolvers) != 1 || f.AllowClusterDNS == nil || *f.AllowClusterDNS {
		t.Fatalf("resolvers/allow_cluster_dns did not parse: %+v", f)
	}
}

// TestClampKubernetesExecutor_BrokenEgressFilterDisablesTheExecutor: the clamp
// will not repair this section field-by-field. Dropping the CIDR an operator
// mistyped leaves a filter narrower than they wrote — a total outage — and
// dropping the filter leaves one wider, which is a security control vanishing
// because of a typo. Neither is a repair.
func TestClampKubernetesExecutor_BrokenEgressFilterDisablesTheExecutor(t *testing.T) {
	cfg := KubernetesExecutorConfig{
		Enabled:      true,
		Namespace:    "cloop-jobs",
		EgressFilter: KubernetesEgressFilterConfig{Enabled: true, CIDRs: []string{"not-a-cidr"}, Ports: []int{443}},
	}
	changed := clampKubernetesExecutor(&cfg)
	if cfg.Enabled {
		t.Error("an executor with an uncompilable egress filter was left registered")
	}
	if !cfg.EgressFilter.Enabled || len(cfg.EgressFilter.CIDRs) != 1 {
		t.Errorf("the filter was silently rewritten: %+v", cfg.EgressFilter)
	}
	if len(changed) == 0 || !strings.Contains(strings.Join(changed, " | "), "egress_filter") {
		t.Errorf("clamp report %v does not name egress_filter", changed)
	}
}

// TestExecutorWarnings_Kubernetes: an isolated executor being enabled must
// count toward "some executor exists", and the advisory notes must fire.
func TestExecutorWarnings_Kubernetes(t *testing.T) {
	hardened := ExecutorsConfig{Kubernetes: KubernetesExecutorConfig{Enabled: true, Namespace: "cloop-jobs",
		Image: "ghcr.io/x/y@sha256:" + strings.Repeat("a", 64), CPULimit: "2", MemoryLimit: "4Gi"}}
	hardened.SetHostProcessAllowed(false)
	if got := ExecutorWarnings(hardened); len(got) != 0 {
		t.Errorf("a fully-configured kubernetes executor warned: %v", got)
	}

	bare := ExecutorsConfig{Kubernetes: KubernetesExecutorConfig{Enabled: true}}
	bare.SetHostProcessAllowed(false)
	joined := strings.Join(ExecutorWarnings(bare), " | ")
	for _, want := range []string{"namespace is unset", "cpu_limit", "built-in default"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings %q are missing %q", joined, want)
		}
	}

	// Enabling an isolated executor while host process is still implicitly
	// allowed is the trap the warning exists for.
	permissive := ExecutorsConfig{Kubernetes: KubernetesExecutorConfig{Enabled: true, Namespace: "cloop-jobs"}}
	joined = strings.Join(ExecutorWarnings(permissive), " | ")
	if !strings.Contains(joined, "allow_host_process") {
		t.Errorf("warnings %q do not flag that unbound projects still run on the host", joined)
	}
}
