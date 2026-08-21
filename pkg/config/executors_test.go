package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/container"
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
		"empty":         {},
		"podman":        {Runtime: "podman"},
		"docker":        {Runtime: "docker"},
		"limits":        {CPUs: 2, Memory: "1g", PIDsLimit: 512},
		"unlimited pids": {PIDsLimit: -1},
		"bridge":        {Network: "bridge"},
		"named network": {Network: "cloop-egress", AllowHosts: []string{"api.example.com:10.0.0.5"}},
		"selinux":       {SELinuxLabel: "z"},
		"extra args":    {ExtraArgs: []string{"--dns=10.0.0.53"}},
		"custom image":  {Image: "ghcr.io/example/harness:v1"},
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
