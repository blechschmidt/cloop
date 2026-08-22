package sandbox

// fuzz_test.go fuzzes the .cloop/sandbox.yaml parser.
//
// The parser is one of cloop's few genuinely adversarial inputs: the file
// arrives by `git pull`, anyone who can open a pull request can propose one,
// and on a hub the person who merges it is not the person whose infrastructure
// executes it. So the fuzzer does not check that parsing *succeeds* — most
// random bytes are not YAML. It checks the two properties that must hold no
// matter what came out of the decoder:
//
//  1. Parse never panics, and never returns a spec alongside an error.
//  2. Anything Parse *accepts* is genuinely confined — the invariants are
//     re-derived here from scratch rather than by calling the same validators
//     the parser used, so a validator that is wrong is caught rather than
//     agreed with.

import (
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
)

func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"\n",
		"# comment only\n",
		"image: alpine:3.20\n",
		"image: repo@sha256:" + strings.Repeat("a", 64) + "\n",
		"setup:\n  - pip install -r requirements.txt\n",
		"env:\n  - GITHUB_TOKEN\n",
		"resources:\n  cpu: 2\n  memory: 4g\n  pids: 512\n",
		"capabilities:\n  git: true\n  network: ci\n",
		"mounts:\n  - source: .cache\n    target: /cache\n    read_only: true\n",

		// Escapes and injections the schema must refuse.
		"mounts:\n  - source: ../../../etc\n    target: /etc\n",
		"mounts:\n  - source: /etc/shadow\n    target: /x\n",
		"mounts:\n  - source: \"a:/etc:rw\"\n    target: /x\n",
		"mounts:\n  - source: a/../../b\n    target: /x\n",
		"setup:\n  - \"echo hi\\nFROM evil\\nCOPY / /\"\n",
		"env:\n  - \"PATH=/evil\"\n",
		"image: \"--privileged\"\n",
		"image: \"a b\"\n",

		// Numeric edges, including the int64 overflow that used to walk past
		// the memory ceiling.
		"resources:\n  memory: 99999999999999999t\n",
		"resources:\n  memory: 9223372036854775807g\n",
		"resources:\n  memory: 0\n",
		"resources:\n  cpu: 1e300\n",
		"resources:\n  pids: -1\n",

		// YAML shapes that are not a mapping at all.
		"- a\n- b\n",
		"just a string\n",
		"123\n",
		"image:\n  nested: true\n",
		"&a [*a]\n",
		"a: &x\n  b: *x\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		spec, warnings, err := Parse(data)

		if err != nil {
			if spec != nil {
				t.Fatalf("Parse returned both a spec and an error %v — a caller that checks "+
					"only one of them gets a half-validated spec", err)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("error %q does not wrap ErrInvalidSpec; it would render as a 500 "+
					"instead of a 400 the author can act on", err)
			}
			return
		}
		if spec == nil {
			t.Fatal("Parse returned nil spec and nil error")
		}

		checkAccepted(t, spec)

		// Warnings are shown to a human; an unbounded one from a repo-supplied
		// file is a log-flooding primitive.
		for _, w := range warnings {
			if len(w) > 4096 {
				t.Fatalf("warning is %d bytes", len(w))
			}
		}

		// Hashing must be total and stable over anything that parsed —
		// it is the derived-image cache key, so a panic or an unstable value
		// here is a wrong image, not just a bad log line.
		if h := spec.Hash(); len(h) != 64 {
			t.Fatalf("Hash() = %q, want 64 hex characters", h)
		}
		if spec.Hash() != spec.Hash() {
			t.Fatal("Hash() is not deterministic")
		}
	})
}

// checkAccepted re-derives every confinement invariant from the parsed spec.
//
// Deliberately independent of the validators Parse used: asserting with the
// same code that decided would only prove the parser is self-consistent, which
// it would be even if it were wrong.
func checkAccepted(t *testing.T, spec *Spec) {
	t.Helper()

	// --- mounts cannot escape the workspace ---------------------------------
	if len(spec.Mounts) > executor.MaxSpecMounts {
		t.Fatalf("accepted %d mounts, over the cap of %d", len(spec.Mounts), executor.MaxSpecMounts)
	}
	targets := make(map[string]struct{}, len(spec.Mounts))
	for _, m := range spec.Mounts {
		switch {
		case m.Source == "" || m.Target == "":
			t.Fatalf("accepted a mount with an empty path: %+v", m)
		case strings.HasPrefix(m.Source, "/"):
			t.Fatalf("accepted an absolute mount source %q — it names a host path", m.Source)
		case !strings.HasPrefix(m.Target, "/"):
			t.Fatalf("accepted a relative mount target %q", m.Target)
		case m.Target == "/":
			t.Fatalf("accepted a mount over the sandbox root")
		case strings.ContainsAny(m.Source+m.Target, ":\x00\n\r\\"):
			t.Fatalf("accepted a mount with a separator or control character: %+v", m)
		}
		for _, p := range []string{m.Source, m.Target} {
			for _, elem := range strings.Split(p, "/") {
				if elem == ".." {
					t.Fatalf("accepted %q, which escapes its root", p)
				}
			}
			if path.Clean(p) != p {
				t.Fatalf("accepted the unclean path %q", p)
			}
		}
		if _, dup := targets[m.Target]; dup {
			t.Fatalf("accepted a duplicate mount target %q", m.Target)
		}
		targets[m.Target] = struct{}{}
	}

	// --- env carries names, never values ------------------------------------
	if len(spec.Env) > MaxEnvNames {
		t.Fatalf("accepted %d env names, over the cap of %d", len(spec.Env), MaxEnvNames)
	}
	for _, name := range spec.Env {
		if name == "" {
			t.Fatal("accepted an empty env name")
		}
		if strings.ContainsRune(name, '=') {
			t.Fatalf("accepted env %q — a value smuggled in through the allowlist", name)
		}
		for i, r := range name {
			ok := r == '_' ||
				(r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9' && i > 0)
			if !ok {
				t.Fatalf("accepted env name %q containing %q", name, r)
			}
		}
	}

	// --- setup becomes Dockerfile RUN lines ---------------------------------
	if len(spec.Setup) > MaxSetupCommands {
		t.Fatalf("accepted %d setup commands, over the cap of %d", len(spec.Setup), MaxSetupCommands)
	}
	for _, cmd := range spec.Setup {
		if strings.TrimSpace(cmd) == "" {
			t.Fatal("accepted a blank setup command")
		}
		if strings.ContainsAny(cmd, "\n\r\x00") {
			t.Fatalf("accepted a multi-line setup command %q — it would inject a "+
				"Dockerfile instruction nobody reviewed", cmd)
		}
		if len(cmd) > MaxSetupCmdLen {
			t.Fatalf("accepted a %d-byte setup command", len(cmd))
		}
	}

	// --- numerics are bounded ------------------------------------------------
	if spec.Resources.CPU < 0 || spec.Resources.CPU > config.ContainerCPUsUpper {
		t.Fatalf("accepted cpu %v, outside [0, %v]", spec.Resources.CPU, config.ContainerCPUsUpper)
	}
	if spec.Resources.PIDs < 0 || spec.Resources.PIDs > config.ContainerPIDsUpper {
		t.Fatalf("accepted pids %d, outside [0, %d]", spec.Resources.PIDs, config.ContainerPIDsUpper)
	}
	if spec.Resources.Memory != "" {
		mb, err := config.ParseMemoryMB(spec.Resources.Memory)
		if err != nil {
			t.Fatalf("accepted memory %q that does not re-parse: %v", spec.Resources.Memory, err)
		}
		if mb > config.ContainerMemoryMBUpper {
			t.Fatalf("accepted memory %q = %d MB, over the ceiling of %d MB",
				spec.Resources.Memory, mb, config.ContainerMemoryMBUpper)
		}
	}

	// --- the applied spec is one the drivers will accept ---------------------
	//
	// The parser's job is not done when it returns a struct; it is done when
	// that struct survives the executor's own validation. A spec that parses
	// here and is refused two layers down is a 500 with a driver-shaped
	// message, which is the failure mode this whole file exists to prevent.
	applied := executor.Spec{WorkDir: "/w", Argv: []string{"cloop"}}
	res := &Resolved{Spec: spec, Hash: spec.Hash()}
	if err := res.ApplyTo(&applied, "/w", allowAll{}); err != nil {
		var denied *GrantDeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("ApplyTo rejected an accepted spec: %v", err)
		}
	}
	if err := applied.Validate(); err != nil {
		t.Fatalf("an accepted spec produced an executor.Spec the drivers refuse: %v", err)
	}

	// A spec that asks for something but names no grant must always end up with
	// the network removed. This is the one-directional guarantee, checked on
	// every accepted input rather than only on the handful the unit tests
	// enumerate.
	//
	// Conditioned on Present() because an empty file — one holding only
	// comments — asks for nothing at all, and applying it is a no-op that
	// leaves the operator's defaults exactly as they were. Confining a project
	// because it created a placeholder would be a surprise, not a guarantee.
	if res.Present() && spec.Capabilities.Network == "" && !applied.DisableNetwork {
		t.Fatal("a spec with no egress grant did not disable the network")
	}
	if !res.Present() && (applied.DisableNetwork || applied.Image != "" || len(applied.Mounts) > 0) {
		t.Fatalf("an empty spec modified the run: %+v", applied)
	}
}
