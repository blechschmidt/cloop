package install

// container.go is the --output docker rendering: an equivalent `podman run`
// invocation and a compose fragment.
//
// "Equivalent" is the design constraint. A device that has podman but no
// systemd should not end up with a materially weaker deployment than one that
// has systemd, so each hardening directive from systemd.go maps onto its
// container-engine counterpart:
//
//	NoNewPrivileges=yes            → --security-opt no-new-privileges
//	CapabilityBoundingSet=         → --cap-drop ALL
//	ProtectSystem=strict           → --read-only + a named volume for state
//	PrivateTmp=yes                 → --tmpfs /tmp
//	UMask=0077 + 0600 credential   → the credential is a read-only bind mount,
//	                                 never an -e environment variable
//
// The credential is mounted rather than passed with -e for the same reason it
// is not in ExecStart: `podman inspect` prints the environment, and a
// container's environment is readable from inside it by anything the harness
// runs.

import (
	"fmt"
	"path/filepath"
	"strings"
)

// containerStatePath is where the state volume is mounted inside the
// container. Fixed, because the host paths in Spec describe the host and the
// container has its own filesystem.
const containerStatePath = "/var/lib/cloop-executor"

// containerSecretPath is where the credential file is bind-mounted read-only.
const containerSecretPath = "/run/secrets/cloop-enrollment"

// containerSpec projects a host Spec onto the paths the containerised agent
// sees. Only the container-internal paths go on the command line; the host
// paths stay in the volume declarations.
func containerSpec(s Spec) Spec {
	c := s
	c.StateDir = containerStatePath
	c.AgentCredential = filepath.Join(containerStatePath, "agent.json")
	c.WorkDirRoot = filepath.Join(containerStatePath, "work")
	c.CredentialsFile = containerSecretPath
	return c
}

// ContainerFragment renders both the `podman run` command and the compose
// service, with the run command first because it is the thing an operator on a
// single device actually pastes.
func ContainerFragment(s Spec) string {
	var b strings.Builder
	b.WriteString("# ── podman / docker run ")
	b.WriteString(strings.Repeat("─", 50))
	b.WriteString("\n")
	b.WriteString("# The enrollment credential is bind-mounted read-only, not passed with -e:\n")
	b.WriteString("# `podman inspect` prints the environment, and so does /proc inside the\n")
	b.WriteString("# container. Write it first:\n")
	fmt.Fprintf(&b, "#   install -m 0600 /dev/null %s\n", s.CredentialsFile)
	fmt.Fprintf(&b, "#   printf '%%s\\n' \"$CLOOP_ENROLL_BUNDLE\" > %s\n", s.CredentialsFile)
	b.WriteString("\n")
	b.WriteString(PodmanRun(s))
	b.WriteString("\n")
	b.WriteString("# ── docker-compose / podman-compose fragment ")
	b.WriteString(strings.Repeat("─", 31))
	b.WriteString("\n")
	b.WriteString(ComposeFragment(s))
	return b.String()
}

// PodmanRun renders the run command. It works unchanged under `docker run`;
// podman is named first because a rootless engine is the better fit for an
// edge device.
func PodmanRun(s Spec) string {
	c := containerSpec(s)
	lines := []string{
		"podman run --detach",
		"  --name " + shellQuote(s.ServiceName),
		"  --restart=always",
		"  --security-opt no-new-privileges",
		"  --cap-drop ALL",
		"  --read-only",
		"  --tmpfs /tmp:rw,nosuid,nodev,size=64m",
		"  --volume " + shellQuote(s.ServiceName+"-state") + ":" + shellQuote(containerStatePath),
		"  --volume " + shellQuote(s.CredentialsFile+":"+containerSecretPath+":ro"),
		"  --env " + shellQuote("HOME="+containerStatePath),
	}
	if ca := strings.TrimSpace(s.RootCAFile); ca != "" {
		lines = append(lines, "  --volume "+shellQuote(ca+":"+ca+":ro"))
	}
	lines = append(lines, "  "+shellQuote(s.Image))
	for _, a := range c.agentArgs() {
		lines = append(lines, "  "+shellQuote(a))
	}
	return strings.Join(lines, " \\\n") + "\n"
}

// ComposeFragment renders the same deployment as a compose service.
func ComposeFragment(s Spec) string {
	c := containerSpec(s)
	var b strings.Builder
	b.WriteString("services:\n")
	fmt.Fprintf(&b, "  %s:\n", s.ServiceName)
	fmt.Fprintf(&b, "    image: %s\n", yamlScalar(s.Image))
	fmt.Fprintf(&b, "    container_name: %s\n", yamlScalar(s.ServiceName))
	b.WriteString("    restart: always\n")
	b.WriteString("    read_only: true\n")
	b.WriteString("    security_opt: [\"no-new-privileges:true\"]\n")
	b.WriteString("    cap_drop: [\"ALL\"]\n")
	b.WriteString("    tmpfs: [\"/tmp:rw,nosuid,nodev,size=64m\"]\n")
	b.WriteString("    environment:\n")
	fmt.Fprintf(&b, "      HOME: %s\n", yamlScalar(containerStatePath))
	b.WriteString("    volumes:\n")
	fmt.Fprintf(&b, "      - %s:%s\n", yamlScalar(s.ServiceName+"-state"), yamlScalar(containerStatePath))
	// :ro on the credential mount, so a compromised workload cannot rewrite
	// the enrollment material to point the device at another control plane.
	fmt.Fprintf(&b, "      - %s\n", yamlScalar(s.CredentialsFile+":"+containerSecretPath+":ro"))
	if ca := strings.TrimSpace(s.RootCAFile); ca != "" {
		fmt.Fprintf(&b, "      - %s\n", yamlScalar(ca+":"+ca+":ro"))
	}
	b.WriteString("    command:\n")
	for _, a := range c.agentArgs() {
		fmt.Fprintf(&b, "      - %s\n", yamlScalar(a))
	}
	b.WriteString("volumes:\n")
	fmt.Fprintf(&b, "  %s-state: {}\n", s.ServiceName)
	return b.String()
}

// yamlScalar quotes a value so it survives YAML parsing as a plain string.
// Everything is quoted rather than only the ambiguous cases: a URL containing
// "://" and a pin containing ":" both need it, and uniform quoting means the
// rule cannot be got wrong later.
func yamlScalar(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}
