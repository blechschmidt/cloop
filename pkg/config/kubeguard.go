package config

// kubeguard.go validates the executors.kube_guard section: the monitor that
// stands between a sandbox and a Kubernetes cluster (Task 20277).
//
// The shape deliberately mirrors executors.git_proxy, because the deployment
// question is the same one — "where does the sandbox reach this hub, and with
// what certificate" — and an operator who has answered it once for git should
// not have to learn a second vocabulary for Kubernetes.

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// KubeGuardSessionMinutesUpper bounds a monitor session, for the reason
// kubeguard.MaxSessionTTL gives: a session that outlives a working day is
// indistinguishable from having handed the sandbox the kubeconfig.
const KubeGuardSessionMinutesUpper = int(kubeguard.MaxSessionTTL / 60e9)

// ValidateKubeGuardConfig returns the first problem found in k, without
// mutating. Like the other executor validators it runs even when the section
// is disabled, so a broken value is reported when it is written rather than
// discovered the first time someone turns it on.
func ValidateKubeGuardConfig(k KubeGuardConfig) error {
	if k.SessionMinutes < 0 || k.SessionMinutes > KubeGuardSessionMinutesUpper {
		return fmt.Errorf("executors.kube_guard.session_minutes must be between 0 and %d (got %d)",
			KubeGuardSessionMinutesUpper, k.SessionMinutes)
	}
	if err := validateKubeGuardListenAddr(k.ListenAddr); err != nil {
		return err
	}
	if err := validateKubeGuardAdvertiseURL(k.AdvertiseURL); err != nil {
		return err
	}
	if v := strings.TrimSpace(k.MinTLSVersion); v != "" {
		if _, err := tlsconf.ParseMinVersion(v); err != nil {
			return fmt.Errorf("executors.kube_guard.min_tls_version: %w", err)
		}
	}
	// The overrides are validated through the policy the monitor enforces
	// with, so a verb nobody spells correctly or a glob that matches nothing
	// is refused here rather than read as a working allowlist.
	if len(k.Verbs) > 0 || len(k.Namespaces) > 0 || len(k.Resources) > 0 {
		if err := k.Policy().ValidateAsFloor(); err != nil {
			return fmt.Errorf("executors.kube_guard: %w", err)
		}
	}
	if k.Enabled {
		cert, key := strings.TrimSpace(k.CertFile), strings.TrimSpace(k.KeyFile)
		if cert == "" || key == "" {
			return fmt.Errorf("executors.kube_guard is enabled but cert_file and key_file are " +
				"not both set; the session token rides an Authorization header on every " +
				"request and cleartext would publish it rather than deliver it")
		}
	}
	return nil
}

// validateKubeGuardListenAddr checks the bind address. Empty means an
// ephemeral loopback port.
func validateKubeGuardListenAddr(addr string) error {
	a := strings.TrimSpace(addr)
	if a == "" {
		return nil
	}
	if strings.Contains(a, "://") || strings.ContainsAny(a, "/?#@ \t") {
		return fmt.Errorf("executors.kube_guard.listen_addr must be host:port, not a URL (got %q)", a)
	}
	_, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("executors.kube_guard.listen_addr must be host:port (got %q)", a)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("executors.kube_guard.listen_addr port must be between 0 and 65535 (got %q)", port)
	}
	return nil
}

// validateKubeGuardAdvertiseURL checks the URL a sandbox's kubeconfig names
// as its server, by the rule the monitor's registry applies when it starts
// (kubeguard.NormalizeBaseURL). The copy that lived here until Task 20387
// refused a path the registry let through, and both accepted "https://:8444".
func validateKubeGuardAdvertiseURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if _, err := kubeguard.NormalizeBaseURL(s); err != nil {
		return fmt.Errorf("executors.kube_guard.advertise_url %q: %w", s, err)
	}
	return nil
}

// clampKubeGuardConfig repairs out-of-range values in place and reports what
// it changed, so Load can warn once per field.
//
// Every repair resets to the zero value, and every zero value is the tighter
// reading: a shorter session, a loopback bind, the built-in read-only policy.
// The exception is Enabled, which is switched *off* when the section could
// only start an unusable or unsafe monitor.
//
// Disabling is the safe repair here for the same reason it is in
// clampGitProxyConfig, but the consequence is different and worth naming: with
// the monitor off, a kubeconfig grant is delivered the way it was before this
// existed — minimised to its allowed contexts, but carrying the cluster
// credential and enforcing no verbs. That is the documented pre-Task-20277
// behaviour rather than a new failure mode, and startKubeGuard says so out
// loud when an enabled section fails to start.
func clampKubeGuardConfig(k *KubeGuardConfig) []string {
	var changed []string

	if k.SessionMinutes < 0 || k.SessionMinutes > KubeGuardSessionMinutesUpper {
		changed = append(changed, fmt.Sprintf("executors.kube_guard.session_minutes: value %d outside [0, %d]",
			k.SessionMinutes, KubeGuardSessionMinutesUpper))
		k.SessionMinutes = 0
	}
	if v := strings.TrimSpace(k.MinTLSVersion); v != "" {
		if _, err := tlsconf.ParseMinVersion(v); err != nil {
			changed = append(changed, fmt.Sprintf("executors.kube_guard.min_tls_version: %v", err))
			k.MinTLSVersion = ""
		}
	}
	if len(k.Verbs) > 0 || len(k.Namespaces) > 0 || len(k.Resources) > 0 {
		if err := k.Policy().ValidateAsFloor(); err != nil {
			// Reset all three together rather than dropping the bad entry and
			// keeping the rest: a half-applied policy is one nobody wrote,
			// and the default is narrower than any override an operator was
			// reaching for.
			changed = append(changed, fmt.Sprintf("executors.kube_guard: %v", err))
			k.Verbs, k.Namespaces, k.Resources = nil, nil, nil
		}
	}
	if err := validateKubeGuardListenAddr(k.ListenAddr); err != nil {
		changed = append(changed, fmt.Sprintf("executors.kube_guard.listen_addr: %v", err))
		k.ListenAddr = ""
		k.Enabled = false
	}
	if err := validateKubeGuardAdvertiseURL(k.AdvertiseURL); err != nil {
		changed = append(changed, fmt.Sprintf("executors.kube_guard.advertise_url: %v", err))
		k.AdvertiseURL = ""
		k.Enabled = false
	}
	if k.Enabled && (strings.TrimSpace(k.CertFile) == "" || strings.TrimSpace(k.KeyFile) == "") {
		changed = append(changed, "executors.kube_guard.cert_file: enabled without TLS material, "+
			"which would carry every session token in cleartext")
		k.Enabled = false
	}
	return changed
}

// CABundle returns the PEM a sandbox's kubectl is told to trust for the
// monitor: ca_file when set, otherwise the serving certificate itself — the
// right answer for a self-signed certificate and harmless for one signed by a
// public CA, since a kubeconfig's certificate-authority-data replaces the
// trust store rather than adding to it, and the serving certificate's own
// chain is exactly what will be presented. Nil when neither is set.
//
// The hub reads it here when it starts the monitor, and refuses to start it on
// an error; `cloop hub doctor` calls the same method, so a directory or an
// unreadable file is reported the way the hub meets it (Task 20387).
func (k KubeGuardConfig) CABundle() ([]byte, error) {
	path := strings.TrimSpace(k.CAFile)
	label := "executors.kube_guard.ca_file"
	if path == "" {
		path = strings.TrimSpace(k.CertFile)
		label = "executors.kube_guard.cert_file"
	}
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return pem, nil
}

// SessionTTLMinutes returns the effective session length, applying the
// default for an unset value. It does not clamp: an out-of-range value is
// repaired at load, and silently narrowing here would hide it.
func (k KubeGuardConfig) SessionTTLMinutes() int {
	if k.SessionMinutes <= 0 {
		return int(kubeguard.DefaultSessionTTL / 60e9)
	}
	return k.SessionMinutes
}

// Policy renders the section's deployment-wide policy floor.
//
// This is a *floor*, not the policy a session runs under. Each grant carries
// its own verbs and namespaces, and the session policy is the intersection —
// see kubeguard.Policy.Intersect and the wiring in pkg/ui/kubeguard.go. An
// operator who narrows this narrows every project on the hub; one who leaves
// it empty gets read-only, which is what a grant that says nothing gets too.
func (k KubeGuardConfig) Policy() kubeguard.Policy {
	pol := kubeguard.Policy{
		Verbs:      append([]string(nil), k.Verbs...),
		Namespaces: append([]string(nil), k.Namespaces...),
		Resources:  append([]string(nil), k.Resources...),
	}
	// Deliberately not Normalize()d. Normalize substitutes the read-only set
	// for an empty verb list, which is right for a session policy and wrong
	// here: it would turn "no ceiling configured" into "no project on this hub
	// may ever write", and `cloop secret grant --verbs create` would silently
	// produce a read-only session. kubeguard.Policy.Intersect reads an empty
	// list on this side as "no restriction", the same way it reads an empty
	// namespace list.
	pol.Verbs = kubeguard.NormalizeVerbs(pol.Verbs)
	return pol
}
