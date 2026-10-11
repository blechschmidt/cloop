package config

// monitortls.go is the tls key the two credential monitors share
// (executors.git_proxy.tls, executors.kube_guard.tls; Task 20409).

import (
	"fmt"
	"strings"
)

// MonitorTLSAuto has the hub issue a monitor's certificate itself, from the
// hub's own CA (pkg/hubca), instead of serving cert_file and key_file.
const MonitorTLSAuto = "auto"

func normalizeMonitorTLS(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// validateMonitorTLS checks a section's tls value: "auto" or nothing.
func validateMonitorTLS(section, v string) error {
	switch normalizeMonitorTLS(v) {
	case "", MonitorTLSAuto:
		return nil
	}
	return fmt.Errorf("%s.tls must be %q or empty (got %q)", section, MonitorTLSAuto, v)
}

// AutoTLS reports whether the proxy's certificate is issued by the hub.
func (g GitProxyConfig) AutoTLS() bool { return normalizeMonitorTLS(g.TLS) == MonitorTLSAuto }

// AutoTLS reports whether the monitor's certificate is issued by the hub.
func (k KubeGuardConfig) AutoTLS() bool { return normalizeMonitorTLS(k.TLS) == MonitorTLSAuto }

// clampMonitorTLS repairs a section's tls value in place and reports what it
// changed. An unknown value is dropped, which leaves the files deciding — and,
// with no files, the section switched off by the caller's next check rather
// than interposing a monitor with a certificate nobody chose. "auto" beside
// files the operator named is dropped too: explicit material wins.
func clampMonitorTLS(section string, tlsMode *string, cert, key string) []string {
	var changed []string
	if err := validateMonitorTLS(section, *tlsMode); err != nil {
		changed = append(changed, fmt.Sprintf("%s.tls: %v", section, err))
		*tlsMode = ""
		return changed
	}
	if normalizeMonitorTLS(*tlsMode) != MonitorTLSAuto {
		*tlsMode = ""
		return changed
	}
	*tlsMode = MonitorTLSAuto
	if strings.TrimSpace(cert) != "" || strings.TrimSpace(key) != "" {
		changed = append(changed, fmt.Sprintf("%s.tls: auto ignored because cert_file or key_file is set; "+
			"the monitor serves those files", section))
		*tlsMode = ""
	}
	return changed
}

// autoTLSConflict is the validation error for tls: auto beside files.
func autoTLSConflict(section, what string) error {
	return fmt.Errorf("%s.tls is auto, which issues the certificate from the hub's own CA; "+
		"drop %s, or drop tls to serve those files", section, what)
}
