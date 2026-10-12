package secretbroker

// kubeshare.go is the broker's half of a self-renewing Kubernetes share (Task
// 20416; the share itself is pkg/kubeshare).
//
// A share the hub renews is a kubeconfig for a ServiceAccount that may create
// tokens for itself: that permission is how the hub mints the next token
// before the current one expires. The Kubernetes access monitor refuses the
// serviceaccounts/token subresource to every sandbox, so through the monitor
// the permission is the hub's alone. Delivered as a file, the same kubeconfig
// would hand the workload a credential that can extend itself indefinitely —
// so a self-renewing share is delivered through the monitor or not at all.
//
// The broker cannot import pkg/kubeshare (it reaches pkg/executor/kubernetes,
// which imports this package), so the one metadata key the rule reads is
// declared here and pkg/kubeshare refers to it.

import "strings"

const (
	// KubeShareMetaRenewal is the secret metadata key naming who renews a
	// share's token.
	KubeShareMetaRenewal = "kube.renewal"
	// KubeShareRenewalHub is its value for a share the hub renews.
	KubeShareRenewalHub = "hub"
)

// SelfRenewingKubeconfig reports whether s is a kubeconfig share the hub
// renews, whose ServiceAccount can therefore create tokens for itself.
func SelfRenewingKubeconfig(s Secret) bool {
	return s.Kind == KindKubeconfig &&
		strings.TrimSpace(s.Metadata[KubeShareMetaRenewal]) == KubeShareRenewalHub
}
