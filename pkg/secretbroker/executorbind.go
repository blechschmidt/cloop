package secretbroker

// Projecting a lease onto the driver-facing types.
//
// A lease is described twice: once here, in the broker's own vocabulary
// (LeaseBinding, DeliveredFile), and once in pkg/executor's, which is what a
// driver actually receives. The translation between them is small, and for
// most of this project's life it lived inline in pkg/ui — the only caller that
// dispatched anything.
//
// It is here now because there is a second caller: `cloop hub doctor --smoke`
// dispatches through the same circuit to prove it works. Two independent
// copies of this projection would be a bad bargain in a specific way — the
// thing being duplicated is *revocation attribution*. If the diagnostic
// projected a binding even slightly differently from the hub, it would prove
// the wrong circuit: a smoke run could report that revocation works while the
// hub's own leases carried an attribution that no driver could act on. A
// diagnostic that can disagree with the thing it diagnoses is worse than none.
//
// Both functions copy every slice they return. The caller of Deliver owns
// buffers that Close will zero, and a driver that base64s a credential into a
// frame must not be handed memory that is about to be wiped underneath it.

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ExecutorBindings projects a lease's per-grant attribution onto the
// driver-facing executor.SecretBinding.
//
// The bindings are what let a driver take *one* credential back mid-run
// instead of killing the workload: they name the environment variables and
// file paths a given grant contributed, and nothing else. No material crosses
// this boundary — see SecretBinding's own documentation for why that is a hard
// rule rather than a convention.
//
// expiresAt rides along on every binding so a driver that has lost contact
// with the control plane can expire the material locally. Without it a lease
// TTL binds only the hub, which is the half of the system least likely to be
// the one holding the credential when it matters.
func ExecutorBindings(leaseID string, expiresAt time.Time, raw []LeaseBinding) []executor.SecretBinding {
	if len(raw) == 0 {
		return nil
	}
	out := make([]executor.SecretBinding, 0, len(raw))
	for _, b := range raw {
		out = append(out, executor.SecretBinding{
			LeaseID:    leaseID,
			GrantID:    b.GrantID,
			SecretName: b.SecretName,
			Kind:       string(b.Kind),
			EnvKeys:    append([]string(nil), b.EnvKeys...),
			Files:      append([]string(nil), b.Files...),
			Dir:        b.Dir,
			// An egress grant opened a network path as well as delivering a
			// credential, so revoking it has to drop the allowlist entry too.
			// The driver cannot infer that from the binding's shape.
			Egress:    b.Kind == KindEgressProxy,
			ExpiresAt: expiresAt,
		})
	}
	return out
}

// ExecutorSecretFiles projects the credential files a driver has to place
// itself onto executor.SecretFile.
//
// Only a delivered (not materialised) lease has these. When the hub wrote the
// files to its own filesystem, the workload reads them from there and the
// bindings already name the paths; handing the contents over as well would put
// plaintext into a second place for no benefit.
func ExecutorSecretFiles(leaseID string, raw []DeliveredFile) []executor.SecretFile {
	if len(raw) == 0 {
		return nil
	}
	out := make([]executor.SecretFile, 0, len(raw))
	for _, f := range raw {
		out = append(out, executor.SecretFile{
			LeaseID: leaseID,
			GrantID: f.GrantID,
			Dir:     f.Dir,
			Name:    f.Name,
			Mode:    f.Mode,
			Content: append([]byte(nil), f.Content...),
		})
	}
	return out
}
