package hubdoctor

// The key-management service check (Task 20433).
//
// A hub whose secrets section names a KMS opens its secret store through it and
// nothing else: `cloop ui` refuses to start on a KMS it cannot reach, and a
// serving hub that loses it keeps only the keys it already holds in memory.
// So the doctor asks the same questions the hub asks at startup, and says
// which one failed:
//
//   - secrets.kms.config: is the section one the hub accepts at all?
//   - secrets.kms.reachable: does each KMS answer, healthy, within the probe
//     timeout — and how long did it take?
//   - secrets.kms.rewrap: is every key a KMS holds wrapped under the key it
//     encrypts under now, or is a rotation of the KMS key still to be
//     followed?
//   - secrets.kms.previous: is a change of root onto, off or between KMSs in
//     progress?
//
// Whether every live sealing key opens with the configured roots — KMS or
// passphrase — is secret_key.matches, the same check as without a KMS.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// kmsRemedy is what to do about a KMS that does not answer.
const kmsRemedy = "The sealing keys open through this KMS and nothing else, and `cloop ui` refuses to start " +
	"while it does not answer. For a KMS v2 plugin: is the sidecar running, and is its socket the one " +
	"secrets.kms.kmsv2.endpoint names? For Transit: is the server reachable, unsealed, and does the hub's " +
	"token or role have encrypt, decrypt and read on the key? A refusal (denied) means the hub's identity " +
	"lost its access to the KMS key"

// checkSecretsKMS reports on the KMSs of the secrets section. roots are what
// kms.Resolve built from it; resolveErr is what it said when it would not.
func checkSecretsKMS(ctx context.Context, cfg *config.Config, opts Options, roots kms.Roots, resolveErr error, add addFn) {
	sc := cfg.Secrets
	if !sc.UsesKMS() && strings.TrimSpace(sc.PreviousRoot) == "" {
		return
	}
	if resolveErr != nil {
		add(Finding{
			Check: "secrets.kms.config", Title: "KMS configuration", Severity: SeverityFail,
			Message: "the secrets section is refused, so the hub will not start: " + resolveErr.Error(),
			Remediation: "Fix the setting the message names. A secrets.kms block that is configured and wrong " +
				"never falls back to CLOOP_SECRET_KEY",
		})
		return
	}
	add(Finding{
		Check: "secrets.kms.config", Title: "KMS configuration", Severity: SeverityPass,
		Message: "the secrets section is accepted: " + describeKMSRoots(roots),
	})

	for i, p := range roots.Providers {
		role := "current"
		if i > 0 || !roots.Current.IsKMS() {
			role = "previous"
		}
		if opts.Offline && p.Kind() == config.KMSProviderTransit {
			add(Finding{
				Check: "secrets.kms.reachable", Title: "KMS reachable", Severity: SeverityWarn,
				Message: fmt.Sprintf("not checked (--offline): the %s KMS %s is %s", role, p.Name(), p.Describe()),
			})
			continue
		}
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DefaultProbeTimeout
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		st, err := p.Status(cctx)
		took := time.Since(start)
		cancel()
		details := map[string]any{"kms": p.Name(), "provider": p.Kind(), "role": role,
			"latency_ms": took.Milliseconds()}
		if err != nil {
			details["unreachable"] = kms.Unreachable(err)
			add(Finding{
				Check: "secrets.kms.reachable", Title: "KMS reachable", Severity: SeverityFail,
				Message:     fmt.Sprintf("the %s KMS (%s) does not answer: %v", role, p.Describe(), err),
				Remediation: kmsRemedy, Details: details,
			})
			continue
		}
		details["key"] = st.KeyID
		sev := SeverityPass
		msg := fmt.Sprintf("the %s KMS (%s) answers in %s, encrypting under %s", role, p.Describe(),
			took.Round(time.Millisecond), st.KeyID)
		if took > timeout/2 {
			sev = SeverityWarn
			msg += fmt.Sprintf(" — more than half the %s timeout", timeout)
		}
		add(Finding{Check: "secrets.kms.reachable", Title: "KMS reachable", Severity: sev, Message: msg, Details: details})
	}

	if !roots.Previous.IsZero() {
		prev, _ := secretbroker.RootName(roots.Previous)
		cur, _ := secretbroker.RootName(roots.Current)
		what := "secrets.kms_previous"
		if !roots.Previous.IsKMS() {
			what = "secrets.previous_root: passphrase"
		}
		add(Finding{
			Check: "secrets.kms.previous", Title: "Change of root", Severity: SeverityWarn,
			Message: fmt.Sprintf("a change of root is in progress: %s (%s) still opens the keys it holds beside "+
				"the current root, %s", what, prev, cur),
			Remediation: "Once every hub member runs on the new secrets section, run `cloop hub key rotate " +
				"--retire-previous`; then remove " + what + " from every member",
		})
	}
}

// checkKMSRewrap reports keys the current KMS holds under a key it no longer
// encrypts under. kr is the hub's keyring opened read-only with the
// configured roots.
func checkKMSRewrap(ctx context.Context, kr *secretbroker.Keyring, opts Options, add addFn) {
	k := kr.CurrentKMS()
	if k == nil {
		return
	}
	rep, ok := k.(secretbroker.KMSKeyReporter)
	if !ok {
		return
	}
	if p, isProvider := k.(kms.Provider); isProvider && opts.Offline && p.Kind() == config.KMSProviderTransit {
		return
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	current, err := rep.CurrentKeyID(cctx)
	cancel()
	if err != nil {
		return // secrets.kms.reachable said so
	}
	stale := kr.StaleKMSKeys(current)
	if len(stale) == 0 {
		msg := fmt.Sprintf("every key the KMS %s holds is wrapped under %s, the key it encrypts under now",
			k.Name(), current)
		if kr.KMSHeldKeys() == 0 {
			msg = fmt.Sprintf("the KMS %s holds no sealing key yet — `cloop hub key rotate --retire-previous` "+
				"mints the first — and encrypts under %s", k.Name(), current)
		}
		add(Finding{
			Check: "secrets.kms.rewrap", Title: "KMS key versions", Severity: SeverityPass,
			Message: msg,
		})
		return
	}
	add(Finding{
		Check: "secrets.kms.rewrap", Title: "KMS key versions", Severity: SeverityWarn,
		Message: fmt.Sprintf("%d key(s) — %s — are wrapped under an older key of the KMS %s, which now encrypts "+
			"under %s: disabling that older key version would make them unopenable", len(stale),
			strings.Join(stale, ", "), k.Name(), current),
		Remediation: "A serving hub's cluster leader rewraps them within a minute; `cloop hub key rewrap` does it " +
			"now. Disable the old KMS key version only once this check passes",
		Details: map[string]any{"stale": stale, "current_kms_key": current},
	})
}

// describeKMSRoots names the roots a secrets section resolved to.
func describeKMSRoots(roots kms.Roots) string {
	name := func(r secretbroker.Root) string {
		if r.IsKMS() {
			return "the KMS " + r.KMS.Name()
		}
		if r.IsZero() {
			return "nothing"
		}
		return "CLOOP_SECRET_KEY"
	}
	s := "new sealing keys come from " + name(roots.Current)
	if !roots.Previous.IsZero() {
		s += ", and " + name(roots.Previous) + " opens the keys of the root being replaced"
	}
	return s
}
