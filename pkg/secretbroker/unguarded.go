package secretbroker

// unguarded.go records the one exception to ErrKubeConstraintsUnenforced
// (Task 20420): an administrator's acknowledgement that a kubeconfig grant may
// reach a sandbox on a hub that runs no Kubernetes access monitor, although it
// claims something only the monitor enforces.
//
// The refusal is the default because the alternative is silent. Without the
// monitor a grant reading "read-only, namespace app" delivers a kubeconfig whose
// identity may do whatever the cluster's RBAC lets it, and nothing anywhere
// says so at the moment it happens. An acknowledgement turns that into a
// decision somebody made: it names who, when and why, it is its own audit row,
// and it is shown wherever the grant is — the Secrets panel, `cloop hub grant
// list`, the lease's summary and the doctor — so the gap between what the grant
// says and what the workload holds is never invisible again.
//
// Who may record one is the caller's to decide: the dashboard requires the
// administrator permission, and `cloop hub grant unguarded` runs on the hub's
// own host against its database. The broker checks what makes one meaningful.

import (
	"context"
	"fmt"
	"strings"
)

// maxUnguardedReason bounds an acknowledgement's reason. It is a sentence for
// the people reading the grant, not a document.
const maxUnguardedReason = 500

// UnguardedAckRequest acknowledges, or withdraws the acknowledgement of, a
// kubeconfig grant delivered without the Kubernetes access monitor.
type UnguardedAckRequest struct {
	GrantID string
	// Actor is who decided, recorded on the grant and the audit row.
	Actor string
	// Reason is why delivering the grant unenforced is acceptable. Required
	// to acknowledge, so the decision carries its own justification.
	Reason string
}

// AcknowledgeUnguarded records req's acknowledgement on its grant and returns
// the grant as stored.
//
// It is refused for a grant that is not a kubeconfig grant, is revoked or
// expired, claims nothing only the monitor enforces (so has nothing to
// acknowledge), or stands on a Kubernetes share the hub renews — whose
// ServiceAccount may mint its own tokens, which no acknowledgement can make
// safe to hand a workload.
func (b *Broker) AcknowledgeUnguarded(ctx context.Context, req UnguardedAckRequest) (Grant, error) {
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	ev := Event{Action: ActionUnguardedAck, Actor: req.Actor, GrantID: strings.TrimSpace(req.GrantID)}
	g, s, err := b.unguardedTarget(&ev)
	if err != nil {
		return Grant{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	switch {
	case reason == "":
		return Grant{}, b.denyf(ev, ErrInvalidGrant,
			"acknowledging grant %s unguarded needs a reason: it is the only record of why its constraints may go unenforced",
			g.ID)
	case len(reason) > maxUnguardedReason:
		return Grant{}, b.denyf(ev, ErrInvalidGrant, "the reason is longer than %d characters", maxUnguardedReason)
	case strings.TrimSpace(req.Actor) == "":
		return Grant{}, b.denyf(ev, ErrInvalidGrant, "an acknowledgement needs an actor to attribute it to")
	}
	claims := g.Constraints.KubeMonitorOnly()
	if len(claims) == 0 {
		return Grant{}, b.denyf(ev, ErrInvalidGrant,
			"grant %s claims nothing only the Kubernetes access monitor enforces, so it is delivered without "+
				"one already and has nothing to acknowledge", g.ID)
	}
	if SelfRenewingKubeconfig(s) {
		return Grant{}, b.denyf(ev, ErrInvalidGrant,
			"grant %s spends %s, a Kubernetes share the hub renews: its ServiceAccount may create its own "+
				"tokens, so it is delivered only through the monitor and no acknowledgement changes that — "+
				"share the cluster again with `cloop remote kube share --renewal manual`", g.ID, s.Name)
	}
	ack := UnguardedAck{At: b.now().UTC(), By: strings.TrimSpace(req.Actor), Reason: reason}
	if err := b.setUnguardedAck(g.ID, ack); err != nil {
		return Grant{}, b.denyErr(ev, err)
	}
	g.UnguardedAck = ack
	ev.Decision = DecisionAllow
	ev.Reason = fmt.Sprintf("acknowledged delivering %s without the Kubernetes access monitor, which alone "+
		"enforces its %s: %s", s.Name, strings.Join(claims, " and "), reason)
	b.emit(ev)
	return g, nil
}

// WithdrawUnguardedAck clears req's grant's acknowledgement, so the grant is
// refused again on a hub with no monitor. Withdrawing one that is not in force
// is refused, so the trail never records a withdrawal of nothing.
func (b *Broker) WithdrawUnguardedAck(ctx context.Context, req UnguardedAckRequest) (Grant, error) {
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	ev := Event{Action: ActionUnguardedWithdraw, Actor: req.Actor, GrantID: strings.TrimSpace(req.GrantID)}
	g, s, err := b.unguardedTargetAny(&ev)
	if err != nil {
		return Grant{}, err
	}
	if !g.UnguardedAck.Recorded() {
		return Grant{}, b.denyf(ev, ErrInvalidGrant, "grant %s carries no unguarded acknowledgement", g.ID)
	}
	previous := g.UnguardedAck
	if err := b.setUnguardedAck(g.ID, UnguardedAck{}); err != nil {
		return Grant{}, b.denyErr(ev, err)
	}
	g.UnguardedAck = UnguardedAck{}
	ev.Decision = DecisionAllow
	ev.Reason = fmt.Sprintf("withdrew the acknowledgement %s recorded on %s for delivering %s without the "+
		"Kubernetes access monitor", previous.By, previous.At.UTC().Format("2006-01-02"), s.Name)
	if why := strings.TrimSpace(req.Reason); why != "" {
		ev.Reason += ": " + why
	}
	b.emit(ev)
	return g, nil
}

// unguardedTarget resolves the grant an acknowledgement is for and checks it
// is one that can carry one: a standing kubeconfig grant.
func (b *Broker) unguardedTarget(ev *Event) (Grant, Secret, error) {
	g, s, err := b.unguardedTargetAny(ev)
	if err != nil {
		return Grant{}, Secret{}, err
	}
	if !g.Standing(b.now()) {
		return Grant{}, Secret{}, b.denyf(*ev, ErrInvalidGrant,
			"grant %s is revoked or expired, so it is delivered nowhere", g.ID)
	}
	return g, s, nil
}

// unguardedTargetAny is unguardedTarget without the standing check, for a
// withdrawal, which is allowed on a grant that has since lapsed.
func (b *Broker) unguardedTargetAny(ev *Event) (Grant, Secret, error) {
	if ev.GrantID == "" {
		return Grant{}, Secret{}, b.denyf(*ev, ErrGrantNotFound, "no grant named")
	}
	g, err := b.store.GetGrant(ev.GrantID)
	if err != nil {
		return Grant{}, Secret{}, b.denyf(*ev, ErrGrantNotFound, "grant %s: %v", SafeRef(ev.GrantID), err)
	}
	ev.SecretID, ev.Subject, ev.Constraints = g.SecretID, g.Subject.String(), g.Constraints.Summary()
	s, err := b.store.GetSecret(g.SecretID)
	if err != nil {
		return Grant{}, Secret{}, b.denyf(*ev, ErrSecretNotFound, "grant %s spends a secret that no longer exists", g.ID)
	}
	ev.SecretName, ev.Kind = s.Name, s.Kind
	if s.Kind != KindKubeconfig {
		return Grant{}, Secret{}, b.denyf(*ev, ErrInvalidGrant,
			"grant %s spends a %s secret; only a kubeconfig grant has constraints the Kubernetes access "+
				"monitor alone enforces", g.ID, s.Kind)
	}
	return g, s, nil
}

func (b *Broker) setUnguardedAck(id string, ack UnguardedAck) error {
	st, ok := b.store.(UnguardedAcknowledger)
	if !ok {
		return ErrUnguardedAckUnsupported
	}
	return st.SetUnguardedAck(id, ack)
}
