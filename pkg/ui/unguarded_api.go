package ui

// unguarded_api.go: what becomes of a kubeconfig grant on this hub, and the
// administrator's acknowledgement that lets one reach a sandbox without the
// Kubernetes access monitor (Task 20420).
//
//	POST   /api/grants/{id}/unguarded   record it   {"reason": "..."}
//	DELETE /api/grants/{id}/unguarded   withdraw it
//
// Without the monitor a kubeconfig grant's namespaces are only kubectl's
// default and its verbs are not checked at all, so the broker refuses a grant
// claiming either (secretbroker.ErrKubeConstraintsUnenforced). The
// acknowledgement is the one way past, and it is a decision about what a
// grant's holders really get — so it is admin-only (user.manage, on the
// route), named on the grant, audited as its own action, and shown on the
// grant's row in the Secrets panel for as long as it stands.

import (
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// What a kubeconfig grant amounts to on this hub. See grantView.KubeDelivery.
const (
	kubeDeliveryMonitor         = "monitor"
	kubeDeliveryMonitorDown     = "monitor_down"
	kubeDeliveryRefused         = "refused"
	kubeDeliveryAcknowledged    = "acknowledged"
	kubeDeliveryUnconstrained   = "unconstrained"
	kubeDeliveryMonitorRequired = "monitor_required"
)

// kubeDelivery reports what the broker does with grant g of kubeconfig sec on
// this hub. It mirrors secretbroker's kubeMaterial and the guard attachKubeGuard
// installs, and unguarded_api_test.go holds the two together.
func kubeDelivery(sec secretbroker.Secret, g secretbroker.Grant) string {
	switch {
	case activeKubeGuard() != nil:
		return kubeDeliveryMonitor
	case kubeGuardRequired.Load():
		return kubeDeliveryMonitorDown
	case secretbroker.SelfRenewingKubeconfig(sec):
		return kubeDeliveryMonitorRequired
	case len(g.Constraints.KubeMonitorOnly()) == 0:
		return kubeDeliveryUnconstrained
	case g.UnguardedAck.Recorded():
		return kubeDeliveryAcknowledged
	default:
		return kubeDeliveryRefused
	}
}

// unguardedAckRequest is the POST body.
type unguardedAckRequest struct {
	// Reason is why delivering the grant without the monitor is acceptable.
	// Required: it is the only record of the decision's justification.
	Reason string `json:"reason"`
}

// handleGrantUnguardedAck serves POST /api/grants/{id}/unguarded.
func (s *Server) handleGrantUnguardedAck(w http.ResponseWriter, r *http.Request) {
	var req unguardedAckRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	s.decideUnguardedAck(w, r, strings.TrimSpace(req.Reason), true)
}

// handleGrantUnguardedWithdraw serves DELETE /api/grants/{id}/unguarded.
func (s *Server) handleGrantUnguardedWithdraw(w http.ResponseWriter, r *http.Request) {
	s.decideUnguardedAck(w, r, "", false)
}

func (s *Server) decideUnguardedAck(w http.ResponseWriter, r *http.Request, reason string, acknowledge bool) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "grant id is required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}
	req := secretbroker.UnguardedAckRequest{GrantID: id, Actor: s.auditActor(r), Reason: reason}
	var (
		g   secretbroker.Grant
		err error
	)
	action := secretbroker.ActionUnguardedWithdraw
	if acknowledge {
		action = secretbroker.ActionUnguardedAck
		g, err = bs.secret.AcknowledgeUnguarded(r.Context(), req)
	} else {
		g, err = bs.secret.WithdrawUnguardedAck(r.Context(), req)
	}
	if err != nil {
		writeBrokerError(w, err, "unguarded acknowledgement")
		return
	}
	sec, _ := bs.secret.DescribeSecret(g.SecretID)
	s.broadcastAuditAppend(string(action))
	s.broadcastSecretsUpdate("grant_updated", g.ID)
	jsonOK(w, secretGrantView(g, sec, time.Now()))
}
