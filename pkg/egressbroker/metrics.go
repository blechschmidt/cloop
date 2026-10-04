package egressbroker

// Hub metrics for the egress broker (Task 20377).
//
// The broker is the one place that knows why it refused something, so it
// records its own verdicts instead of leaving a caller to reverse-engineer them
// from an error string. Every helper here reads the same typed error the audit
// row is derived from — a refusal reaches the metric through errors.Is on a
// sentinel, exactly as it reaches the trail — so the two cannot disagree about
// what happened.
//
// All four families are per process: a session lives in the broker that issued
// it, and so do its bytes and verdicts. Members of a hub cluster each report
// their own, and the sum is the cluster's.

import (
	"errors"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// denialReason names the policy refusal err carries, as a hubmetrics.Egress*
// reason, or "" when err is not a policy decision at all: a failed lookup or
// dial, a malformed request, a socket that closed, a credential that did not
// authenticate. Those are counted as neither allowed nor denied, so the denial
// rate does not move in exactly the situation an operator is paging on.
func denialReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoGrant):
		return hubmetrics.EgressNoGrant
	case errors.Is(err, ErrGrantRevoked):
		return hubmetrics.EgressRevoked
	case errors.Is(err, ErrGrantExpired), errors.Is(err, ErrSessionExpired):
		return hubmetrics.EgressExpired
	case errors.Is(err, ErrHostNotAllowed):
		return hubmetrics.EgressHostNotAllowed
	case errors.Is(err, ErrPortNotAllowed):
		return hubmetrics.EgressPortNotAllowed
	case errors.Is(err, ErrMethodNotAllowed):
		return hubmetrics.EgressMethodNotAllowed
	case errors.Is(err, ErrDestinationBlocked):
		return hubmetrics.EgressDestinationBlocked
	case errors.Is(err, ErrQuotaExceeded):
		return hubmetrics.EgressQuotaExhausted
	}
	return ""
}

// countRequest records the verdict on one request through the proxy — a
// CONNECT tunnel or a plain-HTTP exchange.
func countRequest(err error) {
	if err == nil {
		hubmetrics.EgressRequests.Inc(hubmetrics.ResultAllowed)
		return
	}
	if reason := denialReason(err); reason != "" {
		hubmetrics.EgressRequests.Inc(hubmetrics.ResultDenied)
		hubmetrics.EgressDenials.Inc(reason)
	}
}

// countRefusal records a refusal that is not a request's verdict: a session
// the broker would not issue, or a transfer it cut after allowing it — a quota
// spent, or a session expiring, inside an open tunnel. The latter's request
// already has its allowed sample, so only the denial is counted.
func countRefusal(err error) {
	if reason := denialReason(err); reason != "" {
		hubmetrics.EgressDenials.Inc(reason)
	}
}

// countAudited mirrors one audited proxy decision into the metrics.
func countAudited(action secretbroker.Action, err error) {
	switch action {
	case secretbroker.ActionEgressConnect, secretbroker.ActionEgressRequest:
		countRequest(err)
	case secretbroker.ActionEgressClose:
		countRefusal(err)
	}
}

// countBytes records bytes the proxy carried for a sandbox.
func countBytes(direction string, n int64) {
	if n > 0 {
		hubmetrics.EgressBytes.Add(float64(n), direction)
	}
}
