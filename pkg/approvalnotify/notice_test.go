package approvalnotify

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func request(id string, state secretbroker.RequestState, created, expires, decided time.Time) secretbroker.AccessRequest {
	sub, _ := secretbroker.ParseSubject("project:/srv/api")
	return secretbroker.AccessRequest{
		ID: id, RequestedBy: "dev@example.com", SecretName: "acme-app", Kind: secretbroker.KindGitHubApp,
		Subject: sub, State: state, CreatedAt: created, ExpiresAt: expires, DecidedAt: decided, DecidedBy: "lead@example.com",
	}
}

func keys(ns []Notice) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.Key())
	}
	sort.Strings(out)
	return out
}

// TestScanFindsEachMomentOnce: a waiting request is noticed as filed, and as
// due a reminder from twelve hours before it lapses — unless it was asked to
// wait less than that; a decision or lapse since the watermark is noticed,
// an older one is not; and a waiting token is noticed.
func TestScanFindsEachMomentOnce(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	since := now.Add(-10 * time.Minute)
	snap := Snapshot{RequestsKnown: true, TokensKnown: true, Requests: []secretbroker.AccessRequest{
		request("req_new", secretbroker.RequestPending, now.Add(-time.Minute), now.Add(72*time.Hour), time.Time{}),
		request("req_due", secretbroker.RequestPending, now.Add(-61*time.Hour), now.Add(11*time.Hour), time.Time{}),
		request("req_short", secretbroker.RequestPending, now.Add(-time.Hour), now.Add(3*time.Hour), time.Time{}),
		request("req_ok", secretbroker.RequestApproved, now.Add(-2*time.Hour), now.Add(70*time.Hour), now.Add(-time.Minute)),
		request("req_no", secretbroker.RequestDenied, now.Add(-2*time.Hour), now.Add(70*time.Hour), now.Add(-2*time.Minute)),
		request("req_back", secretbroker.RequestWithdrawn, now.Add(-2*time.Hour), now.Add(70*time.Hour), now.Add(-3*time.Minute)),
		request("req_old", secretbroker.RequestApproved, now.Add(-9*24*time.Hour), now.Add(-6*24*time.Hour), now.Add(-8*24*time.Hour)),
		request("req_lapsed", secretbroker.RequestExpired, now.Add(-72*time.Hour), now.Add(-5*time.Minute), time.Time{}),
		request("req_unswept", secretbroker.RequestPending, now.Add(-72*time.Hour), now.Add(-time.Minute), time.Time{}),
		request("req_long_lapsed", secretbroker.RequestExpired, now.Add(-30*24*time.Hour), now.Add(-27*24*time.Hour), time.Time{}),
	}, Waiting: []TokenInfo{{ID: "0123456789abcdef", Name: "old-ci", Roles: []string{"admin"}}}}

	got := keys(Scan(snap, since, now))
	want := []string{
		"request.approved:req_ok", "request.denied:req_no",
		"request.filed:req_due", "request.filed:req_new", "request.filed:req_short",
		"request.lapsed:req_lapsed", "request.lapsed:req_unswept",
		"request.reminder:req_due",
		"request.withdrawn:req_back",
		"token.waiting:0123456789abcdef",
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("scan found:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, n := range Scan(snap, since, now) {
		if n.Event == config.NotifyEventRequestReminder && !n.At.Equal(now.Add(11*time.Hour).Add(-config.NotificationReminderLead)) {
			t.Errorf("the reminder is dated %s, want twelve hours before the deadline", n.At)
		}
	}
}

// TestSupersededNoticesAreNotSent: telling an approver about a request that
// was decided before the notice went out is worse than silence.
func TestSupersededNoticesAreNotSent(t *testing.T) {
	now := time.Now()
	decided := request("req_1", secretbroker.RequestApproved, now.Add(-time.Hour), now.Add(time.Hour), now)
	waiting := request("req_2", secretbroker.RequestPending, now.Add(-time.Hour), now.Add(time.Hour), time.Time{})
	snap := Snapshot{RequestsKnown: true, TokensKnown: true, Requests: []secretbroker.AccessRequest{decided, waiting}}
	for _, tc := range []struct {
		n    Notice
		want bool
	}{
		{Notice{Event: config.NotifyEventRequestFiled, RequestID: "req_1"}, true},
		{Notice{Event: config.NotifyEventRequestReminder, RequestID: "req_1"}, true},
		{Notice{Event: config.NotifyEventRequestFiled, RequestID: "req_2"}, false},
		{Notice{Event: config.NotifyEventRequestFiled, RequestID: "req_gone"}, true},
		{Notice{Event: config.NotifyEventRequestApproved, RequestID: "req_1"}, false},
		{Notice{Event: config.NotifyEventTokenWaiting, TokenID: "t1"}, true},
	} {
		if got := Superseded(tc.n, snap, now); got != tc.want {
			t.Errorf("Superseded(%s) = %v, want %v", tc.n.Key(), got, tc.want)
		}
	}
	// Unknown is not superseded: an unreadable store says nothing.
	if Superseded(Notice{Event: config.NotifyEventRequestFiled, RequestID: "req_gone"}, Snapshot{}, now) {
		t.Error("a notice was judged superseded against requests that could not be read")
	}
}
