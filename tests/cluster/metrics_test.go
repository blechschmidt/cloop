package cluster_test

// Metrics across a cluster (Task 20377): what each member's /metrics carries,
// read from real processes.
//
// Counters are per member and sum to the cluster's total. The gauges a member
// would read out of the shared database are a different matter — every member
// reads the same rows, so if all three exported them, sum() over the cluster
// would read three times the truth. They are exported by the leader alone, and
// this is where that is shown on processes that really do share one database,
// across a leader that really does die.

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// leaderOnlyGauges are always present on the leader's scrape — a hub without
// sign-on still reports zero live sessions, one that has never rotated a key
// still reports no rotation in progress — and must never appear on another
// member's.
var leaderOnlyGauges = []string{
	"cloop_projects_registered",
	"cloop_quota_enforcement_enabled",
	"cloop_quota_identities",
	"cloop_sessions_live",
	"cloop_secret_kek_rotation_active",
	"cloop_executors{",
}

// perMemberSeries is per-process state every member exports as its own share.
const perMemberSeries = `cloop_secret_leases_live{kind="github_pat"}`

// scrape returns h's /metrics, or "" when it does not answer 200.
func (w *world) scrape(h *hub) string {
	r := w.do(http.MethodGet, h.url(), "/metrics", nil)
	if r.status != http.StatusOK {
		return ""
	}
	return r.body
}

// sumSeries adds up every sample in body whose line starts with prefix — a
// family and some leading labels — and contains each of also, so a family can
// be summed across label values the test does not pin, such as an agent's
// isolation level.
func sumSeries(body, prefix string, also ...string) (float64, bool) {
	total, found := 0.0, false
lines:
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		for _, part := range also {
			if !strings.Contains(line, part) {
				continue lines
			}
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		total, found = total+v, true
	}
	return total, found
}

// clusterSum is sumSeries over every member in hubs.
func (w *world) clusterSum(hubs []*hub, prefix string, also ...string) float64 {
	total := 0.0
	for _, h := range hubs {
		v, _ := sumSeries(w.scrape(h), prefix, also...)
		total += v
	}
	return total
}

// exports reports whether a scrape carries any sample of the named gauge.
// name is a bare family, or a family followed by "{" to mean any series of it.
func exports(body, name string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(name, "{") {
			if strings.HasPrefix(line, name) {
				return true
			}
			continue
		}
		if strings.HasPrefix(line, name+" ") {
			return true
		}
	}
	return false
}

// checkLeaderOnlyGauges asserts, over the live members in hubs, that every
// gauge read from the shared database comes from exactly one member, the
// leader, while each member still exports its own per-process gauges; and that
// summing a fleet gauge over the cluster therefore gives the fleet, not the
// fleet times the number of members.
//
// Leadership can move while three scrapes are taken, so the check is retried
// until a set of scrapes agrees with a leader read straight after them.
func (w *world) checkLeaderOnlyGauges(when string, hubs []*hub, remoteExecutors int) {
	w.t.Helper()
	var problem string
	w.until(30*time.Second, func() bool {
		bodies := make(map[*hub]string, len(hubs))
		for _, h := range hubs {
			body := w.scrape(h)
			if body == "" {
				problem = "hub " + strconv.Itoa(h.port) + " did not serve /metrics"
				return false
			}
			bodies[h] = body
		}
		st, ok := w.status(hubs[0].url())
		if !ok || st.Leader == "" {
			problem = "no leader"
			return false
		}
		for _, name := range leaderOnlyGauges {
			var from []string
			for _, h := range hubs {
				if exports(bodies[h], name) {
					from = append(from, short(h.id))
				}
			}
			if len(from) != 1 || from[0] != short(st.Leader) {
				problem = name + " exported by " + strings.Join(from, ",") + "; leader is " + short(st.Leader)
				return false
			}
		}
		for _, h := range hubs {
			if !exports(bodies[h], perMemberSeries) {
				problem = "hub " + strconv.Itoa(h.port) + " does not export its own " + perMemberSeries
				return false
			}
		}
		// The fleet, summed the way an operator's dashboard sums it.
		remote := 0.0
		for _, h := range hubs {
			v, _ := sumSeries(bodies[h], `cloop_executors{kind="remote",`)
			remote += v
		}
		if remote != float64(remoteExecutors) {
			problem = "sum(cloop_executors{kind=\"remote\"}) over the cluster is " +
				strconv.FormatFloat(remote, 'f', -1, 64) + ", want " + strconv.Itoa(remoteExecutors)
			return false
		}
		problem = ""
		return true
	})
	if problem != "" {
		w.t.Fatalf("metrics %s: %s", when, problem)
	}
	w.t.Logf("metrics %s: shared gauges from the leader only, %d remote executor(s) in sum()", when, remoteExecutors)
}

// waitClusterSum waits until prefix (and also) sums to want over hubs.
func (w *world) waitClusterSum(what string, hubs []*hub, want float64, prefix string, also ...string) {
	w.t.Helper()
	var got float64
	if !w.until(45*time.Second, func() bool {
		got = w.clusterSum(hubs, prefix, also...)
		return got == want
	}) {
		w.t.Fatalf("metrics: %s: %s summed to %v over the cluster, want %v", what, describe(prefix, also), got, want)
	}
	w.t.Logf("metrics: %s: %s sums to %v over the cluster", what, describe(prefix, also), got)
}

// describe names a summed selection for a log line.
func describe(prefix string, also []string) string {
	if len(also) == 0 {
		return prefix + "…"
	}
	return prefix + "…" + strings.Join(also, ",") + "…"
}

// until polls cond until it holds or limit passes, and reports which.
func (w *world) until(limit time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(limit)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}
