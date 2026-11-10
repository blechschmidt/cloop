package executorpool

// controller.go: what the hub knows of a pool's controllers, and what it makes
// of it (Task 20486).
//
// A controller names itself on every request — its build in the User-Agent,
// the pool-controller protocol it speaks in ControllerProtocolHeader — and the
// hub keeps both on the credential it presented, with the time it last used it.
// The controller's health reports may carry a count of its runners' volumes.
// Assess reads all of that against the pool's queue and runners and says what
// needs a person: the dashboard's pool list and hub doctor (the CLI's and the
// Hub health panel's) call the same function, so they cannot disagree about
// whether a pool is stuck.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ControllerProtocol is the pool-controller protocol this hub speaks. A
// controller says which it speaks in ControllerProtocolHeader; one that says
// none predates the numbering.
//
//	1  the demand feed and runner configurations (Task 20482)
//	2  runner states on the feed and retirement by the controller (Task 20483)
//	3  runner storage: what a runner holds, queued projects, health reports (Task 20484)
//	4  the controller names its build and protocol; cordoned pools; volume counts in reports (Task 20486)
//
// Raise it, with a line above, whenever the hub starts telling controllers
// something a controller has to act on: hub doctor then names every
// controller still speaking an older one.
const ControllerProtocol = 4

// ControllerProtocolHeader carries the protocol a controller speaks.
const ControllerProtocolHeader = "X-Cloop-Pool-Controller-Protocol"

// ControllerUserAgentPrefix starts a controller's User-Agent, which goes on
// with "/<build>".
const ControllerUserAgentPrefix = "cloop-executor-controller"

// maxControllerVersion bounds the build a controller may name.
const maxControllerVersion = 64

// ControllerUserAgent is a controller's User-Agent for its build version.
func ControllerUserAgent(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ControllerUserAgentPrefix
	}
	return ControllerUserAgentPrefix + "/" + version
}

// ParseControllerUserAgent returns the build a controller's User-Agent names,
// "" for none. Anything but the controller's own form names none: the value
// is shown to administrators, so only a version-shaped word is kept.
func ParseControllerUserAgent(ua string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(ua), ControllerUserAgentPrefix+"/")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || len(rest) > maxControllerVersion {
		return ""
	}
	for _, r := range rest {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".+-_~", r)) {
			return ""
		}
	}
	return rest
}

// ParseControllerProtocol reads ControllerProtocolHeader's value: the
// protocol, or 0 for none or nonsense.
func ParseControllerProtocol(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 || n > 1_000_000 {
		return 0
	}
	return n
}

// StorageUsage is a controller's count of its pool's runner volumes, as it
// reports it with its health (Task 20486).
type StorageUsage struct {
	// Claims counts the pool's PersistentVolumeClaims; Bound and Pending split
	// them by phase; InUse are held by a runner; Full were under the pool's
	// minimum free space even after clearing; Retained are kept past
	// maxClaims under reclaimPolicy Retain.
	Claims   int `json:"claims"`
	Bound    int `json:"bound"`
	Pending  int `json:"pending"`
	InUse    int `json:"in_use"`
	Full     int `json:"full"`
	Retained int `json:"retained"`
	// BytesUsed and BytesCapacity sum each claim's last measurement.
	BytesUsed     int64 `json:"bytes_used"`
	BytesCapacity int64 `json:"bytes_capacity"`
}

// Valid reports whether every count is one a controller could make.
func (u StorageUsage) Valid() bool {
	const most = 1_000_000
	for _, n := range []int{u.Claims, u.Bound, u.Pending, u.InUse, u.Full, u.Retained} {
		if n < 0 || n > most {
			return false
		}
	}
	return u.BytesUsed >= 0 && u.BytesCapacity >= 0 && u.Bound+u.Pending <= u.Claims+u.Retained
}

// EncodeStorage stores a usage report; nil stores nothing.
func EncodeStorage(u *StorageUsage) string {
	if u == nil {
		return ""
	}
	b, err := json.Marshal(u)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeStorage reads what EncodeStorage stored; nil for nothing or a
// document that does not decode, which is no report rather than a wrong one.
func DecodeStorage(s string) *StorageUsage {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var u StorageUsage
	if err := json.Unmarshal([]byte(s), &u); err != nil || !u.Valid() {
		return nil
	}
	return &u
}

// ControllerReport is one controller's last health report, as the hub keeps
// it.
type ControllerReport struct {
	CredentialID string        `json:"credential_id"`
	Healthy      bool          `json:"healthy"`
	Reason       string        `json:"reason,omitempty"`
	Message      string        `json:"message,omitempty"`
	ReportedAt   time.Time     `json:"reported_at"`
	Storage      *StorageUsage `json:"storage,omitempty"`
}

// ReportFrom reads a stored report.
func ReportFrom(r statedb.PoolControllerStatusRow) ControllerReport {
	return ControllerReport{CredentialID: r.CredentialID, Healthy: r.Healthy, Reason: r.Reason, Message: r.Message,
		ReportedAt: r.ReportedAt, Storage: DecodeStorage(r.Storage)}
}

// Thresholds Assess judges by.
const (
	// ContactStaleAfter is how long a pool's controllers may go without a
	// request before a pool with runs waiting is reported out of contact. A
	// controller asks for its feed at least every minute and the hub records
	// the use at most once a minute, so a live one is never this quiet.
	ContactStaleAfter = 10 * time.Minute
	// StuckAtMaxAfter is how long a run may wait while the pool has all the
	// runners max_runners allows before the pool is reported stuck there.
	StuckAtMaxAfter = 10 * time.Minute
	// ReportFreshFor is how long a controller's report of trouble speaks for
	// its pool: a controller repeats it within minutes while it lasts.
	ReportFreshFor = 10 * time.Minute
	// BehindCountsFor is how recently a credential must have been used for its
	// controller's protocol to matter: an idle credential runs nothing.
	BehindCountsFor = 24 * time.Hour
)

// Problem kinds Assess reports.
const (
	ProblemNoController = "no_controller"
	ProblemNoContact    = "no_contact"
	ProblemAtMax        = "at_max"
	ProblemNotStarting  = "not_starting"
	ProblemStorage      = "storage"
	ProblemPVCsPending  = "pvcs_pending"
	ProblemBehind       = "controller_behind"
	ProblemCordoned     = "cordoned_waiting"
)

// Severities of a problem, as hub doctor grades findings.
const (
	SeverityFail = "fail"
	SeverityWarn = "warn"
)

// Problem is something about a pool that needs a person.
type Problem struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Remedy   string `json:"remedy,omitempty"`
	// CredentialID names the controller the problem is about, where it is
	// about one.
	CredentialID string `json:"credential_id,omitempty"`
}

// HealthInput is what Assess reads of one pool.
type HealthInput struct {
	Pool Pool
	// Waiting counts the runs waiting in the pool's queue; OldestWaiting is
	// when the longest-waiting of them was queued.
	Waiting       int
	OldestWaiting time.Time
	// Runners counts the live runners (pending, idle and busy).
	Runners     int
	Credentials []Credential
	Reports     []ControllerReport
	Now         time.Time
}

// LastContact is the latest use of any of the pool's live credentials, zero
// for none.
func (in HealthInput) LastContact() time.Time {
	var last time.Time
	for _, c := range in.Credentials {
		if !c.Revoked() && c.LastUsedAt.After(last) {
			last = c.LastUsedAt
		}
	}
	return last
}

// Controller is the live credential used most recently: the one whose
// controller speaks for the pool now. ok is false when no live credential was
// ever used.
func (in HealthInput) Controller() (Credential, bool) {
	var best Credential
	ok := false
	for _, c := range in.Credentials {
		if c.Revoked() || c.LastUsedAt.IsZero() {
			continue
		}
		if !ok || c.LastUsedAt.After(best.LastUsedAt) {
			best, ok = c, true
		}
	}
	return best, ok
}

// Storage is the newest volume count any controller of the pool reported,
// nil for none.
func (in HealthInput) Storage() *StorageUsage {
	var (
		best *StorageUsage
		at   time.Time
	)
	for _, r := range in.Reports {
		if r.Storage != nil && r.ReportedAt.After(at) {
			best, at = r.Storage, r.ReportedAt
		}
	}
	return best
}

// Assess says what about a live pool needs a person, most serious first; nil
// for a pool that is fine, and for a revoked one, which runs nothing more.
func Assess(in HealthInput) []Problem {
	p := in.Pool
	if p.Revoked() {
		return nil
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	var out []Problem
	live := 0
	for _, c := range in.Credentials {
		if !c.Revoked() {
			live++
		}
	}
	runs := plural(in.Waiting, "run waits", "runs wait")
	if in.Waiting > 0 && !p.Cordoned() {
		last := in.LastContact()
		switch {
		case live == 0:
			out = append(out, Problem{Kind: ProblemNoController, Severity: SeverityFail,
				Message: fmt.Sprintf("%s for executor pool %s, and it has no live controller credential: nothing can "+
					"start its runners", runs, p.Name),
				Remedy: fmt.Sprintf("Mint a controller credential (cloop executor pool rotate-credential %s) and "+
					"install the executor controller with it, or bind the projects to another executor", p.Name)})
		case last.IsZero():
			out = append(out, Problem{Kind: ProblemNoContact, Severity: SeverityFail,
				Message: fmt.Sprintf("%s for executor pool %s, and no controller has ever contacted the hub with its "+
					"credential", runs, p.Name),
				Remedy: "Install the executor controller with the pool's credential (the helm install command shown " +
					"when the pool was created), and check it reaches this hub: kubectl describe executorpool"})
		case now.Sub(last) >= ContactStaleAfter:
			out = append(out, Problem{Kind: ProblemNoContact, Severity: SeverityFail,
				Message: fmt.Sprintf("%s for executor pool %s, and its controller last contacted the hub %s ago",
					runs, p.Name, roundAge(now.Sub(last))),
				Remedy: "Check the controller's Pods and its ExecutorPool's conditions (kubectl describe executorpool): " +
					"a Degraded HubUnavailable or HubRefused says why it cannot reach this hub"})
		}
	}
	if in.Waiting > 0 && p.Cordoned() {
		out = append(out, Problem{Kind: ProblemCordoned, Severity: SeverityWarn,
			Message: fmt.Sprintf("%s for executor pool %s, which is cordoned: none is handed a runner until it is "+
				"uncordoned", runs, p.Name),
			Remedy: fmt.Sprintf("Uncordon it (cloop executor pool uncordon %s), or bind the projects to another executor", p.Name)})
	}
	if in.Waiting > 0 && !p.Cordoned() && p.MaxRunners > 0 && in.Runners >= p.MaxRunners &&
		!in.OldestWaiting.IsZero() && now.Sub(in.OldestWaiting) >= StuckAtMaxAfter {
		out = append(out, Problem{Kind: ProblemAtMax, Severity: SeverityWarn,
			Message: fmt.Sprintf("executor pool %s has all %d runners max_runners allows, and %s, the oldest for %s",
				p.Name, p.MaxRunners, runs, roundAge(now.Sub(in.OldestWaiting))),
			Remedy: fmt.Sprintf("If the cluster has room, raise the pool's max_runners on the hub (cloop executor pool "+
				"update %s --max-runners N) and its ExecutorPool's spec.maxRunners on the cluster to match (helm upgrade "+
				"<release> <chart> --reuse-values --set pool.maxRunners=N); otherwise the runs start as busy runners finish",
				p.Name)})
	}
	// Runs waiting a long while with room for more runners and a controller
	// in contact that reports no trouble: something on the cluster keeps it
	// from starting them — a spec.maxRunners below the hub's, a quota, an
	// admission policy, an image it cannot pull.
	troubled := false
	for _, r := range in.Reports {
		if !r.Healthy && r.Reason != "" && now.Sub(r.ReportedAt) < ReportFreshFor {
			troubled = true
		}
	}
	if last := in.LastContact(); in.Waiting > 0 && !p.Cordoned() && in.Runners < p.MaxRunners && !troubled &&
		!last.IsZero() && now.Sub(last) < ContactStaleAfter && !in.OldestWaiting.IsZero() &&
		now.Sub(in.OldestWaiting) >= StuckAtMaxAfter {
		out = append(out, Problem{Kind: ProblemNotStarting, Severity: SeverityWarn,
			Message: fmt.Sprintf("%s for executor pool %s, the oldest for %s, though the hub allows %s more: its "+
				"controller is not starting them", runs, p.Name, roundAge(now.Sub(in.OldestWaiting)),
				plural(p.MaxRunners-in.Runners, "runner", "runners")),
			Remedy: "Check the ExecutorPool's conditions and Events (kubectl describe executorpool): a spec.maxRunners " +
				"below the hub's max_runners stops it there, and so do Pods the cluster refuses (a quota, an admission " +
				"policy) or an image it cannot pull"})
	}
	for _, r := range in.Reports {
		if r.Healthy || r.Reason == "" || now.Sub(r.ReportedAt) >= ReportFreshFor {
			continue
		}
		kind, msg := ProblemStorage, fmt.Sprintf("executor pool %s's controller cannot start runners: %s (%s)",
			p.Name, r.Message, r.Reason)
		if r.Reason == "StoragePending" {
			kind = ProblemPVCsPending
			msg = fmt.Sprintf("executor pool %s's runner volumes are stuck Pending, so runners cannot start: %s",
				p.Name, r.Message)
		}
		out = append(out, Problem{Kind: kind, Severity: SeverityWarn, Message: msg, CredentialID: r.CredentialID,
			Remedy: "Check the PersistentVolumeClaims in the controller's namespace (kubectl get pvc, kubectl describe " +
				"pvc): a storage class that does not exist or cannot provision, or a quota, keeps them Pending"})
	}
	for _, c := range in.Credentials {
		if c.Revoked() || c.LastUsedAt.IsZero() || now.Sub(c.LastUsedAt) >= BehindCountsFor ||
			c.ControllerProtocol >= ControllerProtocol {
			continue
		}
		speaks := fmt.Sprintf("speaks pool-controller protocol %d", c.ControllerProtocol)
		if c.ControllerProtocol == 0 {
			speaks = "names no pool-controller protocol, so it predates protocol 4"
		}
		build := "an unnamed build"
		if c.ControllerVersion != "" {
			build = c.ControllerVersion
		}
		out = append(out, Problem{Kind: ProblemBehind, Severity: SeverityWarn, CredentialID: c.ID,
			Message: fmt.Sprintf("executor pool %s's controller (%s, credential %s) %s; this hub speaks %d",
				p.Name, build, c.ID, speaks, ControllerProtocol),
			Remedy: "Upgrade the controller to this hub's build: helm upgrade <release> <this hub's chart> " +
				"--reuse-values --set image.tag=<this hub's image tag>, as cloop executor pool show prints it"})
	}
	return out
}

// HealthInputFor reads what Assess needs of pool from the store.
func (s *Store) HealthInputFor(pool Pool) (HealthInput, error) {
	now := s.now()
	in := HealthInput{Pool: pool, Now: now}
	runners, err := s.db.ListExecutorPoolRunners(pool.ID, statedb.PoolRunnerPending, statedb.PoolRunnerIdle,
		statedb.PoolRunnerBusy)
	if err != nil {
		return in, err
	}
	for _, r := range runners {
		if r.Live(now) {
			in.Runners++
		}
	}
	queue, err := s.db.ListPoolQueue(pool.ID, statedb.PoolQueueWaiting)
	if err != nil {
		return in, err
	}
	for _, q := range queue {
		in.Waiting++
		if in.OldestWaiting.IsZero() || q.CreatedAt.Before(in.OldestWaiting) {
			in.OldestWaiting = q.CreatedAt
		}
	}
	if in.Credentials, err = s.Credentials(pool.ID); err != nil {
		return in, err
	}
	reports, err := s.db.PoolControllerStatuses(pool.ID)
	if err != nil {
		return in, err
	}
	for _, r := range reports {
		in.Reports = append(in.Reports, ReportFrom(r))
	}
	return in, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// roundAge renders an age for a sentence: minutes under two hours, hours under
// two days, days beyond.
func roundAge(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return plural(int(d/time.Second), "second", "seconds")
	case d < 2*time.Hour:
		return plural(int(d/time.Minute), "minute", "minutes")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour", "hours")
	}
	return plural(int(d/(24*time.Hour)), "day", "days")
}
