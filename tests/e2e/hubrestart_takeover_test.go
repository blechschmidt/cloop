package e2e_test

// A hub restarted while its store cannot answer for the run's lease (Task
// 20451).
//
// The restart scenarios beside this one (hubrestart_test.go) take the run's
// lease over at the first attempt. This one injects the fault that attempt can
// meet: while the hub is down the test makes the lease's record unreadable —
// its record no longer decodes, as a store that answers with something it
// cannot read — so the restarted hub adopts the run and cannot decide the
// takeover. Before Task 20451 the hub printed a line and dropped the lease
// from the run's owner row; nobody extended it, and the run lost what it fed.
//
// Now the test checks what an operator would see while the fault lasts — the
// run still running, the lease still named on its owner row along with the
// undecided takeover, a lease_takeover row on the run's history, the metric
// counting retries and `cloop hub doctor` warning runs.lease_takeovers — then
// repairs the record and checks that the hub took the lease over by itself,
// said so on the run, and that the run settles as the other scenarios do:
// the harness started once, the result merged once, the lease released once
// by the restarted hub and never swept off the device.

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestE2EHubRestartRetriesAnUndecidedLeaseTakeover(t *testing.T) {
	s := newRestartScene(t, false)
	s.cloop(s.proj, "task", "add", "Write the report", "--no-ai", "--auto")
	s.startHub()
	s.startAgent()
	s.bind()

	before := s.stubStarts()
	idx := s.projectIdx(s.proj)
	if code, body := s.call("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), nil); code != http.StatusOK {
		t.Fatalf("start the run = %d %v", code, body)
	}
	s.waitFor("the harness to be running on the device", 90*time.Second, func() bool {
		return s.stubStarts() > before
	})
	var r restarted
	var meta map[string]any
	r.oldMember, meta = s.runOwner(s.proj)
	r.handle = fmt.Sprint(meta["handle"])
	leases, _ := meta["leases"].([]any)
	if r.oldMember == "" || len(leases) != 1 {
		t.Fatalf("the running run's owner row = %s %v, want one lease", r.oldMember, meta)
	}
	r.lease = fmt.Sprint(leases[0])

	s.stopHub(syscall.SIGKILL)
	// The fault: the lease's record cannot be read.
	original := s.query(s.hubDir, `SELECT record_json FROM secret_leases WHERE lease_id = ?`, r.lease)
	if len(original) != 1 {
		t.Fatalf("the lease's record = %v", original)
	}
	s.exec(`UPDATE secret_leases SET record_json = ? WHERE lease_id = ?`, `{"unreadable":`, r.lease)
	s.startHub()
	s.waitAgentOnline()
	s.waitFor("the restarted hub to adopt the run", 60*time.Second, func() bool {
		m, _ := s.runOwner(s.proj)
		return m != "" && m != r.oldMember
	})
	r.newMember, _ = s.runOwner(s.proj)

	// While the record cannot be read: the run is adopted, the lease is on
	// its owner row still, and the takeover is named as undecided.
	s.waitFor("the owner row to name the undecided takeover", 30*time.Second, func() bool {
		_, meta = s.runOwner(s.proj)
		tk, _ := meta["takeovers"].([]any)
		return len(tk) == 1
	})
	if got, _ := meta["leases"].([]any); len(got) != 1 || fmt.Sprint(got[0]) != r.lease {
		t.Fatalf("the adopted run's owner row names leases %v, want [%s] kept while its takeover is undecided",
			meta["leases"], r.lease)
	}
	tk, _ := meta["takeovers"].([]any)
	undecided, _ := tk[0].(map[string]any)
	if undecided["kind"] != "run" || undecided["id"] != r.lease || !strings.Contains(fmt.Sprint(undecided["reason"]), "read lease") {
		t.Fatalf("the undecided takeover on the owner row = %v", undecided)
	}
	if h := s.leaseHolder(r.lease); h != r.oldMember {
		t.Fatalf("the lease is held by %q while its record cannot be read, want still %s", h, r.oldMember)
	}
	s.waitFor("the run's history to say the takeover is retried", 30*time.Second, func() bool {
		return len(s.takeoverRows("retrying")) == 1
	})
	if got := s.metric(`cloop_lease_takeovers_total{kind="run",outcome="retrying"}`); got < 1 {
		t.Errorf("retrying takeovers counted %v", got)
	}
	doctor := s.doctorFindings("runs.lease_takeovers")
	if len(doctor) != 1 || doctor[0].Severity != "warn" || !strings.Contains(doctor[0].Message, r.lease) ||
		!strings.Contains(doctor[0].Message, r.newMember) {
		t.Fatalf("hub doctor's runs.lease_takeovers = %+v, want one warning naming the lease and its adopter", doctor)
	}

	// The store answers again: the hub takes the lease over by itself.
	s.exec(`UPDATE secret_leases SET record_json = ? WHERE lease_id = ?`, original[0][0], r.lease)
	s.waitFor("the restarted hub to take the lease over", 90*time.Second, func() bool {
		return s.leaseHolder(r.lease) == r.newMember
	})
	s.waitFor("the run's history to say the lease was taken over", 30*time.Second, func() bool {
		return len(s.takeoverRows("taken_over")) == 1
	})
	s.waitFor("the owner row to name nothing undecided", 30*time.Second, func() bool {
		_, meta = s.runOwner(s.proj)
		tk, _ := meta["takeovers"].([]any)
		got, _ := meta["leases"].([]any)
		return len(tk) == 0 && len(got) == 1 && fmt.Sprint(got[0]) == r.lease
	})
	if !contains(s.listedLeases(), r.lease) {
		t.Errorf("the restarted hub does not list the lease it took over")
	}
	if got := s.metric(`cloop_lease_takeovers_total{kind="run",outcome="taken_over"}`); got != 1 {
		t.Errorf("taken_over takeovers counted %v, want 1", got)
	}
	if doctor := s.doctorFindings("runs.lease_takeovers"); len(doctor) != 1 || doctor[0].Severity != "pass" {
		t.Errorf("hub doctor's runs.lease_takeovers after the takeover = %+v, want a pass", doctor)
	}
	for _, row := range s.auditRows("secret.renew", r.lease) {
		if row.payload["decision"] == "allow" && strings.Contains(fmt.Sprint(row.payload["reason"]), "taken over") {
			r.takeover = row.id
		}
	}
	if r.takeover == 0 {
		t.Fatalf("the lease's trail has no takeover row: %v", s.auditRows("secret.renew", r.lease))
	}

	s.releaseHarness(true)
	s.waitFor("task 1 to be done in the hub's copy", 90*time.Second, func() bool {
		return s.taskStatus(s.proj, 1) == "done"
	})
	s.assertSettled(s.proj, 1, r)
}

// exec runs one write against the hub's state database.
func (s *restartScene) exec(q string, args ...any) {
	s.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(s.hubDir, ".cloop", "state.db")+"?_pragma=busy_timeout(10000)")
	if err != nil {
		s.t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(q, args...)
	if err != nil {
		s.t.Fatalf("exec %q: %v", q, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		s.t.Fatalf("exec %q changed %d rows, want 1", q, n)
	}
}

// takeoverRows returns the messages of the run's lease_takeover rows with
// outcome.
func (s *restartScene) takeoverRows(outcome string) []string {
	rows, err := s.tryQuery(s.proj, `SELECT message, details FROM events WHERE type = 'lease_takeover' ORDER BY id`)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		var d map[string]any
		if json.Unmarshal([]byte(r[1]), &d) == nil && d["outcome"] == outcome {
			out = append(out, r[0])
		}
	}
	return out
}

// metric reads one sample from the hub's /metrics, or -1.
func (s *restartScene) metric(sample string) float64 {
	s.t.Helper()
	req, err := http.NewRequest("GET", s.base+"/metrics", nil)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+restartToken)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		s.t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), sample+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err == nil {
				return f
			}
		}
	}
	return -1
}

// doctorFinding is the part of a hub doctor finding the test reads.
type doctorFinding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// doctorFindings runs `cloop hub doctor --offline --json` against the hub's
// directory and returns the findings of check.
func (s *restartScene) doctorFindings(check string) []doctorFinding {
	s.t.Helper()
	cmd := exec.Command(s.bin, "hub", "doctor", "--offline", "--json", "--port", strconv.Itoa(s.port))
	cmd.Dir = s.hubDir
	cmd.Env = s.env
	out, _ := cmd.Output() // non-zero for any failure of this test hub's own; the JSON is what is read
	var rep struct {
		Findings []doctorFinding `json:"findings"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		s.t.Fatalf("hub doctor --json: %v\n%s", err, out)
	}
	var got []doctorFinding
	for _, f := range rep.Findings {
		if f.Check == check {
			got = append(got, f)
		}
	}
	return got
}
