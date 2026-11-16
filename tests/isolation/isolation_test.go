package isolation_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

// TestAHostileRunOnTheHubsHostReachesNoOtherProject: two projects whose runs
// the hub forks on its own host, each kept to its own tree by the host
// sandbox because the hub serves more than one project.
func TestAHostileRunOnTheHubsHostReachesNoOtherProject(t *testing.T) {
	requireHostSandbox(t)
	s := newScene(t, onHost, "")
	s.start()
	s.attackEveryPhase()
}

// TestAHostileRunOnADeviceReachesNoOtherProject: two projects bound to one
// remote device, whose agent — a second process speaking the agent protocol
// to the hub over a WebSocket — confines each host-mode payload to its
// project because another project may run there.
func TestAHostileRunOnADeviceReachesNoOtherProject(t *testing.T) {
	requireHostSandbox(t)
	s := newScene(t, onDevice, "")
	s.start()
	s.attackEveryPhase()
}

// TestAHostileRunInAContainerReachesNoOtherProject: two projects on one
// container executor, under each OCI runtime Docker offers of those
// CLOOP_ISOLATION_RUNTIMES names (default runc and gVisor's runsc).
func TestAHostileRunInAContainerReachesNoOtherProject(t *testing.T) {
	if os.Getenv("CLOOP_ISOLATION_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_ISOLATION_CONTAINER_E2E=1 to attack a container executor (needs Docker)")
	}
	out, err := execOutput("docker", "info", "--format", "{{json .Runtimes}}")
	if err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	var runtimes map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &runtimes); err != nil {
		t.Fatalf("docker info's runtimes: %v: %s", err, out)
	}
	offered := make([]string, 0, len(runtimes))
	for name := range runtimes {
		offered = append(offered, name)
	}
	sort.Strings(offered)
	wanted := os.Getenv("CLOOP_ISOLATION_RUNTIMES")
	if wanted == "" {
		wanted = "runc,runsc"
	}
	ran := 0
	for _, rt := range strings.Split(wanted, ",") {
		rt = strings.TrimSpace(rt)
		if rt == "" {
			continue
		}
		t.Run(rt, func(t *testing.T) {
			if _, ok := runtimes[rt]; !ok {
				t.Skipf("docker offers no %s runtime (it offers %s)", rt, strings.Join(offered, ", "))
			}
			s := newScene(t, inContainer, rt)
			if rt == "runsc" {
				s.requireGVisorKeepsItsOwnLocks()
				t.Skip("a run in a gVisor sandbox on the hub's own host shares its project's database with the hub " +
					"without the database's locks, and fails on it at random, so there is no steady run to attack " +
					"(docs/security/model.md, \"What is not mitigated\"); under gVisor, pkg/executor/container's " +
					"read-only tests check the binds with CLOOP_TEST_OCI_RUNTIME=runsc")
			}
			s.start()
			s.attackEveryPhase()
		})
		ran++
	}
	if ran == 0 {
		t.Fatalf("CLOOP_ISOLATION_RUNTIMES=%q names no runtime", wanted)
	}
}

// attackEveryPhase is the suite's story on one executor: mallory attacks
// vault while vault's list names nobody and its run is live, again once the
// list names mallory, and again once it no longer does — and vault is as it
// was after each.
func (s *scene) attackEveryPhase() {
	t := s.t
	// library lists mallory for good: its run always holds a session to
	// misuse, and a read the boundary allows.
	s.readers("add", s.library, s.mallory)
	baseline := []string{s.library + " <- " + s.mallory}

	live := s.openVictim("unlisted-victim")
	before := s.snapshotVictim()
	s.attack(phase{name: "unlisted", live: live})
	s.releaseVictim(live)
	s.requireVictimUnchanged("unlisted", before, baseline)

	out := s.readers("add", s.vault, s.mallory)
	listed := append([]string{s.vault + " <- " + s.mallory}, baseline...)
	sort.Strings(listed)
	if ls := s.readers("ls", s.vault); !strings.Contains(ls, "mallory") {
		t.Fatalf("after `cloop project readers add` (%s), vault's list does not name mallory:\n%s",
			strings.TrimSpace(out), ls)
	}
	s.attack(phase{name: "listed", listed: true})
	s.requireVictimUnchanged("listed", before, listed)

	s.readers("rm", s.vault, s.mallory)
	s.attack(phase{name: "removed"})
	s.requireVictimUnchanged("removed", before, baseline)

	if s.kind != inContainer {
		// The operator's opt-out lets a project's runs out of the host
		// sandbox, there and on a device; a container has nothing to opt
		// out of.
		s.attackOptedOut()
	}
}

// requireGVisorKeepsItsOwnLocks pins a limit docs/security/model.md lists:
// a container on the hub's own host shares its project's database with the
// hub, and SQLite's file locks do not cross gVisor's boundary. So the hub and
// a run in a gVisor sandbox there write the database without excluding each
// other, and the run fails at random on it ("disk I/O error"), which leaves no
// run steady enough to attack. Shown directly: a write lock this process holds
// on a database stops a writer in a runc container, the control, and does not
// stop one in a gVisor sandbox. When it does — gVisor forwards the locks —
// drop this pin, let the phases run under gVisor, and rewrite that paragraph.
func (s *scene) requireGVisorKeepsItsOwnLocks() {
	t := s.t
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "locks.db")+"?_pragma=journal_mode(wal)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (a INTEGER)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"locks.db", "locks.db-wal", "locks.db-shm"} {
		_ = os.Chmod(filepath.Join(dir, f), 0o666)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `ROLLBACK`) }()
	image := s.sqliteImage()
	write := func(runtime string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--runtime="+runtime, "--network=none",
			"--user", "65534:65534", "-v", dir+":/w", image, "sqlite3", "/w/locks.db",
			"PRAGMA busy_timeout=2000; BEGIN IMMEDIATE; INSERT INTO t VALUES (2); COMMIT;").CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := write("runc"); err == nil || !strings.Contains(out, "locked") {
		t.Fatalf("the control did not hold: a runc container wrote a database this process holds locked (%v): %s", err, out)
	}
	if out, err := write("runsc"); err != nil {
		t.Fatalf("a gVisor sandbox could not write a database this process holds locked (%v: %s): the limit "+
			"docs/security/model.md lists under \"What is not mitigated\" no longer holds — drop "+
			"requireGVisorKeepsItsOwnLocks, let the phases run under gVisor, and rewrite that paragraph", err, out)
	}
	t.Logf("as docs/security/model.md says, a gVisor sandbox wrote a database this process held locked, which a " +
		"runc container could not: the locks of a project's database do not cross gVisor's boundary")
}

// requireHostSandbox skips a test on a machine whose kernel cannot give the
// host sandbox: the hub refuses such a dispatch rather than run it unconfined.
func requireHostSandbox(t *testing.T) {
	t.Helper()
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this machine, so the hub refuses every run here: %v", err)
	}
}

func execOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// dialable reports whether this machine reaches addr.
func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
