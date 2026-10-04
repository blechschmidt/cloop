package hubdoctor

// `cloop hub doctor` reads where each running hub's egress proxy listens, or
// why it does not, from the status the hub records (Task 20378).

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// recordHosted writes one hub's status row, as a hub hosting the proxy does.
func recordHosted(t *testing.T, path, key string, st egressbroker.HostedStatus) {
	t.Helper()
	meta, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutHubOwner(statedb.HubOwnerRow{Kind: egressbroker.HostedStatusKind, Key: key,
		InstanceID: key, Meta: string(meta)}); err != nil {
		t.Fatal(err)
	}
}

// thisProcess is a status recorded by this test process, which is alive.
func thisProcess(st egressbroker.HostedStatus) egressbroker.HostedStatus {
	id := hublease.LocalIdentity()
	st.Hostname, st.PID, st.BootID, st.HubPort = id.Hostname, id.PID, id.BootID, 8081
	st.UpdatedAt = time.Now().UTC()
	return st
}

// deadPID returns the pid of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot run true: %v", err)
	}
	return cmd.Process.Pid
}

func TestHubDoctorReportsTheHostedEgressProxy(t *testing.T) {
	t.Run("listening, advertised", func(t *testing.T) {
		dir := t.TempDir()
		path := mustInitStateDB(t, dir)
		recordHosted(t, path, "hub@x:8081", thisProcess(egressbroker.HostedStatus{
			Enabled: true, Listening: "0.0.0.0:8899", Advertised: "203.0.113.5:8899"}))
		f := only(t, findingsFor(t, dir, egressCfg(""), Options{Offline: true}), "egress.hosted")
		wantSeverity(t, f, SeverityPass)
		if !strings.Contains(f.Message, "listening on 0.0.0.0:8899, advertised as 203.0.113.5:8899") ||
			!strings.Contains(f.Message, "port 8081") {
			t.Errorf("message = %q", f.Message)
		}
	})

	t.Run("a bind that failed is a failure, with the reason", func(t *testing.T) {
		dir := t.TempDir()
		path := mustInitStateDB(t, dir)
		recordHosted(t, path, "hub@x:8081", thisProcess(egressbroker.HostedStatus{Enabled: true,
			Error: "bind executors.egress.listen_addr 0.0.0.0:8899: address already in use"}))
		f := only(t, findingsFor(t, dir, egressCfg(""), Options{Offline: true}), "egress.hosted")
		wantSeverity(t, f, SeverityFail)
		if !strings.Contains(f.Message, "address already in use") || f.Remediation == "" {
			t.Errorf("finding = %+v", f)
		}
	})

	t.Run("enabled with no hub reporting is a warning", func(t *testing.T) {
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		f := only(t, findingsFor(t, dir, egressCfg(""), Options{Offline: true}), "egress.hosted")
		wantSeverity(t, f, SeverityWarn)
		if !strings.Contains(f.Message, "no running hub") {
			t.Errorf("message = %q", f.Message)
		}
	})

	t.Run("a row a crashed hub left is not a running proxy", func(t *testing.T) {
		dir := t.TempDir()
		path := mustInitStateDB(t, dir)
		st := thisProcess(egressbroker.HostedStatus{Enabled: true, Listening: "0.0.0.0:8899",
			Advertised: "127.0.0.1:8899"})
		st.PID = deadPID(t)
		recordHosted(t, path, "hub@x:8082", st)
		f := only(t, findingsFor(t, dir, egressCfg(""), Options{Offline: true}), "egress.hosted")
		wantSeverity(t, f, SeverityWarn)
	})

	t.Run("a hub whose overlay enables it is reported when this config does not", func(t *testing.T) {
		dir := t.TempDir()
		path := mustInitStateDB(t, dir)
		recordHosted(t, path, "hub@x:8081", thisProcess(egressbroker.HostedStatus{
			Enabled: true, Listening: "127.0.0.1:41000", Advertised: "127.0.0.1:41000"}))
		got := findingsFor(t, dir, &config.Config{}, Options{Offline: true})
		wantSeverity(t, only(t, got, "egress.hosted"), SeverityPass)
		wantSeverity(t, only(t, got, "egress.enabled"), SeverityPass)
	})

	t.Run("disabled, nothing hosted, nothing said", func(t *testing.T) {
		dir := t.TempDir()
		mustInitStateDB(t, dir)
		if got := findingsFor(t, dir, &config.Config{}, Options{Offline: true}); len(got["egress.hosted"]) != 0 {
			t.Errorf("findings = %+v", got["egress.hosted"])
		}
	})
}

// TestHubDoctorReadsEgressStatusWithoutMigrating: the doctor reads a live
// hub's database through a read-only handle, so a database it finds is never
// written by looking at it.
func TestHubDoctorReadsEgressStatusWithoutMigrating(t *testing.T) {
	dir := t.TempDir()
	path := mustInitStateDB(t, dir)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	findingsFor(t, dir, egressCfg(""), Options{Offline: true})
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("the doctor wrote the database (mtime %s → %s)", before.ModTime(), after.ModTime())
	}
}
