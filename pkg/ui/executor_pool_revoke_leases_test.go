package ui

// Revoking an executor pool, or the controller credential that minted its
// runners, takes back the leases those runners hold the way the Leases panel
// revokes one (Task 20487): the revocation is recorded, the hub's own copy
// goes, every holder is told to kill its workload, and lease.revoke_sent is
// on the control plane's audit chain — for a lease another member issued, the
// record is what binds it. Before, the revocation was pushed only to runners
// connected to the member that handled the request, the hub kept its copy
// until the run ended, and nothing was recorded — what tests/kubecontroller
// found on a real cluster.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestRevokingAPoolOrItsCredentialRevokesItsRunnersLeases(t *testing.T) {
	// The registry is process-wide: leave it as it was found.
	t.Cleanup(func() {
		for _, id := range []string{"lease_cred_runner", "lease_pool_runner", "lease_device"} {
			liveLeases.remove(id)
		}
	})
	// The secret store records revocations; it needs its root key.
	t.Setenv(secretbroker.EnvPassphraseKey, "pool-revoke-leases-unit-passphrase")
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 4})
	credID, _, err := executorpool.ParseCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	enrolled := func(credential, executorID string) {
		t.Helper()
		st, body := r.call(http.MethodPost, poolRunnersPath, credential, map[string]int{"count": 1})
		if st != http.StatusCreated {
			t.Fatalf("mint: %d %v", st, body)
		}
		enrollment := body["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
		if _, err := store.DB().MarkExecutorPoolRunnerEnrolled(enrollment, executorID, r.srv.hubInstanceID(), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	lease := func(id, executorID string) {
		liveLeases.add(&secretLease{lease: &secretbroker.Lease{ID: id, ExecutorID: executorID, ProjectID: r.dir,
			IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}})
	}
	revokeSent := func() map[string]string {
		t.Helper()
		st, body := r.call(http.MethodGet, "/api/audit?source=all&event_type=lease.revoke_sent&limit=100", "", nil)
		if st != http.StatusOK {
			t.Fatalf("read the audit trail: %d %v", st, body)
		}
		var events []auditEventJSON
		raw, _ := json.Marshal(body["events"])
		_ = json.Unmarshal(raw, &events)
		out := map[string]string{}
		for _, e := range events {
			out[e.EntityID] = e.Payload
		}
		return out
	}

	enrolled(token, "runner-cred")
	lease("lease_cred_runner", "runner-cred")
	// A lease of the same runner that another hub member issued, and that
	// member has stopped: only the control plane's record of it is here.
	if err := store.DB().PutSecretLease(statedb.SecretLeaseRow{LeaseID: "lease_cred_elsewhere", Holder: "hub_gone",
		ExecutorID: "runner-cred", ProjectID: r.dir, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// A device's lease, which no revocation here concerns.
	lease("lease_device", "edge-01")
	revoked := func(id string) []statedb.LeaseRevocationRow {
		t.Helper()
		rows, err := store.DB().LeaseRevocations(id)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}

	st, body := r.call(http.MethodDelete, "/api/executor-pools/"+id+"/credentials/"+credID, "", nil)
	if st != http.StatusOK {
		t.Fatalf("revoke the credential: %d %v", st, body)
	}
	if leaseIsRegistered("lease_cred_runner") {
		t.Error("the hub still holds the lease of a runner whose credential was revoked")
	}
	if !leaseIsRegistered("lease_device") {
		t.Fatal("revoking a pool's credential took a device's lease")
	}
	sent := revokeSent()
	if p := sent["lease_cred_runner"]; !strings.Contains(p, `"executor_id":"runner-cred"`) ||
		!strings.Contains(p, "controller credential that minted it was revoked") || !strings.Contains(p, `"action":"kill"`) {
		t.Errorf("lease.revoke_sent for the runner's lease: %q", p)
	}
	if _, ok := sent["lease_device"]; ok {
		t.Error("a device's lease was revoked with the pool's credential")
	}
	// On record, each with the kill it asked for: the one this member held,
	// and the one a stopped member issued, which nothing here could reach.
	for _, id := range []string{"lease_cred_runner", "lease_cred_elsewhere"} {
		rows := revoked(id)
		if len(rows) != 1 || rows[0].Action != "kill" || !strings.Contains(rows[0].Reason, "controller credential") {
			t.Errorf("the revocation of %s on record: %+v", id, rows)
		}
	}
	if p := sent["lease_cred_elsewhere"]; !strings.Contains(p, "controller credential that minted it was revoked") {
		t.Errorf("lease.revoke_sent for the lease another member issued: %q", p)
	}
	if rows := revoked("lease_device"); len(rows) != 0 {
		t.Errorf("a device's lease is on record as revoked: %+v", rows)
	}

	// The pool's own revocation does the same for the runners it takes.
	st, body = r.call(http.MethodPost, "/api/executor-pools/"+id+"/credentials", "", map[string]any{})
	if st != http.StatusCreated {
		t.Fatalf("mint a second credential: %d %v", st, body)
	}
	enrolled(body["token"].(string), "runner-pool")
	lease("lease_pool_runner", "runner-pool")
	if st, body := r.call(http.MethodPost, "/api/executor-pools/"+id+"/revoke", "", map[string]any{}); st != http.StatusOK {
		t.Fatalf("revoke the pool: %d %v", st, body)
	}
	if leaseIsRegistered("lease_pool_runner") {
		t.Error("the hub still holds the lease of a runner whose pool was revoked")
	}
	if p := revokeSent()["lease_pool_runner"]; !strings.Contains(p, `"executor_id":"runner-pool"`) ||
		!strings.Contains(p, "executor pool k8s was revoked") {
		t.Errorf("lease.revoke_sent for the revoked pool's runner: %q", p)
	}
	if !leaseIsRegistered("lease_device") {
		t.Error("revoking a pool took a device's lease")
	}
}
