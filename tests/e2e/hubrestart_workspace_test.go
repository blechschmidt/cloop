package e2e_test

// A device run's workspace session survives its hub restarting (Task 20390).
//
// The scene of hubrestart_proxies_test.go — a real hub with its git proxy, a
// real agent in host mode, a stand-in claude blocked on a FIFO, a GitHub App
// whose tokens the forge (answering as github.com, behind a CONNECT proxy)
// checks — with the project itself a checkout of github.com/acme/tool and the
// hub configured to have a run's work pushed back (executors.write_back:
// push). So the device provisions its tree through a pinned proxy session for
// that one repository, and pushes its work back through the same session once
// the workload exits.
//
// The hub is killed (and, in the other subtest, stopped as systemd stops it)
// while the harness is blocked: after the provisioning fetch, before the
// write-back. A new hub process starts in the same directory, the agent
// reconnects, and the new process adopts the run — taking over the workspace
// lease the owner row names and restoring the pinned session under its
// original id and token. Then the harness is released, commits its work, and
// the device's write-back push, presenting the token the stopped process
// minted, must land on the forge through the restored session.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// newRestartWorkspaceScene is a restart scene whose project is a checkout of
// github.com/acme/tool, on a hub that runs a git proxy and pushes a run's work
// back, with the project granted a GitHub App for the repository.
func newRestartWorkspaceScene(t *testing.T) (*restartScene, *proxyUpstreams) {
	t.Helper()
	gitBin, _ := secretbrokertest.GitTools(t)
	u := newProxyUpstreams(t)
	gitPort := freePort(t)
	executors := fmt.Sprintf(`    write_back: push
    git_proxy:
        enabled: true
        listen_addr: 127.0.0.1:%d
        cert_file: %s
        key_file: %s
`, gitPort, u.local.CertFile, u.local.KeyFile)
	s := newRestartSceneWith(t, restartOptions{
		gitRepo:   true,
		executors: executors,
		hubEnv: []string{
			"HTTPS_PROXY=http://" + u.connect.Addr,
			"https_proxy=http://" + u.connect.Addr,
			"SSL_CERT_FILE=" + u.ca.CertFile,
		},
		// The device trusts the hub's git proxy, whose certificate the test CA
		// signed: what an operator's private CA is to a real device.
		agentEnv: []string{"GIT_SSL_CAINFO=" + u.ca.CertFile},
	})

	// The forge holds the project's history, and the hub's checkout knows the
	// origin's tip — the commit the run is provisioned at and measured from.
	bare := filepath.Join(u.forge.Root, "acme", "tool.git")
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = s.proj
		cmd.Env = s.env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("push", "-q", "--force", bare, "HEAD:refs/heads/main")
	runGit("remote", "add", "origin", "https://github.com/acme/tool")
	runGit("update-ref", "refs/remotes/origin/main", "HEAD")

	var app map[string]any
	if err := json.Unmarshal(secretbrokertest.AppPayload(601, 602), &app); err != nil {
		t.Fatal(err)
	}
	app["base_url"] = u.api.URL
	payload, _ := json.Marshal(app)
	appFile := filepath.Join(s.root, "app.json")
	writeTestFile(t, appFile, string(payload))
	s.cloop(s.hubDir, "secret", "mint", "e2e-workspace-app", "--kind", "github_app", "--file", appFile)
	s.cloop(s.hubDir, "secret", "grant", "e2e-workspace-app", "--to", "project:"+s.proj,
		"--repos", "acme/tool", "--permissions", "contents:write", "--ttl", "2h")
	return s, u
}

func TestE2EDeviceRunsWriteBackLandsThroughItsRestoredWorkspaceSession(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGKILL, syscall.SIGTERM} {
		sig := sig
		t.Run(sig.String(), func(t *testing.T) {
			s, u := newRestartWorkspaceScene(t)
			s.cloop(s.proj, "task", "add", "Change the tool", "--no-ai", "--auto")
			s.startHub()
			s.startAgent()
			s.bind()

			var ws struct {
				Lease   string `json:"lease"`
				Session string `json:"session"`
			}
			before := s.stubStarts()
			idx := s.projectIdx(s.proj)
			if code, body := s.call("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), nil); code != http.StatusOK {
				t.Fatalf("start the run = %d %v", code, body)
			}
			s.waitFor("the harness to be running on the device", 90*time.Second, func() bool {
				return s.stubStarts() > before
			})
			// The device fetched its tree through a pinned session for the
			// workspace, which the dispatching process recorded and named in
			// the run's owner row.
			oldMember, meta := s.runOwner(s.proj)
			raw, _ := json.Marshal(meta["workspace"])
			if err := json.Unmarshal(raw, &ws); err != nil || ws.Lease == "" || ws.Session == "" {
				t.Fatalf("the run's owner row names no workspace lease and session: %v", meta)
			}
			if got := s.leaseHolder(ws.Lease); got != oldMember {
				t.Fatalf("workspace lease %s is recorded as held by %q, want %s", ws.Lease, got, oldMember)
			}
			rows := s.query(s.hubDir, `SELECT lease_id, holder, closed_at, scope_json FROM proxy_sessions
				WHERE kind = 'git' AND session_id = ?`, ws.Session)
			if len(rows) != 1 || rows[0][0] != ws.Lease || rows[0][1] != oldMember || rows[0][2] != "" ||
				!strings.Contains(rows[0][3], `"repo_path":"acme/tool"`) {
				t.Fatalf("the pinned session's record = %v", rows)
			}
			if n := len(s.auditRowsFor("gitproxy.fetch", ws.Session)); n == 0 {
				t.Fatalf("the device's provisioning fetch did not go through the workspace session")
			}
			mintsBefore := len(scopedCreates(u))

			t.Logf("run on %s, owner %s, workspace lease %s, session %s; stopping the hub with %v",
				s.executorID, oldMember, ws.Lease, ws.Session, sig)
			s.stopHub(sig)
			s.startHub()
			s.waitAgentOnline()
			var newMember string
			s.waitFor("the restarted hub to take the run over", 60*time.Second, func() bool {
				newMember, _ = s.runOwner(s.proj)
				return newMember != "" && newMember != oldMember
			})
			s.waitFor("the restarted hub to hold the workspace lease", 30*time.Second, func() bool {
				return s.leaseHolder(ws.Lease) == newMember
			})
			s.waitFor("the pinned session to be restored", 30*time.Second, func() bool {
				return len(s.auditRowsFor("gitproxy.session_restored", ws.Session)) > 0
			})
			restored := s.auditRowsFor("gitproxy.session_restored", ws.Session)
			if len(restored) != 1 || !strings.Contains(fmt.Sprint(restored[0]["detail"]), oldMember) {
				t.Fatalf("restored rows = %v, want one naming %s", restored, oldMember)
			}
			if _, meta := s.runOwner(s.proj); meta["workspace"] == nil {
				t.Errorf("the adopted run's owner row no longer names its workspace: %v", meta)
			}
			if got := scopedCreates(u); len(got) <= mintsBefore {
				t.Errorf("the restore minted no App token for the session (%d before, %d after)", mintsBefore, len(got))
			}

			// The harness finishes; the device commits its work and pushes it
			// back through the session the stopped process minted.
			s.releaseHarness(true)
			var branch string
			s.waitFor("the write-back to be journaled", 90*time.Second, func() bool {
				rows, err := s.tryQuery(s.proj, `SELECT message FROM events WHERE type = 'write_back'`)
				if err != nil {
					return false
				}
				for _, r := range rows {
					if m := r[0]; strings.Contains(m, "pushed to cloop/run-") {
						rest := m[strings.Index(m, "cloop/run-"):]
						branch, _, _ = strings.Cut(rest, " ")
						return true
					} else if strings.Contains(m, "could not be pushed") {
						t.Fatalf("the write-back failed: %s", m)
					}
				}
				return false
			})
			if sha := u.forge.Ref(t, "acme/tool", "refs/heads/"+branch); sha == "" {
				t.Fatalf("the write-back push to %s did not reach the forge", branch)
			}
			pushes := s.auditRowsFor("gitproxy.push_allowed", ws.Session)
			if len(pushes) != 1 || !strings.Contains(fmt.Sprint(pushes[0]["refs"]), branch) {
				t.Fatalf("push rows for the workspace session = %v, want the write-back's", pushes)
			}

			s.waitFor("task 1 to be done in the hub's copy", 90*time.Second, func() bool {
				return s.taskStatus(s.proj, 1) == "done"
			})
			s.waitFor("the run's control-plane rows to be cleared", 60*time.Second, func() bool {
				return len(s.leftovers()) == 0
			})
			// The workspace lease ended with the run, released by the process
			// holding it, and the session with it.
			s.waitFor("the workspace lease to be released", 30*time.Second, func() bool {
				return s.leaseHolder(ws.Lease) == ""
			})
			if open := s.query(s.hubDir, `SELECT kind, session_id FROM proxy_sessions WHERE closed_at = ''`); len(open) != 0 {
				t.Errorf("sessions left open after the run: %v", open)
			}
			if n := s.stubStarts(); n != 1 {
				t.Errorf("the harness was started %d times for one task", n)
			}
		})
	}
}

// auditRowsFor returns the payloads of the control plane's audit rows of one
// type for one entity.
func (s *restartScene) auditRowsFor(eventType, entityID string) []map[string]any {
	var out []map[string]any
	rows, err := s.tryQuery(s.hubDir, `SELECT payload FROM audit_events WHERE event_type = ? AND entity_id = ? ORDER BY id`,
		eventType, entityID)
	if err != nil {
		return nil
	}
	for _, r := range rows {
		var p map[string]any
		_ = json.Unmarshal([]byte(r[0]), &p)
		out = append(out, p)
	}
	return out
}

// scopedCreates is every installation token the fake GitHub minted with more
// than the metadata scope discovery uses.
func scopedCreates(u *proxyUpstreams) []secretbroker.InstallationTokenRequest {
	var out []secretbroker.InstallationTokenRequest
	for _, c := range u.gh.Creates() {
		if len(c.Permissions) == 1 && c.Permissions["metadata"] == "read" {
			continue
		}
		out = append(out, c)
	}
	return out
}
