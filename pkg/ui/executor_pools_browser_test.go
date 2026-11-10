package ui

// Browser gate for the Executors tab's executor pools (Task 20486): see
// testdata/executor_pools_browser.js for what it drives and why a browser.
// The hub is served over TLS, as a hub that hands out install commands must
// be. Skips when Chrome or node is missing, like the others.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
)

type poolsBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Card                 string   `json:"card"`
	FocusInitial         string   `json:"focus_initial"`
	TabEscaped           int      `json:"tab_escaped"`
	TabStops             []string `json:"tab_stops"`
	FocusAfterEscape     string   `json:"focus_after_escape"`
	NamespacePlaceholder string   `json:"namespace_placeholder"`
	Command              string   `json:"command"`
	Notice               string   `json:"notice"`
	Notes                string   `json:"notes"`
	FocusResult          string   `json:"focus_result"`
	Phone                struct {
		PageOverflow int  `json:"page_overflow"`
		BoxLeft      int  `json:"box_left"`
		BoxRight     int  `json:"box_right"`
		Width        int  `json:"width"`
		PreOverflow  int  `json:"pre_overflow"`
		DoneVisible  bool `json:"done_visible"`
	} `json:"phone"`
	LeftInPage   bool     `json:"left_in_page"`
	NewCard      string   `json:"new_card"`
	CordonedCard string   `json:"cordoned_card"`
	Answers      []string `json:"answers"`
	TaskChip     string   `json:"task_chip"`
}

func TestExecutorPools_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot press the buttons a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "pools in a browser", []*pm.Task{
		{ID: 1, Title: "Train the ranking model", Status: pm.TaskDone, Priority: 1, ExecutorID: "agent-pool-runner",
			ExecutorKind: "remote", Isolation: "remote"},
	})
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.closePools)
	client := ts.Client()

	call := func(method, path, bearer, protocol string, body any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("User-Agent", "cloop-executor-controller/v0.0.6")
			req.Header.Set(executorpool.ControllerProtocolHeader, protocol)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 300 {
			t.Fatalf("%s %s = %d: %s", method, path, resp.StatusCode, raw)
		}
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return out
	}
	created := call(http.MethodPost, "/api/executor-pools", "", "", map[string]any{"name": "seeded-pool", "max_runners": 2,
		"credential": true, "capabilities": map[string]any{"harnesses": []string{"claude"}}})
	poolID := created["pool"].(map[string]any)["id"].(string)
	token := created["token"].(string)
	minted := call(http.MethodPost, poolRunnersPath, token, "3", map[string]any{"count": 1})
	enrollment := minted["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	call(http.MethodPost, poolStatusPath, token, "3", map[string]any{"healthy": false, "reason": "StoragePending",
		"message": "claim seeded-pool-storage-0 is Pending", "storage": map[string]any{"claims": 2, "bound": 1,
			"pending": 1, "in_use": 1, "bytes_used": 2 << 30, "bytes_capacity": 40 << 30}})
	store, err := srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().MarkExecutorPoolRunnerEnrolled(enrollment, "agent-pool-runner", "member", time.Now()); err != nil {
		t.Fatal(err)
	}
	runner, err := store.RunnerByExecutor("agent-pool-runner")
	if err != nil {
		t.Fatal(err)
	}
	srv.recordPoolPlacement(store, dir, poolID, "agent-pool-runner")

	args := []string{mustAbs(t, "testdata/executor_pools_browser.js"), chrome, ts.URL}
	if d := os.Getenv("POOLS_BROWSER_SHOTS"); d != "" {
		args = append(args, d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, args...).Output()
	var got poolsBrowserResults
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		t.Fatalf("driving the browser failed: %v / %v\n%s", err, jerr, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver failed: %s", got.Error.Message)
	}

	for _, want := range []string{"seeded-pool", "Demand:", "Runners:", "of 2", "Volumes: 1 of 2 bound, 1 pending",
		"Controller: protocol 3", "last contact", "controller v0.0.6, behind", "stuck Pending", "claude"} {
		if !strings.Contains(got.Card, want) {
			t.Errorf("the seeded pool's card lacks %q:\n%s", want, got.Card)
		}
	}
	if got.FocusInitial != "poolName" || got.TabEscaped != 0 || len(got.TabStops) < 8 || got.FocusAfterEscape != "addPool" {
		t.Errorf("focus: opened on %q, %d Tab presses left the dialog, %d stops %v, back on %q after Escape",
			got.FocusInitial, got.TabEscaped, len(got.TabStops), got.TabStops, got.FocusAfterEscape)
	}
	if got.NamespacePlaceholder != "cloop-browser-pool" {
		t.Errorf("the namespace placeholder: %q", got.NamespacePlaceholder)
	}
	for _, want := range []string{"name: cloop-browser-pool", "create secret generic browser-pool-pool-credential",
		"--from-literal=credential=cloop_pool1_", "helm install browser-pool " + ts.URL + "/charts/cloop-executor-controller.tgz",
		"--set-string pool.hubURL=" + ts.URL, "--set pool.maxRunners=2", "--set pool.persistence.enabled=true",
		"--set-string pool.persistence.size=30Gi"} {
		if !strings.Contains(got.Command, want) {
			t.Errorf("the install commands lack %q:\n%s", want, got.Command)
		}
	}
	if !strings.Contains(got.Notice, "shown once") || got.FocusResult != "poolCopyBtn" || got.Notes == "" {
		t.Errorf("the result: notice %q, focus on %q, notes %q", got.Notice, got.FocusResult, got.Notes)
	}
	p := got.Phone
	if p.PageOverflow > 0 || p.BoxLeft < 0 || p.BoxRight > p.Width || p.PreOverflow > 0 || !p.DoneVisible {
		t.Errorf("the result on a 360 px phone: %+v", p)
	}
	if got.LeftInPage {
		t.Error("the credential stayed in the page after the dialog closed")
	}
	if !strings.Contains(got.NewCard, "browser-pool") || !strings.Contains(got.NewCard, "zone=eu-1") {
		t.Errorf("the new pool's card:\n%s", got.NewCard)
	}
	if !strings.Contains(strings.ToLower(got.CordonedCard), "cordoned") || !strings.Contains(got.CordonedCard, "maintenance window") ||
		!strings.Contains(got.CordonedCard, "Uncordon") {
		t.Errorf("the cordoned card:\n%s", got.CordonedCard)
	}
	if len(got.Answers) != 2 || !strings.HasPrefix(got.Answers[0], "prompt:") || !strings.HasPrefix(got.Answers[1], "confirm:") {
		t.Errorf("the page asked %v, want a prompt to cordon and a confirm to revoke", got.Answers)
	}
	if want := "Poolseeded-pool / " + runner.Name; got.TaskChip != want {
		t.Errorf("the task's executor chip: %q, want %q", got.TaskChip, want)
	}

	// What the hub holds after it all.
	pools, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, pl := range pools {
		if pl.Name != "browser-pool" {
			continue
		}
		if !pl.Revoked() || pl.MaxRunners != 2 || pl.Labels["zone"] != "eu-1" {
			t.Errorf("the browser's pool as stored: %+v", pl)
		}
		if aud, _ := store.Audience(pl.ID); len(aud) != 1 || aud[0].Kind != "group" || aud[0].Value != "qa" {
			t.Errorf("its access list: %+v", aud)
		}
		return
	}
	t.Fatal("the hub holds no pool called browser-pool")
}
