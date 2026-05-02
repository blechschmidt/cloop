package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- ShouldSend ---

func TestShouldSend_NilClient(t *testing.T) {
	var c *Client
	if c.ShouldSend(EventSessionStarted) {
		t.Error("nil client should not send")
	}
}

func TestShouldSend_EmptyURL(t *testing.T) {
	c := &Client{}
	if c.ShouldSend(EventSessionStarted) {
		t.Error("empty URL client should not send")
	}
}

func TestShouldSend_AllEventsWhenNoFilter(t *testing.T) {
	c := New("http://example.com/hook", nil, nil, "")
	events := []EventType{
		EventSessionStarted, EventSessionComplete, EventSessionFailed,
		EventTaskStarted, EventTaskDone, EventTaskFailed, EventTaskSkipped,
		EventPlanComplete, EventEvolveDiscovered,
	}
	for _, ev := range events {
		if !c.ShouldSend(ev) {
			t.Errorf("expected ShouldSend(%s) = true with no filter", ev)
		}
	}
}

func TestShouldSend_FilteredEvents(t *testing.T) {
	c := New("http://example.com/hook", []string{"task_done", "task_failed"}, nil, "")
	if !c.ShouldSend(EventTaskDone) {
		t.Error("EventTaskDone should be allowed")
	}
	if !c.ShouldSend(EventTaskFailed) {
		t.Error("EventTaskFailed should be allowed")
	}
	if c.ShouldSend(EventSessionStarted) {
		t.Error("EventSessionStarted should be filtered out")
	}
	if c.ShouldSend(EventTaskSkipped) {
		t.Error("EventTaskSkipped should be filtered out")
	}
}

// --- Slack detection ---

func TestNew_SlackDetection(t *testing.T) {
	tests := []struct {
		url      string
		wantSlack bool
	}{
		{"https://hooks.slack.com/services/T000/B000/xxxx", true},
		{"https://hooks.slack.com/workflows/xxxx", true},
		{"https://example.com/webhook", false},
		{"https://myapp.hooks.slack.com/services/T000/B000/xxxx", true},
		{"http://localhost:8080/hook", false},
	}
	for _, tt := range tests {
		c := New(tt.url, nil, nil, "")
		if c.isSlack != tt.wantSlack {
			t.Errorf("URL %q: isSlack = %v, want %v", tt.url, c.isSlack, tt.wantSlack)
		}
	}
}

// --- Payload JSON serialization ---

func TestPayloadSerialization(t *testing.T) {
	ts := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	p := Payload{
		Event:     EventTaskDone,
		Timestamp: ts,
		Goal:      "build something great",
		Task: &TaskInfo{
			ID:       3,
			Title:    "Implement feature X",
			Status:   "done",
			Duration: "2m30s",
		},
		Progress: &Progress{Done: 3, Total: 5, Failed: 1},
		Session:  &SessionInfo{TotalTasks: 5, DoneTasks: 3, InputTokens: 100, OutputTokens: 200},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var decoded Payload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if decoded.Event != EventTaskDone {
		t.Errorf("event = %q, want %q", decoded.Event, EventTaskDone)
	}
	if decoded.Goal != "build something great" {
		t.Errorf("goal = %q", decoded.Goal)
	}
	if decoded.Task == nil || decoded.Task.ID != 3 {
		t.Errorf("task ID missing or wrong: %+v", decoded.Task)
	}
	if decoded.Progress == nil || decoded.Progress.Done != 3 {
		t.Errorf("progress wrong: %+v", decoded.Progress)
	}
}

func TestPayloadOmitsEmptyOptionals(t *testing.T) {
	p := Payload{Event: EventSessionStarted, Goal: "test goal"}
	data, _ := json.Marshal(p)
	s := string(data)
	if strings.Contains(s, `"task"`) {
		t.Error("empty task field should be omitted")
	}
	if strings.Contains(s, `"progress"`) {
		t.Error("empty progress field should be omitted")
	}
	if strings.Contains(s, `"session"`) {
		t.Error("empty session field should be omitted")
	}
}

// --- HMAC signing ---

func computeExpectedSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestSend_HMACSigningCorrect(t *testing.T) {
	const secret = "my-webhook-secret"
	var (
		mu          sync.Mutex
		receivedSig string
		receivedBody []byte
		done        = make(chan struct{})
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedSig = r.Header.Get("X-Hub-Signature-256")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		mu.Unlock()
		close(done)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, nil, secret)
	c.Send(EventSessionStarted, Payload{Goal: "test"})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server never received request")
	}

	mu.Lock()
	sig := receivedSig
	body := receivedBody
	mu.Unlock()

	if sig == "" {
		t.Fatal("X-Hub-Signature-256 header missing")
	}
	expected := computeExpectedSig(secret, body)
	if sig != expected {
		t.Errorf("HMAC sig = %q, want %q", sig, expected)
	}
}

func TestSend_NoHMACWhenNoSecret(t *testing.T) {
	var (
		sigHeader string
		done      = make(chan struct{})
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get("X-Hub-Signature-256")
		close(done)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, nil, "")
	c.Send(EventSessionStarted, Payload{Goal: "no secret"})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server never received request")
	}
	if sigHeader != "" {
		t.Errorf("expected no signature header, got %q", sigHeader)
	}
}

func TestSend_CustomHeaders(t *testing.T) {
	var (
		authHeader string
		done       = make(chan struct{})
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		close(done)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, map[string]string{"Authorization": "Bearer token123"}, "")
	c.Send(EventTaskDone, Payload{})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server never received request")
	}
	if authHeader != "Bearer token123" {
		t.Errorf("Authorization = %q, want %q", authHeader, "Bearer token123")
	}
}

func TestSend_FilteredEventNotDelivered(t *testing.T) {
	delivered := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.URL, []string{"task_done"}, nil, "")
	c.Send(EventSessionStarted, Payload{Goal: "test"}) // not in filter

	// Give goroutine time if it were to fire
	time.Sleep(100 * time.Millisecond)
	if delivered {
		t.Error("filtered event should not be delivered")
	}
}

// --- Slack message formatting ---

func TestFormatSlackMessage(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		contains []string
	}{
		{
			name:    "session started",
			payload: Payload{Event: EventSessionStarted, Goal: "build app"},
			contains: []string{"Session started", "build app"},
		},
		{
			name: "session complete with stats",
			payload: Payload{
				Event: EventSessionComplete,
				Goal:  "build app",
				Session: &SessionInfo{DoneTasks: 5, TotalTasks: 6, Duration: "10m", EstCostUSD: "$0.05"},
			},
			contains: []string{"Session complete", "5/6", "10m", "$0.05", "build app"},
		},
		{
			name:    "session failed",
			payload: Payload{Event: EventSessionFailed, Goal: "build app"},
			contains: []string{"FAILED", "build app"},
		},
		{
			name: "task started with progress",
			payload: Payload{
				Event:    EventTaskStarted,
				Task:     &TaskInfo{ID: 2, Title: "Write tests"},
				Progress: &Progress{Done: 1, Total: 5},
			},
			contains: []string{"Starting task 2", "[1/5 done]", "Write tests"},
		},
		{
			name: "task done with duration",
			payload: Payload{
				Event:    EventTaskDone,
				Task:     &TaskInfo{ID: 3, Title: "Deploy", Duration: "5m"},
				Progress: &Progress{Done: 3, Total: 5},
			},
			contains: []string{"Task 3 done", "5m", "[3/5 done]", "Deploy"},
		},
		{
			name: "task failed",
			payload: Payload{
				Event:    EventTaskFailed,
				Task:     &TaskInfo{ID: 4, Title: "Lint"},
				Progress: &Progress{Done: 2, Total: 5},
			},
			contains: []string{"Task 4", "FAILED", "Lint"},
		},
		{
			name: "task skipped",
			payload: Payload{
				Event: EventTaskSkipped,
				Task:  &TaskInfo{ID: 5, Title: "Optional step"},
			},
			contains: []string{"Task 5 skipped", "Optional step"},
		},
		{
			name: "plan complete",
			payload: Payload{
				Event: EventPlanComplete,
				Goal:  "finish project",
				Session: &SessionInfo{DoneTasks: 8, TotalTasks: 8},
			},
			contains: []string{"Plan complete", "8/8", "finish project"},
		},
		{
			name: "evolve discovered new tasks",
			payload: Payload{
				Event: EventEvolveDiscovered,
				Goal:  "evolve app",
				Session: &SessionInfo{EvolveStep: 2, NewTasksFound: 3},
			},
			contains: []string{"Evolve #2", "3 new task", "evolve app"},
		},
		{
			name: "evolve no new tasks",
			payload: Payload{
				Event: EventEvolveDiscovered,
				Goal:  "evolve app",
				Session: &SessionInfo{EvolveStep: 1, NewTasksFound: 0},
			},
			contains: []string{"no new tasks", "fully evolved", "evolve app"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := formatSlackMessage(tt.payload)
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q does not contain %q", msg, want)
				}
			}
		})
	}
}

// --- Send delivers correct JSON body ---

func TestSend_JSONBodyFields(t *testing.T) {
	var (
		body map[string]interface{}
		done = make(chan struct{})
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		close(done)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.URL, nil, nil, "")
	c.Send(EventTaskDone, Payload{
		Goal: "test goal",
		Task: &TaskInfo{ID: 1, Title: "Task A", Status: "done"},
	})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server never received request")
	}
	if body["event"] != "task_done" {
		t.Errorf("event = %v", body["event"])
	}
	if body["goal"] != "test goal" {
		t.Errorf("goal = %v", body["goal"])
	}
	if body["timestamp"] == nil {
		t.Error("timestamp should be present")
	}
}

// --- Slack endpoint sends text field ---

func TestSend_SlackFormat(t *testing.T) {
	var (
		body map[string]interface{}
		done = make(chan struct{})
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		close(done)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Force Slack mode by injecting isSlack directly
	c := &Client{url: srv.URL, isSlack: true}
	p := Payload{Goal: "my goal"}
	p.Event = EventSessionStarted
	p.Timestamp = time.Now()
	go c.send(p)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server never received request")
	}
	text, ok := body["text"].(string)
	if !ok || text == "" {
		t.Errorf("expected non-empty 'text' field in Slack body, got %v", body)
	}
	if !strings.Contains(text, "my goal") {
		t.Errorf("Slack text %q does not contain goal", text)
	}
}
