package knowledgerun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestResultsFromEnv(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if c, err := ResultsFromEnv(getenv); c != nil || !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a run without the variables: %v, %v; want ErrNotConfigured", c, err)
	}
	// Blank values — what the orchestrator gives an agent — are none.
	env[EnvResultsURL], env[EnvResultsToken] = "", ""
	if _, err := ResultsFromEnv(getenv); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("blank variables: %v", err)
	}
	env[EnvResultsURL], env[EnvResultsToken] = "https://hub.example/api/run/knowledge", testToken
	if c, err := ResultsFromEnv(getenv); err != nil || c.Base() != "https://hub.example/api/run/knowledge" {
		t.Fatalf("ResultsFromEnv = %v, %v", c, err)
	}
	// The input files' variables do not send results.
	env = map[string]string{EnvInputsURL: "https://hub.example/api/run/knowledge", EnvInputsToken: testToken}
	if _, err := ResultsFromEnv(getenv); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("an input session's variables sent results: %v", err)
	}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestResultUploadQueryRoundTrips(t *testing.T) {
	u := ResultUpload{ID: strings.Repeat("a", 32), Task: 7, TitleSHA256: TitleDigest("the task"), Name: "plots/loss.png",
		Size: 1234, SHA256: sha([]byte("x")), CreatedAt: time.Date(2026, 11, 22, 10, 0, 0, 5, time.UTC), Created: true}
	got, err := ParseResultUpload(u.Query())
	if err != nil {
		t.Fatal(err)
	}
	if got != u {
		t.Fatalf("round trip = %+v, want %+v", got, u)
	}
	for name, mutate := range map[string]func(url.Values){
		"no task":        func(q url.Values) { q.Del("task") },
		"task zero":      func(q url.Values) { q.Set("task", "0") },
		"negative size":  func(q url.Values) { q.Set("size", "-1") },
		"id not hex":     func(q url.Values) { q.Set("id", "../../etc/passwd") },
		"id upper":       func(q url.Values) { q.Set("id", strings.Repeat("A", 32)) },
		"title digest":   func(q url.Values) { q.Set("title_sha256", "abc") },
		"file digest":    func(q url.Values) { q.Set("sha256", "abc") },
		"no name":        func(q url.Values) { q.Set("name", " ") },
		"name too long":  func(q url.Values) { q.Set("name", strings.Repeat("n", 1025)) },
		"bad created_at": func(q url.Values) { q.Set("created_at", "yesterday") },
	} {
		q := u.Query()
		mutate(q)
		if _, err := ParseResultUpload(q); err == nil {
			t.Errorf("%s: accepted %v", name, q)
		}
	}
}

func TestSendResult(t *testing.T) {
	data := []byte(strings.Repeat("plot data ", 1000))
	u := ResultUpload{ID: strings.Repeat("b", 32), Task: 3, TitleSHA256: TitleDigest("plot it"), Name: "loss.png",
		Size: int64(len(data)), SHA256: sha(data)}
	var got []byte
	var query url.Values
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != MountPath+PathResults ||
			r.Header.Get("Authorization") != "Bearer "+testToken ||
			r.Header.Get("Content-Type") != "application/octet-stream" || r.ContentLength != int64(len(data)) {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		query = r.URL.Query()
		got, _ = io.ReadAll(r.Body)
		switch query.Get("name") {
		case "busy.png":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"this run sends files too often"}}`))
		case "huge.png":
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write([]byte(`{"error":{"code":"PAYLOAD_TOO_LARGE","message":"no room"}}`))
		case "odd.png":
			_, _ = w.Write([]byte(`{"outcome":"kept somewhere"}`))
		default:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(ResultResponse{Outcome: ResultAttached, ID: u.ID, Task: 9})
		}
	}))
	defer hub.Close()
	c, err := New(hub.URL+MountPath, testToken)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.SendResult(context.Background(), u, strings.NewReader(string(data)+"and more the file does not have"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Outcome != ResultAttached || resp.Task != 9 || resp.ID != u.ID {
		t.Fatalf("response = %+v", resp)
	}
	if string(got) != string(data) {
		t.Fatalf("the hub got %d bytes, want exactly the %d the upload says", len(got), len(data))
	}
	if back, err := ParseResultUpload(query); err != nil || back.ID != u.ID || back.Created {
		t.Fatalf("the hub read the description as %+v, %v", back, err)
	}

	u.Name = "busy.png"
	_, err = c.SendResult(context.Background(), u, strings.NewReader(string(data)))
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusTooManyRequests || !Retryable(err) {
		t.Fatalf("a busy hub: %v (retryable %v)", err, Retryable(err))
	}
	u.Name = "huge.png"
	if _, err = c.SendResult(context.Background(), u, strings.NewReader(string(data))); err == nil || Retryable(err) ||
		!strings.Contains(err.Error(), "no room") {
		t.Fatalf("a refusal: %v (retryable %v)", err, Retryable(err))
	}
	u.Name = "odd.png"
	if _, err = c.SendResult(context.Background(), u, strings.NewReader(string(data))); err == nil {
		t.Fatal("an answer with no outcome the client knows was taken")
	}
	hub.Close()
	u.Name = "loss.png"
	if _, err = c.SendResult(context.Background(), u, strings.NewReader(string(data))); err == nil || !Retryable(err) {
		t.Fatalf("an unreachable hub: %v (retryable %v)", err, Retryable(err))
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("the token is in the error")
	}
	var nilClient *Client
	if _, err := nilClient.SendResult(context.Background(), u, nil); !errors.Is(err, ErrNotConfigured) || Retryable(err) {
		t.Fatalf("a run with no session: %v", err)
	}
}
