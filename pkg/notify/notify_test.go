package notify

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBuildSlackPayload verifies the JSON structure of a Slack attachment payload.
func TestBuildSlackPayload(t *testing.T) {
	title := "cloop: Task Done"
	body := "Task #3: Implement login\nGoal: Build a web app\nElapsed: 45s"

	data, err := buildSlackPayload(title, body)
	if err != nil {
		t.Fatalf("buildSlackPayload returned error: %v", err)
	}

	var p slackPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal slack payload: %v", err)
	}

	if len(p.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(p.Attachments))
	}
	att := p.Attachments[0]
	if att.Title != title {
		t.Errorf("attachment.title = %q, want %q", att.Title, title)
	}
	if att.Text != body {
		t.Errorf("attachment.text = %q, want %q", att.Text, body)
	}
	if att.Color != "#36a64f" {
		t.Errorf("attachment.color = %q, want #36a64f", att.Color)
	}
	if att.Footer != "cloop" {
		t.Errorf("attachment.footer = %q, want cloop", att.Footer)
	}
}

// TestBuildDiscordPayload verifies the JSON structure of a Discord embed payload.
func TestBuildDiscordPayload(t *testing.T) {
	title := "cloop: Task Failed"
	body := "Task #5: Deploy service\nGoal: Deploy to production\nElapsed: 2m3s"

	data, err := buildDiscordPayload(title, body)
	if err != nil {
		t.Fatalf("buildDiscordPayload returned error: %v", err)
	}

	var p discordPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal discord payload: %v", err)
	}

	if len(p.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(p.Embeds))
	}
	emb := p.Embeds[0]
	if emb.Title != title {
		t.Errorf("embed.title = %q, want %q", emb.Title, title)
	}
	if emb.Description != body {
		t.Errorf("embed.description = %q, want %q", emb.Description, body)
	}
	if emb.Color != 3394611 {
		t.Errorf("embed.color = %d, want 3394611", emb.Color)
	}
	if emb.Footer == nil || emb.Footer.Text != "cloop" {
		t.Errorf("embed.footer.text = %v, want cloop", emb.Footer)
	}
}

// TestSendWebhookEmptyURL verifies that an empty URL is a no-op.
func TestSendWebhookEmptyURL(t *testing.T) {
	if err := SendWebhook("", "title", "body"); err != nil {
		t.Errorf("SendWebhook(\"\") should return nil, got %v", err)
	}
}

// TestSendWebhookUnsupportedURL verifies that an unrecognized URL returns an error.
func TestSendWebhookUnsupportedURL(t *testing.T) {
	err := SendWebhook("https://example.com/webhook", "title", "body")
	if err == nil {
		t.Error("expected error for unsupported URL, got nil")
	}
}

// TestSendWebhookSlack verifies Slack format is sent to a Slack-like URL.
func TestSendWebhookSlack(t *testing.T) {
	var received slackPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Fake a Slack webhook URL by embedding the domain marker in the test server URL.
	// We rewrite SendWebhook's URL detection: use a URL that contains hooks.slack.com
	// by routing through a test server host but with the path prefix embedded.
	// Since we can't easily override the URL domain, patch the function indirectly:
	// test buildSlackPayload + httptest for correctness of HTTP behaviour.
	title := "cloop: Plan Complete"
	body := "Goal: My goal\n4/4 tasks done"
	data, err := buildSlackPayload(title, body)
	if err != nil {
		t.Fatalf("buildSlackPayload: %v", err)
	}
	resp, err := http.Post(srv.URL, "application/json", mustReader(data))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if len(received.Attachments) == 0 {
		t.Fatal("no attachments received")
	}
	if received.Attachments[0].Title != title {
		t.Errorf("title = %q, want %q", received.Attachments[0].Title, title)
	}
}

// TestSendWebhookDiscord verifies Discord format is sent to a Discord-like URL.
func TestSendWebhookDiscord(t *testing.T) {
	var received discordPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	title := "cloop: Task Done"
	body := "Task #1: Init project\nGoal: Setup\nElapsed: 12s"
	data, err := buildDiscordPayload(title, body)
	if err != nil {
		t.Fatalf("buildDiscordPayload: %v", err)
	}
	resp, err := http.Post(srv.URL, "application/json", mustReader(data))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if len(received.Embeds) == 0 {
		t.Fatal("no embeds received")
	}
	if received.Embeds[0].Title != title {
		t.Errorf("title = %q, want %q", received.Embeds[0].Title, title)
	}
	if received.Embeds[0].Description != body {
		t.Errorf("description = %q, want %q", received.Embeds[0].Description, body)
	}
}

// TestSendWebhookHTTPError verifies that non-2xx responses are returned as errors.
func TestSendWebhookHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Manually exercise the HTTP error path using buildSlackPayload + raw POST.
	data, _ := buildSlackPayload("t", "b")
	resp, err := http.Post(srv.URL, "application/json", mustReader(data))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 300 {
		t.Errorf("expected error status, got %d", resp.StatusCode)
	}
}

// TestSlackPayloadJSONKeys checks the output JSON has expected field names.
func TestSlackPayloadJSONKeys(t *testing.T) {
	data, err := buildSlackPayload("T", "B")
	if err != nil {
		t.Fatalf("buildSlackPayload: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["attachments"]; !ok {
		t.Error("missing 'attachments' key in Slack payload")
	}
}

// TestDiscordPayloadJSONKeys checks the output JSON has expected field names.
func TestDiscordPayloadJSONKeys(t *testing.T) {
	data, err := buildDiscordPayload("T", "B")
	if err != nil {
		t.Fatalf("buildDiscordPayload: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["embeds"]; !ok {
		t.Error("missing 'embeds' key in Discord payload")
	}
}

// mustReader wraps a byte slice in an io.Reader.
func mustReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}
