package approvalnotify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Credential-shaped strings, as a careless or hostile requester could put them
// in a name, a subject or an identity. Each is matched by the shared
// credential-pattern registry (pkg/redact).
var leaks = []string{
	"ghp_" + strings.Repeat("A1b2C3d4E5", 3) + "f6g7h8",
	"cloop_pat_0123456789abcdef_" + strings.Repeat("0123456789abcdef", 4),
	"sk-ant-api03-" + strings.Repeat("Ab3dE6gH9", 9) + "AA",
}

// TestRenderedMessagesCarryNoSecretMaterial: whatever a request's free text,
// names or subject hold, a rendered message holds none of it that looks like a
// credential, and none of the request's justification at all — for every
// webhook type.
func TestRenderedMessagesCarryNoSecretMaterial(t *testing.T) {
	now := time.Now()
	sub, _ := secretbroker.ParseSubject("project:/srv/" + leaks[2])
	req := secretbroker.AccessRequest{
		ID: "req_1", RequestedBy: "mallory+" + leaks[0] + "@example.com", SecretID: "sec_1",
		SecretName: "acme-" + leaks[1], Kind: secretbroker.KindGitHubPAT, Subject: sub,
		Constraints:   secretbroker.Constraints{Repos: []string{"acme/private-repo-name"}},
		Justification: "need it now, my old token was " + leaks[0] + " — internal ticket SEC-991",
		State:         secretbroker.RequestPending, CreatedAt: now.Add(-13 * time.Hour), ExpiresAt: now.Add(11 * time.Hour),
	}
	notices := Scan(Snapshot{Requests: []secretbroker.AccessRequest{req}, RequestsKnown: true,
		Waiting: []TokenInfo{{ID: "0123456789abcdef", Name: "token " + leaks[1], Roles: []string{"admin"},
			CreatedBy: leaks[0]}}, TokensKnown: true}, now.Add(-time.Hour), now)
	if len(notices) != 3 {
		t.Fatalf("scan found %d notices, want filed, reminder and token waiting: %+v", len(notices), notices)
	}
	for _, n := range notices {
		for _, kind := range config.NotificationTypes() {
			body, err := Render(kind, n, "https://hub.example.com/?approvals=1", now)
			if err != nil {
				t.Fatalf("Render(%s, %s): %v", kind, n.Event, err)
			}
			if !json.Valid(body) {
				t.Fatalf("Render(%s, %s) is not JSON: %s", kind, n.Event, body)
			}
			text := string(body)
			// Not vacuous: the strings were there to be scrubbed, and were.
			if !strings.Contains(text, "[redacted]") {
				t.Errorf("%s message for %s shows no scrubbed value:\n%s", kind, n.Event, text)
			}
			for _, leak := range leaks {
				if strings.Contains(text, leak) || strings.Contains(text, leak[:24]) {
					t.Errorf("%s message for %s carries credential material %q:\n%s", kind, n.Event, leak[:12], text)
				}
			}
			for _, private := range []string{"SEC-991", "need it now", "acme/private-repo-name"} {
				if strings.Contains(text, private) {
					t.Errorf("%s message for %s carries the justification or the allowlist (%q)", kind, n.Event, private)
				}
			}
		}
	}
}

// TestRenderedMessagesCannotPingOrLink: a name cannot become a Slack
// <!channel>, a Discord @everyone or masked link, or Teams markdown.
func TestRenderedMessagesCannotPingOrLink(t *testing.T) {
	n := Notice{Event: config.NotifyEventRequestFiled, RequestID: "req_x", At: time.Now(),
		RequestedBy: "<!channel> @everyone [click](https://evil.example) **bold**", SecretName: "x", Subject: "project:/a"}

	slack, _ := Render(config.NotifySlack, n, "", time.Now())
	if strings.Contains(string(slack), "<!channel>") || !strings.Contains(string(slack), "&lt;!channel&gt;") {
		t.Errorf("Slack: the mention is not escaped: %s", slack)
	}

	discord, _ := Render(config.NotifyDiscord, n, "", time.Now())
	var d struct {
		Content         string `json:"content"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
		Embeds []struct {
			Fields []struct {
				Value string `json:"value"`
			} `json:"fields"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(discord, &d); err != nil {
		t.Fatal(err)
	}
	if d.AllowedMentions.Parse == nil || len(d.AllowedMentions.Parse) != 0 {
		t.Errorf("Discord: mentions are not switched off: %s", discord)
	}
	all := d.Content
	for _, e := range d.Embeds {
		for _, f := range e.Fields {
			all += "\n" + f.Value
		}
	}
	if strings.Contains(all, "[click](") || strings.Contains(all, " @everyone") || strings.Contains(all, "**bold**") {
		t.Errorf("Discord: markup survives: %q", all)
	}

	teams, _ := Render(config.NotifyTeams, n, "https://hub.example.com/?approvals=1", time.Now())
	var tm struct {
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type string `json:"type"`
				Body []struct {
					Type    string `json:"type"`
					Inlines []struct {
						Type string `json:"type"`
					} `json:"inlines"`
				} `json:"body"`
				Actions []struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"actions"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(teams, &tm); err != nil {
		t.Fatal(err)
	}
	if len(tm.Attachments) != 1 || tm.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" ||
		tm.Attachments[0].Content.Type != "AdaptiveCard" {
		t.Fatalf("Teams: not an Adaptive Card message: %s", teams)
	}
	for _, b := range tm.Attachments[0].Content.Body {
		if b.Type != "RichTextBlock" {
			t.Errorf("Teams: user text in a %s, which renders markdown", b.Type)
		}
		for _, in := range b.Inlines {
			if in.Type != "TextRun" {
				t.Errorf("Teams: an inline of type %s", in.Type)
			}
		}
	}
	if acts := tm.Attachments[0].Content.Actions; len(acts) != 1 || acts[0].Type != "Action.OpenUrl" ||
		acts[0].URL != "https://hub.example.com/?approvals=1" {
		t.Errorf("Teams: the dashboard link is not an OpenUrl action: %+v", acts)
	}
}

// TestJSONMessageShape pins the generic body a receiver parses.
func TestJSONMessageShape(t *testing.T) {
	deadline := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	body, err := Render(config.NotifyJSON, Notice{Event: config.NotifyEventRequestApproved, RequestID: "req_9",
		RequestedBy: "dev@example.com", SecretName: "acme-app", SecretKind: "github_app", Subject: "project:/srv/api",
		DecidedBy: "lead@example.com", Deadline: deadline, At: deadline.Add(-time.Hour)},
		"https://hub.example.com/?approvals=1", deadline.Add(-30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "cloop" || got["event"] != "request.approved" || got["link"] != "https://hub.example.com/?approvals=1" {
		t.Fatalf("JSON body = %s", body)
	}
	req, _ := got["request"].(map[string]any)
	if req["id"] != "req_9" || req["decided_by"] != "lead@example.com" || req["subject"] != "project:/srv/api" ||
		req["deadline"] != "2026-10-20T12:00:00Z" {
		t.Fatalf("JSON request = %v", req)
	}
}
