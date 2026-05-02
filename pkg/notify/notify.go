// Package notify provides OS desktop notification support and webhook notifications.
// Desktop notifications dispatch to platform-native tools (notify-send on Linux,
// osascript on macOS) and silently ignore unsupported platforms or missing tools.
// Webhook notifications support Slack and Discord incoming webhook URLs.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
)

// Send fires a desktop notification with the given title and body.
// Errors are silently swallowed — notifications are best-effort and must
// never interrupt or fail the main orchestration loop.
func Send(title, body string) {
	switch runtime.GOOS {
	case "linux":
		sendLinux(title, body)
	case "darwin":
		sendDarwin(title, body)
	// Other platforms: no-op.
	}
}

// sendLinux uses notify-send (libnotify).
// notify-send is available on most Linux desktop environments (GNOME, KDE, XFCE, etc.).
func sendLinux(title, body string) {
	cmd := exec.Command("notify-send", "--", title, body)
	// Ignore errors: notify-send may be absent in headless environments.
	_ = cmd.Run()
}

// sendDarwin uses osascript to trigger a macOS notification.
func sendDarwin(title, body string) {
	script := `display notification "` + escapeAppleScript(body) + `" with title "` + escapeAppleScript(title) + `"`
	cmd := exec.Command("osascript", "-e", script)
	_ = cmd.Run()
}

// SendWebhook sends a rich notification to a Slack, Discord, or custom HTTP webhook URL.
// The format is auto-detected from the URL:
//   - hooks.slack.com → Slack attachments format
//   - discord.com/api/webhooks → Discord embeds format
//   - anything else → generic JSON: {"title":"...","body":"...","source":"cloop"}
//
// Errors are returned; callers should treat them as best-effort and not block
// the main orchestration flow.
func SendWebhook(webhookURL, title, body string) error {
	if webhookURL == "" {
		return nil
	}

	var payload []byte
	var err error

	switch {
	case strings.Contains(webhookURL, "hooks.slack.com"):
		payload, err = buildSlackPayload(title, body)
	case strings.Contains(webhookURL, "discord.com/api/webhooks"):
		payload, err = buildDiscordPayload(title, body)
	default:
		payload, err = buildCustomPayload(title, body)
	}
	if err != nil {
		return fmt.Errorf("notify: marshal payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(payload)) //nolint:noctx
	if err != nil {
		return fmt.Errorf("notify: POST webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// slackPayload is the JSON body sent to a Slack incoming webhook.
type slackPayload struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Title  string `json:"title"`
	Text   string `json:"text"`
	Color  string `json:"color"`
	Footer string `json:"footer,omitempty"`
}

func buildSlackPayload(title, body string) ([]byte, error) {
	p := slackPayload{
		Attachments: []slackAttachment{
			{
				Title:  title,
				Text:   body,
				Color:  "#36a64f",
				Footer: "cloop",
			},
		},
	}
	return json.Marshal(p)
}

// discordPayload is the JSON body sent to a Discord webhook.
type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Footer      *discordFooter `json:"footer,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func buildDiscordPayload(title, body string) ([]byte, error) {
	p := discordPayload{
		Embeds: []discordEmbed{
			{
				Title:       title,
				Description: body,
				Color:       3394611, // #33cc33 green
				Footer:      &discordFooter{Text: "cloop"},
			},
		},
	}
	return json.Marshal(p)
}

// customPayload is the JSON body for generic HTTP webhook endpoints.
type customPayload struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	Source string `json:"source"`
}

func buildCustomPayload(title, body string) ([]byte, error) {
	return json.Marshal(customPayload{Title: title, Body: body, Source: "cloop"})
}

// escapeAppleScript escapes double-quotes and backslashes for embedding in an
// AppleScript string literal.  Single-quoted form is not used because it does
// not allow escape sequences, so we escape inline instead.
func escapeAppleScript(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			out = append(out, '\\', c)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
