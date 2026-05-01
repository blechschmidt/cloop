// Package webhook provides an event-driven HTTP notification client for cloop.
// It fires JSON payloads to a configured URL on task/session lifecycle events,
// with automatic Slack incoming-webhook format detection.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// EventType classifies a lifecycle notification.
type EventType string

const (
	EventSessionStarted  EventType = "session_started"
	EventSessionComplete EventType = "session_complete"
	EventSessionFailed   EventType = "session_failed"
	EventTaskStarted     EventType = "task_started"
	EventTaskDone        EventType = "task_done"
	EventTaskFailed      EventType = "task_failed"
	EventTaskSkipped     EventType = "task_skipped"
)

// TaskInfo carries task metadata inside a Payload.
type TaskInfo struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	Duration    string `json:"duration,omitempty"`
}

// SessionInfo carries aggregate session stats inside a Payload.
type SessionInfo struct {
	TotalTasks   int    `json:"total_tasks,omitempty"`
	DoneTasks    int    `json:"done_tasks,omitempty"`
	FailedTasks  int    `json:"failed_tasks,omitempty"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`
	Duration     string `json:"duration,omitempty"`
	EstCostUSD   string `json:"est_cost_usd,omitempty"`
}

// Payload is the JSON body sent to the webhook URL.
type Payload struct {
	Event     EventType    `json:"event"`
	Timestamp time.Time    `json:"timestamp"`
	Goal      string       `json:"goal,omitempty"`
	Task      *TaskInfo    `json:"task,omitempty"`
	Session   *SessionInfo `json:"session,omitempty"`
}

// Client sends webhook notifications.
type Client struct {
	url     string
	events  map[EventType]bool // nil = all events
	headers map[string]string
	isSlack bool
}

// New creates a Client. If events is empty all events are sent.
// headers are added verbatim to every request.
func New(url string, events []string, headers map[string]string) *Client {
	c := &Client{
		url:     url,
		headers: headers,
		isSlack: strings.Contains(url, "hooks.slack.com"),
	}
	if len(events) > 0 {
		c.events = make(map[EventType]bool, len(events))
		for _, e := range events {
			c.events[EventType(e)] = true
		}
	}
	return c
}

// ShouldSend returns true when the client is configured and the event is enabled.
func (c *Client) ShouldSend(event EventType) bool {
	if c == nil || c.url == "" {
		return false
	}
	if c.events == nil {
		return true
	}
	return c.events[event]
}

// Send fires an asynchronous HTTP POST for the given event. It is non-blocking
// and never returns an error to the caller — failures are silently discarded so
// that a broken webhook never interrupts the main loop.
func (c *Client) Send(event EventType, payload Payload) {
	if !c.ShouldSend(event) {
		return
	}
	payload.Event = event
	payload.Timestamp = time.Now()
	go c.send(payload)
}

func (c *Client) send(payload Payload) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var bodyBytes []byte
	var err error

	if c.isSlack {
		msg := formatSlackMessage(payload)
		bodyBytes, err = json.Marshal(map[string]string{"text": msg})
	} else {
		bodyBytes, err = json.Marshal(payload)
	}
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cloop/1.0")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// formatSlackMessage builds a human-readable string for Slack's {text: "..."} format.
func formatSlackMessage(p Payload) string {
	switch p.Event {
	case EventSessionStarted:
		return fmt.Sprintf("🚀 *cloop* — Session started | Goal: %s", p.Goal)
	case EventSessionComplete:
		if p.Session != nil {
			cost := ""
			if p.Session.EstCostUSD != "" {
				cost = " | Est. cost: " + p.Session.EstCostUSD
			}
			return fmt.Sprintf("🎉 *cloop* — Session complete! %d/%d tasks done in %s%s | Goal: %s",
				p.Session.DoneTasks, p.Session.TotalTasks, p.Session.Duration, cost, p.Goal)
		}
		return fmt.Sprintf("🎉 *cloop* — Session complete! | Goal: %s", p.Goal)
	case EventSessionFailed:
		return fmt.Sprintf("🚨 *cloop* — Session *FAILED* | Goal: %s", p.Goal)
	case EventTaskStarted:
		if p.Task != nil {
			return fmt.Sprintf("▶ *cloop* — Starting task %d: *%s*", p.Task.ID, p.Task.Title)
		}
	case EventTaskDone:
		if p.Task != nil {
			dur := ""
			if p.Task.Duration != "" {
				dur = " (" + p.Task.Duration + ")"
			}
			return fmt.Sprintf("✅ *cloop* — Task %d done%s: *%s*", p.Task.ID, dur, p.Task.Title)
		}
	case EventTaskFailed:
		if p.Task != nil {
			return fmt.Sprintf("❌ *cloop* — Task %d *FAILED*: *%s*", p.Task.ID, p.Task.Title)
		}
	case EventTaskSkipped:
		if p.Task != nil {
			return fmt.Sprintf("⏭ *cloop* — Task %d skipped: *%s*", p.Task.ID, p.Task.Title)
		}
	}
	data, _ := json.Marshal(p)
	return fmt.Sprintf("*cloop* `%s`: %s", p.Event, string(data))
}
