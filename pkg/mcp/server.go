// Package mcp implements a Model Context Protocol (MCP) server over stdio.
// It exposes cloop functionality as MCP tools so that Claude Desktop, Cursor,
// and other MCP clients can directly control and query cloop.
//
// Protocol: JSON-RPC 2.0 over newline-delimited stdio.
// Spec: https://spec.modelcontextprotocol.io
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Protocol version advertised during initialization.
const protocolVersion = "2024-11-05"

// serverInfo is returned in the initialize response.
var serverInfo = map[string]string{
	"name":    "cloop",
	"version": "1.0.0",
}

// ----------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ----------------------------------------------------------------------------

// Request is an incoming JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // nil for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is an outgoing JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// ----------------------------------------------------------------------------
// MCP-specific types
// ----------------------------------------------------------------------------

// Tool describes an MCP tool (returned by tools/list).
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// TextContent is a text content block in a tool result.
type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolResult is the result returned by tools/call.
type ToolResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

// Server is an MCP server that reads JSON-RPC requests from r and writes
// responses to w, exposing cloop functionality as MCP tools.
type Server struct {
	workDir  string
	prov     provider.Provider
	mu       sync.Mutex
	in       *bufio.Scanner
	out      *json.Encoder
	outMu    sync.Mutex
}

// New creates a new MCP Server.
// workDir is the cloop project directory (.cloop/state.json must exist).
// prov is the AI provider used for run_task; may be nil if only state tools are needed.
func New(workDir string, prov provider.Provider, r io.Reader, w io.Writer) *Server {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024) // 4 MB max line
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Server{
		workDir: workDir,
		prov:    prov,
		in:      scanner,
		out:     enc,
	}
}

// Serve reads requests from stdin until EOF or context cancellation.
func (s *Server) Serve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !s.in.Scan() {
			if err := s.in.Err(); err != nil {
				return fmt.Errorf("mcp: stdin read error: %w", err)
			}
			return nil // EOF
		}

		line := strings.TrimSpace(s.in.Text())
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendError(nil, codeParseError, "parse error: "+err.Error())
			continue
		}

		// Handle notification (no id) — fire and forget.
		if req.ID == nil {
			s.handleNotification(ctx, &req)
			continue
		}

		s.handleRequest(ctx, &req)
	}
}

// handleNotification processes JSON-RPC notifications (no response sent).
func (s *Server) handleNotification(_ context.Context, req *Request) {
	// We don't need to do anything for notifications right now.
	// "initialized" is the main notification we receive from clients.
}

// handleRequest dispatches a request and sends a response.
func (s *Server) handleRequest(ctx context.Context, req *Request) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(ctx, req)
	case "ping":
		s.sendResult(req.ID, map[string]any{})
	default:
		s.sendError(req.ID, codeMethodNotFound, "method not found: "+req.Method)
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (s *Server) handleInitialize(req *Request) {
	result := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": serverInfo,
	}
	s.sendResult(req.ID, result)
}

// handleToolsList returns the list of available MCP tools.
func (s *Server) handleToolsList(req *Request) {
	tools := []Tool{
		{
			Name:        "get_status",
			Description: "Return current cloop orchestrator state including goal, status, step counts, and provider.",
			InputSchema: jsonSchema(map[string]any{}),
		},
		{
			Name:        "get_plan",
			Description: "Return the current PM-mode task plan as JSON, including all tasks with their status, priority, and dependencies.",
			InputSchema: jsonSchema(map[string]any{}),
		},
		{
			Name:        "add_task",
			Description: "Append a new task to the current PM-mode plan.",
			InputSchema: jsonSchema(map[string]any{
				"title": propString("Task title (short, imperative)"),
				"description": propString("Detailed description of what the task should accomplish"),
				"priority": map[string]any{
					"type":        "integer",
					"description": "Task priority (1 = highest). Defaults to one less than the lowest-priority existing task.",
				},
			}, "title"),
		},
		{
			Name:        "complete_task",
			Description: "Mark a task as done and record its result.",
			InputSchema: jsonSchema(map[string]any{
				"id": map[string]any{
					"type":        "integer",
					"description": "Task ID to mark as done",
				},
				"result": propString("Optional result summary to store on the task"),
			}, "id"),
		},
		{
			Name:        "run_task",
			Description: "Execute a one-shot AI prompt using the configured provider and return the response.",
			InputSchema: jsonSchema(map[string]any{
				"prompt":       propString("The prompt to send to the AI provider"),
				"system_prompt": propString("Optional system prompt to prepend"),
			}, "prompt"),
		},
	}

	s.sendResult(req.ID, map[string]any{"tools": tools})
}

// handleToolsCall dispatches a tools/call request to the appropriate handler.
func (s *Server) handleToolsCall(ctx context.Context, req *Request) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.sendError(req.ID, codeInvalidParams, "invalid params: "+err.Error())
		return
	}

	var result ToolResult
	var toolErr error

	switch p.Name {
	case "get_status":
		result, toolErr = s.toolGetStatus()
	case "get_plan":
		result, toolErr = s.toolGetPlan()
	case "add_task":
		result, toolErr = s.toolAddTask(p.Arguments)
	case "complete_task":
		result, toolErr = s.toolCompleteTask(p.Arguments)
	case "run_task":
		result, toolErr = s.toolRunTask(ctx, p.Arguments)
	default:
		s.sendError(req.ID, codeMethodNotFound, "unknown tool: "+p.Name)
		return
	}

	if toolErr != nil {
		result = ToolResult{
			Content: []TextContent{{Type: "text", Text: toolErr.Error()}},
			IsError: true,
		}
	}

	s.sendResult(req.ID, result)
}

// ----------------------------------------------------------------------------
// Tool implementations
// ----------------------------------------------------------------------------

func (s *Server) toolGetStatus() (ToolResult, error) {
	st, err := state.Load(s.workDir)
	if err != nil {
		return ToolResult{}, fmt.Errorf("failed to load state: %w", err)
	}

	summary := map[string]any{
		"goal":         st.Goal,
		"status":       st.Status,
		"provider":     st.Provider,
		"current_step": st.CurrentStep,
		"max_steps":    st.MaxSteps,
		"pm_mode":      st.PMMode,
		"created_at":   st.CreatedAt.Format(time.RFC3339),
		"updated_at":   st.UpdatedAt.Format(time.RFC3339),
	}
	if st.Plan != nil {
		done, total := 0, len(st.Plan.Tasks)
		for _, t := range st.Plan.Tasks {
			if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
				done++
			}
		}
		summary["plan_tasks_total"] = total
		summary["plan_tasks_done"] = done
	}

	text, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return ToolResult{}, fmt.Errorf("failed to marshal status: %w", err)
	}
	return textResult(string(text)), nil
}

func (s *Server) toolGetPlan() (ToolResult, error) {
	st, err := state.Load(s.workDir)
	if err != nil {
		return ToolResult{}, fmt.Errorf("failed to load state: %w", err)
	}
	if st.Plan == nil {
		return textResult(`{"error":"no plan found — run cloop in PM mode first"}`), nil
	}
	text, err := json.MarshalIndent(st.Plan, "", "  ")
	if err != nil {
		return ToolResult{}, fmt.Errorf("failed to marshal plan: %w", err)
	}
	return textResult(string(text)), nil
}

func (s *Server) toolAddTask(raw json.RawMessage) (ToolResult, error) {
	var args struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	if strings.TrimSpace(args.Title) == "" {
		return ToolResult{}, fmt.Errorf("title is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := state.Load(s.workDir)
	if err != nil {
		return ToolResult{}, fmt.Errorf("failed to load state: %w", err)
	}
	if st.Plan == nil {
		st.Plan = pm.NewPlan(st.Goal)
		st.PMMode = true
	}

	// Determine next ID and default priority.
	maxID, maxPriority := 0, 0
	for _, t := range st.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
		if t.Priority > maxPriority {
			maxPriority = t.Priority
		}
	}
	if args.Priority <= 0 {
		args.Priority = maxPriority + 1
	}

	task := &pm.Task{
		ID:          maxID + 1,
		Title:       strings.TrimSpace(args.Title),
		Description: strings.TrimSpace(args.Description),
		Priority:    args.Priority,
		Status:      pm.TaskPending,
	}
	st.Plan.Tasks = append(st.Plan.Tasks, task)

	if err := st.Save(); err != nil {
		return ToolResult{}, fmt.Errorf("failed to save state: %w", err)
	}

	resp := map[string]any{
		"id":       task.ID,
		"title":    task.Title,
		"priority": task.Priority,
		"status":   string(task.Status),
	}
	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil
}

func (s *Server) toolCompleteTask(raw json.RawMessage) (ToolResult, error) {
	var args struct {
		ID     int    `json:"id"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	if args.ID <= 0 {
		return ToolResult{}, fmt.Errorf("id must be a positive integer")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := state.Load(s.workDir)
	if err != nil {
		return ToolResult{}, fmt.Errorf("failed to load state: %w", err)
	}
	if st.Plan == nil {
		return ToolResult{}, fmt.Errorf("no plan found")
	}

	var found *pm.Task
	for _, t := range st.Plan.Tasks {
		if t.ID == args.ID {
			found = t
			break
		}
	}
	if found == nil {
		return ToolResult{}, fmt.Errorf("task %d not found", args.ID)
	}

	now := time.Now()
	found.Status = pm.TaskDone
	found.CompletedAt = &now
	if args.Result != "" {
		found.Result = args.Result
	}

	if err := st.Save(); err != nil {
		return ToolResult{}, fmt.Errorf("failed to save state: %w", err)
	}

	resp := map[string]any{
		"id":           found.ID,
		"title":        found.Title,
		"status":       string(found.Status),
		"completed_at": now.Format(time.RFC3339),
	}
	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil
}

func (s *Server) toolRunTask(ctx context.Context, raw json.RawMessage) (ToolResult, error) {
	var args struct {
		Prompt       string `json:"prompt"`
		SystemPrompt string `json:"system_prompt"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	if strings.TrimSpace(args.Prompt) == "" {
		return ToolResult{}, fmt.Errorf("prompt is required")
	}
	if s.prov == nil {
		return ToolResult{}, fmt.Errorf("no AI provider configured")
	}

	opts := provider.Options{
		WorkDir:      s.workDir,
		SystemPrompt: args.SystemPrompt,
	}
	result, err := s.prov.Complete(ctx, args.Prompt, opts)
	if err != nil {
		return ToolResult{}, fmt.Errorf("provider error: %w", err)
	}

	resp := map[string]any{
		"output":        result.Output,
		"provider":      result.Provider,
		"model":         result.Model,
		"input_tokens":  result.InputTokens,
		"output_tokens": result.OutputTokens,
		"duration_ms":   result.Duration.Milliseconds(),
	}
	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (s *Server) sendResult(id json.RawMessage, result any) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_ = s.out.Encode(Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func (s *Server) sendError(id json.RawMessage, code int, msg string) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_ = s.out.Encode(Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg},
	})
}

func textResult(text string) ToolResult {
	return ToolResult{Content: []TextContent{{Type: "text", Text: text}}}
}

// jsonSchema builds a JSON Schema object for tool input validation.
// props is a map of property name → schema object.
// required lists mandatory property names.
func jsonSchema(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{
		"type": "object",
	}
	if len(props) > 0 {
		schema["properties"] = props
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// propString returns a simple string property schema with the given description.
func propString(description string) map[string]any {
	return map[string]any{
		"type":        "string",
		"description": description,
	}
}

// RunStdio starts the MCP server reading from os.Stdin and writing to os.Stdout.
// It blocks until stdin is closed or ctx is cancelled.
func RunStdio(ctx context.Context, workDir string, prov provider.Provider) error {
	srv := New(workDir, prov, os.Stdin, os.Stdout)
	return srv.Serve(ctx)
}
