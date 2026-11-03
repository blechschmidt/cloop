package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

const testToken = "cloop_know1_0123456789abcdef01234567.c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA"

// TestKnowledgeToolsSearchThroughTheRunSession: in a run with a knowledge
// session, `cloop mcp --knowledge` offers knowledge_search and knowledge_get
// and nothing else, calls the hub with the run's token and the agent's task,
// and answers with the hub's passages fenced as untrusted material.
func TestKnowledgeToolsSearchThroughTheRunSession(t *testing.T) {
	var gotTask int
	var gotAuth string
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case knowledgerun.MountPath + knowledgerun.PathSearch:
			var req knowledgerun.SearchRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			gotTask = req.Task
			_ = json.NewEncoder(w).Encode(knowledgerun.SearchResponse{Hits: []knowledgerun.Hit{{
				DocumentID: 5, Title: "Deploy runbook", URL: "https://wiki/5", Text: "Undo the deploy.", Rank: 1,
				Source: knowledgerun.SourceRef{Name: "Wiki", Kind: "confluence"},
			}}})
		case knowledgerun.MountPath + knowledgerun.PathGet:
			_ = json.NewEncoder(w).Encode(knowledgerun.GetResponse{Documents: []knowledgerun.Document{{
				ID: 5, Title: "Deploy runbook", Text: "## Rollback\nUndo the deploy.", Source: knowledgerun.SourceRef{Name: "Wiki"},
			}}})
		}
	}))
	defer hub.Close()
	client, err := knowledgerun.New(hub.URL+knowledgerun.MountPath, testToken)
	if err != nil {
		t.Fatal(err)
	}

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"knowledge_search","arguments":{"query":"deploy"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"knowledge_get","arguments":{"id":5}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_plan","arguments":{}}}`,
	}, "\n") + "\n"
	var out strings.Builder
	srv := New(t.TempDir(), nil, strings.NewReader(in), &out).WithKnowledge(client, 12, true)
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	var responses []Response
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var r Response
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, r)
	}
	if len(responses) != 4 {
		t.Fatalf("responses: %s", out.String())
	}
	tools, _ := json.Marshal(responses[0].Result)
	if !strings.Contains(string(tools), `"knowledge_search"`) || !strings.Contains(string(tools), `"knowledge_get"`) ||
		strings.Contains(string(tools), `"run_task"`) {
		t.Fatalf("tools/list = %s", tools)
	}
	search, _ := json.Marshal(responses[1].Result)
	for _, want := range []string{"untrusted", "Deploy runbook [document 5]", "Undo the deploy."} {
		if !strings.Contains(string(search), want) {
			t.Errorf("knowledge_search lacks %q: %s", want, search)
		}
	}
	if gotTask != 12 || gotAuth != "Bearer "+testToken {
		t.Errorf("the hub was asked for task %d with %q", gotTask, gotAuth)
	}
	get, _ := json.Marshal(responses[2].Result)
	if !strings.Contains(string(get), "## Rollback") {
		t.Errorf("knowledge_get = %s", get)
	}
	if responses[3].Error == nil {
		t.Errorf("a knowledge-only server ran get_plan: %+v", responses[3])
	}
}
