package knowledgerun

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInputsFromEnv(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if c, err := InputsFromEnv(getenv); c != nil || !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a run without the variables: %v, %v; want ErrNotConfigured", c, err)
	}
	env[EnvInputsURL], env[EnvInputsToken] = "https://hub.example/api/run/knowledge", "not-a-session-token"
	if _, err := InputsFromEnv(getenv); err == nil {
		t.Fatal("a token that is no session's was taken")
	}
	env[EnvInputsToken] = testToken
	c, err := InputsFromEnv(getenv)
	if err != nil || c.Base() != "https://hub.example/api/run/knowledge" {
		t.Fatalf("InputsFromEnv = %v, %v", c, err)
	}
	// The knowledge search's variables are not the input files'.
	env = map[string]string{EnvURL: "https://hub.example/api/run/knowledge", EnvToken: testToken}
	if _, err := InputsFromEnv(getenv); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a knowledge session's variables opened input files: %v", err)
	}
}

func TestInputsClient(t *testing.T) {
	var asked []string
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testToken ||
			r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		asked = append(asked, r.URL.Path+" "+string(raw))
		switch r.URL.Path {
		case MountPath + PathInputs:
			_ = json.NewEncoder(w).Encode(InputsResponse{Task: 7, Files: []InputFile{{ID: strings.Repeat("a", 32),
				Name: "spec.md", Size: 5, MediaType: "text/markdown", Note: "read me"}}})
		case MountPath + PathInputFile:
			var req InputFileRequest
			_ = json.Unmarshal(raw, &req)
			if req.ID == "gone" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"the task has no such input file"}}`))
				return
			}
			_, _ = w.Write([]byte("hello and then some more than was listed"))
		}
	}))
	defer hub.Close()
	c, err := New(hub.URL+MountPath, testToken)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	resp, err := c.Inputs(ctx, InputsRequest{Task: 7, TitleSHA256: TitleDigest("Build it")})
	if err != nil || len(resp.Files) != 1 || resp.Files[0].Name != "spec.md" || resp.Files[0].Note != "read me" {
		t.Fatalf("Inputs = %+v, %v", resp, err)
	}
	body, err := c.OpenInputFile(ctx, InputFileRequest{Task: 7, TitleSHA256: TitleDigest("Build it"), ID: strings.Repeat("a", 32)}, 5)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body)
	_ = body.Close()
	// One byte past what was listed, so the reader can tell the hub sent
	// more than the file.
	if err != nil || string(data) != "hello " {
		t.Fatalf("read %q, %v; want the listed size and one byte more", data, err)
	}
	_, err = c.OpenInputFile(ctx, InputFileRequest{Task: 7, ID: "gone"}, 5)
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusNotFound || !strings.Contains(api.Message, "no such input file") {
		t.Fatalf("a refused file: %v", err)
	}
	if len(asked) != 3 || !strings.Contains(asked[0], `"title_sha256":"`+TitleDigest("Build it")+`"`) ||
		strings.Contains(asked[0], "Build it") || !strings.Contains(asked[1], `"task":7`) {
		t.Fatalf("the hub was asked %q", asked)
	}
	var nilClient *Client
	if _, err := nilClient.OpenInputFile(ctx, InputFileRequest{}, 1); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a nil client: %v", err)
	}
}

func TestTitleDigest(t *testing.T) {
	d := TitleDigest("  Build it\n")
	if d != TitleDigest("Build it") || len(d) != 64 || !ValidTitleDigest(d) {
		t.Fatalf("TitleDigest = %q: the space around a title is not part of it", d)
	}
	// A title of any length names its task in 64 characters.
	if long := TitleDigest(strings.Repeat("a very long title ", 1000)); len(long) != 64 || long == d {
		t.Fatalf("a long title's digest = %q", long)
	}
	for _, bad := range []string{"", "Build it", strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if ValidTitleDigest(bad) {
			t.Errorf("ValidTitleDigest(%q) = true", bad)
		}
	}
}
