package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAPIError_WrapsNon2xx: a bare "unexpected status 403" sends an operator
// hunting through the wrong layer. Every non-2xx must arrive as an APIError
// carrying the verb, the path, the reason and the server's own message.
func TestAPIError_WrapsNon2xx(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	cases := []struct {
		name      string
		fail      apiFailure
		wantCode  int
		wantHint  string
		retryable bool
		notFound  bool
	}{
		{
			name:     "forbidden names the RBAC rule",
			fail:     apiFailure{Code: 403, Reason: "Forbidden", Message: "pods is forbidden"},
			wantCode: 403,
			wantHint: "pods: create, get, list, watch, delete",
		},
		{
			name:     "unauthorized suggests re-minting",
			fail:     apiFailure{Code: 401, Reason: "Unauthorized", Message: "token expired"},
			wantCode: 401,
			wantHint: "re-mint",
		},
		{
			name:     "not found points at the namespace",
			fail:     apiFailure{Code: 404, Reason: "NotFound", Message: `namespaces "nope" not found`},
			wantCode: 404,
			wantHint: "executors.kubernetes.namespace",
			notFound: true,
		},
		{
			name:      "server errors are retryable",
			fail:      apiFailure{Code: 503, Reason: "ServiceUnavailable", Message: "apiserver is shutting down"},
			wantCode:  503,
			wantHint:  "transient",
			retryable: true,
		},
		{
			name:      "throttling is retryable",
			fail:      apiFailure{Code: 429, Reason: "TooManyRequests", Message: "please try again later"},
			wantCode:  429,
			retryable: true,
		},
		{
			name:     "conflict",
			fail:     apiFailure{Code: 409, Reason: "AlreadyExists", Message: "object already exists"},
			wantCode: 409,
			wantHint: "already exists",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api.failAlways("GET /pods", tc.fail)
			defer func() {
				api.mu.Lock()
				delete(api.failures, "GET /pods")
				api.mu.Unlock()
			}()

			_, err := cli.getPod(context.Background(), "cloop", "any")
			if err == nil {
				t.Fatal("getPod returned nil error against a failing API server")
			}
			ae, ok := asAPIError(err)
			if !ok {
				t.Fatalf("error %v is not an *APIError", err)
			}
			if ae.Code != tc.wantCode {
				t.Errorf("Code = %d, want %d", ae.Code, tc.wantCode)
			}
			if ae.Reason != tc.fail.Reason {
				t.Errorf("Reason = %q, want %q", ae.Reason, tc.fail.Reason)
			}
			if !strings.Contains(ae.Error(), tc.fail.Message) {
				t.Errorf("error %q does not carry the server's message", ae.Error())
			}
			if !strings.Contains(ae.Error(), "GET") || !strings.Contains(ae.Error(), "/pods/") {
				t.Errorf("error %q does not locate the failing call", ae.Error())
			}
			if tc.wantHint != "" && !strings.Contains(ae.Error(), tc.wantHint) {
				t.Errorf("error %q is missing the hint %q", ae.Error(), tc.wantHint)
			}
			if ae.Retryable() != tc.retryable {
				t.Errorf("Retryable() = %v, want %v", ae.Retryable(), tc.retryable)
			}
			if ae.NotFound() != tc.notFound {
				t.Errorf("NotFound() = %v, want %v", ae.NotFound(), tc.notFound)
			}
		})
	}
}

// TestAPIError_NonStatusBody: an ingress or a proxy answers with HTML, not a
// Status object. The first line of whatever replied must still reach the
// operator, or the error reads as though the API server said nothing.
func TestAPIError_NonStatusBody(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	api.failAlways("GET /pods", apiFailure{
		Code: 502,
		Raw:  "<html><head><title>502 Bad Gateway</title></head>\n<body>nginx</body></html>",
	})

	_, err = cli.getPod(context.Background(), "cloop", "any")
	ae, ok := asAPIError(err)
	if !ok {
		t.Fatalf("error %v is not an *APIError", err)
	}
	if !strings.Contains(ae.Message, "502 Bad Gateway") {
		t.Errorf("message %q lost the proxy's response", ae.Message)
	}
}

// TestDeletePod_AbsentIsSuccess: the caller asked for the Pod to be gone and
// it is gone. Returning an error would make every cleanup-after-eviction look
// like a failure.
func TestDeletePod_AbsentIsSuccess(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if err := cli.deletePod(context.Background(), "cloop", "never-existed", time.Second); err != nil {
		t.Errorf("deleting an absent Pod = %v, want nil", err)
	}
}

// TestDeletePod_SendsZeroGracePeriod: gracePeriodSeconds is a pointer
// precisely so that zero — "kill now" — is transmitted instead of omitted.
func TestDeletePod_SendsZeroGracePeriod(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	created, err := cli.createPod(context.Background(), "cloop", p)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}
	if err := cli.deletePod(context.Background(), "cloop", created.Metadata.Name, 0); err != nil {
		t.Fatalf("deletePod: %v", err)
	}
	recs := api.deleteRecords()
	if len(recs) != 1 || recs[0].Grace != 0 {
		t.Errorf("delete records = %+v, want one with grace 0", recs)
	}
}

// TestCreatePod_UsesGenerateName: the API server assigns the name, which is
// what makes two simultaneous starts of the same project safe.
func TestCreatePod_UsesGenerateName(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if p.Metadata.Name != "" {
		t.Fatalf("buildPod set metadata.name = %q; it must let the API server generate one", p.Metadata.Name)
	}
	first, err := cli.createPod(context.Background(), "cloop", p)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}
	second, err := cli.createPod(context.Background(), "cloop", p)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}
	if first.Metadata.Name == second.Metadata.Name {
		t.Errorf("two creates produced the same name %q", first.Metadata.Name)
	}
	for _, name := range []string{first.Metadata.Name, second.Metadata.Name} {
		if !strings.HasPrefix(name, p.Metadata.GenerateName) {
			t.Errorf("name %q does not start with the generateName prefix %q", name, p.Metadata.GenerateName)
		}
	}
}

// TestWatchPod_StreamsEvents covers the watch wire format end to end,
// including replay from a resourceVersion.
func TestWatchPod_StreamsEvents(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	p, _ := buildPod(baseRequest())
	created, err := cli.createPod(context.Background(), "cloop", p)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}
	name := created.Metadata.Name

	// Transition before the watch exists: a watch from resourceVersion 1 must
	// still see it, exactly as a real API server would replay it.
	api.run(name)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body, err := cli.watchPod(ctx, "cloop", name, "1")
	if err != nil {
		t.Fatalf("watchPod: %v", err)
	}
	defer body.Close()

	var ev watchEvent
	if err := json.NewDecoder(body).Decode(&ev); err != nil {
		t.Fatalf("decode first event: %v", err)
	}
	if ev.Type != "MODIFIED" {
		t.Errorf("event type = %q, want MODIFIED", ev.Type)
	}
	var observed pod
	if err := json.Unmarshal(ev.Object, &observed); err != nil {
		t.Fatalf("decode event object: %v", err)
	}
	if observed.Status.Phase != phaseRunning {
		t.Errorf("replayed phase = %q, want Running", observed.Status.Phase)
	}
}

// TestFollowLogs_StreamsIncrementally: the whole point of follow=true is that
// output arrives while the workload is still producing it, so a reader must
// see the first chunk before the second is written.
func TestFollowLogs_StreamsIncrementally(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	p, _ := buildPod(baseRequest())
	created, err := cli.createPod(context.Background(), "cloop", p)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}
	name := created.Metadata.Name
	api.run(name)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := cli.followLogs(ctx, "cloop", name, ContainerName, true)
	if err != nil {
		t.Fatalf("followLogs: %v", err)
	}
	defer body.Close()

	api.emitLog(name, "first\n")
	buf := make([]byte, 64)
	n, err := body.Read(buf)
	if err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	if got := string(buf[:n]); got != "first\n" {
		t.Errorf("first chunk = %q, want %q — output is being buffered rather than streamed", got, "first\n")
	}

	api.emitLog(name, "second\n")
	n, err = body.Read(buf)
	if err != nil {
		t.Fatalf("read second chunk: %v", err)
	}
	if got := string(buf[:n]); got != "second\n" {
		t.Errorf("second chunk = %q", got)
	}

	// Terminating the Pod closes the stream, which is how the follower knows
	// the workload is done.
	api.terminate(name, 0, "Completed")
	for {
		if _, err = body.Read(buf); err != nil {
			break
		}
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("stream ended with %v, want io.EOF", err)
	}
}

// TestFollowLogs_RejectedBeforeStart is the 400 the driver retries on.
func TestFollowLogs_RejectedBeforeStart(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	p, _ := buildPod(baseRequest())
	created, err := cli.createPod(context.Background(), "cloop", p)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}

	_, err = cli.followLogs(context.Background(), "cloop", created.Metadata.Name, ContainerName, true)
	ae, ok := asAPIError(err)
	if !ok {
		t.Fatalf("error %v is not an *APIError", err)
	}
	if ae.Code != 400 {
		t.Errorf("code = %d, want 400", ae.Code)
	}
	if !strings.Contains(ae.Message, "waiting to start") {
		t.Errorf("message %q does not explain the container is not up yet", ae.Message)
	}
}

func TestListPods_LabelSelector(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	ours := map[string]string{
		LabelManaged: "true", LabelExecutorID: "k8s", LabelTaskID: "1",
	}
	api.seedPod("ours", ours, phaseRunning, time.Minute)
	api.seedPod("theirs", map[string]string{
		LabelManaged: "true", LabelExecutorID: "other", LabelTaskID: "1",
	}, phaseRunning, time.Minute)
	api.seedPod("untagged", map[string]string{LabelManaged: "true", LabelExecutorID: "k8s"},
		phaseRunning, time.Minute)

	list, err := cli.listPods(context.Background(), "cloop", executorLabelSelector("k8s"))
	if err != nil {
		t.Fatalf("listPods: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].Metadata.Name != "ours" {
		names := make([]string, 0, len(list.Items))
		for _, p := range list.Items {
			names = append(names, p.Metadata.Name)
		}
		t.Errorf("selector matched %v, want only [ours]", names)
	}
}

func TestServerVersion(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	v, err := cli.serverVersion(context.Background())
	if err != nil {
		t.Fatalf("serverVersion: %v", err)
	}
	if v != "v1.31.0" {
		t.Errorf("version = %q", v)
	}
}

// TestClient_ContextCancellationIsNotWrapped: callers errors.Is against
// context.Canceled, so http.Client's *url.Error wrapper must be unwrapped.
func TestClient_ContextCancellation(t *testing.T) {
	api := newFakeAPI(t)
	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = cli.getPod(ctx, "cloop", "any")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("getPod with a cancelled context = %v, want context.Canceled", err)
	}
	_, err = cli.watchPod(ctx, "cloop", "any", "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("watchPod with a cancelled context = %v, want context.Canceled", err)
	}
}

// TestClient_SendsBearerTokenAndUserAgent: the token authenticates and the
// user agent is what an operator greps the API server audit log for.
func TestClient_SendsBearerTokenAndUserAgent(t *testing.T) {
	var gotAuth, gotUA, gotAccept string
	api := newFakeAPI(t)
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		writeJSON(w, 200, map[string]string{"gitVersion": "v1.31.0"})
	})

	cli, err := newClient(api.restConfig(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := cli.serverVersion(context.Background()); err != nil {
		t.Fatalf("serverVersion: %v", err)
	}
	if gotAuth != "Bearer fake-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if !strings.Contains(gotUA, "cloop-executor") {
		t.Errorf("User-Agent = %q; the API server audit log needs to identify cloop", gotUA)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
}

// TestClient_RejectsUntrustedCertificate: a driver that fell back to skipping
// verification would accept a man-in-the-middle holding the bearer token.
func TestClient_RejectsUntrustedCertificate(t *testing.T) {
	api := newFakeAPI(t)
	rc := api.restConfig()
	rc.CAData = nil // no CA: the httptest certificate is not in the system pool

	cli, err := newClient(rc, 5*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := cli.serverVersion(context.Background()); err == nil {
		t.Fatal("the client trusted a certificate signed by nobody it knows")
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("  one\ntwo\n"); got != "one" {
		t.Errorf("firstLine = %q", got)
	}
	long := strings.Repeat("x", 400)
	if got := firstLine(long); len(got) > 310 {
		t.Errorf("firstLine did not truncate: %d chars", len(got))
	}
}
