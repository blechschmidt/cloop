package kubernetes

// attach.go satisfies executor.Attacher for the Kubernetes driver: an
// operator's shell inside a running Pod (Task 20265).
//
// # Why WebSocket and not SPDY
//
// kubectl reaches pods/exec over SPDY/3.1, an upgrade protocol that exists
// essentially nowhere outside Kubernetes and has no implementation in the
// standard library. The apiserver has spoken a WebSocket variant of the same
// endpoint since 1.6, and the rest of this driver is a hand-rolled REST client
// precisely so that cloop does not carry client-go; adding a SPDY stack to
// avoid adding client-go would trade one large dependency for a stranger one.
// nhooyr.io/websocket is already here for the hub and the agent transport.
//
// # The channel framing
//
// The v4.channel.k8s.io subprotocol multiplexes five streams onto one socket by
// prefixing every binary message with a single channel byte:
//
//	0  stdin   (we write)
//	1  stdout  (we read)
//	2  stderr  (we read; unused when tty=true, which merges it into stdout)
//	3  error   (we read; a terminal v1.Status telling us how the command exited)
//	4  resize  (we write; a JSON {"Width":N,"Height":N})
//
// Channel 4 is what v4 added over v3 and the reason this driver asks for v4:
// without it a terminal cannot report a window size, and every full-screen
// program in the sandbox draws at 80x24 regardless of the operator's window.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// execSubprotocol is the channel-multiplexed exec protocol we negotiate.
const execSubprotocol = "v4.channel.k8s.io"

// Channel bytes, per the subprotocol above.
const (
	chStdin  byte = 0
	chStdout byte = 1
	chStderr byte = 2
	chError  byte = 3
	chResize byte = 4
)

// maxExecFrame bounds a single inbound message. The apiserver chunks output, so
// a frame far larger than this is a malformed or hostile peer rather than a
// chatty workload.
const maxExecFrame = 1 << 20

// Attach implements executor.Attacher.
func (e *Executor) Attach(ctx context.Context, req executor.AttachRequest) (executor.AttachConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, err := e.lookup(req.HandleID)
	if err != nil {
		return nil, err
	}
	// An adopted record leases its kubeconfig on its own goroutine; without
	// waiting, a session opened moments after a hub restart finds a nil client.
	if err := rec.awaitClient(ctx); err != nil {
		return nil, err
	}

	rec.mu.Lock()
	running := rec.state == executor.StateRunning || rec.state == executor.StatePending
	namespace, podName := rec.namespace, rec.podName
	cli := rec.cli
	rec.mu.Unlock()

	if !running {
		return nil, fmt.Errorf("%w: pod %s/%s is not running", executor.ErrAttachClosed, namespace, podName)
	}
	if cli == nil {
		return nil, fmt.Errorf("kubernetes: attach: no API client for handle %s", req.HandleID)
	}

	conn, err := cli.dialExec(ctx, namespace, podName, req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: attach to %s/%s: %w", namespace, podName, err)
	}

	// The same set the log bus scrubs with — see the container driver for why
	// the bus rather than the Spec.
	return newExecConn(conn, req, rec.bus.Redactor()), nil
}

// execURL builds the pods/exec endpoint for req, as a ws:// or wss:// URL.
func (c *client) execURL(namespace, podName string, req executor.AttachRequest) (string, error) {
	base, err := url.Parse(c.rest.Server)
	if err != nil {
		return "", fmt.Errorf("kubernetes: parse API server URL %q: %w", c.rest.Server, err)
	}
	switch base.Scheme {
	case "https":
		base.Scheme = "wss"
	case "http":
		base.Scheme = "ws"
	default:
		return "", fmt.Errorf("kubernetes: API server URL %q has no http(s) scheme", c.rest.Server)
	}
	base.Path = fmt.Sprintf("%s/namespaces/%s/pods/%s/exec", apiPrefix, namespace, podName)

	q := url.Values{}
	q.Set("container", ContainerName)
	q.Set("stdout", "true")
	// stderr is not a valid request alongside tty: the apiserver rejects the
	// combination, because a terminal has already merged the two.
	if req.TTY {
		q.Set("tty", "true")
	} else {
		q.Set("stderr", "true")
	}
	if req.Stdin {
		q.Set("stdin", "true")
	}
	for _, a := range req.Argv() {
		q.Add("command", a)
	}
	base.RawQuery = q.Encode()
	return base.String(), nil
}

// dialExec opens the exec WebSocket. It reuses the client's configured
// transport, so the same TLS material, proxy and timeouts that authenticate
// every other call authenticate this one — there is no second credential path.
func (c *client) dialExec(ctx context.Context, namespace, podName string, req executor.AttachRequest) (*websocket.Conn, error) {
	endpoint, err := c.execURL(namespace, podName, req)
	if err != nil {
		return nil, err
	}
	hdr := http.Header{}
	hdr.Set("User-Agent", c.userAgent)
	if c.rest.BearerToken != "" {
		hdr.Set("Authorization", "Bearer "+c.rest.BearerToken)
	}

	conn, resp, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient:   c.stream,
		HTTPHeader:   hdr,
		Subprotocols: []string{execSubprotocol},
	})
	if err != nil {
		// A 403 here is the common and confusing case: the caller's kubeconfig
		// can create Pods but was never granted the pods/exec subresource, and
		// the bare dial error says only "expected 101".
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusForbidden:
				return nil, fmt.Errorf("%w: the kubeconfig for this project may not exec into pods "+
					"(needs the pods/exec subresource on %s)", err, namespace)
			case http.StatusNotFound:
				return nil, fmt.Errorf("%w: pod %s/%s not found", err, namespace, podName)
			}
		}
		return nil, err
	}
	if sub := conn.Subprotocol(); sub != execSubprotocol {
		_ = conn.Close(websocket.StatusProtocolError, "unsupported exec subprotocol")
		return nil, fmt.Errorf("kubernetes: apiserver negotiated %q, want %q "+
			"(the cluster may be too old for resize support)", sub, execSubprotocol)
	}
	return conn, nil
}

// execConn adapts the channel-multiplexed socket to executor.AttachConn.
type execConn struct {
	ws       *websocket.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	writable bool
	// tty records whether the apiserver allocated a terminal, which is what
	// decides whether channel 4 exists. It is deliberately not derived from
	// `writable`: a read-only session can hold a pty and still needs to report
	// its window size.
	tty bool

	out io.Reader // demultiplexed stdout+stderr, already redacted

	writeMu   sync.Mutex
	closeOnce sync.Once
}

// newExecConn starts the demultiplexer and returns the caller's view.
func newExecConn(ws *websocket.Conn, req executor.AttachRequest, redactor *redact.Set) executor.AttachConn {
	// Detached from the request context for the same reason the container
	// driver detaches: an HTTP handler returning must not end the session.
	ctx, cancel := context.WithCancel(context.Background())
	c := &execConn{ws: ws, ctx: ctx, cancel: cancel, writable: req.Stdin, tty: req.TTY}

	pr, pw := io.Pipe()
	go c.demux(pw)
	c.out = executor.RedactAttachOutput(pr, redactor)
	return c
}

// demux reads frames and routes them by channel byte.
func (c *execConn) demux(pw *io.PipeWriter) {
	defer func() { _ = pw.Close() }()
	c.ws.SetReadLimit(maxExecFrame)
	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			_ = pw.CloseWithError(translateExecClose(err))
			return
		}
		if typ != websocket.MessageBinary || len(data) == 0 {
			continue
		}
		ch, payload := data[0], data[1:]
		switch ch {
		case chStdout, chStderr:
			if len(payload) == 0 {
				continue
			}
			if _, err := pw.Write(payload); err != nil {
				return
			}
		case chError:
			// A terminal status. Surfacing it as the stream's error is what
			// lets the operator see "command terminated with exit code 1"
			// rather than an unexplained EOF.
			if msg := execStatusMessage(payload); msg != "" {
				_, _ = pw.Write([]byte("\r\n[" + msg + "]\r\n"))
			}
			_ = pw.CloseWithError(io.EOF)
			return
		}
	}
}

// execStatusMessage renders the apiserver's terminal v1.Status for a human.
// An empty string means "succeeded", which needs no annotation.
func execStatusMessage(payload []byte) string {
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		s := strings.TrimSpace(string(payload))
		if s == "" {
			return ""
		}
		return s
	}
	if strings.EqualFold(st.Status, "Success") {
		return ""
	}
	if st.Message != "" {
		return st.Message
	}
	return st.Reason
}

// translateExecClose turns a normal WebSocket close into io.EOF, so a session
// that simply ended does not look like a transport failure to the operator.
func translateExecClose(err error) error {
	if err == nil {
		return nil
	}
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case websocket.StatusNormalClosure, websocket.StatusGoingAway, websocket.StatusNoStatusRcvd:
			return io.EOF
		}
	}
	if errors.Is(err, context.Canceled) {
		return io.EOF
	}
	return err
}

func (c *execConn) Read(p []byte) (int, error) { return c.out.Read(p) }

func (c *execConn) Write(p []byte) (int, error) {
	if !c.writable {
		return 0, executor.ErrAttachReadOnly
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.sendFrame(chStdin, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *execConn) Resize(rows, cols uint16) error {
	// No TTY means the apiserver never opened channel 4; sending on it would
	// be a protocol error rather than a no-op, so drop it here.
	//
	// Keyed on the terminal and not on write authority. The resize stream is
	// allocated by tty=true alone, and a read-only session — the default, and
	// the one most operators open — still has a window whose size the shell
	// needs.
	if !c.tty || rows == 0 || cols == 0 {
		return nil
	}
	// Width/Height, capitalised: the apiserver decodes into a Go struct with
	// exported fields and no JSON tags, so lowercase keys are silently ignored
	// and the terminal keeps its default size.
	body, err := json.Marshal(struct {
		Width  uint16 `json:"Width"`
		Height uint16 `json:"Height"`
	}{Width: cols, Height: rows})
	if err != nil {
		return err
	}
	return c.sendFrame(chResize, body)
}

// sendFrame writes one channel-prefixed binary message. The mutex is required:
// stdin and resize are written from different goroutines (the reader pump and
// the window-size watcher) and a WebSocket connection permits one writer.
func (c *execConn) sendFrame(ch byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	frame := make([]byte, 0, len(payload)+1)
	frame = append(frame, ch)
	frame = append(frame, payload...)
	return c.ws.Write(c.ctx, websocket.MessageBinary, frame)
}

func (c *execConn) Close() error {
	c.closeOnce.Do(func() {
		// Normal closure, not CloseNow: the apiserver tears the exec'd process
		// down when the socket closes, and a clean close is what tells it the
		// operator meant to leave rather than that the network broke.
		_ = c.ws.Close(websocket.StatusNormalClosure, "attach session closed")
		c.cancel()
	})
	return nil
}
