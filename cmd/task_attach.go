package cmd

// task_attach.go is `cloop task attach` (Task 20265): an operator's terminal
// inside a running task's sandbox, from the command line.
//
// # Why it goes through the hub
//
// It would be shorter to shell out to `docker exec` — and it would be wrong.
// The hub is where the permission lives, where the audit event is written, and
// where the concurrency ceiling is counted; a CLI that reached the runtime
// directly would bypass all three and would only work for the one backend that
// happens to run on the same machine. Kubernetes pods and edge devices are not
// reachable from here at all. So this command is a terminal emulator with a
// WebSocket on one side, and every decision is made server-side.
//
// Note the asymmetry with `cloop task exec`, which runs a command on the HOST
// in a task's *environment*. That is a different tool for a different job and
// the two are easy to confuse, so the help text says so explicitly.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"nhooyr.io/websocket"
)

var (
	attachHubURL     string
	attachToken      string
	attachProjectIdx int
	attachWrite      bool
	attachNoTTY      bool
)

var taskAttachCmd = &cobra.Command{
	Use:   "attach <task-id> [-- command args...]",
	Short: "Open a shell inside a running task's sandbox",
	Long: `Open an interactive session inside the sandbox of a task that is running now.

This is not ` + "`cloop task exec`" + `. That command runs something on this machine
with the task's environment; this one runs it inside the container, pod, or edge
device the task is actually executing in.

Sessions are read-only unless you hold the sandbox.attach.write permission, and
every session is recorded in the hub's audit trail with your identity and the
command you asked for. Tasks running as host processes cannot be attached to:
there is no sandbox to enter.

Examples:
  cloop task attach 41                        # read-only shell in task 41's sandbox
  cloop task attach 41 -- ps aux              # run one command and exit
  cloop task attach 41 --write                # interactive session (needs the permission)
  cloop task attach 41 --hub https://hub:8888 --token "$CLOOP_API_TOKEN"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil || taskID <= 0 {
			return fmt.Errorf("task id must be a positive integer, got %q", args[0])
		}
		command := args[1:]
		if idx := cmd.ArgsLenAtDash(); idx >= 0 {
			command = args[idx:]
		}
		return runTaskAttach(cmd.Context(), taskID, command)
	},
}

// runTaskAttach opens the session and relays until either end hangs up.
func runTaskAttach(ctx context.Context, taskID int, command []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint, err := attachEndpoint(taskID, command)
	if err != nil {
		return err
	}
	hdr := http.Header{}
	if tok := attachAuthToken(); tok != "" {
		hdr.Set("Authorization", "Bearer "+tok)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, resp, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		return attachDialError(err, resp)
	}
	defer conn.CloseNow()
	// No read limit beyond the default is needed for control messages, but the
	// output frames can be a screenful of a build log at a time.
	conn.SetReadLimit(1 << 20)

	// Raw mode, so keystrokes reach the sandbox one at a time instead of a line
	// at a time, and so the remote shell's own echo is the only echo. Restored
	// on every path out, including a panic: leaving a terminal in raw mode is
	// the kind of bug that makes the user's next command invisible.
	restore, interactive := enterRawMode()
	defer restore()

	if interactive && !attachNoTTY {
		go watchWindowSize(ctx, conn)
	}
	if attachWrite && interactive {
		go relayStdin(ctx, conn, cancel)
	}
	return relayOutput(ctx, conn)
}

// attachEndpoint builds the hub WebSocket URL.
func attachEndpoint(taskID int, command []string) (string, error) {
	base := strings.TrimSpace(attachHubURL)
	if base == "" {
		base = strings.TrimSpace(os.Getenv("CLOOP_HUB_URL"))
	}
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("hub url %q: %w", base, err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http", "":
		u.Scheme = "ws"
	case "ws", "wss":
		// already a socket URL
	default:
		return "", fmt.Errorf("hub url %q must be http(s) or ws(s)", base)
	}
	u.Path = fmt.Sprintf("/api/tasks/%d/attach", taskID)

	q := url.Values{}
	if attachProjectIdx > 0 {
		q.Set("project_idx", strconv.Itoa(attachProjectIdx))
	}
	if attachNoTTY {
		q.Set("tty", "0")
	}
	for _, a := range command {
		q.Add("cmd", a)
	}
	if rows, cols, ok := terminalSize(); ok {
		q.Set("rows", strconv.Itoa(rows))
		q.Set("cols", strconv.Itoa(cols))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// attachAuthToken resolves the bearer credential.
func attachAuthToken() string {
	if t := strings.TrimSpace(attachToken); t != "" {
		return t
	}
	return strings.TrimSpace(os.Getenv("CLOOP_API_TOKEN"))
}

// attachDialError turns a failed upgrade into something actionable. The bare
// library error says only "expected handshake response status code 101", which
// is true and useless.
func attachDialError(err error, resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("connect to hub: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	msg := strings.TrimSpace(string(body))
	if decoded := decodeAttachError(body); decoded != "" {
		msg = decoded
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("hub rejected the credential: pass --token or set CLOOP_API_TOKEN")
	case http.StatusForbidden:
		return fmt.Errorf("attach refused: %s", msg)
	case http.StatusNotFound:
		return fmt.Errorf("no attachable sandbox: %s", msg)
	case http.StatusNotImplemented:
		return fmt.Errorf("this executor cannot host a session: %s", msg)
	case http.StatusTooManyRequests:
		return fmt.Errorf("too many sessions already open: %s", msg)
	}
	return fmt.Errorf("attach failed (HTTP %d): %s", resp.StatusCode, msg)
}

// decodeAttachError pulls the message out of the hub's JSON error envelope.
func decodeAttachError(body []byte) string {
	var env struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	if env.Error != "" {
		return env.Error
	}
	return env.Message
}

// relayOutput consumes server messages until the session ends.
func relayOutput(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) && ce.Code == websocket.StatusNormalClosure {
				return nil
			}
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("session ended: %w", err)
		}
		var msg struct {
			Type     string `json:"type"`
			Data     string `json:"data"`
			Message  string `json:"message"`
			Writable bool   `json:"writable"`
			Executor string `json:"executor"`
		}
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "data":
			_, _ = os.Stdout.WriteString(msg.Data)
		case "ready":
			// To stderr, so `cloop task attach 41 -- cat foo > out` captures
			// the sandbox's output and not this banner.
			fmt.Fprintf(os.Stderr, "\r\n[attached to %s — %s]\r\n", msg.Executor, msg.Message)
			if attachWrite && !msg.Writable {
				fmt.Fprintf(os.Stderr, "[--write was requested but this session is read-only: "+
					"you do not hold sandbox.attach.write]\r\n")
			}
		case "error":
			fmt.Fprintf(os.Stderr, "\r\n[%s]\r\n", msg.Message)
		case "closed":
			fmt.Fprintf(os.Stderr, "\r\n[%s]\r\n", msg.Message)
			return nil
		}
	}
}

// relayStdin forwards keystrokes.
func relayStdin(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc) {
	defer cancel()
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			blob, merr := json.Marshal(map[string]any{"type": "stdin", "data": string(buf[:n])})
			if merr != nil {
				return
			}
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			werr := conn.Write(wctx, websocket.MessageText, blob)
			wcancel()
			if werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// watchWindowSize reports terminal resizes to the sandbox.
func watchWindowSize(ctx context.Context, conn *websocket.Conn) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			rows, cols, ok := terminalSize()
			if !ok {
				continue
			}
			blob, err := json.Marshal(map[string]any{"type": "resize", "rows": rows, "cols": cols})
			if err != nil {
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = conn.Write(wctx, websocket.MessageText, blob)
			cancel()
		}
	}
}

// terminalSize reports the local window, when there is one.
func terminalSize() (rows, cols int, ok bool) {
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) {
		return 0, 0, false
	}
	w, h, err := term.GetSize(fd)
	if err != nil || w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return h, w, true
}

// enterRawMode switches the local terminal to raw and returns its restorer.
//
// Only when stdin is a terminal *and* the session can type: putting a piped
// stdin into raw mode is meaningless, and doing it for a read-only session
// would swallow the Ctrl-C the operator uses to leave.
func enterRawMode() (restore func(), interactive bool) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return func() {}, false
	}
	if !attachWrite {
		return func() {}, true
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return func() {}, true
	}
	return func() { _ = term.Restore(fd, old) }, true
}

func init() {
	taskAttachCmd.Flags().StringVar(&attachHubURL, "hub", "",
		"Hub base URL (default http://127.0.0.1:8080, or CLOOP_HUB_URL)")
	taskAttachCmd.Flags().StringVar(&attachToken, "token", "",
		"API token (also reads CLOOP_API_TOKEN)")
	taskAttachCmd.Flags().IntVar(&attachProjectIdx, "project-idx", 0,
		"Project index on a multi-project hub")
	taskAttachCmd.Flags().BoolVar(&attachWrite, "write", false,
		"Request an interactive session (needs the sandbox.attach.write permission)")
	taskAttachCmd.Flags().BoolVar(&attachNoTTY, "no-tty", false,
		"Do not ask for a pseudo-terminal (use when piping the output)")

	taskCmd.AddCommand(taskAttachCmd)
}
