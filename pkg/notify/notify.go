// Package notify provides OS desktop notification support.
// It dispatches to platform-native tools (notify-send on Linux, osascript on macOS)
// and silently ignores unsupported platforms or missing tools.
package notify

import (
	"os/exec"
	"runtime"
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
