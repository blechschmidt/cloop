// Package notifywizard provides an interactive terminal wizard for configuring
// cloop notification channels: desktop notifications, Slack webhooks, Discord
// webhooks, and custom HTTP webhooks.
package notifywizard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/fatih/color"
)

// Channel represents a single notification channel.
type Channel struct {
	Name        string
	Configured  bool
	Reachable   bool
	Detail      string
}

// Setup runs the interactive wizard for all notification channels.
// It reads from in (usually os.Stdin) and writes to out (usually os.Stdout).
// On completion, cfg.Notify is updated and the caller should persist the config.
func Setup(cfg *config.Config, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)

	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)

	cyan.Fprintln(out, "cloop notify setup — notification channel wizard")
	dim.Fprintln(out, "Configure one or more channels. Press Enter to skip a channel.")
	fmt.Fprintln(out)

	// ── Desktop notifications ─────────────────────────────────────────────
	bold.Fprintln(out, "1/4  Desktop notifications")
	supported := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	if supported {
		tool := "notify-send"
		if runtime.GOOS == "darwin" {
			tool = "osascript"
		}
		dim.Fprintf(out, "     Platform: %s (uses %s)\n", runtime.GOOS, tool)
	} else {
		yellow.Fprintf(out, "     Platform: %s — desktop notifications not supported\n", runtime.GOOS)
	}

	current := "disabled"
	if cfg.Notify.Desktop {
		current = "enabled"
	}
	fmt.Fprintf(out, "     Currently: %s\n", current)

	enable := ask(scanner, out, "     Enable desktop notifications? [y/N]: ")
	if enable != "" {
		cfg.Notify.Desktop = strings.ToLower(enable) == "y" || strings.ToLower(enable) == "yes"
	}

	if cfg.Notify.Desktop && supported {
		fmt.Fprint(out, "     Sending test notification … ")
		notify.Send("cloop", "Desktop notifications are working!")
		green.Fprintln(out, "sent")
	} else if cfg.Notify.Desktop && !supported {
		yellow.Fprintln(out, "     Warning: desktop notifications not supported on this platform.")
		cfg.Notify.Desktop = false
	}
	fmt.Fprintln(out)

	// ── Slack webhook ─────────────────────────────────────────────────────
	bold.Fprintln(out, "2/4  Slack webhook")
	dim.Fprintln(out, "     Format: https://hooks.slack.com/services/T.../B.../...")
	if cfg.Notify.SlackWebhook != "" {
		dim.Fprintf(out, "     Currently: %s\n", maskURL(cfg.Notify.SlackWebhook))
	}

	slackURL := ask(scanner, out, "     Slack webhook URL (Enter to skip/keep): ")
	if slackURL != "" {
		cfg.Notify.SlackWebhook = strings.TrimSpace(slackURL)
	}

	if cfg.Notify.SlackWebhook != "" {
		fmt.Fprint(out, "     Testing connectivity … ")
		if err := testWebhook(cfg.Notify.SlackWebhook, "cloop", "Slack notifications are working!"); err != nil {
			red.Fprintf(out, "FAILED: %v\n", err)
			yellow.Fprintln(out, "     Webhook saved anyway; fix the URL when ready.")
		} else {
			green.Fprintln(out, "OK")
		}
	}
	fmt.Fprintln(out)

	// ── Discord webhook ───────────────────────────────────────────────────
	bold.Fprintln(out, "3/4  Discord webhook")
	dim.Fprintln(out, "     Format: https://discord.com/api/webhooks/<id>/<token>")
	if cfg.Notify.DiscordWebhook != "" {
		dim.Fprintf(out, "     Currently: %s\n", maskURL(cfg.Notify.DiscordWebhook))
	}

	discordURL := ask(scanner, out, "     Discord webhook URL (Enter to skip/keep): ")
	if discordURL != "" {
		cfg.Notify.DiscordWebhook = strings.TrimSpace(discordURL)
	}

	if cfg.Notify.DiscordWebhook != "" {
		fmt.Fprint(out, "     Testing connectivity … ")
		if err := testWebhook(cfg.Notify.DiscordWebhook, "cloop", "Discord notifications are working!"); err != nil {
			red.Fprintf(out, "FAILED: %v\n", err)
			yellow.Fprintln(out, "     Webhook saved anyway; fix the URL when ready.")
		} else {
			green.Fprintln(out, "OK")
		}
	}
	fmt.Fprintln(out)

	// ── Custom HTTP webhook ───────────────────────────────────────────────
	bold.Fprintln(out, "4/4  Custom HTTP webhook")
	dim.Fprintln(out, `     cloop POSTs JSON: {"title":"...","body":"...","source":"cloop"}`)
	if cfg.Notify.CustomWebhook != "" {
		dim.Fprintf(out, "     Currently: %s\n", maskURL(cfg.Notify.CustomWebhook))
	}

	customURL := ask(scanner, out, "     Custom webhook URL (Enter to skip/keep): ")
	if customURL != "" {
		cfg.Notify.CustomWebhook = strings.TrimSpace(customURL)
	}

	if cfg.Notify.CustomWebhook != "" {
		fmt.Fprint(out, "     Testing connectivity … ")
		if err := testWebhook(cfg.Notify.CustomWebhook, "cloop", "Custom webhook notifications are working!"); err != nil {
			red.Fprintf(out, "FAILED: %v\n", err)
			yellow.Fprintln(out, "     Webhook saved anyway; fix the URL when ready.")
		} else {
			green.Fprintln(out, "OK")
		}
	}
	fmt.Fprintln(out)

	// ── Summary ───────────────────────────────────────────────────────────
	green.Fprintln(out, "Configuration updated.")
	printChannelSummary(cfg, out)
	return nil
}

// Test sends a test ping to the given channel (or all channels if channel == "").
func Test(cfg *config.Config, channel string, out io.Writer) error {
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	tested := false
	title := "cloop test ping"
	body := "This is a test notification from cloop — " + time.Now().Format("2006-01-02 15:04:05")

	ping := func(name, url string) {
		tested = true
		fmt.Fprintf(out, "  %-20s ", name)
		if url == "" {
			dim.Fprintln(out, "not configured")
			return
		}
		if err := testWebhook(url, title, body); err != nil {
			red.Fprintf(out, "FAILED: %v\n", err)
		} else {
			green.Fprintln(out, "OK")
		}
	}

	pingDesktop := func() {
		tested = true
		fmt.Fprintf(out, "  %-20s ", "desktop")
		if !cfg.Notify.Desktop {
			dim.Fprintln(out, "not configured")
			return
		}
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
			yellow.Fprintln(out, "not supported on this platform")
			return
		}
		notify.Send(title, body)
		green.Fprintln(out, "sent")
	}

	switch strings.ToLower(channel) {
	case "", "all":
		pingDesktop()
		ping("slack", cfg.Notify.SlackWebhook)
		ping("discord", cfg.Notify.DiscordWebhook)
		ping("custom", cfg.Notify.CustomWebhook)
	case "desktop":
		pingDesktop()
	case "slack":
		ping("slack", cfg.Notify.SlackWebhook)
	case "discord":
		ping("discord", cfg.Notify.DiscordWebhook)
	case "custom":
		ping("custom", cfg.Notify.CustomWebhook)
	default:
		return fmt.Errorf("unknown channel %q; valid: desktop, slack, discord, custom", channel)
	}

	if !tested {
		fmt.Fprintln(out, "No channels tested.")
	}
	return nil
}

// Status prints which channels are configured and their last reachability state.
func Status(cfg *config.Config, out io.Writer) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	dim := color.New(color.Faint)

	cyan.Fprintln(out, "cloop notify — channel status")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %-20s  %-12s  %s\n", "CHANNEL", "STATUS", "DETAIL")
	dim.Fprintf(out, "  %s\n", strings.Repeat("─", 60))

	printRow := func(name, url, detail string, enabled bool) {
		if !enabled {
			dim.Fprintf(out, "  %-20s  %-12s  %s\n", name, "disabled", "")
			return
		}
		if url == "" && name != "desktop" {
			dim.Fprintf(out, "  %-20s  %-12s  %s\n", name, "not set", "")
			return
		}
		fmt.Fprintf(out, "  %-20s  ", name)
		green.Printf("%-12s", "configured")
		fmt.Fprintf(out, "  %s\n", detail)
	}

	desktopEnabled := cfg.Notify.Desktop
	desktopDetail := ""
	if desktopEnabled {
		switch runtime.GOOS {
		case "linux":
			desktopDetail = "notify-send"
		case "darwin":
			desktopDetail = "osascript"
		default:
			desktopDetail = "unsupported platform"
		}
	}
	printRow("desktop", "", desktopDetail, desktopEnabled)
	printRow("slack", cfg.Notify.SlackWebhook, maskURL(cfg.Notify.SlackWebhook), cfg.Notify.SlackWebhook != "")
	printRow("discord", cfg.Notify.DiscordWebhook, maskURL(cfg.Notify.DiscordWebhook), cfg.Notify.DiscordWebhook != "")
	printRow("custom", cfg.Notify.CustomWebhook, maskURL(cfg.Notify.CustomWebhook), cfg.Notify.CustomWebhook != "")

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Run 'cloop notify test' to verify connectivity.")
}

// ── helpers ──────────────────────────────────────────────────────────────────

func ask(scanner *bufio.Scanner, out io.Writer, prompt string) string {
	fmt.Fprint(out, prompt)
	if !scanner.Scan() {
		return ""
	}
	return strings.TrimSpace(scanner.Text())
}

// testWebhook sends a test message using notify.SendWebhook for webhook URLs.
func testWebhook(url, title, body string) error {
	return notify.SendWebhook(url, title, body)
}

// maskURL replaces the path portion of a URL with asterisks for safe display.
func maskURL(u string) string {
	if u == "" {
		return ""
	}
	// Find the third slash (after scheme://) and mask everything after
	idx := strings.Index(u, "://")
	if idx < 0 {
		return strings.Repeat("*", len(u))
	}
	prefix := u[:idx+3]
	rest := u[idx+3:]
	// Show the host, mask the path
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return prefix + rest
	}
	host := rest[:slashIdx]
	path := rest[slashIdx:]
	visible := 6
	if len(path) <= visible {
		return prefix + host + strings.Repeat("*", len(path))
	}
	return prefix + host + path[:visible] + strings.Repeat("*", len(path)-visible)
}

// printChannelSummary prints a compact table of configured channels.
func printChannelSummary(cfg *config.Config, out io.Writer) {
	fmt.Fprintln(out)
	Status(cfg, out)
	_ = os.Stdout // suppress unused import
}
