// Package audit implements security and compliance scanning for cloop projects.
package audit

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/env"
)

// Level indicates the severity of an audit finding.
type Level int

const (
	Pass Level = iota
	Warn
	Fail
)

func (l Level) String() string {
	switch l {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	default:
		return "UNKN"
	}
}

// Finding is a single audit result.
type Finding struct {
	Name    string
	Level   Level
	Message string
	Fix     string // optional remediation hint
}

// Options configures the audit run.
type Options struct {
	// SnapshotSizeThresholdMB is the threshold in MiB above which the snapshot
	// directory triggers a warning. Defaults to 50.
	SnapshotSizeThresholdMB int64
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions() Options {
	return Options{SnapshotSizeThresholdMB: 50}
}

type addFn func(Finding)

// Audit inspects the cloop project for security and compliance issues and
// returns a slice of Findings. cfg may be nil; defaults are used in that case.
func Audit(workDir string, cfg *config.Config, opts Options) ([]Finding, error) {
	if opts.SnapshotSizeThresholdMB <= 0 {
		opts.SnapshotSizeThresholdMB = 50
	}
	if cfg == nil {
		cfg = config.Default()
	}

	var findings []Finding
	add := func(f Finding) { findings = append(findings, f) }

	checkCredentialsInGit(workDir, cfg, add)
	checkWebhookHTTP(cfg, add)
	checkUIToken(workDir, add)
	checkSecretsInArtifacts(workDir, add)
	checkHookPermissions(cfg, add)
	checkSnapshotSize(workDir, opts.SnapshotSizeThresholdMB, add)

	return findings, nil
}

// ---------------------------------------------------------------------------
// Check 1: credentials committed to git
// ---------------------------------------------------------------------------

// gitHistoryCheck names the finding. It reads "credentials" rather than "API
// keys" because the scan covers every shape in pkg/redact's registry: private
// keys, JWTs, kubeconfig keys and URL passwords as well as API keys.
const gitHistoryCheck = "Credentials in git history"

func checkCredentialsInGit(workDir string, cfg *config.Config, add addFn) {
	// Is this even a git repo?
	if _, err := exec.LookPath("git"); err != nil {
		return
	}
	cmd := exec.Command("git", "-C", workDir, "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		return // not a git repo — nothing to scan
	}

	// Every registry shape, plus the configured secrets themselves verbatim:
	// a key with no recognisable shape is still a leak if it is the key.
	scan := newLeakScan(collectConfigSecrets(cfg))

	// --all covers every branch and tag. The history is streamed rather than
	// read whole: -p over a long-lived .cloop/ can be gigabytes. --no-color,
	// --no-ext-diff and --no-textconv keep a repository's git config from
	// putting escape codes, a third-party renderer or a conversion filter
	// between the scan and the bytes that were committed.
	//
	// The rest are there because the repository decides what git shows, and
	// an agent working in the tree can write both .git/config and a committed
	// .gitattributes:
	//
	//   - log.showSignature hands every signed commit to gpg.program, a
	//     program of the repository's choosing: --no-show-signature.
	//   - A partial clone fetches a missing blob the moment -p needs it, by
	//     running the remote's upload-pack, which .git/config names:
	//     GIT_NO_LAZY_FETCH and protocol.allow=never fetch nothing, and an
	//     unreadable history is reported as one, below.
	//   - A replace ref shows git a substitute wherever it reads the original,
	//     so one ref swapping the commit that leaked for a clean copy would
	//     hide the leak: --no-replace-objects reads what was committed.
	//   - "-diff" in .gitattributes, or one NUL byte, makes a file's diff
	//     "Binary files differ": --text.
	//   - A merge commit has no diff of its own by default, so a credential
	//     added while resolving a conflict is in no commit the scan reads:
	//     --cc shows what the merge itself introduced.
	//   - A file moved and changed in one commit is a rename, which the
	//     filter would drop with whatever the move added: --no-renames turns
	//     it into a deletion and an addition, and T keeps a type change.
	gitLog := exec.Command("git", "--no-replace-objects", "-c", "protocol.allow=never",
		"-C", workDir, "log", "--all", "-p", "--cc", "--text", "--no-renames",
		"--no-color", "--no-ext-diff", "--no-textconv", "--no-show-signature",
		"--diff-filter=ACDMT", "--", ".cloop/")
	gitLog.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
	var stderr headBuffer
	gitLog.Stderr = &stderr
	stdout, err := gitLog.StdoutPipe()
	if err == nil {
		err = gitLog.Start()
	}
	if err != nil {
		add(Finding{
			Name:    gitHistoryCheck,
			Level:   Warn,
			Message: fmt.Sprintf("Could not run git log to scan .cloop/ history: %v", err),
		})
		return
	}
	readErr := scan.readFrom(stdout)
	if readErr != nil {
		// Stop git rather than leave it blocked on a pipe nobody drains.
		_ = gitLog.Process.Kill()
	}
	waitErr := gitLog.Wait()

	if scan.found() {
		// Reported even when git failed part-way: what was read was read.
		add(Finding{
			Name:  gitHistoryCheck,
			Level: Fail,
			Message: fmt.Sprintf("Possible credential(s) in .cloop/ git history: %s",
				strings.Join(scan.labels(), ", ")),
			Fix: "Rotate every credential listed first — once pushed, a secret is public whatever the " +
				"history says later — then purge it with 'git filter-repo' or BFG Repo-Cleaner",
		})
		return
	}
	switch {
	case readErr != nil:
		add(Finding{
			Name:    gitHistoryCheck,
			Level:   Warn,
			Message: fmt.Sprintf("Scan of .cloop/ git history stopped early: %v", readErr),
		})
	case waitErr != nil:
		// With --all, a repository with no commits is an empty log and exit
		// 0, so a failure here is a history git could not show whole: a
		// partial clone whose blobs it was not allowed to fetch, a corrupt
		// object. Clean is not a conclusion that can be drawn from part of it.
		add(Finding{
			Name:  gitHistoryCheck,
			Level: Warn,
			Message: fmt.Sprintf("Could not read all of .cloop/ git history (%s); what was read "+
				"holds no detected credentials", stderr.firstLine(waitErr)),
			Fix: "In a partial clone, fetch the missing objects (git fetch --refetch, or a full clone) " +
				"and run cloop audit again",
		})
	default:
		add(Finding{
			Name:    gitHistoryCheck,
			Level:   Pass,
			Message: ".cloop/ git history contains no detected credentials",
		})
	}
}

// collectConfigSecrets returns non-empty, non-trivial secret values from cfg.
func collectConfigSecrets(cfg *config.Config) []string {
	var secrets []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if len(v) >= 16 { // ignore very short/placeholder values
			secrets = append(secrets, v)
		}
	}
	add(cfg.Anthropic.APIKey)
	add(cfg.OpenAI.APIKey)
	add(cfg.GitHub.Token)
	add(cfg.Webhook.Secret)
	add(cfg.STT.GroqAPIKey)
	return secrets
}

// ---------------------------------------------------------------------------
// Check 2: Webhook URLs using HTTP instead of HTTPS
// ---------------------------------------------------------------------------

func checkWebhookHTTP(cfg *config.Config, add addFn) {
	type urlCheck struct {
		name string
		url  string
	}
	checks := []urlCheck{
		{"webhook.url", cfg.Webhook.URL},
		{"notify.slack_webhook", cfg.Notify.SlackWebhook},
		{"notify.discord_webhook", cfg.Notify.DiscordWebhook},
	}

	any := false
	for _, c := range checks {
		if c.url == "" {
			continue
		}
		any = true
		if strings.HasPrefix(strings.ToLower(c.url), "http://") {
			add(Finding{
				Name:    fmt.Sprintf("Webhook TLS (%s)", c.name),
				Level:   Fail,
				Message: fmt.Sprintf("%s uses plain HTTP — data is transmitted unencrypted: %s", c.name, c.url),
				Fix:     fmt.Sprintf("Change %s to use https:// in .cloop/config.yaml", c.name),
			})
		} else {
			add(Finding{
				Name:    fmt.Sprintf("Webhook TLS (%s)", c.name),
				Level:   Pass,
				Message: fmt.Sprintf("%s uses HTTPS", c.name),
			})
		}
	}

	if !any {
		add(Finding{
			Name:    "Webhook TLS",
			Level:   Pass,
			Message: "No webhook URLs configured",
		})
	}
}

// ---------------------------------------------------------------------------
// Check 3: Web UI running without a token
// ---------------------------------------------------------------------------

func checkUIToken(workDir string, add addFn) {
	// Check env var first.
	if os.Getenv("CLOOP_UI_TOKEN") != "" {
		add(Finding{
			Name:    "Web UI token",
			Level:   Pass,
			Message: "CLOOP_UI_TOKEN is set in environment — UI authentication is configured",
		})
		return
	}

	// Check .cloop/env.yaml for CLOOP_UI_TOKEN.
	vars, err := env.Load(workDir)
	if err == nil {
		for _, v := range vars {
			if v.Key == "CLOOP_UI_TOKEN" {
				add(Finding{
					Name:    "Web UI token",
					Level:   Pass,
					Message: "CLOOP_UI_TOKEN found in .cloop/env.yaml — UI authentication is configured",
				})
				return
			}
		}
	}

	add(Finding{
		Name:    "Web UI token",
		Level:   Warn,
		Message: "CLOOP_UI_TOKEN is not set — 'cloop ui' will start without authentication",
		Fix:     "Set CLOOP_UI_TOKEN env var or run: cloop env set CLOOP_UI_TOKEN <token> --secret",
	})
}

// ---------------------------------------------------------------------------
// Check 4: secrets exposed in task output artifacts
// ---------------------------------------------------------------------------

// secretKeyPattern matches env var names that likely hold secrets.
var secretKeyPattern = regexp.MustCompile(
	`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth|credential|passwd)`,
)

// artifactDirs are where a task's output comes to rest: the permanent task
// artifact, and the live output and verdict files beside it. Relative to the
// project root, slash-separated for messages.
var artifactDirs = []string{".cloop/tasks", ".cloop/artifacts"}

// checkSecretsInArtifacts scans task output for two different things and
// reports them separately, because they have different remedies. A value from
// .cloop/env.yaml is a credential the project handed the harness. A shape from
// the registry is a credential nobody told cloop about — the agent's own, a
// token it read off disk, one a tool printed — and exact-value redaction could
// not have caught it.
func checkSecretsInArtifacts(workDir string, add addFn) {
	envSecrets, envNote := artifactEnvSecrets(workDir)

	var files []string
	for _, dir := range artifactDirs {
		root := filepath.Join(workDir, filepath.FromSlash(dir))
		// Regular files only, at any depth: a symlink planted in an artifact
		// directory must not turn the audit into a reader of whatever it
		// points at. WalkDir follows none it finds, but it does walk a root
		// that is one, so a symlinked root is refused here.
		if info, err := os.Lstat(root); err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || !entry.Type().IsRegular() {
				return nil
			}
			if rel, rerr := filepath.Rel(workDir, path); rerr == nil {
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	if len(files) == 0 {
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Pass,
			Message: "No task artifacts (.cloop/tasks/, .cloop/artifacts/) to scan",
		})
		add(Finding{
			Name:    "Credentials in task artifacts",
			Level:   Pass,
			Message: "No task artifacts (.cloop/tasks/, .cloop/artifacts/) to scan",
		})
		return
	}

	var exposed, shaped []string
	var unreadable int
	scan := newLeakScan(envSecrets)
	for _, rel := range files {
		scan.reset()
		f, err := openArtifact(filepath.Join(workDir, filepath.FromSlash(rel)))
		if err != nil {
			unreadable++
			continue
		}
		err = scan.readFrom(f)
		f.Close()
		if err != nil {
			unreadable++
		}
		if scan.configured {
			exposed = append(exposed, rel)
		}
		if labels := scan.shapeLabels(); len(labels) > 0 {
			shaped = append(shaped, fmt.Sprintf("%s (%s)", rel, strings.Join(labels, ", ")))
		}
	}
	scanned := fmt.Sprintf("Scanned %d artifact file(s)", len(files)-unreadable)
	if unreadable > 0 {
		scanned += fmt.Sprintf(", %d unreadable", unreadable)
	}

	switch {
	case len(exposed) > 0:
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Fail,
			Message: fmt.Sprintf("Secret env var values found in %d artifact file(s): %s", len(exposed), strings.Join(exposed, ", ")),
			Fix:     "Remove or redact secrets from task artifacts in .cloop/tasks/; consider marking sensitive vars with --secret",
		})
	case envNote != "":
		add(Finding{Name: "Env secrets in task artifacts", Level: Pass, Message: envNote})
	default:
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Pass,
			Message: scanned + " — no secret values detected",
		})
	}

	if len(shaped) > 0 {
		add(Finding{
			Name:    "Credentials in task artifacts",
			Level:   Fail,
			Message: fmt.Sprintf("Credential-shaped values found in %d artifact file(s): %s", len(shaped), strings.Join(shaped, "; ")),
			Fix: "Rotate each credential, then delete the artifact or redact the value in place; " +
				"a credential that reached the agent through a grant should have been redacted at capture, so check how this one arrived",
		})
		return
	}
	add(Finding{
		Name:    "Credentials in task artifacts",
		Level:   Pass,
		Message: scanned + " — no credential shapes detected",
	})
}

// openArtifact opens a file the walk found to be regular, and refuses whatever
// it has become since — the directory is the agent's to write. O_NOFOLLOW
// fails on a symlink rather than following it out of the directory,
// O_NONBLOCK keeps a FIFO from blocking the open until a writer appears, and
// the type is checked again on the open file.
func openArtifact(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", path)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// headBuffer keeps the start of what a child process writes to stderr, enough
// to name a failure, however much it writes.
type headBuffer struct{ b []byte }

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := 4096 - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

// firstLine is the first line of what was kept, or err when nothing was.
func (h *headBuffer) firstLine(err error) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(h.b)), "\n")
	if line == "" {
		return err.Error()
	}
	return line
}

// artifactEnvSecrets returns the plaintext of every .cloop/env.yaml variable
// that is marked secret or named like one, or a note saying why there are
// none.
func artifactEnvSecrets(workDir string) ([]string, string) {
	vars, err := env.Load(workDir)
	if err != nil || len(vars) == 0 {
		return nil, "No env vars configured in .cloop/env.yaml"
	}
	var values []string
	for _, v := range vars {
		if !v.Secret && !secretKeyPattern.MatchString(v.Key) {
			continue
		}
		plain := env.DecodeValue(v)
		if len(plain) < 8 {
			continue // too short to be meaningful
		}
		values = append(values, plain)
	}
	if len(values) == 0 {
		return nil, "No secret env vars found in .cloop/env.yaml"
	}
	return values, ""
}

// ---------------------------------------------------------------------------
// Check 5: Hook scripts running as root or world-writable
// ---------------------------------------------------------------------------

func checkHookPermissions(cfg *config.Config, add addFn) {
	hooks := []struct {
		name string
		cmd  string
	}{
		{"hooks.pre_task", cfg.Hooks.PreTask},
		{"hooks.post_task", cfg.Hooks.PostTask},
		{"hooks.pre_plan", cfg.Hooks.PrePlan},
		{"hooks.post_plan", cfg.Hooks.PostPlan},
	}

	runningAsRoot := os.Getuid() == 0
	if runningAsRoot {
		add(Finding{
			Name:    "Hook execution context (root)",
			Level:   Warn,
			Message: "cloop is running as root — hook scripts will execute with root privileges",
			Fix:     "Run cloop as a non-privileged user",
		})
	}

	anyHook := false
	for _, h := range hooks {
		if h.cmd == "" {
			continue
		}
		anyHook = true
		parts := strings.Fields(h.cmd)
		if len(parts) == 0 {
			continue
		}
		script := parts[0]

		// Only stat file-path-like scripts (contain a slash).
		if !strings.Contains(script, "/") {
			continue
		}

		info, err := os.Stat(script)
		if err != nil {
			// Script not found — this is already caught by doctor; skip here.
			continue
		}

		mode := info.Mode()
		worldWritable := mode&0o002 != 0

		if worldWritable {
			add(Finding{
				Name:    fmt.Sprintf("Hook script permissions (%s)", h.name),
				Level:   Fail,
				Message: fmt.Sprintf("Hook script %q is world-writable (%s) — anyone can modify it", script, mode),
				Fix:     fmt.Sprintf("Run: chmod o-w %s", script),
			})
		} else {
			add(Finding{
				Name:    fmt.Sprintf("Hook script permissions (%s)", h.name),
				Level:   Pass,
				Message: fmt.Sprintf("Hook script %q permissions look safe (%s)", script, mode),
			})
		}
	}

	if !anyHook && !runningAsRoot {
		add(Finding{
			Name:    "Hook script permissions",
			Level:   Pass,
			Message: "No hook scripts configured",
		})
	}
}

// ---------------------------------------------------------------------------
// Check 6: Snapshot directory size
// ---------------------------------------------------------------------------

func checkSnapshotSize(workDir string, thresholdMB int64, add addFn) {
	snapDir := filepath.Join(workDir, ".cloop", "plan-history")
	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		add(Finding{
			Name:    "Snapshot directory size",
			Level:   Pass,
			Message: "No plan-history/ directory found",
		})
		return
	}

	var totalBytes int64
	err := filepath.Walk(snapDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !info.IsDir() {
			totalBytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return
	}

	totalMB := totalBytes / (1024 * 1024)
	if totalMB >= thresholdMB {
		add(Finding{
			Name:    "Snapshot directory size",
			Level:   Warn,
			Message: fmt.Sprintf(".cloop/plan-history/ is %d MiB (threshold: %d MiB)", totalMB, thresholdMB),
			Fix:     "Remove old snapshots: rm -rf .cloop/plan-history/*.json, or raise the threshold with --snapshot-threshold",
		})
	} else {
		add(Finding{
			Name:    "Snapshot directory size",
			Level:   Pass,
			Message: fmt.Sprintf(".cloop/plan-history/ is %d MiB (threshold: %d MiB)", totalMB, thresholdMB),
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// CountsByLevel returns pass, warn, fail counts from a slice of findings.
func CountsByLevel(findings []Finding) (pass, warn, fail int) {
	for _, f := range findings {
		switch f.Level {
		case Pass:
			pass++
		case Warn:
			warn++
		case Fail:
			fail++
		}
	}
	return
}

// ScannerLines is a helper that iterates lines of text via a Scanner.
// (Kept for potential future use by callers.)
func ScannerLines(text string, fn func(string)) {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		fn(sc.Text())
	}
}
