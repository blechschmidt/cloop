package ciworkflow_test

// runner_test.go plays a GitHub-hosted runner executing one job.
//
// It implements the parts of the runner a workflow step can observe, and
// refuses what it does not implement rather than approximating it: a step
// with an `if:`, an unknown action, or a shell other than bash or sh fails the
// test, so a change to the published workflow that this emulation cannot run
// faithfully is noticed instead of passing on an approximation.
//
// What it does implement, as GitHub documents it:
//
//   - `run:` without `shell:` executes as `bash -e {0}`; `shell: bash` as
//     `bash --noprofile --norc -eo pipefail {0}`. The difference matters: under
//     the default, a failing command on the left of a pipe does not fail the
//     step.
//   - $GITHUB_ENV is a fresh file per step. What a step writes to it — NAME=value
//     lines or NAME<<DELIMITER blocks — is in the environment of every later
//     step, and not of the step that wrote it.
//   - `::add-mask::VALUE` on a step's output hides VALUE in every log line that
//     follows it. The command line itself is not logged.
//   - A job that declares `permissions: id-token: write` gets
//     ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN; any other
//     job gets neither.
//   - The first failing step fails the job and the remaining steps are skipped.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// workflowJob is the job-level fragment the guide publishes: permissions and
// steps, with no trigger around it.
type workflowJob struct {
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Name            string            `yaml:"name"`
	ID              string            `yaml:"id"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	Shell           string            `yaml:"shell"`
	Env             map[string]string `yaml:"env"`
	If              string            `yaml:"if"`
	With            map[string]any    `yaml:"with"`
	ContinueOnError bool              `yaml:"continue-on-error"`
}

// label is how the job log names a step.
func (s workflowStep) label() string {
	switch {
	case s.Name != "":
		return s.Name
	case s.Uses != "":
		return "Run " + s.Uses
	default:
		first, _, _ := strings.Cut(strings.TrimSpace(s.Run), "\n")
		return "Run " + first
	}
}

// parseJob decodes a workflow fragment, rejecting fields this emulation would
// otherwise silently ignore.
func parseJob(t *testing.T, text string) workflowJob {
	t.Helper()
	var job workflowJob
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&job); err != nil {
		t.Fatalf("the workflow is not a job this runner understands: %v\n%s", err, text)
	}
	if len(job.Steps) == 0 {
		t.Fatalf("the workflow has no steps:\n%s", text)
	}
	return job
}

// runner is one machine that runs jobs.
type runner struct {
	t     *testing.T
	root  string
	forge *fakeGitHub
	pki   *testPKI

	workspace string // $GITHUB_WORKSPACE
	temp      string // $RUNNER_TEMP
	home      string
	binDir    string // first on PATH: npx
	npxLog    string

	// origin is the repository actions/checkout fetches from, standing in
	// for github.com/<repository>.
	origin string
	sha    string
}

// newRunner provisions a runner for the forge's current job: a home, a
// workspace, an npx that resolves Claude Code locally, and the repository the
// job checks out. claude is the Claude Code binary, or "" for the stand-in.
func newRunner(t *testing.T, forge *fakeGitHub, pki *testPKI, claude string) *runner {
	t.Helper()
	root := t.TempDir()
	job := forge.currentJob()
	_, name, _ := strings.Cut(job.Repository, "/")
	r := &runner{
		t:         t,
		root:      root,
		forge:     forge,
		pki:       pki,
		workspace: filepath.Join(root, "work", name, name),
		temp:      filepath.Join(root, "temp"),
		home:      filepath.Join(root, "home"),
		binDir:    filepath.Join(root, "bin"),
		npxLog:    filepath.Join(root, "npx.log"),
		origin:    filepath.Join(root, "origin", name+".git"),
	}
	for _, d := range []string{r.workspace, r.temp, r.home, r.binDir, filepath.Dir(r.origin)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	r.sha = r.seedOrigin()
	job.SHA = r.sha
	forge.setJob(job)
	r.writeNPX(claude)
	return r
}

// git runs git with an identity and no user or system configuration.
func (r *runner) git(dir string, args ...string) string {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + r.home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=dana", "GIT_AUTHOR_EMAIL=dana@acme.example",
		"GIT_COMMITTER_NAME=dana", "GIT_COMMITTER_EMAIL=dana@acme.example",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// seedOrigin creates the repository the job is for, with a head commit that
// introduces the kind of bug the workflow's prompt asks the agent to find.
func (r *runner) seedOrigin() string {
	r.t.Helper()
	src := filepath.Join(r.root, "seed")
	if err := os.MkdirAll(src, 0o755); err != nil {
		r.t.Fatalf("mkdir: %v", err)
	}
	r.git(src, "init", "-q", "-b", "main")
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(src, "sum.py"), []byte(content), 0o644); err != nil {
			r.t.Fatalf("write: %v", err)
		}
	}
	write("def total(xs):\n    return sum(xs[i] for i in range(len(xs)))\n")
	r.git(src, "add", ".")
	r.git(src, "commit", "-q", "-m", "add total")
	write("def total(xs):\n    return sum(xs[i] for i in range(len(xs) - 1))\n")
	r.git(src, "commit", "-q", "-am", "tidy total")
	r.git(filepath.Dir(r.origin), "clone", "-q", "--bare", src, r.origin)
	return r.git(src, "rev-parse", "HEAD")
}

// checkout does what actions/checkout@v5 does by default: a depth-1 fetch of
// the job's commit into the workspace, on a branch named after the ref.
func (r *runner) checkout(ref string) {
	r.t.Helper()
	branch := strings.TrimPrefix(ref, "refs/heads/")
	r.git(r.workspace, "init", "-q")
	r.git(r.workspace, "remote", "add", "origin", "file://"+r.origin)
	r.git(r.workspace, "fetch", "-q", "--no-tags", "--depth=1", "origin",
		"+"+r.sha+":refs/remotes/origin/"+branch)
	r.git(r.workspace, "checkout", "-q", "--force", "-B", branch, "refs/remotes/origin/"+branch)
}

// writeNPX installs the runner's npx. GitHub's runner image has the real one,
// which would download the package; this runner has no registry, so the one
// package the workflow runs resolves to a local Claude Code — and any other
// package is an error, so a workflow that starts depending on a second one
// fails here rather than passing on a download nobody made.
func (r *runner) writeNPX(claude string) {
	r.t.Helper()
	target := shellQuote(claude)
	if claude == "" {
		target = "bash " + shellQuote(filepath.Join(repoRoot(r.t), "tests", "ciworkflow", "testdata", "stand-in-claude.sh"))
	}
	script := `#!/bin/sh
# npx on the emulated runner; see writeNPX in runner_test.go.
{ printf 'argv'; for a in "$@"; do printf '\t%s' "$a"; done; printf '\n'; } >> ` + shellQuote(r.npxLog) + `
case "$1" in -y|--yes) shift ;; esac
case "$1" in
  @anthropic-ai/claude-code|@anthropic-ai/claude-code@*) shift; exec ` + target + ` "$@" ;;
esac
echo "npx: this runner has no package registry; cannot fetch $1" >&2
exit 127
`
	if err := os.WriteFile(filepath.Join(r.binDir, "npx"), []byte(script), 0o755); err != nil {
		r.t.Fatalf("write npx: %v", err)
	}
}

// npxInvocations returns the argument vectors npx was called with.
func (r *runner) npxInvocations() [][]string {
	r.t.Helper()
	raw, err := os.ReadFile(r.npxLog)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		r.t.Fatalf("read npx log: %v", err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if rest, ok := strings.CutPrefix(line, "argv"); ok {
			out = append(out, strings.Split(strings.TrimPrefix(rest, "\t"), "\t"))
		}
	}
	return out
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// baseEnv is what GitHub puts in every step's environment for this job.
func (r *runner) baseEnv(idToken bool) map[string]string {
	job := r.forge.currentJob()
	owner := job.owner()
	env := map[string]string{
		"CI":                         "true",
		"GITHUB_ACTIONS":             "true",
		"GITHUB_ACTOR":               job.Actor,
		"GITHUB_ACTOR_ID":            job.ActorID,
		"GITHUB_API_URL":             "https://api.github.com",
		"GITHUB_EVENT_NAME":          job.EventName,
		"GITHUB_JOB":                 "review",
		"GITHUB_REF":                 job.Ref,
		"GITHUB_REF_NAME":            strings.TrimPrefix(job.Ref, "refs/heads/"),
		"GITHUB_REF_TYPE":            "branch",
		"GITHUB_REPOSITORY":          job.Repository,
		"GITHUB_REPOSITORY_ID":       job.RepoID,
		"GITHUB_REPOSITORY_OWNER":    owner,
		"GITHUB_REPOSITORY_OWNER_ID": job.OwnerID,
		"GITHUB_RUN_ATTEMPT":         job.RunAttempt,
		"GITHUB_RUN_ID":              job.RunID,
		"GITHUB_RUN_NUMBER":          job.RunNumber,
		"GITHUB_SERVER_URL":          "https://github.com",
		"GITHUB_SHA":                 job.SHA,
		"GITHUB_WORKFLOW":            job.Workflow,
		"GITHUB_WORKFLOW_REF":        job.WorkflowRef,
		"GITHUB_WORKSPACE":           r.workspace,
		"HOME":                       r.home,
		"LANG":                       "C.UTF-8",
		"PATH":                       r.path(),
		"RUNNER_ARCH":                "X64",
		"RUNNER_ENVIRONMENT":         "github-hosted",
		"RUNNER_NAME":                "GitHub Actions 1",
		"RUNNER_OS":                  "Linux",
		"RUNNER_TEMP":                r.temp,
		"TMPDIR":                     r.temp,

		// The rest is the runner *image*, not the job. A hub deployed for
		// real presents a publicly trusted certificate, which the image's
		// trust store already accepts; this one presents a certificate from
		// the test CA, which these two variables hand to curl and to Claude
		// Code respectively.
		"SSL_CERT_FILE":       r.pki.bundleFile,
		"NODE_EXTRA_CA_CERTS": r.pki.caFile,
		// And a runner under test should not phone Anthropic's telemetry or
		// update endpoints. Neither setting changes where Claude Code sends
		// model requests, which is the thing under test.
		"DISABLE_AUTOUPDATER":                      "1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
	}
	if idToken {
		env["ACTIONS_ID_TOKEN_REQUEST_URL"] = r.forge.requestURL()
		env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = r.forge.requestToken
	}
	return env
}

// path is the runner's PATH: its own npx first, then wherever this machine
// keeps the tools a step calls, then the usual system directories. It is built
// rather than inherited, so what a step can run is the runner's choice and not
// whatever the invoking shell has accumulated.
func (r *runner) path() string {
	dirs := []string{r.binDir}
	seen := map[string]bool{r.binDir: true}
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	for _, tool := range runnerTools {
		if p, err := exec.LookPath(tool); err == nil {
			add(filepath.Dir(p))
		}
	}
	for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		add(d)
	}
	return strings.Join(dirs, ":")
}

// jobResult is what a run of a job left behind.
type jobResult struct {
	Steps []stepResult

	// Log is the job log as GitHub would display it: masked, without the
	// workflow commands.
	Log string

	// Env is everything the steps exported through $GITHUB_ENV.
	Env map[string]string

	// Masks are the values registered with ::add-mask::, in order.
	Masks []string
}

type stepResult struct {
	Label    string
	Ran      bool
	ExitCode int
}

// Failed reports whether any step failed.
func (j *jobResult) Failed() bool {
	for _, s := range j.Steps {
		if s.Ran && s.ExitCode != 0 {
			return true
		}
	}
	return false
}

// step returns the result for the step labelled label.
func (j *jobResult) step(t *testing.T, label string) stepResult {
	t.Helper()
	for _, s := range j.Steps {
		if s.Label == label {
			return s
		}
	}
	t.Fatalf("the job has no step %q", label)
	return stepResult{}
}

// masked reports whether v was registered as a mask.
func (j *jobResult) masked(v string) bool {
	for _, m := range j.Masks {
		if m == v {
			return true
		}
	}
	return false
}

// run executes job and returns what it left behind. It fails the test only
// for problems with the emulation itself; a step failing is a result.
func (r *runner) run(job workflowJob) *jobResult {
	r.t.Helper()
	res := &jobResult{Env: map[string]string{}}
	var log strings.Builder

	idToken := job.Permissions["id-token"] == "write"
	base := r.baseEnv(idToken)
	// The runner registers the request token as a secret, as it does every
	// credential it hands a job.
	masks := []string{}
	if idToken {
		masks = append(masks, base["ACTIONS_ID_TOKEN_REQUEST_TOKEN"])
	}

	failed := false
	for i, step := range job.Steps {
		sr := stepResult{Label: step.label()}
		if failed {
			fmt.Fprintf(&log, "▷ %s (skipped: an earlier step failed)\n", sr.Label)
			res.Steps = append(res.Steps, sr)
			continue
		}
		if step.If != "" || step.ContinueOnError {
			r.t.Fatalf("step %q uses if/continue-on-error, which this runner does not evaluate", sr.Label)
		}
		fmt.Fprintf(&log, "▶ %s\n", sr.Label)
		sr.Ran = true
		switch {
		case step.Uses != "":
			sr.ExitCode = r.runAction(step, &log)
		case step.Run != "":
			var out []byte
			env := mergeEnv(base, job.Env, res.Env, step.Env)
			var exported map[string]string
			out, exported, sr.ExitCode = r.runScript(i, step, env)
			masks = appendOutput(&log, out, masks)
			for k, v := range exported {
				res.Env[k] = v
			}
		default:
			r.t.Fatalf("step %q has neither uses nor run", sr.Label)
		}
		if sr.ExitCode != 0 {
			fmt.Fprintf(&log, "Error: Process completed with exit code %d.\n", sr.ExitCode)
			failed = true
		}
		res.Steps = append(res.Steps, sr)
	}
	res.Masks = masks
	res.Log = log.String()
	return res
}

// runAction implements the actions the guide's workflow uses.
func (r *runner) runAction(step workflowStep, log *strings.Builder) int {
	r.t.Helper()
	name, _, _ := strings.Cut(step.Uses, "@")
	switch name {
	case "actions/checkout":
		if len(step.With) > 0 {
			r.t.Fatalf("actions/checkout with inputs %v is not emulated", step.With)
		}
		job := r.forge.currentJob()
		r.checkout(job.Ref)
		fmt.Fprintf(log, "HEAD is now at %s\n", r.sha[:7])
		return 0
	}
	r.t.Fatalf("this runner does not implement the action %s", step.Uses)
	return 1
}

// runScript executes one `run:` step the way the runner does: the script is
// written to a file and handed to the shell, with GITHUB_ENV pointing at a
// file that exists for this step only.
func (r *runner) runScript(index int, step workflowStep, env map[string]string) ([]byte, map[string]string, int) {
	r.t.Helper()
	dir := filepath.Join(r.temp, "_runner_file_commands")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatalf("mkdir: %v", err)
	}
	id := fmt.Sprintf("%d", index)
	files := map[string]string{
		"GITHUB_ENV":          filepath.Join(dir, "set_env_"+id),
		"GITHUB_PATH":         filepath.Join(dir, "add_path_"+id),
		"GITHUB_OUTPUT":       filepath.Join(dir, "set_output_"+id),
		"GITHUB_STATE":        filepath.Join(dir, "save_state_"+id),
		"GITHUB_STEP_SUMMARY": filepath.Join(dir, "step_summary_"+id),
	}
	for k, p := range files {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			r.t.Fatalf("create %s: %v", k, err)
		}
		env[k] = p
	}
	env["GITHUB_ACTION"] = fmt.Sprintf("__run_%d", index)

	script := filepath.Join(r.temp, fmt.Sprintf("step-%d.sh", index))
	if err := os.WriteFile(script, []byte(step.Run), 0o644); err != nil {
		r.t.Fatalf("write script: %v", err)
	}
	var argv []string
	switch step.Shell {
	case "":
		argv = []string{"bash", "-e", script}
	case "bash":
		argv = []string{"bash", "--noprofile", "--norc", "-eo", "pipefail", script}
	case "sh":
		argv = []string{"sh", "-e", script}
	default:
		r.t.Fatalf("step %q: shell %q is not emulated", step.label(), step.Shell)
	}

	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = r.workspace
	cmd.Env = envList(env)
	var out bytes.Buffer
	// One buffer for both streams keeps their lines in the order they were
	// written, which is what the job log shows.
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		r.t.Fatalf("step %q did not finish within %s:\n%s", step.label(), stepTimeout, out.String())
	}
	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		r.t.Fatalf("step %q: %v", step.label(), err)
	}

	exported := parseEnvFile(r.t, files["GITHUB_ENV"])
	if paths := readLines(r.t, files["GITHUB_PATH"]); len(paths) > 0 {
		r.t.Fatalf("step %q wrote GITHUB_PATH, which this runner does not apply: %v", step.label(), paths)
	}
	return out.Bytes(), exported, code
}

// parseEnvFile reads a $GITHUB_ENV file: NAME=value lines, and NAME<<DELIMITER
// blocks for values that span lines.
func parseEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	lines := readLines(t, path)
	out := map[string]string{}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		if name, delim, ok := strings.Cut(line, "<<"); ok && !strings.Contains(name, "=") {
			var val []string
			for i++; i < len(lines) && lines[i] != delim; i++ {
				val = append(val, lines[i])
			}
			if i == len(lines) {
				t.Fatalf("GITHUB_ENV: %s<<%s is never terminated", name, delim)
			}
			out[name] = strings.Join(val, "\n")
			continue
		}
		name, val, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			// GitHub fails the step on a malformed line; so does this.
			t.Fatalf("GITHUB_ENV: malformed line %q", line)
		}
		out[name] = val
	}
	return out
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(raw) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// appendOutput processes one step's output into the job log, applying masks
// and workflow commands in order, and returns the masks now registered.
func appendOutput(log *strings.Builder, out []byte, masks []string) []string {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "::add-mask::"); ok {
			if v = strings.TrimSpace(v); v != "" {
				masks = append(masks, v)
			}
			continue
		}
		if msg, ok := strings.CutPrefix(line, "::error::"); ok {
			line = "Error: " + msg
		}
		log.WriteString(applyMasks(line, masks))
		log.WriteByte('\n')
	}
	return masks
}

// applyMasks replaces every registered value, longest first so a mask that is
// a prefix of another cannot leave the longer one's tail visible.
func applyMasks(line string, masks []string) string {
	sorted := append([]string(nil), masks...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, m := range sorted {
		line = strings.ReplaceAll(line, m, "***")
	}
	return line
}

// mergeEnv layers environments, later ones winning.
func mergeEnv(layers ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, l := range layers {
		for k, v := range l {
			out[k] = v
		}
	}
	return out
}

func envList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
