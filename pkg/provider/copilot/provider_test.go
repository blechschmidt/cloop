package copilot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// fakeCLI installs a stub `copilot` on PATH that records its arguments, one
// per line, and its stdin in the returned directory, then runs body — so these
// tests exercise the real spawn, wait and settle path without the real CLI.
func fakeCLI(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/bash\n" +
		`printf '%s\n' "$@" > "` + dir + `/args"` + "\n" +
		`cat > "` + dir + `/stdin"` + "\n" +
		body + "\n"
	if err := os.WriteFile(filepath.Join(dir, Binary), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	resetFlags(t)
	return dir
}

// resetFlags forgets every flag an earlier test's CLI refused.
func resetFlags(t *testing.T) {
	t.Helper()
	clear := func() {
		for _, f := range optionalFlags {
			unsupportedFlags.Delete(f)
		}
	}
	clear()
	t.Cleanup(clear)
}

func readArgs(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatalf("the stub CLI was not run: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

// argValue returns the value a --flag=value argument carries.
func argValue(args []string, flag string) (string, bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v, true
		}
	}
	return "", false
}

func TestNameAndDefaultModel(t *testing.T) {
	p := New()
	if p.Name() != "copilot" {
		t.Errorf("Name() = %q", p.Name())
	}
	if p.DefaultModel() != "" {
		t.Errorf("DefaultModel() = %q; with none set the CLI's own choice must apply", p.DefaultModel())
	}
}

func TestCompleteReturnsTheAgentsAnswer(t *testing.T) {
	fakeCLI(t, `printf 'Added the test.\nTASK_DONE\n\n'`)
	res, err := New().Complete(context.Background(), "add a test", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Output != "Added the test.\nTASK_DONE" {
		t.Errorf("Output = %q", res.Output)
	}
	if res.Provider != ProviderName {
		t.Errorf("Provider = %q", res.Provider)
	}
}

// The prompt travels on stdin, where no argument-length limit truncates a
// large task and no process listing shows it; a system prompt the CLI has no
// flag for leads it rather than being dropped.
func TestPromptArrivesOnStdin(t *testing.T) {
	dir := fakeCLI(t, `echo TASK_DONE`)
	prompt := strings.Repeat("context line\n", 20000) + "do the task"
	if _, err := New().Complete(context.Background(), prompt, provider.Options{SystemPrompt: "You plan."}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "stdin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "You plan.\n\n"+prompt {
		t.Errorf("stdin carried %d bytes beginning %q, want the system prompt and then the %d-byte prompt",
			len(got), string(got[:min(len(got), 40)]), len(prompt))
	}
	for _, a := range readArgs(t, dir) {
		if strings.Contains(a, "do the task") {
			t.Errorf("the prompt must not be an argument: %q", a)
		}
	}
}

func TestArgsForAWorkingCall(t *testing.T) {
	dir := fakeCLI(t, `echo TASK_DONE`)
	_, err := New().Complete(context.Background(), "x", provider.Options{Model: "gpt-5.4", Effort: "high"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	args := readArgs(t, dir)
	for _, want := range []string{"--silent", "--allow-all-tools", "--allow-all-paths", "--allow-all-urls",
		"--no-ask-user", "--model=gpt-5.4", "--reasoning-effort=high"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
	if id, ok := argValue(args, "--session-id"); !ok || uuid.Validate(id) != nil {
		t.Errorf("a new conversation must get an id the caller can resume, got %q in %q", id, args)
	}
	if _, ok := argValue(args, "--usage-output-file"); !ok {
		t.Errorf("args %q ask for no usage report", args)
	}
	if slices.Contains(args, "--available-tools=view,grep,glob") {
		t.Errorf("a working call must not be limited to reading: %q", args)
	}
}

func TestNoModelOrEffortLeavesTheCLIsChoice(t *testing.T) {
	dir := fakeCLI(t, `echo TASK_DONE`)
	if _, err := New().Complete(context.Background(), "x", provider.Options{Effort: "bogus"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	for _, a := range readArgs(t, dir) {
		if strings.HasPrefix(a, "--model") || strings.HasPrefix(a, "--reasoning-effort") {
			t.Errorf("unexpected %q: no model was set and an invalid effort must be dropped", a)
		}
	}
}

// A model name is typed into the dashboard. Passed as a separate argument, one
// beginning with "-" would be read by the CLI as a flag of its own; the CLI
// was shown to do exactly that with "--model --weird".
func TestAModelThatLooksLikeAFlagStaysAValue(t *testing.T) {
	dir := fakeCLI(t, `echo TASK_DONE`)
	if _, err := New().Complete(context.Background(), "x", provider.Options{Model: "--yolo"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	args := readArgs(t, dir)
	if !slices.Contains(args, "--model=--yolo") || slices.Contains(args, "--yolo") {
		t.Errorf("args = %q; the model must travel as --model=<value>", args)
	}
}

// The review gate's reviewer may read the work and nothing more.
func TestReadOnlyCallGetsReadingToolsOnly(t *testing.T) {
	dir := fakeCLI(t, `echo '{"verdict":"approve"}'`)
	if _, err := New().Complete(context.Background(), "review", provider.Options{ReadOnly: true}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	args := readArgs(t, dir)
	for _, want := range []string{"--available-tools=view,grep,glob", "--disable-builtin-mcps"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
	for _, refused := range []string{"--allow-all-paths", "--allow-all-urls", "--allow-all", "--yolo"} {
		if slices.Contains(args, refused) {
			t.Errorf("a read-only call must keep the CLI's path and URL checks, got %q", refused)
		}
	}
}

func TestCompleteResumesTheConversationItWasGiven(t *testing.T) {
	dir := fakeCLI(t, `echo TASK_DONE`)
	p := New()
	first, err := p.Complete(context.Background(), "start", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	issued, _ := argValue(readArgs(t, dir), "--session-id")
	if first.SessionID == "" || first.SessionID != issued {
		t.Fatalf("SessionID = %q, but the CLI was given %q", first.SessionID, issued)
	}

	second, err := p.Complete(context.Background(), "carry on", provider.Options{ResumeSession: first.SessionID})
	if err != nil {
		t.Fatalf("resumed Complete: %v", err)
	}
	args := readArgs(t, dir)
	if got, _ := argValue(args, "--resume"); got != first.SessionID {
		t.Errorf("args = %q; the call must resume %s", args, first.SessionID)
	}
	if _, ok := argValue(args, "--session-id"); ok {
		t.Errorf("a resumed call must not also start a new session: %q", args)
	}
	if second.SessionID != first.SessionID {
		t.Errorf("a resumed call reports session %q, want %q", second.SessionID, first.SessionID)
	}
}

// --resume also takes a session's name or an id prefix; a value that is not an
// id this provider issued must not pick some other conversation.
func TestResumeRefusesAnythingButAUUID(t *testing.T) {
	for _, bad := range []string{"--yolo", "0cb916d", "my feature", " "} {
		if got := resumableSession(bad); got != "" {
			t.Errorf("resumableSession(%q) = %q, want none", bad, got)
		}
	}
	id := uuid.NewString()
	if got := resumableSession(" " + id + " "); got != id {
		t.Errorf("resumableSession(%q) = %q", id, got)
	}
}

func TestUsageIsReadFromTheCLIsReport(t *testing.T) {
	fakeCLI(t, `for a in "$@"; do case "$a" in --usage-output-file=*) out="${a#--usage-output-file=}";; esac; done
cat > "$out" <<'JSON'
{"totalPremiumRequestCost": 1, "currentModel": "claude-sonnet-4.5",
 "modelMetrics": {
   "claude-sonnet-4.5": {"requests": {"count": 2}, "usage": {"inputTokens": 1200, "outputTokens": 80}},
   "gpt-5-mini": {"usage": {"inputTokens": 34, "outputTokens": 5}}}}
JSON
echo TASK_DONE`)
	res, err := New().Complete(context.Background(), "x", provider.Options{Model: "auto"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.InputTokens != 1234 || res.OutputTokens != 85 {
		t.Errorf("tokens = %d in, %d out; want the report's sums, 1234 and 85", res.InputTokens, res.OutputTokens)
	}
	if res.Model != "claude-sonnet-4.5" {
		t.Errorf("Model = %q; the model the CLI chose for \"auto\" is the one to record", res.Model)
	}
	leftovers, _ := filepath.Glob(filepath.Join(os.TempDir(), "cloop-copilot-usage-*.json"))
	for _, f := range leftovers {
		if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) < time.Minute {
			t.Errorf("the usage report %s was left behind", f)
		}
	}
}

func TestNoUsageReportIsNoCounts(t *testing.T) {
	fakeCLI(t, `echo TASK_DONE`)
	res, err := New().Complete(context.Background(), "x", provider.Options{Model: "gpt-5.4"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.InputTokens != 0 || res.OutputTokens != 0 || res.Model != "gpt-5.4" {
		t.Errorf("without a report: tokens %d/%d, model %q", res.InputTokens, res.OutputTokens, res.Model)
	}
}

func TestASignedOutCLIIsAnAuthFailure(t *testing.T) {
	fakeCLI(t, `echo "Error: No authentication information found." >&2
echo "  • Set the COPILOT_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN environment variable" >&2
exit 1`)
	_, err := New().Complete(context.Background(), "x", provider.Options{})
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("err = %v, want ErrAuthFailure", err)
	}
	for _, want := range []string{"No authentication information found", "copilot login", EnvGitHubToken} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestARefusedProviderKeyIsAnAuthFailure(t *testing.T) {
	fakeCLI(t, `echo "Authentication failed with provider at http://127.0.0.1:1/v1 (HTTP 401)." >&2; exit 1`)
	if _, err := New().Complete(context.Background(), "x", provider.Options{}); !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("err = %v, want ErrAuthFailure", err)
	}
}

func TestAnyOtherFailureSaysWhatTheCLISaid(t *testing.T) {
	fakeCLI(t, `echo "partial answer"
echo "Failed to get response from the AI model; retried 5 times. Last error: 500 upstream" >&2
exit 1`)
	_, err := New().Complete(context.Background(), "x", provider.Options{})
	if err == nil {
		t.Fatal("a CLI that exits 1 must not succeed")
	}
	if errors.Is(err, ErrAuthFailure) {
		t.Errorf("a server error is not an auth failure: %v", err)
	}
	if !strings.Contains(err.Error(), "500 upstream") || !strings.Contains(err.Error(), "exit 1") {
		t.Errorf("error %q must carry the CLI's reason and exit code", err)
	}
}

func TestSilenceWithADiagnosticIsAnError(t *testing.T) {
	fakeCLI(t, `echo "model returned nothing" >&2; exit 0`)
	_, err := New().Complete(context.Background(), "x", provider.Options{})
	if err == nil || !strings.Contains(err.Error(), "model returned nothing") {
		t.Fatalf("err = %v; an empty answer with a reason on stderr must report the reason", err)
	}
}

// A CLI older than an optional flag refuses it as unknown. The call is made
// again without it, and later calls stop sending it.
func TestAnOptionalFlagACLIRefusesIsDropped(t *testing.T) {
	dir := fakeCLI(t, `for a in "$@"; do
  if [ "$a" = "--no-ask-user" ]; then
    echo "error: unexpected argument '--no-ask-user' found" >&2; exit 2
  fi
done
echo TASK_DONE`)
	p := New()
	res, err := p.Complete(context.Background(), "x", provider.Options{})
	if err != nil || res.Output != "TASK_DONE" {
		t.Fatalf("Complete = %+v, %v; the call must succeed without the flag", res, err)
	}
	if slices.Contains(readArgs(t, dir), "--no-ask-user") {
		t.Error("the retry still sent the refused flag")
	}
	if _, err := p.Complete(context.Background(), "x", provider.Options{}); err != nil {
		t.Fatalf("second Complete: %v", err)
	}
	if slices.Contains(readArgs(t, dir), "--no-ask-user") {
		t.Error("a later call sent the flag the CLI refused")
	}
}

// Every flag in turn: an old enough CLI knows none of the optional ones.
func TestEveryOptionalFlagCanBeDropped(t *testing.T) {
	dir := fakeCLI(t, `for a in "$@"; do
  case "$a" in --no-ask-user|--session-id=*|--usage-output-file=*)
    echo "error: unexpected argument '${a%%=*}' found" >&2; exit 2;;
  esac
done
echo TASK_DONE`)
	res, err := New().Complete(context.Background(), "x", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.SessionID != "" {
		t.Errorf("SessionID = %q from a CLI that cannot take one", res.SessionID)
	}
	for _, a := range readArgs(t, dir) {
		for _, f := range optionalFlags {
			if a == f || strings.HasPrefix(a, f+"=") {
				t.Errorf("the final call still sent %q", a)
			}
		}
	}
}

// A flag that is not optional is a real failure, not a retry.
func TestARefusedRequiredFlagIsAFailure(t *testing.T) {
	fakeCLI(t, `echo "error: unexpected argument '--disable-builtin-mcps' found" >&2; exit 2`)
	_, err := New().Complete(context.Background(), "x", provider.Options{ReadOnly: true})
	if err == nil || !strings.Contains(err.Error(), "--disable-builtin-mcps") {
		t.Fatalf("err = %v; a read-only call the CLI cannot restrict must fail, naming why", err)
	}
}

func TestStreamedOutputReachesOnToken(t *testing.T) {
	fakeCLI(t, `printf 'first '; sleep 0.2; printf 'second\nTASK_DONE\n'`)
	var mu sync.Mutex
	var streamed strings.Builder
	res, err := New().Complete(context.Background(), "x", provider.Options{OnToken: func(s string) {
		mu.Lock()
		streamed.WriteString(s)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if streamed.String() != "first second\nTASK_DONE\n" {
		t.Errorf("streamed %q", streamed.String())
	}
	if res.Output != "first second\nTASK_DONE" {
		t.Errorf("Output = %q; streaming must not change the answer", res.Output)
	}
}

func TestWorkDirIsTheCLIsWorkingDirectory(t *testing.T) {
	work := t.TempDir()
	fakeCLI(t, `pwd`)
	res, err := New().Complete(context.Background(), "x", provider.Options{WorkDir: work})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	want, _ := filepath.EvalSymlinks(work)
	if got, _ := filepath.EvalSymlinks(res.Output); got != want {
		t.Errorf("the CLI ran in %q, want %q", res.Output, work)
	}
}

// The defaults the provider sets yield to the environment, and what the
// caller adds for one call wins over both.
func TestEnvironmentLayers(t *testing.T) {
	fakeCLI(t, `echo "update=$COPILOT_AUTO_UPDATE color=$NO_COLOR hold=$CLOOP_HOLD"`)
	res, err := New().Complete(context.Background(), "x", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Output != "update=false color=1 hold=" {
		t.Errorf("defaults: %q", res.Output)
	}

	t.Setenv("COPILOT_AUTO_UPDATE", "true")
	t.Setenv("CLOOP_HOLD", "inherited")
	res, err = New().Complete(context.Background(), "x", provider.Options{Env: []string{"CLOOP_HOLD=pinned"}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Output != "update=true color=1 hold=pinned" {
		t.Errorf("layers: %q; the environment outranks the defaults and the caller outranks both", res.Output)
	}
}

func TestCancellationEndsTheCLI(t *testing.T) {
	fakeCLI(t, `sleep 60`)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	_, err := New().Complete(ctx, "x", provider.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want a cancellation", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("Complete took %s after cancel", took)
	}
}

func TestATimeoutIsAnErrorNotAnAnswer(t *testing.T) {
	fakeCLI(t, `echo "half an answer"; sleep 60`)
	_, err := New().Complete(context.Background(), "x", provider.Options{Timeout: 300 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
}

// Task 20205 for this harness: the CLI's shell tool can leave a job running,
// and Complete must not return before it finishes.
func TestBackgroundWorkIsWaitedFor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process-group detection is procfs-only")
	}
	work := t.TempDir()
	marker := filepath.Join(work, "model.bin")
	fakeCLI(t, `nohup bash -c 'sleep 3; echo trained > `+marker+`' >/dev/null 2>&1 &
echo "Started the training run."
echo TASK_DONE`)
	var told bool
	res, err := New().Complete(context.Background(), "train", provider.Options{
		WorkDir:          work,
		OnBackgroundWait: func(provider.BackgroundActivity) { told = true },
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("Complete returned before the background work finished: %v", err)
	}
	if res.Background == nil || !res.Background.Drained || !told {
		t.Errorf("the wait must be reported and announced, got %+v (told %v)", res.Background, told)
	}
}

func TestFindBinaryLooksWhereInstallersPutIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	bin := filepath.Join(home, ".local", "bin", Binary)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindBinary(); got != bin {
		t.Errorf("FindBinary() = %q, want the install script's location %q", got, bin)
	}
}

func TestAMissingCLIIsNamed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	_, err := New().Complete(context.Background(), "x", provider.Options{})
	if err == nil || !strings.Contains(err.Error(), Binary) {
		t.Fatalf("err = %v; a missing CLI must be reported by name", err)
	}
}
