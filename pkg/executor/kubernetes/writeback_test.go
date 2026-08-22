package kubernetes

// writeback_test.go covers getting a finished task's work *out* of a Pod: the
// wrapper buildPod renders around the harness, the sentinel line the wrapper
// prints, and the refusals that keep a run from silently discarding what it
// produced.
//
// The tests that matter most are again the negative ones, and for a sharper
// reason than in workspace_test.go. A run whose workspace never arrived at
// least produces a confusing transcript; a run whose *output* was discarded
// produces a perfectly convincing one — the harness really did make those
// edits, and really did report them — and the loss is invisible until someone
// goes looking for the commit. So "the Pod reported nothing" has to become a
// stated failure rather than an absent result, and that is asserted here
// against the driver's own Status rather than against its intentions.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	wbTestBranch = "cloop/task-42-add-retry"
	// A well-formed base: Spec.Validate requires the workspace to be pinned to
	// an exact commit whenever a write-back is asked for.
	wbTestBase   = "1111111111111111111111111111111111111111"
	wbTestCommit = "2222222222222222222222222222222222222222"
)

func wbWorkspace() executor.Workspace {
	return executor.Workspace{
		Kind: executor.WorkspaceGit,
		Repo: "https://github.com/acme/widgets.git",
		Ref:  wbTestBase,
	}
}

func wbSpec() executor.WriteBack {
	return executor.WriteBack{
		Mode:    executor.WriteBackPush,
		Branch:  wbTestBranch,
		Message: "cloop(task-42): add a retry",
	}
}

// --- the Pod's shape --------------------------------------------------------

// TestBuildPod_WrapsTheHarnessForWriteBack pins the four properties the wrapper
// has to preserve. Each one silently breaking would be worse than not wrapping:
// a lost exit code makes every failed task look successful, and a real command
// hidden behind the wrapper makes `kubectl describe pod` lie.
func TestBuildPod_WrapsTheHarnessForWriteBack(t *testing.T) {
	req := baseRequest()
	req.Argv = []string{"claude", "--print", "do the thing"}
	req.Workspace = wbWorkspace()
	req.WriteBack = wbSpec()

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	c := p.Spec.Containers[0]
	argv := append([]string{c.Command[0]}, c.Args...)

	if argv[0] != "cloop" || argv[1] != "workspace" || argv[2] != "writeback" {
		t.Fatalf("harness argv starts %v, want the write-back wrapper", argv[:min(3, len(argv))])
	}

	// The real command survives, after a "--" so nothing in it can be read as
	// a flag of the wrapper.
	sep := -1
	for i, a := range argv {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("no %q separator in %v; the harness's own flags would be parsed by cobra", "--", argv)
	}
	if got := strings.Join(argv[sep+1:], " "); got != "claude --print do the thing" {
		t.Errorf("wrapped command = %q, want the original harness argv", got)
	}

	// The wrapper is told everything it needs and nothing it should infer.
	flags := map[string]string{}
	for i := 3; i < sep-1; i++ {
		if strings.HasPrefix(argv[i], "--") && i+1 < sep && !strings.HasPrefix(argv[i+1], "--") {
			flags[argv[i]] = argv[i+1]
		}
	}
	for flag, want := range map[string]string{
		"--dir":    PodWorkspace,
		"--repo":   "https://github.com/acme/widgets.git",
		"--branch": wbTestBranch,
		"--base":   wbTestBase,
	} {
		if got := flags[flag]; got != want {
			t.Errorf("%s = %q, want %q", flag, got, want)
		}
	}
	if !containsArg(argv[:sep], "--push") {
		t.Error("the wrapper was not told to push; a bundle cannot leave a Pod")
	}

	// The operator's view keeps naming the real command.
	if got := p.Metadata.Annotations[AnnotationArgv]; !strings.Contains(got, "claude") {
		t.Errorf("%s = %q, want the harness's own command", AnnotationArgv, got)
	}
	if strings.Contains(p.Metadata.Annotations[AnnotationArgv], "writeback") {
		t.Errorf("%s names the wrapper; an operator reading it would not see what was dispatched",
			AnnotationArgv)
	}
}

// TestBuildPod_NoWriteBackLeavesTheArgvAlone is the control. A feature that
// rewrote every Pod's command would be a much larger change than this one.
func TestBuildPod_NoWriteBackLeavesTheArgvAlone(t *testing.T) {
	req := baseRequest()
	req.Argv = []string{"claude", "--print", "hello"}

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	c := p.Spec.Containers[0]
	if got := append([]string{c.Command[0]}, c.Args...); strings.Join(got, " ") != "claude --print hello" {
		t.Errorf("argv = %v, want the harness command untouched", got)
	}
}

// TestBuildPod_WriteBackCredentialTravelsByReference is the same guarantee the
// provisioner has, at the other end of the run: the token authorising the push
// is never in the object, only a secretKeyRef to it.
func TestBuildPod_WriteBackCredentialTravelsByReference(t *testing.T) {
	req := baseRequest()
	req.Workspace = wbWorkspace()
	req.WriteBack = wbSpec()
	req.WorkspaceSecretName = "cloop-ws-k-abc123"

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	var ref *envVarSource
	for _, e := range p.Spec.Containers[0].Env {
		if e.Name == EnvWorkspaceToken {
			if e.Value != "" {
				t.Fatalf("%s carries a literal value in the Pod object", EnvWorkspaceToken)
			}
			ref = e.ValueFrom
		}
	}
	if ref == nil || ref.SecretKeyRef == nil {
		t.Fatal("the harness container has no credential reference, so the push cannot authenticate")
	}
	if ref.SecretKeyRef.Name != "cloop-ws-k-abc123" {
		t.Errorf("secret ref = %q, want the one the caller created", ref.SecretKeyRef.Name)
	}
}

// TestBuildPod_RefusesABundleWriteBack pins the mode gate. A bundle written
// inside a Pod goes into an emptyDir that stops existing moments later, and
// this driver's only channel out of a finished Pod is its log stream.
func TestBuildPod_RefusesABundleWriteBack(t *testing.T) {
	req := baseRequest()
	req.Workspace = wbWorkspace()
	req.WriteBack = executor.WriteBack{Mode: executor.WriteBackBundle, Branch: wbTestBranch}

	if _, err := buildPod(req); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("buildPod = %v, want ErrInvalidSpec for a bundle this driver cannot carry", err)
	}
}

// TestBuildPod_RefusesAnUnpinnedWriteBack is the rule that makes the returned
// range answerable. A branch name does not identify a commit — the remote tip
// can move between the hub dispatching and the sandbox fetching — and a base
// the hub guessed wrong is a range it does not hold the other end of.
func TestBuildPod_RefusesAnUnpinnedWriteBack(t *testing.T) {
	req := baseRequest()
	ws := wbWorkspace()
	ws.Ref = "main"
	req.Workspace = ws
	req.WriteBack = wbSpec()

	if _, err := buildPod(req); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("buildPod = %v, want ErrInvalidSpec for a workspace pinned to a branch name", err)
	}
}

func containsArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// --- the round trip through a fake cluster ----------------------------------

// wbTestSpec is a full Spec the driver will accept for a write-back run.
func wbTestSpec() executor.Spec {
	s := testSpec()
	s.Workspace = wbWorkspace()
	s.WriteBack = wbSpec()
	return s
}

// TestWriteBack_RoundTripThroughAPod is the Kubernetes half of the feature:
// the Pod runs, prints the wrapper's report, and the driver surfaces it on the
// handle's terminal status where executor.Run will find it.
func TestWriteBack_RoundTripThroughAPod(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)

	handle, err := ex.Start(context.Background(), wbTestSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	line, err := executor.MarshalWriteBackSentinel(executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: wbTestBranch,
		CommitSHA: wbTestCommit, BaseSHA: wbTestBase,
		Pushed: true, Commits: 1, FilesChanged: 3,
	})
	if err != nil {
		t.Fatalf("MarshalWriteBackSentinel: %v", err)
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.finishInitContainer(name, 0, "Completed")
	api.emitLog(name, "working...\nTASK_DONE\n")
	api.emitLog(name, line+"\n")
	api.terminate(name, 0, "Completed")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateExited {
		t.Fatalf("state = %q (%s), want exited", st.State, st.Error)
	}
	if st.WriteBack == nil {
		t.Fatal("the Pod reported a write-back and the driver surfaced none")
	}
	if st.WriteBack.Err != "" {
		t.Fatalf("write-back reported an error: %s", st.WriteBack.Err)
	}
	if st.WriteBack.CommitSHA != wbTestCommit {
		t.Errorf("CommitSHA = %q, want %q", st.WriteBack.CommitSHA, wbTestCommit)
	}
	if st.WriteBack.Branch != wbTestBranch {
		t.Errorf("Branch = %q, want %q", st.WriteBack.Branch, wbTestBranch)
	}
	if !st.WriteBack.Delivered() {
		t.Error("a pushed branch at a named commit did not count as delivered")
	}
}

// TestWriteBack_SentinelSplitAcrossLogChunks covers the shape of the real
// stream. Log bytes arrive in whatever slices the API server chose, so a
// scanner that assumed a chunk was a line would miss the one line that matters
// whenever it happened to straddle a boundary — intermittently, and only for
// large outputs.
func TestWriteBack_SentinelSplitAcrossLogChunks(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), wbTestSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	line, err := executor.MarshalWriteBackSentinel(executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: wbTestBranch,
		CommitSHA: wbTestCommit, BaseSHA: wbTestBase, Pushed: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.finishInitContainer(name, 0, "Completed")
	// Split mid-JSON, with no trailing newline on the first half.
	api.emitLog(name, "noise\n"+line[:len(line)/2])
	api.emitLog(name, line[len(line)/2:]+"\n")
	api.terminate(name, 0, "Completed")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.WriteBack == nil || st.WriteBack.CommitSHA != wbTestCommit {
		t.Fatalf("a sentinel split across chunks was not reassembled: %+v", st.WriteBack)
	}
}

// TestWriteBack_MissingReportIsAStatedFailure is the test this whole file
// exists for. A Pod that was asked for a write-back and produced none must not
// look like a task that changed nothing — those are opposite outcomes and only
// one of them means work was destroyed.
func TestWriteBack_MissingReportIsAStatedFailure(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), wbTestSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.finishInitContainer(name, 0, "Completed")
	api.emitLog(name, "working...\nTASK_DONE\n") // no sentinel
	api.terminate(name, 0, "Completed")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.WriteBack == nil {
		t.Fatal("a Pod that swallowed its work product reported no write-back at all; " +
			"the run is indistinguishable from one that changed nothing")
	}
	if st.WriteBack.Err == "" {
		t.Fatal("the missing write-back was not reported as a failure")
	}
	if st.WriteBack.Delivered() {
		t.Error("a missing write-back counted as delivered")
	}
}

// TestWriteBack_NotRequestedReportsNothing is the control for the test above:
// the synthesised failure must fire only when a write-back was actually asked
// for, or every ordinary run would carry a spurious one.
func TestWriteBack_NotRequestedReportsNothing(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)
	api.emitLog(name, "TASK_DONE\n")
	api.terminate(name, 0, "Completed")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.WriteBack != nil {
		t.Fatalf("a run that asked for no write-back reported one: %+v", st.WriteBack)
	}
}

// TestWriteBack_ForgedSentinelLosesToTheRealOne is the containment for the fact
// that the harness shares the Pod's stdout. Model-authored code can print a
// sentinel naming any commit it likes; the wrapper's line always comes after,
// and last wins.
func TestWriteBack_ForgedSentinelLosesToTheRealOne(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), wbTestSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	forged, err := executor.MarshalWriteBackSentinel(executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: "cloop/attacker-chosen",
		CommitSHA: strings.Repeat("f", 40), BaseSHA: wbTestBase, Pushed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	real, err := executor.MarshalWriteBackSentinel(executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: wbTestBranch,
		CommitSHA: wbTestCommit, BaseSHA: wbTestBase, Pushed: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.finishInitContainer(name, 0, "Completed")
	api.emitLog(name, forged+"\n") // printed by the harness, while it still can
	api.emitLog(name, real+"\n")   // printed by the wrapper, after it cannot
	api.terminate(name, 0, "Completed")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.WriteBack == nil {
		t.Fatal("no write-back recorded")
	}
	if st.WriteBack.Branch != wbTestBranch || st.WriteBack.CommitSHA != wbTestCommit {
		t.Errorf("the forged sentinel won: branch=%q commit=%q",
			st.WriteBack.Branch, st.WriteBack.CommitSHA)
	}
}

// TestWriteBack_MalformedSentinelsAreIgnored keeps a workload from using the
// scanner as a way to break the run, and keeps ordinary output that happens to
// mention the marker from being parsed as a report.
func TestWriteBack_MalformedSentinelsAreIgnored(t *testing.T) {
	for _, line := range []string{
		executor.WriteBackSentinel,
		executor.WriteBackSentinel + " not json at all",
		executor.WriteBackSentinel + " {",
		executor.WriteBackSentinel + " " + strings.Repeat("x", executor.MaxWriteBackSentinelBytes+1),
		"prefixed " + executor.WriteBackSentinel + ` {"branch":"cloop/x"}`,
	} {
		if _, ok := executor.ScanWriteBackSentinel(line); ok {
			t.Errorf("accepted a malformed sentinel: %.60q", line)
		}
	}
}

// TestWriteBack_ScannerDropsOrdinaryOutputImmediately pins the memory bound. A
// harness printing megabytes without a newline must not be buffered on the
// chance that it eventually becomes a sentinel.
func TestWriteBack_ScannerDropsOrdinaryOutputImmediately(t *testing.T) {
	var s sentinelScanner
	s.observe(strings.Repeat("compiling some very long line without any newline ", 10_000))
	if got := len(s.partial); got != 0 {
		t.Errorf("buffered %d bytes of ordinary output; a line that cannot become a sentinel "+
			"must be dropped on sight", got)
	}
	// And it still works afterwards: dropping the buffer must not wedge it.
	line, err := executor.MarshalWriteBackSentinel(executor.WriteBackResult{
		Mode: executor.WriteBackPush, Branch: wbTestBranch, CommitSHA: wbTestCommit,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.observe("\n" + line + "\n")
	if got := s.snapshot(); got == nil || got.CommitSHA != wbTestCommit {
		t.Errorf("the scanner did not recover after dropping a long line: %+v", got)
	}
}

// TestWriteBack_CapabilityIsAdvertised pins the placement contract. Without it
// the hub could route a write-back run to this driver and discover only
// afterwards that the work had nowhere to go.
func TestWriteBack_CapabilityIsAdvertised(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	if !ex.Capabilities().SupportsWriteBack {
		t.Error("the Kubernetes driver does not advertise write-back, so placement would " +
			"refuse every run that needs its work returned")
	}
}
