package kubernetes

// projectresult_test.go covers the Kubernetes round trip of a seeded run (Task
// 20402): the hub's project going into the Pod through the lease Secret, and
// the run's outcome coming back out of the Pod's log.
//
// The assertions that matter most are again the negative ones. A seed that
// reached the Pod object would publish a project's instructions and plan to
// every identity that can `get pods`; a seed that reached the harness's own
// mounts would hand it the Secret volume the init container alone needs; and a
// frame that yielded *part* of a result would merge some of a run's outcomes
// and not others — so every malformed shape must come back unavailable, with
// no bytes, and every one is exercised against the driver rather than against
// the parser alone.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/resultframe"
)

// testSeed returns a gzip-compressed project state, as projectseed.Build would,
// padded with random-looking bytes so a test can search for it.
func testSeed(t *testing.T, padding int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"goal":    "Task 20402: run a project whose repository has no .cloop",
		"padding": strings.Repeat("x7Qz", padding/4),
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func seededRequest() podRequest {
	req := baseRequest()
	req.Workspace = executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/widgets.git", Ref: "main"}
	req.ProjectSeed = true
	req.LeaseSecretName = leaseSecretName(req.HandleID)
	return req
}

func seededSpec(t *testing.T) executor.Spec {
	s := testSpec()
	s.Workspace = executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/widgets.git", Ref: "main"}
	s.ProjectSeed = testSeed(t, 64)
	return s
}

func findContainer(cs []container, name string) *container {
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}

func mountOf(c *container, volume string) *volumeMount {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == volume {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}

// TestBuildPod_SeedReachesOnlyTheInitContainer pins where the seed may be: the
// lease Secret's one key, projected read-only into the workspace init container
// and nowhere else, with the copy the harness reads mounted read-only.
func TestBuildPod_SeedReachesOnlyTheInitContainer(t *testing.T) {
	req := seededRequest()
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}

	var seedVol, dispatchVol *volume
	for i := range p.Spec.Volumes {
		switch p.Spec.Volumes[i].Name {
		case seedVolume:
			seedVol = &p.Spec.Volumes[i]
		case dispatchVolume:
			dispatchVol = &p.Spec.Volumes[i]
		}
	}
	if seedVol == nil || seedVol.Secret == nil {
		t.Fatalf("no seed Secret volume: %+v", p.Spec.Volumes)
	}
	if seedVol.Secret.SecretName != req.LeaseSecretName {
		t.Errorf("seed volume reads Secret %q, want the lease Secret %q", seedVol.Secret.SecretName, req.LeaseSecretName)
	}
	if len(seedVol.Secret.Items) != 1 || seedVol.Secret.Items[0].Key != projectSeedKey {
		t.Errorf("seed volume projects %+v; it must project the seed key and nothing else — the lease's "+
			"credential files and environment are not the init container's", seedVol.Secret.Items)
	}
	if seedVol.Secret.Optional == nil || *seedVol.Secret.Optional {
		t.Error("the seed volume must not be optional: a missing seed must hold the Pod")
	}
	if dispatchVol == nil || dispatchVol.EmptyDir == nil || dispatchVol.EmptyDir.SizeLimit == "" {
		t.Fatalf("no bounded dispatch emptyDir: %+v", dispatchVol)
	}

	initC := findContainer(p.Spec.InitContainers, InitContainerName)
	harness := findContainer(p.Spec.Containers, ContainerName)
	if initC == nil || harness == nil {
		t.Fatal("the Pod lacks its init container or its harness")
	}
	if m := mountOf(initC, seedVolume); m == nil || !m.ReadOnly || m.MountPath != seedMountDir {
		t.Errorf("init container's seed mount = %+v, want read-only at %s", m, seedMountDir)
	}
	if m := mountOf(initC, dispatchVolume); m == nil || m.ReadOnly {
		t.Errorf("init container's dispatch mount = %+v, want writable", m)
	}
	if m := mountOf(harness, seedVolume); m != nil {
		t.Errorf("the harness mounts the seed's Secret volume (%+v); it gets the read-only copy only", m)
	}
	if m := mountOf(harness, dispatchVolume); m == nil || !m.ReadOnly || m.MountPath != dispatchMountDir {
		t.Errorf("harness's dispatch mount = %+v, want read-only at %s", m, dispatchMountDir)
	}

	initArgs := strings.Join(initC.Args, " ")
	if !strings.Contains(initArgs, "--seed "+seedMountDir+"/"+seedFileName+" --seed-copy "+dispatchMountDir+"/"+seedFileName) {
		t.Errorf("init container args lack the seed flags: %s", initArgs)
	}

	argv := append(append([]string{}, harness.Command...), harness.Args...)
	joined := strings.Join(argv, " ")
	want := "cloop workspace writeback --dir /workspace --seed " + dispatchMountDir + "/" + seedFileName +
		" --project-result-frame " + req.HandleID + " -- cloop run"
	if joined != want {
		t.Errorf("harness argv = %q\nwant          %q", joined, want)
	}
	if strings.Contains(joined, "--push") || strings.Contains(joined, "--repo") {
		t.Errorf("a seeded run that asked for no write-back is pushing: %s", joined)
	}
	if p.Metadata.Annotations[AnnotationArgv] != "cloop run" {
		t.Errorf("argv annotation = %q, want the real command", p.Metadata.Annotations[AnnotationArgv])
	}
}

// TestBuildPod_SeedWithAPushWriteBack: one wrapper does both halves, the push
// flags and the read-back, before the "--".
func TestBuildPod_SeedWithAPushWriteBack(t *testing.T) {
	req := seededRequest()
	req.Workspace = wbWorkspace()
	req.WriteBack = wbSpec()
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	harness := findContainer(p.Spec.Containers, ContainerName)
	joined := strings.Join(append(append([]string{}, harness.Command...), harness.Args...), " ")
	for _, want := range []string{"--push", "--base " + wbTestBase, "--branch " + wbTestBranch,
		"--seed " + dispatchMountDir + "/" + seedFileName, "--project-result-frame " + req.HandleID} {
		if !strings.Contains(joined, want) {
			t.Errorf("wrapper lacks %q: %s", want, joined)
		}
	}
	if i, j := strings.Index(joined, "--project-result-frame"), strings.Index(joined, " -- "); i < 0 || j < i {
		t.Errorf("the read-back flags must come before the harness's argv: %s", joined)
	}
}

func TestBuildPod_SeedNeedsAFetchedTreeAndASecret(t *testing.T) {
	req := seededRequest()
	req.Workspace = executor.Workspace{Kind: executor.WorkspaceNone}
	if _, err := buildPod(req); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("a seed on a workspace nothing fetches: %v, want ErrInvalidSpec", err)
	}
	req = seededRequest()
	req.LeaseSecretName = ""
	if _, err := buildPod(req); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("a seed with no Secret to carry it: %v, want ErrInvalidSpec", err)
	}
	req = seededRequest()
	req.SecretFiles = []executor.SecretFile{{Dir: seedMountDir, Name: "token", Content: []byte("x")}}
	if _, err := buildPod(req); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Errorf("a lease directory over the seed's mount: %v, want ErrInvalidSpec", err)
	}
}

// TestLeaseSecretData_SeedFitsTheSecretOrIsRefused: the Secret's whole data —
// files, environment, seed, keys included — stays under the API server's 1 MiB,
// and a seed that does not fit is refused naming the project's state and the
// room it had.
func TestLeaseSecretData_SeedFitsTheSecretOrIsRefused(t *testing.T) {
	seed := testSeed(t, 64)
	data, err := leaseSecretData(nil, []string{"TOKEN=value"}, seed)
	if err != nil {
		t.Fatalf("leaseSecretData: %v", err)
	}
	if !bytes.Equal(data[projectSeedKey], seed) || string(data["env.TOKEN"]) != "value" {
		t.Fatalf("the Secret carries %v", keysOf(data))
	}
	if d, err := leaseSecretData(nil, nil, seed); err != nil || len(d) != 1 {
		t.Fatalf("a seed alone: %v, %v", keysOf(d), err)
	}

	// Each credential file is capped well under a Secret on its own; three of
	// them leave too little room for this seed.
	var files []executor.SecretFile
	for _, name := range []string{"kubeconfig", "gitconfig", "github-token"} {
		files = append(files, executor.SecretFile{Dir: "/run/cloop/cloop-lease-1", Name: name,
			Content: bytes.Repeat([]byte("k"), 200<<10)})
	}
	big := testSeed(t, 500<<10)
	_, err = leaseSecretData(files, nil, big)
	if !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("a Secret over 1 MiB: %v, want ErrInvalidSpec", err)
	}
	for _, want := range []string{"project's state", "lease Secret", "cloop task archive", "room for a project state"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
	// The same seed without the files fits: the cap is the Secret's, shared.
	if _, err := leaseSecretData(nil, nil, big); err != nil {
		t.Errorf("a %d-byte seed alone was refused: %v", len(big), err)
	}
}

// TestStart_SeedTravelsInTheLeaseSecretAndNowhereElse runs a seeded Start
// against the fake API server and reads back what it was sent.
func TestStart_SeedTravelsInTheLeaseSecretAndNowhereElse(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	spec := seededSpec(t)
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)

	sec := api.secretObject(leaseSecretName(h.ID))
	if sec == nil {
		t.Fatal("a seeded run created no lease Secret")
	}
	if !bytes.Equal(sec.Data[projectSeedKey], spec.ProjectSeed) {
		t.Fatalf("the lease Secret's %s key holds %d bytes, want the %d-byte seed",
			projectSeedKey, len(sec.Data[projectSeedKey]), len(spec.ProjectSeed))
	}
	if len(sec.Metadata.OwnerReferences) != 1 {
		t.Errorf("the Secret carrying the seed is not owned by its Pod: %+v", sec.Metadata.OwnerReferences)
	}

	api.mu.Lock()
	raw, _ := json.Marshal(api.pods[name])
	api.mu.Unlock()
	podJSON := string(raw)
	if strings.Contains(podJSON, base64.StdEncoding.EncodeToString(spec.ProjectSeed)) ||
		strings.Contains(podJSON, string(spec.ProjectSeed)) {
		t.Fatal("the seed is in the Pod object, readable by every identity that can get pods")
	}
	for _, want := range []string{`"--seed"`, `"--project-result-frame"`, `"` + h.ID + `"`} {
		if !strings.Contains(podJSON, want) {
			t.Errorf("the Pod lacks %s", want)
		}
	}
}

// TestStart_OversizedSeedCreatesNothing: refused before the Pod exists.
func TestStart_OversizedSeedCreatesNothing(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)
	spec := seededSpec(t)
	spec.ProjectSeed = testSeed(t, 1100<<10)
	if _, err := ex.Start(context.Background(), spec); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Start with a seed no Secret can hold: %v, want ErrInvalidSpec", err)
	}
	if n := len(api.podNames()); n != 0 {
		t.Errorf("%d Pod(s) created for a run that was refused", n)
	}
	if n := api.secretCreateCount(); n != 0 {
		t.Errorf("%d Secret(s) created for a run that was refused", n)
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// collectStream reads a handle's stream to its end.
func collectStream(t *testing.T, ex *Executor, id string) <-chan string {
	t.Helper()
	lines, err := ex.Stream(context.Background(), id)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	out := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for l := range lines {
			sb.WriteString(l.Text)
		}
		out <- sb.String()
	}()
	return out
}

func frameFor(t *testing.T, tag string, kind resultframe.Kind, payload []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := resultframe.Write(&buf, tag, kind, payload); err != nil {
		t.Fatalf("resultframe.Write: %v", err)
	}
	return buf.String()
}

// runSeeded starts a seeded run, plays log through its Pod in the given chunks
// and ends it, returning the handle and the transcript its stream carried.
func runSeeded(t *testing.T, ex *Executor, api *fakeAPI, chunks func(handleID string) []string) (executor.Handle, string) {
	t.Helper()
	h, err := ex.Start(context.Background(), seededSpec(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	transcript := collectStream(t, ex, h.ID)
	name := api.onlyPodName(t)
	api.finishInitContainer(name, 0, "Completed")
	api.run(name)
	for _, c := range chunks(h.ID) {
		api.emitLog(name, c)
	}
	api.terminate(name, 0, "Completed")
	st := waitStatus(t, ex, h.ID, 5*time.Second)
	if st.State != executor.StateExited {
		t.Fatalf("state = %q (%s)", st.State, st.Error)
	}
	select {
	case out := <-transcript:
		return h, out
	case <-time.After(5 * time.Second):
		t.Fatal("the stream never closed")
	}
	return h, ""
}

// cutEvery splits s into pieces of n bytes, the way a log stream arrives.
func cutEvery(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

// TestProjectResult_RoundTripThroughAPod is the outcome half: the wrapper's
// frame, split across log chunks, comes back whole through ProjectResult — once
// — and none of its lines reach the transcript.
func TestProjectResult_RoundTripThroughAPod(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	payload := testSeed(t, 40<<10) // any bytes; the hub decodes, the driver only carries
	h, transcript := runSeeded(t, ex, api, func(id string) []string {
		text := "stand-in: probe\nTASK_DONE\n" + frameFor(t, id, resultframe.KindResult, payload)
		return cutEvery(text, 1000)
	})

	res, err := ex.ProjectResult(h.ID)
	if err != nil {
		t.Fatalf("ProjectResult: %v", err)
	}
	if !bytes.Equal(res.Data, payload) || res.Err != "" {
		t.Fatalf("got %d bytes (err %q), want the %d the Pod printed", len(res.Data), res.Err, len(payload))
	}
	if res.Redact == nil {
		t.Fatal("a result carries no redaction for the hub to apply")
	}
	if _, err := ex.ProjectResult(h.ID); !errors.Is(err, executor.ErrProjectResultUnavailable) {
		t.Errorf("a second ProjectResult: %v, want ErrProjectResultUnavailable — merging a run twice "+
			"books its spend twice", err)
	}

	if strings.Contains(transcript, resultframe.Marker) {
		t.Error("a line of the result frame reached the run's transcript")
	}
	for _, want := range []string{"stand-in: probe\nTASK_DONE\n", "read the run's project state back"} {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript lacks %q:\n%s", want, transcript)
		}
	}
	ex.mu.Lock()
	held := ex.held.total
	ex.mu.Unlock()
	if held != 0 {
		t.Errorf("%d bytes still counted as held after collection", held)
	}
}

// TestProjectResult_ErrorFrame: the wrapper's reason for having no result comes
// back as the result's Err, as a device's would.
func TestProjectResult_ErrorFrame(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	h, _ := runSeeded(t, ex, api, func(id string) []string {
		return []string{frameFor(t, id, resultframe.KindError, []byte("the workload removed the project it was sent"))}
	})
	res, err := ex.ProjectResult(h.ID)
	if err != nil {
		t.Fatalf("ProjectResult: %v", err)
	}
	if res.Err != "the workload removed the project it was sent" || len(res.Data) != 0 {
		t.Fatalf("got Err %q and %d bytes", res.Err, len(res.Data))
	}
}

// TestProjectResult_BrokenFramesAreUnavailable: every way the workload or the
// log can mangle the frame yields ErrProjectResultUnavailable and no bytes.
func TestProjectResult_BrokenFramesAreUnavailable(t *testing.T) {
	payload := testSeed(t, 10<<10)
	cases := map[string]func(t *testing.T, id string) string{
		"truncated": func(t *testing.T, id string) string {
			f := frameFor(t, id, resultframe.KindResult, payload)
			return f[:len(f)*2/3]
		},
		"duplicated": func(t *testing.T, id string) string {
			f := frameFor(t, id, resultframe.KindResult, payload)
			return f + f
		},
		"forged before the real one": func(t *testing.T, id string) string {
			return frameFor(t, id, resultframe.KindResult, []byte("forged")) +
				"more output\n" + frameFor(t, id, resultframe.KindResult, payload)
		},
		"interleaved": func(t *testing.T, id string) string {
			a := strings.SplitAfter(frameFor(t, id, resultframe.KindResult, payload), "\n")
			b := strings.SplitAfter(frameFor(t, id, resultframe.KindResult, []byte("other")), "\n")
			return strings.Join(a[:3], "") + strings.Join(b, "") + strings.Join(a[3:], "")
		},
		"unframed": func(t *testing.T, id string) string {
			lines := strings.SplitAfter(frameFor(t, id, resultframe.KindResult, payload), "\n")
			return strings.Join(lines[2:], "") // the blank line and the begin dropped
		},
		"none at all": func(t *testing.T, id string) string { return "TASK_DONE\n" },
		"over the ceiling": func(t *testing.T, id string) string {
			return resultframe.Marker + " " + id + " begin result 655361 " + strings.Repeat("a", 64) + "\n"
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			ex, api, _ := newTestExecutor(t, nil)
			h, transcript := runSeeded(t, ex, api, func(id string) []string { return cutEvery(build(t, id), 777) })
			res, err := ex.ProjectResult(h.ID)
			if !errors.Is(err, executor.ErrProjectResultUnavailable) {
				t.Fatalf("ProjectResult = %d bytes, %v; want ErrProjectResultUnavailable", len(res.Data), err)
			}
			if len(res.Data) != 0 || res.Err != "" {
				t.Fatal("an unavailable result carried content")
			}
			if strings.Contains(transcript, resultframe.Marker+" "+h.ID+" ") {
				t.Error("frame protocol reached the transcript")
			}
			if !strings.Contains(transcript, "no project result came back") {
				t.Errorf("the transcript does not say the result was lost:\n%s", transcript)
			}
		})
	}
}

// TestProjectResult_UnseededRunIsLeftAlone: a run that was not sent the project
// has nothing to return, and a frame in its log is somebody else's text —
// forwarded untouched.
func TestProjectResult_UnseededRunIsLeftAlone(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	h, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	transcript := collectStream(t, ex, h.ID)
	name := api.onlyPodName(t)
	api.run(name)
	frame := frameFor(t, h.ID, resultframe.KindResult, []byte("not asked for"))
	api.emitLog(name, frame)
	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, h.ID, 5*time.Second)
	if out := <-transcript; !strings.Contains(out, frame) {
		t.Errorf("an unseeded run's log was altered:\n%s", out)
	}
	if _, err := ex.ProjectResult(h.ID); !errors.Is(err, executor.ErrProjectResultUnavailable) {
		t.Errorf("ProjectResult on an unseeded run: %v", err)
	}

	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Spec.Containers[0].Args, " "); got != "run" {
		t.Errorf("an unseeded run without a write-back was wrapped: %q", got)
	}
}

// TestProjectResult_RedactsTheRefusalReason: a refusal can quote a line of the
// Pod's log, and its reason goes to the project's journal, not the scrubbed
// live log — so it is scrubbed here.
func TestProjectResult_RedactsTheRefusalReason(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	const secretValue = "s3cr3t-token-value"
	spec := seededSpec(t)
	// Declared sensitive the way a lease declares it (redact.EnvKey).
	spec.Env = []string{"API_TOKEN=" + secretValue, "CLOOP_REDACT_ENV=API_TOKEN"}
	h, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.finishInitContainer(name, 0, "Completed")
	api.run(name)
	api.emitLog(name, resultframe.Marker+" "+h.ID+" "+secretValue+"\n")
	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, h.ID, 5*time.Second)
	_, err = ex.ProjectResult(h.ID)
	if !errors.Is(err, executor.ErrProjectResultUnavailable) {
		t.Fatalf("ProjectResult: %v", err)
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("the refusal quotes a leased credential: %v", err)
	}
}

// TestHeldResults_EvictsTheOldestUncollected: results nobody collects — a
// helper subcommand's — cannot add up without bound, and the newest is never
// the one dropped.
func TestHeldResults_EvictsTheOldestUncollected(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	big := make([]byte, resultframe.KindResult.Limit())
	n := maxHeldProjectResultBytes/len(big) + 2
	var ids []string
	for i := 0; i < n; i++ {
		id := "k-held" + strings.Repeat("0", 4) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		s, err := resultframe.NewScanner(id)
		if err != nil {
			t.Fatal(err)
		}
		s.Feed(frameFor(t, id, resultframe.KindResult, big))
		s.Close()
		rec := &record{id: id, result: s, done: true}
		ex.mu.Lock()
		ex.handles[id] = rec
		ex.held.holdLocked(ex, id, len(big))
		ex.mu.Unlock()
		ids = append(ids, id)
	}
	ex.mu.Lock()
	total := ex.held.total
	ex.mu.Unlock()
	if total > maxHeldProjectResultBytes {
		t.Fatalf("holding %d bytes, over the %d bound", total, maxHeldProjectResultBytes)
	}
	if _, err := ex.handles[ids[0]].result.Take(); !errors.Is(err, resultframe.ErrDropped) {
		t.Errorf("the oldest uncollected result: %v, want ErrDropped", err)
	}
	if f, err := ex.handles[ids[len(ids)-1]].result.Take(); err != nil || len(f.Payload) != len(big) {
		t.Errorf("the newest result was not kept: %v", err)
	}
}

func TestCapabilities_ProjectRoundTrip(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	caps := ex.Capabilities()
	if !caps.SupportsProjectSeed || !caps.ReturnsProjectState {
		t.Fatalf("SupportsProjectSeed=%v ReturnsProjectState=%v; a Kubernetes run must carry its project "+
			"in and its outcome out", caps.SupportsProjectSeed, caps.ReturnsProjectState)
	}
}

// TestRehydrate_AdoptedSeededRunReturnsItsResult: the row remembers the run was
// seeded, so a process that adopts the Pod after a restart reads the frame out
// of the re-read log.
func TestRehydrate_AdoptedSeededRunReturnsItsResult(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex1, api, src := newTestExecutor(t, func(o *Options) { o.HandleStore = store })
	h, err := ex1.Start(context.Background(), seededSpec(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	rows, err := store.ListHandles("k8s-test")
	if err != nil || len(rows) != 1 || rows[0].Meta[metaProjectSeed] != "1" {
		t.Fatalf("the row does not record the seed: %+v, %v", rows, err)
	}

	ex1.Close()
	waitStatus(t, ex1, h.ID, 5*time.Second)
	src.waitOutstandingEmpty(t, 3*time.Second)

	ex2 := newRestartedExecutor(t, api, src, store)
	payload := []byte("the outcome, printed after the restart")
	api.finishInitContainer(name, 0, "Completed")
	api.run(name)
	api.emitLog(name, "TASK_DONE\n"+frameFor(t, h.ID, resultframe.KindResult, payload))
	api.terminate(name, 0, "Completed")
	if st := waitStatus(t, ex2, h.ID, 5*time.Second); st.State != executor.StateExited {
		t.Fatalf("state = %q (%s)", st.State, st.Error)
	}
	res, err := ex2.ProjectResult(h.ID)
	if err != nil || !bytes.Equal(res.Data, payload) {
		t.Fatalf("the adopted run's result: %q, %v", res.Data, err)
	}
}
