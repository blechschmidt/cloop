package remote_test

// Control-plane-side tests for carrying a lease's credential files to a device.
//
// The device's half — a real write, a real relocation, a real refusal of a
// crafted name — lives in pkg/executor/agent's secretfiles_test.go. What only
// the hub can get wrong is here, and it is three things:
//
//   - the bytes must reach the frame and must not reach the Spec, because
//     pkg/executorstore persists the dispatched Spec and the audit trail echoes
//     it. Everything else in this file is a rule; that one is the reason the
//     wire type exists at all;
//   - a workload whose credentials are files must not be placed on an agent
//     that would ignore them, since ignoring them is silent; and
//   - `%v` on a payload must never print a token, because the thing that makes
//     a credential leak into a log is nobody having written this test.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// secretFileToken is the material under test. A test asserting on a placeholder
// would pass just as happily against an implementation that shipped no bytes.
const secretFileToken = "ghp_secret_file_0123456789abcdef"

// nominalLeaseDir is the directory the hub declares. It is not a path that
// exists anywhere: the broker mints one per lease and the device relocates off
// it, which is exactly the property these tests are about.
const nominalLeaseDir = "/run/cloop/cloop-lease-deadbeefcafe"

// fileSpec is a workload whose credentials arrive as files, assembled the way
// pkg/ui does at spawn time: the environment already names the paths, the
// binding names them for revocation, and the bytes ride alongside.
func fileSpec(workDir string) executor.Spec {
	return executor.Spec{
		WorkDir: workDir,
		Argv:    []string{"/bin/sh", "-c", "true"},
		Env: []string{
			"CLOOP_LEASE_DIR=" + nominalLeaseDir,
			"GIT_CONFIG_GLOBAL=" + nominalLeaseDir + "/gitconfig",
		},
		Secrets: []executor.SecretBinding{{
			LeaseID:    "lease_files",
			GrantID:    "grant_files",
			SecretName: "github-ci",
			Kind:       "github_pat",
			Dir:        nominalLeaseDir,
			Files:      []string{nominalLeaseDir + "/token"},
		}},
		SecretFiles: []executor.SecretFile{{
			LeaseID: "lease_files",
			GrantID: "grant_files",
			Dir:     nominalLeaseDir,
			Name:    "token",
			Mode:    0o600,
			Content: []byte(secretFileToken),
		}},
	}
}

// TestSecretFilesTravelBesideTheSpec is the central assertion of the hub's half.
//
// executor.Spec.SecretFiles is tagged json:"-" so the bytes *cannot* be
// serialized inside a Spec, and the whole point of the v6 field is to carry
// them anyway, deliberately and in exactly one place. Both halves have to be
// checked together: a payload that carried the token in the Spec would pass a
// "the agent received it" test and still make the credential durable in the
// handle store.
func TestSecretFilesTravelBesideTheSpec(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	defer sess.Close()

	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), fileSpec(t.TempDir())); err != nil {
		t.Fatalf("Start: %v", err)
	}
	payload := <-got

	// The bytes reached the agent.
	files := payload.CredentialFiles()
	if len(files) != 1 {
		t.Fatalf("agent received %d credential files, want 1", len(files))
	}
	if string(files[0].Content) != secretFileToken {
		t.Errorf("content = %q, want the leased token", files[0].Content)
	}
	if files[0].Path() != nominalLeaseDir+"/token" {
		t.Errorf("declared path = %q, want %s/token", files[0].Path(), nominalLeaseDir)
	}
	if files[0].FileMode() != fs.FileMode(0o600) {
		t.Errorf("mode = %v, want 0600", files[0].FileMode())
	}
	if files[0].LeaseID != "lease_files" || files[0].GrantID != "grant_files" {
		t.Errorf("attribution lost in transit: lease=%q grant=%q", files[0].LeaseID, files[0].GrantID)
	}

	// And they are absent from the Spec, marshalled exactly as the handle store
	// would marshal it.
	blob, err := json.Marshal(payload.Spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if strings.Contains(string(blob), secretFileToken) {
		t.Fatalf("the token is inside the serialized Spec, which pkg/executorstore persists:\n%s", blob)
	}
	if len(payload.Spec.SecretFiles) != 0 {
		t.Errorf("Spec.SecretFiles survived serialization with %d entries; the json:\"-\" tag is the "+
			"only thing keeping plaintext out of the handle store", len(payload.Spec.SecretFiles))
	}
	// The binding still names the files, because that is what a later revoke
	// frame matches on. Names are not secrets; contents are.
	if len(payload.Spec.Secrets) != 1 || len(payload.Spec.Secrets[0].Files) != 1 {
		t.Errorf("the lease binding must still name its files for revocation; got %+v", payload.Spec.Secrets)
	}
}

// TestSecretFileFormattingIsRedacted covers the failure mode nothing else can:
// a credential that leaks not through the protocol but through a log line
// somebody adds later. Every fmt verb on the wire type must be inert.
func TestSecretFileFormattingIsRedacted(t *testing.T) {
	payload := remote.StartPayload{
		HandleID:    "h-1",
		Spec:        fileSpec("/tmp/x"),
		SecretFiles: remote.NewSecretFiles(fileSpec("/tmp/x").SecretFiles),
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		rendered := fmt.Sprintf(format, payload)
		if strings.Contains(rendered, secretFileToken) {
			t.Errorf("%s on a start payload printed the token:\n%s", format, rendered)
		}
		// The redaction has to be visible, not merely a blank: an operator
		// reading a log needs to know a credential was there.
		if !strings.Contains(rendered, "redacted") {
			t.Errorf("%s should say the content was redacted; got:\n%s", format, rendered)
		}
	}
	// And on the file alone, which is how it will be printed in practice.
	one := remote.NewSecretFile(fileSpec("/tmp/x").SecretFiles[0])
	for _, rendered := range []string{fmt.Sprint(one), fmt.Sprintf("%#v", one), one.String(), one.GoString()} {
		if strings.Contains(rendered, secretFileToken) {
			t.Errorf("a secret file rendered its content: %s", rendered)
		}
	}
	// Marshalling is unaffected — the redaction is a fmt property, not a
	// serialization one, or the device would receive nothing.
	blob, err := json.Marshal(one)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back remote.SecretFile
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(back.Content) != secretFileToken {
		t.Errorf("round trip lost the content: %q", back.Content)
	}
}

// TestSecretFileFrameRoundTrip drives the real encode/decode path rather than
// the structs, since that is where a tag typo or a missing validation hook
// would show up.
func TestSecretFileFrameRoundTrip(t *testing.T) {
	spec := fileSpec("/tmp/x")
	frame, err := remote.NewFrame(remote.TypeStart, "corr-1", "h-1", remote.StartPayload{
		HandleID:    "h-1",
		Spec:        spec,
		SecretFiles: remote.NewSecretFiles(spec.SecretFiles),
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	// A frame's own String must not print the payload, since that payload now
	// contains plaintext.
	if strings.Contains(frame.String(), secretFileToken) {
		t.Fatalf("Frame.String printed the payload: %s", frame.String())
	}

	decoded, err := remote.DecodeStart(frame)
	if err != nil {
		t.Fatalf("DecodeStart: %v", err)
	}
	files := decoded.CredentialFiles()
	if len(files) != 1 || string(files[0].Content) != secretFileToken {
		t.Fatalf("content did not survive the frame: %+v", files)
	}
	if files[0].Dir != nominalLeaseDir || files[0].Name != "token" {
		t.Errorf("placement lost in transit: dir=%q name=%q", files[0].Dir, files[0].Name)
	}
	// The zero mode is resolved once, on the sending side, so the device is told
	// what to create rather than left to re-derive a default.
	if files[0].Mode != 0o600 {
		t.Errorf("mode = %v, want an explicit 0600 on the wire", files[0].Mode)
	}
}

// TestOversizedSecretFilesAreRefused pins the frame-level bound.
//
// A start frame carried nothing large until v6. The cap exists so a lease that
// cannot fit is refused with a message naming the credential files, on both
// sides — rather than the hub emitting a frame the device rejects as an
// oversized payload, a diagnostic that points at the protocol instead of at the
// secret.
func TestOversizedSecretFilesAreRefused(t *testing.T) {
	// Three files, each inside executor.MaxSecretFileBytes, whose sum is not.
	// The per-file rule and the aggregate rule are different rules, and this is
	// the case that distinguishes them.
	var files []executor.SecretFile
	for i := range 3 {
		files = append(files, executor.SecretFile{
			LeaseID: "lease_big",
			Dir:     nominalLeaseDir,
			Name:    fmt.Sprintf("chunk-%d", i),
			Mode:    0o600,
			Content: make([]byte, 200<<10),
		})
	}
	wire := remote.NewSecretFiles(files)
	if err := remote.ValidateSecretFiles(wire); err == nil {
		t.Fatal("a payload over the ceiling must be refused")
	} else {
		if !errors.Is(err, remote.ErrProtocol) {
			t.Errorf("error should be an ErrProtocol; got %v", err)
		}
		for _, want := range []string{"credential file", "ceiling"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("diagnostic should mention %q; got %q", want, err)
			}
		}
	}

	// The receiving side re-derives it rather than trusting the sender, because
	// the sender is the party this device cannot vouch for.
	frame, err := remote.NewFrame(remote.TypeStart, "corr-1", "h-1", remote.StartPayload{
		HandleID: "h-1", SecretFiles: wire,
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	if _, err := remote.DecodeStart(frame); err == nil {
		t.Fatal("the device must refuse an oversized start frame")
	}

	// The hub refuses to dispatch it at all, before a credential is leased or a
	// handle row is written. A frame that went out and came back as
	// "payload 1103241 bytes exceeds 1048576" would name the protocol instead of
	// the secret, and would leave a durable row describing a workload that never
	// ran.
	ex := newTestExecutor(t, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	defer sess.Close()

	big := fileSpec(t.TempDir())
	big.SecretFiles = files
	big.Secrets[0].Files = nil
	if _, err := ex.Start(context.Background(), big); err == nil {
		t.Fatal("the hub must refuse a lease too large to fit in a start frame")
	} else if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("the refusal should name the ceiling; got %v", err)
	}

	// A set just under the ceiling still goes through, or the bound would be a
	// limit on leases rather than on frames.
	ok := remote.NewSecretFiles([]executor.SecretFile{{
		LeaseID: "lease_ok", Dir: nominalLeaseDir, Name: "token", Mode: 0o600,
		Content: make([]byte, remote.MaxSecretFilesBytes/2),
	}})
	if err := remote.ValidateSecretFiles(ok); err != nil {
		t.Errorf("a lease inside the ceiling must be accepted: %v", err)
	}
}

// TestUnsafeSecretFileNamesAreRefusedAtDecode is the receiving side's
// confinement check. The name is the field that turns into a path, so a
// separator in it is an arbitrary-file-write primitive aimed at whatever device
// happens to be enrolled.
func TestUnsafeSecretFileNamesAreRefusedAtDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		file remote.SecretFile
	}{
		{"traversal", remote.SecretFile{Dir: nominalLeaseDir, Name: "../evil", Mode: 0o600}},
		{"absolute", remote.SecretFile{Dir: nominalLeaseDir, Name: "/etc/ld.so.preload", Mode: 0o600}},
		{"nested", remote.SecretFile{Dir: nominalLeaseDir, Name: "a/b", Mode: 0o600}},
		{"relative dir", remote.SecretFile{Dir: "run/cloop", Name: "token", Mode: 0o600}},
		{"world readable", remote.SecretFile{Dir: nominalLeaseDir, Name: "token", Mode: 0o644}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.file.Content = []byte(secretFileToken)
			frame, err := remote.NewFrame(remote.TypeStart, "corr-1", "h-1", remote.StartPayload{
				HandleID: "h-1", SecretFiles: []remote.SecretFile{tc.file},
			})
			if err != nil {
				t.Fatalf("NewFrame: %v", err)
			}
			if _, err := remote.DecodeStart(frame); err == nil {
				t.Fatal("a crafted secret file must not survive decode")
			}
		})
	}
}

// TestOldAgentIsRefusedSecretFiles is the placement rule.
//
// A v5 agent still connects and still runs ordinary work — stranding a fleet
// mid-upgrade over a capability most workloads do not need would be the worse
// failure. What it must not receive is a workload whose credentials are files,
// because it does not reject the field, it ignores it: the harness would run
// with GIT_CONFIG_GLOBAL naming a directory nothing created and fail to
// authenticate for a reason nothing in the transcript explains.
func TestOldAgentIsRefusedSecretFiles(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinSecretFilesVersion-1), nil)
	defer sess.Close()

	if ex.Capabilities().SupportsSecretFiles {
		t.Error("a pre-v6 session must not claim it can deliver credential files")
	}

	_, err := ex.Start(context.Background(), fileSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrSecretFilesUnsupported) {
		t.Fatalf("Start error = %v, want ErrSecretFilesUnsupported", err)
	}
	// The diagnostic is what an operator reads in the Executors panel, so it
	// names the device, the credential, the version and the fix.
	for _, want := range []string{"edge-1", "github-ci", "v5", "install --upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}

	// A spec whose bindings merely *name* files is refused too: the hub cannot
	// know whether the paths exist on that machine, and on a remote agent they
	// certainly do not.
	named := fileSpec(t.TempDir())
	named.SecretFiles = nil
	if _, err := ex.Start(context.Background(), named); !errors.Is(err, remote.ErrSecretFilesUnsupported) {
		t.Errorf("a binding naming files must be refused too; got %v", err)
	}

	// The same device still runs ordinary work. This is a workload rule, not a
	// connectivity rule.
	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(), Argv: []string{"sleep", "60"},
	}); err != nil {
		t.Fatalf("an older agent must still accept work with no credential files: %v", err)
	}
	<-got
}

// TestSupportsSecretFilesTracksTheProtocolVersion mirrors the write-back and
// workspace rules, with one difference worth stating: there is no device
// capability to intersect with. Writing a file needs no tool, so the protocol
// version is the whole question.
func TestSupportsSecretFilesTracksTheProtocolVersion(t *testing.T) {
	if remote.SupportsSecretFiles(remote.MinSecretFilesVersion - 1) {
		t.Errorf("v%d should not claim secret-file support", remote.MinSecretFilesVersion-1)
	}
	if !remote.SupportsSecretFiles(remote.MinSecretFilesVersion) {
		t.Errorf("v%d should claim secret-file support", remote.MinSecretFilesVersion)
	}

	current := newTestExecutor(t, nil)
	connect(t, current, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	caps := current.Capabilities()
	if !caps.SupportsSecretFiles {
		t.Error("a current device must be able to place credential files; it needs no tool to do it")
	}
	// The hub must never write plaintext for a device that cannot read it: the
	// agent shares no filesystem with the control plane.
	if caps.SecretFilesFromHostPath {
		t.Error("a remote executor must not claim the workload reads files off the hub's filesystem")
	}

	old := newTestExecutor(t, nil)
	oldHello := defaultHello()
	oldHello.ProtocolVersion = remote.MinSecretFilesVersion - 1
	connect(t, old, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, oldHello, nil)
	if old.Capabilities().SupportsSecretFiles {
		t.Error("a pre-v6 session claimed it could deliver credential files; a workload placed " +
			"there would run with an environment naming files nobody wrote")
	}
}

// TestSecretFilesVersionFloorStaysInRange is the fleet-compatibility guard,
// matching the ones the other floors carry: a floor above the negotiable range
// would make the feature permanently unreachable, and one at or below the
// minimum would claim every deployed v1 device understands a frame field that
// did not exist when it was built.
func TestSecretFilesVersionFloorStaysInRange(t *testing.T) {
	if remote.MinSecretFilesVersion > remote.ProtocolVersion {
		t.Fatalf("MinSecretFilesVersion (%d) is above ProtocolVersion (%d): no session could ever "+
			"negotiate it", remote.MinSecretFilesVersion, remote.ProtocolVersion)
	}
	if remote.MinSecretFilesVersion <= remote.MinWriteBackVersion {
		t.Fatalf("MinSecretFilesVersion (%d) should be newer than MinWriteBackVersion (%d)",
			remote.MinSecretFilesVersion, remote.MinWriteBackVersion)
	}
	for v := remote.MinProtocolVersion; v <= remote.ProtocolVersion; v++ {
		if remote.SupportsSecretFiles(v) != (v >= remote.MinSecretFilesVersion) {
			t.Errorf("SupportsSecretFiles(%d) disagrees with MinSecretFilesVersion", v)
		}
	}
	// The wire ceiling must stay well under the frame ceiling, since JSON
	// base64-expands the content by 4/3 and the Spec travels in the same frame.
	if remote.MaxSecretFilesBytes*4/3 >= remote.MaxFrameBytes {
		t.Errorf("MaxSecretFilesBytes (%d) leaves no room for the envelope inside MaxFrameBytes (%d)",
			remote.MaxSecretFilesBytes, remote.MaxFrameBytes)
	}
}

// TestSecretFilesAreOmittedForAnEmptyLease keeps the common case on the wire it
// had before v6: a workload that leases only environment variables must not
// start carrying an empty array, since every enrolled device decodes this frame
// for every dispatch.
func TestSecretFilesAreOmittedForAnEmptyLease(t *testing.T) {
	frame, err := remote.NewFrame(remote.TypeStart, "corr-1", "h-1", remote.StartPayload{
		HandleID: "h-1",
		Spec:     executor.Spec{WorkDir: "/tmp/x", Argv: []string{"true"}},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	if strings.Contains(string(frame.Payload), "secret_files") {
		t.Errorf("a lease with no files should omit the field entirely: %s", frame.Payload)
	}
	if remote.NewSecretFiles(nil) != nil {
		t.Error("NewSecretFiles(nil) should stay nil so the field is omitted")
	}
	// And validation of an absent set is not an error, or every ordinary
	// dispatch would fail.
	if err := remote.ValidateSecretFiles(nil); err != nil {
		t.Errorf("validating no files should succeed: %v", err)
	}
}

// TestSecretFilesReachTheDeviceWithinTheDispatch guards the ordering the whole
// design rests on: the bytes go out in the same frame that dispatches the work,
// not in a follow-up the device might miss.
func TestSecretFilesReachTheDeviceWithinTheDispatch(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), nil)
	defer sess.Close()

	done := make(chan remote.Frame, 1)
	go func() {
		f := p.readUntil(remote.TypeStart)
		done <- f
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle, PID: 42, StartedAt: time.Now(),
		})
		if err == nil {
			p.write(reply)
		}
	}()

	if _, err := ex.Start(context.Background(), fileSpec(t.TempDir())); err != nil {
		t.Fatalf("Start: %v", err)
	}
	frame := <-done
	if frame.Type != remote.TypeStart {
		t.Fatalf("first frame was %s, want start", frame.Type)
	}
	payload, err := remote.DecodeStart(frame)
	if err != nil {
		t.Fatalf("DecodeStart: %v", err)
	}
	if len(payload.SecretFiles) != 1 {
		t.Fatalf("the start frame itself must carry the files; got %d", len(payload.SecretFiles))
	}
}
