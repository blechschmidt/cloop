package remote

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestUpgradePayloadHasNoRemoteCodeExecutionFields is the gate on the security
// argument in upgradeproto.go.
//
// The upgrade frame tells a device to install and run a new binary as root. It
// is safe to expose only because the hub cannot say *which bytes* — it names a
// version, and the device resolves that through its own release channel and
// verifies the signature before installing. Two fields would each undo that on
// their own: a source URL, and a switch that turns verification off. Either
// would convert "can send one frame" into "owns every device in the fleet".
//
// Both are the kind of field somebody adds in good faith — a URL looks like a
// caching optimisation, a skip flag looks like air-gap support — so the
// prohibition is enforced here rather than left to the comment.
func TestUpgradePayloadHasNoRemoteCodeExecutionFields(t *testing.T) {
	banned := []string{
		"source", "url", "uri", "download", "binary", "path", "mirror", "checksum",
		"skipverify", "insecure", "noverify", "unverified", "bundle", "signature",
	}

	for _, typ := range []reflect.Type{
		reflect.TypeOf(UpgradePayload{}),
		reflect.TypeOf(UpgradeRequest{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.ToLower(f.Name)
			tag := strings.ToLower(strings.Split(f.Tag.Get("json"), ",")[0])
			for _, b := range banned {
				if strings.Contains(name, b) || (tag != "" && strings.Contains(tag, b)) {
					t.Fatalf(
						"%s.%s (json %q) looks like it lets the control plane choose the bytes a "+
							"device installs, or lets it disable verification.\n\n"+
							"The upgrade frame is a remote code execution primitive and is only "+
							"safe because it can name a *version* and nothing else: the device "+
							"resolves it through its own release channel and checks the signature "+
							"against a pinned identity. If this field is genuinely needed, the "+
							"security argument at the top of upgradeproto.go has to change first.",
						typ.Name(), f.Name, tag)
				}
			}
		}
	}
}

// TestDecodeUpgradeRejectsAnAbsentTarget pins the choice not to default a
// missing target to "latest". A frame that lost its target is malformed, and
// quietly turning it into "roll the fleet to the newest release" is the worst
// available reading of a truncated write.
func TestDecodeUpgradeRejectsAnAbsentTarget(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"absent", `{}`},
		{"empty", `{"target_version":""}`},
		{"blank", `{"target_version":"   "}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Frame{V: ProtocolVersion, Type: TypeUpgrade, Payload: json.RawMessage(tc.body)}
			if _, err := DecodeUpgrade(f); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decoding %s target gave err=%v, want ErrProtocol", tc.name, err)
			}
		})
	}
}

// TestDecodeUpgradeRejectsNegativeSettle guards the one numeric field: a
// negative settle would become a negative timeout on the device, which the
// installer would treat as "already expired" and roll back a good upgrade.
func TestDecodeUpgradeRejectsNegativeSettle(t *testing.T) {
	f := Frame{
		V:       ProtocolVersion,
		Type:    TypeUpgrade,
		Payload: json.RawMessage(`{"target_version":"v1.0.0","settle_seconds":-5}`),
	}
	if _, err := DecodeUpgrade(f); !errors.Is(err, ErrProtocol) {
		t.Fatalf("negative settle_seconds gave err=%v, want ErrProtocol", err)
	}
}

func TestDecodeUpgradeRoundTrips(t *testing.T) {
	f, err := NewFrame(TypeUpgrade, "id-1", "", UpgradePayload{
		TargetVersion: "v1.2.3",
		Force:         true,
		SettleSeconds: 45,
		Reason:        "operator",
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	got, err := DecodeUpgrade(f)
	if err != nil {
		t.Fatalf("DecodeUpgrade: %v", err)
	}
	if got.TargetVersion != "v1.2.3" || !got.Force || got.SettleSeconds != 45 {
		t.Fatalf("round trip lost data: %+v", got)
	}
}

// TestUpgradeIsGatedOnTheProtocolVersionItWasAddedIn stops the gate drifting
// away from the version that introduced the frame. A device that predates it
// answers an upgrade with a protocol error and keeps running its old build, so
// the hub has to refuse before sending rather than discover it afterwards.
func TestUpgradeIsGatedOnTheProtocolVersionItWasAddedIn(t *testing.T) {
	if !SupportsUpgrade(MinUpgradeVersion) {
		t.Fatalf("SupportsUpgrade(%d) is false at its own floor", MinUpgradeVersion)
	}
	if SupportsUpgrade(MinUpgradeVersion - 1) {
		t.Fatalf("SupportsUpgrade(%d) is true below the floor", MinUpgradeVersion-1)
	}
	if ProtocolVersion < MinUpgradeVersion {
		t.Fatalf("ProtocolVersion %d is below MinUpgradeVersion %d, so no agent built from this "+
			"tree could ever be upgraded remotely", ProtocolVersion, MinUpgradeVersion)
	}
}

// TestUpgradeOutcomeSummaryNeverClaimsSuccess is the wording gate.
//
// The one thing about this feature that is easy to report wrongly is the
// difference between "the device accepted" and "the device upgraded" — the
// restart kills the session, so the hub genuinely cannot know the second. Three
// callers render this line, and all three go through Summary so they cannot
// drift into overclaiming independently.
func TestUpgradeOutcomeSummaryNeverClaimsSuccess(t *testing.T) {
	s := UpgradeOutcome{Accepted: true, FromVersion: "v1.0.0", TargetVersion: "v1.1.0"}.
		Summary("edge-7")
	for _, overclaim := range []string{"upgraded", "succeeded", "complete", "done"} {
		if strings.Contains(strings.ToLower(s), overclaim) {
			t.Fatalf("accepted-upgrade summary claims completion (%q): %s", overclaim, s)
		}
	}
	if !strings.Contains(s, "reconnect") {
		t.Fatalf("summary does not tell the operator what confirmation looks like: %s", s)
	}

	if got := (UpgradeOutcome{AlreadyCurrent: true, FromVersion: "v1.1.0"}).Summary("edge-7"); //
	!strings.Contains(got, "nothing to do") {
		t.Fatalf("already-current summary reads like a failure: %s", got)
	}
	if got := (UpgradeOutcome{}).Summary("edge-7"); !strings.Contains(got, "refused") {
		t.Fatalf("refusal summary does not say it was refused: %s", got)
	}
}
