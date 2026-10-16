package gitproxy

// pushscan.go: a push must not carry a credential the run holds (Task 20436).
//
// # The hole
//
// The proxy decided on a push's command section and streamed its pack to the
// forge unread. A workload holds its leased credentials in plaintext by design —
// the env secrets it was granted, the bearer token in its kubeconfig, its
// registry auth, its egress proxy's password — so a workload that commits one
// and pushes publishes it, possibly to a public repository, through the one
// choke point every proxied push crosses. GitHub's push protection knows vendor
// shapes, and only where it is enabled; an internal API key granted as an env
// secret matches nothing it knows.
//
// # What is matched
//
// The exact values the hub delivered to the run, which the hub knows and no
// shape registry can: every env value a lease delivered, the tokens and client
// keys in a delivered kubeconfig, registry auth, egress proxy credentials, and
// — as defence in depth, since the proxy holds them — the session's own
// upstream PAT or App token. Each value also in the encodings a commit is
// likely to carry it in: base64 at every alignment, both alphabets, and
// percent-encoded. A value shorter than redact.MinLen matches nothing.
//
// Shapes mode adds pkg/redact's credential registry on top. It is opt-in
// because a repository's own test fixtures carry realistic fake keys — this
// one's do — and a mode that refused those would be turned off.
//
// # How a push is decided
//
// The pack is inflated as it streams through the proxy; nothing is buffered
// whole. Every object is scanned: commits, trees, blobs and tags in full, and
// for a delta the bytes it inserts. A delta's copied ranges come from an
// object that is either in the same pack, where it was scanned in its own
// right, or already on the forge, where it was published before this push. A
// value split across a copy and an insert is the residual that leaves (see
// docs/architecture/git-proxy.md).
//
// The forge gets the pack as it arrives except its last checksum, which the
// proxy holds until the scan ends. A pack without it is one receive-pack never
// accepts, so a refused push is aborted upstream and updates no ref. A scan
// that cannot finish — past a size or time limit, or a pack the proxy cannot
// read — refuses the push too: a scan that gave up is not a scan that found
// nothing.

import (
	"fmt"
	"strings"
	"time"
)

// ScanMode says what a push is scanned for.
type ScanMode string

const (
	// ScanOff forwards a push's pack unread, as the proxy did before Task
	// 20436.
	ScanOff ScanMode = "off"
	// ScanValues matches the exact values the run was delivered, in their
	// common encodings. The default whenever the proxy runs.
	ScanValues ScanMode = "values"
	// ScanShapes is ScanValues plus pkg/redact's credential registry.
	ScanShapes ScanMode = "shapes"
)

// Configuration keys behind the scan, named in refusals so the operator who
// reads one knows what to change. pkg/config's yaml tags spell the same keys,
// and a test there holds the two together.
const (
	SettingPushScan          = "executors.git_proxy.push_scan"
	SettingPushScanObjectMB  = "executors.git_proxy.push_scan_max_object_mb"
	SettingPushScanPushMB    = "executors.git_proxy.push_scan_max_push_mb"
	SettingPushScanSeconds   = "executors.git_proxy.push_scan_seconds"
	defaultPushScanObjectMB  = 1024
	defaultPushScanPushMB    = 4096
	defaultPushScanSeconds   = 300
	maxPushScanFindings      = 16
	pushScanMiB              = 1 << 20
	pushScanReportObjectHex  = 12
	pushScanIdleReadDeadline = 2 * time.Minute
)

// Default limits. A push is refused past any of them.
const (
	// DefaultScanMaxObjectBytes bounds one object's inflated bytes.
	DefaultScanMaxObjectBytes int64 = defaultPushScanObjectMB * pushScanMiB
	// DefaultScanMaxPushBytes bounds a whole push's inflated bytes. It is
	// what stops a pack built to inflate a thousandfold from holding a core.
	DefaultScanMaxPushBytes int64 = defaultPushScanPushMB * pushScanMiB
	// DefaultScanMaxDuration bounds the time spent scanning — inflating and
	// matching — not the time spent waiting on the sandbox or the forge, so
	// a slow link does not count against it.
	DefaultScanMaxDuration = defaultPushScanSeconds * time.Second
)

// ParseScanMode reads a configured mode. Empty is ScanValues: scanning is the
// default whenever the proxy runs, and switching it off has to be written down.
func ParseScanMode(s string) (ScanMode, error) {
	switch m := ScanMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return ScanValues, nil
	case ScanOff, ScanValues, ScanShapes:
		return m, nil
	default:
		return "", fmt.Errorf("%s must be %q, %q or %q, not %q", SettingPushScan, ScanValues, ScanShapes, ScanOff, s)
	}
}

// rank orders modes by how much they refuse.
func (m ScanMode) rank() int {
	switch m {
	case ScanOff:
		return 0
	case ScanShapes:
		return 2
	default:
		// Empty and anything unrecognised scan values: a mode nobody can name
		// must not read as off.
		return 1
	}
}

// Normalize returns m as one of the three modes, unrecognised values reading
// as ScanValues.
func (m ScanMode) Normalize() ScanMode {
	switch m.rank() {
	case 0:
		return ScanOff
	case 2:
		return ScanShapes
	default:
		return ScanValues
	}
}

// StricterScanMode returns the stricter of a and b. It is how a project's own
// setting combines with the hub's: a project may tighten the scan and never
// loosen it.
func StricterScanMode(a, b ScanMode) ScanMode {
	if b.rank() > a.rank() {
		return b.Normalize()
	}
	return a.Normalize()
}

// ScanSecret is one value a push must not carry, and where it came from.
//
// Value is plaintext and stays in memory: it is never logged, persisted,
// audited or echoed, and nothing in this package renders it. The other fields
// are what a refusal names instead.
type ScanSecret struct {
	Value string
	// Grant and Secret name the grant and the secret the run was delivered
	// the value through. Either may be empty for a value no grant carried —
	// the session's own token, or an egress session's.
	Grant  string
	Secret string
	// Field says which part of the delivery it is: "env API_KEY", "the
	// kubeconfig's token for user ci", "the session's upstream token".
	Field string
}

// describe names a secret's provenance for a refusal, without its value.
func (s ScanSecret) describe() string {
	field := strings.TrimSpace(s.Field)
	if field == "" {
		field = "a credential"
	}
	var parts []string
	if name := strings.TrimSpace(s.Secret); name != "" {
		parts = append(parts, fmt.Sprintf("secret %q", name))
	}
	if g := strings.TrimSpace(s.Grant); g != "" {
		parts = append(parts, "grant "+g)
	}
	if len(parts) == 0 {
		return field
	}
	return field + " (" + strings.Join(parts, ", ") + ")"
}

// ScanLimits bounds a scan. Zero fields take the defaults.
type ScanLimits struct {
	MaxObjectBytes int64
	MaxPushBytes   int64
	MaxDuration    time.Duration
}

// withDefaults fills unset limits.
func (l ScanLimits) withDefaults() ScanLimits {
	if l.MaxObjectBytes <= 0 {
		l.MaxObjectBytes = DefaultScanMaxObjectBytes
	}
	if l.MaxPushBytes <= 0 {
		l.MaxPushBytes = DefaultScanMaxPushBytes
	}
	if l.MaxDuration <= 0 {
		l.MaxDuration = DefaultScanMaxDuration
	}
	return l
}

// PushScan is how one push through a session is scanned.
type PushScan struct {
	Mode ScanMode
	// Secrets are the values the session's run holds. The session's own
	// upstream credential is added to them by the proxy.
	Secrets []ScanSecret
	Limits  ScanLimits
}

// PushScanFunc decides how a push through sess is scanned. The proxy calls it
// once per push, on the request goroutine.
type PushScanFunc func(sess *Session) PushScan

// ScanFinding is one place a refused push carries a credential. It names
// objects and provenance, never the value.
type ScanFinding struct {
	// Object is the object's id. Empty for a delta, whose id the proxy does
	// not resolve: it would need the base, which may be on the forge.
	Object string `json:"object,omitempty"`
	// Type is commit, tree, blob or tag, or "delta".
	Type string `json:"type"`
	// Base is what a delta is a delta against: an object id, or the pack
	// offset of an object in the same pack whose id is not known.
	Base string `json:"base,omitempty"`
	// Where says which part of the push carries it: "content", "message",
	// "an inserted range", "a ref name", "a push option".
	Where string `json:"where"`
	// Path is where a tree in the same pack names the object: the full path
	// when every tree above it is in the pack whole, or its name alone when
	// only a delta inserting it was seen.
	Path string `json:"path,omitempty"`
	// PathPartial reports that Path is the object's name alone.
	PathPartial bool `json:"path_partial,omitempty"`
	// Commit is the commit that carries the object, when the pack says.
	Commit string `json:"commit,omitempty"`
	// Ref is the ref a finding in the command section is about, or the ref
	// whose tip is named when the carrying commit could not be told.
	Ref string `json:"ref,omitempty"`
	// Tag is an annotated tag's name, for a finding in a tag object.
	Tag string `json:"tag,omitempty"`
	// Grant, Secret and Field are the matched value's provenance; Form is
	// the encoding it was found in ("as delivered", "base64",
	// "percent-encoded", "a line of a PEM block"). A shapes-mode finding
	// carries the detector's label in Field and no grant.
	Grant  string `json:"grant,omitempty"`
	Secret string `json:"secret,omitempty"`
	Field  string `json:"field"`
	Form   string `json:"form,omitempty"`
}

// summary renders a finding as one line.
func (f ScanFinding) summary() string {
	var b strings.Builder
	switch {
	case f.Where == whereRef:
		b.WriteString("the ref name " + f.Ref)
	case f.Where == wherePushOption:
		b.WriteString("a push option")
	case f.Type == "delta":
		b.WriteString("a delta")
		if f.Base != "" {
			b.WriteString(" against " + abbreviate(f.Base))
		}
	default:
		b.WriteString(f.Type)
		if f.Object != "" {
			b.WriteString(" " + abbreviate(f.Object))
		}
	}
	if f.Tag != "" {
		b.WriteString(" (tag " + f.Tag + ")")
	}
	if f.Path != "" {
		if f.PathPartial {
			b.WriteString(" (named " + f.Path + ")")
		} else {
			b.WriteString(" (" + f.Path + ")")
		}
	}
	switch {
	case f.Commit != "" && f.Type != "commit":
		b.WriteString(" in commit " + abbreviate(f.Commit))
	case f.Commit == "" && f.Ref != "" && f.Where != whereRef:
		b.WriteString(" pushed to " + f.Ref)
	}
	if f.Where != "" && f.Where != whereContent && f.Where != whereRef && f.Where != wherePushOption {
		b.WriteString(", in its " + f.Where)
	}
	b.WriteString(": ")
	b.WriteString(ScanSecret{Grant: f.Grant, Secret: f.Secret, Field: f.Field}.describe())
	if f.Form != "" && f.Form != formRaw {
		b.WriteString(", " + f.Form)
	}
	return b.String()
}

// abbreviate shortens an object id for a line a person reads.
func abbreviate(id string) string {
	if len(id) > pushScanReportObjectHex && validObjectName(id) {
		return id[:pushScanReportObjectHex]
	}
	return id
}

// Where a finding sits.
const (
	whereContent    = "content"
	whereMessage    = "message"
	whereInsert     = "inserted bytes"
	whereEntryName  = "entry names"
	whereRef        = "ref name"
	wherePushOption = "push option"
)
