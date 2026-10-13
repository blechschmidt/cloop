package config

// audit.forward: where the hub ships its audit trail as it is written
// (Task 20426).
//
// Until this section existed the content of the trail left the hub only when an
// operator scheduled `cloop audit-log export | logger`. Checkpoints (Task 20404)
// pin a chain's length, not its content, so whoever could write state.db could
// still delete rows nobody had exported. A sink here is the off-box copy: the
// cluster leader tails every chain and sends each row to every sink, advancing a
// durable cursor only once the sink has acknowledged it (pkg/auditforward).
//
// Three rules shape what a sink may say, and all three are enforced here, at
// load, rather than discovered at the first send:
//
//   - No credential in the file. A sink names its HEC token or TLS client key
//     as a secret in the hub's secret store (token_secret, client_key_secret).
//     There is no field that could hold one, and a URL carrying userinfo is
//     refused for the same reason.
//   - No plaintext off the host. syslog over plain TCP and https:// spelled
//     http:// are refused unless the host is loopback *and* the sink says
//     allow_plaintext_loopback: true — a local collector (an rsyslog or a
//     Splunk forwarder on the same machine) is the one place plaintext is a
//     deployment choice rather than a leak.
//   - A file sink lives outside every .cloop/ directory, for the reason the
//     checkpoint file does: a copy whoever rewrites the database can also
//     rewrite is no copy.
//
// Load does not refuse to start over a bad sink. It drops the sink and records
// the switch-off (LoadRepair.SwitchedOff), which `cloop hub doctor` reports as a
// failure: forwarding to a sink the operator did not ask for — or in a way they
// did not ask for — is the outcome that must never happen, and an absent sink
// is loud everywhere the forwarder reports.

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// Bounds and defaults for audit.forward.
const (
	// AuditForwardMaxSinks bounds how many sinks a hub forwards to. Each one
	// is a goroutine, a connection, a cursor per chain and a label value on
	// three metric families, so the bound is part of what keeps the metrics
	// registry's cardinality closed.
	AuditForwardMaxSinks = 16

	// Rows per batch: a batch is what is read from the database, sent, and
	// acknowledged as one, so it is also what a leader killed mid-send
	// repeats.
	AuditForwardBatchSizeDefault = 500
	AuditForwardBatchSizeLower   = 1
	AuditForwardBatchSizeUpper   = 5000

	// Bytes per batch, for the https and file sinks. A batch always holds at
	// least one row, however large.
	AuditForwardMaxBatchBytesDefault = 1 << 20
	AuditForwardMaxBatchBytesLower   = 64 << 10
	AuditForwardMaxBatchBytesUpper   = 64 << 20

	// Bytes per syslog message, frame excluded. RFC 5425 §4.3.1 obliges a
	// receiver to accept 2048 octets and says it SHOULD accept 8192; a row
	// that does not fit is sent with its payload cut and says so.
	AuditForwardMaxMessageBytesDefault = 8192
	AuditForwardMaxMessageBytesLower   = 2048
	AuditForwardMaxMessageBytesUpper   = 1 << 20

	// How long one send may take before it counts as failed.
	AuditForwardTimeoutDefault = 30 * time.Second
	AuditForwardTimeoutLower   = time.Second
	AuditForwardTimeoutUpper   = 10 * time.Minute

	// How far a sink may fall behind before `cloop hub doctor` warns: the age
	// of the oldest row it has not acknowledged.
	AuditForwardMaxLagDefault = 15 * time.Minute
	AuditForwardMaxLagLower   = time.Minute
	AuditForwardMaxLagUpper   = 7 * 24 * time.Hour
)

// Sink types.
const (
	AuditSinkSyslog = "syslog"
	AuditSinkHTTPS  = "https"
	AuditSinkFile   = "file"
)

// Body formats.
const (
	// AuditFormatJSON is one JSON object per row: the record
	// `cloop audit-log export --format jsonl` writes, with the chain it came
	// from. Lossless.
	AuditFormatJSON = "json"
	// AuditFormatCEF is the ArcSight Common Event Format line
	// `cloop audit-log export --format cef` writes. Payloads are truncated.
	AuditFormatCEF = "cef"
)

// Syslog transports.
const (
	AuditTransportTLS = "tls"
	AuditTransportTCP = "tcp"
)

// AuditVariantSplunkHEC sends the https sink's rows to a Splunk HTTP Event
// Collector, each wrapped in the envelope HEC expects.
const AuditVariantSplunkHEC = "splunk_hec"

// How the https sink presents its token.
const (
	// AuditAuthBearer: Authorization: Bearer <token>.
	AuditAuthBearer = "bearer"
	// AuditAuthAPIKey: Authorization: ApiKey <token>, as Elasticsearch takes
	// an encoded API key.
	AuditAuthAPIKey = "apikey"
	// AuditAuthBasic: the token is "user:password", sent as HTTP Basic.
	AuditAuthBasic = "basic"
	// AuditAuthSplunk: Authorization: Splunk <token>, the HEC scheme.
	AuditAuthSplunk = "splunk"
)

// Where a sink begins on a chain it has never sent.
const (
	// AuditStartOldest sends every row still in the database.
	AuditStartOldest = "oldest"
	// AuditStartLatest begins at the chain's head when the forwarder first
	// sees it; what came before is backfilled with `cloop audit-log export`.
	AuditStartLatest = "latest"
)

// AuditForwardConfig is the audit.forward section.
type AuditForwardConfig struct {
	// Sinks receive every row of every chain the hub serves.
	Sinks []AuditForwardSink `yaml:"sinks,omitempty"`

	// MaxLag is how old the oldest unacknowledged row may be before `cloop
	// hub doctor` warns about a sink, as a Go duration. Empty means
	// AuditForwardMaxLagDefault.
	MaxLag string `yaml:"max_lag,omitempty"`

	// Hostname names this hub in what it sends: the HOSTNAME of every syslog
	// message, "hub" in every JSON record, the HEC host. Empty means the
	// machine's host name — which changes with the cluster leader, so a
	// cluster should set it.
	Hostname string `yaml:"hostname,omitempty"`
}

// AuditForwardSink is one destination.
type AuditForwardSink struct {
	// Name identifies the sink: its cursors, its metric label and its rows in
	// the audit trail. Lower-case letters, digits, '-' and '_'.
	Name string `yaml:"name"`

	// Type is syslog, https or file.
	Type string `yaml:"type"`

	// Format is json (the default) or cef. An https sink sends json.
	Format string `yaml:"format,omitempty"`

	// ── syslog ──

	// Address is host:port of an RFC 5425 receiver (6514 is the registered
	// port for syslog over TLS).
	Address string `yaml:"address,omitempty"`

	// Transport is tls (the default) or tcp. tcp is plaintext and is refused
	// unless Address is loopback and AllowPlaintextLoopback is set.
	Transport string `yaml:"transport,omitempty"`

	// Facility is the syslog facility name. Empty means local0.
	Facility string `yaml:"facility,omitempty"`

	// AppName is the RFC 5424 APP-NAME. Empty means "cloop".
	AppName string `yaml:"app_name,omitempty"`

	// MaxMessageBytes bounds one syslog message. Zero means
	// AuditForwardMaxMessageBytesDefault.
	MaxMessageBytes int `yaml:"max_message_bytes,omitempty"`

	// ── https ──

	// URL receives each batch as one POST. http:// is refused unless the
	// host is loopback and AllowPlaintextLoopback is set.
	URL string `yaml:"url,omitempty"`

	// Variant is empty for an NDJSON body, or splunk_hec.
	Variant string `yaml:"variant,omitempty"`

	// TokenSecret names the secret in the hub's secret store holding the
	// token the sink presents: "name", or "name#KEY" for one key of an env
	// secret holding several. Empty sends no Authorization header.
	TokenSecret string `yaml:"token_secret,omitempty"`

	// AuthScheme is how the token is presented: bearer (the default), apikey,
	// basic or splunk. A splunk_hec sink always uses splunk.
	AuthScheme string `yaml:"auth_scheme,omitempty"`

	// SplunkIndex, SplunkSourceType and SplunkSource fill the HEC envelope.
	// Empty leaves the index to the token's default, and the source type and
	// source as "cloop:audit" and "cloop".
	SplunkIndex      string `yaml:"splunk_index,omitempty"`
	SplunkSourceType string `yaml:"splunk_sourcetype,omitempty"`
	SplunkSource     string `yaml:"splunk_source,omitempty"`

	// MaxBatchBytes bounds one POST body or one file append. Zero means
	// AuditForwardMaxBatchBytesDefault.
	MaxBatchBytes int `yaml:"max_batch_bytes,omitempty"`

	// ── file ──

	// Path is the file rows are appended to, fsynced after each batch. It
	// must be absolute and outside every .cloop/ directory.
	Path string `yaml:"path,omitempty"`

	// ── TLS (syslog over tls, https) ──

	// CAFile adds a PEM bundle to the system roots for this sink.
	CAFile string `yaml:"ca_file,omitempty"`

	// ClientCert is a PEM certificate presented to the receiver; its key is
	// the secret ClientKeySecret names. Both or neither.
	ClientCert      string `yaml:"client_cert,omitempty"`
	ClientKeySecret string `yaml:"client_key_secret,omitempty"`

	// ServerName overrides the name the receiver's certificate is checked
	// against, for a receiver dialled by address.
	ServerName string `yaml:"server_name,omitempty"`

	// AllowPlaintextLoopback acknowledges a plaintext sink on a loopback
	// address. It never permits plaintext to any other host.
	AllowPlaintextLoopback bool `yaml:"allow_plaintext_loopback,omitempty"`

	// ── delivery ──

	// BatchSize is rows per batch. Zero means AuditForwardBatchSizeDefault.
	BatchSize int `yaml:"batch_size,omitempty"`

	// Timeout bounds one send, as a Go duration. Empty means
	// AuditForwardTimeoutDefault.
	Timeout string `yaml:"timeout,omitempty"`

	// Start is where the sink begins on a chain it has never sent: oldest
	// (the default) or latest.
	Start string `yaml:"start,omitempty"`
}

// auditSinkNameRE is the sink name rule. Lower-case only, so a name is one
// metric label value and one cursor key however it was typed.
var auditSinkNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// auditSecretNameRE mirrors secretbroker.ValidateName, which pkg/config cannot
// import; auditEnvKeyRE an environment variable name.
var (
	auditSecretNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	auditEnvKeyRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// syslogFacilities maps RFC 5424 facility names to codes.
var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"ntp": 12, "audit": 13, "alert": 14, "clock": 15,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// SyslogFacility returns the facility code of a name, and whether it is one.
func SyslogFacility(name string) (int, bool) {
	code, ok := syslogFacilities[strings.ToLower(strings.TrimSpace(name))]
	return code, ok
}

// EffectiveFormat is the body format in force.
func (s AuditForwardSink) EffectiveFormat() string {
	if f := strings.ToLower(strings.TrimSpace(s.Format)); f != "" {
		return f
	}
	return AuditFormatJSON
}

// EffectiveTransport is the syslog transport in force.
func (s AuditForwardSink) EffectiveTransport() string {
	if t := strings.ToLower(strings.TrimSpace(s.Transport)); t != "" {
		return t
	}
	return AuditTransportTLS
}

// EffectiveFacility is the syslog facility code in force.
func (s AuditForwardSink) EffectiveFacility() int {
	if code, ok := SyslogFacility(s.Facility); ok {
		return code
	}
	return syslogFacilities["local0"]
}

// EffectiveAppName is the RFC 5424 APP-NAME in force.
func (s AuditForwardSink) EffectiveAppName() string {
	if a := strings.TrimSpace(s.AppName); a != "" {
		return a
	}
	return "cloop"
}

// EffectiveAuthScheme is how the https sink presents its token.
func (s AuditForwardSink) EffectiveAuthScheme() string {
	if strings.EqualFold(strings.TrimSpace(s.Variant), AuditVariantSplunkHEC) {
		return AuditAuthSplunk
	}
	if a := strings.ToLower(strings.TrimSpace(s.AuthScheme)); a != "" {
		return a
	}
	return AuditAuthBearer
}

// EffectiveBatchSize is rows per batch.
func (s AuditForwardSink) EffectiveBatchSize() int {
	if s.BatchSize >= AuditForwardBatchSizeLower && s.BatchSize <= AuditForwardBatchSizeUpper {
		return s.BatchSize
	}
	return AuditForwardBatchSizeDefault
}

// EffectiveMaxBatchBytes is bytes per batch.
func (s AuditForwardSink) EffectiveMaxBatchBytes() int {
	if s.MaxBatchBytes >= AuditForwardMaxBatchBytesLower && s.MaxBatchBytes <= AuditForwardMaxBatchBytesUpper {
		return s.MaxBatchBytes
	}
	return AuditForwardMaxBatchBytesDefault
}

// EffectiveMaxMessageBytes is bytes per syslog message.
func (s AuditForwardSink) EffectiveMaxMessageBytes() int {
	if s.MaxMessageBytes >= AuditForwardMaxMessageBytesLower && s.MaxMessageBytes <= AuditForwardMaxMessageBytesUpper {
		return s.MaxMessageBytes
	}
	return AuditForwardMaxMessageBytesDefault
}

// EffectiveTimeout bounds one send.
func (s AuditForwardSink) EffectiveTimeout() time.Duration {
	d, err := parseBoundedDuration(s.Timeout, AuditForwardTimeoutLower, AuditForwardTimeoutUpper)
	if err != nil || d == 0 {
		return AuditForwardTimeoutDefault
	}
	return d
}

// EffectiveStart is where the sink begins on a chain it has never sent.
func (s AuditForwardSink) EffectiveStart() string {
	if strings.EqualFold(strings.TrimSpace(s.Start), AuditStartLatest) {
		return AuditStartLatest
	}
	return AuditStartOldest
}

// Plaintext reports whether the sink sends without TLS.
func (s AuditForwardSink) Plaintext() bool {
	switch strings.ToLower(strings.TrimSpace(s.Type)) {
	case AuditSinkSyslog:
		return s.EffectiveTransport() == AuditTransportTCP
	case AuditSinkHTTPS:
		u, err := url.Parse(strings.TrimSpace(s.URL))
		return err == nil && strings.EqualFold(u.Scheme, "http")
	}
	return false
}

// Endpoint names where the sink sends, for status lines and the audit trail:
// the URL, the address, or the path. A URL is rendered without userinfo,
// which validation refuses anyway.
func (s AuditForwardSink) Endpoint() string {
	switch strings.ToLower(strings.TrimSpace(s.Type)) {
	case AuditSinkSyslog:
		return s.EffectiveTransport() + "://" + strings.TrimSpace(s.Address)
	case AuditSinkHTTPS:
		if u, err := url.Parse(strings.TrimSpace(s.URL)); err == nil {
			// Without the query string: what a status line or an audit row
			// says about where rows go is the collector, not its parameters.
			u.RawQuery, u.ForceQuery = "", false
			return u.Redacted()
		}
		return strings.TrimSpace(s.URL)
	case AuditSinkFile:
		return strings.TrimSpace(s.Path)
	}
	return ""
}

// StoreRefs lists the secret-store references the sink reads, in a stable
// order: its token, then its client key.
func (s AuditForwardSink) StoreRefs() []string {
	var out []string
	for _, r := range []string{s.TokenSecret, s.ClientKeySecret} {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// EffectiveMaxLag is the doctor's bound in force.
func (c AuditForwardConfig) EffectiveMaxLag() time.Duration {
	d, err := parseBoundedDuration(c.MaxLag, AuditForwardMaxLagLower, AuditForwardMaxLagUpper)
	if err != nil || d == 0 {
		return AuditForwardMaxLagDefault
	}
	return d
}

// SplitSecretRef splits "name#KEY" into its parts; KEY is empty for a bare
// name.
func SplitSecretRef(ref string) (name, key string) {
	name, key, _ = strings.Cut(strings.TrimSpace(ref), "#")
	return name, key
}

// validateSecretRef checks a secret-store reference's syntax. Whether it names
// a secret that exists, of the right kind, is the forwarder's question.
func validateSecretRef(ref string) error {
	name, key := SplitSecretRef(ref)
	if !auditSecretNameRE.MatchString(name) {
		return fmt.Errorf("%q is not a secret name (letters, digits, '-', '_', '.'; optionally #KEY)", ref)
	}
	if strings.Contains(ref, "#") && !auditEnvKeyRE.MatchString(key) {
		return fmt.Errorf("%q names key %q, which is not an environment variable name", ref, key)
	}
	return nil
}

// parseBoundedDuration parses a duration that must lie in [lower, upper];
// "" is 0.
func parseBoundedDuration(s string, lower, upper time.Duration) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (e.g. 30s, 15m)", s)
	}
	if d < lower || d > upper {
		return 0, fmt.Errorf("%s is outside [%s, %s]", d, lower, upper)
	}
	return d, nil
}

// validSyslogToken reports whether s is 1..max printable US-ASCII characters
// with no space: RFC 5424's PRINTUSASCII fields (HOSTNAME, APP-NAME).
func validSyslogToken(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// validHECField reports whether s may fill a HEC envelope field.
func validHECField(s string) bool {
	if len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidateAuditForwardFile reports why path cannot receive forwarded rows: it
// must be absolute and must not lie inside any .cloop/ directory. Symlinks are
// resolved where the rows are written, because the file need not exist yet.
func ValidateAuditForwardFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("a file sink needs a path")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%q must be an absolute path", path)
	}
	if PathInsideCloopDir(path) {
		return fmt.Errorf("%q lies inside a .cloop/ directory; forwarded rows must be kept outside it, "+
			"where whoever can rewrite the database cannot also rewrite them", path)
	}
	return nil
}

// CheckOutsideCloopOnDisk applies the outside-.cloop rule to path after
// resolving symlinks — in its directory and, when it exists, in the file
// itself — so a link cannot walk a record kept off the database back in beside
// it. An existing path must be a regular file: appending to a device or a FIFO
// is not keeping a record. A file that resolves nowhere yet is refused rather
// than trusted, because appending follows the link and creates its target.
//
// path has already passed the lexical rule (ValidateAuditCheckpointFile,
// ValidateAuditForwardFile). Shared by the checkpoint file and the audit
// forwarder's file sink.
func CheckOutsideCloopOnDisk(path string) error {
	dir := filepath.Dir(filepath.Clean(path))
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("directory %s: %w", dir, err)
	}
	if PathInsideCloopDir(real) {
		return fmt.Errorf("%q resolves to %s, inside a .cloop/ directory", path, real)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("%q is a symlink that does not resolve: %v", path, err)
			}
			if PathInsideCloopDir(target) {
				return fmt.Errorf("%q resolves to %s, inside a .cloop/ directory", path, target)
			}
			if fi, err = os.Stat(target); err != nil {
				return fmt.Errorf("%q: %v", path, err)
			}
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file", path)
		}
	}
	return nil
}

// plaintextRefusal explains why a plaintext endpoint on host is refused, or
// returns nil when it is a loopback host the sink acknowledged.
func plaintextRefusal(host string, acked bool, what string) error {
	if !tlsconf.IsLoopbackHost(host) {
		return fmt.Errorf("%s is plaintext to %q, which is not a loopback address: every row would cross the "+
			"network readable and alterable by anything on the path — use TLS", what, host)
	}
	if !acked {
		return fmt.Errorf("%s is plaintext to loopback %q; acknowledge it with allow_plaintext_loopback: true, "+
			"or use TLS", what, host)
	}
	return nil
}

// ValidateAuditForwardSink is the strict check of one sink.
func ValidateAuditForwardSink(s AuditForwardSink) error {
	name := strings.TrimSpace(s.Name)
	if !auditSinkNameRE.MatchString(name) {
		return fmt.Errorf("name %q must be 1-32 lower-case letters, digits, '-' or '_', starting with a letter or digit", s.Name)
	}
	format := s.EffectiveFormat()
	if format != AuditFormatJSON && format != AuditFormatCEF {
		return fmt.Errorf("format %q is not one of json, cef", s.Format)
	}
	if s.BatchSize != 0 && (s.BatchSize < AuditForwardBatchSizeLower || s.BatchSize > AuditForwardBatchSizeUpper) {
		return fmt.Errorf("batch_size %d is outside [%d, %d]", s.BatchSize, AuditForwardBatchSizeLower, AuditForwardBatchSizeUpper)
	}
	if _, err := parseBoundedDuration(s.Timeout, AuditForwardTimeoutLower, AuditForwardTimeoutUpper); err != nil {
		return fmt.Errorf("timeout: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(s.Start)) {
	case "", AuditStartOldest, AuditStartLatest:
	default:
		return fmt.Errorf("start %q is not one of oldest, latest", s.Start)
	}
	if s.ClientCert != "" || s.ClientKeySecret != "" {
		if s.ClientCert == "" || s.ClientKeySecret == "" {
			return fmt.Errorf("client_cert and client_key_secret go together: the certificate is presented with the key the secret holds")
		}
		if !filepath.IsAbs(s.ClientCert) {
			return fmt.Errorf("client_cert %q must be an absolute path", s.ClientCert)
		}
		if err := validateSecretRef(s.ClientKeySecret); err != nil {
			return fmt.Errorf("client_key_secret: %w", err)
		}
	}
	if s.CAFile != "" && !filepath.IsAbs(s.CAFile) {
		return fmt.Errorf("ca_file %q must be an absolute path", s.CAFile)
	}
	tlsFields := s.CAFile != "" || s.ClientCert != "" || s.ServerName != ""

	switch strings.ToLower(strings.TrimSpace(s.Type)) {
	case AuditSinkSyslog:
		return validateSyslogSink(s, tlsFields)
	case AuditSinkHTTPS:
		return validateHTTPSSink(s, format, tlsFields)
	case AuditSinkFile:
		if tlsFields || s.TokenSecret != "" || s.URL != "" || s.Address != "" {
			return fmt.Errorf("a file sink takes a path and nothing that dials")
		}
		return ValidateAuditForwardFile(s.Path)
	case "":
		return fmt.Errorf("type is required: syslog, https or file")
	default:
		return fmt.Errorf("type %q is not one of syslog, https, file", s.Type)
	}
}

func validateSyslogSink(s AuditForwardSink, tlsFields bool) error {
	if s.URL != "" || s.Path != "" || s.TokenSecret != "" || s.Variant != "" {
		return fmt.Errorf("a syslog sink takes an address; url, path, variant and token_secret belong to other types")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(s.Address))
	if err != nil || host == "" {
		return fmt.Errorf("address %q is not host:port", s.Address)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("address %q has no valid port", s.Address)
	}
	switch s.EffectiveTransport() {
	case AuditTransportTLS:
	case AuditTransportTCP:
		if tlsFields {
			return fmt.Errorf("ca_file, client_cert and server_name need transport: tls")
		}
		if err := plaintextRefusal(host, s.AllowPlaintextLoopback, "transport tcp"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("transport %q is not one of tls, tcp", s.Transport)
	}
	if s.Facility != "" {
		if _, ok := SyslogFacility(s.Facility); !ok {
			return fmt.Errorf("facility %q is not a syslog facility (e.g. local0, auth, audit)", s.Facility)
		}
	}
	if s.AppName != "" && !validSyslogToken(s.AppName, 48) {
		return fmt.Errorf("app_name %q must be 1-48 printable ASCII characters without spaces", s.AppName)
	}
	if s.MaxMessageBytes != 0 && (s.MaxMessageBytes < AuditForwardMaxMessageBytesLower || s.MaxMessageBytes > AuditForwardMaxMessageBytesUpper) {
		return fmt.Errorf("max_message_bytes %d is outside [%d, %d]", s.MaxMessageBytes,
			AuditForwardMaxMessageBytesLower, AuditForwardMaxMessageBytesUpper)
	}
	return nil
}

func validateHTTPSSink(s AuditForwardSink, format string, tlsFields bool) error {
	if s.Address != "" || s.Path != "" || s.Transport != "" || s.Facility != "" || s.AppName != "" {
		return fmt.Errorf("an https sink takes a url; address, path, transport, facility and app_name belong to other types")
	}
	if format != AuditFormatJSON {
		return fmt.Errorf("an https sink sends json (NDJSON, or HEC events); format %q is for syslog and file sinks", s.Format)
	}
	raw := strings.TrimSpace(s.URL)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("url %q is not an absolute http(s) URL", s.URL)
	}
	if u.User != nil {
		return fmt.Errorf("url carries credentials; put the token in the secret store and name it in token_secret")
	}
	if u.Fragment != "" {
		return fmt.Errorf("url %q has a fragment, which is never sent", u.Redacted())
	}
	for name := range u.Query() {
		if credentialParam(name) {
			return fmt.Errorf("url passes %q as a query parameter, which reads as a credential; put it in the "+
				"secret store and name it in token_secret", name)
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if tlsFields {
			return fmt.Errorf("ca_file, client_cert and server_name need an https url")
		}
		if err := plaintextRefusal(u.Hostname(), s.AllowPlaintextLoopback, "url "+u.Redacted()); err != nil {
			return err
		}
	default:
		return fmt.Errorf("url %q must be https:// (or http:// to a loopback collector)", u.Redacted())
	}
	switch strings.ToLower(strings.TrimSpace(s.Variant)) {
	case "":
		if s.SplunkIndex != "" || s.SplunkSourceType != "" || s.SplunkSource != "" {
			return fmt.Errorf("splunk_index, splunk_sourcetype and splunk_source need variant: splunk_hec")
		}
	case AuditVariantSplunkHEC:
		if s.TokenSecret == "" {
			return fmt.Errorf("a splunk_hec sink needs token_secret: HEC refuses a request without its token")
		}
		if a := strings.ToLower(strings.TrimSpace(s.AuthScheme)); a != "" && a != AuditAuthSplunk {
			return fmt.Errorf("a splunk_hec sink presents its token as auth_scheme splunk, not %q", s.AuthScheme)
		}
		for _, f := range []struct{ key, v string }{
			{"splunk_index", s.SplunkIndex}, {"splunk_sourcetype", s.SplunkSourceType}, {"splunk_source", s.SplunkSource},
		} {
			if !validHECField(f.v) {
				return fmt.Errorf("%s must be at most 128 characters with no control characters", f.key)
			}
		}
	default:
		return fmt.Errorf("variant %q is not splunk_hec (or empty for NDJSON)", s.Variant)
	}
	switch strings.ToLower(strings.TrimSpace(s.AuthScheme)) {
	case "", AuditAuthBearer, AuditAuthAPIKey, AuditAuthBasic, AuditAuthSplunk:
	default:
		return fmt.Errorf("auth_scheme %q is not one of bearer, apikey, basic, splunk", s.AuthScheme)
	}
	if s.AuthScheme != "" && s.TokenSecret == "" {
		return fmt.Errorf("auth_scheme %q presents a token, but no token_secret names one", s.AuthScheme)
	}
	if s.TokenSecret != "" {
		if err := validateSecretRef(s.TokenSecret); err != nil {
			return fmt.Errorf("token_secret: %w", err)
		}
	}
	if s.MaxBatchBytes != 0 && (s.MaxBatchBytes < AuditForwardMaxBatchBytesLower || s.MaxBatchBytes > AuditForwardMaxBatchBytesUpper) {
		return fmt.Errorf("max_batch_bytes %d is outside [%d, %d]", s.MaxBatchBytes,
			AuditForwardMaxBatchBytesLower, AuditForwardMaxBatchBytesUpper)
	}
	return nil
}

// credentialParamWords are the fragments that make a query parameter's name
// read as a credential.
var credentialParamWords = []string{"token", "secret", "password", "passwd", "pwd", "key", "sig", "auth", "credential"}

// credentialParam reports whether a URL query parameter's name reads as a
// credential: a collector that takes its key as a parameter would otherwise
// have it written into config.yaml, the audit trail and every log line naming
// the sink.
func credentialParam(name string) bool {
	n := strings.ToLower(name)
	for _, w := range credentialParamWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// auditForwardSinkKey names a sink in a load repair: by name when it has a
// usable one, by position otherwise.
func auditForwardSinkKey(i int, s AuditForwardSink) string {
	if n := strings.TrimSpace(s.Name); auditSinkNameRE.MatchString(n) {
		return "audit.forward.sinks." + n
	}
	return fmt.Sprintf("audit.forward.sinks[%d]", i)
}

// ValidateAuditForward is the strict check of the audit.forward section,
// shared by `cloop config set` and `cloop config validate`.
func ValidateAuditForward(c AuditForwardConfig) error {
	if len(c.Sinks) > AuditForwardMaxSinks {
		return fmt.Errorf("audit.forward.sinks: %d sinks configured, at most %d", len(c.Sinks), AuditForwardMaxSinks)
	}
	seen := map[string]bool{}
	for i, s := range c.Sinks {
		key := auditForwardSinkKey(i, s)
		if err := ValidateAuditForwardSink(s); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		name := strings.TrimSpace(s.Name)
		if seen[name] {
			return fmt.Errorf("%s: the name is used by an earlier sink", key)
		}
		seen[name] = true
	}
	if _, err := parseBoundedDuration(c.MaxLag, AuditForwardMaxLagLower, AuditForwardMaxLagUpper); err != nil {
		return fmt.Errorf("audit.forward.max_lag: %w", err)
	}
	if c.Hostname != "" && !validSyslogToken(c.Hostname, 255) {
		return fmt.Errorf("audit.forward.hostname %q must be printable ASCII without spaces", c.Hostname)
	}
	return nil
}

// clampAuditForward is Load's repair of audit.forward. A sink that fails
// validation is dropped and recorded as switched off — never repaired into a
// sink nobody configured: a plaintext sink is not quietly upgraded to TLS, and
// a file inside .cloop/ is not quietly moved.
func (c *Config) clampAuditForward(path string, warn func(field, msg string)) {
	f := &c.Audit.Forward
	if _, err := parseBoundedDuration(f.MaxLag, AuditForwardMaxLagLower, AuditForwardMaxLagUpper); err != nil {
		warn("audit.forward.max_lag", err.Error())
		f.MaxLag = ""
	}
	if f.Hostname != "" && !validSyslogToken(f.Hostname, 255) {
		warn("audit.forward.hostname", fmt.Sprintf("%q is not printable ASCII without spaces; using the host name", f.Hostname))
		f.Hostname = ""
	}
	if len(f.Sinks) == 0 {
		return
	}
	kept := make([]AuditForwardSink, 0, len(f.Sinks))
	seen := map[string]bool{}
	for i, s := range f.Sinks {
		key := auditForwardSinkKey(i, s)
		err := ValidateAuditForwardSink(s)
		switch {
		case err != nil:
		case seen[strings.TrimSpace(s.Name)]:
			err = fmt.Errorf("the name is used by an earlier sink")
		case len(kept) >= AuditForwardMaxSinks:
			err = fmt.Errorf("at most %d sinks are forwarded to", AuditForwardMaxSinks)
		}
		if err != nil {
			detail := "refused at load: " + err.Error() + "; the sink is disabled"
			warn(key, detail)
			c.loadRepairs = append(c.loadRepairs, LoadRepair{
				File: path, Field: key, SwitchedOff: key, Detail: detail,
			})
			continue
		}
		s.Name = strings.TrimSpace(s.Name)
		seen[s.Name] = true
		kept = append(kept, s)
	}
	f.Sinks = kept
}
