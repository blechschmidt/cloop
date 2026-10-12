// Package kubeexec runs a kubeconfig's exec credential plugin on the
// developer's own machine and reads back the credential it prints, the way
// kubectl does (Task 20416).
//
// Managed clusters authenticate people through exec credential plugins:
// kubelogin on AKS with Entra ID, `aws eks get-token` on EKS,
// gke-gcloud-auth-plugin on GKE. The hub refuses such a kubeconfig, because
// running the plugin there would execute code named in an uploaded file on
// the control-plane host (pkg/executor/kubernetes.ParseKubeconfig). So the
// plugin is run here instead, by `cloop remote kube share` on the developer's
// machine, against the developer's own kubeconfig, as the developer — which
// is exactly where kubectl would have run it.
//
// Nothing the hub runs may import this package. tests/security asserts that:
// the guarantee "the hub never runs a credential plugin" is structural, not a
// promise that a code path is never taken.
//
// The protocol is client.authentication.k8s.io's ExecCredential, versions v1
// and v1beta1 (v1alpha1 was removed from Kubernetes in 1.24 and is refused
// with that said). The behaviour mirrors client-go's exec authenticator:
//
//   - KUBERNETES_EXEC_INFO carries an ExecCredential whose spec says whether
//     the plugin may interact with the user and, with provideClusterInfo, which
//     cluster it is authenticating to;
//   - interactiveMode decides whether the plugin gets this process's stdin:
//     Never, IfAvailable (when stdin is a terminal) or Always (and fail when it
//     is not); v1 requires the field, v1beta1 defaults it to IfAvailable;
//   - the plugin's stderr is the user's, so a device-code prompt reaches them;
//   - its stdout is the credential: a bearer token or a client certificate and
//     key, with an optional expirationTimestamp.
//
// A plugin's output is a credential. It is read under a size cap, never
// echoed into an error, and Credential's String method redacts it.
package kubeexec

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The ExecCredential API versions.
const (
	APIVersionV1       = "client.authentication.k8s.io/v1"
	APIVersionV1beta1  = "client.authentication.k8s.io/v1beta1"
	apiVersionV1alpha1 = "client.authentication.k8s.io/v1alpha1"
)

// ClusterExtensionName is the name of the cluster extension whose content is
// handed to a plugin with provideClusterInfo, as spec.cluster.config.
const ClusterExtensionName = "client.authentication.k8s.io/exec"

// InteractiveMode is the exec block's interactiveMode.
type InteractiveMode string

// The three interactive modes.
const (
	InteractiveNever       InteractiveMode = "Never"
	InteractiveIfAvailable InteractiveMode = "IfAvailable"
	InteractiveAlways      InteractiveMode = "Always"
)

// Limits.
const (
	// maxOutputBytes caps what is read of a plugin's stdout. An
	// ExecCredential is a few kilobytes even with a certificate chain in it; a
	// plugin that prints more is not printing one.
	maxOutputBytes = 1 << 20

	// DefaultTimeout bounds a plugin that may not interact with anyone.
	DefaultTimeout = 2 * time.Minute
	// DefaultInteractiveTimeout bounds one that may: a device-code sign-in
	// waits for a person to type a code into a browser.
	DefaultInteractiveTimeout = 10 * time.Minute
)

// EnvVar is one entry of the exec block's env list.
type EnvVar struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

// Config is a kubeconfig user's exec block.
type Config struct {
	APIVersion         string
	Command            string
	Args               []string
	Env                []EnvVar
	InstallHint        string
	ProvideClusterInfo bool
	InteractiveMode    InteractiveMode
	// Dir is the directory a relative command path resolves against: the
	// directory of the kubeconfig file the block came from, as kubectl does.
	// A bare name ("kubelogin") is looked up on PATH instead.
	Dir string
}

// Cluster is what a plugin with provideClusterInfo is told about the cluster
// it is authenticating to.
type Cluster struct {
	Server                   string
	TLSServerName            string
	InsecureSkipTLSVerify    bool
	CertificateAuthorityData []byte
	ProxyURL                 string
	DisableCompression       bool
	// Config is the cluster's client.authentication.k8s.io/exec extension, as
	// JSON. Nil when the cluster has none.
	Config json.RawMessage
}

// Credential is what a plugin printed.
type Credential struct {
	Token                 string
	ClientCertificateData []byte
	ClientKeyData         []byte
	// ExpiresAt is when the plugin said the credential stops working; zero
	// when it did not say.
	ExpiresAt time.Time
}

// String redacts the credential, so a %v of one cannot log it.
func (c *Credential) String() string {
	if c == nil {
		return "(no credential)"
	}
	kind := "bearer token"
	if c.Token == "" {
		kind = "client certificate"
	}
	if c.ExpiresAt.IsZero() {
		return kind + " [redacted]"
	}
	return fmt.Sprintf("%s [redacted], expires %s", kind, c.ExpiresAt.UTC().Format(time.RFC3339))
}

// GoString mirrors String.
func (c *Credential) GoString() string { return c.String() }

// Options are the runtime knobs. The zero value runs the plugin the way
// kubectl would in this process.
type Options struct {
	// Stdin is handed to an interactive plugin. Default os.Stdin.
	Stdin io.Reader
	// Stderr receives the plugin's own stderr: its prompts and its errors.
	// Default os.Stderr.
	Stderr io.Writer
	// Terminal reports whether Stdin is a terminal, which decides
	// IfAvailable and Always.
	Terminal bool
	// Timeout bounds the plugin. Zero picks DefaultTimeout, or
	// DefaultInteractiveTimeout when it may interact.
	Timeout time.Duration
	// Environ is the environment the plugin inherits before its own env
	// entries. Nil means os.Environ().
	Environ []string
	// Now is the clock an expiry is judged against. Nil means time.Now.
	Now func() time.Time
	// LookPath resolves a bare command name. Nil means exec.LookPath.
	LookPath func(string) (string, error)
}

// Errors a caller may want to tell apart.
var (
	// ErrNotFound is a plugin command that does not exist. Its message carries
	// the exec block's installHint, which is the one thing a person seeing it
	// needs.
	ErrNotFound = errors.New("exec credential plugin not found")
	// ErrMalformed is a plugin whose output is not a usable ExecCredential.
	ErrMalformed = errors.New("exec credential plugin printed no usable credential")
	// ErrExpired is a plugin that answered with a credential already past its
	// expiry.
	ErrExpired = errors.New("exec credential plugin returned an expired credential")
	// ErrInteractive is a plugin that needs a terminal this process has not got.
	ErrInteractive = errors.New("exec credential plugin needs an interactive terminal")
)

// execCredential is the wire shape both directions use. Only the fields this
// package reads or writes are declared.
type execCredential struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Spec       execCredentialSpec    `json:"spec"`
	Status     *execCredentialStatus `json:"status,omitempty"`
}

type execCredentialSpec struct {
	Cluster     *execCluster `json:"cluster,omitempty"`
	Interactive bool         `json:"interactive"`
}

type execCluster struct {
	Server                   string          `json:"server"`
	TLSServerName            string          `json:"tls-server-name,omitempty"`
	InsecureSkipTLSVerify    bool            `json:"insecure-skip-tls-verify,omitempty"`
	CertificateAuthorityData []byte          `json:"certificate-authority-data,omitempty"`
	ProxyURL                 string          `json:"proxy-url,omitempty"`
	DisableCompression       bool            `json:"disable-compression,omitempty"`
	Config                   json.RawMessage `json:"config,omitempty"`
}

type execCredentialStatus struct {
	ExpirationTimestamp   *time.Time `json:"expirationTimestamp,omitempty"`
	Token                 string     `json:"token,omitempty"`
	ClientCertificateData string     `json:"clientCertificateData,omitempty"`
	ClientKeyData         string     `json:"clientKeyData,omitempty"`
}

// Validate reports the first problem with the exec block itself, before
// anything is run.
func (c Config) Validate() error {
	switch strings.TrimSpace(c.APIVersion) {
	case APIVersionV1, APIVersionV1beta1:
	case apiVersionV1alpha1:
		return fmt.Errorf("exec plugin %s uses %s, which Kubernetes removed in 1.24; update the "+
			"kubeconfig (for most plugins, re-run the command that wrote it) to %s",
			c.name(), apiVersionV1alpha1, APIVersionV1)
	case "":
		return fmt.Errorf("exec plugin %s names no apiVersion; it must be %s or %s",
			c.name(), APIVersionV1, APIVersionV1beta1)
	default:
		return fmt.Errorf("exec plugin %s uses apiVersion %q; cloop speaks %s and %s",
			c.name(), c.APIVersion, APIVersionV1, APIVersionV1beta1)
	}
	if strings.TrimSpace(c.Command) == "" {
		return errors.New("the kubeconfig's exec block names no command")
	}
	if _, err := c.mode(); err != nil {
		return err
	}
	for _, e := range c.Env {
		if strings.TrimSpace(e.Name) == "" || strings.ContainsAny(e.Name, "=\x00") {
			return fmt.Errorf("exec plugin %s has an env entry with an unusable name %q", c.name(), e.Name)
		}
	}
	return nil
}

// mode resolves interactiveMode, with v1beta1's default.
func (c Config) mode() (InteractiveMode, error) {
	switch InteractiveMode(strings.TrimSpace(string(c.InteractiveMode))) {
	case InteractiveNever:
		return InteractiveNever, nil
	case InteractiveIfAvailable:
		return InteractiveIfAvailable, nil
	case InteractiveAlways:
		return InteractiveAlways, nil
	case "":
		if strings.TrimSpace(c.APIVersion) == APIVersionV1 {
			return "", fmt.Errorf("exec plugin %s: interactiveMode must be set for %s "+
				"(Never, IfAvailable or Always)", c.name(), APIVersionV1)
		}
		return InteractiveIfAvailable, nil
	default:
		return "", fmt.Errorf("exec plugin %s: unknown interactiveMode %q (want Never, IfAvailable or Always)",
			c.name(), c.InteractiveMode)
	}
}

// name is the plugin as a person would recognise it in a message.
func (c Config) name() string {
	n := filepath.Base(strings.TrimSpace(c.Command))
	if n == "" || n == "." || n == "/" {
		return "(unnamed)"
	}
	return n
}

// Run executes the plugin and returns the credential it printed.
//
// cluster is required when the exec block sets provideClusterInfo, and
// ignored otherwise.
func Run(ctx context.Context, cfg Config, cluster *Cluster, opts Options) (*Credential, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	mode, _ := cfg.mode()
	interactive := false
	switch mode {
	case InteractiveIfAvailable:
		interactive = opts.Terminal
	case InteractiveAlways:
		if !opts.Terminal {
			return nil, fmt.Errorf("%w: %s is set to interactiveMode Always and standard input is not a "+
				"terminal; run the command from an interactive shell", ErrInteractive, cfg.name())
		}
		interactive = true
	}

	path, err := resolveCommand(cfg, opts.LookPath)
	if err != nil {
		return nil, err
	}

	input := execCredential{
		APIVersion: strings.TrimSpace(cfg.APIVersion),
		Kind:       "ExecCredential",
		Spec:       execCredentialSpec{Interactive: interactive},
	}
	if cfg.ProvideClusterInfo {
		if cluster == nil || strings.TrimSpace(cluster.Server) == "" {
			return nil, fmt.Errorf("exec plugin %s asks for the cluster's details (provideClusterInfo) "+
				"and the kubeconfig gives it no server", cfg.name())
		}
		input.Spec.Cluster = &execCluster{
			Server:                   cluster.Server,
			TLSServerName:            cluster.TLSServerName,
			InsecureSkipTLSVerify:    cluster.InsecureSkipTLSVerify,
			CertificateAuthorityData: cluster.CertificateAuthorityData,
			ProxyURL:                 cluster.ProxyURL,
			DisableCompression:       cluster.DisableCompression,
			Config:                   cluster.Config,
		}
	}
	info, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("exec plugin %s: encode KUBERNETES_EXEC_INFO: %w", cfg.name(), err)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
		if interactive {
			timeout = DefaultInteractiveTimeout
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, path, cfg.Args...)
	env := opts.Environ
	if env == nil {
		env = os.Environ()
	}
	env = append([]string(nil), env...)
	for _, e := range cfg.Env {
		env = append(env, e.Name+"="+e.Value)
	}
	// Last, so an env entry in the exec block cannot replace it: os/exec keeps
	// the last of duplicate keys.
	env = append(env, "KUBERNETES_EXEC_INFO="+string(info))
	cmd.Env = env
	// The plugin's working directory is the caller's, as under kubectl: a
	// plugin that reads a relative path of its own expects that.
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	cmd.Stderr = stderr
	if interactive {
		in := opts.Stdin
		if in == nil {
			in = os.Stdin
		}
		cmd.Stdin = in
	}
	out := &cappedBuffer{limit: maxOutputBytes}
	cmd.Stdout = out
	// A plugin that leaves a child holding stdout open must not wedge Wait
	// past the deadline.
	cmd.WaitDelay = 2 * time.Second

	runErr := cmd.Run()
	defer out.wipe()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("exec plugin %s did not finish within %s", cfg.name(), timeout)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return nil, fmt.Errorf("exec plugin %s failed with exit code %d (its own message is above)",
				cfg.name(), exitErr.ExitCode())
		}
		return nil, fmt.Errorf("exec plugin %s: %w", cfg.name(), runErr)
	}
	if out.over {
		return nil, fmt.Errorf("%w: %s printed more than %d bytes", ErrMalformed, cfg.name(), maxOutputBytes)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	return parseCredential(cfg, out.Bytes(), now())
}

// parseCredential checks and decodes a plugin's stdout.
//
// Every error here describes the output's shape, never its content: the
// content is a credential, and a malformed one may still carry most of a
// valid token.
func parseCredential(cfg Config, raw []byte, now time.Time) (*Credential, error) {
	name := cfg.name()
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: %s printed nothing on stdout", ErrMalformed, name)
	}
	var got execCredential
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&got); err != nil {
		return nil, fmt.Errorf("%w: %s's output is not an ExecCredential JSON document (%s)",
			ErrMalformed, name, jsonErrorShape(err))
	}
	if want := strings.TrimSpace(cfg.APIVersion); got.APIVersion != want {
		return nil, fmt.Errorf("%w: %s is configured for %s and answered with apiVersion %q",
			ErrMalformed, name, want, got.APIVersion)
	}
	if got.Kind != "ExecCredential" {
		return nil, fmt.Errorf("%w: %s answered with kind %q, not ExecCredential", ErrMalformed, name, got.Kind)
	}
	st := got.Status
	if st == nil {
		return nil, fmt.Errorf("%w: %s's ExecCredential has no status", ErrMalformed, name)
	}
	cred := &Credential{Token: strings.TrimSpace(st.Token)}
	hasCert, hasKey := st.ClientCertificateData != "", st.ClientKeyData != ""
	switch {
	case cred.Token == "" && !hasCert && !hasKey:
		return nil, fmt.Errorf("%w: %s's ExecCredential carries neither a token nor a client certificate",
			ErrMalformed, name)
	case hasCert != hasKey:
		return nil, fmt.Errorf("%w: %s returned a client certificate without its key, or a key without "+
			"its certificate", ErrMalformed, name)
	case hasCert:
		// The ExecCredential carries PEM, not base64, unlike a kubeconfig's
		// *-data fields.
		if !strings.Contains(st.ClientCertificateData, "-----BEGIN") ||
			!strings.Contains(st.ClientKeyData, "-----BEGIN") {
			return nil, fmt.Errorf("%w: %s's client certificate or key is not PEM", ErrMalformed, name)
		}
		cred.ClientCertificateData = []byte(st.ClientCertificateData)
		cred.ClientKeyData = []byte(st.ClientKeyData)
	}
	if strings.ContainsAny(cred.Token, " \t\r\n") {
		return nil, fmt.Errorf("%w: %s's token contains whitespace", ErrMalformed, name)
	}
	if st.ExpirationTimestamp != nil && !st.ExpirationTimestamp.IsZero() {
		cred.ExpiresAt = st.ExpirationTimestamp.UTC()
		if !now.Before(cred.ExpiresAt) {
			return nil, fmt.Errorf("%w: %s's credential expired at %s; sign in again with the plugin "+
				"(for kubelogin, `kubelogin remove-tokens`) and retry", ErrExpired, name,
				cred.ExpiresAt.Format(time.RFC3339))
		}
	}
	return cred, nil
}

// jsonErrorShape describes a decoding error without quoting the input.
func jsonErrorShape(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("syntax error at byte %d", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Sprintf("field %q has the wrong type", typ.Field)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	}
	var parseErr *time.ParseError
	if errors.As(err, &parseErr) {
		return "expirationTimestamp is not an RFC 3339 time"
	}
	return "not JSON"
}

// resolveCommand finds the plugin binary the way kubectl does: a command with
// a path separator is a path, relative to the kubeconfig's directory when it
// is relative; a bare name is looked up on PATH.
func resolveCommand(cfg Config, lookPath func(string) (string, error)) (string, error) {
	command := strings.TrimSpace(cfg.Command)
	if strings.ContainsRune(command, filepath.Separator) || strings.ContainsRune(command, '/') {
		if !filepath.IsAbs(command) && cfg.Dir != "" {
			command = filepath.Join(cfg.Dir, command)
		}
		st, err := os.Stat(command)
		if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			return "", notFound(cfg, command)
		}
		return command, nil
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath(command)
	if err != nil {
		return "", notFound(cfg, command)
	}
	return path, nil
}

// notFound is ErrNotFound with the install hint, which is the sentence the
// plugin's authors wrote for exactly this moment.
func notFound(cfg Config, command string) error {
	msg := command + " is not installed, or not on PATH, on this machine"
	if hint := strings.TrimSpace(cfg.InstallHint); hint != "" {
		msg += "\n\n" + hint
	}
	return fmt.Errorf("%w: %s", ErrNotFound, msg)
}

// cappedBuffer collects stdout up to a limit and records whether more came.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room <= 0 {
		c.over = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// wipe zeroes what the plugin printed once it has been parsed.
func (c *cappedBuffer) wipe() {
	b := c.buf.Bytes()
	for i := range b {
		b[i] = 0
	}
	c.buf.Reset()
}

// decodeB64 decodes a kubeconfig *-data field.
func decodeB64(s, field string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64: %w", field, err)
	}
	return b, nil
}
