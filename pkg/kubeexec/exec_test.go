package kubeexec

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// plantedToken is what a fake plugin prints as its credential. Every malformed
// output below carries it too, so a test can check that no error message ever
// quotes what the plugin printed.
const plantedToken = "eyJhbGciOiJSUzI1NiJ9.planted-credential-0123456789"

// fakePlugin writes an executable shell script into dir and returns its path.
// The body runs with KUBERNETES_EXEC_INFO in the environment; $OUT names a file
// the script may record what it saw into.
func fakePlugin(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// credentialJSON renders an ExecCredential the way a real plugin prints one.
func credentialJSON(apiVersion, token string, expires time.Time) string {
	status := map[string]any{"token": token}
	if !expires.IsZero() {
		status["expirationTimestamp"] = expires.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(map[string]any{
		"apiVersion": apiVersion, "kind": "ExecCredential", "spec": map[string]any{}, "status": status,
	})
	return string(b)
}

// printing returns a script body that prints s exactly, whatever it contains.
func printing(s string) string {
	return "printf '%s' '" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var testNow = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

func runOpts(stderr *bytes.Buffer) Options {
	return Options{
		Stderr:  stderr,
		Now:     func() time.Time { return testNow },
		Environ: []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir()},
	}
}

func TestRunReadsTheTokenAFakePluginPrints(t *testing.T) {
	dir := t.TempDir()
	seen := filepath.Join(dir, "exec-info.json")
	expires := testNow.Add(50 * time.Minute)
	plugin := fakePlugin(t, dir, "kubelogin",
		`printf '%s' "$KUBERNETES_EXEC_INFO" > "`+seen+`"
printf 'argv:%s\n' "$*" >> "`+seen+`.argv"
printf 'tenant:%s\n' "$AZURE_TENANT" >> "`+seen+`.argv"
echo "To sign in, use a web browser to open the page" >&2
`+printing(credentialJSON(APIVersionV1, plantedToken, expires)))

	var stderr bytes.Buffer
	cred, err := Run(context.Background(), Config{
		APIVersion:         APIVersionV1,
		Command:            plugin,
		Args:               []string{"get-token", "--login", "devicecode"},
		Env:                []EnvVar{{Name: "AZURE_TENANT", Value: "contoso"}},
		InteractiveMode:    InteractiveNever,
		ProvideClusterInfo: true,
	}, &Cluster{
		Server:                   "https://aks-dev.example.com:443",
		CertificateAuthorityData: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
		Config:                   json.RawMessage(`{"audience":"6dae42f8"}`),
	}, runOpts(&stderr))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if cred.Token != plantedToken {
		t.Fatalf("token = %q", cred.Token)
	}
	if !cred.ExpiresAt.Equal(expires) {
		t.Fatalf("expires = %s, want %s", cred.ExpiresAt, expires)
	}
	if !strings.Contains(stderr.String(), "use a web browser") {
		t.Errorf("the plugin's stderr did not reach the user: %q", stderr.String())
	}
	if s := cred.String(); strings.Contains(s, plantedToken) || !strings.Contains(s, "redacted") {
		t.Errorf("Credential.String leaks or does not redact: %q", s)
	}

	// What the plugin was told.
	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Interactive *bool `json:"interactive"`
			Cluster     *struct {
				Server string          `json:"server"`
				CAData string          `json:"certificate-authority-data"`
				Config json.RawMessage `json:"config"`
			} `json:"cluster"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("KUBERNETES_EXEC_INFO is not JSON: %v (%s)", err, raw)
	}
	if info.APIVersion != APIVersionV1 || info.Kind != "ExecCredential" {
		t.Errorf("exec info = %s/%s", info.APIVersion, info.Kind)
	}
	if info.Spec.Interactive == nil || *info.Spec.Interactive {
		t.Errorf("spec.interactive = %v under interactiveMode Never, want false", info.Spec.Interactive)
	}
	if info.Spec.Cluster == nil || info.Spec.Cluster.Server != "https://aks-dev.example.com:443" {
		t.Fatalf("provideClusterInfo: spec.cluster = %+v", info.Spec.Cluster)
	}
	if ca, _ := base64.StdEncoding.DecodeString(info.Spec.Cluster.CAData); !strings.Contains(string(ca), "BEGIN CERTIFICATE") {
		t.Errorf("certificate-authority-data did not reach the plugin base64-encoded: %q", info.Spec.Cluster.CAData)
	}
	if string(info.Spec.Cluster.Config) != `{"audience":"6dae42f8"}` {
		t.Errorf("the cluster's exec extension = %s", info.Spec.Cluster.Config)
	}
	argv, _ := os.ReadFile(seen + ".argv")
	for _, want := range []string{"argv:get-token --login devicecode", "tenant:contoso"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("the plugin did not see %q; it saw:\n%s", want, argv)
		}
	}
}

func TestRunWithoutProvideClusterInfoSendsNoCluster(t *testing.T) {
	dir := t.TempDir()
	seen := filepath.Join(dir, "info")
	plugin := fakePlugin(t, dir, "plugin", `printf '%s' "$KUBERNETES_EXEC_INFO" > "`+seen+`"
`+printing(credentialJSON(APIVersionV1beta1, plantedToken, time.Time{})))
	cred, err := Run(context.Background(), Config{APIVersion: APIVersionV1beta1, Command: plugin},
		&Cluster{Server: "https://k8s.example.com"}, runOpts(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	if !cred.ExpiresAt.IsZero() {
		t.Errorf("a credential the plugin gave no expiry for has one: %s", cred.ExpiresAt)
	}
	raw, _ := os.ReadFile(seen)
	if strings.Contains(string(raw), "k8s.example.com") || strings.Contains(string(raw), `"cluster"`) {
		t.Errorf("the plugin was told the cluster without provideClusterInfo: %s", raw)
	}
}

func TestInteractiveModes(t *testing.T) {
	dir := t.TempDir()
	// The plugin reads one line from stdin when it was told it may interact,
	// and echoes it back as its token — the shape of a device-code or
	// password prompt.
	plugin := fakePlugin(t, dir, "prompting", `
case "$KUBERNETES_EXEC_INFO" in
*'"interactive":true'*) read -r answer; tok="typed-$answer" ;;
*) tok="silent" ;;
esac
printf '{"apiVersion":"%s","kind":"ExecCredential","status":{"token":"%s"}}' "$API" "$tok"`)

	run := func(apiVersion string, mode InteractiveMode, terminal bool) (*Credential, error) {
		opts := runOpts(&bytes.Buffer{})
		opts.Environ = append(opts.Environ, "API="+apiVersion)
		opts.Terminal = terminal
		opts.Stdin = strings.NewReader("hunter2\n")
		return Run(context.Background(), Config{APIVersion: apiVersion, Command: plugin, InteractiveMode: mode}, nil, opts)
	}

	cases := []struct {
		name     string
		api      string
		mode     InteractiveMode
		terminal bool
		want     string
		wantErr  error
		errText  string
	}{
		{"never ignores the terminal", APIVersionV1, InteractiveNever, true, "silent", nil, ""},
		{"if-available with a terminal interacts", APIVersionV1, InteractiveIfAvailable, true, "typed-hunter2", nil, ""},
		{"if-available without one does not", APIVersionV1, InteractiveIfAvailable, false, "silent", nil, ""},
		{"always without a terminal is refused", APIVersionV1, InteractiveAlways, false, "", ErrInteractive, "not a terminal"},
		{"always with one interacts", APIVersionV1, InteractiveAlways, true, "typed-hunter2", nil, ""},
		{"v1beta1 defaults to if-available", APIVersionV1beta1, "", true, "typed-hunter2", nil, ""},
		{"v1 requires the field", APIVersionV1, "", true, "", nil, "interactiveMode must be set"},
		{"an unknown mode is refused", APIVersionV1, "Sometimes", true, "", nil, "unknown interactiveMode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := run(tc.api, tc.mode, tc.terminal)
			if tc.wantErr != nil || tc.errText != "" {
				if err == nil {
					t.Fatalf("Run succeeded; want an error")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("err = %v, want %v", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.errText) {
					t.Errorf("err = %v, want it to mention %q", err, tc.errText)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if cred.Token != tc.want {
				t.Errorf("token = %q, want %q", cred.Token, tc.want)
			}
		})
	}
}

func TestRunRefusesAnExpiredCredential(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		expires time.Time
		ok      bool
	}{
		{"expired an hour ago", testNow.Add(-time.Hour), false},
		{"expiring this instant", testNow, false},
		{"one more minute", testNow.Add(time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plugin := fakePlugin(t, dir, "p", printing(credentialJSON(APIVersionV1, plantedToken, tc.expires)))
			cred, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: plugin,
				InteractiveMode: InteractiveNever}, nil, runOpts(&bytes.Buffer{}))
			if tc.ok {
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				if !cred.ExpiresAt.Equal(tc.expires) {
					t.Errorf("expiry = %s", cred.ExpiresAt)
				}
				return
			}
			if !errors.Is(err, ErrExpired) {
				t.Fatalf("err = %v, want ErrExpired", err)
			}
			if strings.Contains(err.Error(), plantedToken) {
				t.Errorf("the refusal quotes the credential: %v", err)
			}
			if !strings.Contains(err.Error(), tc.expires.UTC().Format(time.RFC3339)) {
				t.Errorf("the refusal does not say when it expired: %v", err)
			}
		})
	}
}

func TestRunRefusesMalformedOutput(t *testing.T) {
	dir := t.TempDir()
	pemCert := "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n"
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{"nothing", "", "printed nothing"},
		{"whitespace", "   \n", "printed nothing"},
		{"not JSON", "Bearer " + plantedToken, "not an ExecCredential"},
		{"truncated JSON", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"` + plantedToken, "not an ExecCredential"},
		{"the wrong apiVersion", credentialJSON(APIVersionV1beta1, plantedToken, time.Time{}), "answered with apiVersion"},
		{"the wrong kind", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"TokenRequest","status":{"token":"` + plantedToken + `"}}`, "not ExecCredential"},
		{"no status", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{}}`, "has no status"},
		{"an empty status", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{}}`, "neither a token nor a client certificate"},
		{"a certificate without its key", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"clientCertificateData":"` + pemCert + `"}}`, "without its key"},
		{"a certificate that is not PEM", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"clientCertificateData":"` + plantedToken + `","clientKeyData":"` + plantedToken + `"}}`, "not PEM"},
		{"a token with a newline", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"abc def` + plantedToken + `"}}`, "whitespace"},
		{"a token of the wrong type", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":12345}}`, "wrong type"},
		{"an unparseable expiry", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"` + plantedToken + `","expirationTimestamp":"next tuesday"}}`, "not an ExecCredential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plugin := fakePlugin(t, dir, "p", printing(tc.output))
			_, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: plugin,
				InteractiveMode: InteractiveNever}, nil, runOpts(&bytes.Buffer{}))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), plantedToken) || strings.Contains(err.Error(), "planted-credential") {
				t.Errorf("the error quotes the plugin's output: %v", err)
			}
		})
	}

	t.Run("more than the cap", func(t *testing.T) {
		plugin := fakePlugin(t, dir, "big", fmt.Sprintf(`head -c %d /dev/zero | tr '\0' 'a'`, maxOutputBytes+10))
		_, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: plugin,
			InteractiveMode: InteractiveNever}, nil, runOpts(&bytes.Buffer{}))
		if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "more than") {
			t.Fatalf("err = %v, want the size cap", err)
		}
	})
}

func TestRunAcceptsAClientCertificate(t *testing.T) {
	dir := t.TempDir()
	cert := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	key := "-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----\n"
	out, _ := json.Marshal(map[string]any{
		"apiVersion": APIVersionV1, "kind": "ExecCredential",
		"status": map[string]any{"clientCertificateData": cert, "clientKeyData": key},
	})
	plugin := fakePlugin(t, dir, "certs", printing(string(out)))
	cred, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: plugin,
		InteractiveMode: InteractiveNever}, nil, runOpts(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	if cred.Token != "" || string(cred.ClientCertificateData) != cert || string(cred.ClientKeyData) != key {
		t.Errorf("credential = %+v", cred)
	}
}

func TestRunReportsAFailingPlugin(t *testing.T) {
	dir := t.TempDir()
	plugin := fakePlugin(t, dir, "aws", `echo "An error occurred (ExpiredToken): the security token included in the request is expired" >&2
exit 255`)
	var stderr bytes.Buffer
	_, err := Run(context.Background(), Config{APIVersion: APIVersionV1beta1, Command: plugin,
		Args: []string{"eks", "get-token"}}, nil, runOpts(&stderr))
	if err == nil || !strings.Contains(err.Error(), "exit code 255") || !strings.Contains(err.Error(), "aws") {
		t.Fatalf("err = %v, want the plugin and its exit code named", err)
	}
	if !strings.Contains(stderr.String(), "ExpiredToken") {
		t.Errorf("the plugin's own explanation did not reach the user: %q", stderr.String())
	}
}

func TestRunNamesAMissingPluginWithItsInstallHint(t *testing.T) {
	_, err := Run(context.Background(), Config{
		APIVersion:      APIVersionV1,
		Command:         "gke-gcloud-auth-plugin-not-installed-anywhere",
		InteractiveMode: InteractiveNever,
		InstallHint:     "Install gke-gcloud-auth-plugin for use with kubectl by following https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl#install_plugin",
	}, nil, Options{Environ: []string{"PATH=/nonexistent"}, LookPath: func(string) (string, error) {
		return "", errors.New("not found")
	}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "Install gke-gcloud-auth-plugin") {
		t.Errorf("the install hint is missing: %v", err)
	}
}

func TestRunResolvesARelativeCommandAgainstTheKubeconfigsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	fakePlugin(t, filepath.Join(dir, "bin"), "auth", printing(credentialJSON(APIVersionV1, plantedToken, time.Time{})))
	cred, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: "./bin/auth",
		InteractiveMode: InteractiveNever, Dir: dir}, nil, runOpts(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	if cred.Token != plantedToken {
		t.Errorf("token = %q", cred.Token)
	}
	// A directory, or a file that is not executable, is not a plugin.
	if err := os.WriteFile(filepath.Join(dir, "bin", "notexec"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"./bin", "./bin/notexec", "./bin/missing"} {
		_, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: cmd,
			InteractiveMode: InteractiveNever, Dir: dir}, nil, runOpts(&bytes.Buffer{}))
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", cmd, err)
		}
	}
}

func TestRunKeepsExecInfoOutOfTheExecBlocksReach(t *testing.T) {
	dir := t.TempDir()
	seen := filepath.Join(dir, "info")
	plugin := fakePlugin(t, dir, "p", `printf '%s' "$KUBERNETES_EXEC_INFO" > "`+seen+`"
`+printing(credentialJSON(APIVersionV1, plantedToken, time.Time{})))
	_, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: plugin,
		InteractiveMode: InteractiveNever,
		Env:             []EnvVar{{Name: "KUBERNETES_EXEC_INFO", Value: `{"spec":{"interactive":true}}`}},
	}, nil, runOpts(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(seen)
	if !strings.Contains(string(raw), `"interactive":false`) {
		t.Errorf("an env entry in the exec block replaced KUBERNETES_EXEC_INFO: %s", raw)
	}
}

func TestRunGivesUpOnAPluginThatHangs(t *testing.T) {
	dir := t.TempDir()
	plugin := fakePlugin(t, dir, "slow", "sleep 30")
	opts := runOpts(&bytes.Buffer{})
	opts.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := Run(context.Background(), Config{APIVersion: APIVersionV1, Command: plugin,
		InteractiveMode: InteractiveNever}, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the timeout took %s to fire", took)
	}
}

func TestValidateRefusesRetiredAndUnknownVersions(t *testing.T) {
	for api, want := range map[string]string{
		"client.authentication.k8s.io/v1alpha1": "removed in 1.24",
		"":                                      "names no apiVersion",
		"client.authentication.k8s.io/v2":       "cloop speaks",
	} {
		err := Config{APIVersion: api, Command: "x", InteractiveMode: InteractiveNever}.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("apiVersion %q: err = %v, want %q", api, err, want)
		}
	}
	if err := (Config{APIVersion: APIVersionV1, InteractiveMode: InteractiveNever}).Validate(); err == nil {
		t.Error("an exec block with no command validated")
	}
	if err := (Config{APIVersion: APIVersionV1, Command: "x", InteractiveMode: InteractiveNever,
		Env: []EnvVar{{Name: "A=B", Value: "c"}}}).Validate(); err == nil {
		t.Error("an env name carrying '=' validated")
	}
}
