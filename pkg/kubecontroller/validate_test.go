package kubecontroller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func validSpec() ExecutorPoolSpec {
	return ExecutorPoolSpec{HubURL: "https://cloop.example.com", PoolCredentialSecretRef: SecretKeyRef{Name: "pool-cred"},
		MaxRunners: 5}.Normalize()
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAValidSpecHasNoProblems(t *testing.T) {
	s := validSpec()
	s.HubCAPin = "sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	s.HubCABundle = testCAPEM(t)
	s.MinRunners = 2
	s.ScaleDownDelay = "90s"
	s.RunnerLabels = map[string]string{"team": "platform", "example.com/cost-center": "42"}
	s.Template = RunnerTemplate{
		Image: "ghcr.io/example/runner:1.2", ImagePullPolicy: "IfNotPresent",
		ImagePullSecrets: []LocalObjectReference{{Name: "ghcr-login"}}, RuntimeClassName: "gvisor",
		Resources: ResourceRequirements{Requests: map[string]Quantity{"cpu": "500m", "memory": "1Gi"},
			Limits: map[string]Quantity{"memory": "4Gi", "ephemeral-storage": "20Gi"}},
		NodeSelector: map[string]string{"kubernetes.io/arch": "amd64"},
		Tolerations: []Toleration{{Key: "dedicated", Operator: "Equal", Value: "runners", Effect: "NoSchedule"},
			{Operator: "Exists"}},
		Affinity:           json.RawMessage(`{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{}}}`),
		ServiceAccountName: "runner",
		Env:                []SecretEnvVar{{Name: "HTTPS_PROXY", SecretKeyRef: SecretKeyRef{Name: "proxy", Key: "url"}}},
	}
	if problems := s.Validate(); len(problems) != 0 {
		t.Fatalf("a valid spec has problems: %v", problems)
	}
}

// Each problem is named, with its field.
func TestValidateNamesEveryProblem(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ExecutorPoolSpec)
		want   string
	}{
		{"no hub", func(s *ExecutorPoolSpec) { s.HubURL = "" }, "spec.hubURL: is required"},
		{"plaintext hub", func(s *ExecutorPoolSpec) { s.HubURL = "http://cloop.example.com" }, "spec.hubURL: must be an https URL"},
		{"hub with a user", func(s *ExecutorPoolSpec) { s.HubURL = "https://u:p@cloop.example.com" }, "user or password"},
		{"hub with a query", func(s *ExecutorPoolSpec) { s.HubURL = "https://cloop.example.com/?x=1" }, "query or a fragment"},
		{"a bad pin", func(s *ExecutorPoolSpec) { s.HubCAPin = "sha1:abc" }, "spec.hubCAPin"},
		{"a bundle with no certificate", func(s *ExecutorPoolSpec) { s.HubCABundle = "hello" }, "spec.hubCABundle: holds no PEM"},
		{"a bundle with a key", func(s *ExecutorPoolSpec) {
			s.HubCABundle = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		}, "only CERTIFICATE blocks"},
		{"no credential secret", func(s *ExecutorPoolSpec) { s.PoolCredentialSecretRef.Name = "" }, "spec.poolCredentialSecretRef.name: is required"},
		{"a bad secret key", func(s *ExecutorPoolSpec) { s.PoolCredentialSecretRef.Key = "a/b" }, "spec.poolCredentialSecretRef.key"},
		{"no max", func(s *ExecutorPoolSpec) { s.MaxRunners = 0 }, "spec.maxRunners: must be between 1 and 1000"},
		{"a huge max", func(s *ExecutorPoolSpec) { s.MaxRunners = 1001 }, "spec.maxRunners"},
		{"negative min", func(s *ExecutorPoolSpec) { s.MinRunners = -1 }, "spec.minRunners: cannot be negative"},
		{"min over max", func(s *ExecutorPoolSpec) { s.MinRunners = 6 }, "must not exceed maxRunners"},
		{"a bad delay", func(s *ExecutorPoolSpec) { s.ScaleDownDelay = "five minutes" }, "spec.scaleDownDelay"},
		{"a long delay", func(s *ExecutorPoolSpec) { s.ScaleDownDelay = "25h" }, "between 0s and 24h"},
		{"a reserved label", func(s *ExecutorPoolSpec) { s.RunnerLabels = map[string]string{"cloop.dev/x": "y"} }, "is the controller's"},
		{"managed-by", func(s *ExecutorPoolSpec) {
			s.RunnerLabels = map[string]string{"app.kubernetes.io/managed-by": "me"}
		}, "is the controller's"},
		{"a bad label value", func(s *ExecutorPoolSpec) { s.RunnerLabels = map[string]string{"a": "-x"} }, "is not a label value"},
		{"a bad label key", func(s *ExecutorPoolSpec) { s.RunnerLabels = map[string]string{"a b": "x"} }, "is not a label key"},
		{"an image with spaces", func(s *ExecutorPoolSpec) { s.Template.Image = "a b" }, "spec.template.image"},
		{"a pull policy", func(s *ExecutorPoolSpec) { s.Template.ImagePullPolicy = "Sometimes" }, "imagePullPolicy"},
		{"a runtime class", func(s *ExecutorPoolSpec) { s.Template.RuntimeClassName = "G_Visor" }, "runtimeClassName"},
		{"a resource", func(s *ExecutorPoolSpec) {
			s.Template.Resources.Limits = map[string]Quantity{"nvidia.com/gpu": "1"}
		}, "is not cpu, memory or ephemeral-storage"},
		{"a quantity", func(s *ExecutorPoolSpec) {
			s.Template.Resources.Requests = map[string]Quantity{"cpu": "lots"}
		}, "is not a non-negative quantity"},
		{"a toleration operator", func(s *ExecutorPoolSpec) {
			s.Template.Tolerations = []Toleration{{Key: "k", Operator: "Maybe"}}
		}, "operator: must be Equal or Exists"},
		{"Exists with a value", func(s *ExecutorPoolSpec) {
			s.Template.Tolerations = []Toleration{{Key: "k", Operator: "Exists", Value: "v"}}
		}, "must be empty with operator Exists"},
		{"tolerationSeconds without NoExecute", func(s *ExecutorPoolSpec) {
			n := int64(5)
			s.Template.Tolerations = []Toleration{{Key: "k", Operator: "Exists", TolerationSeconds: &n}}
		}, "applies to effect NoExecute only"},
		{"affinity not an object", func(s *ExecutorPoolSpec) { s.Template.Affinity = json.RawMessage(`[1]`) }, "affinity: must be an object"},
		{"affinity with a stranger", func(s *ExecutorPoolSpec) { s.Template.Affinity = json.RawMessage(`{"nodeName":"x"}`) }, "nodeName"},
		{"a reserved variable", func(s *ExecutorPoolSpec) {
			s.Template.Env = []SecretEnvVar{{Name: "CLOOP_TOKEN", SecretKeyRef: SecretKeyRef{Name: "s", Key: "k"}}}
		}, "is the runner's own"},
		{"HOME", func(s *ExecutorPoolSpec) {
			s.Template.Env = []SecretEnvVar{{Name: "HOME", SecretKeyRef: SecretKeyRef{Name: "s", Key: "k"}}}
		}, "is the runner's own"},
		{"a variable twice", func(s *ExecutorPoolSpec) {
			s.Template.Env = []SecretEnvVar{{Name: "A", SecretKeyRef: SecretKeyRef{Name: "s", Key: "k"}},
				{Name: "A", SecretKeyRef: SecretKeyRef{Name: "s", Key: "k"}}}
		}, "is set twice"},
		{"the credential's own Secret", func(s *ExecutorPoolSpec) {
			s.Template.Env = []SecretEnvVar{{Name: "X", SecretKeyRef: SecretKeyRef{Name: "pool-cred", Key: "credential"}}}
		}, "is never given"},
		{"a variable without a key", func(s *ExecutorPoolSpec) {
			s.Template.Env = []SecretEnvVar{{Name: "A", SecretKeyRef: SecretKeyRef{Name: "s"}}}
		}, "secretKeyRef.key: is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := validSpec()
			tc.mutate(&s)
			problems := s.Validate()
			joined := strings.Join(problems, "\n")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("problems %q, want one containing %q", problems, tc.want)
			}
		})
	}
}

// The defaults the CRD declares are applied for an object written without
// them.
func TestNormalizeAppliesTheCRDDefaults(t *testing.T) {
	s := ExecutorPoolSpec{}.Normalize()
	if s.PoolCredentialSecretRef.Key != DefaultCredentialKey || s.ScaleDownDelay != DefaultScaleDownDelay {
		t.Fatalf("Normalize left %+v", s)
	}
	if d := s.ScaleDownDelayDuration(); d != 5*time.Minute {
		t.Fatalf("the default delay is %s", d)
	}
}

// A quantity may be written as a number.
func TestQuantityAcceptsANumber(t *testing.T) {
	var r ResourceRequirements
	if err := json.Unmarshal([]byte(`{"requests":{"cpu":2,"memory":"1Gi"}}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Requests["cpu"] != "2" || r.Requests["memory"] != "1Gi" {
		t.Fatalf("decoded %+v", r)
	}
}
