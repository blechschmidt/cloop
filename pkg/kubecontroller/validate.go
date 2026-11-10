package kubecontroller

// validate.go repeats the CRD's schema and x-kubernetes-validations rules in
// Go (Task 20483).
//
// The API server enforces the schema on every write, so in a cluster that
// installed the CRD this file refuses nothing the server let through. It is
// here for the clusters where that does not hold — a CRD applied before a rule
// was added, an API server older than one of its CEL functions, an object
// written before the CRD was updated — and for the rules the schema cannot
// state: a pin that parses, a CA bundle that holds a certificate, an image
// reference the registry could serve. An invalid spec is reported on the
// object as the Invalid condition, with every problem named, and the
// controller starts nothing for it.
//
// crd_test.go holds the two to the same fields; each rule here names the CRD
// rule it repeats where there is one.

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// Bounds, each also in the CRD schema.
const (
	maxURLLen         = 2048
	maxPinLen         = 1024
	maxCABundleLen    = 64 << 10
	maxDNSSubdomain   = 253
	maxImageLen       = 1024
	maxMapEntries     = 32
	maxTolerations    = 32
	maxPullSecrets    = 16
	maxEnv            = 64
	maxEnvNameLen     = 128
	maxScaleDownDelay = 24 * time.Hour
)

var (
	// dnsSubdomain is RFC 1123: a Secret's, a ServiceAccount's or a
	// RuntimeClass's name.
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	// secretKey is what a Secret's data key may be.
	secretKey = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
	// labelName and labelPrefix make up a qualified label key.
	labelName   = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	labelPrefix = dnsSubdomain
	// labelValue is a label's value, which may be empty.
	labelValue = regexp.MustCompile(`^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$`)
	// envName is a variable's name.
	envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// quantity is the Kubernetes quantity grammar, as the API's own schema
	// writes it.
	quantity = regexp.MustCompile(`^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$`)
)

// reservedLabelPrefixes are label keys the controller owns: runnerLabels may
// not set them, or an operator's label could make a Pod the controller's or
// hide one from it.
var reservedLabelPrefixes = []string{"cloop.dev/", "app.kubernetes.io/managed-by", "app.kubernetes.io/name"}

// reservedEnv are variables the runner's own configuration uses.
var reservedEnv = map[string]bool{"HOME": true, "PATH": true}

// resourceNames are the container resources a template may ask for.
var resourceNames = map[string]bool{"cpu": true, "memory": true, "ephemeral-storage": true}

// Normalize applies the defaults the CRD schema declares, for an object
// written before the CRD carried them.
func (s ExecutorPoolSpec) Normalize() ExecutorPoolSpec {
	s.HubURL = strings.TrimSpace(s.HubURL)
	s.HubCAPin = strings.TrimSpace(s.HubCAPin)
	if strings.TrimSpace(s.PoolCredentialSecretRef.Key) == "" {
		s.PoolCredentialSecretRef.Key = DefaultCredentialKey
	}
	if strings.TrimSpace(s.ScaleDownDelay) == "" {
		s.ScaleDownDelay = DefaultScaleDownDelay
	}
	return s
}

// ScaleDownDelayDuration is the parsed scale-down delay; Validate has
// refused one that does not parse.
func (s ExecutorPoolSpec) ScaleDownDelayDuration() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s.ScaleDownDelay))
	if err != nil || d < 0 {
		d, _ = time.ParseDuration(DefaultScaleDownDelay)
	}
	return d
}

// Validate returns every problem with the (normalized) spec, "field: what is
// wrong", sorted; none means it is valid.
func (s ExecutorPoolSpec) Validate() []string {
	var v validator

	// hubURL — CRD: required, maxLength, isURL, https.
	switch {
	case s.HubURL == "":
		v.add("spec.hubURL", "is required")
	case len(s.HubURL) > maxURLLen:
		v.add("spec.hubURL", fmt.Sprintf("is longer than %d characters", maxURLLen))
	default:
		u, err := url.Parse(s.HubURL)
		switch {
		case err != nil:
			v.add("spec.hubURL", "is not a URL: "+err.Error())
		case u.Scheme != "https":
			v.add("spec.hubURL", "must be an https URL: the pool credential and every runner token travel on it")
		case u.Host == "" || u.Hostname() == "":
			v.add("spec.hubURL", "names no host")
		case u.User != nil:
			v.add("spec.hubURL", "must not carry a user or password")
		case u.RawQuery != "" || u.Fragment != "":
			v.add("spec.hubURL", "must not carry a query or a fragment")
		}
	}

	// hubCAPin — CRD: maxLength, pattern; here: every pin parses.
	if s.HubCAPin != "" {
		if len(s.HubCAPin) > maxPinLen {
			v.add("spec.hubCAPin", fmt.Sprintf("is longer than %d characters", maxPinLen))
		} else if _, err := tlsconf.ParsePinSet(s.HubCAPin); err != nil {
			v.add("spec.hubCAPin", "is not a set of sha256:<base64> SPKI pins: "+err.Error())
		}
	}

	// hubCABundle — CRD: maxLength, contains a PEM certificate; here: every
	// block is a certificate that parses.
	if strings.TrimSpace(s.HubCABundle) != "" {
		if len(s.HubCABundle) > maxCABundleLen {
			v.add("spec.hubCABundle", fmt.Sprintf("is larger than %d bytes", maxCABundleLen))
		} else if err := checkCABundle(s.HubCABundle); err != nil {
			v.add("spec.hubCABundle", err.Error())
		}
	}

	// poolCredentialSecretRef — CRD: name required, DNS subdomain; key pattern.
	ref := s.PoolCredentialSecretRef
	v.dnsName("spec.poolCredentialSecretRef.name", ref.Name, true)
	v.secretKey("spec.poolCredentialSecretRef.key", ref.Key)

	// minRunners/maxRunners — CRD: minimum, maximum, and the rule
	// "minRunners must not exceed maxRunners".
	if s.MinRunners < 0 {
		v.add("spec.minRunners", "cannot be negative")
	}
	if s.MaxRunners < 1 || s.MaxRunners > executorpool.MaxRunnersCeiling {
		v.add("spec.maxRunners", fmt.Sprintf("must be between 1 and %d", executorpool.MaxRunnersCeiling))
	}
	if s.MinRunners > s.MaxRunners && s.MaxRunners >= 1 {
		v.add("spec.minRunners", fmt.Sprintf("(%d) must not exceed maxRunners (%d)", s.MinRunners, s.MaxRunners))
	}

	// scaleDownDelay — CRD: a duration between 0s and 24h.
	if d, err := time.ParseDuration(strings.TrimSpace(s.ScaleDownDelay)); err != nil {
		v.add("spec.scaleDownDelay", fmt.Sprintf("%q is not a duration such as 5m or 90s", s.ScaleDownDelay))
	} else if d < 0 || d > maxScaleDownDelay {
		v.add("spec.scaleDownDelay", fmt.Sprintf("must be between 0s and %s", maxScaleDownDelay))
	}

	// runnerLabels — CRD: maxProperties, key and value rules, no reserved key.
	v.labels("spec.runnerLabels", s.RunnerLabels, true)

	s.Template.validate(&v)
	// A runner runs model-authored code: the controller's own credential is
	// the one Secret it must never be handed — with it, a run could mint
	// runners and read the pool's demand. CRD: the rule on spec.
	for i, e := range s.Template.Env {
		if e.SecretKeyRef.Name != "" && e.SecretKeyRef.Name == ref.Name {
			v.add(fmt.Sprintf("spec.template.env[%d].secretKeyRef.name", i),
				fmt.Sprintf("%q holds the pool's controller credential, which a runner is never given", ref.Name))
		}
	}
	return v.sorted()
}

// validate checks the runner template.
func (t RunnerTemplate) validate(v *validator) {
	const f = "spec.template"
	if img := strings.TrimSpace(t.Image); img != "" {
		switch {
		case len(img) > maxImageLen:
			v.add(f+".image", fmt.Sprintf("is longer than %d characters", maxImageLen))
		case strings.ContainsAny(img, " \t\n"):
			v.add(f+".image", "must not contain whitespace")
		default:
			if _, err := imagepolicy.ParseReference(img); err != nil {
				v.add(f+".image", "is not an image reference: "+err.Error())
			}
		}
	}
	switch t.ImagePullPolicy {
	case "", "Always", "IfNotPresent", "Never":
	default:
		v.add(f+".imagePullPolicy", "must be Always, IfNotPresent or Never")
	}
	if len(t.ImagePullSecrets) > maxPullSecrets {
		v.add(f+".imagePullSecrets", fmt.Sprintf("names more than %d Secrets", maxPullSecrets))
	}
	for i, r := range t.ImagePullSecrets {
		v.dnsName(fmt.Sprintf("%s.imagePullSecrets[%d].name", f, i), r.Name, true)
	}
	v.dnsName(f+".runtimeClassName", t.RuntimeClassName, false)
	v.dnsName(f+".serviceAccountName", t.ServiceAccountName, false)
	v.resources(f+".resources.requests", t.Resources.Requests)
	v.resources(f+".resources.limits", t.Resources.Limits)
	v.labels(f+".nodeSelector", t.NodeSelector, false)
	if len(t.Tolerations) > maxTolerations {
		v.add(f+".tolerations", fmt.Sprintf("has more than %d entries", maxTolerations))
	}
	for i, tol := range t.Tolerations {
		v.toleration(fmt.Sprintf("%s.tolerations[%d]", f, i), tol)
	}
	if len(t.Affinity) > 0 && string(t.Affinity) != "null" {
		var aff map[string]json.RawMessage
		if err := json.Unmarshal(t.Affinity, &aff); err != nil {
			v.add(f+".affinity", "must be an object")
		} else {
			for k := range aff {
				switch k {
				case "nodeAffinity", "podAffinity", "podAntiAffinity":
				default:
					v.add(f+".affinity", fmt.Sprintf("has %q, which is not nodeAffinity, podAffinity or podAntiAffinity", k))
				}
			}
		}
	}
	if len(t.Env) > maxEnv {
		v.add(f+".env", fmt.Sprintf("has more than %d variables", maxEnv))
	}
	seen := map[string]bool{}
	for i, e := range t.Env {
		p := fmt.Sprintf("%s.env[%d]", f, i)
		switch {
		case e.Name == "":
			v.add(p+".name", "is required")
		case len(e.Name) > maxEnvNameLen || !envName.MatchString(e.Name):
			v.add(p+".name", fmt.Sprintf("%q is not a variable name", e.Name))
		case reservedEnv[e.Name] || strings.HasPrefix(e.Name, "CLOOP_"):
			v.add(p+".name", fmt.Sprintf("%q is the runner's own: HOME, PATH and CLOOP_* are set by the controller", e.Name))
		case seen[e.Name]:
			v.add(p+".name", fmt.Sprintf("%q is set twice", e.Name))
		}
		seen[e.Name] = true
		v.dnsName(p+".secretKeyRef.name", e.SecretKeyRef.Name, true)
		if strings.TrimSpace(e.SecretKeyRef.Key) == "" {
			v.add(p+".secretKeyRef.key", "is required")
		} else {
			v.secretKey(p+".secretKeyRef.key", e.SecretKeyRef.Key)
		}
	}
}

// checkCABundle reports whether pemText holds certificates and nothing else.
func checkCABundle(pemText string) error {
	rest := []byte(pemText)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("holds a %s block; only CERTIFICATE blocks belong in a CA bundle", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("holds a certificate that does not parse: %v", err)
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("holds no PEM certificate")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("has text after its last certificate")
	}
	return nil
}

// validator collects problems.
type validator struct{ problems []string }

func (v *validator) add(field, msg string) { v.problems = append(v.problems, field+": "+msg) }

func (v *validator) sorted() []string {
	sort.Strings(v.problems)
	return v.problems
}

// dnsName checks an RFC 1123 subdomain, required or not.
func (v *validator) dnsName(field, name string, required bool) {
	switch {
	case name == "" && required:
		v.add(field, "is required")
	case name == "":
	case len(name) > maxDNSSubdomain || !dnsSubdomain.MatchString(name):
		v.add(field, fmt.Sprintf("%q is not a lowercase RFC 1123 name", name))
	}
}

// secretKey checks a Secret data key; "" is left to the default.
func (v *validator) secretKey(field, key string) {
	if key != "" && (len(key) > maxDNSSubdomain || !secretKey.MatchString(key)) {
		v.add(field, fmt.Sprintf("%q is not a Secret key", key))
	}
}

// labels checks a label map; reserved refuses the controller's own keys.
func (v *validator) labels(field string, m map[string]string, reserved bool) {
	if len(m) > maxMapEntries {
		v.add(field, fmt.Sprintf("has more than %d entries", maxMapEntries))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !validLabelKey(k) {
			v.add(field, fmt.Sprintf("%q is not a label key", k))
			continue
		}
		if reserved {
			for _, p := range reservedLabelPrefixes {
				if strings.HasPrefix(k, p) {
					v.add(field, fmt.Sprintf("%q is the controller's: keys under cloop.dev/ and "+
						"app.kubernetes.io/name and managed-by are set by it", k))
					break
				}
			}
		}
		if val := m[k]; len(val) > 63 || !labelValue.MatchString(val) {
			v.add(field, fmt.Sprintf("%q's value %q is not a label value", k, val))
		}
	}
}

// validLabelKey reports whether k is a qualified label key.
func validLabelKey(k string) bool {
	prefix, name, hasPrefix := strings.Cut(k, "/")
	if !hasPrefix {
		name, prefix = prefix, ""
	}
	if hasPrefix && (prefix == "" || len(prefix) > maxDNSSubdomain || !labelPrefix.MatchString(prefix)) {
		return false
	}
	return name != "" && len(name) <= 63 && labelName.MatchString(name)
}

// resources checks a requests or limits map.
func (v *validator) resources(field string, m map[string]Quantity) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !resourceNames[k] {
			v.add(field, fmt.Sprintf("%q is not cpu, memory or ephemeral-storage", k))
			continue
		}
		if q := string(m[k]); len(q) > 64 || !quantity.MatchString(q) || strings.HasPrefix(q, "-") {
			v.add(field, fmt.Sprintf("%s: %q is not a non-negative quantity such as 500m or 2Gi", k, q))
		}
	}
}

// toleration checks one toleration — CRD: operator and effect enums, and the
// rule that Exists takes no value.
func (v *validator) toleration(field string, t Toleration) {
	switch t.Operator {
	case "", "Equal", "Exists":
	default:
		v.add(field+".operator", "must be Equal or Exists")
	}
	switch t.Effect {
	case "", "NoSchedule", "PreferNoSchedule", "NoExecute":
	default:
		v.add(field+".effect", "must be NoSchedule, PreferNoSchedule or NoExecute")
	}
	if t.Key != "" && !validLabelKey(t.Key) {
		v.add(field+".key", fmt.Sprintf("%q is not a label key", t.Key))
	}
	if t.Key == "" && t.Operator != "Exists" {
		v.add(field+".operator", "must be Exists when the key is empty")
	}
	if t.Operator == "Exists" && t.Value != "" {
		v.add(field+".value", "must be empty with operator Exists")
	}
	if len(t.Value) > 63 || !labelValue.MatchString(t.Value) {
		v.add(field+".value", fmt.Sprintf("%q is not a label value", t.Value))
	}
	if t.TolerationSeconds != nil && t.Effect != "NoExecute" {
		v.add(field+".tolerationSeconds", "applies to effect NoExecute only")
	}
}
