package kubernetes

// validate.go holds the input checks shared by the driver and by
// pkg/config's executors.kubernetes validator.
//
// They live here rather than in pkg/config for the same reason the container
// driver's flag denylist does: a rule that decides whether a value is safe
// must have exactly one definition, next to the code it protects. pkg/config
// calls into these so `cloop config set` rejects a bad value where the
// operator typed it, and Options.Normalize applies the identical rule at
// construction.

import (
	"fmt"
	"strconv"
	"strings"
)

// maxDNSSubdomain is Kubernetes' RFC 1123 subdomain length limit, used for
// namespaces, ServiceAccounts and Secret names.
const maxDNSSubdomain = 253

// ValidateNamespace checks a namespace name against the API's own rules, and
// refuses the namespaces a cloop workload must never be scheduled into.
//
// kube-system in particular: a Pod there frequently inherits privileged
// PodSecurity exemptions and sits next to the control plane's own components.
// A workload running model-authored code has no business in that blast
// radius, and an operator who typed it into a config file almost certainly
// meant something else.
func ValidateNamespace(ns string) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace must not be empty")
	}
	if err := validateDNSSubdomain(ns, "namespace"); err != nil {
		return err
	}
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return fmt.Errorf("namespace %q is reserved for cluster components; "+
			"create a dedicated namespace for cloop workloads instead", ns)
	}
	return nil
}

// validateDNSSubdomain checks an RFC 1123 subdomain: lowercase alphanumerics,
// '-' and '.', beginning and ending alphanumeric.
func validateDNSSubdomain(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(s) > maxDNSSubdomain {
		return fmt.Errorf("%s %q exceeds %d characters", field, s, maxDNSSubdomain)
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '.':
			if i == 0 || i == len(s)-1 {
				return fmt.Errorf("%s %q must begin and end with a lowercase letter or digit", field, s)
			}
		default:
			return fmt.Errorf("%s %q may only contain lowercase letters, digits, '-' and '.' "+
				"(RFC 1123); %q is not allowed", field, s, string(r))
		}
	}
	return nil
}

// ValidateImageRef rejects image references that are not usable as one.
//
// It is deliberately shallow: full reference grammar lives in the registry
// clients, and re-implementing it here would reject valid references. What it
// does catch is the shapes that break something — a leading dash the API
// server would read as a flag in tooling downstream, whitespace, an empty
// tag — plus the ":latest" habit, which for an execution sandbox means the
// code you audited and the code you run are different artefacts.
func ValidateImageRef(ref string) error {
	r := strings.TrimSpace(ref)
	if r == "" {
		return fmt.Errorf("image reference must not be empty")
	}
	if r != ref {
		return fmt.Errorf("image reference %q has leading or trailing whitespace", ref)
	}
	if strings.HasPrefix(r, "-") {
		return fmt.Errorf("image reference %q must not begin with '-'", ref)
	}
	if strings.ContainsAny(r, " \t\n\r\"'`$;|&<>()") {
		return fmt.Errorf("image reference %q contains characters that are not valid in one", ref)
	}
	if len(r) > 512 {
		return fmt.Errorf("image reference is %d characters long; that is not a reference", len(r))
	}
	// Reject a trailing ':' or '@' with nothing after it — a truncated tag or
	// digest that would resolve to something unintended.
	if strings.HasSuffix(r, ":") || strings.HasSuffix(r, "@") {
		return fmt.Errorf("image reference %q ends with an empty tag or digest", ref)
	}
	return nil
}

// ImageWarnings returns advisory notes about an otherwise-valid image
// reference. Separate from ValidateImageRef because a floating tag is a bad
// idea, not an error: plenty of legitimate deployments track :latest on
// purpose, and refusing to boot over it would be disproportionate.
func ImageWarnings(ref string) []string {
	r := strings.TrimSpace(ref)
	if r == "" {
		return nil
	}
	var out []string
	if strings.Contains(r, "@sha256:") {
		return nil
	}
	tag := ""
	if i := strings.LastIndexByte(r, ':'); i >= 0 && !strings.Contains(r[i:], "/") {
		tag = r[i+1:]
	}
	switch tag {
	case "", "latest", "main", "master", "edge":
		out = append(out, fmt.Sprintf("image %q uses a floating tag; pin it by digest "+
			"(image@sha256:...) so the sandbox you audited is the sandbox that runs", ref))
	}
	if r == DefaultImage {
		out = append(out, fmt.Sprintf("image is still the built-in default %q — "+
			"set executors.kubernetes.image to an image that actually contains the cloop harness", DefaultImage))
	}
	return out
}

// ValidateQuantity checks a Kubernetes resource quantity string.
//
// The full quantity grammar supports scientific notation and signed values;
// this accepts the subset that means anything for a CPU or memory allowance:
// a positive decimal with an optional binary ("Ki", "Mi", "Gi", "Ti", "Pi")
// or decimal ("n", "u", "m", "k", "M", "G", "T", "P", "E") suffix.
//
// Rejecting rather than passing through is the point. A quantity the API
// server cannot parse fails the Pod create with a validation error that names
// the field but not the value, and an operator ends up bisecting their config
// to find which of six limits was the typo.
func ValidateQuantity(q string) error {
	s := strings.TrimSpace(q)
	if s == "" {
		return nil
	}
	// Any whitespace, not just leading and trailing: "4 Gi" would otherwise
	// be reported as an unknown suffix " Gi", which sends the operator
	// looking for the right unit name when the problem is the space.
	if strings.ContainsAny(q, " \t\n\r") {
		return fmt.Errorf("quantity %q contains whitespace (write it as \"4Gi\", not \"4 Gi\")", q)
	}

	// Split the numeric head from the suffix.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	head, suffix := s[:i], s[i:]
	if head == "" {
		return fmt.Errorf("quantity %q has no numeric value", q)
	}
	value, err := strconv.ParseFloat(head, 64)
	if err != nil {
		return fmt.Errorf("quantity %q is not a number", q)
	}
	if value <= 0 {
		return fmt.Errorf("quantity %q must be greater than zero", q)
	}

	switch suffix {
	case "",
		"n", "u", "m", "k", "M", "G", "T", "P", "E",
		"Ki", "Mi", "Gi", "Ti", "Pi", "Ei":
		return nil
	default:
		return fmt.Errorf("quantity %q has an unknown suffix %q "+
			"(expected one of Ki/Mi/Gi/Ti, k/M/G/T, or m for millicores)", q, suffix)
	}
}
