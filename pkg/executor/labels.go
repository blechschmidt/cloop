package executor

// labels.go: what an executor label may be (Task 20432).
//
// Labels used to be scheduler metadata that nothing enforced, so nothing
// checked them either: an enrollment could carry a key with a comma in it, and
// the selector syntax a grant is written in — label:k1=v1,k2=v2 — can never
// name such a key. Once a label decides which credentials reach a machine, a
// label no selector can express is a grant nobody can write, so every place an
// operator states labels — an enrollment token, the configuration of a
// container or Kubernetes executor, a label edit — is held to the rules a
// selector can match.

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Label limits. Generous for what labels are for — region, site, tier, gpu —
// and small enough that a label set never makes a grant listing or an audit
// row unwieldy.
const (
	MaxLabels          = 32
	MaxLabelKeyBytes   = 63
	MaxLabelValueBytes = 253
)

// NormalizeLabels trims every key and value, the way a selector is trimmed
// when it is parsed. Nil for none.
func NormalizeLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// ValidateLabels reports why labels could not be matched by a selector, or
// nil. Call it on normalized labels: it refuses surrounding space rather than
// trimming it, so that what is stored is exactly what a selector compares.
//
// A key is a non-empty run of printable characters without space, ',' or '='.
// A value may be empty and may contain '=' (a selector splits a pair at its
// first '='), but not ',', which separates pairs, nor a control character.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return fmt.Errorf("%d labels; at most %d are allowed", len(labels), MaxLabels)
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := validateLabelKey(k); err != nil {
			return err
		}
		if err := validateLabelValue(k, labels[k]); err != nil {
			return err
		}
	}
	return nil
}

func validateLabelKey(k string) error {
	switch {
	case k == "":
		return fmt.Errorf("a label has an empty key")
	case k != strings.TrimSpace(k):
		return fmt.Errorf("label key %q has surrounding space", k)
	case len(k) > MaxLabelKeyBytes:
		return fmt.Errorf("label key %q is longer than %d bytes", k, MaxLabelKeyBytes)
	}
	for _, r := range k {
		switch {
		case r == ',' || r == '=':
			return fmt.Errorf("label key %q contains %q, which a selector cannot express", k, string(r))
		case unicode.IsSpace(r) || !unicode.IsPrint(r):
			return fmt.Errorf("label key %q contains a space or a control character", k)
		}
	}
	return nil
}

func validateLabelValue(k, v string) error {
	switch {
	case v != strings.TrimSpace(v):
		return fmt.Errorf("the value of label %q has surrounding space", k)
	case len(v) > MaxLabelValueBytes:
		return fmt.Errorf("the value of label %q is longer than %d bytes", k, MaxLabelValueBytes)
	}
	for _, r := range v {
		switch {
		case r == ',':
			return fmt.Errorf("the value of label %q contains ',', which a selector cannot express", k)
		case !unicode.IsPrint(r) && r != ' ':
			return fmt.Errorf("the value of label %q contains a control character", k)
		}
	}
	return nil
}
