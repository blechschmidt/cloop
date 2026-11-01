package config

// requirements: requirement-gated completion (Task 20461).
//
// The gate itself is project state (pm.RequirementsGate): it travels with the
// project to the executor a run is dispatched to, which never sees this file.
// This section is the declaration a repository can carry. `cloop run` writes
// a declared gate into the project before it starts, so the setting a config
// file names is the one the run holds its tasks to; the dashboard's control
// rewrites the declaration whenever it changes a project that has one, so the
// two never disagree. A project whose config.yaml says nothing keeps whatever
// the dashboard or `cloop requirements gate` last set.

import (
	"fmt"
	"strings"
)

// The modes requirements.gate accepts. They are pm's (RequirementsGateModes);
// config cannot import pm, so they are spelled here and a test keeps the two
// lists equal.
const (
	RequirementsGateOff        = "off"
	RequirementsGateLinked     = "linked"
	RequirementsGateLinkedMust = "linked+must"
)

// RequirementsGateModes lists the modes requirements.gate accepts.
func RequirementsGateModes() []string {
	return []string{RequirementsGateOff, RequirementsGateLinked, RequirementsGateLinkedMust}
}

// RequirementsConfig is the requirements section.
type RequirementsConfig struct {
	// Gate is off, linked or linked+must; empty declares nothing.
	Gate string `yaml:"gate,omitempty"`
	// Assess asks the model about the requirements in the gate's scope that
	// have no tests. Unset declares nothing.
	Assess *bool `yaml:"assess,omitempty"`
}

// NormalizeRequirementsGate reads a mode as a person writes it — any case,
// linked-must or linked_must for linked+must — and returns it as stored, or
// an error naming the modes. The empty string is not a mode.
func NormalizeRequirementsGate(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case RequirementsGateOff:
		return RequirementsGateOff, nil
	case RequirementsGateLinked:
		return RequirementsGateLinked, nil
	case RequirementsGateLinkedMust, "linked-must", "linked_must":
		return RequirementsGateLinkedMust, nil
	}
	return "", fmt.Errorf("requirements.gate must be one of %s (got %q)",
		strings.Join(RequirementsGateModes(), ", "), v)
}

// Declares reports whether the section declares a gate.
func (r RequirementsConfig) Declares() bool { return strings.TrimSpace(r.Gate) != "" }

// ValidateRequirements is the strict check `cloop config set` and `cloop
// config validate` apply: a declared gate must be a mode.
func ValidateRequirements(r RequirementsConfig) error {
	if !r.Declares() {
		return nil
	}
	_, err := NormalizeRequirementsGate(r.Gate)
	return err
}
