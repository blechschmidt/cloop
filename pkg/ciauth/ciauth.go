// Package ciauth federates a CI/CD pipeline's OIDC identity into a cloop
// session, without the pipeline ever holding a long-lived cloop credential.
//
// # The problem it solves
//
// Running an agent harness from CI means the runner needs an Anthropic
// credential. The obvious way to arrange that is a repository secret holding
// an API key, and it is the wrong way: the key is long-lived, it is copied
// into every fork-adjacent workflow that can read the secret, it survives the
// job that used it, and nothing about it says which pipeline spent it.
//
// GitHub Actions can instead mint a short-lived, signed OIDC token that says
// what the job *is* — repository, ref, workflow, environment, actor, event —
// and hand that to a third party. This package is the third party. It verifies
// the token against the forge's own signing keys, matches the claims against
// an allowlist the operator wrote, and returns the policy a matching pipeline
// has been granted. What the pipeline receives in exchange is minted by
// pkg/claudeproxy and is worth only what the policy says, for only as long as
// the job runs.
//
// The credential never leaves the hub. That is the same bargain pkg/gitproxy
// makes for a GitHub PAT and pkg/kubeguard makes for a kubeconfig, applied to
// the one credential CI actually wants.
//
// # Trust is in two independent halves
//
// Verify establishes that the forge signed this token and that it was minted
// for this hub. Match establishes that the operator meant to trust the
// identity it describes. Neither is sufficient: every GitHub repository in the
// world can obtain a correctly signed token naming itself, so a hub that
// verifies without matching trusts the internet.
package ciauth

import (
	"errors"
	"fmt"
	"strings"
)

// GitHubActionsIssuer is the issuer GitHub Actions stamps into the ID tokens
// it mints for hosted and self-hosted runners alike.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// DefaultAudience is the `aud` value a pipeline must request. It is not the
// hub URL: GitHub lets a workflow choose any audience string, so binding to a
// URL would give a false sense that the token could only have been minted for
// this deployment. Operators who run more than one hub should set a distinct
// audience per hub and, more importantly, write rules that name repositories.
const DefaultAudience = "cloop"

// Errors callers distinguish. Everything a pipeline sees collapses to one
// HTTP status; these exist so the audit trail and the operator-facing message
// can say which of the two halves of trust failed.
var (
	// ErrUnverified means the token is not something this hub will read: bad
	// signature, wrong issuer, wrong audience, expired, replayed.
	ErrUnverified = errors.New("ciauth: token not verified")

	// ErrNoRule means the token is genuine and names an identity no rule
	// admits. This is the common case on a correctly configured hub and is
	// not an error condition worth alerting on.
	ErrNoRule = errors.New("ciauth: no rule admits this pipeline")

	// ErrReplayed means this exact token was already exchanged.
	ErrReplayed = errors.New("ciauth: token has already been exchanged")

	// ErrDisabled means CI federation is not turned on for this hub.
	ErrDisabled = errors.New("ciauth: CI federation is not enabled")
)

// Claims is a verified token's payload.
//
// The typed fields are the GitHub Actions claims rules are usually written
// against; All carries the decoded payload so a CEL condition can reach any
// claim, including ones GitHub adds after this code was written. Rules are
// evaluated against All, never against the typed fields, so the two can never
// disagree.
type Claims struct {
	// Issuer, Subject, Audience and the lifetime bounds are the parts Verify
	// checked. They are recorded rather than recomputed so an audit entry
	// describes the token that was actually accepted.
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	JTI      string   `json:"jti,omitempty"`

	IssuedAt  int64 `json:"iat,omitempty"`
	NotBefore int64 `json:"nbf,omitempty"`
	ExpiresAt int64 `json:"exp,omitempty"`

	// The workload's identity, as GitHub describes it.
	Repository          string `json:"repository,omitempty"`
	RepositoryOwner     string `json:"repository_owner,omitempty"`
	RepositoryVisiblity string `json:"repository_visibility,omitempty"`
	Ref                 string `json:"ref,omitempty"`
	RefType             string `json:"ref_type,omitempty"`
	Workflow            string `json:"workflow,omitempty"`
	WorkflowRef         string `json:"workflow_ref,omitempty"`
	JobWorkflowRef      string `json:"job_workflow_ref,omitempty"`
	Environment         string `json:"environment,omitempty"`
	Actor               string `json:"actor,omitempty"`
	EventName           string `json:"event_name,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	RunAttempt          string `json:"run_attempt,omitempty"`
	RunnerEnvironment   string `json:"runner_environment,omitempty"`
	SHA                 string `json:"sha,omitempty"`

	// All is the decoded payload, for CEL conditions.
	All map[string]any `json:"-"`
}

// Label is a short, credential-free description for audit entries and the
// sessions table. It never contains the token.
func (c *Claims) Label() string {
	if c == nil {
		return "unknown"
	}
	var b strings.Builder
	if c.Repository != "" {
		b.WriteString(c.Repository)
	} else {
		b.WriteString(c.Subject)
	}
	if c.Ref != "" {
		b.WriteString("@")
		b.WriteString(c.Ref)
	}
	if c.Workflow != "" {
		b.WriteString(" (")
		b.WriteString(c.Workflow)
		b.WriteString(")")
	}
	return b.String()
}

// RunURL reconstructs the Actions run this token was minted for, or "" when
// the claims do not carry enough to do so. Useful in the dashboard: an
// operator looking at a denied exchange wants the job, not the claim set.
func (c *Claims) RunURL(forgeBase string) string {
	if c == nil || c.Repository == "" || c.RunID == "" {
		return ""
	}
	base := strings.TrimSuffix(forgeBase, "/")
	if base == "" {
		base = "https://github.com"
	}
	return fmt.Sprintf("%s/%s/actions/runs/%s", base, c.Repository, c.RunID)
}
