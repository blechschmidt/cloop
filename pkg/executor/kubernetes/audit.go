package kubernetes

// Audit seam for the security conformance suite (tests/security).
//
// The same reasoning as container/audit.go: the property worth machine-checking
// — that a project cannot get an image the operator's policy forbids into a Pod
// — is decided inside buildPodFor, behind a constructor that demands a
// credential source and a fake API server. That is exactly the kind of
// precondition that leaves a security property tested only from inside the
// package, where a future caller that bypasses the check would not be noticed.
//
// AuditPodImage exposes the real construction with those preconditions removed.
// It calls the same buildPodFor that Start calls, so a check that stops being
// applied in production stops being applied here too. A test-only
// reimplementation of the policy call would pass forever while production
// drifted, which is the failure this seam exists to prevent.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// AuditPodJSON returns the exact bytes that would be POSTed to the API server
// for spec, with workspaceSecret standing in for the Secret that Start would
// have created.
//
// It exists for one assertion the conformance suite has to be able to make
// from outside this package: that a leased workspace credential never appears
// in the Pod object. That property is decided by buildPod — whether the token
// goes into an `env[].value` or into a `secretKeyRef` — and an in-package test
// of it would be checking the same file that would be edited to break it.
// Rendering the real object and letting an external suite grep the bytes is the
// only form of the check that a future refactor cannot quietly satisfy.
//
// Like AuditPodImage it needs no cluster and no credential source: buildPodFor
// touches neither.
func AuditPodJSON(ctx context.Context, opts Options, spec executor.Spec, workspaceSecret string) ([]byte, error) {
	p, err := auditPod(ctx, opts, spec, workspaceSecret)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// auditPod is the shared construction behind both seams.
func auditPod(ctx context.Context, opts Options, spec executor.Spec, workspaceSecret string) (*pod, error) {
	if opts.Namespace == "" {
		// Normalize leaves it empty because in production the namespace comes
		// from the credential lease, which this seam deliberately has none of.
		opts.Namespace = DefaultNamespace
	}
	norm, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	ex := &Executor{
		id:   norm.ID,
		opts: norm,
		// The production verifier, so a signature requirement here behaves as
		// it would on a hub: it looks for cosign, and refuses when there is
		// none rather than passing.
		verifier: imagepolicy.NewCosignVerifier(),
		handles:  make(map[string]*record),
	}
	return ex.buildPodFor(ctx, spec, "audit", norm.Namespace, workspaceSecret)
}

// AuditPodImage returns the image a Pod would actually be created with for
// spec, or the error that refuses it.
//
// It is the answer to "what would the kubelet pull", which for a digest-pinned
// policy must be a digest and never the tag a project wrote. No credential
// source and no cluster are needed: nothing on this path touches either.
func AuditPodImage(ctx context.Context, opts Options, spec executor.Spec) (string, error) {
	// No workspace Secret: this seam builds the Pod without a cluster, so
	// there is nothing to have created one in. A git workspace still renders
	// its init container, just with an unauthenticated fetch — which is what
	// the image question being asked here is about anyway.
	p, err := auditPod(ctx, opts, spec, "")
	if err != nil {
		return "", err
	}
	for _, c := range p.Spec.Containers {
		if c.Name == ContainerName {
			return c.Image, nil
		}
	}
	return "", fmt.Errorf("kubernetes: the built Pod has no %q container", ContainerName)
}
