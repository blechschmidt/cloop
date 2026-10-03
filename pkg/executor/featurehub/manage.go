package featurehub

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/featureops"
)

// The operations below are pkg/featureops's, run by the hub in hub mode
// (featureops.WithHubEnv) for a project bound to an executor that isolates
// from the hub's filesystem.
//
// For a project the hub runs itself, `cloop feature …` is dispatched to the
// project's executor like any workload and runs there, with that executor's
// credentials. That cannot work for an isolating one: a container sees the
// project at /workspace, so a worktree created there records paths that mean
// nothing on the hub, and a remote device does not have the project at all.
// The feature lives on the hub, so the hub is the only place it can be created,
// removed, or pushed from.

// hubContext puts ctx in hub mode for the repository at dir.
func hubContext(ctx context.Context, dir string) (context.Context, error) {
	env, err := HubEnv(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("prepare git for %s: %w", dir, err)
	}
	return featureops.WithHubEnv(ctx, featureops.HubEnv(env)), nil
}

// Create makes a feature of opts.ProjectDir.
func Create(ctx context.Context, opts featureops.CreateOptions) (*feature.Info, error) {
	hctx, err := hubContext(ctx, opts.ProjectDir)
	if err != nil {
		return nil, err
	}
	return featureops.Create(hctx, opts)
}

// Remove removes a feature of opts.ProjectDir.
func Remove(ctx context.Context, opts featureops.RemoveOptions) (*featureops.RemoveResult, error) {
	hctx, err := hubContext(ctx, opts.ProjectDir)
	if err != nil {
		return nil, err
	}
	return featureops.Remove(hctx, opts)
}

// ErrNoCredential reports a pull request the hub has no credential to open.
var ErrNoCredential = errors.New("no credential for the project's repository")

// OpenPR pushes a feature's branch and opens its pull request. opts.Token is
// the only credential used — the project's grant, or the hub's own token where
// policy allows it; the caller decides which.
func OpenPR(ctx context.Context, opts featureops.PROptions) (*featureops.PRResult, error) {
	if strings.TrimSpace(opts.Token) == "" {
		return nil, fmt.Errorf("%w: %w — grant the project its GitHub repository with write and "+
			"pull-request access", featureops.ErrNoToken, ErrNoCredential)
	}
	hctx, err := hubContext(ctx, opts.FeatureDir)
	if err != nil {
		return nil, err
	}
	return featureops.OpenPR(hctx, opts)
}

// RefreshPR re-reads a feature's pull request state from the forge.
func RefreshPR(ctx context.Context, dir, token, apiURL string) (*feature.PR, error) {
	hctx, err := hubContext(ctx, dir)
	if err != nil {
		return nil, err
	}
	return featureops.RefreshPR(hctx, dir, token, apiURL)
}

// Origin returns the forge repository behind the feature's origin remote, read
// with hub-mode git: what a pull request would be opened against.
func Origin(ctx context.Context, dir string) (featureops.Remote, error) {
	g, err := newGitRunner(ctx, dir)
	if err != nil {
		return featureops.Remote{}, err
	}
	raw, err := g.run(ctx, "config", "--get", "remote.origin.url")
	if err != nil || strings.TrimSpace(raw) == "" {
		return featureops.Remote{}, fmt.Errorf("the repository has no origin remote to open a pull request on")
	}
	return featureops.ParseRemote(raw)
}
