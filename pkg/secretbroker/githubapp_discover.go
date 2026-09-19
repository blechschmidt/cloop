package secretbroker

// Discovery: the two read-only questions a hub asks GitHub on an operator's
// behalf while they are configuring an App, as opposed to while a task is
// running.
//
// Both exist because configuring a github_app secret used to require knowing
// two things the operator does not have. GitHub's App settings page gives out
// an App ID and a private key; the installation ID belongs to whoever installed
// the App and appears only in a settings URL, and the list of repositories the
// installation covers appears nowhere at all outside GitHub. Before Task 20306
// the answer to both was "go and look", and a wrong guess surfaced as a 404
// during someone else's run.
//
// Neither call can produce a credential for anyone. Installation discovery is
// authenticated by a JWT this process signs and holds for the length of one
// HTTP request. The repository listing needs an installation token, so it mints
// one with metadata:read — the narrowest permission that can enumerate names,
// and one that cannot read a line of code — and destroys it before returning.

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// DiscoverGitHubAppInstallations reports where an App is installed.
//
// The payload is a github_app payload with the installation_id omitted: an
// app_id, a private_key, and optionally a base_url for GitHub Enterprise
// Server. It is the operator's own input, arriving from a dialog, and is never
// stored — the caller decides which installation to keep and mints the secret
// afterwards with that ID filled in.
//
// The returned list is public information: account names and numeric IDs. It is
// sorted by account so a hub with several installations renders the same order
// on every call rather than GitHub's.
func (b *Broker) DiscoverGitHubAppInstallations(ctx context.Context, payload []byte) ([]AppInstallation, error) {
	if b == nil {
		return nil, wrapf(ErrGitHubAppMint, "no broker")
	}
	api := b.githubAPI()
	if api == nil {
		return nil, wrapf(ErrGitHubAppMint,
			"this hub has no GitHub API client, so a GitHub App cannot be discovered")
	}
	cred, err := ParseGitHubAppConnection(payload)
	if err != nil {
		return nil, err
	}
	// The JWT authenticates the app, not an installation, which is the only
	// thing that can be true before an installation is known.
	appJWT, err := cred.signJWT(b.now())
	if err != nil {
		return nil, err
	}
	installs, err := api.ListAppInstallations(ctx, cred.BaseURL, appJWT)
	if err != nil {
		return nil, err
	}
	if len(installs) == 0 {
		// A working key that reaches GitHub and finds nothing is a specific,
		// fixable state — the App exists but nobody has installed it — and it
		// is worth saying so rather than returning an empty list the dialog
		// would have to interpret.
		return nil, wrapf(ErrGitHubAppMint,
			"GitHub App %d is not installed on any account; install it on the organisation "+
				"or user whose repositories cloop should reach, then try again", cred.AppID)
	}
	sort.Slice(installs, func(i, j int) bool {
		if strings.EqualFold(installs[i].Account, installs[j].Account) {
			return installs[i].ID < installs[j].ID
		}
		return strings.ToLower(installs[i].Account) < strings.ToLower(installs[j].Account)
	})
	return installs, nil
}

// GitHubAppRepositories lists the repositories a stored github_app secret's
// installation covers.
//
// This is what turns assigning repositories to a project into picking from a
// list instead of typing patterns blind. A name typed by hand is a name that
// can be wrong in a way nothing detects until a clone fails; a name chosen from
// the installation's own inventory is one GitHub has already confirmed.
//
// The secret's private key is opened, used, and dropped inside this call. The
// discovery token minted to read the list is metadata:read and is destroyed
// before the function returns.
func (b *Broker) GitHubAppRepositories(ctx context.Context, ref string) ([]InstallationRepo, error) {
	if b == nil {
		return nil, wrapf(ErrGitHubAppMint, "no broker")
	}
	sec, err := b.DescribeSecret(ref)
	if err != nil {
		return nil, err
	}
	if sec.Kind != KindGitHubApp {
		return nil, wrapf(ErrInvalidKind,
			"secret %s is kind %s; only a github_app secret has an installation to enumerate",
			sec.Name, sec.Kind)
	}
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, sec.ID), sec.Envelope())
	if err != nil {
		return nil, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, sec.Name, err)
	}
	defer zero(plaintext)

	cred, err := ParseGitHubApp(plaintext)
	if err != nil {
		return nil, err
	}
	if b.appMinter == nil {
		return nil, wrapf(ErrGitHubAppMint,
			"this hub has no GitHub API client, so a GitHub App installation cannot be enumerated")
	}
	appJWT, err := cred.signJWT(b.now())
	if err != nil {
		return nil, err
	}
	// Shares the minter's cache with the lease path on purpose: an operator who
	// has just opened this list and then starts a run should not make the hub
	// enumerate the same installation twice, and the staleness window is the
	// one already reasoned about in githubapp.go — it can only narrow.
	repos, err := b.appMinter.inventory(ctx, cred, appJWT)
	if err != nil {
		return nil, err
	}
	out := append([]InstallationRepo(nil), repos...)
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].FullName) < strings.ToLower(out[j].FullName)
	})
	return out, nil
}

// githubAPI is the GitHub client this broker was built with, or the package
// default. It is a method rather than a field read so the nil-broker and
// nil-minter cases have one answer.
func (b *Broker) githubAPI() GitHubAppAPI {
	if b == nil || b.appMinter == nil {
		return nil
	}
	return b.appMinter.api
}
