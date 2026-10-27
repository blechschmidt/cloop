package cmd

// hub_verify_image.go: `cloop hub verify-image` checks one of cloop's own
// images the way a hub checks it before a sandbox runs it (Task 20453).
//
// The same function a dispatch calls — imagepolicy.OwnImageCheck — with the
// registry as the resolver, as for a device, and cosign as the verifier, so the
// verdict it prints is the one a run would get. It is what an operator runs
// before turning executors.image_provenance to required, what the remedy of an
// unsigned image tells them to run against a newer tag, and what the publishing
// workflow runs, from the hub image it just published, against the images it
// just signed.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

// verifyImageTimeout bounds one verification: a registry request for a tag
// and a cosign run.
const verifyImageTimeout = 3 * time.Minute

var hubVerifyImageCmd = &cobra.Command{
	Use:   "verify-image <image>",
	Short: "Verify one of cloop's own images against the workflow that publishes them",
	Long: `Verify one of cloop's own published images — ghcr.io/blechschmidt/cloop,
cloop-harness or cloop-harness-copilot — exactly as a hub does before a sandbox
runs it: a tag is resolved to the digest its registry serves now, and cosign
verifies that digest's signature against the pinned identity of
.github/workflows/publish-images.yml on main or on a release tag.

  cloop hub verify-image ghcr.io/blechschmidt/cloop-harness:latest
  cloop hub verify-image --json ghcr.io/blechschmidt/cloop-harness@sha256:…

The verdict is one of:

  verified      the digest carries a signature from the pinned workflow
  unsigned      it carries no signature at all — an image published before
                signing began, or one pushed unsigned
  unverifiable  nothing could say: no cosign here, the registry or Sigstore
                out of reach
  mismatch      it carries a signature, and not the pinned workflow's; a hub
                refuses to run it

An enterprise that rebuilds the images and signs them with its own workflow
repoints the pin with ` + provenance.ImagesIssuerEnv + ` and
` + provenance.ImagesIdentityEnv + `.

Exit status 0 only for verified.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runHubVerifyImage,
}

func runHubVerifyImage(cmd *cobra.Command, args []string) error {
	ref := strings.TrimSpace(args[0])
	if !imagepolicy.IsOwnImage(ref) {
		return fmt.Errorf("%s is not one of cloop's own images (%s); an image of your own is checked by "+
			"sandbox.image_policy's cosign keys and identities instead", ref,
			strings.Join(imagepolicy.OwnRepositories, ", "))
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, verifyImageTimeout)
	defer cancel()

	p, err := imagepolicy.OwnImageCheck{
		Image:    ref,
		Resolver: imagepolicy.NewRegistryResolver(),
		Verifier: &imagepolicy.CosignProvenanceVerifier{},
		Subject:  "this host",
		Field:    "the image",
	}.Run(ctx)
	if p.Status == "" {
		// Not a verdict: the reference could not even be checked.
		return err
	}
	// The warning is a run's sentence ("… ran unverified on …"); nothing ran.
	p.Warning = ""
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if jerr := enc.Encode(p); jerr != nil {
			return jerr
		}
	} else {
		fmt.Fprintf(out, "%s: %s\n", ref, p.Status)
		if p.Digest != "" {
			fmt.Fprintf(out, "  digest:   %s\n", p.Digest)
		}
		fmt.Fprintf(out, "  pin:      %s (issuer %s)\n", p.Identity, p.Issuer)
		if p.Detail != "" {
			fmt.Fprintf(out, "  detail:   %s\n", p.Detail)
		}
	}
	if p.Verified() {
		return nil
	}
	return fmt.Errorf("%s is %s", ref, p.Status)
}

func init() {
	hubVerifyImageCmd.Flags().Bool("json", false, "print the verdict as JSON")
	hubCmd.AddCommand(hubVerifyImageCmd)
}
