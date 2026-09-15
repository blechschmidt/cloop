package cmd

// `cloop hub doctor` — the pre-flight for a hosted deployment.
//
// It is a sibling of `cloop doctor`, not a replacement, because the two have
// different subjects. `cloop doctor` asks whether this working copy can run
// cloop: is there a .cloop directory, is `go` installed, is the API key set.
// Every one of those can pass on a deployment that is comprehensively broken as
// a hub — an issuer that does not resolve, a certificate that expired, an RBAC
// policy under which nobody is an administrator, strict mode with nothing to
// dispatch to — because none of those conditions existed when it was written.
//
// The intended use is twice: once before the first `docker compose up` or `helm
// install`, and once in CI on the config repo. Hence --json and an exit code
// that is 1 only on failures. Warnings do not fail the command, because a good
// number of them are deployment choices (a hub behind a proxy has no
// certificate of its own) and a gate that goes red on choices gets switched
// off, taking the real failures with it.

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
)

var hubDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose a hosted control plane: SSO, TLS, RBAC, image trust, executors, storage, quotas",
	Long: `Check whether this deployment would actually work as a hub.

` + "`cloop doctor`" + ` diagnoses a developer's checkout. This diagnoses the
things that only exist once cloop is hosted, and that fail silently or at the
worst possible moment when they are wrong:

  identity     the issuer resolves, its discovery document agrees on its own
               name, its signing keys are fetchable, and the redirect URI
               matches the external URL a browser will actually be on
  transport    the certificate and key are a matching pair, the chain is
               ordered, it has not expired and it covers the external hostname
  secrets      CLOOP_SECRET_KEY is present, and is generated key material
               rather than a passphrase or a placeholder from the docs
  authorization the role mappings parse, and — the one that has no runtime
               symptom — somebody maps to admin
  image trust  the policy is deny-by-default, the hub's own executor images
               satisfy it, and the allowed registries are reachable
  executors    strict mode has something isolating to dispatch to, and every
               registered executor answers a liveness probe
  storage      state.db passes quick_check and its schema matches this binary
  admission    quotas and budget bound what one tenant can consume

Every finding that is not a pass carries a one-line remediation.

` + "`--smoke`" + ` adds the check the others cannot make: it dispatches a trivial
workload — no network, no repository, no model call — through the same
primitives a real task takes, and reports each leg separately.

  placement    would the scheduler actually choose this executor
  workspace    did the workload get a usable working directory
  lease        was a throwaway credential file delivered to the sandbox
  dispatch     did the workload start and exit zero
  logs         did its output come back, complete and correctly attributed
  write_back   did file changes return, where the backend advertises it
  revocation   is the credential gone — verified, not assumed
  cleanup      was every container, directory and credential removed

It defaults to every non-cordoned executor, so "which of my ten devices is
broken" is one command; --executor narrows it to one, and naming a cordoned
device smokes it anyway. Nothing it creates outlives the run: the credential's
TTL is measured in seconds, and everything is removed on every exit path,
including ctrl-C.

Every finding that is not a pass carries a one-line remediation.

Exit codes. Warnings never fail the command — several are legitimate
deployment choices, and a CI gate that goes red on choices gets disabled,
taking the real failures with it.

  0  only passes and warnings
  1  a configuration check failed
  3  --smoke found no executor to dispatch to
  4  --smoke failed a stage on at least one executor
  5  --smoke could not clean up after itself — needs a human

  cloop hub doctor
  cloop hub doctor --json | jq '.findings[] | select(.severity=="fail")'
  cloop hub doctor --offline     # config only; contacts nothing
  cloop hub doctor --smoke       # every non-cordoned executor
  cloop hub doctor --smoke --executor edge-01 --json`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runHubDoctor,
}

func runHubDoctor(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Flags().GetBool("json")
	offline, _ := cmd.Flags().GetBool("offline")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	strict, _ := cmd.Flags().GetBool("strict")
	probeNetpol, _ := cmd.Flags().GetBool("probe-network-policy")
	probeExecutor, _ := cmd.Flags().GetString("executor")
	probeImage, _ := cmd.Flags().GetString("probe-image")
	probeTimeout, _ := cmd.Flags().GetDuration("probe-timeout")
	smoke, _ := cmd.Flags().GetBool("smoke")
	smokeTimeout, _ := cmd.Flags().GetDuration("smoke-timeout")

	if timeout <= 0 {
		return fmt.Errorf("--timeout must be positive (got %s)", timeout)
	}
	if probeNetpol && probeTimeout <= 0 {
		return fmt.Errorf("--probe-timeout must be positive (got %s)", probeTimeout)
	}
	if smoke && smokeTimeout <= 0 {
		return fmt.Errorf("--smoke-timeout must be positive (got %s)", smokeTimeout)
	}
	// Naming an executor without asking for a probe is a command that silently
	// does nothing the operator asked for. Say so rather than run the read-only
	// checks and let them believe a probe happened.
	if !probeNetpol && !smoke && strings.TrimSpace(probeExecutor) != "" {
		return fmt.Errorf("--executor applies to --smoke or --probe-network-policy; " +
			"add one of them, or drop --executor")
	}
	if !probeNetpol && strings.TrimSpace(probeImage) != "" {
		return fmt.Errorf("--probe-image only applies to --probe-network-policy")
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}

	// A config that fails to load is diagnosed, not fatal: Run reports the
	// absence as its own finding, and a hub whose config.yaml is unparseable
	// is precisely the case someone runs this command for.
	cfg, cfgErr := config.Load(dir)
	if cfgErr != nil {
		cfg = nil
	}

	rep := hubdoctor.Run(cmd.Context(), dir, cfg, hubdoctor.Options{
		Offline:            offline,
		Timeout:            timeout,
		ProbeNetworkPolicy: probeNetpol,
		ProbeExecutorID:    probeExecutor,
		ProbeImage:         probeImage,
		ProbeTimeout:       probeTimeout,
		Smoke:              smoke,
		SmokeTimeout:       smokeTimeout,
		// To stderr, so `--json | jq` still gets clean JSON on stdout while an
		// operator watching a long probe can see which Pod or device it is on.
		ProbeLogf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "  probe: "+format+"\n", args...)
		},
	})

	if asJSON {
		out, err := rep.JSON()
		if err != nil {
			return err
		}
		_, _ = cmd.OutOrStdout().Write(out)
		return exitFor(rep, strict)
	}

	renderHubDoctor(rep)
	return exitFor(rep, strict)
}

// renderHubDoctor prints the report with colour, falling back to the plain
// renderer's layout so the two stay identical modulo escape codes.
func renderHubDoctor(rep *hubdoctor.Report) {
	header := color.New(color.FgCyan, color.Bold)
	pass := color.New(color.FgGreen)
	warn := color.New(color.FgYellow)
	fail := color.New(color.FgRed, color.Bold)
	dim := color.New(color.Faint)

	header.Printf("cloop hub doctor — %s\n", rep.Dir)
	mode := "permissive (host execution allowed)"
	if rep.StrictMode {
		mode = "strict (no host execution)"
	}
	fmt.Printf("execution policy: %s\n", mode)
	if rep.Offline {
		dim.Println("offline: network probes were skipped")
	}
	fmt.Println()

	// Sections are keyed by the rendered heading rather than by the check
	// prefix, so quotas.* and budget.* land under one ADMISSION heading
	// instead of printing it twice in a row.
	lastSection := ""
	for _, f := range rep.Findings {
		group := f.Check
		for i, r := range group {
			if r == '.' {
				group = group[:i]
				break
			}
		}
		if section := groupTitle(group); section != lastSection {
			if lastSection != "" {
				fmt.Println()
			}
			dim.Printf("%s\n", section)
			lastSection = section
		}

		c := pass
		switch f.Severity {
		case hubdoctor.SeverityWarn:
			c = warn
		case hubdoctor.SeverityFail:
			c = fail
		}
		c.Printf("  %s ", f.Severity.Symbol())
		fmt.Printf("%-32s %s\n", f.Title, f.Message)
		if f.Remediation != "" {
			dim.Printf("      → %s\n", f.Remediation)
		}
		for _, k := range sortedDetailKeys(f.Details) {
			dim.Printf("      %s: %v\n", k, f.Details[k])
		}
	}

	renderSmoke(rep, pass, warn, fail, dim)

	passN, warnN, failN := rep.Counts()
	fmt.Println()
	summary := fmt.Sprintf("%d passed, %d warning(s), %d failure(s)", passN, warnN, failN)
	switch {
	case failN > 0:
		fail.Println(summary)
	case warnN > 0:
		warn.Println(summary)
	default:
		pass.Println(summary)
	}
}

// renderSmoke prints the per-stage table for each executor that was smoked.
//
// It is rendered separately from the findings rather than as more of them
// because the two answer different questions. A finding is a verdict on the
// hub; this is a trace of one run through it, and an operator debugging a
// broken device reads it top to bottom looking for the first ✗. Collapsing it
// into the findings list would either bury that trace or flood the report with
// eight rows per device.
func renderSmoke(rep *hubdoctor.Report, pass, warn, fail, dim *color.Color) {
	if len(rep.Smoke) == 0 {
		return
	}
	fmt.Println()
	dim.Println("DISPATCH SMOKE TEST")
	for _, res := range rep.Smoke {
		fmt.Printf("  %s (%s, isolation %s) — %dms\n",
			res.ExecutorID, res.Kind, res.Isolation, res.DurationMS)
		for _, s := range res.Stages {
			c, symbol := pass, "✔"
			switch s.Outcome {
			case hubdoctor.StageFail:
				c, symbol = fail, "✗"
			case hubdoctor.StageSkip:
				c, symbol = dim, "–"
			}
			c.Printf("    %s ", symbol)
			fmt.Printf("%-14s %s\n", s.Stage, s.Message)
			// Only a non-pass gets its remediation printed. A green run that
			// explained how to fix each stage would be unreadable, and the
			// text is still in --json for anyone who wants it.
			if s.Outcome != hubdoctor.StagePass && s.Remediation != "" {
				dim.Printf("        → %s\n", s.Remediation)
			}
		}
		switch {
		case len(res.Leaked) > 0:
			fail.Printf("    leaked: %s\n", strings.Join(res.Leaked, "; "))
		case res.FirstFailure != "":
			fail.Printf("    first failure: %s\n", res.FirstFailure)
		default:
			pass.Printf("    the dispatch circuit works end to end\n")
		}
	}
	// Named here rather than only in the exit status, because an operator
	// running this by hand never sees $?.
	if code := rep.SmokeExitCode(); code == hubdoctor.SmokeExitLeaked {
		warn.Println("\n  This run could not clean up after itself. Remove the resources named " +
			"above before re-running.")
	}
}

// groupTitle renders a check-id prefix as a section heading.
func groupTitle(group string) string {
	switch group {
	case "policy":
		return "EXECUTION POLICY"
	case "oidc":
		return "IDENTITY"
	case "tls":
		return "TRANSPORT"
	case "secret_key":
		return "SECRETS"
	case "rbac":
		return "AUTHORIZATION"
	case "images":
		return "IMAGE TRUST"
	case "executors":
		return "EXECUTORS"
	case "storage":
		return "STORAGE"
	case "retention":
		return "DISK RETENTION"
	case "quotas", "budget":
		return "ADMISSION"
	default:
		return group
	}
}

func sortedDetailKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Small maps; insertion sort keeps this dependency-free and stable.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// exitFor turns the report into a process exit, bypassing Cobra's error
// decoration: a doctor that printed a full report and then appended "Error:
// exit status 1" reads as if the tool itself broke.
//
// A --smoke run uses the granular code, so a pipeline can tell a misconfigured
// hub from a broken executor from a leak without parsing JSON. A plain run
// keeps the two-valued code it has always had, because every gate built on it
// treats non-zero as "something is wrong" and a new value would be read as a
// crash.
func exitFor(rep *hubdoctor.Report, strict bool) error {
	code := rep.SmokeExitCode()
	if code == 0 && strict {
		if _, warn, _ := rep.Counts(); warn > 0 {
			code = 1
		}
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func init() {
	hubDoctorCmd.Flags().Bool("json", false,
		"emit the report as JSON for CI (stable check ids)")
	hubDoctorCmd.Flags().Bool("offline", false,
		"skip every network probe: issuer discovery, JWKS, registries, executor liveness")
	hubDoctorCmd.Flags().Duration("timeout", hubdoctor.DefaultProbeTimeout,
		"per-probe timeout")
	hubDoctorCmd.Flags().Bool("strict", false,
		"exit non-zero on warnings too")
	hubDoctorCmd.Flags().Bool("probe-network-policy", false,
		"prove whether the cluster enforces NetworkPolicy by creating two throwaway Pods "+
			"and a default-deny policy (mutates the cluster; cleans up after itself)")
	hubDoctorCmd.Flags().String("executor", "",
		"restrict --probe-network-policy to one executor id")
	hubDoctorCmd.Flags().String("probe-image", "",
		"image the probe Pods run (default busybox:1.36; must provide sh, httpd and wget)")
	hubDoctorCmd.Flags().Duration("probe-timeout", hubdoctor.DefaultNetworkPolicyProbeTimeout,
		"time budget for one --probe-network-policy run")
	hubDoctorCmd.Flags().Bool("smoke", false,
		"dispatch a trivial hermetic workload through the real circuit — placement, workspace, "+
			"a throwaway credential lease, log streaming, teardown and write-back — and report "+
			"each stage (default: every non-cordoned executor)")
	hubDoctorCmd.Flags().Duration("smoke-timeout", hubdoctor.DefaultSmokeTimeout,
		"time budget for one executor's --smoke run")

	hubCmd.AddCommand(hubDoctorCmd)
}
