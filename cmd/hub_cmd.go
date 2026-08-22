package cmd

// hub_cmd.go is the operator surface for the control plane's own transport
// security: generating a development certificate, and reading back the pin
// that edge devices must be told to expect.
//
// Both exist because the alternative is worse. Without `tls-init` an operator
// evaluating cloop reaches for `ws://` and gets a working system, at which
// point plaintext is the path of least resistance and stays. Without `pin`
// there is no way to answer "what should the device's --pin be" for a
// certificate cloop did not generate, which is every production deployment.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

var hubCmd = &cobra.Command{
	Use:   "hub",
	Short: "Manage the cloop control plane's transport security",
	Long: `Operator commands for the control plane ("hub") itself.

A hub serves the dashboard, the REST API, and the endpoint where remote
executor agents dial in. All three share one TLS configuration, set under
` + "`ui.tls`" + ` in .cloop/config.yaml or via --tls-cert/--tls-key on
` + "`cloop ui`" + ` and ` + "`cloop serve`" + `.`,
}

var hubTLSInitCmd = &cobra.Command{
	Use:   "tls-init",
	Short: "Generate a self-signed TLS certificate for development",
	Long: `Generate a self-signed certificate and key for local development.

This is NOT for production. A self-signed certificate is trusted by no
system store, so every agent that dials the hub must be handed the
certificate explicitly (` + "`cloop executor agent --ca-file`" + `). For a
real deployment use a certificate from a CA your devices already trust —
Let's Encrypt, or your organisation's internal CA — and point ui.tls at it.

What this does give you is a hub that speaks TLS at all, so enrollment
tokens and agent credentials are not crossing your network in the clear
while you evaluate. The printed pin is what devices verify the hub with.

Files are written through cloop's atomic-write path: the key is mode 0600
from the instant it exists and is never briefly world-readable, and a crash
mid-write cannot leave a certificate that does not match its key.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := cmd.Flags().GetString("dir")
		hosts, _ := cmd.Flags().GetStringSlice("host")
		days, _ := cmd.Flags().GetInt("days")
		force, _ := cmd.Flags().GetBool("force")

		workdir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine working directory: %w", err)
		}
		if strings.TrimSpace(dir) == "" {
			dir = filepath.Join(workdir, ".cloop", "tls")
		}
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")

		// Refuse to clobber. Overwriting the key silently invalidates every
		// pin already distributed to a device, and the failure surfaces later
		// as a fleet that will not reconnect.
		if !force {
			for _, p := range []string{certPath, keyPath} {
				if _, statErr := os.Stat(p); statErr == nil {
					return fmt.Errorf(
						"%s already exists.\n"+
							"Regenerating changes the hub's key, so every agent pinned to the old one "+
							"will refuse to connect until it is re-pinned.\n"+
							"Pass --force if that is what you want, or `cloop hub pin` to read the current pin",
						p)
				}
			}
		}

		if len(hosts) == 0 {
			hosts = defaultCertHosts()
		}
		pin, err := tlsconf.GenerateSelfSigned(certPath, keyPath, tlsconf.SelfSignedOptions{
			Hosts:    hosts,
			ValidFor: time.Duration(days) * 24 * time.Hour,
		})
		if err != nil {
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		warn := color.New(color.FgYellow, color.Bold)
		dim := color.New(color.Faint)

		header.Println("Generated a development TLS certificate")
		fmt.Printf("  certificate: %s\n", certPath)
		fmt.Printf("  key:         %s (mode 0600)\n", keyPath)
		fmt.Printf("  valid for:   %s\n", strings.Join(hosts, ", "))
		fmt.Printf("  expires:     %s\n", time.Now().AddDate(0, 0, days).Format("2006-01-02"))
		fmt.Printf("  pin:         %s\n\n", pin)

		warn.Println("Development only — this certificate is trusted by no system store.")
		fmt.Println()
		fmt.Println("Enable it in .cloop/config.yaml:")
		dim.Printf("\n  ui:\n    tls:\n      cert_file: %s\n      key_file: %s\n      min_version: \"1.2\"\n\n",
			certPath, keyPath)
		fmt.Println("Then enroll a device — the pin travels with the token:")
		dim.Println("\n  cloop executor enroll --name edge-1 --server wss://<host>:8080/api/executors/connect")
		fmt.Println()
		fmt.Println("On the device, hand it this certificate as a trusted root:")
		dim.Printf("\n  cloop executor agent --server … --token … --pin %s --ca-file %s\n", pin, certPath)
		return nil
	},
}

var hubPinCmd = &cobra.Command{
	Use:   "pin",
	Short: "Print the SPKI pin of the hub's TLS certificate",
	Long: `Print the pin that agents should verify this hub with.

The pin is a SHA-256 over the certificate's public key (its SPKI), not over
the certificate itself. That means a routine certificate renewal which reuses
the same key does NOT change the pin, so a fleet of enrolled devices survives
renewal without re-enrollment. Rotating onto a new key does change it, and is
the case worth staging: distribute the new pin alongside the old one, roll the
hub, then retire the old.

With no --cert, the certificate is read from ui.tls.cert_file in
.cloop/config.yaml.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, _ := cmd.Flags().GetString("cert")
		if strings.TrimSpace(certPath) == "" {
			workdir, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("determine working directory: %w", err)
			}
			cfg, err := config.Load(workdir)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			certPath = strings.TrimSpace(cfg.UI.TLS.CertFile)
			if certPath == "" {
				return fmt.Errorf(
					"no TLS certificate configured.\n" +
						"Set ui.tls.cert_file in .cloop/config.yaml, pass --cert <path>, " +
						"or run `cloop hub tls-init` for a development certificate")
			}
		}
		pin, err := tlsconf.PinFromCertFile(certPath)
		if err != nil {
			return err
		}
		fmt.Println(pin)
		return nil
	},
}

// defaultCertHosts is the SAN list for a generated development certificate:
// loopback plus this machine's hostname and non-loopback addresses.
//
// The addresses matter more than they look. The whole point of a hub is that
// devices dial it from elsewhere on the network, and a certificate valid only
// for "localhost" fails hostname verification for every one of them — which
// presents as an inscrutable TLS error rather than as "you generated the wrong
// certificate".
func defaultCertHosts() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	seen := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

	if name, err := os.Hostname(); err == nil && name != "" && !seen[name] {
		hosts = append(hosts, name)
		seen[name] = true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return hosts
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		s := ipnet.IP.String()
		if !seen[s] {
			hosts = append(hosts, s)
			seen[s] = true
		}
	}
	return hosts
}

func init() {
	hubTLSInitCmd.Flags().String("dir", "",
		"directory to write cert.pem and key.pem into (default: .cloop/tls)")
	hubTLSInitCmd.Flags().StringSlice("host", nil,
		"DNS name or IP the certificate is valid for (repeatable; default: localhost plus this machine)")
	hubTLSInitCmd.Flags().Int("days", 365, "certificate lifetime in days")
	hubTLSInitCmd.Flags().Bool("force", false,
		"overwrite existing key material (invalidates pins already distributed to devices)")

	hubPinCmd.Flags().String("cert", "",
		"certificate to read (default: ui.tls.cert_file from .cloop/config.yaml)")

	hubCmd.AddCommand(hubTLSInitCmd)
	hubCmd.AddCommand(hubPinCmd)
	rootCmd.AddCommand(hubCmd)
}
