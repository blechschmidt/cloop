package cmd

// forward_cmd.go is the operator surface for device forwarders: a minimal
// binary that bridges one on-prem USB device or network interface to a cloop
// control plane and does nothing else.
//
// It is the executor-agent commands' shape, narrowed to the one thing a
// forwarder does. `cloop forward enroll` mints a token on the control plane and
// prints the command to run on the device; the device runs `cloop forward` and
// dials back. Nothing here ever dials a device — the device is unreachable, so
// it connects outward, exactly like an agent.

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/forwarderstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// forwarderConnectPath mirrors pkg/ui's route, repeated for the reason
// executorConnectPath is: importing pkg/ui for one string would drag the whole
// dashboard into every command's link graph.
const forwarderConnectPath = "/api/forwarders/connect"

// openForwarderStore opens the control plane's forwarder storage.
func openForwarderStore() (*forwarderstore.Store, *statedb.DB, error) {
	workdir, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("determine working directory: %w", err)
	}
	db, err := statedb.Open(state.DBPath(workdir))
	if err != nil {
		return nil, nil, fmt.Errorf("open control-plane database: %w", err)
	}
	store, err := forwarderstore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return store, db, nil
}

// parseDeviceFlags turns --usb/--interface into a ForwardedDevice.
func parseDeviceFlags(usbSpec, iface, label string) (deviceforward.ForwardedDevice, error) {
	usbSpec = strings.TrimSpace(usbSpec)
	iface = strings.TrimSpace(iface)
	switch {
	case usbSpec != "" && iface != "":
		return deviceforward.ForwardedDevice{}, fmt.Errorf("give either --usb or --interface, not both")
	case usbSpec != "":
		m, err := parseUSBSpec(usbSpec)
		if err != nil {
			return deviceforward.ForwardedDevice{}, err
		}
		return deviceforward.ForwardedDevice{Kind: deviceforward.KindUSB, USB: &m, Label: label}, nil
	case iface != "":
		return deviceforward.ForwardedDevice{Kind: deviceforward.KindL2, Interface: iface, Label: label}, nil
	default:
		return deviceforward.ForwardedDevice{}, fmt.Errorf("a forwarder needs a device: --usb vendor:product[:serial] or --interface <name>")
	}
}

// parseUSBSpec parses "vendor:product[:serial]".
func parseUSBSpec(s string) (executor.USBMatch, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return executor.USBMatch{}, fmt.Errorf("--usb must be vendor:product[:serial] (like 1050:0030 or 1050:0030:0001234)")
	}
	m := executor.USBMatch{VendorID: parts[0], ProductID: parts[1]}
	if len(parts) == 3 {
		m.Serial = parts[2]
	}
	return m.Normalize()
}

var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Forward one on-prem USB device or network interface to a cloop control plane",
	Long: `Run a device forwarder on this machine.

A forwarder is a minimal process that bridges ONE configured device — a USB
device or a layer-2 network interface — to a cloop control plane over a single
authenticated, outbound WebSocket. It runs no harness and no workload: its only
job is to carry that one device, so a machine wired to on-prem hardware can be
reached by an agent running in an isolated cloud sandbox without running the
agent itself.

First run needs an enrollment token:

    cloop forward --server wss://host/api/forwarders/connect --token <tok> \
      --usb 1050:0030

or, with an interface:

    cloop forward --server wss://host/api/forwarders/connect --token <tok> \
      --interface eth1

The token is redeemed for a long-lived credential saved 0600 at
~/.cloop/forwarder.json. After that, plain ` + "`cloop forward`" + ` is enough.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		token, _ := cmd.Flags().GetString("token")
		bundleStr, _ := cmd.Flags().GetString("bundle")
		tokenFile, _ := cmd.Flags().GetString("token-file")
		credPath, _ := cmd.Flags().GetString("credential")
		usbSpec, _ := cmd.Flags().GetString("usb")
		iface, _ := cmd.Flags().GetString("interface")
		label, _ := cmd.Flags().GetString("label")
		pin, _ := cmd.Flags().GetString("pin")
		caFile, _ := cmd.Flags().GetString("ca-file")
		insecure, _ := cmd.Flags().GetBool("insecure-transport")

		if credPath == "" {
			credPath = defaultForwarderCredentialPath()
		}

		// A bundle or a saved credential can carry the device; explicit flags
		// win over both.
		var dev deviceforward.ForwardedDevice
		var haveDev bool
		if strings.TrimSpace(bundleStr) != "" {
			if b, err := deviceforward.DecodeBundle(bundleStr); err == nil {
				dev, haveDev = b.Device, b.Device.Kind != ""
			}
		}
		if f := strings.TrimSpace(tokenFile); f != "" {
			if b, warning, err := deviceforward.ReadTokenFile(f); err == nil {
				if warning != "" {
					color.New(color.FgYellow, color.Bold).Fprintf(os.Stderr, "warning: %s\n", warning)
				}
				if b.Device.Kind != "" {
					dev, haveDev = b.Device, true
				}
				if strings.TrimSpace(bundleStr) == "" && strings.TrimSpace(b.Token) != "" {
					bundleStr = f // ReadTokenFile already parsed; pass via Bundle below only if encoded
				}
			}
		}
		if !haveDev {
			if c, ok, err := deviceforward.LoadCredential(credPath); err == nil && ok {
				dev, haveDev = c.Device, c.Device.Kind != ""
			}
		}
		if usbSpec != "" || iface != "" {
			d, err := parseDeviceFlags(usbSpec, iface, label)
			if err != nil {
				return err
			}
			dev, haveDev = d, true
		}
		if !haveDev {
			return fmt.Errorf("no device configured: pass --usb or --interface (or enroll with a bundle that names one)")
		}

		src, err := buildForwardSource(dev)
		if err != nil {
			return err
		}

		dim := color.New(color.Faint)
		f, err := deviceforward.NewForwarder(deviceforward.ForwarderConfig{
			Server:         server,
			Token:          token,
			Bundle:         bundleStr,
			CredentialPath: credPath,
			Pin:            pin,
			CAFile:         caFile,
			Insecure:       insecure,
			Source:         src,
			AgentVersion:   version.Version,
			Logf: func(format string, args ...any) {
				dim.Fprintf(os.Stderr, "[forward] "+format+"\n", args...)
			},
		})
		if err != nil {
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		header.Printf("cloop device forwarder\n")
		fmt.Printf("  device: %s\n", dev.Describe())
		fmt.Printf("  link:   %s\n", f.TransportSummary())

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return f.Run(ctx)
	},
}

var forwardEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Mint a single-use token for enrolling a device forwarder",
	Long: `Create a single-use, time-limited enrollment token for a device forwarder.

This does not contact anything: it mints a token and prints the command to run
on the on-prem device, which dials back. The token is shown once; only its hash
is stored. Revoke a leak with ` + "`cloop forward revoke <id>`" + `.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		ttl, _ := cmd.Flags().GetDuration("ttl")
		usbSpec, _ := cmd.Flags().GetString("usb")
		iface, _ := cmd.Flags().GetString("interface")
		label, _ := cmd.Flags().GetString("label")
		server, _ := cmd.Flags().GetString("server")
		pin, _ := cmd.Flags().GetString("pin")

		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("--name is required")
		}
		dev, err := parseDeviceFlags(usbSpec, iface, label)
		if err != nil {
			return err
		}
		server, pin, err = resolveEnrollTransport(server, pin)
		if err != nil {
			return err
		}
		server = forwarderServerURL(server)

		store, db, err := openForwarderStore()
		if err != nil {
			return err
		}
		defer db.Close()

		encoded, rec, err := deviceforward.MintBundle(store, deviceforward.MintOptions{
			Name:   name,
			Device: dev,
			TTL:    ttl,
			Server: server,
			Pin:    pin,
		})
		if err != nil {
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		header.Printf("Device forwarder enrollment token minted\n\n")
		fmt.Printf("  id:      %s\n", rec.ID)
		fmt.Printf("  name:    %s\n", rec.Name)
		fmt.Printf("  device:  %s\n", dev.Describe())
		fmt.Printf("  expires: %s\n\n", rec.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Run this on the on-prem device:\n\n")
		color.New(color.Bold).Printf("  cloop forward --bundle %s\n\n", encoded)
		fmt.Printf("The token is single-use and shown only once. Revoke it with:\n")
		fmt.Printf("  cloop forward revoke %s\n", rec.ID)
		return nil
	},
}

var forwardRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke a forwarder enrollment token or credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openForwarderStore()
		if err != nil {
			return err
		}
		defer db.Close()
		kind, err := deviceforward.Revoke(store, args[0], time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Revoked %s %q.\n", kind, args[0])
		return nil
	},
}

var forwardListCmd = &cobra.Command{
	Use:   "list",
	Short: "List enrolled device forwarders",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openForwarderStore()
		if err != nil {
			return err
		}
		defer db.Close()
		fwds, err := store.ListForwarders()
		if err != nil {
			return err
		}
		if len(fwds) == 0 {
			fmt.Println("No forwarders enrolled.")
			return nil
		}
		for _, f := range fwds {
			state := "active"
			if f.Revoked() {
				state = "revoked"
			}
			fmt.Printf("%-24s  %-16s  %-8s  %s\n", f.ForwarderID, f.Name, state, f.Device.Describe())
		}
		return nil
	},
}

// forwarderServerURL swaps an executor connect path for the forwarder one, so
// resolveEnrollTransport's derived URL points at the right endpoint.
func forwarderServerURL(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return s
	}
	return strings.Replace(s, executorConnectPath, forwarderConnectPath, 1)
}

// defaultForwarderCredentialPath is ~/.cloop/forwarder.json.
func defaultForwarderCredentialPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".cloop-forwarder.json"
	}
	return home + "/.cloop/forwarder.json"
}

func init() {
	forwardCmd.Flags().String("server", "", "control-plane WebSocket URL (wss://host/api/forwarders/connect)")
	forwardCmd.Flags().String("token", "", "enrollment token (first run only)")
	forwardCmd.Flags().String("bundle", "", "enrollment bundle (server, token and pin in one blob)")
	forwardCmd.Flags().String("token-file", "", "path to a file holding the enrollment token or bundle")
	forwardCmd.Flags().String("credential", "", "path to the saved credential (default ~/.cloop/forwarder.json)")
	forwardCmd.Flags().String("usb", "", "forward a USB device, vendor:product[:serial]")
	forwardCmd.Flags().String("interface", "", "forward a network interface by name")
	forwardCmd.Flags().String("label", "", "operator-facing label for the device")
	forwardCmd.Flags().String("pin", "", "hub SPKI pin (sha256:...)")
	forwardCmd.Flags().String("ca-file", "", "additional CA certificate to trust")
	forwardCmd.Flags().Bool("insecure-transport", false, "allow plaintext to a non-loopback host (unsafe)")

	forwardEnrollCmd.Flags().String("name", "", "operator-facing name for the forwarder")
	forwardEnrollCmd.Flags().Duration("ttl", deviceforward.DefaultEnrollTTL, "how long the token may be redeemed")
	forwardEnrollCmd.Flags().String("usb", "", "forward a USB device, vendor:product[:serial]")
	forwardEnrollCmd.Flags().String("interface", "", "forward a network interface by name")
	forwardEnrollCmd.Flags().String("label", "", "operator-facing label for the device")
	forwardEnrollCmd.Flags().String("server", "", "control-plane WebSocket URL to record in the bundle")
	forwardEnrollCmd.Flags().String("pin", "", "hub SPKI pin to record in the bundle")

	forwardCmd.AddCommand(forwardEnrollCmd, forwardRevokeCmd, forwardListCmd)
	rootCmd.AddCommand(forwardCmd)
}

// buildForwardSource constructs the on-prem device endpoint for a descriptor.
func buildForwardSource(dev deviceforward.ForwardedDevice) (deviceforward.LocalSource, error) {
	switch dev.Kind {
	case deviceforward.KindUSB:
		if dev.USB == nil {
			return nil, fmt.Errorf("usb forwarder has no device identity")
		}
		return deviceforward.NewUSBSource(*dev.USB, deviceforward.USBSourceOptions{
			Logf: func(format string, args ...any) {
				color.New(color.Faint).Fprintf(os.Stderr, "[forward] "+format+"\n", args...)
			},
		})
	case deviceforward.KindL2:
		return deviceforward.NewL2Source(dev.Interface, deviceforward.L2SourceOptions{
			Logf: func(format string, args ...any) {
				color.New(color.Faint).Fprintf(os.Stderr, "[forward] "+format+"\n", args...)
			},
		})
	default:
		return nil, fmt.Errorf("unknown device kind %q", dev.Kind)
	}
}
