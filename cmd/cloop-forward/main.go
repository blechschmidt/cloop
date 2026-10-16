// Command cloop-forward is the device forwarder as a standalone binary: it
// dials a cloop hub and bridges exactly one configured USB device or network
// interface, and does nothing else (Task 20429).
//
// It is deliberately tiny. The full `cloop forward` subcommand does the same
// thing, but it lives in a binary that also contains an orchestrator, a web
// dashboard and a hundred other commands. The trust model here is "the agent
// runs in an isolated environment in the cloud with limited access to on-prem
// hardware", and the aperture through which that access is granted should be as
// small as the job: this main imports pkg/deviceforward and nothing of the rest
// of cloop, so what runs on the machine wired to the hardware is a byte pump
// with a credential, not a product.
//
// Enrollment, revocation and listing are hub-side operations — run them with
// the full `cloop forward enroll|revoke|list` on the control plane. This binary
// only runs a forwarder that someone already enrolled.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/version"
)

func main() {
	fs := flag.NewFlagSet("cloop-forward", flag.ExitOnError)
	var (
		server   = fs.String("server", "", "control-plane WebSocket URL (wss://host/api/forwarders/connect)")
		token    = fs.String("token", "", "enrollment token (first run only)")
		bundle   = fs.String("bundle", "", "enrollment bundle (server, token and pin in one blob)")
		tokFile  = fs.String("token-file", "", "path to a file holding the enrollment token or bundle")
		credPath = fs.String("credential", "", "path to the saved credential (default ~/.cloop/forwarder.json)")
		usbSpec  = fs.String("usb", "", "forward a USB device, vendor:product[:serial]")
		iface    = fs.String("interface", "", "forward a network interface by name")
		label    = fs.String("label", "", "operator-facing label for the device")
		pin      = fs.String("pin", "", "hub SPKI pin (sha256:...)")
		caFile   = fs.String("ca-file", "", "additional CA certificate to trust")
		insecure = fs.Bool("insecure-transport", false, "allow plaintext to a non-loopback host (unsafe)")
		showVer  = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "cloop-forward: bridge one on-prem USB device or interface to a cloop hub.\n\n"+
			"Enroll on the hub with `cloop forward enroll`, then run the printed command here:\n"+
			"  cloop-forward --bundle cloopfwd1.…\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])
	if *showVer {
		fmt.Println(version.Version)
		return
	}

	if *credPath == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			*credPath = home + "/.cloop/forwarder.json"
		} else {
			*credPath = ".cloop-forwarder.json"
		}
	}

	dev, err := resolveDevice(*bundle, *tokFile, *credPath, *usbSpec, *iface, *label)
	if err != nil {
		fatal(err)
	}
	src, err := buildSource(dev)
	if err != nil {
		fatal(err)
	}

	f, err := deviceforward.NewForwarder(deviceforward.ForwarderConfig{
		Server:         *server,
		Token:          *token,
		Bundle:         *bundle,
		CredentialPath: *credPath,
		Pin:            *pin,
		CAFile:         *caFile,
		Insecure:       *insecure,
		Source:         src,
		AgentVersion:   version.Version,
		Logf:           func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[forward] "+format+"\n", args...) },
	})
	if err != nil {
		fatal(err)
	}
	fmt.Printf("cloop-forward\n  device: %s\n  link:   %s\n", dev.Describe(), f.TransportSummary())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := f.Run(ctx); err != nil {
		fatal(err)
	}
}

// resolveDevice works out which device to forward, with explicit flags winning
// over a bundle, a token file and a saved credential in that order.
func resolveDevice(bundle, tokFile, credPath, usbSpec, iface, label string) (deviceforward.ForwardedDevice, error) {
	var dev deviceforward.ForwardedDevice
	if strings.TrimSpace(bundle) != "" {
		if b, err := deviceforward.DecodeBundle(bundle); err == nil && b.Device.Kind != "" {
			dev = b.Device
		}
	}
	if strings.TrimSpace(tokFile) != "" {
		if b, _, err := deviceforward.ReadTokenFile(tokFile); err == nil && b.Device.Kind != "" {
			dev = b.Device
		}
	}
	if dev.Kind == "" {
		if c, ok, err := deviceforward.LoadCredential(credPath); err == nil && ok && c.Device.Kind != "" {
			dev = c.Device
		}
	}
	if strings.TrimSpace(usbSpec) != "" || strings.TrimSpace(iface) != "" {
		d, err := deviceFromFlags(usbSpec, iface, label)
		if err != nil {
			return deviceforward.ForwardedDevice{}, err
		}
		dev = d
	}
	if dev.Kind == "" {
		return deviceforward.ForwardedDevice{}, fmt.Errorf("no device configured: pass --usb or --interface, or a --bundle that names one")
	}
	return dev, nil
}

func deviceFromFlags(usbSpec, iface, label string) (deviceforward.ForwardedDevice, error) {
	usbSpec = strings.TrimSpace(usbSpec)
	iface = strings.TrimSpace(iface)
	switch {
	case usbSpec != "" && iface != "":
		return deviceforward.ForwardedDevice{}, fmt.Errorf("give either --usb or --interface, not both")
	case usbSpec != "":
		parts := strings.Split(usbSpec, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return deviceforward.ForwardedDevice{}, fmt.Errorf("--usb must be vendor:product[:serial]")
		}
		m := executor.USBMatch{VendorID: parts[0], ProductID: parts[1]}
		if len(parts) == 3 {
			m.Serial = parts[2]
		}
		nm, err := m.Normalize()
		if err != nil {
			return deviceforward.ForwardedDevice{}, err
		}
		return deviceforward.ForwardedDevice{Kind: deviceforward.KindUSB, USB: &nm, Label: label}, nil
	default:
		return deviceforward.ForwardedDevice{Kind: deviceforward.KindL2, Interface: iface, Label: label}, nil
	}
}

func buildSource(dev deviceforward.ForwardedDevice) (deviceforward.LocalSource, error) {
	logf := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[forward] "+format+"\n", args...) }
	switch dev.Kind {
	case deviceforward.KindUSB:
		return deviceforward.NewUSBSource(*dev.USB, deviceforward.USBSourceOptions{Logf: logf})
	case deviceforward.KindL2:
		return deviceforward.NewL2Source(dev.Interface, deviceforward.L2SourceOptions{Logf: logf})
	default:
		return nil, fmt.Errorf("unknown device kind %q", dev.Kind)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "cloop-forward:", err)
	os.Exit(1)
}
