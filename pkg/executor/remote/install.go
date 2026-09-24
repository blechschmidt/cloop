package remote

// Hub side of the harness-install frame (Task 20336).
//
// The contrast with upgrade.go, which is the file this one is shaped against:
// there, success cannot be observed on the connection that asked for it,
// because the upgrade restarts the agent and drops the session. Here it can.
// Installing a harness leaves the agent running, so this returns what actually
// happened rather than what the device intends to attempt — and that is what
// lets Start install and then carry on with the same dispatch instead of
// failing and hoping the operator retries.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrHarnessInstallUnsupported reports that a device's agent predates the
// install frame. It is informational rather than fatal: the caller falls back
// to refusing the dispatch with the message that names the manual remedies.
var ErrHarnessInstallUnsupported = errors.New("remote: agent does not support harness install")

// HarnessInstallTimeout bounds one install attempt from the hub's side.
//
// Longer than the agent's own script timeout on purpose. The device is the
// authority on when to give up — it is the one that can see the download — and
// a hub deadline that fired first would abandon a running installer and report
// a failure for an install that then succeeded, leaving the fleet in a state
// the hub's own record disagrees with.
const HarnessInstallTimeout = 20 * time.Minute

// HarnessInstallOutcome reports what the device ended up with.
type HarnessInstallOutcome struct {
	// Installed reports that the harness is runnable on the device now. True
	// for AlreadyPresent too: the question was "can you run this", not "did
	// you do work".
	Installed bool
	// AlreadyPresent marks the harness as having been there before the ask,
	// which happens when two dispatches race for one device.
	AlreadyPresent bool
	// Harness, Path and Version describe what the device has. Path is worth
	// surfacing: an install under a home directory is the thing an operator
	// debugging PATH needs to see.
	Harness string
	Path    string
	Version string
	// Reason explains a failure, in terms the operator can act on.
	Reason string
}

// Summary renders the outcome as one line for a log or a toast.
func (o HarnessInstallOutcome) Summary(device string) string {
	switch {
	case o.AlreadyPresent:
		return fmt.Sprintf("%s already had %s", device, o.Harness)
	case o.Installed:
		at := o.Path
		if strings.TrimSpace(at) == "" {
			at = "an unreported path"
		}
		return fmt.Sprintf("%s installed %s at %s", device, o.Harness, at)
	default:
		reason := strings.TrimSpace(o.Reason)
		if reason == "" {
			reason = "the device refused without giving a reason"
		}
		return fmt.Sprintf("%s could not install %s: %s", device, o.Harness, reason)
	}
}

// RequestHarnessInstall asks the device to install a harness from that
// harness's official installer.
//
// The version gate returns ErrHarnessInstallUnsupported rather than a message
// telling the operator to go and upgrade the agent. That is deliberate and the
// opposite of RequestUpgrade's choice: nobody asked for an install here — it is
// an attempt the hub makes on its own behalf, mid-dispatch — so the useful
// error is the one the caller was already about to produce about the missing
// harness, not a second one about the agent's age layered on top of it.
func (e *Executor) RequestHarnessInstall(
	ctx context.Context, harness, reason string,
) (HarnessInstallOutcome, error) {
	harness = strings.TrimSpace(harness)
	if harness == "" {
		return HarnessInstallOutcome{}, errors.New("remote: install request names no harness")
	}

	sess := e.currentSession()
	if sess == nil {
		return HarnessInstallOutcome{}, fmt.Errorf(
			"%w: %s (%s) has no live session, so it cannot be asked to install %s",
			ErrAgentUnreachable, e.id, e.name, harness)
	}
	if v := sess.Version(); !SupportsHarnessInstall(v) {
		return HarnessInstallOutcome{}, fmt.Errorf(
			"%w: %s (%s) speaks protocol v%d, and installing a harness on request needs v%d",
			ErrHarnessInstallUnsupported, e.id, e.name, v, MinHarnessInstallVersion)
	}

	payload := InstallHarnessPayload{Harness: harness, Reason: strings.TrimSpace(reason)}
	frame, err := sess.frame(TypeInstallHarness, newCorrelationID(), "", payload)
	if err != nil {
		return HarnessInstallOutcome{}, fmt.Errorf(
			"remote: build install frame for %s: %w", e.id, err)
	}

	// A deadline of this hub's own, and not merely ctx's. ctx here is the
	// dispatch's, which may have minutes left or may have none, and an install
	// that inherited a nearly-expired one would abort the moment it started —
	// producing "install failed" for a device that was never given time to try.
	reqCtx, cancel := context.WithTimeout(ctx, HarnessInstallTimeout)
	defer cancel()

	reply, err := sess.request(reqCtx, frame, TypeHarnessInstalled)
	if err != nil {
		return HarnessInstallOutcome{}, fmt.Errorf(
			"remote: ask %s (%s) to install %s: %w", e.id, e.name, harness, err)
	}
	ack, err := DecodeHarnessInstalled(reply)
	if err != nil {
		return HarnessInstallOutcome{}, fmt.Errorf(
			"remote: decode install result from %s: %w", e.id, err)
	}

	out := HarnessInstallOutcome{
		Installed:      ack.Installed,
		AlreadyPresent: ack.AlreadyPresent,
		Harness:        firstNonEmpty(ack.Harness, harness),
		Path:           ack.Path,
		Version:        ack.Version,
		Reason:         ack.Reason,
	}
	if out.Installed {
		// The device's advertised inventory is now wrong, and the very next
		// thing this dispatch does is re-read it. Recording the harness here
		// rather than waiting for the device to reconnect is what makes the
		// install take effect within the dispatch that triggered it.
		e.recordHarness(out.Harness)
	}
	return out, nil
}

// recordHarness adds a harness to this executor's cached inventory.
//
// The cache is refreshed wholesale from every hello, so this is not a second
// source of truth that can drift: it is the same value the device will report
// on its next connection, written early because the alternative is a dispatch
// that installs a harness and then refuses itself for not having it.
func (e *Executor) recordHarness(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range e.caps.Harnesses {
		if strings.EqualFold(h, name) {
			return
		}
	}
	e.caps.Harnesses = append(e.caps.Harnesses, name)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
