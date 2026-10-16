// Forwarded devices at dispatch (Task 20430).
//
// A device forwarder carries one on-prem USB device or network segment to the
// hub; a binding (forwarder_bindings.go) makes it available to one project's
// runs. This file is where that decision takes effect: when a run of a bound
// project is dispatched, the hub opens a stream to each bound forwarder —
// through its own forwarder tunnel, or through the hub member that holds it —
// and gives it to the executor that starts the sandbox:
//
//   - an executor agent (remote.Executor, a virtual executor of one) gets the
//     stream on a device channel of its own tunnel and attaches the device on
//     its host, with no listener (protocol v22);
//   - the container driver on the hub's own host has the device attached here,
//     in this process, the same way — vhci_hcd through a socketpair for USB, a
//     TAP for L2 — and passed through as an ordinary device or interface.
//
// Nothing else gets one. A host-process run has no sandbox to give a device
// to, so a bound project that runs on the host is refused rather than handed
// hardware every process on the machine could reach: the loopback import
// endpoint this replaces was exactly that.
//
// Every stream is held in liveForwards for as long as its run uses it, so the
// run's end, a binding's revocation or lapse, and a forwarder's revocation —
// on this member, another, or from the CLI — each find and close it, which
// detaches the device wherever it was attached.

package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// forwarderOfflineError refuses a dispatch whose bound forwarder has no live
// session anywhere in the cluster. It names the forwarder, because the
// operator's next move is to look at that machine.
type forwarderOfflineError struct {
	ForwarderID string
	Name        string
	Project     string
}

func (e *forwarderOfflineError) Error() string {
	return fmt.Sprintf("device forwarder %q (%s), which is bound to this project, is offline: its device "+
		"cannot reach the run's sandbox", e.Name, e.ForwarderID)
}

// Remediation says what to do about it.
func (e *forwarderOfflineError) Remediation() string {
	return "Start `cloop forward` on the machine the device is plugged into, or unbind the forwarder " +
		"from this project (Executors → Device forwarders) to run without the device."
}

// forwardedDevicesRefusedError refuses a dispatch whose bound devices the
// project's executor cannot take into a sandbox.
type forwardedDevicesRefusedError struct {
	ExecutorID string
	Reason     string
}

func (e *forwardedDevicesRefusedError) Error() string {
	return fmt.Sprintf("this project holds a device forwarder binding, and executor %s cannot give the "+
		"device to the run's sandbox: %s", e.ExecutorID, e.Reason)
}

// Remediation says what to do about it.
func (e *forwardedDevicesRefusedError) Remediation() string {
	return "Bind the project to a container executor or an executor agent that can attach the device, " +
		"or unbind the forwarder from this project."
}

// ── the relay registry ───────────────────────────────────────────────────────

// forwardRelay is one forwarded device held open for one run: the stream to
// the forwarder and, for a sandbox on this host, the attachment this process
// made from it.
type forwardRelay struct {
	bindingID     string
	forwarderID   string
	forwarderName string
	project       string
	runID         string
	kind          string

	mu         sync.Mutex
	stream     io.ReadWriteCloser
	local      io.Closer
	executorID string
	handleID   string
	attached   bool
	closed     bool
	reason     string
}

// Read and Write make the relay the stream a driver holds; Close is the
// driver giving it back.
func (r *forwardRelay) Read(p []byte) (int, error)  { return r.stream.Read(p) }
func (r *forwardRelay) Write(p []byte) (int, error) { return r.stream.Write(p) }
func (r *forwardRelay) Close() error {
	r.close("the device stream ended")
	return nil
}

// close ends the relay once: the in-process attachment, then the stream —
// which, for an agent's device, closes its channel and has the agent detach.
func (r *forwardRelay) close(reason string) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.reason = reason
	local, stream := r.local, r.stream
	attached, handleID, executorID := r.attached, r.handleID, r.executorID
	r.mu.Unlock()
	liveForwards.remove(r)
	if local != nil {
		_ = local.Close()
	}
	if stream != nil {
		_ = stream.Close()
	}
	if attached {
		auditForwardEvent(auditaction.ActionForwarderDetach, r.forwarderID, map[string]any{
			"binding_id": r.bindingID, "project": r.project, "handle_id": handleID,
			"executor_id": executorID, "reason": reason,
		})
	}
}

// EndReason is why the hub ended the relay, once it has: what the agent is
// told when its device channel closes.
func (r *forwardRelay) EndReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reason
}

// isClosed reports whether the relay has ended.
func (r *forwardRelay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// liveForwards is every forwarded device this member holds open for a run.
var liveForwards = &forwardRegistry{all: map[*forwardRelay]struct{}{}}

type forwardRegistry struct {
	mu  sync.Mutex
	all map[*forwardRelay]struct{}
}

func (g *forwardRegistry) add(r *forwardRelay) {
	g.mu.Lock()
	g.all[r] = struct{}{}
	g.mu.Unlock()
}

func (g *forwardRegistry) remove(r *forwardRelay) {
	g.mu.Lock()
	delete(g.all, r)
	g.mu.Unlock()
}

func (g *forwardRegistry) match(pred func(*forwardRelay) bool) []*forwardRelay {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*forwardRelay
	for r := range g.all {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

func (g *forwardRegistry) snapshot() []*forwardRelay {
	return g.match(func(*forwardRelay) bool { return true })
}

// closeForwardsWhere closes the relays pred selects and reports how many.
func closeForwardsWhere(pred func(*forwardRelay) bool, reason string) int {
	rs := liveForwards.match(pred)
	for _, r := range rs {
		r.close(reason)
	}
	return len(rs)
}

// closeForwardsForBinding detaches a binding's device from every run holding
// it on this member.
func closeForwardsForBinding(bindingID, reason string) int {
	return closeForwardsWhere(func(r *forwardRelay) bool { return r.bindingID == bindingID }, reason)
}

// closeForwardsForForwarder detaches a forwarder's device from every run
// holding it on this member.
func closeForwardsForForwarder(forwarderID, reason string) int {
	return closeForwardsWhere(func(r *forwardRelay) bool { return r.forwarderID == forwarderID }, reason)
}

// closeRunForwards detaches every forwarded device the workload with handleID
// holds. Every path that ends a run calls it, beside closeRunEgress.
func closeRunForwards(handleID, reason string) {
	if handleID == "" {
		return
	}
	closeForwardsWhere(func(r *forwardRelay) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.handleID == handleID
	}, reason)
}

// forwardsInUse describes the relays one binding has open, for the panels.
type forwardInUse struct {
	HandleID   string `json:"handle_id,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
}

func forwardsInUse(bindingID string) []forwardInUse {
	var out []forwardInUse
	for _, r := range liveForwards.match(func(r *forwardRelay) bool { return r.bindingID == bindingID }) {
		r.mu.Lock()
		out = append(out, forwardInUse{HandleID: r.handleID, ExecutorID: r.executorID, RunID: r.runID})
		r.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HandleID < out[j].HandleID })
	return out
}

// runForwards is the forwarded devices one dispatch holds.
type runForwards struct {
	project string
	runID   string

	mu     sync.Mutex
	relays []*forwardRelay
}

func (f *runForwards) add(r *forwardRelay) {
	f.mu.Lock()
	f.relays = append(f.relays, r)
	f.mu.Unlock()
	liveForwards.add(r)
}

// bindHandle records the workload the dispatch's devices now belong to, and
// audits each attachment. Nil-safe.
func (f *runForwards) bindHandle(ex executor.Executor, handleID string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	relays := append([]*forwardRelay(nil), f.relays...)
	f.mu.Unlock()
	for _, r := range relays {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			continue
		}
		r.handleID, r.executorID, r.attached = handleID, ex.ID(), true
		r.mu.Unlock()
		auditForwardEvent(auditaction.ActionForwarderAttach, r.forwarderID, map[string]any{
			"binding_id": r.bindingID, "project": r.project, "executor_id": ex.ID(),
			"handle_id": handleID, "run_id": r.runID,
		})
	}
}

// close ends every device of a dispatch that did not start. Nil-safe.
func (f *runForwards) close(reason string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	relays := append([]*forwardRelay(nil), f.relays...)
	f.mu.Unlock()
	for _, r := range relays {
		r.close(reason)
	}
}

// ── dispatch ─────────────────────────────────────────────────────────────────

// forwardedBinding is one binding resolved for a dispatch.
type forwardedBinding struct {
	row     statedb.ForwarderBindingRow
	fwd     statedb.ForwarderRow
	device  deviceforward.ForwardedDevice
	iface   forwardedInterface
	devName string
}

// applyForwardedDevices puts the project's bound forwarded devices on spec, or
// refuses the dispatch. An unbound project gets nothing and costs one query.
//
// For an executor agent the devices ride the Spec and the driver attaches
// them on the device; for the container driver on this host they are attached
// here and handed over as Devices and Interfaces. The returned set holds every
// stream opened; the caller binds it to the handle once the workload starts,
// or closes it.
func applyForwardedDevices(spec executor.Spec, ex executor.Executor, workDir, runID string) (executor.Spec, *runForwards, error) {
	project := policyProjectPath(workDir)
	cp := controlPlaneDir()
	if cp == "" || project == "" {
		return spec, nil, nil
	}
	if _, err := os.Stat(state.DBPath(cp)); err != nil {
		return spec, nil, nil
	}
	db, err := statedb.Open(state.DBPath(cp))
	if err != nil {
		// Refused rather than run without the devices: a bound project's run
		// that silently lacked its hardware would look like a software bug.
		return spec, nil, fmt.Errorf("read this project's device forwarder bindings: %w", err)
	}
	defer db.Close()
	bindings, err := resolveForwardedBindings(db, project, ex, time.Now())
	if err != nil || len(bindings) == 0 {
		return spec, nil, err
	}

	// Every bound forwarder must be reachable now, or the run does not start.
	for _, b := range bindings {
		if online, _ := forwarderOnline(b.fwd.ForwarderID); !online {
			return spec, nil, &forwarderOfflineError{ForwarderID: b.fwd.ForwarderID, Name: b.fwd.Name, Project: project}
		}
	}

	devs := make([]executor.ForwardedDevice, 0, len(bindings))
	rf := &runForwards{project: project, runID: runID}
	for _, b := range bindings {
		devs = append(devs, b.forwarded(rf))
	}
	kinds := executor.ForwardedKinds(devs)

	if taker, ok := executor.AsForwardedDeviceTaker(ex); ok {
		if err := taker.CanTakeForwardedDevices(kinds); err != nil {
			return spec, nil, err
		}
		spec.ForwardedDevices = append(append([]executor.ForwardedDevice(nil), spec.ForwardedDevices...), devs...)
		return spec, rf, nil
	}
	if ex.Kind() != executor.KindContainer {
		return spec, nil, &forwardedDevicesRefusedError{ExecutorID: ex.ID(),
			Reason: fmt.Sprintf("a %s executor runs payloads with no sandbox a device could be given to", ex.Kind())}
	}
	if err := canAttachHere(ex, kinds); err != nil {
		return spec, nil, &forwardedDevicesRefusedError{ExecutorID: ex.ID(), Reason: err.Error()}
	}
	out, err := attachForwardedHere(spec, devs)
	if err != nil {
		rf.close("the device could not be attached")
		return spec, nil, fmt.Errorf("attach the project's forwarded devices on this host: %w", err)
	}
	return out, rf, nil
}

// resolveForwardedBindings returns the bindings in force for a project's run on
// ex: those naming no virtual executor, and those naming ex when it is one.
// Two bindings of one forwarder resolve to one device.
func resolveForwardedBindings(db *statedb.DB, project string, ex executor.Executor, now time.Time) ([]forwardedBinding, error) {
	rows, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{Project: project, ActiveAt: now})
	if err != nil {
		return nil, fmt.Errorf("read this project's device forwarder bindings: %w", err)
	}
	vx := ""
	if _, ok := ex.(*remote.Virtual); ok {
		vx = ex.ID()
	}
	seen := map[string]bool{}
	var out []forwardedBinding
	for _, row := range rows {
		if row.VirtualExecutor != "" && row.VirtualExecutor != vx {
			continue
		}
		if seen[row.ForwarderID] {
			continue
		}
		fwd, err := db.GetForwarder(row.ForwarderID)
		if err != nil || !fwd.RevokedAt.IsZero() {
			continue
		}
		seen[row.ForwarderID] = true
		b := forwardedBinding{row: row, fwd: fwd, device: unmarshalForwarderDevice(fwd.DeviceJSON)}
		b.iface = decodeForwardedInterface(row.InterfaceJSON)
		out = append(out, b)
	}
	if len(out) > executor.MaxForwardedDevices {
		return nil, fmt.Errorf("this project has %d forwarded devices bound; a run may hold at most %d",
			len(out), executor.MaxForwardedDevices)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].fwd.ForwarderID < out[j].fwd.ForwarderID })
	for i := range out {
		out[i].devName = forwardedDeviceName(out[i].fwd)
		if out[i].device.Kind == deviceforward.KindL2 && out[i].iface.Target == "" {
			out[i].iface.Target = fmt.Sprintf("fwd%d", i)
		}
	}
	return out, nil
}

// forwarded builds the executor's view of one binding, with an opener that
// records the stream it opens on rf.
func (b forwardedBinding) forwarded(rf *runForwards) executor.ForwardedDevice {
	fd := executor.ForwardedDevice{
		BindingID:   b.row.ID,
		ForwarderID: b.fwd.ForwarderID,
		Name:        b.devName,
		Kind:        string(b.device.Kind),
		Label:       b.device.DefaultLabel(),
	}
	if b.device.Kind == deviceforward.KindL2 {
		fd.Interface = executor.HostInterface{
			Target: b.iface.Target, Address: b.iface.Address, Gateway: b.iface.Gateway, MTU: b.iface.MTU,
		}
	}
	fd.Open = func(ctx context.Context) (executor.ForwardedStream, error) {
		st, exported, err := openForwarderStream(ctx, b.fwd.ForwarderID, "attach", b.row.ID)
		if err != nil {
			return executor.ForwardedStream{}, err
		}
		r := &forwardRelay{
			bindingID: b.row.ID, forwarderID: b.fwd.ForwarderID, forwarderName: b.fwd.Name,
			project: rf.project, runID: rf.runID, kind: fd.Kind, stream: st,
		}
		rf.add(r)
		return executor.ForwardedStream{ReadWriteCloser: r, BusID: exported.BusID}, nil
	}
	return fd
}

// forwardedDeviceName is the sandbox-facing handle for a forwarder's device:
// its name, made a valid handle, so a workload sees "fwd-bench-hsm" rather
// than an opaque id.
func forwardedDeviceName(f statedb.ForwarderRow) string {
	var b strings.Builder
	for _, c := range strings.ToLower(f.Name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-.")
	if name == "" {
		name = strings.ToLower(f.ForwarderID)
	}
	name = "fwd-" + name
	if len(name) > 48 {
		name = name[:48]
	}
	return name
}

// ── attaching on this host ───────────────────────────────────────────────────

// canAttachHere reports whether this process can attach forwarded devices of
// these kinds for a sandbox of ex, the container driver on this host.
func canAttachHere(ex executor.Executor, kinds []string) error {
	caps := ex.Capabilities()
	for _, k := range kinds {
		switch k {
		case executor.ForwardedUSB:
			if !caps.SupportsDevices {
				return errors.New("its runtime cannot be given a host device")
			}
			if err := (deviceforward.VHCI{}).Available(); err != nil {
				return fmt.Errorf("the hub cannot import a USB device on its host: %v", err)
			}
		case executor.ForwardedL2:
			if !caps.SupportsInterfaces {
				return errors.New("it cannot move a network interface into its sandboxes (that needs the hub to run as root, ip(8) and nsenter(1), and a runtime other than gVisor or Kata)")
			}
			if f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err != nil {
				return fmt.Errorf("the hub cannot create a TAP: %v", err)
			} else {
				_ = f.Close()
			}
		}
	}
	return nil
}

// attachForwardedHere attaches each device in this process and adds what the
// sandbox is given to the Spec. On failure, whatever was attached is undone by
// the caller closing the dispatch's set.
func attachForwardedHere(spec executor.Spec, devs []executor.ForwardedDevice) (executor.Spec, error) {
	var env []string
	for _, fd := range devs {
		nodes, iface, err := attachOneHere(fd)
		if err != nil {
			return spec, err
		}
		if len(nodes) > 0 {
			spec.Devices = append(append([]executor.HostDevice(nil), spec.Devices...), nodes...)
			env = append(env, executor.ForwardedEnvEntry(fd.Name, fd.Kind, nodes[0].EffectiveTarget()))
		}
		if iface != nil {
			spec.Interfaces = append(append([]executor.HostInterface(nil), spec.Interfaces...), *iface)
			env = append(env, executor.ForwardedEnvEntry(fd.Name, fd.Kind, iface.EffectiveTarget()))
		}
	}
	spec.ForwardedDevices = nil
	spec.Env = executor.WithForwardedEnv(spec.Env, env)
	return spec, nil
}

// attachOneHere attaches one forwarded device in this process: a USB device
// through this host's vhci_hcd, a segment through a TAP.
func attachOneHere(fd executor.ForwardedDevice) ([]executor.HostDevice, *executor.HostInterface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := fd.Open(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: open the forwarder's device: %w", fd.Describe(), err)
	}
	relay := st.ReadWriteCloser.(*forwardRelay)
	ledger := hubDeviceLedger()
	switch fd.Kind {
	case executor.ForwardedUSB:
		imp, err := deviceforward.ImportUSB(ctx, relay.stream, st.BusID, deviceforward.ImportOptions{
			Ledger: ledger,
			Logf:   func(f string, a ...any) { fmt.Fprintf(os.Stderr, "ui: "+f+"\n", a...) },
		})
		if err != nil {
			relay.close("the device could not be attached")
			return nil, nil, fmt.Errorf("%s: %w", fd.Describe(), err)
		}
		relay.mu.Lock()
		relay.local = imp
		relay.mu.Unlock()
		go watchLocalAttachment(relay, imp.Done())
		return imp.HostDevices(fd.Name), nil, nil
	case executor.ForwardedL2:
		tap := hubTAPName(fd.BindingID)
		id := ledger.Add(deviceforward.LedgerEntry{Kind: deviceforward.LedgerTAP, TAP: tap})
		br, err := deviceforward.BridgeTAP(relay.stream, tap)
		if err != nil {
			ledger.Remove(id)
			relay.close("the segment could not be attached")
			return nil, nil, fmt.Errorf("%s: %w", fd.Describe(), err)
		}
		relay.mu.Lock()
		relay.local = br
		relay.mu.Unlock()
		go func() {
			<-br.Done()
			ledger.Remove(id)
		}()
		go watchLocalAttachment(relay, br.Done())
		iface := fd.Interface
		iface.Name = fd.Name
		iface.Source = br.Name()
		return nil, &iface, nil
	}
	relay.close("unknown device kind")
	return nil, nil, fmt.Errorf("%s: unknown device kind %q", fd.Describe(), fd.Kind)
}

// watchLocalAttachment ends the relay when its attachment ends on its own —
// the forwarder went away, the stream broke.
func watchLocalAttachment(r *forwardRelay, done <-chan struct{}) {
	<-done
	r.close("the device stream ended")
}

// hubTAPName names a TAP this hub creates for a binding.
func hubTAPName(bindingID string) string {
	return "cfwh" + shortHash(bindingID+fmt.Sprint(time.Now().UnixNano()), 10)
}

var (
	hubLedgerOnce sync.Once
	hubLedger     *deviceforward.Ledger
)

// hubDeviceLedger is this hub process's record of the devices it attached in
// process, under the control plane's .cloop, opened after sweeping what a
// previous process left. Nil-safe to use: a ledger that cannot be opened
// costs only the sweep after a crash.
func hubDeviceLedger() *deviceforward.Ledger {
	hubLedgerOnce.Do(func() {
		cp := controlPlaneDir()
		if cp == "" {
			return
		}
		dir := filepath.Join(cp, ".cloop", "forwarded-devices")
		rep := deviceforward.SweepLedgers(dir, func(f string, a ...any) { fmt.Fprintf(os.Stderr, "ui: "+f+"\n", a...) })
		if n := len(rep.Detached) + len(rep.Removed); n > 0 {
			fmt.Fprintf(os.Stderr, "ui: swept %d forwarded-device attachment(s) a previous hub process left\n", n)
		}
		l, err := deviceforward.OpenLedger(dir, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: forwarded devices attached here will not be swept after a crash: %v\n", err)
			return
		}
		hubLedger = l
	})
	return hubLedger
}

// ── reaching a forwarder ─────────────────────────────────────────────────────

// forwarderReach is how this member reaches a forwarder's device: through its
// own forwarder tunnel, or through the member holding it. A variable so a test
// can stand a forwarder in without a kernel or a second hub.
var forwarderReach forwarderReacher = clusterForwarderReach{}

type forwarderReacher interface {
	// online reports whether a forwarder has a live session on this member
	// or a live peer, and which member.
	online(forwarderID string) (bool, string)
	// open opens a stream to the forwarder's device.
	open(ctx context.Context, forwarderID, purpose, bindingID string) (io.ReadWriteCloser, deviceforward.ExportedDevice, error)
}

func forwarderOnline(forwarderID string) (bool, string) { return forwarderReach.online(forwarderID) }

func openForwarderStream(ctx context.Context, forwarderID, purpose, bindingID string) (io.ReadWriteCloser, deviceforward.ExportedDevice, error) {
	return forwarderReach.open(ctx, forwarderID, purpose, bindingID)
}

// clusterForwarderReach is the real one.
type clusterForwarderReach struct{}

func (clusterForwarderReach) online(forwarderID string) (bool, string) {
	if hub := activeForwarderHub(); hub != nil {
		if _, ok := hub.Session(forwarderID); ok {
			return true, processInstanceID()
		}
	}
	if n := currentCluster(); n != nil {
		o, found, err := n.Lookup(ownerForwarder, forwarderID)
		if err == nil && found && !o.Self && o.Alive {
			return true, o.InstanceID
		}
	}
	return false, ""
}

func (clusterForwarderReach) open(ctx context.Context, forwarderID, purpose, bindingID string) (io.ReadWriteCloser, deviceforward.ExportedDevice, error) {
	if hub := activeForwarderHub(); hub != nil {
		if _, ok := hub.Session(forwarderID); ok {
			ds, err := hub.OpenDevice(ctx, forwarderID, purpose)
			if err != nil {
				return nil, deviceforward.ExportedDevice{}, err
			}
			return ds, ds.Exported, nil
		}
	}
	if n := currentCluster(); n != nil {
		o, found, err := n.Lookup(ownerForwarder, forwarderID)
		if err == nil && found && !o.Self && o.Alive {
			return dialPeerForwarderStream(ctx, n, o.Member, forwarderID, purpose, bindingID)
		}
	}
	return nil, deviceforward.ExportedDevice{}, deviceforward.ErrForwarderOffline
}

// ── supervision ──────────────────────────────────────────────────────────────

// forwardRecheckInterval is how often this member re-reads the bindings and
// forwarders behind the devices it holds open. It is the backstop under the
// immediate cut a revocation makes: a binding that lapses, or a revocation
// whose announcement this member missed, still detaches within it.
const forwardRecheckInterval = 3 * time.Second

// recheckForwards closes every relay whose binding is no longer in force or
// whose forwarder was revoked, stamping a lapsed binding once so the trail
// says it ended.
func recheckForwards(now time.Time) {
	relays := liveForwards.snapshot()
	if len(relays) == 0 {
		return
	}
	cp := controlPlaneDir()
	if cp == "" {
		return
	}
	db, err := statedb.Open(state.DBPath(cp))
	if err != nil {
		return
	}
	defer db.Close()
	for _, r := range relays {
		if r.isClosed() {
			continue
		}
		b, err := db.GetForwarderBinding(r.bindingID)
		switch {
		case errors.Is(err, statedb.ErrForwarderBindingNotFound):
			r.close("its binding no longer exists")
			continue
		case err != nil:
			continue // a busy database is not a revocation
		case b.Revoked():
			r.close("its binding was revoked: " + nonEmpty(b.RevokeReason, "by "+nonEmpty(b.RevokedBy, "an operator")))
			continue
		case b.Expired(now):
			lapseForwarderBinding(db, b)
			r.close("its binding's TTL ran out")
			continue
		}
		if f, err := db.GetForwarder(r.forwarderID); err == nil && !f.RevokedAt.IsZero() {
			r.close("its forwarder was revoked")
		}
	}
}

// lapseForwarderBinding stamps a binding whose TTL ran out as revoked, once
// across the cluster, and audits it.
func lapseForwarderBinding(db *statedb.DB, b statedb.ForwarderBindingRow) {
	ok, err := db.RevokeForwarderBinding(b.ID, "system", "its TTL ran out", b.ExpiresAt)
	if err != nil || !ok {
		return
	}
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: auditaction.ActionForwarderUnbind, ForwarderID: b.ForwarderID, Actor: "system",
		Detail: map[string]any{"binding_id": b.ID, "project": b.Project, "reason": "its TTL ran out"},
	})
}

// sweepLapsedForwarderBindings stamps every binding whose TTL has run out,
// whether or not a run holds it, so the audit trail records each lapse. Run
// by the leader.
func sweepLapsedForwarderBindings(now time.Time) {
	cp := controlPlaneDir()
	if cp == "" {
		return
	}
	if _, err := os.Stat(state.DBPath(cp)); err != nil {
		return
	}
	db, err := statedb.Open(state.DBPath(cp))
	if err != nil {
		return
	}
	defer db.Close()
	rows, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{})
	if err != nil {
		return
	}
	for _, b := range rows {
		if !b.Revoked() && b.Expired(now) {
			lapseForwarderBinding(db, b)
		}
	}
	if expired, err := db.ExpireForwarderBindingRequests(now); err == nil {
		for _, req := range expired {
			statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
				Action: auditaction.ActionForwarderBindRequestExpire, ForwarderID: req.ForwarderID, Actor: "system",
				Detail: map[string]any{"request_id": req.ID},
			})
		}
	}
}

// auditForwardEvent records a forwarded-device event on the control plane,
// best-effort.
func auditForwardEvent(action auditaction.Action, forwarderID string, detail map[string]any) {
	cp := controlPlaneDir()
	if cp == "" {
		return
	}
	db, err := statedb.Open(state.DBPath(cp))
	if err != nil {
		return
	}
	defer db.Close()
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: action, ForwarderID: forwarderID, Actor: "system", Detail: detail,
	})
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// shortHash is the first n hex digits of s's SHA-256.
func shortHash(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	h := hex.EncodeToString(sum[:])
	if n > len(h) {
		n = len(h)
	}
	return h[:n]
}
