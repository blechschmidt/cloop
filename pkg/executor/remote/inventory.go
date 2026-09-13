package remote

// inventory.go exposes what a connected device said about itself, so the hub
// can answer "which cloop build is each edge device running?" without inferring
// it from behaviour.
//
// The data already crossed the wire — HelloPayload.AgentVersion has carried a
// comment about "diagnosing version-skew problems from the control plane" since
// the protocol was written. What was missing was any reader: the value was
// decoded at hello and dropped, there was no column for it, and the panel had
// nothing to show. These accessors are the first half of closing that.
//
// Both return the *live* session's view and fall back to empty rather than to a
// stored value. That is deliberate: a stored version describes the build that
// was running at some point in the past, and for the one question these answer
// — "what is on this device right now" — a stale answer is worse than none.
// Persistence is the caller's job, and it happens on every connect precisely so
// the stored copy tracks reality.

// displayAgentVersion renders a reported build for a log line, naming an
// absent one rather than leaving a dangling field. A log reading "build " is
// indistinguishable from a truncated line.
func displayAgentVersion(v string) string {
	if v == "" {
		return "unreported"
	}
	return v
}

// AgentVersion reports the cloop build the connected agent advertised, or "" if
// the device is not currently connected.
//
// An empty string from a *connected* agent is meaningful in itself: it is a
// build from before agents reported a version at all.
func (e *Executor) AgentVersion() string {
	sess := e.currentSession()
	if sess == nil {
		return ""
	}
	return sess.AgentVersion()
}

// AgentInventory returns the full capability advertisement of the connected
// agent, and whether there was a session to ask.
//
// The bool matters because the zero AgentCapabilities is indistinguishable from
// a device that genuinely reported nothing, and rendering "0 CPUs, no
// harnesses" for a merely-offline device would invent a fault.
func (e *Executor) AgentInventory() (AgentCapabilities, bool) {
	sess := e.currentSession()
	if sess == nil {
		return AgentCapabilities{}, false
	}
	return sess.Capabilities(), true
}
