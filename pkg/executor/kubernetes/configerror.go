package kubernetes

// configerror.go turns a container the kubelet cannot create into a failed run,
// instead of a run that reads "pending" forever.
//
// # The failure
//
// A secretKeyRef is resolved when the kubelet creates the container that
// carries it. If the Secret — or the key — is missing at that moment, the
// kubelet does not fail the Pod: it reports the container as waiting with
// reason CreateContainerConfigError, leaves the Pod Pending, and retries on its
// sync loop for as long as the Pod exists. The driver used to narrate that as
// one more waiting state, so a run stranded this way showed "pending" until
// activeDeadlineSeconds — which outside the chart is unbounded.
//
// It became a live risk when the whole environment moved into the lease Secret
// (leaseenv.go). The harness container is created only after the workspace
// fetch, which can take minutes, and anything that deletes the Secret in that
// window — a control plane that cleaned up on its way down, an operator, a
// revocation that then failed to delete the Pod — strands the harness. finish
// no longer deletes a Secret whose consumer has not started; this file is what
// makes the other causes visible.
//
// # Fast, but not on the race Start lives with
//
// The Pod is created before its Secrets, because they carry an ownerReference
// naming it (see pod.go). A kubelet quick enough to try the container in that
// gap reports exactly this error for a Secret that lands a moment later, and
// its next sync — ten to fifteen seconds on, with the kubelet's backoff and
// jitter — starts the container normally. So an error seen within
// defaultConfigErrorGrace of the run's start arms one re-check and is not yet
// fatal; one seen after it fails the run at once. A run adopted after a hub
// restart started long before, so a stranded harness found then fails on the
// first look.
//
// Any CreateContainerConfigError is treated this way, not only a missing
// Secret: every other cause the kubelet reports under that reason — a subPath
// it cannot prepare, a user it cannot verify as non-root — is a property of the
// Pod spec, which nothing will change while the run waits.

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// reasonCreateContainerConfigError is the kubelet's waiting reason for a
// container whose configuration cannot be resolved.
const reasonCreateContainerConfigError = "CreateContainerConfigError"

// defaultConfigErrorGrace is how long after a run's start a configuration error
// is still presumed to be the Secret-creation race rather than a missing
// Secret. Three of the kubelet's ten-second sync backoffs, with room for its
// jitter.
const defaultConfigErrorGrace = 45 * time.Second

// configErrorGrace returns the grace in effect.
func (o Options) configErrorGrace() time.Duration {
	if o.configErrorGraceOverride > 0 {
		return o.configErrorGraceOverride
	}
	return defaultConfigErrorGrace
}

// containerConfigError is a container the kubelet cannot create, and the
// reason the run is failed.
type containerConfigError struct {
	namespace string
	pod       string
	// container is the container the kubelet is holding: the harness or the
	// workspace provisioner.
	container string
	// kubelet is the kubelet's own message, verbatim apart from trimming.
	kubelet string
	// secret is the Secret the message names when it is one of this run's
	// own, and what that Secret carries; both empty otherwise.
	secret   string
	carrying string
}

func (c *containerConfigError) Error() string {
	who := "the harness container"
	if c.container == InitContainerName {
		who = "the workspace provisioner"
	}
	if c.secret != "" {
		return fmt.Sprintf("%s could not be created: the per-run Secret %s/%s, which carries %s, "+
			"no longer exists (%s). It was deleted before the container read it, so the kubelet "+
			"would wait for it for as long as pod %s exists — the run is failed rather than left "+
			"pending; dispatch the task again", who, c.namespace, c.secret, c.carrying, c.kubelet, c.pod)
	}
	return fmt.Sprintf("%s could not be created: %s: %s — the kubelet retries this for as long as "+
		"pod %s/%s exists, and nothing in the run can change it, so the run is failed rather than "+
		"left pending", who, reasonCreateContainerConfigError, c.kubelet, c.namespace, c.pod)
}

// The two shapes in which the kubelet names a Secret it could not use for a
// container's environment. The first comes from the Secret lookup — "secret" or
// "secrets" depending on whether the kubelet's cache or the API server answered
// — and the second from a key missing in a Secret that exists.
var (
	secretNotFoundRe = regexp.MustCompile(`secrets? "([^"]+)" not found`)
	secretKeyRe      = regexp.MustCompile(`couldn't find key \S+ in Secret [^/\s]+/([^\s]+)`)
)

// secretNamedIn returns the Secret a kubelet message names, if any.
func secretNamedIn(msg string) string {
	if m := secretNotFoundRe.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	if m := secretKeyRe.FindStringSubmatch(msg); m != nil {
		return strings.TrimRight(m[1], ".,;:")
	}
	return ""
}

// stuckContainer returns the container the kubelet cannot create, provisioner
// first: while it waits the harness has no status at all.
func stuckContainer(p *pod) (string, *stateWaiting) {
	if cs := p.workspaceInitStatus(); cs != nil && cs.State.Waiting != nil &&
		cs.State.Waiting.Reason == reasonCreateContainerConfigError {
		return InitContainerName, cs.State.Waiting
	}
	if cs := p.harnessStatus(); cs != nil && cs.State.Waiting != nil &&
		cs.State.Waiting.Reason == reasonCreateContainerConfigError {
		return ContainerName, cs.State.Waiting
	}
	return "", nil
}

// observeConfigError fails the run once a container has been stuck in
// CreateContainerConfigError past the grace period, and arms a second look when
// it is seen inside it. Called with every non-terminal Pod the watcher sees.
func (e *Executor) observeConfigError(rec *record, p *pod) {
	container, w := stuckContainer(p)
	if w == nil {
		return
	}
	if age := e.opts.now().Sub(rec.startedAt); age < e.opts.configErrorGrace() {
		rec.armRecheck(e.opts.configErrorGrace() - age)
		return
	}

	cfg := &containerConfigError{
		namespace: rec.namespace,
		pod:       rec.podName,
		container: container,
		kubelet:   firstLine(strings.TrimSpace(w.Message)),
	}
	if cfg.kubelet == "" {
		cfg.kubelet = w.Reason
	}
	// Only this run's own Secrets get the specific explanation: both names
	// are pure functions of the handle ID, which is what lets an adopted
	// record — holding no state for either — recognise them too.
	switch secretNamedIn(w.Message) {
	case leaseSecretName(rec.id):
		cfg.secret, cfg.carrying = leaseSecretName(rec.id), "this run's environment and any credential files it was leased"
	case workspaceSecretName(rec.id):
		cfg.secret, cfg.carrying = workspaceSecretName(rec.id), "this run's git workspace credential"
	}

	rec.mu.Lock()
	first := rec.configErr == nil && !rec.done
	if first {
		rec.configErr = cfg
	}
	rec.mu.Unlock()
	if first {
		rec.bus.Emit("[cloop] " + cfg.Error() + "\n")
	}
}

// configFailure returns the configuration error that fails this run, or nil.
// An error interface rather than the pointer, so that "none" is a nil error
// and not a typed nil.
func (r *record) configFailure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.configErr == nil {
		return nil
	}
	return r.configErr
}

// armRecheck schedules one more look at the Pod after d, by breaking the watch
// so the watcher re-lists — a kubelet that keeps failing posts no new status,
// so without this the next look could be the watch's own five-minute timeout.
// At most one is pending per record; finish stops it.
func (r *record) armRecheck(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done || r.recheck != nil {
		return
	}
	r.recheck = time.AfterFunc(d, func() {
		r.mu.Lock()
		r.recheck = nil
		r.mu.Unlock()
		r.interruptWatch()
	})
}

// noteContainerStarts records which containers the kubelet has started.
// Running or terminated both count: either way the container was created, its
// environment resolved and the Pod's volumes mounted.
func (r *record) noteContainerStarts(p *pod) {
	started := func(cs *containerStatus) bool {
		return cs != nil && (cs.State.Running != nil || cs.State.Terminated != nil)
	}
	initUp, harnessUp := started(p.workspaceInitStatus()), started(p.harnessStatus())
	if !initUp && !harnessUp {
		return
	}
	r.mu.Lock()
	// A harness that started implies a provisioner that finished: init
	// containers run to completion first. A watch that missed the
	// provisioner's own status must not leave its Secret looking unread.
	r.initStarted = r.initStarted || initUp || harnessUp
	r.harnessStarted = r.harnessStarted || harnessUp
	r.mu.Unlock()
}
