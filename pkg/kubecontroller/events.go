package kubecontroller

// events.go records Kubernetes Events on an ExecutorPool: every refusal — the
// hub refusing the credential or a runner, the API server refusing a Pod, an
// invalid spec, an image that would not resolve — and the controller's own
// scaling, so `kubectl describe executorpool` tells the story.
//
// The same event for the same pool is recorded once per dedupWindow: a pool
// whose hub is down is reconciled every few seconds, and the Event that says
// so needs saying once, not a thousand times.

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Event types and reasons.
const (
	EventNormal  = "Normal"
	EventWarning = "Warning"

	ReasonInvalidSpec       = "InvalidSpec"
	ReasonHubUnavailable    = "HubUnavailable"
	ReasonHubRefused        = "HubRefused"
	ReasonRunnersRefused    = "RunnersRefused"
	ReasonPodRefused        = "PodRefused"
	ReasonImageUnresolved   = "ImageUnresolved"
	ReasonImageUnverified   = "ImageUnverified"
	ReasonRunnerFailed      = "RunnerFailed"
	ReasonDuplicatePool     = "DuplicatePool"
	ReasonScaledUp          = "ScaledUp"
	ReasonScaledDown        = "ScaledDown"
	ReasonOrphanCollected   = "OrphanCollected"
	ReasonRetireRefused     = "RetireRefused"
	ReasonCredentialMissing = "CredentialUnreadable"
	ReasonHubTooOld         = "HubTooOld"
)

// dedupWindow is how long an identical Event is not repeated.
var dedupWindow = 10 * time.Minute

type recorder struct {
	api      *kubeAPI
	instance string
	logf     func(string, ...any)
	now      func() time.Time

	mu     sync.Mutex
	recent map[string]time.Time
}

func newRecorder(api *kubeAPI, instance string, logf func(string, ...any)) *recorder {
	return &recorder{api: api, instance: instance, logf: logf, now: time.Now, recent: map[string]time.Time{}}
}

// record emits an Event about pool, unless the same one was emitted within
// dedupWindow.
func (r *recorder) record(ctx context.Context, pool *ExecutorPool, typ, reason, message string) {
	message = trimMessage(message)
	key := pool.Metadata.UID + "\x00" + reason + "\x00" + message
	now := r.now()
	r.mu.Lock()
	if last, ok := r.recent[key]; ok && now.Sub(last) < dedupWindow {
		r.mu.Unlock()
		return
	}
	r.recent[key] = now
	if len(r.recent) > 4096 {
		for k, at := range r.recent {
			if now.Sub(at) >= dedupWindow {
				delete(r.recent, k)
			}
		}
	}
	r.mu.Unlock()

	ts := now.UTC().Format(time.RFC3339)
	ev := &Event{
		APIVersion: "v1",
		Kind:       "Event",
		Metadata: ObjectMeta{
			GenerateName: strings.TrimRight(truncate(pool.Metadata.Name, 200), "-.") + ".",
			Namespace:    pool.Metadata.Namespace,
		},
		InvolvedObject: ObjectReference{APIVersion: APIVersion, Kind: Kind, Namespace: pool.Metadata.Namespace,
			Name: pool.Metadata.Name, UID: pool.Metadata.UID, ResourceVersion: pool.Metadata.ResourceVersion},
		Reason: reason, Message: message, Type: typ,
		Source:         EventSource{Component: ManagedBy},
		FirstTimestamp: ts, LastTimestamp: ts, Count: 1,
		ReportingComponent: ManagedBy, ReportingInstance: r.instance,
	}
	ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := r.api.createEvent(ectx, ev); err != nil {
		r.logf("record event %s on %s: %v", reason, pool.Key(), err)
	}
	r.logf("%s %s/%s: %s: %s", strings.ToLower(typ), pool.Metadata.Namespace, pool.Metadata.Name, reason, message)
}
