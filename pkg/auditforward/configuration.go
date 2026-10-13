package auditforward

// configuration.go: recording a change of forward configuration in the audit
// trail, and retiring the cursors nothing forwards any more.
//
// A change is detected, not reported. The leader fingerprints the sinks it
// runs under and compares the fingerprint with the one the control plane
// remembers, so an edit made with any tool — a settings panel, `cloop config
// set`, an editor, a deployment pipeline rewriting the overlay while the hub
// was down — is recorded by the first leader to run under it. Disabling
// forwarding is the change an attacker most wants unrecorded, and it is
// recorded in the chain the remaining sinks still receive.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// configMetaKey is the hub-meta record of the configuration last recorded.
const configMetaKey = "audit.forward.config"

// SinkDescription is what the audit trail records about a sink: everything
// that decides where and how its rows go, and no credential — the secret-store
// references are names.
type SinkDescription struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Format     string   `json:"format"`
	Endpoint   string   `json:"endpoint"`
	Variant    string   `json:"variant,omitempty"`
	Refs       []string `json:"refs,omitempty"`
	CAFile     string   `json:"ca_file,omitempty"`
	ClientCert string   `json:"client_cert,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	// PlaintextLoopback is true for a sink acknowledged to send plaintext to
	// a loopback collector.
	PlaintextLoopback bool   `json:"plaintext_loopback,omitempty"`
	Start             string `json:"start"`
	Fingerprint       string `json:"fingerprint"`
}

// Describe renders a sink for the audit trail and status output.
func Describe(s config.AuditForwardSink) SinkDescription {
	return SinkDescription{
		Name:              s.Name,
		Type:              strings.ToLower(s.Type),
		Format:            s.EffectiveFormat(),
		Endpoint:          s.Endpoint(),
		Variant:           strings.ToLower(s.Variant),
		Refs:              s.StoreRefs(),
		CAFile:            s.CAFile,
		ClientCert:        s.ClientCert,
		ServerName:        s.ServerName,
		PlaintextLoopback: s.Plaintext(),
		Start:             s.EffectiveStart(),
		Fingerprint:       sinkFingerprint(s),
	}
}

// sinkFingerprint is a short digest of everything a sink says.
func sinkFingerprint(s config.AuditForwardSink) string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// recordedConfig is the hub-meta record.
type recordedConfig struct {
	Fingerprint string            `json:"fingerprint"`
	Sinks       map[string]string `json:"sinks"`
}

func fingerprintConfig(cfg config.AuditForwardConfig) recordedConfig {
	rc := recordedConfig{Sinks: map[string]string{}}
	names := make([]string, 0, len(cfg.Sinks))
	for _, s := range cfg.Sinks {
		rc.Sinks[s.Name] = sinkFingerprint(s)
		names = append(names, s.Name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n + "=" + rc.Sinks[n] + "\n"))
	}
	h.Write([]byte("max_lag=" + cfg.MaxLag + "\nhostname=" + cfg.Hostname + "\n"))
	rc.Fingerprint = hex.EncodeToString(h.Sum(nil)[:8])
	return rc
}

// recordConfiguration appends audit.forward.configured when the configuration
// differs from the one last recorded. A failure is said and retried at the
// next reconcile.
func (f *Forwarder) recordConfiguration(cp *statedb.DB, cfg config.AuditForwardConfig) {
	cur := fingerprintConfig(cfg)
	if cur.Fingerprint == f.configured {
		return
	}
	var prev recordedConfig
	raw, found, err := cp.HubMeta(configMetaKey)
	if err != nil {
		f.logf("could not read the forward configuration last recorded: %v", err)
		return
	}
	if found {
		_ = json.Unmarshal([]byte(raw), &prev)
	}
	if found && prev.Fingerprint == cur.Fingerprint {
		f.configured = cur.Fingerprint
		return
	}
	if !found && len(cfg.Sinks) == 0 {
		// Never configured, and still not: nothing changed.
		f.configured = cur.Fingerprint
		return
	}

	var added, removed, changed []string
	for name, fp := range cur.Sinks {
		switch old, ok := prev.Sinks[name]; {
		case !ok:
			added = append(added, name)
		case old != fp:
			changed = append(changed, name)
		}
	}
	for name := range prev.Sinks {
		if _, ok := cur.Sinks[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	sinks := make([]SinkDescription, 0, len(cfg.Sinks))
	for _, s := range cfg.Sinks {
		sinks = append(sinks, Describe(s))
	}
	var refused []string
	if f.opts.Refused != nil {
		refused = f.opts.Refused()
	}
	payload := map[string]any{
		"added":       nonNil(added),
		"removed":     nonNil(removed),
		"changed":     nonNil(changed),
		"sinks":       sinks,
		"refused":     nonNil(refused),
		"fingerprint": cur.Fingerprint,
		"file":        f.opts.ConfigSource,
	}
	if found {
		payload["previous_fingerprint"] = prev.Fingerprint
	}
	ev := statedb.AuditEvent{
		Actor:      "system",
		EventType:  string(auditaction.ActionAuditForwardConfigured),
		EntityType: "config",
		EntityID:   "audit.forward",
		Payload:    statedb.MarshalAuditPayload(payload),
	}
	if err := cp.AppendAuditEvent(&ev); err != nil {
		f.logf("could not record the forward configuration change: %v", err)
		return
	}
	b, _ := json.Marshal(cur)
	if err := cp.SetHubMeta(configMetaKey, string(b)); err != nil {
		f.logf("could not remember the forward configuration: %v", err)
		return
	}
	f.configured = cur.Fingerprint
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// syncCursors brings the cursors' service state in line with what is being
// forwarded — every configured sink on every served chain: a cursor of a sink
// no longer configured, or of a chain no longer served, stops holding
// retention, and one whose sink and chain are back returns to service, however
// long a worker has been asleep in backoff with it cached. It runs on every
// pass and writes only what differs.
func (f *Forwarder) syncCursors(cp *statedb.DB, sinks []config.AuditForwardSink, chains []Chain) {
	live := make([]statedb.AuditForwardKey, 0, len(sinks)*len(chains))
	for _, s := range sinks {
		for _, c := range chains {
			live = append(live, statedb.AuditForwardKey{Sink: s.Name, Chain: c.Path})
		}
	}
	if _, _, err := cp.SyncAuditForwardCursors(live, f.now()); err != nil {
		f.logf("could not bring the cursors in line with the sinks and chains forwarded: %v", err)
	}
}
