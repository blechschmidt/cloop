package config

import (
	"strings"
	"testing"
)

// A sink that would send the trail in plaintext off the host is refused at
// load — dropped, and recorded as switched off — never repaired into a sink
// that sends somewhere, or somehow, nobody configured; the strict validators
// `cloop config set` and `cloop config validate` use refuse the same file
// outright. Plaintext to an acknowledged loopback collector loads (Task 20426).
func TestAPlaintextNonLoopbackSinkIsRefusedAtLoad(t *testing.T) {
	file := `audit:
  forward:
    sinks:
      - name: tls-syslog
        type: syslog
        address: siem.example.com:6514
      - name: plain-syslog
        type: syslog
        address: 10.0.0.5:514
        transport: tcp
        allow_plaintext_loopback: true
      - name: plain-https
        type: https
        url: http://siem.example.com/ingest
        allow_plaintext_loopback: true
      - name: loopback-unacknowledged
        type: syslog
        address: 127.0.0.1:514
        transport: tcp
      - name: local-collector
        type: syslog
        address: 127.0.0.1:514
        transport: tcp
        allow_plaintext_loopback: true
      - name: in-cloop
        type: file
        path: /srv/hub/.cloop/audit.jsonl
      - name: inline-credentials
        type: https
        url: https://user:pass@siem.example.com/ingest
`
	dir := writeConfigs(t, file, "", 0)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var kept []string
	for _, s := range cfg.Audit.Forward.Sinks {
		kept = append(kept, s.Name)
	}
	if got := strings.Join(kept, ","); got != "tls-syslog,local-collector" {
		t.Fatalf("sinks kept at load = %s, want tls-syslog,local-collector", got)
	}

	off := map[string]string{}
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff != "" {
			off[r.SwitchedOff] = r.Detail
		}
	}
	for sink, why := range map[string]string{
		"plain-syslog":            "not a loopback address",
		"plain-https":             "not a loopback address",
		"loopback-unacknowledged": "allow_plaintext_loopback",
		"in-cloop":                ".cloop/",
		"inline-credentials":      "token_secret",
	} {
		detail, ok := off["audit.forward.sinks."+sink]
		if !ok {
			t.Errorf("%s was not recorded as switched off: %+v", sink, cfg.LoadRepairs())
			continue
		}
		if !strings.Contains(detail, why) || !strings.Contains(detail, "the sink is disabled") {
			t.Errorf("%s: switch-off says %q, want it to name %q", sink, detail, why)
		}
	}

	// The strict validators refuse the file the loader repaired.
	raw := &Config{}
	raw.Audit.Forward = AuditForwardConfig{Sinks: []AuditForwardSink{{
		Name: "plain-syslog", Type: AuditSinkSyslog, Address: "10.0.0.5:514", Transport: AuditTransportTCP,
		AllowPlaintextLoopback: true,
	}}}
	if err := raw.ValidateNumeric(); err == nil || !strings.Contains(err.Error(), "not a loopback address") {
		t.Errorf("ValidateNumeric = %v, want the plaintext refusal", err)
	}
}

func TestAuditForwardSinkValidation(t *testing.T) {
	ok := []AuditForwardSink{
		{Name: "s", Type: "syslog", Address: "[2001:db8::1]:6514", Format: "cef", Facility: "audit"},
		{Name: "h", Type: "https", URL: "https://hec.example.com:8088/services/collector/event",
			Variant: "splunk_hec", TokenSecret: "hec-token", SplunkIndex: "audit"},
		{Name: "e", Type: "https", URL: "https://es.example.com/ingest", TokenSecret: "es#API_KEY", AuthScheme: "apikey"},
		{Name: "m", Type: "syslog", Address: "rsyslog:6514", ClientCert: "/etc/cloop/client.pem",
			ClientKeySecret: "client-key", CAFile: "/etc/cloop/ca.pem"},
		{Name: "f", Type: "file", Path: "/var/log/cloop/audit.jsonl", Start: "latest"},
	}
	for _, s := range ok {
		if err := ValidateAuditForwardSink(s); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
	}
	bad := map[string]AuditForwardSink{
		"name":           {Name: "Has Spaces", Type: "file", Path: "/x"},
		"type":           {Name: "a", Type: "udp", Address: "h:514"},
		"no port":        {Name: "a", Type: "syslog", Address: "siem.example.com"},
		"facility":       {Name: "a", Type: "syslog", Address: "h:6514", Facility: "local9"},
		"https cef":      {Name: "a", Type: "https", URL: "https://h/x", Format: "cef"},
		"hec no token":   {Name: "a", Type: "https", URL: "https://h/x", Variant: "splunk_hec"},
		"scheme no tok":  {Name: "a", Type: "https", URL: "https://h/x", AuthScheme: "bearer"},
		"key alone":      {Name: "a", Type: "syslog", Address: "h:6514", ClientKeySecret: "k"},
		"relative file":  {Name: "a", Type: "file", Path: "audit.jsonl"},
		"bad secret ref": {Name: "a", Type: "https", URL: "https://h/x", TokenSecret: "has space"},
		"bad key ref":    {Name: "a", Type: "https", URL: "https://h/x", TokenSecret: "name#1BAD"},
		"tls on tcp":     {Name: "a", Type: "syslog", Address: "127.0.0.1:514", Transport: "tcp", AllowPlaintextLoopback: true, CAFile: "/ca.pem"},
		"batch":          {Name: "a", Type: "file", Path: "/x", BatchSize: 10000},
		"start":          {Name: "a", Type: "file", Path: "/x", Start: "yesterday"},
		"query key":      {Name: "a", Type: "https", URL: "https://h/ingest?api_key=abc"},
		"query token":    {Name: "a", Type: "https", URL: "https://h/ingest?Access_Token=abc"},
	}
	for why, s := range bad {
		if err := ValidateAuditForwardSink(s); err == nil {
			t.Errorf("%s: %+v was accepted", why, s)
		}
	}
	// A query string that is not a credential is kept, and never shown.
	hec := AuditForwardSink{Name: "q", Type: "https", URL: "https://h:8088/services/collector/event?index=audit&channel=x",
		Variant: "splunk_hec", TokenSecret: "t"}
	if err := ValidateAuditForwardSink(hec); err != nil {
		t.Errorf("a HEC URL with index and channel parameters was refused: %v", err)
	}
	if got := hec.Endpoint(); got != "https://h:8088/services/collector/event" {
		t.Errorf("Endpoint() = %q, want the URL without its query", got)
	}
	dup := AuditForwardConfig{Sinks: []AuditForwardSink{ok[4], ok[4]}}
	if err := ValidateAuditForward(dup); err == nil || !strings.Contains(err.Error(), "earlier sink") {
		t.Errorf("duplicate names: %v", err)
	}
	if err := ValidateAuditForward(AuditForwardConfig{MaxLag: "5s"}); err == nil {
		t.Error("a max_lag below a minute was accepted")
	}
}
