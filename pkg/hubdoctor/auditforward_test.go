package hubdoctor

// The audit forwarding checks (Task 20426).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func forwardFindings(t *testing.T, dir string, cfg *config.Config, now time.Time) map[string][]Finding {
	t.Helper()
	out := map[string][]Finding{}
	checkAuditForward(dir, cfg, Options{Now: func() time.Time { return now }}, func(f Finding) {
		if f.Severity != SeverityPass && f.Remediation == "" {
			t.Errorf("%s is %s without a remediation: %s", f.Check, f.Severity, f.Message)
		}
		out[f.Check] = append(out[f.Check], f)
	})
	return out
}

// setCursor records a sink's position on the hub's own chain, as its
// forwarder would.
func setCursor(t *testing.T, dbPath, sink string, acked int64, ackedAt time.Time) {
	t.Helper()
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	abs, _ := filepath.Abs(dbPath)
	c, err := db.InitAuditForwardCursor(statedb.AuditForwardCursor{
		Sink: sink, Chain: abs, Source: "control-plane", Dir: filepath.Dir(filepath.Dir(abs)),
		AckedID: 0, AckedHash: statedb.AuditGenesisHash,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if acked == 0 {
		return
	}
	row, ok, err := db.AuditRowAt(acked)
	if err != nil || !ok {
		t.Fatalf("row %d: %v", acked, err)
	}
	if err := db.AdvanceAuditForwardCursor(sink, abs, statedb.AuditForwardAdvance{
		FromID: c.AckedID, FromHash: c.AckedHash, ToID: acked, ToHash: row.RowHash, ToRowAt: row.Timestamp,
		Delivered: acked, At: ackedAt,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditForwardFindings(t *testing.T) {
	dir, dbPath := auditHubDir(t)
	now := time.Now().UTC()
	fileSink := func(name string) config.AuditForwardSink {
		return config.AuditForwardSink{Name: name, Type: config.AuditSinkFile, Path: filepath.Join(t.TempDir(), name+".jsonl")}
	}

	t.Run("nothing forwarded", func(t *testing.T) {
		got := forwardFindings(t, dir, config.Default(), now)
		if f := got["audit.forward"]; len(f) != 1 || f[0].Severity != SeverityWarn || !strings.Contains(f[0].Message, "no audit sink") {
			t.Fatalf("no sinks: %+v", got)
		}
	})

	t.Run("refused at load", func(t *testing.T) {
		cdir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(cdir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		yaml := "audit:\n  forward:\n    sinks:\n      - name: plain\n        type: syslog\n" +
			"        address: 10.1.2.3:514\n        transport: tcp\n        allow_plaintext_loopback: true\n"
		if err := os.WriteFile(config.ConfigPath(cdir), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(cdir)
		if err != nil {
			t.Fatal(err)
		}
		got := forwardFindings(t, cdir, cfg, now)
		f := got["audit.forward.sink"]
		if len(f) != 1 || f[0].Severity != SeverityFail || !strings.Contains(f[0].Message, "not a loopback address") {
			t.Fatalf("a refused sink must fail the doctor: %+v", got)
		}
		// And the generic load-repair check leaves it to this one.
		var repaired []Finding
		checkLoadRepairs(cfg, func(f Finding) { repaired = append(repaired, f) })
		if len(repaired) != 0 {
			t.Errorf("the switch-off was reported twice: %+v", repaired)
		}
	})

	t.Run("a secret that is not there", func(t *testing.T) {
		t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-forward-test-key-0123456789abcdef")
		cfg := config.Default()
		cfg.Audit.Forward.Sinks = []config.AuditForwardSink{{
			Name: "hec", Type: config.AuditSinkHTTPS, URL: "https://hec.example.com/services/collector/event",
			Variant: config.AuditVariantSplunkHEC, TokenSecret: "missing-token",
		}}
		got := forwardFindings(t, dir, cfg, now)
		f := got["audit.forward.sink"]
		if len(f) != 1 || f[0].Severity != SeverityFail || !strings.Contains(f[0].Message, "missing-token") {
			t.Fatalf("a sink naming a secret the store lacks: %+v", got)
		}
	})

	t.Run("never delivered", func(t *testing.T) {
		cfg := config.Default()
		cfg.Audit.Forward.Sinks = []config.AuditForwardSink{fileSink("never")}
		setCursor(t, dbPath, "never", 0, time.Time{})
		f := forwardFindings(t, dir, cfg, now)["audit.forward.lag"]
		if len(f) != 1 || f[0].Severity != SeverityWarn || !strings.Contains(f[0].Message, "never delivered") {
			t.Fatalf("a sink with rows waiting that never delivered: %+v", f)
		}
	})

	t.Run("lagging and healthy", func(t *testing.T) {
		cfg := config.Default()
		cfg.Audit.Forward.MaxLag = "10m"
		cfg.Audit.Forward.Sinks = []config.AuditForwardSink{fileSink("behind"), fileSink("current")}
		setCursor(t, dbPath, "behind", 2, now.Add(-time.Hour))
		setCursor(t, dbPath, "current", 5, now)
		// The rows behind is waiting for are a day old.
		got := forwardFindings(t, dir, cfg, now.Add(24*time.Hour))
		lag := got["audit.forward.lag"]
		if len(lag) != 1 || !strings.Contains(lag[0].Message, "behind") || !strings.Contains(lag[0].Message, "max_lag") {
			t.Fatalf("a sink beyond max_lag: %+v", got)
		}
		pass := got["audit.forward"]
		if len(pass) != 1 || pass[0].Severity != SeverityPass || !strings.Contains(pass[0].Message, "current") {
			t.Fatalf("the healthy sink is not reported as forwarding: %+v", got)
		}
	})
}
