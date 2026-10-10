package configvalidate

// audit.checkpoints through all three doors (Task 20404): Load drops a file
// that may not hold checkpoints and runs a bad interval at the default, `cloop
// config set` refuses both (cmd/config_cmd_test.go), and this command reports
// what the operator wrote rather than what Load kept.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

func TestAuditCheckpointsThroughEveryPath(t *testing.T) {
	cases := []struct {
		name, yaml string
		bad        bool
		inMessage  string
	}{
		{"default", "", false, ""},
		{"a file outside .cloop", "audit:\n  checkpoints:\n    file: /var/log/cloop/cps.jsonl\n", false, ""},
		{"a file inside .cloop", "audit:\n  checkpoints:\n    file: /srv/hub/.cloop/cps.jsonl\n", true, ".cloop"},
		{"a relative file", "audit:\n  checkpoints:\n    file: cps.jsonl\n", true, "absolute"},
		{"an interval too short", "audit:\n  checkpoints:\n    interval: 10s\n", true, "outside"},
		{"an interval that does not parse", "audit:\n  checkpoints:\n    interval: hourly\n", true, "not a duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeConfig(t, tc.yaml)

			rep, err := Run(context.Background(), dir, ValidateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, f := range rep.Findings {
				if f.Field == "config.audit.checkpoints" && strings.Contains(f.Message, tc.inMessage) {
					found = true
				}
			}
			if found != tc.bad {
				t.Errorf("config validate reported it: %v, want %v; findings %+v", found, tc.bad, rep.Findings)
			}

			cfg, err := config.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.ValidateNumeric(); err != nil {
				t.Errorf("Load left a value ValidateNumeric refuses: %v", err)
			}
			repaired := false
			for _, r := range cfg.LoadRepairs() {
				if strings.HasPrefix(r.Field, "audit.checkpoints") {
					repaired = true
				}
			}
			if repaired != tc.bad {
				t.Errorf("Load repaired it: %v, want %v", repaired, tc.bad)
			}
			if got := cfg.Audit.Checkpoints.EffectiveInterval(); got < config.AuditCheckpointIntervalLower {
				t.Errorf("effective interval %s", got)
			}
		})
	}
}
