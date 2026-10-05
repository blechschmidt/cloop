package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/config"
)

// minFreeDiskMB resolves the free-space floor a run applies (Task 20381).
//
// The project's orchestrator.min_free_disk_mb answers, or the default when it
// is unset. A hub dispatching a run of its own directory says what its
// Settings say through CLOOP_MIN_FREE_DISK_MB: an operator who set the floor
// there may have written it to the hub's per-instance overlay, which only
// `cloop ui` reads, and the run should not apply a different floor from the
// one the hub's doctor and banner hold its disk to. A value there that is out
// of range is ignored, with a warning, in favour of the configuration.
//
// cfg may be nil (a configuration that would not load), which reads as unset.
func minFreeDiskMB(cfg *config.Config) int {
	if raw := strings.TrimSpace(os.Getenv(config.EnvMinFreeDiskMB)); raw != "" {
		v, err := strconv.Atoi(raw)
		if err == nil && config.ValidMinFreeDiskMB(v) {
			return v
		}
		why := "not a whole number of megabytes"
		if err == nil {
			why = config.MinFreeDiskMBError(v).Error()
		}
		warnBadFloorEnv.Do(func() {
			fmt.Fprintf(os.Stderr, "warning: ignoring %s=%q: %s\n", config.EnvMinFreeDiskMB, raw, why)
		})
	}
	if cfg == nil {
		return config.MinFreeDiskMBDefault
	}
	return cfg.Orchestrator.EffectiveMinFreeDiskMB()
}

// warnBadFloorEnv says once per process that the environment's floor was
// unusable; the daemon and agent resolve it every cycle.
var warnBadFloorEnv sync.Once
