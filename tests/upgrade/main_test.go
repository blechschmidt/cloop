// Package upgrade_test rehearses a rolling upgrade from cloop's latest published
// release to the build under test, with the real release binary and the real
// build side by side on one database and one cluster (Task 20452).
//
// # Why
//
// docs/architecture/hub-cluster.md promises a rolling upgrade: start a member
// of the new build, stop the old members one at a time, each stopping member
// hands its runs and agents over, and the old members keep serving the
// migrated database for as long as they tolerate every migration they lack.
// Each half of that was tested within one build only: pkg/statedb's
// schema_compat tests imitate an older binary in SQL, and tests/cluster runs
// the same binary for every member. Mixed versions are routine — every release
// moves the executor protocol, and the stable UI on :8080 is an old build
// sharing :8888's database — and nothing had ever run a published release
// beside main.
//
// # What runs
//
// The release is fetched from GitHub (releases/latest, linux-amd64; on a
// release tag the release before it), its checksum checked and its Sigstore
// bundle verified against the pinned release identity (pkg/provenance) before
// anything of it runs. The archive is cached by tag and verified again on every
// use; only the bytes from a verified archive are ever executed.
//
// TestRollingUpgradeFromTheLatestRelease is the forward rehearsal: two release
// members, a project the release built, an enrolled release agent running a
// device run with a secret lease and git proxy and Kubernetes monitor sessions,
// CI exchanges, quota counters and SSO sessions; then a member of the build
// under test joins, migrates and records its verdicts, and the release members
// are stopped one at a time. TestRollbackToTheReleaseAfterMainMigrated is the
// backward one: the release opening the database main migrated, tolerating or
// refusing exactly as docs/operations/runbook.md#rollback says.
//
// Every hub has sign-in (SSO and a token) and listens on loopback, every
// process runs in a process group of its own and is killed by it, and the
// scratch tree is removed afterwards.
//
// # Running it
//
//	CLOOP_UPGRADE_E2E=1 go test ./tests/upgrade/ -v -count=1 -timeout 12m
//
// CLOOP_UPGRADE_MAIN_BIN names a prebuilt build under test (otherwise one is
// built from this checkout, stamped with its commit and sequence the way the
// :8888 deploy stamps its build); CLOOP_UPGRADE_FROM pins the release to
// rehearse from; CLOOP_UPGRADE_CACHE is the archive cache (default: the user
// cache directory); CLOOP_UPGRADE_COSIGN names the cosign binary (default:
// cosign on PATH); CLOOP_UPGRADE_KEEP=1 leaves the scratch tree behind.
//
// Without network the suite skips, naming what it could not reach; CI's
// Upgrade rehearsal job requires the tests to have passed by name, so a skip
// there fails the job.
package upgrade_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// Environment variables that change what the suite runs against.
const (
	// enableEnv opts in: the rehearsal downloads a release and spawns hubs.
	enableEnv = "CLOOP_UPGRADE_E2E"
	// mainBinEnv supplies a prebuilt build under test.
	mainBinEnv = "CLOOP_UPGRADE_MAIN_BIN"
	// fromEnv pins the release rehearsed from, instead of the latest one.
	fromEnv = "CLOOP_UPGRADE_FROM"
	// cacheEnv is where release archives are kept, by tag.
	cacheEnv = "CLOOP_UPGRADE_CACHE"
	// cosignEnv names the cosign binary, for a machine where it is not on PATH.
	cosignEnv = "CLOOP_UPGRADE_COSIGN"
	// keepEnv leaves the scratch tree behind for inspection.
	keepEnv = "CLOOP_UPGRADE_KEEP"
)

// Read before hometest.Isolate moves HOME: Go's build and module caches and
// the user cache directory default to places under it.
var (
	goEnv        []string
	userCacheDir string
)

func TestMain(m *testing.M) {
	goEnv = captureGoEnv()
	if dir, err := os.UserCacheDir(); err == nil {
		userCacheDir = dir
	}
	os.Exit(hometest.Isolate(m))
}

// captureGoEnv carries GOCACHE, GOMODCACHE and GOPATH into the build of the
// binary under test: against empty ones it is a cold compile that needs the
// network for every module.
func captureGoEnv() []string {
	names := []string{"GOCACHE", "GOMODCACHE", "GOPATH"}
	out, err := exec.Command("go", append([]string{"env"}, names...)...).Output()
	if err != nil {
		return nil
	}
	var env []string
	for i, v := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if i < len(names) && v != "" {
			env = append(env, names[i]+"="+v)
		}
	}
	return env
}

// cacheRoot is where release archives are cached, by tag.
func cacheRoot() string {
	if dir := strings.TrimSpace(os.Getenv(cacheEnv)); dir != "" {
		return dir
	}
	if userCacheDir != "" {
		return filepath.Join(userCacheDir, "cloop", "upgrade-rehearsal")
	}
	return filepath.Join(os.TempDir(), "cloop-upgrade-rehearsal-cache")
}

// requireRehearsal skips unless the suite was asked for, naming how to ask.
func requireRehearsal(t *testing.T) {
	t.Helper()
	if os.Getenv(enableEnv) != "1" {
		t.Skipf("%s is not 1; this downloads cloop's latest release and runs it beside this build", enableEnv)
	}
	for _, tool := range []string{"bash", "git", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required by the rehearsal's stand-in harness: %v", tool, err)
		}
	}
}
