package config

// ui.oidc.sudo_max_age_minutes (Task 20448): how recently the person behind a
// session must have signed in for a privileged action.

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestSudoMaxAgeIsDefaultedClampedAndSwitchedOff: zero is the default, -1 the
// documented off, and everything else is held to 1..1440, as device approval's
// window is — which is what reaches the authenticator.
func TestSudoMaxAgeIsDefaultedClampedAndSwitchedOff(t *testing.T) {
	for _, c := range []struct{ in, want int }{
		{0, 120}, {-1, -1}, {-30, -1}, {1, 1}, {45, 45}, {1440, 1440}, {5000, 1440},
	} {
		o := OIDCConfig{SudoMaxAgeMinutes: c.in}
		if got := o.EffectiveSudoMaxAgeMinutes(); got != c.want {
			t.Errorf("EffectiveSudoMaxAgeMinutes(%d) = %d, want %d", c.in, got, c.want)
		}
		if got, want := o.AuthConfig().SudoMaxAge, time.Duration(c.want)*time.Minute; got != want {
			t.Errorf("AuthConfig().SudoMaxAge for %d = %v, want %v", c.in, got, want)
		}
	}
	if (OIDCConfig{SudoMaxAgeMinutes: -1}).SudoOff() {
		t.Error("a block with single sign-on off cannot have sudo mode off: there are no sessions")
	}
	if !(OIDCConfig{Enabled: true, SudoMaxAgeMinutes: -1}).SudoOff() {
		t.Error("SudoOff must report -1 on a hub with single sign-on")
	}
	if (OIDCConfig{Enabled: true}).SudoOff() {
		t.Error("the default is on")
	}
}

// TestSudoMaxAgeValidation: the panel, `cloop config set` and `cloop config
// validate` refuse what the hub would clamp into something else.
func TestSudoMaxAgeValidation(t *testing.T) {
	for _, ok := range []int{0, -1, 1, 120, 1440} {
		if err := ValidSudoMaxAgeMinutes(ok); err != nil {
			t.Errorf("%d refused: %v", ok, err)
		}
	}
	for _, bad := range []int{-2, -60, 1441, 100000} {
		err := ValidSudoMaxAgeMinutes(bad)
		if err == nil || !strings.Contains(err.Error(), "ui.oidc.sudo_max_age_minutes") {
			t.Errorf("%d accepted or unnamed: %v", bad, err)
		}
	}
	cfg := Default()
	cfg.UI.OIDC.SudoMaxAgeMinutes = 9999
	if err := cfg.ValidateNumeric(); err == nil || !strings.Contains(err.Error(), "sudo_max_age_minutes") {
		t.Errorf("ValidateNumeric accepted sudo_max_age_minutes 9999: %v", err)
	}
}

// TestOverlaySudoMaxAgeWins: like every other ui.oidc key, the per-hub overlay
// decides for its hub — including turning sudo mode off for one hub alone.
func TestOverlaySudoMaxAgeWins(t *testing.T) {
	dir := writeConfigs(t, `provider: claudecode
ui:
    oidc:
        sudo_max_age_minutes: 30
`, `ui:
    oidc:
        enabled: true
        sudo_max_age_minutes: -1
`, 8081)
	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if got := cfg.UI.OIDC.EffectiveSudoMaxAgeMinutes(); got != -1 {
		t.Errorf("sudo_max_age_minutes = %d, want the overlay's -1", got)
	}

	// And a save from the panel writes it there, for this hub.
	overlay := UIInstanceConfigPath(dir, 8081)
	o := cfg.UI.OIDC
	o.SudoMaxAgeMinutes = 45
	if err := SaveUIInstanceOIDC(overlay, o); err != nil {
		t.Fatal(err)
	}
	cfg, _, err = LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.UI.OIDC.SudoMaxAgeMinutes; got != 45 {
		t.Errorf("after the panel's save sudo_max_age_minutes = %d, want 45", got)
	}
}

// TestSudoMaxAgeIsMirroredToTheDatabase: the key is in the copy of config.yaml
// state.db keeps, like the rest of ui.oidc.
func TestSudoMaxAgeIsMirroredToTheDatabase(t *testing.T) {
	dir := tempDir(t)
	initStateDB(t, dir)
	cfg := Default()
	cfg.UI.OIDC.SudoMaxAgeMinutes = 90
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	db, err := statedb.Open(stateDBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blob, err := db.GetConfigBlob()
	if err != nil || !strings.Contains(blob, "sudo_max_age_minutes: 90") {
		t.Fatalf("the mirror does not carry sudo_max_age_minutes (%v):\n%s", err, blob)
	}
}
