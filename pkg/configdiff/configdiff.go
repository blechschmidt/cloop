// Package configdiff compares the canonical .cloop/config.yaml against the
// SQLite-mirrored copy stored by Save() (see pkg/config). The two stores
// diverge whenever:
//
//   - The user runs `cloop config set` against a binary that mirrors, then
//     restores the YAML from a backup that predates the SQLite mirror.
//   - A different cloop binary (one without the mirror code) writes config.yaml,
//     leaving the SQLite copy stale.
//   - Direct SQL edits or migrations mutate the metadata blob without touching
//     the YAML.
//   - The YAML is hand-edited but cloop hasn't run Save() yet.
//
// Silent drift between the two leads to "why did my config change not take
// effect" bug reports — Load() prefers YAML when present, but tools that
// query the SQLite mirror (analytics, the doctor command, third-party
// inspection scripts) see the stale copy. This package exposes the drift
// explicitly so users can resolve it deliberately.
package configdiff

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Direction selects which source wins during Sync.
type Direction string

const (
	// FromYAML overwrites the SQLite mirror with the YAML contents (default).
	// This is the natural recovery path because YAML is the canonical
	// human-edited source — Load() already prefers it.
	FromYAML Direction = "from-yaml"

	// FromDB overwrites the YAML with the SQLite mirror. Used to recover
	// when the YAML has been corrupted or accidentally truncated and the
	// SQLite blob has the last good copy.
	FromDB Direction = "from-db"
)

// DiffKind describes how a key differs between the two stores.
type DiffKind string

const (
	// Added means the key exists in the right side (DB) but not the left (YAML).
	Added DiffKind = "added"
	// Removed means the key exists in the left side (YAML) but not the right (DB).
	Removed DiffKind = "removed"
	// Changed means the key exists in both with different values.
	Changed DiffKind = "changed"
)

// Entry is a single keyed difference between YAML and DB.
//
// Path is a dotted key path into the YAML structure (e.g.
// "anthropic.api_key", "rate_limit.burst"). YAMLValue and DBValue are the
// human-readable string forms of each side; either may be empty when the kind
// is Added/Removed.
type Entry struct {
	Path      string
	Kind      DiffKind
	YAMLValue string
	DBValue   string
}

// Report is the result of comparing the two stores.
type Report struct {
	// YAMLPresent is true when .cloop/config.yaml exists on disk.
	YAMLPresent bool
	// DBPresent is true when .cloop/state.db exists AND has a non-empty config blob.
	DBPresent bool
	// Entries lists every keyed difference, ordered by Path.
	Entries []Entry
}

// HasDrift returns true when the two stores disagree in any way the user
// should care about. Special cases the "DB has no blob yet" scenario as
// non-drift — a fresh project that hasn't been mirrored yet isn't drift, just
// uninitialised state.
func (r *Report) HasDrift() bool {
	if !r.YAMLPresent && !r.DBPresent {
		return false
	}
	if r.YAMLPresent && !r.DBPresent {
		// YAML exists but mirror was never written. Treat as drift so the
		// user is prompted to sync from-yaml (which initialises the mirror).
		return true
	}
	return len(r.Entries) > 0
}

// Summary returns a one-line human-readable summary suitable for embedding in
// doctor reports or CLI output. Empty string when there's no drift.
func (r *Report) Summary() string {
	if !r.HasDrift() {
		return ""
	}
	if r.YAMLPresent && !r.DBPresent {
		return "YAML present but SQLite mirror is missing — run 'cloop config sync' to initialise"
	}
	if !r.YAMLPresent && r.DBPresent {
		return "config.yaml is missing but SQLite mirror has a copy — run 'cloop config sync --from-db' to restore"
	}
	added, removed, changed := 0, 0, 0
	for _, e := range r.Entries {
		switch e.Kind {
		case Added:
			added++
		case Removed:
			removed++
		case Changed:
			changed++
		}
	}
	parts := []string{}
	if changed > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", changed))
	}
	if removed > 0 {
		parts = append(parts, fmt.Sprintf("%d only in yaml", removed))
	}
	if added > 0 {
		parts = append(parts, fmt.Sprintf("%d only in db", added))
	}
	return "config drift: " + strings.Join(parts, ", ")
}

// stateDBPath mirrors pkg/config.stateDBPath but is duplicated here to keep
// pkg/configdiff a leaf package free of cmd/* and config-private helpers.
func stateDBPath(workdir string) string {
	return filepath.Join(workdir, ".cloop", "state.db")
}

// readYAML returns the raw YAML bytes from .cloop/config.yaml or ("", false)
// when the file is missing. Other errors propagate as ("", false, err).
func readYAML(workdir string) ([]byte, bool, error) {
	data, err := os.ReadFile(config.ConfigPath(workdir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read yaml: %w", err)
	}
	return data, true, nil
}

// readDB returns the YAML blob stored in state.db's metadata table, or
// ("", false) when state.db is missing or has no blob yet.
func readDB(workdir string) (string, bool, error) {
	dbPath := stateDBPath(workdir)
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return "", false, fmt.Errorf("open state.db: %w", err)
	}
	defer db.Close()
	blob, err := db.GetConfigBlob()
	if err != nil {
		return "", false, fmt.Errorf("read config blob: %w", err)
	}
	if blob == "" {
		return "", false, nil
	}
	return blob, true, nil
}

// Compute compares the two stores and returns a structured Report. Returns
// an error only on unexpected I/O or parse failures; "absent" is normal state
// and reflected via the booleans on Report.
func Compute(workdir string) (*Report, error) {
	yamlBytes, yamlPresent, err := readYAML(workdir)
	if err != nil {
		return nil, err
	}
	dbBlob, dbPresent, err := readDB(workdir)
	if err != nil {
		return nil, err
	}

	rep := &Report{YAMLPresent: yamlPresent, DBPresent: dbPresent}

	// Both absent: nothing to compare.
	if !yamlPresent && !dbPresent {
		return rep, nil
	}

	yamlMap := map[string]any{}
	dbMap := map[string]any{}
	if yamlPresent {
		if err := yaml.Unmarshal(yamlBytes, &yamlMap); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
	}
	if dbPresent {
		if err := yaml.Unmarshal([]byte(dbBlob), &dbMap); err != nil {
			return nil, fmt.Errorf("parse db blob: %w", err)
		}
	}
	rep.Entries = diffMaps("", yamlMap, dbMap)
	sort.Slice(rep.Entries, func(i, j int) bool {
		return rep.Entries[i].Path < rep.Entries[j].Path
	})
	return rep, nil
}

// diffMaps walks two YAML-decoded map[string]any structures and emits an
// Entry for every leaf-level difference. Sub-maps recurse; non-map mismatches
// (including type mismatches, e.g. map vs scalar) are reported at the
// containing path.
func diffMaps(prefix string, left, right map[string]any) []Entry {
	out := []Entry{}
	keys := unionKeys(left, right)
	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		lv, lok := left[k]
		rv, rok := right[k]
		switch {
		case lok && !rok:
			out = append(out, Entry{Path: path, Kind: Removed, YAMLValue: formatValue(lv)})
		case !lok && rok:
			out = append(out, Entry{Path: path, Kind: Added, DBValue: formatValue(rv)})
		default:
			lm, lIsMap := toStringMap(lv)
			rm, rIsMap := toStringMap(rv)
			if lIsMap && rIsMap {
				out = append(out, diffMaps(path, lm, rm)...)
				continue
			}
			if lIsMap != rIsMap {
				// Shape mismatch (one side is a map, the other a scalar/list).
				// Report as a single Changed at this level.
				out = append(out, Entry{
					Path:      path,
					Kind:      Changed,
					YAMLValue: formatValue(lv),
					DBValue:   formatValue(rv),
				})
				continue
			}
			if !valuesEqual(lv, rv) {
				out = append(out, Entry{
					Path:      path,
					Kind:      Changed,
					YAMLValue: formatValue(lv),
					DBValue:   formatValue(rv),
				})
			}
		}
	}
	return out
}

// unionKeys returns sorted union of keys from both maps. Sorted ordering is
// load-bearing for deterministic reports — the test asserts on Path order.
func unionKeys(a, b map[string]any) []string {
	seen := map[string]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// toStringMap promotes the various map representations yaml.v3 may produce
// (map[string]any, map[any]any) into a uniform map[string]any. Returns
// (_, false) for non-map values.
func toStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, vv := range m {
			out[fmt.Sprintf("%v", k)] = vv
		}
		return out, true
	default:
		return nil, false
	}
}

// valuesEqual compares two YAML-decoded scalars (or lists) for equality. We
// do the comparison via formatted-string equality because YAML's int/float
// promotion rules differ between the two stores after a round-trip (e.g.
// "0.0" → float64(0); on the other side "0" → int(0)). String equality
// after canonical formatting is the cheapest correct comparator.
func valuesEqual(a, b any) bool {
	return formatValue(a) == formatValue(b)
}

// formatValue produces a stable human-readable string for any YAML-decoded
// value. Lists and maps are marshalled via yaml.Marshal (compact flow style
// for short scalars; one-line for everything else). Sensitive scalars are
// NOT redacted here — the caller (Render) is responsible for masking, since
// internal callers (Sync, tests) need the raw value.
func formatValue(v any) string {
	if v == nil {
		return "<nil>"
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", x)
	case int64:
		return fmt.Sprintf("%d", x)
	case float64:
		// Trim trailing zeros so 7.5 doesn't become "7.500000".
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", x), "0"), ".")
	default:
		// Arrays, maps, time values: round-trip through YAML for a stable
		// canonical form. yaml.Marshal of a scalar/list produces a
		// single-line string with a trailing newline we trim.
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return strings.TrimRight(string(out), "\n")
	}
}

// sensitivePathSubstrings lists the dotted-path fragments whose values
// represent secrets we should mask in human-facing diff output. Matches are
// case-insensitive and substring (e.g. "anthropic.api_key" matches via
// "api_key"; "github.token" matches via "token").
var sensitivePathSubstrings = []string{
	"api_key",
	"token",
	"secret",
	"webhook",
}

// IsSensitive returns true when the given dotted config path likely names a
// secret. Used by Render() to mask values before printing the diff.
func IsSensitive(path string) bool {
	lower := strings.ToLower(path)
	for _, frag := range sensitivePathSubstrings {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// MaskSecret returns a redacted form of a secret value suitable for human
// display. Mirrors the masking convention of cmd/config_cmd.go's maskSecret
// — keep the first/last 4 chars when long enough, otherwise return ****.
func MaskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

// Render formats a Report as a multi-line, human-readable string. Secret
// values (api keys, tokens) are masked. Returns an empty string when no
// drift is present (callers usually short-circuit before calling Render).
func Render(rep *Report) string {
	if rep == nil {
		return ""
	}
	var b strings.Builder

	if !rep.YAMLPresent && !rep.DBPresent {
		b.WriteString("No config.yaml and no SQLite mirror — nothing to compare.\n")
		return b.String()
	}
	if rep.YAMLPresent && !rep.DBPresent {
		b.WriteString("config.yaml present, SQLite mirror missing.\n")
		b.WriteString("Run 'cloop config sync' to initialise the mirror.\n")
		return b.String()
	}
	if !rep.YAMLPresent && rep.DBPresent {
		b.WriteString("config.yaml missing, SQLite mirror has a copy.\n")
		b.WriteString("Run 'cloop config sync --from-db' to restore the YAML.\n")
		return b.String()
	}

	if len(rep.Entries) == 0 {
		b.WriteString("config.yaml and SQLite mirror are in sync.\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("Config drift: %d differences\n", len(rep.Entries)))
	b.WriteString("(YAML is the canonical source; DB is the SQLite mirror)\n\n")
	for _, e := range rep.Entries {
		yval, dval := e.YAMLValue, e.DBValue
		if IsSensitive(e.Path) {
			yval = MaskSecret(yval)
			dval = MaskSecret(dval)
		}
		switch e.Kind {
		case Added:
			b.WriteString(fmt.Sprintf("  + %s    only in db: %s\n", e.Path, dval))
		case Removed:
			b.WriteString(fmt.Sprintf("  - %s    only in yaml: %s\n", e.Path, yval))
		case Changed:
			b.WriteString(fmt.Sprintf("  ~ %s    yaml=%s  db=%s\n", e.Path, yval, dval))
		}
	}
	return b.String()
}

// Sync resolves drift in the chosen direction. Returns an error when the
// chosen source is not available (e.g. FromDB with no mirror, FromYAML with
// no YAML file). The opposite store is overwritten atomically — for FromYAML
// via config.Save (which already mirrors); for FromDB via writing the blob
// out and calling config.Save to round-trip via the validated, atomic path.
//
// We deliberately go through config.Save rather than writing raw bytes so:
//   - The validateAndClamp pass runs on the rehydrated config — operators
//     can't accidentally restore a stale-and-invalid blob.
//   - 0o600 perms and atomic rename behaviour are inherited.
//   - The reverse mirror is also refreshed (FromDB writes YAML + re-mirrors,
//     so any missing fields in the blob are normalised on the way through).
func Sync(workdir string, dir Direction) error {
	switch dir {
	case FromYAML:
		return syncFromYAML(workdir)
	case FromDB:
		return syncFromDB(workdir)
	default:
		return fmt.Errorf("unknown sync direction %q (want %q or %q)", dir, FromYAML, FromDB)
	}
}

// syncFromYAML loads the YAML via config.Load (which clamps numerics) and
// re-saves it. Save() mirrors into SQLite as a side-effect, so the blob is
// refreshed whether or not it existed before. If state.db doesn't exist yet,
// Save() does nothing on the SQLite side (by design — we don't auto-create
// state.db here either, mirroring config.Save's contract).
func syncFromYAML(workdir string) error {
	if _, err := os.Stat(config.ConfigPath(workdir)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot sync from-yaml: %s does not exist", config.ConfigPath(workdir))
		}
		return fmt.Errorf("stat config.yaml: %w", err)
	}
	cfg, err := config.Load(workdir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := config.Save(workdir, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// syncFromDB pulls the blob out of state.db, parses it as a config, then
// writes it back via config.Save (which validates, atomically writes the
// YAML, and re-mirrors). Refusing to round-trip via config.Save would skip
// validateAndClamp and let a corrupted blob propagate.
func syncFromDB(workdir string) error {
	blob, ok, err := readDB(workdir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("cannot sync from-db: state.db has no config mirror (run 'cloop config sync --from-yaml' first)")
	}
	cfg := config.Default()
	if err := yaml.Unmarshal([]byte(blob), cfg); err != nil {
		return fmt.Errorf("parse db blob: %w", err)
	}
	// Defence-in-depth: reject obviously bad numerics before persisting.
	// validateAndClamp inside Load() would catch them but only after writing
	// — we want the operator to see the error before the YAML is rewritten
	// from a corrupt blob.
	if err := cfg.ValidateNumeric(); err != nil {
		return fmt.Errorf("db blob has invalid values: %w", err)
	}
	if err := config.Save(workdir, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}
