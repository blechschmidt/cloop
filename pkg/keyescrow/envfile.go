package keyescrow

// Putting a recovered key back where the hub reads it.
//
// The key belongs in exactly one file — the hub's environment file, 0600,
// which `cloop hub bootstrap` wrote and systemd or compose loads — so that is
// where `cloop hub key escrow import` puts it, line for line beside whatever
// else the file holds. Everything here is about not making a recovery worse
// than the loss it recovers from: an env file holding a *different* key is
// never overwritten without being asked, and when asked it is kept aside rather
// than deleted, because it may be the only copy of a key something is still
// sealed under.

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// EnvInstall reports what WriteEnvFile did.
type EnvInstall struct {
	Path string
	// Created: there was no file; it holds the key and nothing else.
	Created bool
	// Unchanged: the file already held this key, and was not touched.
	Unchanged bool
	// Previous is where the earlier file went when it held a different key.
	Previous string
}

// isKeyLine reports whether line assigns the key, and the value it assigns:
// bare, as the bootstrap writes it, or exported, as a shell-sourced file
// might, quoted or not. A commented-out line is not an assignment.
func isKeyLine(line string) (value string, ok bool) {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "export ")
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, EnvKey) {
		return "", false
	}
	rest := strings.TrimSpace(s[len(EnvKey):])
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	v := strings.TrimSpace(rest[1:])
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return v, true
}

// envSafe reports whether key can be written to an env file unquoted and
// read back identically by both systemd's EnvironmentFile and a POSIX shell.
// Every key `cloop hub bootstrap` generates is (base64url). A shell expands a
// tilde at the start of an assignment's value or after a colon, so neither is
// in the set.
func envSafe(key []byte) bool {
	for _, c := range key {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-_.+/=", c) >= 0:
		default:
			return false
		}
	}
	return len(key) > 0
}

// WriteEnvFile puts key into the env file at path — the file a symlink there
// points to — as CLOOP_SECRET_KEY, keeping every other line. A file that
// already holds this key, once, is left alone; one holding a different key in
// any of its assignments is refused unless replace is set, and then kept
// beside it as <path>.pre-import.<UTC>.
func WriteEnvFile(path string, key []byte, replace bool, now time.Time) (EnvInstall, error) {
	// A hub.env that is a link to where the service unit reads it from is
	// written through: replacing the link with a file would leave the unit
	// reading the old key.
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	res := EnvInstall{Path: path}
	if len(key) == 0 {
		return res, ErrNoKey
	}
	if !envSafe(key) {
		return res, fmt.Errorf("keyescrow: this %s holds characters an env file would need quoted, "+
			"and systemd and a shell quote differently; print it with --stdout and store it yourself", EnvKey)
	}
	existing, err := os.ReadFile(path)
	defer zero(existing)
	switch {
	case errors.Is(err, os.ErrNotExist):
		existing = nil
		res.Created = true
	case err != nil:
		return res, fmt.Errorf("keyescrow: read %s: %w", path, err)
	}

	var (
		out bytes.Buffer
		// assignments counts the lines assigning the key, same those
		// assigning this one, and other says one assigns a different key.
		// Every assignment counts, not the first: the last is what a shell
		// sourcing the file ends up with.
		assignments, same int
		other             bool
	)
	sc := bufio.NewScanner(bytes.NewReader(existing))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := isKeyLine(line); ok {
			assignments++
			switch {
			case v == "":
			case subtle.ConstantTimeCompare([]byte(v), key) == 1:
				same++
			default:
				other = true
			}
			if assignments == 1 {
				out.WriteString(EnvKey + "=" + string(key) + "\n")
			}
			// A second assignment is dropped rather than left to mean
			// something else when the file is sourced.
			continue
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("keyescrow: read %s: %w", path, err)
	}
	if assignments == 1 && same == 1 {
		res.Unchanged = true
		return res, nil
	}
	if assignments == 0 {
		if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n\n")) {
			out.WriteString("\n")
		}
		out.WriteString("# Recovered from a key escrow by `cloop hub key escrow import`.\n")
		out.WriteString(EnvKey + "=" + string(key) + "\n")
	}
	defer zero(out.Bytes())

	if other && !replace {
		return res, fmt.Errorf("keyescrow: %s already holds a different %s; it may be the only copy of a key "+
			"something is sealed under. Pass --force to keep it aside as %s.pre-import.<UTC> and install this one",
			path, EnvKey, filepath.Base(path))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return res, fmt.Errorf("keyescrow: %w", err)
	}
	if other {
		res.Previous = path + ".pre-import." + now.UTC().Format("20060102T150405Z")
		if err := os.Rename(path, res.Previous); err != nil {
			return res, fmt.Errorf("keyescrow: keep %s aside: %w", path, err)
		}
	}
	if err := writeAtomically(path, out.Bytes()); err != nil {
		if res.Previous != "" {
			if rerr := os.Rename(res.Previous, path); rerr != nil {
				err = errors.Join(err, fmt.Errorf("keyescrow: put %s back: %w", res.Previous, rerr))
			} else {
				res.Previous = ""
			}
		}
		return res, err
	}
	return res, nil
}

// KeyFileInstall reports what WriteKeyFile did; the same shape as EnvInstall.
type KeyFileInstall = EnvInstall

// WriteKeyFile puts key into the key file at path — the file a symlink there
// points to — the way the hub reads it from CLOOP_SECRET_KEY_FILE or loads it
// as a systemd credential: the key and a newline, nothing else, mode 0600
// (Task 20425).
//
// The same care as WriteEnvFile: a file that already holds this key is left
// alone, one holding a different key is refused unless replace is set and then
// kept beside it as <path>.pre-import.<UTC>, and a temporary that fails on the
// way is destroyed with pkg/securewipe. A path inside a .cloop/ directory is
// refused, because the hub refuses to read a key from there.
func WriteKeyFile(path string, key []byte, replace bool, now time.Time) (KeyFileInstall, error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	res := KeyFileInstall{Path: path}
	switch {
	case len(key) == 0:
		return res, ErrNoKey
	case !filepath.IsAbs(path):
		return res, fmt.Errorf("keyescrow: %s is not an absolute path; the hub reads its key file by one", path)
	case rootkey.InsideCloopDir(path):
		return res, fmt.Errorf("keyescrow: %s is inside a .cloop/ directory, where the hub refuses to read a key "+
			"from: keep it apart from the database it protects", path)
	case bytes.IndexByte(key, 0) >= 0 || bytes.ContainsAny(key, "\r\n"):
		return res, fmt.Errorf("keyescrow: this %s holds a byte a key file cannot carry; print it with --stdout "+
			"and store it yourself", EnvKey)
	}

	existing, err := os.ReadFile(path)
	defer zero(existing)
	switch {
	case errors.Is(err, os.ErrNotExist):
		res.Created = true
	case err != nil:
		return res, fmt.Errorf("keyescrow: read %s: %w", path, err)
	default:
		held := bytes.TrimSuffix(bytes.TrimSuffix(existing, []byte("\n")), []byte("\r"))
		if subtle.ConstantTimeCompare(held, key) == 1 {
			res.Unchanged = true
			return res, nil
		}
		if len(held) > 0 && !replace {
			return res, fmt.Errorf("keyescrow: %s already holds a different key; it may be the only copy of a key "+
				"something is sealed under. Pass --force to keep it aside as %s.pre-import.<UTC> and install this one",
				path, filepath.Base(path))
		}
	}

	out := make([]byte, 0, len(key)+1)
	out = append(append(out, key...), '\n')
	defer zero(out)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return res, fmt.Errorf("keyescrow: %w", err)
	}
	if !res.Created {
		res.Previous = path + ".pre-import." + now.UTC().Format("20060102T150405Z")
		if err := os.Rename(path, res.Previous); err != nil {
			return res, fmt.Errorf("keyescrow: keep %s aside: %w", path, err)
		}
	}
	if err := writeAtomically(path, out); err != nil {
		if res.Previous != "" {
			if rerr := os.Rename(res.Previous, path); rerr != nil {
				err = errors.Join(err, fmt.Errorf("keyescrow: put %s back: %w", res.Previous, rerr))
			} else {
				res.Previous = ""
			}
		}
		return res, err
	}
	return res, nil
}

// EnvFileHoldsKey reports whether the env file at path assigns the key — the
// layout a hub bootstrapped before Task 20425 keeps it in.
func EnvFileHoldsKey(path string) bool {
	data, err := os.ReadFile(path)
	defer zero(data)
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if v, ok := isKeyLine(sc.Text()); ok && v != "" {
			return true
		}
	}
	return false
}
