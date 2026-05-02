package env_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/env"
)

func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadEmpty(t *testing.T) {
	dir := setup(t)
	vars, err := env.Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 0 {
		t.Errorf("expected empty slice, got %v", vars)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := setup(t)
	input := []env.Var{
		{Key: "FOO", Value: "bar", Description: "a test var"},
		{Key: "SECRET", Value: "mysecret", Secret: true},
	}
	if err := env.Save(dir, input); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := env.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(loaded))
	}

	// Plain var should survive unchanged.
	if loaded[0].Key != "FOO" || loaded[0].Value != "bar" {
		t.Errorf("FOO mismatch: %+v", loaded[0])
	}

	// Secret should be stored encoded, but Expand should decode it.
	expanded := env.Expand(loaded)
	if expanded["SECRET"] != "mysecret" {
		t.Errorf("SECRET expected 'mysecret', got %q", expanded["SECRET"])
	}
}

func TestExpandPlain(t *testing.T) {
	vars := []env.Var{
		{Key: "A", Value: "alpha"},
		{Key: "B", Value: "beta"},
	}
	m := env.Expand(vars)
	if m["A"] != "alpha" || m["B"] != "beta" {
		t.Errorf("unexpected expand result: %v", m)
	}
}

func TestExpandSecret(t *testing.T) {
	dir := setup(t)
	vars := []env.Var{{Key: "TOKEN", Value: "secret123", Secret: true}}
	if err := env.Save(dir, vars); err != nil {
		t.Fatal(err)
	}
	loaded, err := env.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := env.Expand(loaded)
	if m["TOKEN"] != "secret123" {
		t.Errorf("expected decoded secret, got %q", m["TOKEN"])
	}
}

func TestInjectIntoPrompt(t *testing.T) {
	vars := []env.Var{
		{Key: "HOST", Value: "localhost"},
		{Key: "PORT", Value: "8080"},
	}
	prompt := "Connect to {{HOST}}:{{PORT}} and check {{MISSING}}"
	got := env.InjectIntoPrompt(prompt, vars)
	want := "Connect to localhost:8080 and check {{MISSING}}"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestInjectIntoPromptNoVars(t *testing.T) {
	prompt := "No placeholders here"
	got := env.InjectIntoPrompt(prompt, nil)
	if got != prompt {
		t.Errorf("expected prompt unchanged, got %q", got)
	}
}

func TestUpsert(t *testing.T) {
	vars := []env.Var{{Key: "A", Value: "1"}}
	vars = env.Upsert(vars, env.Var{Key: "A", Value: "2"})
	if len(vars) != 1 || vars[0].Value != "2" {
		t.Errorf("upsert update failed: %v", vars)
	}
	vars = env.Upsert(vars, env.Var{Key: "B", Value: "3"})
	if len(vars) != 2 {
		t.Errorf("upsert add failed: %v", vars)
	}
}

func TestDelete(t *testing.T) {
	vars := []env.Var{{Key: "A", Value: "1"}, {Key: "B", Value: "2"}}
	vars, ok := env.Delete(vars, "A")
	if !ok || len(vars) != 1 || vars[0].Key != "B" {
		t.Errorf("delete failed: ok=%v vars=%v", ok, vars)
	}
	_, ok = env.Delete(vars, "NOTEXIST")
	if ok {
		t.Error("expected false for missing key")
	}
}

func TestGetVar(t *testing.T) {
	vars := []env.Var{{Key: "X", Value: "42"}}
	v, ok := env.Get(vars, "X")
	if !ok || v.Value != "42" {
		t.Errorf("Get failed: ok=%v v=%v", ok, v)
	}
	_, ok = env.Get(vars, "Y")
	if ok {
		t.Error("expected false for missing key")
	}
}

func TestDecodeValue(t *testing.T) {
	dir := setup(t)
	vars := []env.Var{{Key: "S", Value: "plain-secret", Secret: true}}
	if err := env.Save(dir, vars); err != nil {
		t.Fatal(err)
	}
	loaded, _ := env.Load(dir)
	v, _ := env.Get(loaded, "S")
	if env.DecodeValue(v) != "plain-secret" {
		t.Errorf("DecodeValue expected 'plain-secret', got %q", env.DecodeValue(v))
	}
}

func TestEnvLines(t *testing.T) {
	vars := []env.Var{{Key: "FOO", Value: "bar"}}
	lines := env.EnvLines(vars)
	if len(lines) != 1 || lines[0] != "FOO=bar" {
		t.Errorf("EnvLines unexpected: %v", lines)
	}
}
