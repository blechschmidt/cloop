package statedb

import "testing"

// SetHubMetas writes its keys together and HubMetas reads them together
// (Task 20443): a record kept across two keys — one a newer build reads, one an
// older build still does — is never seen half rewritten.
func TestHubMetasWriteAndReadTogether(t *testing.T) {
	d := openTestDB(t)
	if err := d.SetHubMetas(map[string]string{"pair.a": "1", "pair.b": "one"}); err != nil {
		t.Fatal(err)
	}
	got, err := d.HubMetas("pair.a", "pair.b", "pair.missing")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["pair.a"] != "1" || got["pair.b"] != "one" {
		t.Fatalf("HubMetas = %v", got)
	}
	if _, ok := got["pair.missing"]; ok {
		t.Error("a key with no value was reported")
	}
	if v, ok, err := d.HubMeta("pair.b"); err != nil || !ok || v != "one" {
		t.Errorf("HubMeta(pair.b) = %q, %v, %v", v, ok, err)
	}

	// A batch that cannot be written whole writes nothing.
	if err := d.SetHubMetas(map[string]string{"pair.a": "2", " ": "bad"}); err == nil {
		t.Fatal("a batch with an empty key was accepted")
	}
	if got, _ := d.HubMetas("pair.a"); got["pair.a"] != "1" {
		t.Errorf("a refused batch changed pair.a to %q", got["pair.a"])
	}
	if err := d.SetHubMetas(map[string]string{"pair.a": "2", "pair.b": "two"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.HubMetas("pair.a", "pair.b"); got["pair.a"] != "2" || got["pair.b"] != "two" {
		t.Errorf("rewritten pair = %v", got)
	}
}
