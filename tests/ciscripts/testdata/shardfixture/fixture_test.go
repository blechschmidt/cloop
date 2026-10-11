package shardfixture

import (
	"fmt"
	"testing"
)

// The duration table tests/ciscripts writes gives these the most time.
func TestSlowA(t *testing.T) {}
func TestSlowB(t *testing.T) {}
func TestSlowC(t *testing.T) {}

// TestStop is a prefix of TestStopAll, so a regex that selects one without
// anchors selects both.
func TestStop(t *testing.T) {
	if Sign(0) != "zero" {
		t.Fatal("zero")
	}
}

func TestStopAll(t *testing.T) {
	if Sign(-1) != "negative" {
		t.Fatal("negative")
	}
}

func TestSignPositive(t *testing.T) {
	if Sign(1) != "positive" {
		t.Fatal("positive")
	}
}

// Not in the table: each is placed by a hash of its name.
func TestNewOne(t *testing.T)   {}
func TestNewTwo(t *testing.T)   {}
func TestNewThree(t *testing.T) {}
func TestNewFour(t *testing.T)  {}
func TestNewFive(t *testing.T)  {}
func TestNewSix(t *testing.T)   {}

func FuzzDouble(f *testing.F) {
	f.Add(3)
	f.Fuzz(func(t *testing.T, n int) {
		if Double(n) != n+n {
			t.Fatalf("Double(%d) = %d", n, Double(n))
		}
	})
}

func ExampleDouble() {
	fmt.Println(Double(21))
	// Output: 42
}

// Listed by go test -list, run only under -bench: no shard may claim it.
func BenchmarkDouble(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Double(i)
	}
}
