// Package failing fails the ordinary ways: an assertion, a fatal, subtests
// nested two deep, two parallel tests, a long log, and a message carrying
// what a workflow command would misread. It is a fixture: `go test ./...`
// never runs it, and scripts/ci-annotate's recordings were made from it.
package failing

import "testing"

func TestPasses(t *testing.T) { t.Log("nothing to see") }

func TestSkips(t *testing.T) { t.Skip("not on this machine") }

func TestAssertion(t *testing.T) {
	t.Log("comparing the totals")
	if got, want := 2+2, 5; got != want {
		t.Errorf("2+2 = %d, want %d", got, want)
	}
}

func TestFatal(t *testing.T) {
	t.Fatalf("cannot continue:\nthe store answered 503\nafter 3 attempts")
}

func TestNested(t *testing.T) {
	t.Run("passes", func(t *testing.T) {})
	t.Run("fails", func(t *testing.T) {
		t.Error("the leaf failed")
	})
	t.Run("deeper", func(t *testing.T) {
		t.Run("still deeper", func(t *testing.T) {
			t.Error("two levels down")
		})
	})
}

func TestParallelOne(t *testing.T) {
	t.Parallel()
	t.Error("one of two parallel failures")
}

func TestParallelTwo(t *testing.T) {
	t.Parallel()
	t.Error("two of two parallel failures")
}

func TestLongLog(t *testing.T) {
	for i := 1; i <= 80; i++ {
		t.Logf("progress line %d of 80", i)
	}
	t.Error("the failure after eighty lines")
}

// TestHostileMessage fails with text an annotation must carry as text: a
// percent sign, a carriage return, and lines that are workflow commands.
func TestHostileMessage(t *testing.T) {
	t.Error("100% sure: \r\n::error file=injected.go,line=1::an injected annotation\n::warning::another, with %0A in it")
}
