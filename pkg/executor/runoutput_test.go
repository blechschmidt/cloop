package executor

import (
	"context"
	"strings"
	"testing"
)

// chunkedExecutor streams a fixed list of chunks for its one workload.
type chunkedExecutor struct {
	fakeExecutor
	chunks []string
}

func (c *chunkedExecutor) Stream(context.Context, string) (<-chan LogLine, error) {
	ch := make(chan LogLine, len(c.chunks))
	for i, text := range c.chunks {
		ch <- LogLine{Seq: uint64(i + 1), Text: text}
	}
	close(ch)
	return ch, nil
}

// TestRunWithOutputRelaysEachChunkInOrder: WithOutput sees every chunk as Run
// receives it (Task 20442), and Run's own result is what it would have been
// without it.
func TestRunWithOutputRelaysEachChunkInOrder(t *testing.T) {
	ex := &chunkedExecutor{fakeExecutor: fakeExecutor{id: "chunked", kind: KindLocalProcess},
		chunks: []string{"first\n", "half a li", "ne\n", "last\n"}}
	var relayed []string
	res, err := Run(context.Background(), ex, Spec{Argv: []string{"x"}},
		WithOutput(func(l LogLine) { relayed = append(relayed, l.Text) }))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Join(relayed, "|") != "first\n|half a li|ne\n|last\n" {
		t.Fatalf("relayed %q", relayed)
	}
	plain, err := Run(context.Background(), ex, Spec{Argv: []string{"x"}})
	if err != nil {
		t.Fatalf("Run without the option: %v", err)
	}
	if string(res.Output) != string(plain.Output) || string(res.Output) != "first\nhalf a line\nlast\n" {
		t.Fatalf("output with the option %q, without %q", res.Output, plain.Output)
	}
}
