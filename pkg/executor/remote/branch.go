package remote

// branch.go is the hub's half of shipping a branch to a device (protocol v16,
// Task 20367): the git bundle a feature's workspace names is streamed to the
// agent in branch_chunk frames, ahead of the start frame that names it. The
// device's half is in pkg/executor/agent/branch.go.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// sendBranchBundle streams the bundle at path to the agent as branch chunks for
// handleID.
//
// It reads the file in MaxBranchChunkBytes slices rather than loading it,
// because a bundle is bounded but not small, and it fails on the first frame
// that cannot be written: a bundle with a hole in it is refused by the device
// anyway, and saying so here names the link rather than the bundle.
func sendBranchBundle(ctx context.Context, sess *Session, handleID, path string, total int64) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read the bundle: %w", err)
	}
	defer f.Close()

	buf := make([]byte, MaxBranchChunkBytes)
	var offset int64
	for {
		n, readErr := io.ReadFull(f, buf)
		if n > 0 {
			if offset+int64(n) > total {
				return fmt.Errorf("the bundle grew past the %d bytes it was measured at", total)
			}
			frame, err := sess.frame(TypeBranchChunk, "", handleID,
				BranchChunkPayload{Offset: offset, Data: buf[:n], Total: total})
			if err != nil {
				return fmt.Errorf("encoding the chunk at offset %d: %w", offset, err)
			}
			if err := sess.write(ctx, frame); err != nil {
				return fmt.Errorf("chunk at offset %d: %w", offset, err)
			}
			offset += int64(n)
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading the bundle at offset %d: %w", offset, readErr)
		}
	}
	if offset != total {
		return fmt.Errorf("the bundle is %d bytes but %d were measured", offset, total)
	}
	return nil
}
