package logtail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"time"
)

// Follow streams appended bytes from path to w, like `tail -f`. It tolerates:
//   - The file not existing yet at start (waits with capped exponential
//     backoff until it appears, instead of erroring out).
//   - The file being removed mid-session (closes the fd, waits for the file
//     to reappear, then resumes from the start of the new file).
//   - The file being replaced (different inode) — reopens at offset 0.
//   - The file being truncated (size shrinks below the current read offset)
//     — reopens at offset 0.
//
// Initial existing content is NOT replayed: the first open seeks to EOF.
// Callers wanting backlog should call Tail first, then Follow.
//
// Follow returns nil when ctx is cancelled, or a non-nil error when an
// unrecoverable I/O failure occurs (e.g. permission denied reopening the
// file, or w returns an error). A vanished-then-reappeared file is not an
// error; backoff is capped so polling cannot busy-loop.
//
// Follow is not internally concurrent and must be called from one goroutine.
func Follow(ctx context.Context, path string, w io.Writer) error {
	return followWithConfig(ctx, path, w, defaultFollowConfig())
}

// followConfig parameterises Follow for tests.
type followConfig struct {
	pollInterval   time.Duration // wait between drain cycles
	fastPoll       time.Duration // wait when last drain emitted bytes
	backoffInitial time.Duration // first wait when file is missing
	backoffMax     time.Duration // upper cap on missing-file backoff
	bufSize        int           // bufio reader buffer
}

func defaultFollowConfig() followConfig {
	return followConfig{
		pollInterval:   500 * time.Millisecond,
		fastPoll:       100 * time.Millisecond,
		backoffInitial: 200 * time.Millisecond,
		backoffMax:     5 * time.Second,
		bufSize:        64 * 1024,
	}
}

func followWithConfig(ctx context.Context, path string, w io.Writer, cfg followConfig) error {
	var (
		f      *os.File
		info   os.FileInfo
		reader *bufio.Reader
	)
	closeF := func() {
		if f != nil {
			_ = f.Close()
			f = nil
			reader = nil
			info = nil
		}
	}
	defer closeF()

	open := func(seekToEnd bool) error {
		nf, err := os.Open(path)
		if err != nil {
			return err
		}
		if seekToEnd {
			if _, err := nf.Seek(0, io.SeekEnd); err != nil {
				_ = nf.Close()
				return err
			}
		}
		ni, err := nf.Stat()
		if err != nil {
			_ = nf.Close()
			return err
		}
		closeF()
		f = nf
		info = ni
		reader = bufio.NewReaderSize(nf, cfg.bufSize)
		return nil
	}

	sleep := func(d time.Duration) bool {
		if d <= 0 {
			return true
		}
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}

	// Initial open: tolerate missing file with backoff.
	backoff := cfg.backoffInitial
	for {
		err := open(true)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if !sleep(backoff) {
			return nil
		}
		backoff = nextBackoff(backoff, cfg.backoffMax)
	}

	drainBuf := make([]byte, 32*1024)
	for {
		emitted, err := drain(reader, w, drainBuf)
		if err != nil {
			return err
		}

		// Detect rotation / truncation / removal.
		ni, statErr := os.Stat(path)
		switch {
		case statErr == nil && !os.SameFile(info, ni):
			if err := open(false); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					// Race: replaced and removed between our Stat and Open.
					// Fall through to the missing-file branch on next iteration.
					closeF()
					if !sleep(cfg.backoffInitial) {
						return nil
					}
					continue
				}
				return err
			}
			continue
		case statErr == nil:
			// Same file. Truncation: size dropped below current offset.
			cur, _ := f.Seek(0, io.SeekCurrent)
			if ni.Size() < cur {
				if err := open(false); err != nil {
					return err
				}
				continue
			}
			info = ni
		case errors.Is(statErr, fs.ErrNotExist):
			closeF()
			waitFor := cfg.backoffInitial
			for {
				if !sleep(waitFor) {
					return nil
				}
				if err := open(false); err == nil {
					break
				} else if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				waitFor = nextBackoff(waitFor, cfg.backoffMax)
			}
			continue
		default:
			return statErr
		}

		wait := cfg.pollInterval
		if emitted {
			wait = cfg.fastPoll
		}
		if !sleep(wait) {
			return nil
		}
	}
}

// drain copies all currently-readable bytes from r to w, stopping at the
// first transient EOF. Returns whether any bytes were emitted plus any
// non-EOF error from a Read or Write.
func drain(r *bufio.Reader, w io.Writer, buf []byte) (bool, error) {
	if r == nil {
		return false, nil
	}
	emitted := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return emitted, werr
			}
			emitted = true
		}
		if err == io.EOF {
			return emitted, nil
		}
		if err != nil {
			return emitted, err
		}
	}
}

// nextBackoff doubles cur with ±25% jitter, capped at maxD and floored at 50ms.
func nextBackoff(cur, maxD time.Duration) time.Duration {
	const minBackoff = 50 * time.Millisecond
	next := cur * 2
	if next > maxD {
		next = maxD
	}
	if next < minBackoff {
		next = minBackoff
	}
	jitter := int64(next) / 4
	if jitter > 0 {
		offset := rand.Int63n(jitter*2+1) - jitter
		next = time.Duration(int64(next) + offset)
	}
	if next < minBackoff {
		next = minBackoff
	}
	return next
}
