//go:build !linux

package diskwatch

// Off Linux the walk goes by path: cloop's sandboxes run on Linux, and this
// exists so the package builds and measures on a developer's machine. A path
// is bounded by PATH_MAX, so a tree nested deeper than that is reported as
// unreadable below that depth rather than measured; see walk_linux.go for the
// descriptor-relative walk that has no such limit.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// root measures one tree.
func (m *walk) root(r Root) error {
	root := filepath.Clean(r.Path)
	info, err := os.Lstat(root)
	if err != nil {
		if r.Optional && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("diskwatch: %w", err)
	}
	if !info.IsDir() {
		if r.Optional {
			return nil
		}
		return fmt.Errorf("diskwatch: %s is not a directory", root)
	}
	st := statOf(info)
	m.raw += st.bytes
	m.usage.Entries++

	exclude := make(map[string]bool, len(r.Exclude))
	for _, name := range r.Exclude {
		exclude[name] = true
	}

	// Depth-first with an explicit stack: a workload controls the depth of
	// the tree, and recursion would let it control the depth of this stack.
	stack := []string{root}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if err := m.check(); err != nil {
			return err
		}
		var ex map[string]bool
		if dir == root {
			ex = exclude
		}
		sub, err := m.dir(dir, st.dev, ex)
		if err != nil {
			return err
		}
		stack = append(stack, sub...)
	}
	return nil
}

// dir counts one directory's entries and returns the subdirectories to visit.
func (m *walk) dir(dir string, rootDev uint64, exclude map[string]bool) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, m.unlistable(dir, err)
	}
	defer f.Close()

	var sub []string
	for {
		entries, readErr := f.ReadDir(readBatch)
		for _, e := range entries {
			if err := m.tick(); err != nil {
				return nil, err
			}
			name := e.Name()
			if exclude[name] {
				continue
			}
			path := joinPath(dir, name)
			info, err := e.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return sub, m.unlistable(dir, err)
			}
			st := statOf(info)
			if info.IsDir() {
				if m.isMount(path, st.dev, rootDev) {
					m.usage.MountsSkipped++
					continue
				}
				m.raw += st.bytes
				sub = append(sub, path)
				continue
			}
			m.file(st.bytes, st.dev, st.ino, st.nlink)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return sub, nil
			}
			return sub, m.unlistable(dir, readErr)
		}
	}
}
