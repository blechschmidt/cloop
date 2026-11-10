// Package helm compiles the executor controller's Helm chart into the cloop
// binary (Task 20486), so a hub can serve the chart of its own build to `helm
// install` the way it serves /install.sh to an edge device: the command the
// dashboard hands an administrator then needs no checkout of this repository,
// and installs a controller of the same build as the hub it talks to.
//
// Only the executor controller's chart is here. The hub's own chart
// (cloop-hub) is installed before there is a hub to serve it.
package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"path"
	"sort"
	"sync"
	"time"
)

// ExecutorControllerChartName is the chart's name, which is also the
// directory its archive holds it in: Helm requires the two to match.
const ExecutorControllerChartName = "cloop-executor-controller"

// all: keeps _helpers.tpl and _validate.tpl, which a plain pattern would skip
// for their leading underscore.
//
//go:embed all:cloop-executor-controller
var executorController embed.FS

var (
	archiveOnce sync.Once
	archive     []byte
	archiveSum  string
	archiveErr  error
)

// ExecutorControllerChart returns the chart as a gzipped tar, the form `helm
// package` writes and `helm install <URL>` reads, and its SHA-256 in hex. The
// archive is made once and is the same bytes on every call and every build of
// the same tree: entries in name order, with fixed times and modes.
func ExecutorControllerChart() ([]byte, string, error) {
	archiveOnce.Do(func() {
		archive, archiveErr = pack(executorController, ExecutorControllerChartName)
		if archiveErr == nil {
			sum := sha256.Sum256(archive)
			archiveSum = hex.EncodeToString(sum[:])
		}
	})
	return archive, archiveSum, archiveErr
}

// ExecutorControllerFiles is the chart's files, for tests that compare them
// with the repository's.
func ExecutorControllerFiles() fs.FS { return executorController }

// epoch is every entry's time: a fixed one keeps the archive's bytes, and so
// its digest, a function of the files alone.
var epoch = time.Unix(0, 0).UTC()

func pack(fsys fs.FS, root string) ([]byte, error) {
	var names []string
	if err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			names = append(names, p)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{Name: path.Clean(name), Mode: 0o644, Size: int64(len(body)), ModTime: epoch,
			Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
