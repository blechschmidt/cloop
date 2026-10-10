package auditcheckpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/blechschmidt/cloop/pkg/config"
)

// Sink is where records go: a file, stderr, or both.
type Sink struct {
	// File is appended to and fsynced; "" writes no file.
	File string
	// Stderr receives one JSON line per record; nil writes none.
	Stderr io.Writer
}

// CheckFile reports why path cannot hold checkpoints: the configuration rule
// (absolute, outside every .cloop/ directory), and the same rule again after
// resolving symlinks — in its directory and, when it exists, in the file
// itself — so a link cannot walk the records back in beside the database. An
// existing path must be a regular file: appending to a device or a FIFO is not
// keeping a record.
func CheckFile(path string) error {
	if err := config.ValidateAuditCheckpointFile(path); err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	dir := filepath.Dir(filepath.Clean(path))
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("checkpoint directory %s: %w", dir, err)
	}
	if config.PathInsideCloopDir(real) {
		return fmt.Errorf("%q resolves to %s, inside a .cloop/ directory", path, real)
	}
	// The file itself may be a link too, and appending follows it — creating
	// the target if it does not exist, so a link that resolves nowhere yet is
	// refused rather than trusted.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("%q is a symlink that does not resolve: %v", path, err)
			}
			if config.PathInsideCloopDir(target) {
				return fmt.Errorf("%q resolves to %s, inside a .cloop/ directory", path, target)
			}
			if fi, err = os.Stat(target); err != nil {
				return fmt.Errorf("%q: %v", path, err)
			}
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file", path)
		}
	}
	return nil
}

// Write appends recs to the file with one fsync, then prints them to stderr.
//
// The file comes first and its error is the one returned: it is the copy an
// operator configured on purpose. A directory that does not exist is an error
// rather than something to create — a missing mount point would otherwise turn
// "the records go to the archive volume" into "the records go to the root
// disk, beside the database".
func (s Sink) Write(recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("auditcheckpoint: encode record: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	var fileErr error
	if s.File != "" {
		fileErr = appendDurably(s.File, buf.Bytes())
	}
	if s.Stderr != nil {
		_, _ = s.Stderr.Write(buf.Bytes())
	}
	return fileErr
}

// appendDurably appends b to path and fsyncs it, and the directory when the
// file is new.
func appendDurably(path string, b []byte) error {
	if err := CheckFile(path); err != nil {
		return fmt.Errorf("auditcheckpoint: %w", err)
	}
	_, statErr := os.Stat(path)
	created := os.IsNotExist(statErr)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("auditcheckpoint: open %s: %w", path, err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("auditcheckpoint: append to %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("auditcheckpoint: fsync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("auditcheckpoint: close %s: %w", path, err)
	}
	if created {
		if d, err := os.Open(filepath.Dir(path)); err == nil {
			_ = d.Sync()
			d.Close() //nolint:errcheck
		}
	}
	return nil
}

// Located is a record and the line it was read from.
type Located struct {
	Record
	Line int
}

// ParseResult is what Parse found.
type ParseResult struct {
	Records []Located
	// Malformed counts lines that name a checkpoint but do not decode — a
	// truncated write, or an edit.
	Malformed []int
	// Oversized lists lines longer than a record can be, which were skipped
	// unread: in a log export they are somebody else's lines; in the
	// checkpoint file itself, an edit.
	Oversized []int
}

// envelopeFields are the fields log shippers wrap a line in: journald's JSON
// output, Docker's json-file driver, and the common structured-log names. A
// record found inside one is read as if the line were bare.
var envelopeFields = []string{"MESSAGE", "log", "message", "msg"}

// maxLine bounds one line of input.
const maxLine = 1 << 20

// Parse reads records from r: the checkpoint file itself, or a log export with
// a record somewhere on some of its lines — prefixed by a timestamp, or wrapped
// in a shipper's JSON envelope. Lines without a record are skipped silently;
// lines that name one and do not decode are reported, and so are lines too
// long to be one, which are skipped rather than allowed to end the read — one
// oversized line appended to the file must not blind verification to every
// record after it.
func Parse(r io.Reader) (ParseResult, error) {
	var res ParseResult
	br := bufio.NewReaderSize(r, 64*1024)
	for line := 1; ; line++ {
		text, oversized, err := readLine(br)
		if err != nil && err != io.EOF {
			return res, fmt.Errorf("auditcheckpoint: read: %w", err)
		}
		switch {
		case oversized:
			res.Oversized = append(res.Oversized, line)
		case bytes.Contains(text, []byte(Kind)):
			if rec, ok := decodeLine(text); ok {
				res.Records = append(res.Records, Located{Record: rec, Line: line})
			} else {
				res.Malformed = append(res.Malformed, line)
			}
		}
		if err == io.EOF {
			return res, nil
		}
	}
}

// readLine reads one line without its terminator. A line past maxLine is
// consumed to its end and reported oversized, without being kept.
func readLine(br *bufio.Reader) (line []byte, oversized bool, err error) {
	for {
		frag, err := br.ReadSlice('\n')
		if !oversized {
			if len(line)+len(frag) > maxLine {
				oversized, line = true, nil
			} else {
				line = append(line, frag...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return bytes.TrimRight(line, "\r\n"), oversized, err
	}
}

// decodeLine finds a record on one line.
func decodeLine(text []byte) (Record, bool) {
	i := bytes.IndexByte(text, '{')
	if i < 0 {
		return Record{}, false
	}
	obj := bytes.TrimSpace(text[i:])
	var rec Record
	if err := json.Unmarshal(obj, &rec); err == nil && rec.Kind == Kind {
		return rec, true
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(obj, &env); err != nil {
		return Record{}, false
	}
	for _, f := range envelopeFields {
		raw, ok := env[f]
		if !ok {
			continue
		}
		var inner string
		if err := json.Unmarshal(raw, &inner); err != nil {
			continue
		}
		if rec, ok := decodeLine([]byte(inner)); ok {
			return rec, true
		}
	}
	return Record{}, false
}

// ReadFile parses the records in path.
func ReadFile(path string) (ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ParseResult{}, err
	}
	defer f.Close()
	return Parse(f)
}

// ByPath groups records by the database path they name, each group in the
// order the records were written.
func ByPath(recs []Located) map[string][]Located {
	out := map[string][]Located{}
	for _, r := range recs {
		key := ValidPath(r.Path)
		out[key] = append(out[key], r)
	}
	for k := range out {
		sortRecords(out[k])
	}
	return out
}

// sortRecords orders records by time, then by where they were read.
func sortRecords(recs []Located) {
	sort.SliceStable(recs, func(i, j int) bool {
		ai, aj := recs[i].At(), recs[j].At()
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return recs[i].Line < recs[j].Line
	})
}
