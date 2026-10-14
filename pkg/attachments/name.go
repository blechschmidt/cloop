package attachments

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// CleanName turns the path a file had in an outbox, or the name it was given
// on a command line, into the name it is attached under: slash-separated, no
// empty, "." or ".." components, no control characters, valid UTF-8, at most
// statedb.MaxAttachmentNameBytes bytes. The name is a label — it never names a
// file on disk — but it is shown in the dashboard, in a terminal and in a
// download's Content-Disposition, so it is kept printable.
//
// Format characters go too: a right-to-left override (U+202E) placed before
// "txt.exe" is how an executable is made to read as a text file.
//
// A name over the limit keeps its end, where the file name and its extension
// are.
func CleanName(name string) string {
	name = strings.ToValidUTF8(strings.ReplaceAll(name, "\\", "/"), "\uFFFD")
	var parts []string
	for _, p := range strings.Split(name, "/") {
		p = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return -1
			}
			return r
		}, p)
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		parts = append(parts, p)
	}
	out := strings.Join(parts, "/")
	if out == "" {
		return "file"
	}
	if n := statedb.MaxAttachmentNameBytes; len(out) > n {
		cut := len(out) - n
		for cut < len(out) && !utf8.RuneStart(out[cut]) {
			cut++
		}
		out = strings.TrimLeft(out[cut:], "/")
	}
	return out
}

// BaseName is the last component of an attachment's name: what a download is
// saved as.
func BaseName(name string) string {
	if b := path.Base(CleanName(name)); b != "." && b != "/" {
		return b
	}
	return "file"
}
