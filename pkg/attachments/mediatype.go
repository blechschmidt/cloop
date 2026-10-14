package attachments

// mediatype.go decides what an attached file is, and — the part with a
// security consequence — which files the hub may hand a browser to display
// rather than to save.
//
// An attachment is written by a run, and a run is model-authored code. The
// hub serves it from its own origin, the origin the dashboard's session lives
// on, so a file a browser renders as a document is a file that can script the
// dashboard: an .html report, an .svg chart, an .xhtml export. None of those
// is ever served to be displayed. Only images a browser decodes as pixels and
// text it shows as text are, and only when the bytes say the same thing as
// the name — a "chart.png" that is HTML inside is a download.

import (
	"mime"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"
)

// byExtension maps the extensions runs commonly produce to their types. It is
// consulted before content sniffing because a sniffer cannot tell CSV from
// text, or JSON from text, and the name usually can.
var byExtension = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
	".webp": "image/webp", ".svg": "image/svg+xml", ".bmp": "image/bmp", ".ico": "image/x-icon",
	".pdf": "application/pdf",
	".txt": "text/plain", ".log": "text/plain", ".out": "text/plain", ".diff": "text/x-diff",
	".patch": "text/x-diff", ".md": "text/markdown", ".csv": "text/csv",
	".tsv": "text/tab-separated-values", ".json": "application/json", ".jsonl": "application/jsonl",
	".ndjson": "application/jsonl", ".yaml": "application/yaml", ".yml": "application/yaml",
	".toml": "application/toml", ".xml": "application/xml", ".html": "text/html",
	".htm": "text/html", ".ipynb": "application/x-ipynb+json",
	".zip": "application/zip", ".gz": "application/gzip", ".tgz": "application/gzip",
	".tar": "application/x-tar", ".mp4": "video/mp4", ".webm": "video/webm",
	".mp3": "audio/mpeg", ".wav": "audio/wav",
}

// textTypes are the recorded types whose files the hub may display as plain
// text, provided the bytes are text.
var textTypes = map[string]bool{
	"text/plain": true, "text/x-diff": true, "text/markdown": true, "text/csv": true,
	"text/tab-separated-values": true, "application/json": true, "application/jsonl": true,
	"application/yaml": true, "application/toml": true, "application/x-ipynb+json": true,
}

// inlineImages are the image types a browser decodes as pixels only. SVG is
// not one: it is a document that may carry script.
var inlineImages = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true,
}

// DetectType returns the media type recorded for a file named name whose
// content starts with head.
func DetectType(name string, head []byte) string {
	sniffed := baseType(http.DetectContentType(head))
	ext := strings.ToLower(path.Ext(name))
	claimed := byExtension[ext]
	switch {
	case claimed == "":
		if sniffed == "text/html" || sniffed == "text/xml" {
			// Whatever a sniffer took for markup is recorded as nothing in
			// particular: the name did not say so.
			return "application/octet-stream"
		}
		if sniffed == "text/plain" && !looksLikeText(head) {
			return "application/octet-stream"
		}
		return sniffed
	case strings.HasPrefix(claimed, "image/") && claimed != "image/svg+xml":
		// An image is what its bytes are. A name that claims one the content
		// is not gets nothing of the claim.
		if strings.HasPrefix(sniffed, "image/") {
			return sniffed
		}
		return "application/octet-stream"
	case textTypes[claimed] && !looksLikeText(head):
		return "application/octet-stream"
	}
	return claimed
}

// TypeByName is the type a file's name claims, for an attachment whose bytes
// cannot be looked at: one a remote run left on its executor. Only a label —
// nothing is ever served on its strength.
func TypeByName(name string) string {
	if t := byExtension[strings.ToLower(path.Ext(name))]; t != "" {
		return t
	}
	return "application/octet-stream"
}

// InlineType returns the Content-Type to display an attachment under, and
// whether it may be displayed at all, from its recorded type and the first
// bytes of what is in the store now. The bytes are looked at again because
// the store is in a workload's reach: a recorded type is only a claim.
func InlineType(recorded string, head []byte) (string, bool) {
	recorded = baseType(recorded)
	if inlineImages[recorded] {
		if baseType(http.DetectContentType(head)) == recorded {
			return recorded, true
		}
		return "", false
	}
	if textTypes[recorded] && looksLikeText(head) {
		return "text/plain; charset=utf-8", true
	}
	return "", false
}

// Previewable reports whether the dashboard should offer to show a file of
// the recorded type, before it fetches a byte of it. InlineType has the last
// word.
func Previewable(recorded string) bool {
	recorded = baseType(recorded)
	return inlineImages[recorded] || textTypes[recorded]
}

// looksLikeText reports whether head reads as UTF-8 text: no NUL, valid
// UTF-8 but for a sequence the cut at the end of head may have split.
func looksLikeText(head []byte) bool {
	if len(head) == 0 {
		return true
	}
	for _, c := range head {
		if c == 0 {
			return false
		}
	}
	if utf8.Valid(head) {
		return true
	}
	// Trim at most one partial rune off the end before deciding.
	for i := 1; i < utf8.UTFMax && i < len(head); i++ {
		if utf8.Valid(head[:len(head)-i]) {
			return true
		}
	}
	return false
}

// baseType drops parameters — "text/plain; charset=utf-8" is text/plain.
func baseType(t string) string {
	if mt, _, err := mime.ParseMediaType(t); err == nil {
		return mt
	}
	t, _, _ = strings.Cut(t, ";")
	return strings.ToLower(strings.TrimSpace(t))
}
