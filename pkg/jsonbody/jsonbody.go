// Package jsonbody is how a cloop HTTP handler reads a JSON request body —
// the only way, in pkg/ui and pkg/apiserver alike (Task 20394).
//
// Before it, every handler decoded r.Body itself, and every one of them
// decoded it as JSON whatever its Content-Type said. That turns out to be the
// detail a cross-site request forgery needs: a form with enctype=text/plain,
// or fetch() in no-cors mode, sends a body a page on another origin chose —
// `{"title":"…","x":"=…"}` is a perfectly good text/plain form field — without
// asking the server first. A browser asks first (a CORS preflight, which the
// hub never grants) only for a content type outside the three a form can
// produce. So an endpoint that accepts nothing but application/json cannot be
// reached by a page elsewhere at all, whatever else goes wrong.
//
// What Decode does, in order:
//
//   - A Content-Type that is not application/json is refused with 415 before
//     the body is read.
//   - The body is read up to the limit; past it, 413.
//   - An empty body is the handler's defaults when it said the body is
//     optional, and 400 otherwise. A body is not empty here just because
//     Content-Length said so: a chunked request has none.
//   - A body with no Content-Type at all is refused with 415. A browser can
//     send one (fetch with a Blob of no type), and it would otherwise be the
//     way around the first rule.
//   - Anything that does not decode into dst is 400.
//
// Every refusal is written here, as a pkg/apierror body, so a handler that
// sees false has nothing left to say.
package jsonbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/sameorigin"
)

// DefaultLimit is the cap when Options.Limit is zero: 10 MiB, generous enough
// for a chat transcript or a bulk task edit.
const DefaultLimit int64 = 10 << 20

// Options describes how one handler reads its body. The zero value is a
// required body of at most DefaultLimit.
type Options struct {
	// Limit caps the body in bytes; zero is DefaultLimit.
	Limit int64
	// Optional lets the body be empty, which leaves dst untouched — the
	// handler's defaults. A non-empty body must still be JSON.
	Optional bool
	// Strict refuses fields dst does not declare.
	Strict bool
	// MediaTypes are JSON media types the body may carry besides
	// application/json. A browser sends its Content-Security-Policy reports
	// as application/csp-report or application/reports+json, which a form on
	// another page cannot produce either (Task 20408). The body still decodes
	// as JSON.
	MediaTypes []string
}

// Decode reads r's JSON body into dst. It reports whether the handler may
// continue; when it may not, the response has been written.
func Decode(w http.ResponseWriter, r *http.Request, dst any, o Options) bool {
	data, refusal := Read(w, r, o)
	if refusal != nil {
		apierror.WriteError(w, refusal)
		return false
	}
	if len(data) == 0 {
		return true // optional, and empty
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if o.Strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "invalid JSON body: "+err.Error()))
		return false
	}
	return true
}

// Read applies Decode's rules — the media type, the size limit, a required
// body — and returns the body undecoded, or the refusal Decode would have
// written. An optional body that is empty is returned as nil.
//
// For a handler that answers its refusals in a dialect of its own: the SCIM
// routes (Task 20415) speak RFC 7644's error document to identity providers,
// and take application/scim+json, but read their bodies here like every other
// handler, so the rules a cross-site form cannot satisfy hold for them too.
func Read(w http.ResponseWriter, r *http.Request, o Options) ([]byte, *apierror.APIError) {
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct != "" && !sameorigin.IsJSON(ct) && !IsMediaType(ct, o.MediaTypes...) {
		return nil, apierror.New(apierror.CodeUnsupportedMediaType, MediaTypeMessage(ct, o.MediaTypes...))
	}
	limit := o.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	var data []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		data, err = io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return nil, apierror.Newf(apierror.CodePayloadTooLarge,
					"request body too large: the limit is %d bytes", limit)
			}
			return nil, apierror.New(apierror.CodeInvalidInput, "could not read the request body: "+err.Error())
		}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if o.Optional {
			return nil, nil
		}
		return nil, apierror.New(apierror.CodeInvalidInput,
			"a JSON request body is required (Content-Type: application/json)")
	}
	if ct == "" {
		return nil, apierror.New(apierror.CodeUnsupportedMediaType, MediaTypeMessage("", o.MediaTypes...))
	}
	return data, nil
}

// MediaTypeMessage is the sentence a 415 carries: what was sent, what is
// taken, and why the hub is strict about it. Exported so the middleware that
// refuses a form body before any handler runs says the same thing.
func MediaTypeMessage(sent string, also ...string) string {
	got := "no Content-Type"
	if sent != "" {
		got = fmt.Sprintf("Content-Type %q", sent)
	}
	accepted := "Content-Type: application/json"
	if len(also) > 0 {
		accepted += " (or " + strings.Join(also, ", ") + ")"
	}
	return fmt.Sprintf("this endpoint takes a body only as %s, and the request sent %s. "+
		"A page on another site can send form data and text/plain without asking first, "+
		"so the hub accepts neither.", accepted, got)
}

// IsMediaType reports whether contentType names one of types, parameters
// aside and case insensitively.
func IsMediaType(contentType string, types ...string) bool {
	mt, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
	if err != nil {
		return false
	}
	for _, t := range types {
		if strings.EqualFold(mt, t) {
			return true
		}
	}
	return false
}
