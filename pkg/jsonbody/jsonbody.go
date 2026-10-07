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
}

// Decode reads r's JSON body into dst. It reports whether the handler may
// continue; when it may not, the response has been written.
func Decode(w http.ResponseWriter, r *http.Request, dst any, o Options) bool {
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct != "" && !sameorigin.IsJSON(ct) {
		writeMediaType(w, ct)
		return false
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
				apierror.WriteError(w, apierror.Newf(apierror.CodePayloadTooLarge,
					"request body too large: the limit is %d bytes", limit))
				return false
			}
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
				"could not read the request body: "+err.Error()))
			return false
		}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if o.Optional {
			return true
		}
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"a JSON request body is required (Content-Type: application/json)"))
		return false
	}
	if ct == "" {
		writeMediaType(w, "")
		return false
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

func writeMediaType(w http.ResponseWriter, sent string) {
	apierror.WriteError(w, apierror.New(apierror.CodeUnsupportedMediaType, MediaTypeMessage(sent)))
}
