package jsonbody

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type payload struct {
	Title string `json:"title"`
}

func TestDecode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ct       string
		body     string
		chunked  bool
		opts     Options
		wantOK   bool
		wantCode int
		wantErr  string // apierror code
		title    string
	}{
		{name: "json", ct: "application/json", body: `{"title":"a"}`, wantOK: true, title: "a"},
		{name: "json with charset", ct: "application/json; charset=utf-8", body: `{"title":"b"}`, wantOK: true, title: "b"},
		// The forged-request shapes: what a form or a no-cors fetch can send.
		{name: "text/plain", ct: "text/plain", body: `{"title":"x"}`, wantCode: 415, wantErr: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "text/plain from fetch", ct: "text/plain;charset=UTF-8", body: `{"title":"x"}`, wantCode: 415, wantErr: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "urlencoded", ct: "application/x-www-form-urlencoded", body: `{"title":"x"}=`, wantCode: 415, wantErr: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "multipart", ct: "multipart/form-data; boundary=b", body: "--b--", wantCode: 415, wantErr: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "no content type with a body", body: `{"title":"x"}`, wantCode: 415, wantErr: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "text/plain refused even when empty", ct: "text/plain", body: "", opts: Options{Optional: true}, wantCode: 415, wantErr: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "required and empty", ct: "application/json", body: "", wantCode: 400, wantErr: "INVALID_INPUT"},
		{name: "required, empty, no type", body: "", wantCode: 400, wantErr: "INVALID_INPUT"},
		{name: "optional and empty", body: "", opts: Options{Optional: true}, wantOK: true},
		{name: "optional, whitespace", ct: "application/json", body: " \n", opts: Options{Optional: true}, wantOK: true},
		{name: "optional, chunked empty", ct: "application/json", body: "", chunked: true, opts: Options{Optional: true}, wantOK: true},
		{name: "optional still decodes", ct: "application/json", body: `{"title":"c"}`, opts: Options{Optional: true}, wantOK: true, title: "c"},
		{name: "malformed", ct: "application/json", body: `{"title":`, wantCode: 400, wantErr: "INVALID_INPUT"},
		{name: "truncated optional is not empty", ct: "application/json", body: `{"title":`, opts: Options{Optional: true}, wantCode: 400, wantErr: "INVALID_INPUT"},
		{name: "strict refuses unknown fields", ct: "application/json", body: `{"title":"a","x":1}`, opts: Options{Strict: true}, wantCode: 400, wantErr: "INVALID_INPUT"},
		{name: "lenient ignores unknown fields", ct: "application/json", body: `{"title":"a","x":1}`, wantOK: true, title: "a"},
		{name: "too large", ct: "application/json", body: `{"title":"` + strings.Repeat("a", 100) + `"}`, opts: Options{Limit: 32}, wantCode: 413, wantErr: "PAYLOAD_TOO_LARGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader = strings.NewReader(tc.body)
			if tc.chunked {
				body = io.MultiReader(strings.NewReader(tc.body)) // hides the length
			}
			r := httptest.NewRequest(http.MethodPost, "/api/x", body)
			if tc.chunked {
				r.ContentLength = -1
			}
			if tc.ct != "" {
				r.Header.Set("Content-Type", tc.ct)
			}
			rec := httptest.NewRecorder()
			var p payload
			ok := Decode(rec, r, &p, tc.opts)
			if ok != tc.wantOK {
				t.Fatalf("Decode = %v, want %v (status %d, body %s)", ok, tc.wantOK, rec.Code, rec.Body.String())
			}
			if ok {
				if p.Title != tc.title {
					t.Errorf("title = %q, want %q", p.Title, tc.title)
				}
				return
			}
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			var env struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Error.Code != tc.wantErr {
				t.Errorf("body = %s, want code %s", rec.Body.String(), tc.wantErr)
			}
			if tc.wantCode == 415 && !strings.Contains(env.Error.Message, "application/json") {
				t.Errorf("a 415 that does not say what is taken: %q", env.Error.Message)
			}
		})
	}
}

func TestMediaTypeMessageNamesWhatWasSent(t *testing.T) {
	if m := MediaTypeMessage("text/plain", "multipart/form-data"); !strings.Contains(m, `"text/plain"`) ||
		!strings.Contains(m, "multipart/form-data") {
		t.Errorf("message = %q", m)
	}
	if m := MediaTypeMessage(""); !strings.Contains(m, "no Content-Type") {
		t.Errorf("message = %q", m)
	}
}
