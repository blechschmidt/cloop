// Package scim is the wire protocol of SCIM 2.0 (RFC 7643 and RFC 7644) as
// the hub speaks it to an identity provider (Task 20415): the resource
// documents, the filter and attribute-path grammars, PATCH, list responses,
// errors and the three discovery documents.
//
// It holds no policy and touches no storage. What a provisioned account means
// to the hub — which identity it is, what deactivating it severs, what a group
// grants — is pkg/provision's; this package only answers "what did the
// identity provider ask for", and answers it the same way for every provider.
// Like pkg/oidcauth it uses nothing beyond the standard library, so the parser
// an attacker's bytes reach first can be audited by reading it.
//
// # The providers this was written against
//
// RFC 7644 leaves enough unsaid that the two providers that matter here speak
// noticeably different dialects of it, and both are accepted:
//
//   - Microsoft Entra ID sends PATCH operations capitalised ("Replace"),
//     booleans as the strings "True" and "False", group member removals as
//     `{"op":"Remove","path":"members","value":[{"value":"…"}]}` — which by
//     the letter of RFC 7644 would remove every member — and, with its SCIM
//     2.0 compliance flag, path-less operations whose value object's keys are
//     themselves attribute paths (`"name.givenName"`). It creates groups under
//     a schema URN of its own, replaces `emails[type eq "work"].value` on a user
//     who has no work address, and its validator invents attributes and
//     expects them back verbatim.
//   - Okta deactivates with `{"op":"replace","value":{"active":false}}`, or on
//     older integrations with a PUT of the whole user; renames a group with a
//     replace whose value repeats the group's id; and sends a password, which
//     is never stored.
//
// Where the two disagree with the RFC, the reading chosen is the one that does
// what the provider meant, and the test corpus in pkg/ui replays both.
package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Schema and message URNs.
const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"

	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"

	// SchemaEntraGroup is the schema URN Microsoft Entra ID's provisioning
	// service attached to every group it created before its SCIM 2.0
	// compliance fixes. It names no attribute anybody defined, and is
	// accepted and dropped.
	SchemaEntraGroup = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
)

// MediaType is SCIM's JSON media type. Responses carry it; requests may send
// it or application/json.
const MediaType = "application/scim+json"

// Error types (RFC 7644 §3.12, "scimType").
const (
	ErrInvalidFilter = "invalidFilter"
	ErrTooMany       = "tooMany"
	ErrUniqueness    = "uniqueness"
	ErrMutability    = "mutability"
	ErrInvalidSyntax = "invalidSyntax"
	ErrInvalidPath   = "invalidPath"
	ErrNoTarget      = "noTarget"
	ErrInvalidValue  = "invalidValue"
	ErrInvalidVers   = "invalidVers"
)

// Error is a SCIM error response: an HTTP status, the scimType RFC 7644 names
// for it when there is one, and a sentence for whoever reads the provisioning
// log. It is also the error every function in this package returns for input
// it refuses, so a caller can hand it to the client as it is.
type Error struct {
	Status int
	Type   string
	Detail string
}

func (e *Error) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("scim %d %s: %s", e.Status, e.Type, e.Detail)
	}
	return fmt.Sprintf("scim %d: %s", e.Status, e.Detail)
}

// MarshalJSON renders the RFC 7644 §3.12 error document. status is a string
// there, not a number.
func (e *Error) MarshalJSON() ([]byte, error) {
	doc := struct {
		Schemas []string `json:"schemas"`
		Status  string   `json:"status"`
		Type    string   `json:"scimType,omitempty"`
		Detail  string   `json:"detail,omitempty"`
	}{[]string{SchemaError}, strconv.Itoa(e.Status), e.Type, e.Detail}
	return json.Marshal(doc)
}

// Errorf builds an Error.
func Errorf(status int, scimType, format string, args ...any) *Error {
	return &Error{Status: status, Type: scimType, Detail: fmt.Sprintf(format, args...)}
}

// BadRequest is a 400 of the given type.
func BadRequest(scimType, format string, args ...any) *Error {
	return Errorf(http.StatusBadRequest, scimType, format, args...)
}

// NotFound is the 404 for a resource id that does not resolve.
func NotFound(kind, id string) *Error {
	return Errorf(http.StatusNotFound, "", "%s %q not found", kind, id)
}

// Conflict is the 409 uniqueness error.
func Conflict(format string, args ...any) *Error {
	return Errorf(http.StatusConflict, ErrUniqueness, format, args...)
}

// AsError returns err as a SCIM error, wrapping anything else in a 500 whose
// detail says nothing of the internals.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	if se, ok := err.(*Error); ok {
		return se
	}
	return &Error{Status: http.StatusInternalServerError, Detail: "the hub could not complete this request; " +
		"its log and audit trail say why"}
}

// WriteError writes err as a SCIM error response.
func WriteError(w http.ResponseWriter, err error) {
	se := AsError(err)
	WriteJSON(w, se.Status, se)
}

// WriteJSON writes v with SCIM's media type.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", MediaType+"; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// ETag renders a resource version the way meta.version and the ETag header
// carry it: a weak validator, since the representation is not byte-stable.
func ETag(version int64) string {
	return `W/"` + strconv.FormatInt(version, 10) + `"`
}

// MatchesETag reports whether an If-Match header value admits version. An
// empty header, and "*", admit any version. A list is accepted, weak or strong.
func MatchesETag(header string, version int64) bool {
	header = strings.TrimSpace(header)
	if header == "" || header == "*" {
		return true
	}
	want := strconv.FormatInt(version, 10)
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(part)
		tag = strings.TrimPrefix(tag, "W/")
		tag = strings.Trim(tag, `"`)
		if tag == want {
			return true
		}
	}
	return false
}
