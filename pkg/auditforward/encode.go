package auditforward

// encode.go turns one audit row into what one sink sends for it.
//
// The record itself is pkg/auditexport's — the JSON object `cloop audit-log
// export --format jsonl` writes, or its CEF line — with the chain it came from
// (source, dir) and the hub that sent it, so a receiver of a stream mixing
// every chain can verify each on its own. Nothing here re-serialises a payload
// or redacts one: a payload was redacted when its row was appended, and the
// receiver can only recompute row_hash over the bytes the chain holds.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/auditexport"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// message is one row, encoded for a sink.
type message struct {
	// id and rowHash identify the row the message carries.
	id      int64
	rowHash string
	// data is the encoded message: an RFC 5424 message (unframed), an NDJSON
	// line or a HEC event (without its newline), or a file line.
	data []byte
	// truncated reports that the payload was left out to fit the sink's
	// message size.
	truncated bool
}

// encoder encodes rows for one sink.
type encoder struct {
	cfg     config.AuditForwardSink
	hub     string
	version string
}

// minPayloadExcerpt is the shortest excerpt a cut payload keeps, however
// little room a message size leaves.
const minPayloadExcerpt = 64

// encode returns the message for ev from chain ch.
func (e *encoder) encode(ev statedb.AuditEvent, ch Chain) (message, error) {
	m := message{id: ev.ID, rowHash: ev.RowHash}
	body, err := e.body(ev, ch, 0)
	if err != nil {
		return message{}, err
	}
	switch strings.ToLower(e.cfg.Type) {
	case config.AuditSinkSyslog:
		header := e.syslogHeader(ev)
		budget := e.cfg.EffectiveMaxMessageBytes()
		// Leave the payload out — the record says so, with its length and
		// digest — rather than let a collector cut the message somewhere in
		// the middle of the JSON. The excerpt is cut in raw bytes and then
		// escaped, which can lengthen it, so the encoded message is measured
		// and cut again until it fits; every byte less of excerpt is at least
		// a byte less of message, so this converges.
		limit := len(ev.Payload)
		for i := 0; i < 8 && len(header)+len(body) > budget && limit > minPayloadExcerpt; i++ {
			limit -= len(header) + len(body) - budget
			if i == 0 {
				// The record that says the payload was cut is longer than
				// one that does not; leave room for it the first time.
				limit -= 256
			}
			limit = max(limit, minPayloadExcerpt)
			cut, err := e.body(ev, ch, limit)
			if err != nil {
				break
			}
			body, m.truncated = cut, true
		}
		m.data = append([]byte(header), body...)
	case config.AuditSinkHTTPS:
		if strings.EqualFold(e.cfg.Variant, config.AuditVariantSplunkHEC) {
			env, err := e.hecEvent(ev, body)
			if err != nil {
				return message{}, err
			}
			m.data = env
		} else {
			m.data = body
		}
	default:
		m.data = body
	}
	return m, nil
}

// shrink re-encodes ev with its payload cut to fit, for a receiver that
// refused the whole row as too large.
func (e *encoder) shrink(ev statedb.AuditEvent, ch Chain) (message, error) {
	m, err := e.encode(ev, ch)
	if err != nil || len(ev.Payload) <= minPayloadExcerpt*16 {
		return m, err
	}
	body, err := e.body(ev, ch, minPayloadExcerpt*16)
	if err != nil {
		return message{}, err
	}
	switch {
	case strings.EqualFold(e.cfg.Type, config.AuditSinkSyslog):
		m.data = append([]byte(e.syslogHeader(ev)), body...)
	case strings.EqualFold(e.cfg.Variant, config.AuditVariantSplunkHEC):
		if m.data, err = e.hecEvent(ev, body); err != nil {
			return message{}, err
		}
	default:
		m.data = body
	}
	m.truncated = true
	return m, nil
}

// body is the record for ev in the sink's format, with the payload cut to
// limit bytes when limit is positive and the payload longer.
func (e *encoder) body(ev statedb.AuditEvent, ch Chain, limit int) ([]byte, error) {
	opts := auditexport.Options{
		ProductVersion: e.version,
		Provenance:     &auditexport.Provenance{Source: ch.Source, Dir: ch.Dir, Hub: e.hub},
	}
	if e.cfg.EffectiveFormat() == config.AuditFormatCEF {
		opts.Format = auditexport.FormatCEF
		if limit > 0 {
			opts.MaxPayloadBytes = limit
		}
	} else {
		opts.Format = auditexport.FormatJSONL
		opts.JSONPayloadLimit = limit
	}
	var buf bytes.Buffer
	if err := auditexport.Write(&buf, []auditexport.Event{ev}, opts); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// syslogHeader is the RFC 5424 header and the space before MSG:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA SP
//
// TIMESTAMP is the row's, to the microsecond RFC 5424 allows; MSGID the event
// type, so a collector can route on it without parsing the body. There is no
// structured data: an SD-ID needs an IANA enterprise number, and everything
// it would carry is in the body. MSG carries no BOM, which RFC 5424 permits
// (MSG-ANY) and which keeps a JSON or CEF parser from tripping on one.
func (e *encoder) syslogHeader(ev statedb.AuditEvent) string {
	pri := e.cfg.EffectiveFacility()*8 + syslogSeverity(ev)
	ts := ev.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	msgid := sanitizeToken(ev.EventType, 32)
	return "<" + strconv.Itoa(pri) + ">1 " + ts + " " + sanitizeToken(e.hub, 255) + " " +
		sanitizeToken(e.cfg.EffectiveAppName(), 48) + " - " + msgid + " - "
}

// syslogSeverity maps auditexport's CEF ranking onto RFC 5424 severities:
// what the CEF header calls 8 and above (a denial) is a warning, 6 and 7 (a
// credential or an executor) a notice, the rest informational.
func syslogSeverity(ev statedb.AuditEvent) int {
	switch sev := auditexport.Severity(ev); {
	case sev >= 8:
		return 4
	case sev >= 6:
		return 5
	}
	return 6
}

// hecEvent wraps a record in the envelope a Splunk HTTP Event Collector
// takes: one JSON object per event, the record under "event".
func (e *encoder) hecEvent(ev statedb.AuditEvent, record []byte) ([]byte, error) {
	source := e.cfg.SplunkSource
	if source == "" {
		source = "cloop"
	}
	sourceType := e.cfg.SplunkSourceType
	if sourceType == "" {
		sourceType = "cloop:audit"
	}
	env := struct {
		Time       json.Number     `json:"time"`
		Host       string          `json:"host,omitempty"`
		Source     string          `json:"source"`
		SourceType string          `json:"sourcetype"`
		Index      string          `json:"index,omitempty"`
		Event      json.RawMessage `json:"event"`
	}{
		Time:       json.Number(fmt.Sprintf("%d.%03d", ev.Timestamp.Unix(), ev.Timestamp.Nanosecond()/1e6)),
		Host:       e.hub,
		Source:     source,
		SourceType: sourceType,
		Index:      e.cfg.SplunkIndex,
		Event:      json.RawMessage(record),
	}
	return json.Marshal(env)
}

// sanitizeToken renders s as an RFC 5424 PRINTUSASCII field of at most max
// characters: anything outside 33-126 becomes '_', and an empty result is the
// NILVALUE "-".
func sanitizeToken(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if c < 33 || c > 126 {
			c = '_'
		}
		b.WriteByte(c)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
