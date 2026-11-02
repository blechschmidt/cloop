package hubdoctor

// Knowledge embeddings (Task 20471): whether the hub sends its knowledge to an
// embedding endpoint, and where.
//
// Semantic retrieval is off unless an administrator turns it on, because on
// it sends the text of every chunk of every synced source, and every search
// query, to the endpoint knowledge.embeddings names. Whoever reads the doctor's
// report — an operator, a security review, the Hub health panel — must be able
// to see that it does and to whom, so an enabled section is always a finding
// that names the endpoint. Beside it: a section refused at load, an endpoint
// reached in plaintext beyond loopback, a key the secret store cannot provide,
// and the syncs whose last embedding pass failed.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/knowledge/embed"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxListedEmbeddingWarnings bounds the sources a finding quotes a warning of.
const maxListedEmbeddingWarnings = 5

func checkKnowledgeEmbeddings(dir string, cfg *config.Config, add addFn) {
	const check, title = "knowledge.embeddings", "Knowledge embeddings"
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff != check {
			continue
		}
		add(Finding{
			Check: check, Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("knowledge.embeddings in %s was %s: no chunk is embedded, and searches rank by "+
				"words alone", r.File, r.Detail),
			Remediation: fmt.Sprintf("Correct the section in %s; it stays off until it loads", r.File),
			Details:     map[string]any{"file": r.File},
		})
		return
	}
	e := cfg.Knowledge.Embeddings
	if !e.Enabled {
		add(Finding{
			Check: check, Title: title, Severity: SeverityPass,
			Message: "off: no chunk text or search query leaves this hub for an embedding endpoint, and searches " +
				"rank by words (BM25)",
		})
		return
	}
	endpoint := e.EndpointDisplay()
	model := strings.TrimSpace(e.Model)
	where := fmt.Sprintf("the text of every chunk of every synced knowledge source, and every search query, is "+
		"sent to %s (%s, model %s, %d dimensions)", endpoint, e.ProviderName(), model, e.Dimensions)
	details := map[string]any{"endpoint": endpoint, "provider": e.ProviderName(), "model": model,
		"dimensions": e.Dimensions}

	if ref := strings.TrimSpace(e.SecretRef); ref != "" {
		if problem := hubCredentialProblem(dir, []string{ref}); problem != "" {
			add(Finding{
				Check: check + ".secret", Title: title, Severity: SeverityFail,
				Message: fmt.Sprintf("on, and its key cannot be presented: %s — every request %s would refuse, "+
					"so nothing is embedded and searches rank by words alone", problem, endpoint),
				Remediation: "Store the endpoint's key as a shared env secret (cloop secret mint <name> --kind env) " +
					"and name it in knowledge.embeddings.secret_ref",
				Details: details,
			})
		}
	}

	coverage := embeddingCoverage(dir, embed.ModelKey(e.ProviderName(), model, e.Dimensions))
	switch {
	case e.PlaintextBeyondLoopback():
		add(Finding{
			Check: check, Title: title, Severity: SeverityWarn,
			Message: "on: " + where + " — over plain http to an address that is not loopback, so the text, the " +
				"queries and the key cross the network unencrypted" + coverage.sentence(),
			Remediation: "Serve the endpoint over https, or reach it over loopback (a sidecar, an SSH tunnel)",
			Details:     details,
		})
	default:
		add(Finding{
			Check: check, Title: title, Severity: SeverityPass,
			Message: "on: " + where + coverage.sentence(),
			Details: details,
		})
	}
	if len(coverage.warnings) > 0 {
		quoted := coverage.warnings
		if len(quoted) > maxListedEmbeddingWarnings {
			quoted = quoted[:maxListedEmbeddingWarnings]
		}
		add(Finding{
			Check: check + ".sync", Title: title, Severity: SeverityWarn,
			Message: fmt.Sprintf("the last sync of %d knowledge source(s) could not embed their chunks: %s",
				len(coverage.warnings), strings.Join(quoted, "; ")),
			Remediation: "Check the endpoint is reachable and accepts the key and the model; each source's next " +
				"sync embeds what is waiting, and searches find it by its words until then",
			Details: map[string]any{"endpoint": endpoint, "sources": len(coverage.warnings)},
		})
	}
}

// embeddingState is what the control plane says about the vectors of a model.
type embeddingState struct {
	read            bool
	chunks, vectors int
	warnings        []string
}

// sentence renders the coverage for a finding's message, or nothing when the
// database could not be read.
func (s embeddingState) sentence() string {
	if !s.read {
		return ""
	}
	return fmt.Sprintf("; %d of the %d chunks the enabled sources hold have a vector of this model", s.vectors, s.chunks)
}

// embeddingCoverage reads how many chunks of the enabled sources have a vector
// of model, and the warnings their last syncs recorded. A hub with no control
// plane yet has nothing to read, and no database is created for it.
func embeddingCoverage(dir, model string) embeddingState {
	var out embeddingState
	if _, err := os.Stat(state.DBPath(dir)); err != nil {
		return out
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return out
	}
	defer db.Close()
	sources, err := db.ListKnowledgeSources()
	if err != nil {
		return out
	}
	counts, err := db.CountKnowledge()
	if err != nil {
		return out
	}
	vectors, err := db.CountKnowledgeVectors(model)
	if err != nil {
		return out
	}
	out.read = true
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		out.chunks += counts[src.ID].Chunks
		out.vectors += vectors[src.ID]
		var report struct {
			Warning string `json:"warning"`
		}
		if json.Unmarshal([]byte(src.SyncReport), &report) == nil && strings.TrimSpace(report.Warning) != "" {
			out.warnings = append(out.warnings, fmt.Sprintf("%s (%d): %s", src.Name, src.ID, report.Warning))
		}
	}
	sort.Strings(out.warnings)
	return out
}
