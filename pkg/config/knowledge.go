package config

// knowledge: how the hub searches the knowledge its sources hold (Task 20471).
//
// The knowledge index ranks chunks by BM25 over SQLite's full-text index, on
// the hub and nowhere else. knowledge.embeddings adds semantic retrieval on top
// of it: each chunk is turned into a vector by an embedding endpoint, and a
// search ranks the chunks whose vectors are nearest the query's, fused with the
// words' ranking.
//
// Off by default, and on only when an administrator says so, because turning
// it on sends the text of every chunk of every synced source — and every search
// query — to the endpoint named here. The rules enforced at load:
//
//   - The endpoint is named, never defaulted, for an OpenAI-compatible API:
//     the same request shape reaches OpenAI, Azure OpenAI, Ollama and vLLM,
//     and a hub must not send its knowledge to api.openai.com because an
//     operator who meant their own Ollama left the endpoint out. Voyage AI's
//     API has one home, which is its default.
//   - No credential in the file. The endpoint's key lives in the hub's secret
//     store as a shared env secret, named by secret_ref; an endpoint whose
//     query passes something that reads as a credential is refused, as an
//     api_key field is.
//   - Never a cloud metadata service: the client checks the address it dials,
//     after DNS, and an endpoint naming one as an address is refused here.
//
// A section that fails validation is switched off at load and recorded
// (LoadRepair.SwitchedOff), which `cloop hub doctor` reports: off is the
// direction that sends nothing anywhere.

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
)

// Embedding providers: the request shape the endpoint speaks.
const (
	// EmbeddingsOpenAI is an OpenAI-compatible POST {endpoint}/embeddings:
	// OpenAI, Azure OpenAI, Ollama (/v1) and vLLM all answer it.
	EmbeddingsOpenAI = "openai"
	// EmbeddingsVoyage is Voyage AI's POST {endpoint}/embeddings, which
	// takes an input type for documents and queries.
	EmbeddingsVoyage = "voyage"
)

// How the endpoint's key is presented.
const (
	// EmbeddingsAuthBearer sends Authorization: Bearer <key>, as OpenAI,
	// Voyage, vLLM's --api-key and Azure OpenAI's v1 API take it.
	EmbeddingsAuthBearer = "bearer"
	// EmbeddingsAuthAPIKey sends api-key: <key>, as an Azure OpenAI
	// deployment takes it. The default for an Azure OpenAI host.
	EmbeddingsAuthAPIKey = "api-key"
)

// Bounds and defaults for knowledge.embeddings.
const (
	// EmbeddingsVoyageEndpoint is the voyage provider's default endpoint.
	EmbeddingsVoyageEndpoint = "https://api.voyageai.com/v1"

	// EmbeddingsMaxDimensions bounds dimensions: past every embedding model
	// in use, so a typo is caught rather than stored.
	EmbeddingsMaxDimensions = 8192

	// How many chunks one request embeds.
	EmbeddingsBatchSizeDefault = 64
	EmbeddingsBatchSizeUpper   = 512

	// How long one request to the endpoint may take.
	EmbeddingsTimeoutDefault = 30 * time.Second
	EmbeddingsTimeoutLower   = time.Second
	EmbeddingsTimeoutUpper   = 5 * time.Minute

	// How many vectors one search compares its query with at most.
	EmbeddingsMaxCandidatesDefault = 50_000
	EmbeddingsMaxCandidatesLower   = 1_000
	EmbeddingsMaxCandidatesUpper   = 1_000_000

	embeddingsMaxEndpointBytes = 2048
	embeddingsMaxModelBytes    = 256
)

// azureOpenAIHostSuffixes are the hosts an Azure OpenAI deployment answers at,
// which take the key as api-key rather than as a bearer token.
var azureOpenAIHostSuffixes = []string{".openai.azure.com", ".cognitiveservices.azure.com", ".services.ai.azure.com"}

// KnowledgeConfig is the knowledge section. Hub-scope: read by `cloop ui` with
// its per-instance overlay merged in, never from a project's configuration.
type KnowledgeConfig struct {
	// Embeddings adds semantic retrieval to the knowledge index.
	Embeddings EmbeddingsConfig `yaml:"embeddings,omitempty"`
}

// EmbeddingsConfig is knowledge.embeddings.
type EmbeddingsConfig struct {
	// Enabled turns semantic retrieval on. Off unless set: chunk text and
	// search queries are sent to Endpoint once it is.
	Enabled bool `yaml:"enabled,omitempty"`

	// Provider is the request shape: openai (any OpenAI-compatible API —
	// OpenAI, Azure OpenAI, Ollama, vLLM) or voyage.
	Provider string `yaml:"provider,omitempty"`

	// Endpoint is the API's base URL; the hub posts to <endpoint>/embeddings.
	// Required for openai: https://api.openai.com/v1, an Azure OpenAI
	// deployment (https://<resource>.openai.azure.com/openai/deployments/
	// <name>?api-version=2024-10-21), http://localhost:11434/v1 for Ollama,
	// or a vLLM server's /v1. Defaults to EmbeddingsVoyageEndpoint for voyage.
	Endpoint string `yaml:"endpoint,omitempty"`

	// Model is the embedding model, as the endpoint names it
	// ("text-embedding-3-small", "nomic-embed-text", "voyage-3.5").
	Model string `yaml:"model,omitempty"`

	// Dimensions is the length of the model's vectors. A vector of any other
	// length is refused, whatever the endpoint sends.
	Dimensions int `yaml:"dimensions,omitempty"`

	// RequestDimensions asks the endpoint for Dimensions-long vectors — the
	// dimensions parameter of OpenAI's text-embedding-3 models, Voyage's
	// output_dimension — for a model that can shorten its vectors. Off sends
	// no such parameter, which a model that cannot is refused for.
	RequestDimensions bool `yaml:"request_dimensions,omitempty"`

	// SecretRef names the shared env secret holding the endpoint's key:
	// "name", or "name#KEY" for one key of a secret holding several. Empty
	// for an endpoint that takes none, such as a local Ollama.
	SecretRef string `yaml:"secret_ref,omitempty"`

	// Auth is how the key is presented: bearer (Authorization: Bearer), or
	// api-key (the api-key header an Azure OpenAI deployment takes). Empty
	// means api-key for an Azure OpenAI host, bearer for any other.
	Auth string `yaml:"auth,omitempty"`

	// BatchSize is how many chunks one request embeds; 0 means
	// EmbeddingsBatchSizeDefault.
	BatchSize int `yaml:"batch_size,omitempty"`

	// Timeout bounds one request, as a Go duration; empty means
	// EmbeddingsTimeoutDefault. A search waits at most five seconds for its
	// query's vector whatever this says, and then ranks by words alone.
	Timeout string `yaml:"timeout,omitempty"`

	// MaxCandidates bounds how many vectors one search compares its query
	// with; 0 means EmbeddingsMaxCandidatesDefault. A project whose bound
	// sources hold more is searched by meaning over that many of them, and
	// by words over all of them.
	MaxCandidates int `yaml:"max_candidates,omitempty"`

	// APIKey is never read: a key in the configuration is refused, and the
	// section with it. It exists so that one written here is a load error
	// naming secret_ref rather than a field the loader drops in silence.
	APIKey string `yaml:"api_key,omitempty" json:"-"`
}

// ProviderName is the provider, lower-cased.
func (e EmbeddingsConfig) ProviderName() string {
	return strings.ToLower(strings.TrimSpace(e.Provider))
}

// EffectiveEndpoint is the endpoint in force: Endpoint, or the voyage
// provider's default.
func (e EmbeddingsConfig) EffectiveEndpoint() string {
	if v := strings.TrimSpace(e.Endpoint); v != "" {
		return v
	}
	if e.ProviderName() == EmbeddingsVoyage {
		return EmbeddingsVoyageEndpoint
	}
	return ""
}

// EndpointDisplay is the endpoint as messages name it: its scheme, host and
// path, without the query.
func (e EmbeddingsConfig) EndpointDisplay() string {
	u, err := url.Parse(e.EffectiveEndpoint())
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host + strings.TrimRight(u.EscapedPath(), "/")
}

// EffectiveAuth is how the key is presented.
func (e EmbeddingsConfig) EffectiveAuth() string {
	if v := strings.ToLower(strings.TrimSpace(e.Auth)); v != "" {
		return v
	}
	if u, err := url.Parse(e.EffectiveEndpoint()); err == nil {
		host := strings.ToLower(u.Hostname())
		for _, suffix := range azureOpenAIHostSuffixes {
			if strings.HasSuffix(host, suffix) {
				return EmbeddingsAuthAPIKey
			}
		}
	}
	return EmbeddingsAuthBearer
}

// EffectiveBatchSize is how many chunks one request embeds.
func (e EmbeddingsConfig) EffectiveBatchSize() int {
	if e.BatchSize <= 0 || e.BatchSize > EmbeddingsBatchSizeUpper {
		return EmbeddingsBatchSizeDefault
	}
	return e.BatchSize
}

// EffectiveTimeout bounds one request.
func (e EmbeddingsConfig) EffectiveTimeout() time.Duration {
	d, err := parseBoundedDuration(e.Timeout, EmbeddingsTimeoutLower, EmbeddingsTimeoutUpper)
	if err != nil || d == 0 {
		return EmbeddingsTimeoutDefault
	}
	return d
}

// EffectiveMaxCandidates bounds the vectors one search compares.
func (e EmbeddingsConfig) EffectiveMaxCandidates() int {
	if e.MaxCandidates < EmbeddingsMaxCandidatesLower || e.MaxCandidates > EmbeddingsMaxCandidatesUpper {
		return EmbeddingsMaxCandidatesDefault
	}
	return e.MaxCandidates
}

// PlaintextBeyondLoopback reports an http endpoint whose host is not a
// loopback address or localhost: chunk text, queries and the key would cross
// the network unencrypted.
func (e EmbeddingsConfig) PlaintextBeyondLoopback() bool {
	u, err := url.Parse(e.EffectiveEndpoint())
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil && a.Unmap().IsLoopback() {
		return false
	}
	return true
}

// ValidateEmbeddings is the strict check of knowledge.embeddings, shared by
// `cloop config validate` and the loader. A disabled section is checked for
// nothing but a key written into it: it sends nothing anywhere, but a key in
// the file is in every backup and diff of it, on or off.
func ValidateEmbeddings(e EmbeddingsConfig) error {
	if strings.TrimSpace(e.APIKey) != "" {
		return fmt.Errorf("api_key holds a credential, which never belongs in the configuration: store it as a " +
			"shared env secret (cloop secret mint <name> --kind env) and name that secret in secret_ref")
	}
	if !e.Enabled {
		return nil
	}
	switch e.ProviderName() {
	case EmbeddingsOpenAI, EmbeddingsVoyage:
	case "":
		return fmt.Errorf("provider is required: openai (OpenAI, Azure OpenAI, Ollama, vLLM) or voyage")
	default:
		return fmt.Errorf("provider %q is not openai (any OpenAI-compatible API: OpenAI, Azure OpenAI, Ollama, "+
			"vLLM) or voyage", e.Provider)
	}
	if e.ProviderName() == EmbeddingsOpenAI && strings.TrimSpace(e.Endpoint) == "" {
		return fmt.Errorf("endpoint is required for provider openai — https://api.openai.com/v1, an Azure OpenAI " +
			"deployment, http://localhost:11434/v1 for Ollama or a vLLM server's /v1: chunk text is sent there, " +
			"so it is never assumed")
	}
	if err := validateEmbeddingsEndpoint(e.EffectiveEndpoint()); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	model := strings.TrimSpace(e.Model)
	switch {
	case model == "":
		return fmt.Errorf("model is required: the embedding model, as the endpoint names it")
	case len(model) > embeddingsMaxModelBytes:
		return fmt.Errorf("model is %d bytes, at most %d", len(model), embeddingsMaxModelBytes)
	case strings.IndexFunc(model, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return fmt.Errorf("model %q holds a space or control character", e.Model)
	}
	if e.Dimensions < 1 || e.Dimensions > EmbeddingsMaxDimensions {
		return fmt.Errorf("dimensions is %d; it is the length of the model's vectors, from 1 to %d", e.Dimensions,
			EmbeddingsMaxDimensions)
	}
	if ref := strings.TrimSpace(e.SecretRef); ref != "" {
		if err := validateSecretRef(ref); err != nil {
			return fmt.Errorf("secret_ref: %w", err)
		}
	}
	switch strings.ToLower(strings.TrimSpace(e.Auth)) {
	case "", EmbeddingsAuthBearer, EmbeddingsAuthAPIKey:
	default:
		return fmt.Errorf("auth %q is not bearer or api-key", e.Auth)
	}
	if e.BatchSize != 0 && (e.BatchSize < 1 || e.BatchSize > EmbeddingsBatchSizeUpper) {
		return fmt.Errorf("batch_size %d is outside 1-%d (or 0 for %d)", e.BatchSize, EmbeddingsBatchSizeUpper,
			EmbeddingsBatchSizeDefault)
	}
	if _, err := parseBoundedDuration(e.Timeout, EmbeddingsTimeoutLower, EmbeddingsTimeoutUpper); err != nil {
		return fmt.Errorf("timeout: %w", err)
	}
	if e.MaxCandidates != 0 && (e.MaxCandidates < EmbeddingsMaxCandidatesLower || e.MaxCandidates > EmbeddingsMaxCandidatesUpper) {
		return fmt.Errorf("max_candidates %d is outside %d-%d (or 0 for %d)", e.MaxCandidates,
			EmbeddingsMaxCandidatesLower, EmbeddingsMaxCandidatesUpper, EmbeddingsMaxCandidatesDefault)
	}
	return nil
}

// validateEmbeddingsEndpoint checks the endpoint's URL.
func validateEmbeddingsEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if len(raw) > embeddingsMaxEndpointBytes {
		return fmt.Errorf("the URL is %d bytes, at most %d", len(raw), embeddingsMaxEndpointBytes)
	}
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return fmt.Errorf("the URL holds a control character")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	if !strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("%q is not an http(s) URL", raw)
	}
	if u.User != nil {
		return fmt.Errorf("the URL carries a user name or password; store the key as a secret and name it in secret_ref")
	}
	if u.Fragment != "" {
		return fmt.Errorf("the URL has a fragment, which is never sent")
	}
	for name := range u.Query() {
		if credentialParam(name) {
			return fmt.Errorf("the URL passes %q as a query parameter, which reads as a credential; store the key as "+
				"a secret and name it in secret_ref", name)
		}
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		if svc, ok := cloudmeta.LookupDialed(a); ok {
			return fmt.Errorf("%s is the cloud metadata service %s, which the hub never sends anything to",
				u.Hostname(), svc.Describe())
		}
	}
	return nil
}

// clampEmbeddings is Load's repair of knowledge.embeddings: a section that is
// enabled and fails validation is switched off and recorded, never repaired
// into an endpoint nobody configured.
func (c *Config) clampEmbeddings(path string, warn func(field, msg string)) {
	e := &c.Knowledge.Embeddings
	err := ValidateEmbeddings(*e)
	if err == nil {
		return
	}
	const key = "knowledge.embeddings"
	detail := "refused at load: " + err.Error() + "; knowledge.embeddings is disabled"
	warn(key, detail)
	c.loadRepairs = append(c.loadRepairs, LoadRepair{File: path, Field: key, SwitchedOff: key, Detail: detail})
	e.Enabled = false
	// The key is dropped with the section, so nothing that reads this Config
	// later — a doctor, a log line — can repeat it.
	e.APIKey = ""
}
