package ui

// Semantic retrieval on the hub (Task 20471): the embedding client the hub's
// knowledge.embeddings names, made once per configuration and handed to every
// knowledge Service the hub opens — a search's, a sync's, a listing's.
//
// The configuration is read on every call, overlay included, as every
// hub-scope setting is: an administrator who turns embeddings off stops the
// next search and the next sync sending text anywhere, without a restart. The
// client is kept while the section is unchanged, so its connections, its key
// and what it knows about the endpoint failing outlive one request.
//
// The key is a hub credential (secretbroker.HubCredential): a shared env
// secret the hub presents as itself, opened here and never handed to an
// executor.

import (
	"fmt"
	"sync"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/embed"
)

// knowledgeEmbedState is a member's embedding client, made on first use.
type knowledgeEmbedState struct {
	mu     sync.Mutex
	cfg    config.EmbeddingsConfig
	client *embed.Client
}

// get returns the client for e, making it — and closing the one made for an
// earlier configuration — when e is not what it was made for.
func (st *knowledgeEmbedState) get(e config.EmbeddingsConfig, cred func(string) ([]byte, error)) (*embed.Client, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.client != nil && st.cfg == e {
		return st.client, nil
	}
	if st.client != nil {
		st.client.Close()
		st.client = nil
	}
	ref := e.SecretRef
	client, err := embed.FromConfig(e, func() ([]byte, error) { return cred(ref) })
	if err != nil {
		return nil, err
	}
	st.cfg, st.client = e, client
	return client, nil
}

// drop closes the client, for a hub whose embeddings were turned off.
func (st *knowledgeEmbedState) drop() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.client != nil {
		st.client.Close()
		st.client = nil
	}
	st.cfg = config.EmbeddingsConfig{}
}

// knowledgeEmbeddings is semantic retrieval as the hub's configuration says:
// off, on with its client, or broken — a section refused at load, which syncs
// and searches report rather than going quiet about.
func (s *Server) knowledgeEmbeddings() knowledge.Embeddings {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		// No configuration to read is no section turning anything on.
		return knowledge.Embeddings{}
	}
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff == "knowledge.embeddings" {
			s.knowledgeEmbed.drop()
			return knowledge.Embeddings{Broken: "knowledge.embeddings was " + r.Detail}
		}
	}
	e := cfg.Knowledge.Embeddings
	if !e.Enabled {
		s.knowledgeEmbed.drop()
		return knowledge.Embeddings{}
	}
	client, err := s.knowledgeEmbed.get(e, s.hubCredential)
	if err != nil {
		return knowledge.Embeddings{Broken: err.Error()}
	}
	return knowledge.Embeddings{Embedder: client, BatchSize: e.EffectiveBatchSize(), MaxCandidates: e.EffectiveMaxCandidates()}
}

// hubCredential opens a shared env secret the hub presents as itself: an
// audit sink's token, the embedding endpoint's key.
func (s *Server) hubCredential(ref string) ([]byte, error) {
	bs, err := s.openBrokers()
	if err != nil {
		return nil, err
	}
	defer bs.close()
	if bs.secret == nil {
		return nil, fmt.Errorf("%s: %s", bs.status.Reason, bs.status.Remediation)
	}
	return bs.secret.HubCredential(ref)
}
