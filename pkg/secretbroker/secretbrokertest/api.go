package secretbrokertest

// api.go serves the fake GitHub's App API over HTTP (Task 20383), for a hub
// that is a separate process: a github_app secret whose base_url names this
// server mints, lists and destroys installation tokens here instead of at
// api.github.com, with the same clock and the same tokens the forge honours.

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// APIHandler serves the three App API routes a hub calls: minting an
// installation token, listing an installation's repositories, and destroying
// a token. The app JWT is not verified — this stands in for GitHub, not for
// its authentication.
func (g *GitHub) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, `{"message":"bad installation id"}`, http.StatusNotFound)
			return
		}
		var body struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				http.Error(w, `{"message":"bad body"}`, http.StatusUnprocessableEntity)
				return
			}
		}
		tok, err := g.CreateInstallationToken(r.Context(), secretbroker.InstallationTokenRequest{
			InstallationID: id, RepositoryIDs: body.RepositoryIDs, Permissions: body.Permissions,
			AppJWT: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tok)
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		repos, err := g.ListInstallationRepos(r.Context(), "", token)
		if err != nil {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		if page, _ := strconv.Atoi(r.URL.Query().Get("page")); page > 1 {
			repos = nil
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(repos), "repositories": repos})
	})
	mux.HandleFunc("DELETE /installation/token", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_ = g.RevokeInstallationToken(r.Context(), "", token)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
