// Package api serves the dashboard's read endpoints and the GitHub webhook.
//
// Every /api route except sign-in sits behind auth.RequireUser, and every
// state-changing request behind auth.SameOrigin. The webhook is outside both:
// GitHub proves itself with an HMAC signature, verified by the handler.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"sbomdelta/internal/auth"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

type API struct {
	db     *storage.DB
	blob   *storage.BlobStore
	queue  *queue.Queue
	auth   *auth.Service
	logger *slog.Logger
}

func New(db *storage.DB, blob *storage.BlobStore, q *queue.Queue, authService *auth.Service, logger *slog.Logger) *API {
	return &API{db: db, blob: blob, queue: q, auth: authService, logger: logger}
}

// Routes builds the HTTP handler. The webhook is mounted by the caller so that
// its dependencies stay in the github package.
//
// The data routes live on their own mux, mounted at /api/ behind sign-in, so a
// route added there later is protected without anyone remembering to wrap it.
// Only the sign-in endpoints are registered outside it, by exact path.
func (a *API) Routes(webhook http.Handler) http.Handler {
	data := http.NewServeMux()
	data.HandleFunc("GET /api/me", a.auth.Me)
	data.HandleFunc("GET /api/repos", a.listRepositories)
	data.HandleFunc("GET /api/repos/{id}", a.getRepository)
	data.HandleFunc("GET /api/repos/{id}/scans", a.listScans)
	data.HandleFunc("GET /api/repos/{id}/drift", a.driftTimeline)
	data.HandleFunc("GET /api/repos/{id}/pulls", a.listPullRequests)
	data.HandleFunc("GET /api/pulls/{id}", a.getPullRequest)
	data.HandleFunc("GET /api/scans/{id}", a.getScan)
	data.HandleFunc("GET /api/scans/{id}/components", a.listComponents)
	data.HandleFunc("GET /api/scans/{id}/drift", a.listDrift)
	data.HandleFunc("GET /api/scans/{id}/vulnerabilities", a.listVulnerabilities)
	data.HandleFunc("GET /api/scans/{id}/sbom", a.downloadSBOM)
	// Queueing a scan by hand and registering a repository by URL are off
	// until they can be offered safely: the old scan endpoint trusted any
	// caller-supplied commit, could re-run a finished scan over its results,
	// and resolved refs anonymously; registration let anyone make the worker
	// clone any public repository.
	data.HandleFunc("POST /api/repos/{id}/scans", unavailable)
	data.HandleFunc("POST /api/repos", unavailable)

	mux := http.NewServeMux()
	mux.Handle("POST /webhooks/github", webhook)
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /api/auth/github/login", a.auth.Login)
	mux.HandleFunc("GET "+auth.CallbackPath, a.auth.Callback)
	mux.HandleFunc("POST /api/auth/logout", a.auth.Logout)
	mux.Handle("/api/", a.auth.RequireUser(data))

	// No CORS headers are sent at all: the dashboard is served from the same
	// origin as the API, and no other origin should be able to read it.
	return a.withLogging(a.auth.SameOrigin(mux))
}

func unavailable(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not available")
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{"status": "ok"}
	code := http.StatusOK

	if err := a.db.Ping(r.Context()); err != nil {
		status["status"] = "degraded"
		status["database"] = err.Error()
		code = http.StatusServiceUnavailable
	}
	if stats, err := a.queue.Stats(r.Context()); err == nil {
		status["queue"] = stats
	}
	writeJSON(w, code, status)
}

// listRepositories returns the repositories SBOMDelta can currently reach.
// ?access=inactive returns the ones it has lost access to, whose history is
// still stored, and ?access=all returns both.
func (a *API) listRepositories(w http.ResponseWriter, r *http.Request) {
	filter := storage.AccessFilterActive
	switch access := r.URL.Query().Get("access"); access {
	case "", "active":
	case "inactive":
		filter = storage.AccessFilterInactive
	case "all":
		filter = storage.AccessFilterAll
	default:
		writeError(w, http.StatusBadRequest, "access must be one of active, inactive, all")
		return
	}

	repos, err := a.db.ListRepositories(r.Context(), filter)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": repos})
}

func (a *API) getRepository(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	repo, err := a.db.GetRepository(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, repo)
}

func (a *API) listScans(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scans, err := a.db.ListScans(r.Context(), id, limitParam(r, 50, 200))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

// driftTimeline returns the per-scan change counts the dashboard plots. Risk
// scoring lands in Phase 5; until then the timeline is measured in dependency
// movement rather than in risk.
func (a *API) driftTimeline(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	const query = `
		SELECT s.id, s.commit_sha, s.created_at, s.component_count, s.risk_score,
		       COUNT(*) FILTER (WHERE d.change_type = 'added')   AS added,
		       COUNT(*) FILTER (WHERE d.change_type = 'updated') AS updated,
		       COUNT(*) FILTER (WHERE d.change_type = 'removed') AS removed
		FROM scans s
		LEFT JOIN drift_events d ON d.scan_id = s.id
		WHERE s.repository_id = $1 AND s.status = 'completed' AND s.pull_request_id IS NULL
		GROUP BY s.id
		ORDER BY s.created_at DESC
		LIMIT $2`

	rows, err := a.db.Pool().Query(r.Context(), query, id, limitParam(r, 100, 500))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	defer rows.Close()

	type point struct {
		ScanID         int64     `json:"scanId"`
		CommitSHA      string    `json:"commitSha"`
		CreatedAt      time.Time `json:"createdAt"`
		ComponentCount int       `json:"componentCount"`
		RiskScore      *float64  `json:"riskScore"`
		Added          int       `json:"added"`
		Updated        int       `json:"updated"`
		Removed        int       `json:"removed"`
	}

	timeline := make([]point, 0)
	for rows.Next() {
		var p point
		if err := rows.Scan(&p.ScanID, &p.CommitSHA, &p.CreatedAt, &p.ComponentCount, &p.RiskScore,
			&p.Added, &p.Updated, &p.Removed); err != nil {
			a.fail(w, r, err)
			return
		}
		timeline = append(timeline, p)
	}
	if err := rows.Err(); err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"timeline": timeline})
}

func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scan, err := a.db.GetScan(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (a *API) listComponents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	components, err := a.db.ListComponents(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": components})
}

func (a *API) listDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	events, err := a.db.ListDriftEvents(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"driftEvents": events})
}

// downloadSBOM redirects to a short-lived presigned URL rather than streaming
// the document through the API, which keeps multi-megabyte SBOMs off this
// process's heap.
func (a *API) downloadSBOM(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scan, err := a.db.GetScan(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if scan.SBOMLocation == "" {
		writeError(w, http.StatusNotFound, "this scan has no stored SBOM")
		return
	}

	url, err := a.blob.PresignSBOM(r.Context(), scan.SBOMLocation, 10*time.Minute)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *API) listPullRequests(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	pulls, err := a.db.ListPullRequests(r.Context(), id, limitParam(r, 50, 200))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pullRequests": pulls})
}

func (a *API) getPullRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	pull, err := a.db.GetPullRequest(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pull)
}

// listVulnerabilities returns the advisories for a scan, plus whether
// enrichment has actually run.
//
// The flag is derived from the scan's enriched_at timestamp rather than
// hardcoded, so it starts reporting true the moment Phase 4 lands instead of
// waiting for someone to remember to flip a literal. Until then an empty list
// means "not analyzed", which the dashboard must not render as "clean".
func (a *API) listVulnerabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scan, err := a.db.GetScan(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	vulnerabilities, err := a.db.ListVulnerabilities(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vulnerabilities":     vulnerabilities,
		"enrichmentAvailable": scan.EnrichedAt != nil,
		"enrichedAt":          scan.EnrichedAt,
	})
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	a.logger.Error("request failed", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func (a *API) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		a.logger.Info("request",
			"method", r.Method, "path", r.URL.Path,
			"status", recorder.status, "duration", time.Since(started))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "id must be a positive integer")
		return 0, false
	}
	return id, true
}

func limitParam(r *http.Request, fallback, ceiling int) int {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		return fallback
	}
	return min(limit, ceiling)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already sent, so there is nothing left to do but
		// let the client see a truncated body.
		return
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
