// Package api serves the dashboard's read endpoints and the GitHub webhook.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

type API struct {
	db     *storage.DB
	blob   *storage.BlobStore
	queue  *queue.Queue
	logger *slog.Logger
}

func New(db *storage.DB, blob *storage.BlobStore, q *queue.Queue, logger *slog.Logger) *API {
	return &API{db: db, blob: blob, queue: q, logger: logger}
}

// Routes builds the HTTP handler. The webhook is mounted by the caller so that
// its dependencies stay in the github package.
func (a *API) Routes(webhook http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("POST /webhooks/github", webhook)

	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /api/repos", a.listRepositories)
	mux.HandleFunc("GET /api/repos/{id}", a.getRepository)
	mux.HandleFunc("GET /api/repos/{id}/scans", a.listScans)
	mux.HandleFunc("GET /api/repos/{id}/drift", a.driftTimeline)
	mux.HandleFunc("GET /api/scans/{id}", a.getScan)
	mux.HandleFunc("GET /api/scans/{id}/components", a.listComponents)
	mux.HandleFunc("GET /api/scans/{id}/drift", a.listDrift)
	mux.HandleFunc("GET /api/scans/{id}/sbom", a.downloadSBOM)

	return a.withLogging(a.withCORS(mux))
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

func (a *API) listRepositories(w http.ResponseWriter, r *http.Request) {
	repos, err := a.db.ListRepositories(r.Context())
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

// withCORS lets the Vue dev server call the API from a different origin.
func (a *API) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
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
