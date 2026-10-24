// Package api serves the dashboard's read endpoints and the GitHub webhook.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sbomdelta/internal/config"
	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

type API struct {
	db   *storage.DB
	blob *storage.BlobStore
	// scanner config is needed only to resolve a ref to a commit before
	// queueing; the scan itself still happens on the worker.
	scanner config.Scanner
	queue   *queue.Queue
	logger  *slog.Logger
}

func New(db *storage.DB, blob *storage.BlobStore, q *queue.Queue, scanner config.Scanner, logger *slog.Logger) *API {
	return &API{db: db, blob: blob, queue: q, scanner: scanner, logger: logger}
}

// Routes builds the HTTP handler. The webhook is mounted by the caller so that
// its dependencies stay in the github package.
func (a *API) Routes(webhook http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("POST /webhooks/github", webhook)

	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /api/repos", a.listRepositories)
	mux.HandleFunc("POST /api/repos", a.registerRepository)
	mux.HandleFunc("GET /api/repos/{id}", a.getRepository)
	mux.HandleFunc("GET /api/repos/{id}/scans", a.listScans)
	mux.HandleFunc("POST /api/repos/{id}/scans", a.triggerScan)
	mux.HandleFunc("GET /api/repos/{id}/drift", a.driftTimeline)
	mux.HandleFunc("GET /api/repos/{id}/pulls", a.listPullRequests)
	mux.HandleFunc("GET /api/pulls/{id}", a.getPullRequest)
	mux.HandleFunc("GET /api/scans/{id}", a.getScan)
	mux.HandleFunc("GET /api/scans/{id}/components", a.listComponents)
	mux.HandleFunc("GET /api/scans/{id}/drift", a.listDrift)
	mux.HandleFunc("GET /api/scans/{id}/vulnerabilities", a.listVulnerabilities)
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

// registerRepository adds a repository by hand, without the GitHub App.
//
// The scan pipeline does not actually need GitHub: given a clone URL and a
// commit it produces the same SBOM, diff and drift history. This endpoint
// exists so a public repository can be tracked directly, and so the product
// can be run and demonstrated before an App is installed anywhere.
func (a *API) registerRepository(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner         string `json:"owner"`
		Name          string `json:"name"`
		CloneURL      string `json:"cloneUrl"`
		DefaultBranch string `json:"defaultBranch"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	body.Owner = strings.TrimSpace(body.Owner)
	body.Name = strings.TrimSpace(body.Name)
	if body.Owner == "" || body.Name == "" {
		writeError(w, http.StatusBadRequest, "owner and name are required")
		return
	}
	if body.DefaultBranch == "" {
		body.DefaultBranch = "main"
	}
	if body.CloneURL == "" {
		body.CloneURL = fmt.Sprintf("https://github.com/%s/%s.git", body.Owner, body.Name)
	}
	// Only anonymous HTTPS is supported here. An ssh:// or file:// source
	// would let a caller reach things the API should not reach on its behalf.
	if !strings.HasPrefix(body.CloneURL, "https://") {
		writeError(w, http.StatusBadRequest, "cloneUrl must be an https:// url")
		return
	}

	repo, err := a.db.UpsertManualRepository(r.Context(), models.Repository{
		Owner:         body.Owner,
		Name:          body.Name,
		DefaultBranch: body.DefaultBranch,
		CloneURL:      body.CloneURL,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, repo)
}

// triggerScan queues a manual scan of one commit.
//
// It accepts either an exact commitSha or a ref to resolve. Resolving happens
// here rather than in the worker because a scan row is keyed on its commit,
// and that is what makes re-triggering the same commit idempotent instead of
// piling up duplicate scans.
func (a *API) triggerScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Ref       string `json:"ref"`
		CommitSHA string `json:"commitSha"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	repo, err := a.db.GetRepository(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Its history stays readable, but a repository SBOMDelta lost access to
	// cannot be cloned with the access it had.
	if !repo.Accessible() {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("SBOMDelta no longer has access to %s (%s); its history is still available", repo.FullName(), repo.Access))
		return
	}

	commitSHA := strings.TrimSpace(body.CommitSHA)
	if commitSHA == "" {
		ref := strings.TrimSpace(body.Ref)
		if ref == "" {
			ref = repo.DefaultBranch
		}
		commitSHA, err = sbom.ResolveRef(r.Context(), a.scanner, repo.CloneURL, ref)
		if err != nil {
			// A failed lookup is the caller's problem to fix (wrong ref,
			// private repo, rate limit), not a server fault.
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if !sbom.IsCommitSHA(commitSHA) {
		writeError(w, http.StatusBadRequest, "commitSha must be a full 40-character sha")
		return
	}

	// The previous completed scan is the baseline, mirroring what a push to
	// the default branch would compare against.
	var baseCommitSHA string
	if previous, err := a.db.LatestCompletedScan(r.Context(), repo.ID, 0, time.Now()); err == nil {
		baseCommitSHA = previous.CommitSHA
	} else if !errors.Is(err, storage.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	if baseCommitSHA == commitSHA {
		baseCommitSHA = ""
	}

	scan, err := a.db.CreateScan(r.Context(), models.Scan{
		RepositoryID:  repo.ID,
		CommitSHA:     commitSHA,
		BaseCommitSHA: baseCommitSHA,
		Trigger:       models.TriggerManual,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}

	if _, err := a.queue.Enqueue(r.Context(), queue.KindScan,
		queue.ScanPayload{ScanID: scan.ID}, fmt.Sprintf("scan:%d", scan.ID)); err != nil {
		a.fail(w, r, err)
		return
	}

	// 202: the work is accepted, not finished. Poll GET /api/scans/{id}.
	writeJSON(w, http.StatusAccepted, scan)
}

// decodeJSON reads a JSON body, rejecting unknown fields so a typo in a
// hand-written request is reported instead of silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body: "+err.Error())
		return false
	}
	return true
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
