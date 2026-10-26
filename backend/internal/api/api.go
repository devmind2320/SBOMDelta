// Package api serves the dashboard's read endpoints and the GitHub webhook.
//
// Every /api route except sign-in sits behind auth.RequireUser, and every
// state-changing request behind auth.SameOrigin. The webhook is outside both:
// GitHub proves itself with an HMAC signature, verified by the handler.
//
// Behind sign-in, every repository, scan and pull request is checked against
// the signed-in user's repositories from GitHub (storage.CanAccessRepository).
// One the user may not see answers 404, exactly like one that does not exist.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"sbomdelta/internal/auth"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/report"
	"sbomdelta/internal/storage"
)

// ScanRequester starts a scan of a repository's default branch head.
// *github.ManualScanner satisfies it.
type ScanRequester interface {
	Request(ctx context.Context, repositoryID int64) (models.Scan, ghapp.ScanOutcome, error)
}

type API struct {
	db    *storage.DB
	blob  *storage.BlobStore
	queue *queue.Queue
	auth  *auth.Service
	// scans is nil when GitHub integration is disabled.
	scans  ScanRequester
	logger *slog.Logger
}

func New(db *storage.DB, blob *storage.BlobStore, q *queue.Queue, authService *auth.Service, scans ScanRequester, logger *slog.Logger) *API {
	return &API{db: db, blob: blob, queue: q, auth: authService, scans: scans, logger: logger}
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
	data.HandleFunc("GET /api/me/repositories", a.listMyRepositories)
	data.HandleFunc("GET /api/me/tracked", a.listTracked)
	data.HandleFunc("PUT /api/me/tracked/{id}", a.track)
	data.HandleFunc("DELETE /api/me/tracked/{id}", a.untrack)
	data.HandleFunc("GET /api/me/scans", a.listRecentScans)
	data.HandleFunc("GET /api/impact/vulnerabilities", a.vulnerabilityImpact)
	data.HandleFunc("GET /api/impact/components", a.componentImpact)
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
	data.HandleFunc("GET /api/scans/{id}/vulnerability-changes", a.vulnerabilityChanges)
	data.HandleFunc("GET /api/scans/{id}/risk", a.scanRisk)
	data.HandleFunc("GET /api/scans/{id}/sbom", a.downloadSBOM)
	data.HandleFunc("GET /api/scans/{id}/report", a.downloadReport)
	// A scan request takes no input but the repository: the commit is the
	// default branch head, resolved as the App installation, and one scan
	// exists per commit (see github.ManualScanner).
	data.HandleFunc("POST /api/repos/{id}/scans", a.requestScan)
	// Registering a repository by URL stays off: it let anyone make the
	// worker clone any public repository.
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

// canAccess reports whether the signed-in user may see a repository. With
// sign-in disabled for local development there is one user, who sees all.
func (a *API) canAccess(ctx context.Context, repositoryID int64) (bool, error) {
	if a.auth.Disabled() {
		return true, nil
	}
	user, ok := auth.UserFrom(ctx)
	if !ok {
		return false, nil
	}
	return a.db.CanAccessRepository(ctx, user.ID, repositoryID)
}

// authorizeRepository answers 404 and returns false unless the signed-in
// user may see the repository. Not 403: whether a repository the user cannot
// see exists is itself not theirs to learn.
func (a *API) authorizeRepository(w http.ResponseWriter, r *http.Request, repositoryID int64) bool {
	ok, err := a.canAccess(r.Context(), repositoryID)
	if err != nil {
		a.fail(w, r, err)
		return false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
	}
	return ok
}

func (a *API) authorizeScan(w http.ResponseWriter, r *http.Request, scanID int64) bool {
	repositoryID, err := a.db.RepositoryIDForScan(r.Context(), scanID)
	if err != nil {
		a.fail(w, r, err)
		return false
	}
	return a.authorizeRepository(w, r, repositoryID)
}

func (a *API) authorizePullRequest(w http.ResponseWriter, r *http.Request, pullRequestID int64) bool {
	repositoryID, err := a.db.RepositoryIDForPullRequest(r.Context(), pullRequestID)
	if err != nil {
		a.fail(w, r, err)
		return false
	}
	return a.authorizeRepository(w, r, repositoryID)
}

// listMyRepositories returns one page of the repositories GitHub reported at
// sign-in for the signed-in user ("All Repos"), searchable with ?q=, paged
// with ?page= and ?perPage=, optionally without the ones already tracked
// (?exclude=tracked), plus when that list was read and why reading it
// failed, if it did.
func (a *API) listMyRepositories(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page, err := strconv.Atoi(query.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	perPage := limitParamNamed(r, "perPage", 30, 100)
	// With sign-in disabled for local development there is no GitHub list:
	// the one local user sees every stored repository (as canAccess allows),
	// and listing.error says why the list is not GitHub's.
	if a.auth.Disabled() {
		repos, total, err := a.db.ListAllRepositoryOverviews(r.Context(), query.Get("q"), perPage, (page-1)*perPage)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"repositories": repos, "total": total, "page": page, "perPage": perPage,
			"listing": storage.RepositoryListing{Error: "auth_disabled"},
		})
		return
	}
	user, _ := auth.UserFrom(r.Context())
	listing, err := a.db.UserRepositoryListing(r.Context(), user.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// ?exclude=tracked leaves out repositories already in "Tracked Repos".
	untrackedOnly := query.Get("exclude") == "tracked"
	repos, total, err := a.db.ListUserRepositories(r.Context(), user.ID, query.Get("q"), untrackedOnly, perPage, (page-1)*perPage)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repositories": repos, "total": total, "page": page, "perPage": perPage, "listing": listing,
	})
}

// listTracked returns the repositories the signed-in user tracks and can
// still access, with their latest scans ("Tracked Repos").
func (a *API) listTracked(w http.ResponseWriter, r *http.Request) {
	if a.auth.Disabled() {
		writeJSON(w, http.StatusOK, map[string]any{"repositories": []models.TrackedRepository{}})
		return
	}
	user, _ := auth.UserFrom(r.Context())
	repos, err := a.db.ListTrackedRepositories(r.Context(), user.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": repos})
}

// track adds a repository the signed-in user can access to their tracked
// list without scanning it. Tracking twice is not an error.
func (a *API) track(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	user, signedIn := auth.UserFrom(r.Context())
	if !signedIn || user.ID == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !a.authorizeRepository(w, r, id) {
		return
	}
	if err := a.db.TrackRepository(r.Context(), user.ID, id); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// untrack removes a repository from the signed-in user's tracked list. Its
// scan history is kept.
func (a *API) untrack(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	user, signedIn := auth.UserFrom(r.Context())
	if !signedIn || user.ID == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	removed, err := a.db.UntrackRepository(r.Context(), user.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requestScan scans a repository's default branch head for the signed-in
// user, who must be able to access it. Scanning never tracks: that is the
// user's separate choice (PUT /api/me/tracked/{id}). It answers
// 202 with the scan and what the request did: queued, in_progress,
// up_to_date (that commit's results are already current) or retried.
func (a *API) requestScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeRepository(w, r, id) {
		return
	}
	if a.scans == nil {
		writeError(w, http.StatusServiceUnavailable, "scanning is unavailable: GitHub integration is disabled")
		return
	}

	scan, outcome, err := a.scans.Request(r.Context(), id)
	var notScannable *ghapp.NotScannableError
	switch {
	case errors.As(err, &notScannable):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": notScannableMessage(notScannable.Reason), "reason": notScannable.Reason,
		})
		return
	case errors.Is(err, ghapp.ErrHeadLookupFailed):
		a.logger.Warn("could not resolve the branch to scan", "repository", id, "error", err)
		writeError(w, http.StatusBadGateway, "GitHub could not be reached to find the commit to scan; try again shortly")
		return
	case err != nil:
		a.fail(w, r, err)
		return
	}

	// The commit is already scanned, but its vulnerability lookup may never
	// have succeeded (OSV was down, or the scan predates the lookup). Asking
	// to scan again is the natural way to ask for that, so queue it.
	if outcome == ghapp.ScanUpToDate && scan.EnrichedAt == nil {
		if _, err := a.queue.Enqueue(r.Context(), queue.KindEnrich, queue.EnrichPayload{ScanID: scan.ID},
			queue.EnrichDedupeKey(scan.ID)); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scan": scan, "outcome": outcome})
}

func notScannableMessage(reason string) string {
	switch reason {
	case ghapp.NotScannableNoAccess:
		return "SBOMDelta's GitHub App no longer has access to this repository"
	case ghapp.NotScannableNoBranchHead:
		return "this repository has no commits on its default branch to scan"
	case ghapp.NotScannableRenamed:
		return "this repository was renamed on GitHub; SBOMDelta will pick up the new name shortly, then it can be scanned"
	default:
		return "this repository cannot be scanned"
	}
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

// listRepositories returns the repositories the signed-in user may see that
// SBOMDelta can currently reach.
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

	var repos []models.Repository
	var err error
	if a.auth.Disabled() {
		repos, err = a.db.ListRepositories(r.Context(), filter)
	} else {
		user, _ := auth.UserFrom(r.Context())
		repos, err = a.db.ListRepositoriesForUser(r.Context(), user.ID, filter)
	}
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
	if !a.authorizeRepository(w, r, id) {
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
	if !a.authorizeRepository(w, r, id) {
		return
	}
	scans, err := a.db.ListScans(r.Context(), id, limitParam(r, 50, 200))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

// driftTimeline returns the per-scan change counts the dashboard plots, with
// each scan's risk score once it has been checked for vulnerabilities (NULL
// before then, never zero).
func (a *API) driftTimeline(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeRepository(w, r, id) {
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
	if !a.authorizeScan(w, r, id) {
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
	if !a.authorizeScan(w, r, id) {
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
	if !a.authorizeScan(w, r, id) {
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
	if !a.authorizeScan(w, r, id) {
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

// reportFormats are the report downloads, by the format query parameter.
var reportFormats = map[string]struct {
	contentType string
	write       func(io.Writer, report.Report) error
}{
	"csv": {"text/csv; charset=utf-8", report.WriteCSV},
	"pdf": {"application/pdf", report.WritePDF},
}

// downloadReport serves a scan's SBOM report as a file: ?format=csv is one
// row per component, ?format=pdf a document for people. Both come from the
// database, through this process, so the browser never has to reach blob
// storage. The report is built in full before anything is sent, so a failure
// is an error response rather than a truncated file.
func (a *API) downloadReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeScan(w, r, id) {
		return
	}
	format, ok := reportFormats[r.URL.Query().Get("format")]
	if !ok {
		writeError(w, http.StatusBadRequest, "format must be csv or pdf")
		return
	}
	ctx := r.Context()
	scan, err := a.db.GetScan(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if scan.Status != models.ScanCompleted {
		writeError(w, http.StatusConflict, "the scan has not completed")
		return
	}
	repository, err := a.db.GetRepository(ctx, scan.RepositoryID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	components, err := a.db.ListComponents(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	vulnerabilities, err := a.db.ListVulnerabilities(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	drift, err := a.db.ListDriftEvents(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	rep := report.Report{Repository: repository, Scan: scan, Components: components,
		Vulnerabilities: vulnerabilities, Drift: drift, Generated: time.Now()}
	var body bytes.Buffer
	if err := format.write(&body, rep); err != nil {
		a.fail(w, r, err)
		return
	}
	extension := r.URL.Query().Get("format")
	w.Header().Set("Content-Type", format.contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+rep.Filename(extension)+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	// The report is the user's private data: no shared cache may keep it.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = body.WriteTo(w)
}

func (a *API) listPullRequests(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeRepository(w, r, id) {
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
	if !a.authorizePullRequest(w, r, id) {
		return
	}
	pull, err := a.db.GetPullRequest(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pull)
}

// listVulnerabilities returns the advisories for a scan, plus whether the
// scan has actually been checked. An empty list on an unchecked scan means
// "not analyzed", which the dashboard must not render as "clean"; summary
// says which it is and, when the lookup failed, why.
func (a *API) listVulnerabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !a.authorizeScan(w, r, id) {
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
	summary, err := a.db.ScanVulnerabilitySummary(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vulnerabilities":     vulnerabilities,
		"enrichmentAvailable": scan.EnrichedAt != nil,
		"enrichedAt":          scan.EnrichedAt,
		"summary":             summary,
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
	return limitParamNamed(r, "limit", fallback, ceiling)
}

func limitParamNamed(r *http.Request, name string, fallback, ceiling int) int {
	limit, err := strconv.Atoi(r.URL.Query().Get(name))
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
