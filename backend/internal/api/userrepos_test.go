package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sbomdelta/internal/api"
	"sbomdelta/internal/auth"
	"sbomdelta/internal/config"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

// as sends a request with another user's session.
func (f fixture) as(t *testing.T, session *http.Cookie, method, path string) (int, string) {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.AddCookie(session)
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set(auth.CSRFHeader, "1")
		request.Header.Set("Origin", testPublicURL)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.String()
}

// A second allowed user whose GitHub list holds only the active repository
// sees nothing of the other one: not in lists, not by direct link to the
// repository, its scans, components, drift, vulnerabilities, SBOM or pull
// requests, and cannot scan it. Every refusal is a 404 that names nothing.
func TestUsersSeeOnlyRepositoriesGitHubGrantsThem(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pull, err := f.db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: f.revoked.ID, Number: 7, State: "open", BaseSHA: strings.Repeat("1", 40), HeadSHA: strings.Repeat("2", 40),
	})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}
	teammate := newSession(t, f.db, 5001, "teammate")
	grant(t, f.db, userNamed(t, f.db, "teammate"), f.active)

	hidden := jsonID(f.revoked.ID)
	scan := jsonID(f.scan.ID)
	for _, path := range []string{
		"/api/repos/" + hidden,
		"/api/repos/" + hidden + "/scans",
		"/api/repos/" + hidden + "/drift",
		"/api/repos/" + hidden + "/pulls",
		"/api/pulls/" + jsonID(pull.ID),
		"/api/scans/" + scan,
		"/api/scans/" + scan + "/components",
		"/api/scans/" + scan + "/drift",
		"/api/scans/" + scan + "/vulnerabilities",
		"/api/scans/" + scan + "/sbom",
		"/api/scans/" + scan + "/risk",
		"/api/scans/" + scan + "/vulnerability-changes",
		"/api/me/scans?repositoryId=" + hidden,
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			status, body := f.as(t, teammate, method, path)
			if status != http.StatusNotFound || strings.Contains(body, "dropped") || strings.Contains(body, "4444") {
				t.Errorf("%s %s as teammate = %d %q, want a bare 404", method, path, status, body)
			}
		}
		// The owner of that access still gets through.
		if status, _ := f.as(t, f.session, http.MethodGet, path); status == http.StatusNotFound && !strings.HasSuffix(path, "/sbom") {
			t.Errorf("GET %s as devmind2320 = 404, want it readable", path)
		}
	}

	status, _ := f.as(t, teammate, http.MethodPost, "/api/repos/"+hidden+"/scans")
	if status != http.StatusNotFound || len(f.scans.requested) != 0 {
		t.Errorf("teammate scan request = %d with %d scans requested, want 404 and none", status, len(f.scans.requested))
	}

	status, body := f.as(t, teammate, http.MethodGet, "/api/repos?access=all")
	if status != http.StatusOK || strings.Contains(body, "dropped") || !strings.Contains(body, "kept") {
		t.Errorf("teammate GET /api/repos?access=all = %d %s, want only the granted repository", status, body)
	}
	status, body = f.as(t, teammate, http.MethodGet, "/api/me/repositories")
	if status != http.StatusOK || strings.Contains(body, "dropped") || !strings.Contains(body, "kept") {
		t.Errorf("teammate GET /api/me/repositories = %d %s, want only the granted repository", status, body)
	}

	// Once GitHub stops listing a repository for the user, it is gone for them.
	grant(t, f.db, userNamed(t, f.db, "teammate"))
	if status, _ := f.as(t, teammate, http.MethodGet, "/api/repos/"+jsonID(f.active.ID)); status != http.StatusNotFound {
		t.Errorf("after GitHub stopped listing it: GET repository = %d, want 404", status)
	}
}

type userRepositoryPage struct {
	Repositories []models.UserRepository   `json:"repositories"`
	Total        int                       `json:"total"`
	Page         int                       `json:"page"`
	PerPage      int                       `json:"perPage"`
	Listing      storage.RepositoryListing `json:"listing"`
}

func (f fixture) myRepositories(t *testing.T, query string) userRepositoryPage {
	t.Helper()
	status, body := f.as(t, f.session, http.MethodGet, "/api/me/repositories"+query)
	if status != http.StatusOK {
		t.Fatalf("GET /api/me/repositories%s = %d %s", query, status, body)
	}
	var page userRepositoryPage
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return page
}

func TestMyRepositoriesArePagedSearchableAndJoinedToScans(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	listed := []models.AccessibleRepository{
		{GitHubRepoID: 1001, GitHubInstallationID: 4242, Owner: "devmind2320", Name: "kept", Private: true, DefaultBranch: "main"},
		{GitHubRepoID: 1002, GitHubInstallationID: 4242, Owner: "devmind2320", Name: "dropped", Private: true, DefaultBranch: "main"},
	}
	// Repositories GitHub lists that SBOMDelta has not stored yet still show.
	for i := range 5 {
		listed = append(listed, models.AccessibleRepository{
			GitHubRepoID: int64(9000 + i), GitHubInstallationID: 4242, Owner: "acme", Name: fmt.Sprintf("svc-%d", i),
		})
	}
	listedAt := time.Now().UTC().Truncate(time.Second)
	if err := f.db.ReplaceUserRepositories(ctx, f.user.ID, listed, listedAt); err != nil {
		t.Fatal(err)
	}

	first := f.myRepositories(t, "?perPage=3")
	if first.Total != 7 || len(first.Repositories) != 3 || first.Page != 1 || first.PerPage != 3 {
		t.Fatalf("page 1 = total %d, %d rows, page %d/%d; want 7, 3, 1/3", first.Total, len(first.Repositories), first.Page, first.PerPage)
	}
	if first.Listing.ListedAt == nil || !first.Listing.ListedAt.Equal(listedAt) || first.Listing.Error != "" {
		t.Errorf("listing = %+v, want listed at %v with no error", first.Listing, listedAt)
	}
	seen := map[string]bool{}
	for page := 1; page <= 3; page++ {
		for _, repo := range f.myRepositories(t, fmt.Sprintf("?perPage=3&page=%d", page)).Repositories {
			name := repo.Owner + "/" + repo.Name
			if seen[name] {
				t.Errorf("%s appears on two pages", name)
			}
			seen[name] = true
		}
	}
	if len(seen) != 7 {
		t.Errorf("pages covered %d repositories, want all 7", len(seen))
	}
	if beyond := f.myRepositories(t, "?perPage=3&page=4"); len(beyond.Repositories) != 0 || beyond.Total != 7 {
		t.Errorf("page past the end = %d rows, total %d", len(beyond.Repositories), beyond.Total)
	}

	search := f.myRepositories(t, "?q=DEVMIND2320/ke")
	if search.Total != 1 || len(search.Repositories) != 1 || search.Repositories[0].Name != "kept" {
		t.Fatalf("search = %+v, want only kept", search)
	}
	kept := search.Repositories[0]
	if kept.RepositoryID == nil || *kept.RepositoryID != f.active.ID || kept.Access == nil || *kept.Access != models.AccessActive {
		t.Errorf("kept = %+v, want joined to repository %d, active", kept, f.active.ID)
	}
	if like := f.myRepositories(t, "?q=%25"); like.Total != 0 {
		t.Errorf("a %% in the search matched %d repositories, want it taken literally", like.Total)
	}

	dropped := f.myRepositories(t, "?q=dropped").Repositories[0]
	if dropped.LatestScan == nil || dropped.LatestScan.ID != f.scan.ID || dropped.LatestScan.Status != models.ScanCompleted {
		t.Errorf("dropped latest scan = %+v, want the completed fixture scan", dropped.LatestScan)
	}
	unstored := f.myRepositories(t, "?q=svc-0").Repositories[0]
	if unstored.RepositoryID != nil || unstored.Access != nil || unstored.LatestScan != nil || unstored.Tracked {
		t.Errorf("unstored = %+v, want no repository, access, scan or tracking yet", unstored)
	}
}

func TestMyRepositoriesReportsAFailedListing(t *testing.T) {
	f := newFixture(t)
	if err := f.db.ClearUserRepositories(context.Background(), f.user.ID, auth.ListErrorRateLimited, time.Now()); err != nil {
		t.Fatal(err)
	}
	page := f.myRepositories(t, "")
	if page.Total != 0 || len(page.Repositories) != 0 || page.Listing.Error != auth.ListErrorRateLimited {
		t.Errorf("after a failed listing = %+v, want an empty list and the rate_limited reason", page)
	}
	// Clearing the list also removes access granted by the old one.
	if status, _ := f.do(t, http.MethodGet, "/api/repos/"+jsonID(f.active.ID), ""); status != http.StatusNotFound {
		t.Errorf("GET repository after the list was cleared = %d, want 404", status)
	}
}

// Scanning and tracking are independent: a scan request queues the scan and
// leaves the tracked list alone, and the repository stays in All Repos.
func TestRequestScanQueuesWithoutTracking(t *testing.T) {
	f := newFixture(t)
	path := "/api/repos/" + jsonID(f.active.ID) + "/scans"

	status, body := f.do(t, http.MethodPost, path, "")
	if status != http.StatusAccepted {
		t.Fatalf("POST %s = %d %v, want 202", path, status, body)
	}
	if string(body["outcome"]) != `"queued"` {
		t.Errorf("outcome = %s, want queued", body["outcome"])
	}
	var scan models.Scan
	if err := json.Unmarshal(body["scan"], &scan); err != nil || scan.ID != 77 || scan.RepositoryID != f.active.ID {
		t.Errorf("scan = %+v (%v), want scan 77 of the repository", scan, err)
	}
	if len(f.scans.requested) != 1 || f.scans.requested[0] != f.active.ID {
		t.Errorf("requested = %v, want the repository once", f.scans.requested)
	}

	if _, body := f.do(t, http.MethodGet, "/api/me/tracked", ""); string(body["repositories"]) != "[]" {
		t.Errorf("tracked after scanning = %s, want [] (scanning must not track)", body["repositories"])
	}
	if mine := f.myRepositories(t, "?q=kept"); mine.Total != 1 || mine.Repositories[0].Tracked {
		t.Errorf("All Repos after scanning = %+v, want the repository listed and untracked", mine.Repositories)
	}

	// Tracking it afterwards keeps it in All Repos, now marked tracked.
	track := "/api/me/tracked/" + jsonID(f.active.ID)
	if status, _ := f.as(t, f.session, http.MethodPut, track); status != http.StatusNoContent {
		t.Fatalf("PUT %s = %d, want 204", track, status)
	}
	if mine := f.myRepositories(t, "?q=kept"); mine.Total != 1 || !mine.Repositories[0].Tracked {
		t.Errorf("All Repos after tracking = %+v, want the repository listed and tracked", mine.Repositories)
	}

	// Stop tracking; the scan history stays.
	if status, _ := f.as(t, f.session, http.MethodDelete, track); status != http.StatusNoContent {
		t.Errorf("DELETE %s = %d, want 204", track, status)
	}
	if status, _ := f.as(t, f.session, http.MethodDelete, track); status != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", status)
	}
	if _, body := f.do(t, http.MethodGet, "/api/me/tracked", ""); string(body["repositories"]) != "[]" {
		t.Errorf("tracked after untracking = %s, want []", body["repositories"])
	}
	if mine := f.myRepositories(t, "?q=kept"); mine.Total != 1 {
		t.Errorf("All Repos after untracking total = %d, want 1", mine.Total)
	}
}

func TestRequestScanFailures(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{"App lost access", &ghapp.NotScannableError{Reason: ghapp.NotScannableNoAccess}, http.StatusConflict, `"reason":"no_access"`},
		{"empty repository", &ghapp.NotScannableError{Reason: ghapp.NotScannableNoBranchHead}, http.StatusConflict, `"reason":"no_branch_head"`},
		{"renamed", &ghapp.NotScannableError{Reason: ghapp.NotScannableRenamed}, http.StatusConflict, `"reason":"renamed"`},
		{"GitHub down", fmt.Errorf("%w: HTTP 502", ghapp.ErrHeadLookupFailed), http.StatusBadGateway, "GitHub could not be reached"},
		{"database", fmt.Errorf("connection reset"), http.StatusInternalServerError, "internal error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.scans.err = tt.err
			status, body := f.as(t, f.session, http.MethodPost, "/api/repos/"+jsonID(f.active.ID)+"/scans")
			if status != tt.wantStatus || !strings.Contains(body, tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %s", status, body, tt.wantStatus, tt.wantBody)
			}
			if strings.Contains(body, "connection reset") || strings.Contains(body, "HTTP 502") {
				t.Errorf("internal error text leaked: %s", body)
			}
			if _, body := f.do(t, http.MethodGet, "/api/me/tracked", ""); string(body["repositories"]) != "[]" {
				t.Errorf("a failed request tracked the repository: %s", body["repositories"])
			}
		})
	}
}

func TestRequestScanWithoutGitHubIntegration(t *testing.T) {
	f := newFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	public, _ := url.Parse(testPublicURL)
	authService := auth.New(config.Auth{
		ClientID: "Iv1.apitest", ClientSecret: "api-test-client-secret", PublicURL: public,
		WebBaseURL: "https://github.invalid", AllowedLogins: []string{"devmind2320"}, SessionTTL: time.Hour,
	}, "https://api.github.invalid/", f.db, logger)
	f.handler = api.New(f.db, nil, queue.New(f.db.Pool(), time.Minute), authService, nil, logger).Routes(http.NotFoundHandler())

	status, body := f.as(t, f.session, http.MethodPost, "/api/repos/"+jsonID(f.active.ID)+"/scans")
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "GitHub integration is disabled") {
		t.Errorf("= %d %s, want 503", status, body)
	}
}

// The new state-changing routes are held to the same CSRF rule as the rest.
func TestNewStateChangingRoutesRequireCSRFHeader(t *testing.T) {
	f := newFixture(t)
	for _, request := range []struct{ method, path string }{
		{http.MethodPost, "/api/repos/" + jsonID(f.active.ID) + "/scans"},
		{http.MethodDelete, "/api/me/tracked/" + jsonID(f.active.ID)},
		{http.MethodPut, "/api/me/tracked/" + jsonID(f.active.ID)},
	} {
		for _, headers := range []map[string]string{
			{},
			{"Origin": testPublicURL},
			{auth.CSRFHeader: "1", "Origin": "https://evil.example"},
		} {
			r := httptest.NewRequest(request.method, request.path, nil)
			r.AddCookie(f.session)
			for key, value := range headers {
				r.Header.Set(key, value)
			}
			recorder := httptest.NewRecorder()
			f.handler.ServeHTTP(recorder, r)
			if recorder.Code != http.StatusForbidden {
				t.Errorf("%s %s with %v = %d, want 403", request.method, request.path, headers, recorder.Code)
			}
		}
	}
	if len(f.scans.requested) != 0 {
		t.Errorf("a refused request still requested %d scans", len(f.scans.requested))
	}
}
