package api_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"sbomdelta/internal/api"
	"sbomdelta/internal/auth"
	"sbomdelta/internal/config"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
	"sbomdelta/internal/storage/storagetest"
)

// tenant is one user of an open deployment, with their own GitHub App
// installation and a scanned, private repository in it.
type tenant struct {
	login   string
	session *http.Cookie
	repo    models.Repository
	scan    models.Scan
}

// newTenants builds a deployment with no ALLOWED_GITHUB_LOGINS and two
// unrelated users, each of whom installed the App on their own account. Both
// repositories depend on lodash, so a query that crossed tenants would find
// the other one.
func newTenants(t *testing.T) (fixture, tenant, tenant) {
	t.Helper()
	db := storagetest.Open(t, "test_api")
	ctx := context.Background()

	setup := func(githubUserID, installationID, repoID int64, login, name string) tenant {
		installation, err := db.UpsertInstallation(ctx, models.Installation{
			GitHubInstallationID: installationID, AccountLogin: login, AccountID: githubUserID, AccountType: "User",
		})
		if err != nil {
			t.Fatalf("UpsertInstallation(%s) error = %v", login, err)
		}
		repo, err := db.UpsertRepository(ctx, models.Repository{
			InstallationID: &installation.ID, GitHubRepoID: &repoID, Owner: login, Name: name, DefaultBranch: "main", Private: true,
		})
		if err != nil {
			t.Fatalf("UpsertRepository(%s) error = %v", name, err)
		}
		sha := strings.Repeat(string(rune('a'+repoID%6)), 40)
		scan, err := db.CreateScan(ctx, models.Scan{RepositoryID: repo.ID, CommitSHA: sha, Trigger: models.TriggerPush})
		if err != nil {
			t.Fatalf("CreateScan(%s) error = %v", name, err)
		}
		if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID, Components: []sbom.Component{{
			PURL: "pkg:npm/lodash@4.17.20", Identity: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20", Ecosystem: "npm",
		}}}); err != nil {
			t.Fatalf("SaveScanResult(%s) error = %v", name, err)
		}
		session := newSession(t, db, githubUserID, login)
		if err := db.ReplaceUserRepositories(ctx, userNamed(t, db, login).ID, []models.AccessibleRepository{{
			GitHubRepoID: repoID, GitHubInstallationID: installationID, Owner: login, Name: name, Private: true, DefaultBranch: "main",
		}}, time.Now()); err != nil {
			t.Fatalf("ReplaceUserRepositories(%s) error = %v", login, err)
		}
		return tenant{login: login, session: session, repo: repo, scan: scan}
	}
	alice := setup(8101, 31, 3101, "alice", "alice-private-app")
	bob := setup(8102, 32, 3201, "bob", "bob-private-svc")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	public, _ := url.Parse(testPublicURL)
	authService := auth.New(config.Auth{
		ClientID: "Iv1.apitest", ClientSecret: "api-test-client-secret", PublicURL: public,
		WebBaseURL: "https://github.invalid", SessionTTL: time.Hour,
	}, "https://api.github.invalid/", db, logger)
	scans := &fakeScans{scan: models.Scan{ID: 77, Status: models.ScanPending, Trigger: models.TriggerManual,
		CommitSHA: strings.Repeat("6", 40)}, outcome: ghapp.ScanQueued}
	handler := api.New(db, nil, queue.New(db.Pool(), time.Minute), authService, scans, logger).
		Routes(http.NotFoundHandler())
	return fixture{db: db, handler: handler, scans: scans}, alice, bob
}

// With sign-in open to every GitHub account, two unrelated users each see,
// track and scan only their own repository. Nothing of the other's appears in
// any list, aggregate or search, and every direct reference to it is a bare
// 404, including the write routes.
func TestTenantsSeeAndActOnlyOnTheirOwnRepositories(t *testing.T) {
	f, alice, bob := newTenants(t)

	for _, pair := range [][2]tenant{{alice, bob}, {bob, alice}} {
		me, other := pair[0], pair[1]

		if status, _ := f.as(t, me.session, http.MethodPut, "/api/me/tracked/"+jsonID(me.repo.ID)); status >= 300 {
			t.Fatalf("%s tracking their own repository = %d, want success", me.login, status)
		}
		for _, path := range []string{
			"/api/me",
			"/api/repos?access=all",
			"/api/me/repositories",
			"/api/me/tracked",
			"/api/me/scans",
			"/api/impact/vulnerabilities",
			"/api/impact/components?q=lodash",
		} {
			status, body := f.as(t, me.session, http.MethodGet, path)
			if status != http.StatusOK {
				t.Errorf("%s GET %s = %d, want 200", me.login, path, status)
			}
			if strings.Contains(body, other.repo.Name) || strings.Contains(body, other.scan.CommitSHA) {
				t.Errorf("%s GET %s leaks %s's repository: %s", me.login, path, other.login, body)
			}
		}
		if _, body := f.as(t, me.session, http.MethodGet, "/api/me/tracked"); !strings.Contains(body, me.repo.Name) {
			t.Errorf("%s does not see their own tracked repository", me.login)
		}

		repo, scan := jsonID(other.repo.ID), jsonID(other.scan.ID)
		for _, path := range []string{
			"/api/repos/" + repo,
			"/api/repos/" + repo + "/scans",
			"/api/repos/" + repo + "/drift",
			"/api/repos/" + repo + "/pulls",
			"/api/scans/" + scan,
			"/api/scans/" + scan + "/components",
			"/api/scans/" + scan + "/drift",
			"/api/scans/" + scan + "/vulnerabilities",
			"/api/scans/" + scan + "/vulnerability-changes",
			"/api/scans/" + scan + "/risk",
			"/api/scans/" + scan + "/sbom",
			"/api/scans/" + scan + "/report?format=csv",
			"/api/scans/" + scan + "/report?format=pdf",
			"/api/me/scans?repositoryId=" + repo,
		} {
			if status, body := f.as(t, me.session, http.MethodGet, path); status != http.StatusNotFound || strings.Contains(body, other.repo.Name) {
				t.Errorf("%s GET %s = %d %q, want a bare 404", me.login, path, status, body)
			}
		}
		requested := len(f.scans.requested)
		for _, write := range [][2]string{
			{http.MethodPost, "/api/repos/" + repo + "/scans"},
			{http.MethodPut, "/api/me/tracked/" + repo},
			{http.MethodDelete, "/api/me/tracked/" + repo},
		} {
			if status, _ := f.as(t, me.session, write[0], write[1]); status != http.StatusNotFound {
				t.Errorf("%s %s %s = %d, want 404", me.login, write[0], write[1], status)
			}
		}
		if len(f.scans.requested) != requested {
			t.Errorf("%s's request queued a scan of %s's repository", me.login, other.login)
		}

		// Their own repository can be scanned.
		if status, _ := f.as(t, me.session, http.MethodPost, "/api/repos/"+jsonID(me.repo.ID)+"/scans"); status != http.StatusAccepted {
			t.Errorf("%s scanning their own repository = %d, want 202", me.login, status)
		}
	}
	if got := f.scans.requested; len(got) != 2 || got[0] != alice.repo.ID || got[1] != bob.repo.ID {
		t.Errorf("scans requested for %v, want only each user's own [%d %d]", got, alice.repo.ID, bob.repo.ID)
	}
}

// A user GitHub lists nothing for, such as someone who signed in but has not
// installed the App, sees an empty dashboard rather than anyone else's data.
func TestNewUserWithoutAnInstallationSeesNothing(t *testing.T) {
	f, alice, bob := newTenants(t)
	newcomer := newSession(t, f.db, 8199, "newcomer")

	// Open sign-in is still sign-in: without a session there is nothing.
	anonymous := httptest.NewRecorder()
	f.handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/me/repositories", nil))
	if got := strings.TrimRight(anonymous.Body.String(), "\n"); anonymous.Code != http.StatusUnauthorized ||
		got != `{"error":"authentication required"}` {
		t.Errorf("anonymous GET /api/me/repositories = %d %q, want 401 with the sign-in refusal", anonymous.Code, got)
	}

	for _, path := range []string{"/api/repos?access=all", "/api/me/repositories", "/api/me/tracked", "/api/me/scans",
		"/api/impact/vulnerabilities", "/api/impact/components?q=lodash"} {
		status, body := f.as(t, newcomer, http.MethodGet, path)
		if status != http.StatusOK || strings.Contains(body, alice.repo.Name) || strings.Contains(body, bob.repo.Name) {
			t.Errorf("newcomer GET %s = %d %s, want 200 and nobody's repositories", path, status, body)
		}
	}
	if status, _ := f.as(t, newcomer, http.MethodPost, "/api/repos/"+jsonID(alice.repo.ID)+"/scans"); status != http.StatusNotFound {
		t.Errorf("newcomer scanning alice's repository = %d, want 404", status)
	}
}

// Each user downloads the SBOM report of their own scan, as CSV or PDF, as an
// attachment no shared cache keeps. It names their repository and component,
// and nothing of the other user's.
func TestTenantsDownloadOnlyTheirOwnReports(t *testing.T) {
	f, alice, bob := newTenants(t)

	for _, pair := range [][2]tenant{{alice, bob}, {bob, alice}} {
		me, other := pair[0], pair[1]
		for _, format := range []struct{ name, contentType, magic string }{
			{"csv", "text/csv; charset=utf-8", "name,version,ecosystem"},
			{"pdf", "application/pdf", "%PDF-1.4"},
		} {
			request := httptest.NewRequest(http.MethodGet, "/api/scans/"+jsonID(me.scan.ID)+"/report?format="+format.name, nil)
			request.AddCookie(me.session)
			recorder := httptest.NewRecorder()
			f.handler.ServeHTTP(recorder, request)
			body := recorder.Body.String()

			if recorder.Code != http.StatusOK || !strings.HasPrefix(body, format.magic) {
				t.Fatalf("%s %s report = %d %.40q, want 200 and a %s file", me.login, format.name, recorder.Code, body, format.name)
			}
			header := recorder.Header()
			wantName := fmt.Sprintf(`attachment; filename="sbomdelta-%s-%s.%s"`, me.repo.Name, me.scan.CommitSHA[:7], format.name)
			if header.Get("Content-Type") != format.contentType || header.Get("Content-Disposition") != wantName ||
				header.Get("Cache-Control") != "private, no-store" || header.Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Errorf("%s %s report headers = %v", me.login, format.name, header)
			}
			if !strings.Contains(body, "lodash") || (format.name == "pdf" && !strings.Contains(body, me.login+"/"+me.repo.Name)) {
				t.Errorf("%s %s report does not show their own scan", me.login, format.name)
			}
			if strings.Contains(body, other.repo.Name) || strings.Contains(body, other.scan.CommitSHA) {
				t.Errorf("%s %s report leaks %s's repository", me.login, format.name, other.login)
			}
		}
	}

	for _, format := range []string{"", "json", "PDF", "../pdf"} {
		status, body := f.as(t, alice.session, http.MethodGet, "/api/scans/"+jsonID(alice.scan.ID)+"/report?format="+url.QueryEscape(format))
		if status != http.StatusBadRequest || !strings.Contains(body, "format must be csv or pdf") {
			t.Errorf("report format %q = %d %s, want 400", format, status, body)
		}
	}

	// A scan still running has nothing to report yet.
	pending, err := f.db.CreateScan(context.Background(), models.Scan{
		RepositoryID: alice.repo.ID, CommitSHA: strings.Repeat("9", 40), Trigger: models.TriggerManual,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if status, body := f.as(t, alice.session, http.MethodGet, "/api/scans/"+jsonID(pending.ID)+"/report?format=pdf"); status != http.StatusConflict {
		t.Errorf("report of a pending scan = %d %s, want 409", status, body)
	}
}
