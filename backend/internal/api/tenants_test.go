package api_test

import (
	"context"
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
