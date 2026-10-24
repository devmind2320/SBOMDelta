package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sbomdelta/internal/api"
	"sbomdelta/internal/config"
	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
	"sbomdelta/internal/storage/storagetest"
)

type fixture struct {
	db      *storage.DB
	handler http.Handler
	active  models.Repository
	revoked models.Repository
	scan    models.Scan
}

// newFixture stores one active and one revoked App repository; the revoked
// one has a completed scan, which is the history that must stay reachable.
func newFixture(t *testing.T) fixture {
	t.Helper()
	db := storagetest.Open(t, "test_api")
	ctx := context.Background()

	installation, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 4242, AccountLogin: "devmind2320", AccountType: "User",
	})
	if err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}
	upsert := func(githubID int64, name string) models.Repository {
		repo, err := db.UpsertRepository(ctx, models.Repository{
			InstallationID: &installation.ID, GitHubRepoID: &githubID,
			Owner: "devmind2320", Name: name, DefaultBranch: "main",
		})
		if err != nil {
			t.Fatalf("UpsertRepository(%s) error = %v", name, err)
		}
		return repo
	}
	active := upsert(1001, "kept")
	revoked := upsert(1002, "dropped")

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: revoked.ID, CommitSHA: "4444444444444444444444444444444444444444", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}
	if _, err := db.MarkRepositoriesRevoked(ctx, installation.ID, []int64{1002}); err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := api.New(db, nil, queue.New(db.Pool(), time.Minute), config.Scanner{}, logger).
		Routes(http.NotFoundHandler())
	return fixture{db: db, handler: handler, active: active, revoked: revoked, scan: scan}
}

func (f fixture) do(t *testing.T, method, path, body string) (int, map[string]json.RawMessage) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)

	decoded := map[string]json.RawMessage{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("%s %s: decode body %q: %v", method, path, recorder.Body.String(), err)
	}
	return recorder.Code, decoded
}

func (f fixture) listNames(t *testing.T, path string) []string {
	t.Helper()
	status, body := f.do(t, http.MethodGet, path, "")
	if status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, status)
	}
	var repos []models.Repository
	if err := json.Unmarshal(body["repositories"], &repos); err != nil {
		t.Fatalf("decode repositories: %v", err)
	}
	names := make([]string, 0, len(repos))
	for _, repo := range repos {
		names = append(names, repo.Name+":"+string(repo.Access))
	}
	return names
}

func TestListRepositoriesFiltersByAccess(t *testing.T) {
	f := newFixture(t)

	tests := []struct {
		path string
		want string
	}{
		{"/api/repos", "kept:active"},
		{"/api/repos?access=active", "kept:active"},
		{"/api/repos?access=inactive", "dropped:revoked"},
		{"/api/repos?access=all", "dropped:revoked,kept:active"},
	}
	for _, tt := range tests {
		if got := strings.Join(f.listNames(t, tt.path), ","); got != tt.want {
			t.Errorf("GET %s = %q, want %q", tt.path, got, tt.want)
		}
	}

	if status, _ := f.do(t, http.MethodGet, "/api/repos?access=bogus", ""); status != http.StatusBadRequest {
		t.Errorf("unknown access filter status = %d, want 400", status)
	}
}

// Losing access hides a repository from the list, not from direct links: its
// page, scans and drift stay readable.
func TestRevokedRepositoryHistoryStaysReadable(t *testing.T) {
	f := newFixture(t)
	id := jsonID(f.revoked.ID)

	status, body := f.do(t, http.MethodGet, "/api/repos/"+id, "")
	if status != http.StatusOK {
		t.Fatalf("GET repository status = %d, want 200", status)
	}
	if string(body["access"]) != `"revoked"` {
		t.Errorf("access = %s, want \"revoked\"", body["access"])
	}

	status, body = f.do(t, http.MethodGet, "/api/repos/"+id+"/scans", "")
	if status != http.StatusOK {
		t.Fatalf("GET scans status = %d, want 200", status)
	}
	var scans []models.Scan
	if err := json.Unmarshal(body["scans"], &scans); err != nil {
		t.Fatalf("decode scans: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != f.scan.ID {
		t.Errorf("scans = %v, want the stored scan %d", scans, f.scan.ID)
	}

	if status, _ := f.do(t, http.MethodGet, "/api/repos/"+id+"/drift", ""); status != http.StatusOK {
		t.Errorf("GET drift status = %d, want 200", status)
	}
}

func TestTriggerScanRejectsRevokedRepository(t *testing.T) {
	f := newFixture(t)

	// A full SHA skips ref resolution, so the access check is all that stands
	// between this request and a queued scan.
	status, body := f.do(t, http.MethodPost, "/api/repos/"+jsonID(f.revoked.ID)+"/scans",
		`{"commitSha":"5555555555555555555555555555555555555555"}`)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", status)
	}
	if !strings.Contains(string(body["error"]), "no longer has access") {
		t.Errorf("error = %s, want it to explain the revoked access", body["error"])
	}

	var queued int
	if err := f.db.Pool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM jobs WHERE kind = 'scan'`).Scan(&queued); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if queued != 0 {
		t.Errorf("scan jobs = %d, want 0", queued)
	}
}

func jsonID(id int64) string {
	encoded, _ := json.Marshal(id)
	return string(encoded)
}
