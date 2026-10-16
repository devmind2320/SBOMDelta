package storage_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

// These tests exercise the real schema. They are skipped unless
// TEST_DATABASE_URL points at a throwaway database:
//
//	docker compose up -d postgres
//	TEST_DATABASE_URL='postgres://sbomdelta:sbomdelta@localhost:5432/sbomdelta?sslmode=disable' go test ./internal/storage/...
//
// The database is truncated between tests, so never point this at anything
// you care about.
func newTestDB(t *testing.T) *storage.DB {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}

	ctx := context.Background()
	db, err := storage.Open(ctx, url)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	truncate(t, db)
	return db
}

// truncate deliberately leaves the jobs table alone: the queue package's tests
// own it, and `go test ./...` runs the two packages concurrently against the
// same database.
func truncate(t *testing.T, db *storage.DB) {
	t.Helper()
	_, err := db.Pool().Exec(context.Background(), `
		TRUNCATE installations, repositories, commits, pull_requests, scans,
		         components, drift_events, vulnerabilities, webhook_deliveries
		RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// seedRepository creates the installation and repository other tests build on.
func seedRepository(t *testing.T, db *storage.DB) models.Repository {
	t.Helper()
	ctx := context.Background()

	installation, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 4242,
		AccountLogin:         "acme",
		AccountType:          "Organization",
	})
	if err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	repo, err := db.UpsertRepository(ctx, models.Repository{
		InstallationID: &installation.ID,
		GitHubRepoID:   githubRepoID(99001),
		Owner:          "acme",
		Name:           "payments-api",
		DefaultBranch:  "main",
	})
	if err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}
	return repo
}

func githubRepoID(id int64) *int64 { return &id }

func component(purl string) sbom.Component {
	identity, version, ecosystem, name := sbom.ParseIdentity(purl)
	return sbom.Component{
		PURL: purl, Identity: identity, Name: name,
		Version: version, Ecosystem: ecosystem, Type: "library",
	}
}

// TestMigrateIsIdempotent proves a second deploy of the same build does not
// try to re-apply the schema.
func TestMigrateIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	if err := db.Migrate(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
}

func TestUpsertRepositoryHandlesRename(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	// GitHub keeps the numeric ID stable across a rename, so the same row must
	// be updated rather than a second one created.
	renamed, err := db.UpsertRepository(ctx, models.Repository{
		GitHubRepoID:  githubRepoID(99001),
		Owner:         "acme",
		Name:          "billing-api",
		DefaultBranch: "main",
	})
	if err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}
	if renamed.ID != repo.ID {
		t.Errorf("id = %d, want the original %d", renamed.ID, repo.ID)
	}
	if renamed.Name != "billing-api" {
		t.Errorf("name = %q, want %q", renamed.Name, "billing-api")
	}
	// A rename must not orphan the installation link the worker needs.
	if renamed.InstallationID == nil {
		t.Error("installation link was lost on rename")
	}
}

// A redelivered webhook must reuse the existing scan rather than create a
// duplicate; this is the constraint the whole retry story rests on.
func TestCreateScanIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	first, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "abc123", BaseCommitSHA: "def456", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	second, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "abc123", BaseCommitSHA: "def456", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("second CreateScan() error = %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("second scan id = %d, want the existing %d", second.ID, first.ID)
	}
	if second.BaseCommitSHA != "def456" {
		t.Errorf("base commit = %q, want it preserved", second.BaseCommitSHA)
	}
}

// The same commit can legitimately be scanned both as a push and as a PR head;
// those are different questions and must not collide.
func TestCreateScanSeparatesPushFromPullRequest(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: repo.ID, Number: 42, Title: "Bump deps",
		State: "open", BaseSHA: "base111", HeadSHA: "abc123",
	})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}

	push, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "abc123", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan(push) error = %v", err)
	}
	prScan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "abc123", PullRequestID: &pr.ID,
		BaseCommitSHA: "base111", Trigger: models.TriggerPullRequest,
	})
	if err != nil {
		t.Fatalf("CreateScan(pr) error = %v", err)
	}
	if push.ID == prScan.ID {
		t.Error("the push scan and the pull request scan collapsed into one row")
	}
}

func TestSaveScanResultPersistsComponentsAndDrift(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "head999", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	base := []sbom.Component{component("pkg:npm/axios@1.6.0"), component("pkg:npm/left-pad@1.3.0")}
	head := []sbom.Component{component("pkg:npm/axios@1.7.0"), component("pkg:npm/express@4.18.2")}
	head[0].Licenses = []string{"MIT"}
	head[1].LicenseExpression = "MIT OR Apache-2.0"
	head[1].Direct = true

	comparison := diff.Compare(base, head)
	if err := db.SaveScanResult(ctx, storage.ScanResult{
		ScanID:       scan.ID,
		SBOMLocation: "s3://sbomdelta/sboms/repo-1/head999/cyclonedx.json",
		SBOMSHA256:   "0f1e2d",
		Components:   head,
		Diff:         comparison,
	}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	stored, err := db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error = %v", err)
	}
	if stored.Status != models.ScanCompleted {
		t.Errorf("status = %q, want %q", stored.Status, models.ScanCompleted)
	}
	if stored.ComponentCount != 2 {
		t.Errorf("component count = %d, want 2", stored.ComponentCount)
	}

	components, err := db.ListComponents(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListComponents() error = %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("components = %d, want 2", len(components))
	}
	// The identity has to survive the round trip, or the next scan's diff
	// would match nothing.
	for _, stored := range components {
		if stored.Identity == "" {
			t.Errorf("component %q came back with no identity", stored.PURL)
		}
	}
	if components[0].Name == "axios" && len(components[0].Licenses) != 1 {
		t.Errorf("axios licenses = %v, want [MIT]", components[0].Licenses)
	}

	events, err := db.ListDriftEvents(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListDriftEvents() error = %v", err)
	}
	// express added, axios updated, left-pad removed.
	if len(events) != 3 {
		t.Fatalf("drift events = %d, want 3; got %+v", len(events), events)
	}

	byType := make(map[string]models.DriftEvent, len(events))
	for _, event := range events {
		byType[event.ChangeType] = event
	}
	if updated := byType["updated"]; updated.OldVersion != "1.6.0" || updated.NewVersion != "1.7.0" {
		t.Errorf("updated event = %s -> %s, want 1.6.0 -> 1.7.0", updated.OldVersion, updated.NewVersion)
	}
	if updated := byType["updated"]; updated.Direction != string(diff.DirectionUpgrade) {
		t.Errorf("direction = %q, want %q", updated.Direction, diff.DirectionUpgrade)
	}
	if added := byType["added"]; added.Name != "express" {
		t.Errorf("added event = %q, want express", added.Name)
	}
}

// Re-running a scan after a transient failure must replace its projection
// rather than trip the unique constraints.
func TestSaveScanResultIsRepeatable(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "retry01", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	head := []sbom.Component{component("pkg:npm/axios@1.7.0")}
	result := storage.ScanResult{
		ScanID:     scan.ID,
		Components: head,
		Diff:       diff.Compare([]sbom.Component{component("pkg:npm/axios@1.6.0")}, head),
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := db.SaveScanResult(ctx, result); err != nil {
			t.Fatalf("SaveScanResult() attempt %d error = %v", attempt, err)
		}
	}

	components, err := db.ListComponents(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListComponents() error = %v", err)
	}
	if len(components) != 1 {
		t.Errorf("components = %d after two saves, want 1", len(components))
	}
	events, err := db.ListDriftEvents(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListDriftEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Errorf("drift events = %d after two saves, want 1", len(events))
	}
}

// The baseline for a push is the previous default-branch scan. Pull request
// scans describe proposals, not branch state, so they must never be picked.
func TestLatestCompletedScanIgnoresPullRequestScans(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	older, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "old111", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: older.ID}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{
		RepositoryID: repo.ID, Number: 7, State: "open", BaseSHA: "old111", HeadSHA: "prhead",
	})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}
	prScan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "prhead", PullRequestID: &pr.ID, Trigger: models.TriggerPullRequest,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: prScan.ID}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}

	current, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "new222", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	base, err := db.LatestCompletedScan(ctx, repo.ID, current.ID, time.Now())
	if err != nil {
		t.Fatalf("LatestCompletedScan() error = %v", err)
	}
	if base.ID != older.ID {
		t.Errorf("base scan = %d, want the push scan %d (not the PR scan %d)", base.ID, older.ID, prScan.ID)
	}
}

func TestLatestCompletedScanReportsNoBaseline(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "first01", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	_, err = db.LatestCompletedScan(ctx, repo.ID, scan.ID, time.Now())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want storage.ErrNotFound", err)
	}
}

// An in-flight scan is not a valid baseline; only completed ones are.
func TestCompletedScanForCommitIgnoresUnfinishedScans(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "base777", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.MarkScanRunning(ctx, scan.ID); err != nil {
		t.Fatalf("MarkScanRunning() error = %v", err)
	}

	if _, err := db.CompletedScanForCommit(ctx, repo.ID, "base777"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want storage.ErrNotFound while the scan is running", err)
	}

	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}
	found, err := db.CompletedScanForCommit(ctx, repo.ID, "base777")
	if err != nil {
		t.Fatalf("CompletedScanForCommit() error = %v", err)
	}
	if found.ID != scan.ID {
		t.Errorf("scan = %d, want %d", found.ID, scan.ID)
	}
}

func TestRecordWebhookDeliveryDetectsReplays(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	fresh, err := db.RecordWebhookDelivery(ctx, "delivery-1", "push", "")
	if err != nil {
		t.Fatalf("RecordWebhookDelivery() error = %v", err)
	}
	if !fresh {
		t.Error("first delivery reported as a replay")
	}

	fresh, err = db.RecordWebhookDelivery(ctx, "delivery-1", "push", "")
	if err != nil {
		t.Fatalf("second RecordWebhookDelivery() error = %v", err)
	}
	if fresh {
		t.Error("replayed delivery reported as fresh")
	}
}

func TestMarkScanFailedRecordsCause(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "bad0001", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.MarkScanFailed(ctx, scan.ID, "syft exited 1"); err != nil {
		t.Fatalf("MarkScanFailed() error = %v", err)
	}

	stored, err := db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error = %v", err)
	}
	if stored.Status != models.ScanFailed || stored.Error != "syft exited 1" {
		t.Errorf("scan = %q / %q, want failed / %q", stored.Status, stored.Error, "syft exited 1")
	}
	if stored.FinishedAt == nil {
		t.Error("finished_at was not set on failure")
	}
}

func TestGetInstallationIDForRepo(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	installationID, err := db.GetInstallationIDForRepo(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetInstallationIDForRepo() error = %v", err)
	}
	if installationID != 4242 {
		t.Errorf("installation = %d, want 4242", installationID)
	}

	// An uninstalled app must stop granting access to its old repositories.
	if err := db.MarkInstallationDeleted(ctx, 4242); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}
	if _, err := db.GetInstallationIDForRepo(ctx, repo.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want storage.ErrNotFound after uninstall", err)
	}
}
