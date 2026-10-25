package scanner

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"sbomdelta/internal/config"
	"sbomdelta/internal/models"
	"sbomdelta/internal/storage/storagetest"
)

// A scan queued before access was revoked must not be attempted, and must not
// be left pending or retried: it is recorded as failed with the reason.
func TestRunRefusesRepositoryWithoutAccess(t *testing.T) {
	db := storagetest.Open(t, "test_scanner")
	ctx := context.Background()

	installation, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 4242, AccountLogin: "acme", AccountType: "Organization",
	})
	if err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}
	githubID := int64(99001)
	repo, err := db.UpsertRepository(ctx, models.Repository{
		InstallationID: &installation.ID, GitHubRepoID: &githubID,
		Owner: "acme", Name: "payments-api", DefaultBranch: "main",
	})
	if err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}
	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: "3333333333333333333333333333333333333333", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if _, err := db.MarkRepositoriesRevoked(ctx, installation.ID, []int64{githubID}); err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}

	// No app, blob store or generator: reaching any of them would panic,
	// which is exactly what this path must not do.
	s := New(db, nil, nil, nil, config.Scanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Run(ctx, scan.ID); err != nil {
		t.Fatalf("Run() error = %v, want nil so the job is not retried", err)
	}

	got, err := db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error = %v", err)
	}
	if got.Status != models.ScanFailed {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if !strings.Contains(got.Error, "no longer has access") {
		t.Errorf("error = %q, want it to explain the revoked access", got.Error)
	}
}

// Initial, manual and backfill scans never open a check run. The scanner has
// no GitHub app here, so reaching StartCheckRun would panic.
func TestOpenCheckRunSkipsScansNotCausedByAPushOrPullRequest(t *testing.T) {
	s := New(nil, nil, nil, nil, config.Scanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, trigger := range []models.ScanTrigger{models.TriggerInitial, models.TriggerManual, models.TriggerBackfill} {
		scan := models.Scan{ID: 1, CommitSHA: "3333333333333333333333333333333333333333", Trigger: trigger}
		if id := s.openCheckRun(context.Background(), s.logger, scan, models.Repository{}, repoAccess{installationID: 4242}); id != 0 {
			t.Errorf("%s scan opened check run %d, want none", trigger, id)
		}
	}
}
