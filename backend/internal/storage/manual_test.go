package storage_test

import (
	"context"
	"errors"
	"testing"

	"sbomdelta/internal/models"
	"sbomdelta/internal/storage"
)

// A manually registered repository has no GitHub repo ID. The schema has to
// allow that, because the scan pipeline is useful without the App.
func TestUpsertManualRepository(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	repo, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner:         "sigstore",
		Name:          "cosign",
		DefaultBranch: "main",
		CloneURL:      "https://github.com/sigstore/cosign.git",
	})
	if err != nil {
		t.Fatalf("UpsertManualRepository() error = %v", err)
	}
	if repo.ID == 0 {
		t.Fatal("repository was not assigned an id")
	}
	if repo.GitHubRepoID != nil {
		t.Errorf("githubRepoId = %v, want nil for a manual repository", *repo.GitHubRepoID)
	}
	if repo.CloneURL != "https://github.com/sigstore/cosign.git" {
		t.Errorf("cloneUrl = %q, want it stored", repo.CloneURL)
	}

	// Re-registering is an update, not a duplicate.
	again, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner:         "sigstore",
		Name:          "cosign",
		DefaultBranch: "release",
		CloneURL:      "https://github.com/sigstore/cosign.git",
	})
	if err != nil {
		t.Fatalf("second UpsertManualRepository() error = %v", err)
	}
	if again.ID != repo.ID {
		t.Errorf("id = %d, want the existing %d", again.ID, repo.ID)
	}
	if again.DefaultBranch != "release" {
		t.Errorf("defaultBranch = %q, want it updated", again.DefaultBranch)
	}
}

// Several manual repositories coexist: Postgres permits duplicate NULLs under
// the UNIQUE constraint on github_repo_id, which is what makes this work.
func TestManualRepositoriesCoexist(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, name := range []string{"cosign", "rekor", "fulcio"} {
		if _, err := db.UpsertManualRepository(ctx, models.Repository{
			Owner: "sigstore", Name: name, DefaultBranch: "main",
			CloneURL: "https://github.com/sigstore/" + name + ".git",
		}); err != nil {
			t.Fatalf("UpsertManualRepository(%s) error = %v", name, err)
		}
	}

	repos, err := db.ListRepositories(ctx, storage.AccessFilterAll)
	if err != nil {
		t.Fatalf("ListRepositories() error = %v", err)
	}
	if len(repos) != 3 {
		t.Fatalf("repositories = %d, want 3", len(repos))
	}
}

// A manual repository has no installation, which is how the scanner decides to
// clone anonymously. ErrNotFound here is the expected signal, not a failure.
func TestManualRepositoryHasNoInstallation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	repo, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner: "sigstore", Name: "cosign", DefaultBranch: "main",
		CloneURL: "https://github.com/sigstore/cosign.git",
	})
	if err != nil {
		t.Fatalf("UpsertManualRepository() error = %v", err)
	}

	if _, err := db.GetInstallationIDForRepo(ctx, repo.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want storage.ErrNotFound for a manual repository", err)
	}
}

// Manual scans run through the same pipeline and the same idempotency rules as
// webhook-triggered ones.
func TestManualScanIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	repo, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner: "sigstore", Name: "cosign", DefaultBranch: "main",
		CloneURL: "https://github.com/sigstore/cosign.git",
	})
	if err != nil {
		t.Fatalf("UpsertManualRepository() error = %v", err)
	}

	const sha = "0123456789abcdef0123456789abcdef01234567"
	first, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: sha, Trigger: models.TriggerManual,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	second, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: sha, Trigger: models.TriggerManual,
	})
	if err != nil {
		t.Fatalf("second CreateScan() error = %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("re-triggering the same commit created scan %d, want the existing %d",
			second.ID, first.ID)
	}
	if first.Trigger != models.TriggerManual {
		t.Errorf("trigger = %q, want %q", first.Trigger, models.TriggerManual)
	}
}

// Adopting a manually tracked repository into the GitHub App later must keep
// the same row, so its scan history survives.
func TestManualRepositoryCanBeAdoptedByTheApp(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	manual, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner: "sigstore", Name: "cosign", DefaultBranch: "main",
		CloneURL: "https://github.com/sigstore/cosign.git",
	})
	if err != nil {
		t.Fatalf("UpsertManualRepository() error = %v", err)
	}

	installation, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 777, AccountLogin: "sigstore", AccountType: "Organization",
	})
	if err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	adopted, err := db.UpsertRepository(ctx, models.Repository{
		InstallationID: &installation.ID,
		GitHubRepoID:   githubRepoID(555001),
		Owner:          "sigstore",
		Name:           "cosign",
		DefaultBranch:  "main",
	})
	if err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}
	if adopted.ID != manual.ID {
		t.Errorf("adopted id = %d, want the existing %d; scan history would be orphaned",
			adopted.ID, manual.ID)
	}

	if _, err := db.GetInstallationIDForRepo(ctx, manual.ID); err != nil {
		t.Errorf("GetInstallationIDForRepo() error = %v, want the adopted installation", err)
	}
}
