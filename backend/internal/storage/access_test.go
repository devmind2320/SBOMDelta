package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

// seedScannedRepository creates a repository with one completed scan, so a
// test can check that access changes leave the history alone.
func seedScannedRepository(t *testing.T, db *storage.DB) (models.Repository, models.Scan) {
	t.Helper()
	ctx := context.Background()

	repo := seedRepository(t, db)
	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID,
		CommitSHA:    "1111111111111111111111111111111111111111",
		Trigger:      models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{
		ScanID:     scan.ID,
		Components: []sbom.Component{component("pkg:npm/lodash@4.17.21")},
	}); err != nil {
		t.Fatalf("SaveScanResult() error = %v", err)
	}
	return repo, scan
}

func repoIDs(repos []models.Repository) []int64 {
	ids := make([]int64, 0, len(repos))
	for _, repo := range repos {
		ids = append(ids, repo.ID)
	}
	return ids
}

func listIDs(t *testing.T, db *storage.DB, filter storage.AccessFilter) []int64 {
	t.Helper()
	repos, err := db.ListRepositories(context.Background(), filter)
	if err != nil {
		t.Fatalf("ListRepositories(%s) error = %v", filter, err)
	}
	return repoIDs(repos)
}

func assertHistoryIntact(t *testing.T, db *storage.DB, repo models.Repository, scan models.Scan) {
	t.Helper()
	ctx := context.Background()

	scans, err := db.ListScans(ctx, repo.ID, 10)
	if err != nil {
		t.Fatalf("ListScans() error = %v", err)
	}
	if len(scans) != 1 || scans[0].ID != scan.ID {
		t.Fatalf("scans = %v, want the original scan %d", scans, scan.ID)
	}
	components, err := db.ListComponents(ctx, scan.ID)
	if err != nil {
		t.Fatalf("ListComponents() error = %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("components = %d, want 1", len(components))
	}
}

func TestRepositoryFromAppIsActive(t *testing.T) {
	db := newTestDB(t)
	repo := seedRepository(t, db)

	if repo.Access != models.AccessActive {
		t.Errorf("access = %q, want %q", repo.Access, models.AccessActive)
	}
	if repo.AccessRevokedAt != nil {
		t.Errorf("accessRevokedAt = %v, want nil", repo.AccessRevokedAt)
	}
}

// Removing a repository from the App's selection must hide it from the active
// list without destroying a single scan.
func TestMarkRepositoriesRevokedPreservesHistory(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo, scan := seedScannedRepository(t, db)

	revoked, err := db.MarkRepositoriesRevoked(ctx, *repo.InstallationID, []int64{*repo.GitHubRepoID})
	if err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1", revoked)
	}

	got, err := db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.Access != models.AccessRevoked || got.AccessRevokedAt == nil {
		t.Errorf("access = %q (revokedAt %v), want revoked with a timestamp", got.Access, got.AccessRevokedAt)
	}
	if got.Accessible() {
		t.Error("Accessible() = true for a revoked repository")
	}

	if ids := listIDs(t, db, storage.AccessFilterActive); len(ids) != 0 {
		t.Errorf("active repositories = %v, want none", ids)
	}
	if ids := listIDs(t, db, storage.AccessFilterInactive); len(ids) != 1 || ids[0] != repo.ID {
		t.Errorf("inactive repositories = %v, want [%d]", ids, repo.ID)
	}
	if ids := listIDs(t, db, storage.AccessFilterAll); len(ids) != 1 {
		t.Errorf("all repositories = %v, want the one stored row", ids)
	}

	assertHistoryIntact(t, db, repo, scan)

	// Revoking again is a no-op rather than a fresh timestamp.
	again, err := db.MarkRepositoriesRevoked(ctx, *repo.InstallationID, []int64{*repo.GitHubRepoID})
	if err != nil {
		t.Fatalf("second MarkRepositoriesRevoked() error = %v", err)
	}
	if again != 0 {
		t.Errorf("second revoke affected %d rows, want 0", again)
	}
}

// A removal delivered for one installation must not revoke a repository that
// is now reached through a different one.
func TestMarkRepositoriesRevokedIsScopedToInstallation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	other, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 5151, AccountLogin: "other", AccountType: "User",
	})
	if err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	revoked, err := db.MarkRepositoriesRevoked(ctx, other.ID, []int64{*repo.GitHubRepoID})
	if err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}
	if revoked != 0 {
		t.Errorf("revoked = %d, want 0 for a repository owned by another installation", revoked)
	}
}

// Only events that prove access may restore it.
func TestUpsertAccessibleRepositoryRestoresAccess(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	if _, err := db.MarkRepositoriesRevoked(ctx, *repo.InstallationID, []int64{*repo.GitHubRepoID}); err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}

	// Re-adding the repository to the selection arrives as an upsert.
	restored, err := db.UpsertAccessibleRepository(ctx, models.Repository{
		InstallationID: repo.InstallationID,
		GitHubRepoID:   repo.GitHubRepoID,
		Owner:          repo.Owner,
		Name:           repo.Name,
		DefaultBranch:  repo.DefaultBranch,
	})
	if err != nil {
		t.Fatalf("UpsertAccessibleRepository() error = %v", err)
	}
	if restored.ID != repo.ID {
		t.Errorf("id = %d, want the existing %d", restored.ID, repo.ID)
	}
	if restored.Access != models.AccessActive || restored.AccessRevokedAt != nil {
		t.Errorf("access = %q (revokedAt %v), want active", restored.Access, restored.AccessRevokedAt)
	}
}

func TestAccessReflectsInstallationState(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	manual, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner: "sigstore", Name: "cosign", DefaultBranch: "main",
		CloneURL: "https://github.com/sigstore/cosign.git",
	})
	if err != nil {
		t.Fatalf("UpsertManualRepository() error = %v", err)
	}
	if manual.Access != models.AccessActive {
		t.Errorf("manual repository access = %q, want active", manual.Access)
	}

	suspendedAt := time.Now()
	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 4242, AccountLogin: "acme", AccountType: "Organization",
		SuspendedAt: &suspendedAt,
	}); err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}
	got, err := db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.Access != models.AccessSuspended {
		t.Errorf("access = %q, want suspended", got.Access)
	}

	if err := db.MarkInstallationDeleted(ctx, 4242); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}
	got, err = db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.Access != models.AccessUninstalled {
		t.Errorf("access = %q, want uninstalled", got.Access)
	}

	if ids := listIDs(t, db, storage.AccessFilterActive); len(ids) != 1 || ids[0] != manual.ID {
		t.Errorf("active repositories = %v, want only the manual one [%d]", ids, manual.ID)
	}

	usable, err := db.ListUsableInstallations(ctx)
	if err != nil {
		t.Fatalf("ListUsableInstallations() error = %v", err)
	}
	if len(usable) != 0 {
		t.Errorf("usable installations = %v, want none after uninstall", usable)
	}
}

func appRepo(installationID, githubID int64, name string) models.Repository {
	return models.Repository{
		InstallationID: &installationID,
		GitHubRepoID:   githubRepoID(githubID),
		Owner:          "acme",
		Name:           name,
		DefaultBranch:  "main",
	}
}

// The case that started this: narrowing an installation from "All
// repositories" to a selection. Whatever GitHub no longer lists is revoked,
// and its history is kept.
func TestReconcileRevokesUnlistedRepositories(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo, scan := seedScannedRepository(t, db)
	installationID := *repo.InstallationID

	if _, err := db.UpsertRepository(ctx, appRepo(installationID, 99002, "web")); err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}

	listedAt, err := db.Now(ctx)
	if err != nil {
		t.Fatalf("Now() error = %v", err)
	}
	result, err := db.ReconcileInstallationRepositories(ctx, installationID, []models.Repository{
		appRepo(installationID, 99002, "web"),
		appRepo(installationID, 99003, "new-service"),
	}, listedAt)
	if err != nil {
		t.Fatalf("ReconcileInstallationRepositories() error = %v", err)
	}
	if result.Accessible != 2 || result.Revoked != 1 {
		t.Errorf("result = %+v, want 2 accessible and 1 revoked", result)
	}

	got, err := db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.Access != models.AccessRevoked {
		t.Errorf("unlisted repository access = %q, want revoked", got.Access)
	}
	assertHistoryIntact(t, db, repo, scan)

	active, err := db.ListRepositories(ctx, storage.AccessFilterActive)
	if err != nil {
		t.Fatalf("ListRepositories() error = %v", err)
	}
	names := map[string]bool{}
	for _, r := range active {
		names[r.Name] = true
	}
	if len(active) != 2 || !names["web"] || !names["new-service"] {
		t.Errorf("active repositories = %v, want web and new-service", names)
	}
}

// GitHub really can report an installation with no repositories: the
// installer selected none. That is authoritative and revokes everything.
func TestReconcileWithEmptyListRevokesAll(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo, scan := seedScannedRepository(t, db)

	listedAt, err := db.Now(ctx)
	if err != nil {
		t.Fatalf("Now() error = %v", err)
	}
	result, err := db.ReconcileInstallationRepositories(ctx, *repo.InstallationID, nil, listedAt)
	if err != nil {
		t.Fatalf("ReconcileInstallationRepositories() error = %v", err)
	}
	if result.Revoked != 1 {
		t.Errorf("revoked = %d, want 1", result.Revoked)
	}
	assertHistoryIntact(t, db, repo, scan)
}

func TestReconcileRestoresListedRepository(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)
	installationID := *repo.InstallationID

	if _, err := db.MarkRepositoriesRevoked(ctx, installationID, []int64{*repo.GitHubRepoID}); err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}
	// Taken after the revocation: the listing is newer, so it wins.
	listedAt, err := db.Now(ctx)
	if err != nil {
		t.Fatalf("Now() error = %v", err)
	}
	if _, err := db.ReconcileInstallationRepositories(ctx, installationID, []models.Repository{
		appRepo(installationID, *repo.GitHubRepoID, repo.Name),
	}, listedAt); err != nil {
		t.Fatalf("ReconcileInstallationRepositories() error = %v", err)
	}

	got, err := db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.Access != models.AccessActive {
		t.Errorf("access = %q, want active after GitHub lists it again", got.Access)
	}
}

// A webhook processed while GitHub was being paged through is newer than the
// listing, and the stale listing must not undo it in either direction.
func TestReconcileDoesNotOverrideNewerWebhooks(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)
	installationID := *repo.InstallationID

	listedAt, err := db.Now(ctx)
	if err != nil {
		t.Fatalf("Now() error = %v", err)
	}

	// After listedAt: "payments-api" is removed, and "late" is added.
	if _, err := db.MarkRepositoriesRevoked(ctx, installationID, []int64{*repo.GitHubRepoID}); err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}
	late, err := db.UpsertRepository(ctx, appRepo(installationID, 99009, "late"))
	if err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}

	// The stale listing still includes payments-api and has never heard of late.
	if _, err := db.ReconcileInstallationRepositories(ctx, installationID, []models.Repository{
		appRepo(installationID, *repo.GitHubRepoID, repo.Name),
	}, listedAt); err != nil {
		t.Fatalf("ReconcileInstallationRepositories() error = %v", err)
	}

	got, err := db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.Access != models.AccessRevoked {
		t.Errorf("payments-api access = %q, want the newer revocation to stand", got.Access)
	}
	gotLate, err := db.GetRepository(ctx, late.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if gotLate.Access != models.AccessActive {
		t.Errorf("late access = %q, want the newer addition to stand", gotLate.Access)
	}
}

// A manually tracked repository that GitHub later lists is adopted, not
// duplicated, so its history carries over.
func TestReconcileAdoptsManualRepository(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	installation, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 4242, AccountLogin: "acme", AccountType: "Organization",
	})
	if err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}
	manual, err := db.UpsertManualRepository(ctx, models.Repository{
		Owner: "acme", Name: "tools", DefaultBranch: "main",
		CloneURL: "https://github.com/acme/tools.git",
	})
	if err != nil {
		t.Fatalf("UpsertManualRepository() error = %v", err)
	}

	listedAt, err := db.Now(ctx)
	if err != nil {
		t.Fatalf("Now() error = %v", err)
	}
	if _, err := db.ReconcileInstallationRepositories(ctx, installation.ID, []models.Repository{
		appRepo(installation.ID, 77001, "tools"),
	}, listedAt); err != nil {
		t.Fatalf("ReconcileInstallationRepositories() error = %v", err)
	}

	all := listIDs(t, db, storage.AccessFilterAll)
	if len(all) != 1 || all[0] != manual.ID {
		t.Errorf("repositories = %v, want the adopted row [%d]", all, manual.ID)
	}
}

// A push or pull request delivery for a revoked repository -- a redelivery,
// typically -- refreshes the row but must not quietly restore access.
func TestUpsertRepositoryPreservesRevocation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)

	if _, err := db.MarkRepositoriesRevoked(ctx, *repo.InstallationID, []int64{*repo.GitHubRepoID}); err != nil {
		t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
	}
	updated, err := db.UpsertRepository(ctx, models.Repository{
		InstallationID: repo.InstallationID, GitHubRepoID: repo.GitHubRepoID,
		Owner: repo.Owner, Name: repo.Name, DefaultBranch: "trunk",
	})
	if err != nil {
		t.Fatalf("UpsertRepository() error = %v", err)
	}
	if updated.Access != models.AccessRevoked {
		t.Errorf("access = %q, want revocation preserved", updated.Access)
	}
	if updated.DefaultBranch != "trunk" {
		t.Errorf("defaultBranch = %q, want the row itself refreshed", updated.DefaultBranch)
	}
}

func TestEnsureInstallationPreservesLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Unknown installation: created from the bare reference.
	created, err := db.EnsureInstallation(ctx, 777, "", "")
	if err != nil {
		t.Fatalf("EnsureInstallation() error = %v", err)
	}
	if created.AccountType != "User" {
		t.Errorf("accountType = %q, want the schema default User", created.AccountType)
	}

	suspendedAt := time.Now()
	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: 777, AccountLogin: "acme", AccountType: "Organization", SuspendedAt: &suspendedAt,
	}); err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	// A push payload: ID only.
	got, err := db.EnsureInstallation(ctx, 777, "", "")
	if err != nil {
		t.Fatalf("EnsureInstallation() error = %v", err)
	}
	if got.ID != created.ID || got.AccountLogin != "acme" || got.AccountType != "Organization" || got.SuspendedAt == nil {
		t.Errorf("after bare reference = %+v, want acme/Organization still suspended", got)
	}

	if err := db.MarkInstallationDeleted(ctx, 777); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}
	// An installation_repositories payload: full account, renamed.
	got, err = db.EnsureInstallation(ctx, 777, "acme-renamed", "Organization")
	if err != nil {
		t.Fatalf("EnsureInstallation() error = %v", err)
	}
	if got.AccountLogin != "acme-renamed" {
		t.Errorf("accountLogin = %q, want the non-empty login applied", got.AccountLogin)
	}
	if got.DeletedAt == nil {
		t.Error("deleted_at was cleared by a non-lifecycle event")
	}
}

func TestReconcileAbandonsUnusableInstallation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo, scan := seedScannedRepository(t, db)

	listedAt, err := db.Now(ctx)
	if err != nil {
		t.Fatalf("Now() error = %v", err)
	}
	if err := db.MarkInstallationDeleted(ctx, 4242); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}

	_, err = db.ReconcileInstallationRepositories(ctx, *repo.InstallationID, nil, listedAt)
	if !errors.Is(err, storage.ErrInstallationUnusable) {
		t.Fatalf("error = %v, want ErrInstallationUnusable", err)
	}
	got, err := db.GetRepository(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if got.AccessRevokedAt != nil {
		t.Errorf("accessRevokedAt = %v, want untouched by an abandoned reconciliation", got.AccessRevokedAt)
	}
	assertHistoryIntact(t, db, repo, scan)
}
