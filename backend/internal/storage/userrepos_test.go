package storage_test

import (
	"context"
	"testing"
	"time"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

func seedUser(t *testing.T, db *storage.DB, githubID int64, login string) models.User {
	t.Helper()
	user, err := db.UpsertUser(context.Background(), models.User{GitHubUserID: githubID, Login: login})
	if err != nil {
		t.Fatalf("UpsertUser() error = %v", err)
	}
	return user
}

func listedRepo(githubID int64, owner, name string) models.AccessibleRepository {
	return models.AccessibleRepository{GitHubRepoID: githubID, GitHubInstallationID: 4242, Owner: owner, Name: name, Private: true}
}

// Access follows the user's list from GitHub, per user, and replacing or
// clearing that list takes access away again.
func TestRepositoryAccessFollowsTheUsersGitHubList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db) // github id 99001
	alice := seedUser(t, db, 1, "alice")
	bob := seedUser(t, db, 2, "bob")

	can := func(user models.User, repositoryID int64) bool {
		t.Helper()
		ok, err := db.CanAccessRepository(ctx, user.ID, repositoryID)
		if err != nil {
			t.Fatalf("CanAccessRepository() error = %v", err)
		}
		return ok
	}

	if err := db.ReplaceUserRepositories(ctx, alice.ID, []models.AccessibleRepository{listedRepo(99001, "acme", "payments-api")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !can(alice, repo.ID) || can(bob, repo.ID) {
		t.Errorf("access: alice %v bob %v, want only alice", can(alice, repo.ID), can(bob, repo.ID))
	}
	if can(alice, repo.ID+1000) {
		t.Error("a repository that does not exist is accessible")
	}

	all, err := db.ListRepositoriesForUser(ctx, alice.ID, storage.AccessFilterAll)
	if err != nil || len(all) != 1 || all[0].ID != repo.ID {
		t.Errorf("ListRepositoriesForUser(alice) = %+v (%v), want the repository", all, err)
	}
	none, err := db.ListRepositoriesForUser(ctx, bob.ID, storage.AccessFilterAll)
	if err != nil || len(none) != 0 {
		t.Errorf("ListRepositoriesForUser(bob) = %+v (%v), want none", none, err)
	}

	if err := db.ReplaceUserRepositories(ctx, alice.ID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if can(alice, repo.ID) {
		t.Error("access survived a list that no longer names the repository")
	}

	if err := db.ReplaceUserRepositories(ctx, alice.ID, []models.AccessibleRepository{listedRepo(99001, "acme", "payments-api")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.ClearUserRepositories(ctx, alice.ID, "rate_limited", time.Now()); err != nil {
		t.Fatal(err)
	}
	listing, err := db.UserRepositoryListing(ctx, alice.ID)
	if err != nil || listing.Error != "rate_limited" || listing.ListedAt == nil {
		t.Errorf("listing = %+v (%v), want rate_limited with a time", listing, err)
	}
	if can(alice, repo.ID) {
		t.Error("access survived a cleared list")
	}
}

// Tracked repositories show the latest scan in any state and the last one
// that completed, with that scan's dependency changes. A failed newer scan
// never replaces the completed results.
func TestTrackedRepositoriesShowLatestAndLastCompletedScans(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)
	alice := seedUser(t, db, 1, "alice")
	if err := db.ReplaceUserRepositories(ctx, alice.ID, []models.AccessibleRepository{listedRepo(99001, "acme", "payments-api")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.TrackRepository(ctx, alice.ID, repo.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.TrackRepository(ctx, alice.ID, repo.ID); err != nil {
		t.Fatalf("tracking twice: %v", err)
	}

	tracked, err := db.ListTrackedRepositories(ctx, alice.ID)
	if err != nil || len(tracked) != 1 || tracked[0].LatestScan != nil || tracked[0].LastCompletedScan != nil {
		t.Fatalf("before any scan = %+v (%v), want one repository, never scanned", tracked, err)
	}

	scan := func(sha string, trigger models.ScanTrigger) models.Scan {
		t.Helper()
		s, err := db.CreateScan(ctx, models.Scan{RepositoryID: repo.ID, CommitSHA: sha, Trigger: trigger})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := []sbom.Component{component("pkg:npm/axios@1.6.0"), component("pkg:npm/left-pad@1.3.0")}
	head := []sbom.Component{component("pkg:npm/axios@1.7.0"), component("pkg:npm/express@4.18.2")}

	first := scan("1111111111111111111111111111111111111111", models.TriggerInitial)
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: first.ID, Components: base, Diff: diff.Compare(nil, base)}); err != nil {
		t.Fatal(err)
	}
	tracked, _ = db.ListTrackedRepositories(ctx, alice.ID)
	if got := tracked[0]; got.LastCompletedScan == nil || got.LastCompletedScan.ID != first.ID || !got.Baseline {
		t.Errorf("after the first scan = %+v, want it completed and marked as a baseline", got)
	}

	second := scan("2222222222222222222222222222222222222222", models.TriggerManual)
	if err := db.SaveScanResult(ctx, storage.ScanResult{
		ScanID: second.ID, BaseScanID: &first.ID, Components: head, Diff: diff.Compare(base, head),
	}); err != nil {
		t.Fatal(err)
	}
	failed := scan("3333333333333333333333333333333333333333", models.TriggerManual)
	if err := db.MarkScanFailed(ctx, failed.ID, "clone failed"); err != nil {
		t.Fatal(err)
	}
	// A backfilled base scan is internal and never "the latest".
	scan("0000000000000000000000000000000000000000", models.TriggerBackfill)

	tracked, err = db.ListTrackedRepositories(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := tracked[0]
	if got.LatestScan == nil || got.LatestScan.ID != failed.ID || got.LatestScan.Status != models.ScanFailed || got.LatestScan.Error != "clone failed" {
		t.Errorf("latest scan = %+v, want the failed scan with its error", got.LatestScan)
	}
	if got.LastCompletedScan == nil || got.LastCompletedScan.ID != second.ID || got.LastCompletedScan.ComponentCount != 2 ||
		got.LastCompletedScan.FinishedAt == nil {
		t.Errorf("last completed scan = %+v, want scan %d with 2 components", got.LastCompletedScan, second.ID)
	}
	if got.Baseline || got.Added != 1 || got.Updated != 1 || got.Removed != 1 {
		t.Errorf("changes = baseline %v +%d ~%d -%d, want +1 ~1 -1 against the first scan", got.Baseline, got.Added, got.Updated, got.Removed)
	}

	page, total, err := db.ListUserRepositories(ctx, alice.ID, "", false, 10, 0)
	if err != nil || total != 1 || !page[0].Tracked || page[0].LatestScan == nil || page[0].LatestScan.ID != failed.ID {
		t.Errorf("All Repos = %+v total %d (%v), want it tracked with the failed scan latest", page, total, err)
	}
	// The failed rescan does not replace the last successful scan, whose
	// finish time All Repos shows as "last scanned".
	if len(page) == 1 && (page[0].LastCompletedScan == nil || page[0].LastCompletedScan.ID != second.ID ||
		page[0].LastCompletedScan.FinishedAt == nil || !page[0].LastCompletedScan.FinishedAt.Equal(*got.LastCompletedScan.FinishedAt)) {
		t.Errorf("All Repos last completed scan = %+v, want scan %d as in Tracked Repos", page[0].LastCompletedScan, second.ID)
	}

	// Another user tracking nothing sees nothing; a repository the user lost
	// access to drops out of their tracked list without losing the row.
	bob := seedUser(t, db, 2, "bob")
	if other, err := db.ListTrackedRepositories(ctx, bob.ID); err != nil || len(other) != 0 {
		t.Errorf("bob's tracked list = %+v (%v), want empty", other, err)
	}
	if err := db.ReplaceUserRepositories(ctx, alice.ID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if lost, err := db.ListTrackedRepositories(ctx, alice.ID); err != nil || len(lost) != 0 {
		t.Errorf("tracked list after losing access = %+v (%v), want empty", lost, err)
	}
	removed, err := db.UntrackRepository(ctx, alice.ID, repo.ID)
	if err != nil || !removed {
		t.Errorf("UntrackRepository() = %v, %v; want the row removed", removed, err)
	}
}

func TestRequeueFailedScanOnlyTouchesFailedScans(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := seedRepository(t, db)
	scan, err := db.CreateScan(ctx, models.Scan{RepositoryID: repo.ID, CommitSHA: "4444444444444444444444444444444444444444", Trigger: models.TriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.RequeueFailedScan(ctx, scan.ID); err != nil || ok {
		t.Errorf("requeue of a pending scan = %v, %v; want no change", ok, err)
	}
	if err := db.MarkScanFailed(ctx, scan.ID, "boom"); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.RequeueFailedScan(ctx, scan.ID); err != nil || !ok {
		t.Errorf("requeue of a failed scan = %v, %v; want it requeued", ok, err)
	}
	stored, _ := db.GetScan(ctx, scan.ID)
	if stored.Status != models.ScanPending || stored.Error != "" || stored.FinishedAt != nil {
		t.Errorf("requeued scan = %+v, want pending with no error or finish time", stored)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.RequeueFailedScan(ctx, scan.ID); err != nil || ok {
		t.Errorf("requeue of a completed scan = %v, %v; want no change", ok, err)
	}
}

// With sign-in disabled for local development, All Repos lists every stored
// repository in the same shape, untracked, with its latest and last
// completed scans; a failed rescan never replaces the completed one.
func TestDevelopmentListingCoversEveryStoredRepository(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	_, repos := impactFixture(t, db)

	first := completedScan(t, db, repos[0].ID, "a1", nil, "pkg:npm/lodash@4.17.20")
	failed, err := db.CreateScan(ctx, models.Scan{RepositoryID: repos[0].ID, CommitSHA: "a2", Trigger: models.TriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkScanFailed(ctx, failed.ID, "clone failed"); err != nil {
		t.Fatal(err)
	}

	page, total, err := db.ListAllRepositoryOverviews(ctx, "", 10, 0)
	if err != nil || total != 4 || len(page) != 4 {
		t.Fatalf("ListAllRepositoryOverviews() = %d rows, total %d, %v; want all 4", len(page), total, err)
	}
	api := page[0]
	if api.Name != "api" || api.RepositoryID == nil || *api.RepositoryID != repos[0].ID || api.Tracked || api.GitHubRepoID != 7000 {
		t.Errorf("first row = %+v, want acme/api, stored and untracked", api)
	}
	if api.LatestScan == nil || api.LatestScan.ID != failed.ID || api.LastCompletedScan == nil || api.LastCompletedScan.ID != first.ID {
		t.Errorf("scans = latest %+v, completed %+v; want the failed rescan latest and the first scan completed", api.LatestScan, api.LastCompletedScan)
	}
	if page[1].LatestScan != nil || page[1].LastCompletedScan != nil {
		t.Errorf("never-scanned row = %+v, want no scans", page[1])
	}

	if only, total, err := db.ListAllRepositoryOverviews(ctx, "WEB", 10, 0); err != nil || total != 1 || len(only) != 1 || only[0].Name != "web" {
		t.Errorf("search = %+v total %d (%v), want acme/web only", only, total, err)
	}
}
