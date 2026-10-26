package github

import (
	"context"
	"slices"
	"testing"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/storage"
)

// An installation on an account outside ALLOWED_INSTALLATION_ACCOUNTS: the
// kind anyone can create once the App is public.
const (
	strangerInstallationID = 7777
	strangerAccountID      = 5555
)

func strangerInstallation() *gh.Installation {
	return &gh.Installation{
		ID:      gh.Int64(strangerInstallationID),
		Account: &gh.User{Login: gh.String("stranger"), ID: gh.Int64(strangerAccountID), Type: gh.String("Organization")},
	}
}

func strangerRepo(id int64, name string) *gh.Repository {
	return &gh.Repository{ID: gh.Int64(id), FullName: gh.String("stranger/" + name), Name: gh.String(name)}
}

// strangerPush and strangerPullRequest are real-shaped payloads: like every
// push and pull request, they carry only the installation's ID.
func strangerPush() *gh.PushEvent {
	event := pushEvent(6001, "big-monorepo")
	event.Repo.Owner = &gh.User{Name: gh.String("stranger"), Login: gh.String("stranger")}
	event.Installation = &gh.Installation{ID: gh.Int64(strangerInstallationID)}
	return event
}

func strangerPullRequest() *gh.PullRequestEvent {
	event := pullRequestEvent("opened", 3, "3333333333333333333333333333333333333333", false)
	event.Repo.ID = gh.Int64(6002)
	event.Repo.Owner = &gh.User{Login: gh.String("stranger")}
	event.Installation = &gh.Installation{ID: gh.Int64(strangerInstallationID)}
	return event
}

func count(t *testing.T, db *storage.DB, query string) int {
	t.Helper()
	var n int
	if err := db.Pool().QueryRow(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func allJobs(t *testing.T, db *storage.DB) int  { return count(t, db, `SELECT COUNT(*) FROM jobs`) }
func allScans(t *testing.T, db *storage.DB) int { return count(t, db, `SELECT COUNT(*) FROM scans`) }
func allRepos(t *testing.T, db *storage.DB) int {
	return count(t, db, `SELECT COUNT(*) FROM repositories`)
}

func installationRow(t *testing.T, db *storage.DB, githubInstallationID int64) models.Installation {
	t.Helper()
	installation, err := db.GetInstallationByGitHubID(context.Background(), githubInstallationID)
	if err != nil {
		t.Fatalf("GetInstallationByGitHubID(%d) error = %v", githubInstallationID, err)
	}
	return installation
}

// An unapproved installation is recorded with its stable account ID, so it
// can be audited, approved later and uninstalled, but nothing it sends queues
// a job, creates a scan or stores its repositories.
func TestUnapprovedInstallationIsRecordedButQueuesNothing(t *testing.T) {
	h, db := newTestHandler(t)

	dispatch(t, h, &gh.InstallationEvent{
		Action:       gh.String("created"),
		Installation: strangerInstallation(),
		Repositories: []*gh.Repository{strangerRepo(6001, "big-monorepo"), strangerRepo(6002, "web")},
	})
	got := installationRow(t, db, strangerInstallationID)
	if got.AccountLogin != "stranger" || got.AccountID != strangerAccountID || got.DeletedAt != nil {
		t.Fatalf("installation = %+v, want it recorded with account stranger (%d)", got, strangerAccountID)
	}

	dispatch(t, h, &gh.InstallationRepositoriesEvent{
		Action:            gh.String("added"),
		RepositoriesAdded: []*gh.Repository{strangerRepo(6003, "docs")},
		Installation:      strangerInstallation(),
	})
	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("new_permissions_accepted"), Installation: strangerInstallation()})
	dispatch(t, h, strangerPush())
	dispatch(t, h, strangerPullRequest())

	if n := allJobs(t, db); n != 0 {
		t.Errorf("jobs = %d, want none queued for an unapproved installation", n)
	}
	if n := allScans(t, db); n != 0 {
		t.Errorf("scans = %d, want none created for an unapproved installation", n)
	}
	if n := allRepos(t, db); n != 0 {
		t.Errorf("repositories = %d, want none stored for an unapproved installation", n)
	}

	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("deleted"), Installation: strangerInstallation()})
	if installationRow(t, db, strangerInstallationID).DeletedAt == nil {
		t.Error("uninstalling an unapproved installation was not recorded")
	}
}

// The approved installation keeps today's behaviour: installing queues a
// reconciliation, and pushes and pull requests queue scans.
func TestApprovedInstallationQueuesWork(t *testing.T) {
	h, db := newTestHandler(t)

	dispatch(t, h, &gh.InstallationEvent{
		Action:       gh.String("created"),
		Installation: testInstallation(),
		Repositories: []*gh.Repository{eventRepo(1001, "devmind2320/api")},
	})
	if got := installationRow(t, db, testInstallationID).AccountID; got != testAccountID {
		t.Errorf("account ID = %d, want %d recorded from the installation event", got, testAccountID)
	}
	if n := reconcileJobs(t, db); n != 1 {
		t.Errorf("reconcile jobs = %d, want 1", n)
	}

	dispatch(t, h, pushEvent(1001, "api"))
	pull := pullRequestEvent("opened", 7, "4444444444444444444444444444444444444444", false)
	pull.Repo.ID = gh.Int64(1001)
	dispatch(t, h, pull)
	if n := count(t, db, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan'`); n != 2 {
		t.Errorf("scan jobs = %d, want one for the push and one for the pull request", n)
	}
}

// An empty allowlist approves nothing, not even the account that used to be
// the only one: the gate fails closed.
func TestEmptyAllowlistApprovesNoInstallation(t *testing.T) {
	_, db := newTestHandler(t)
	h := NewWebhookHandler("unused", nil, db, testQueue(db), discardLogger())

	dispatch(t, h, &gh.InstallationEvent{
		Action:       gh.String("created"),
		Installation: testInstallation(),
		Repositories: []*gh.Repository{eventRepo(1001, "devmind2320/api")},
	})
	addRepos(t, h, eventRepo(1002, "devmind2320/web"))
	dispatch(t, h, pushEvent(1001, "api"))
	dispatch(t, h, pullRequestEvent("opened", 7, "4444444444444444444444444444444444444444", false))

	lister := &fakeLister{repos: []*gh.Repository{apiRepo(1001, "api")}}
	if err := NewReconciler(lister, nil, db, testQueue(db), discardLogger()).
		Reconcile(context.Background(), testInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	if n := allJobs(t, db); n != 0 {
		t.Errorf("jobs = %d, want none with an empty allowlist", n)
	}
	if n := allScans(t, db); n != 0 {
		t.Errorf("scans = %d, want none with an empty allowlist", n)
	}
	if lister.calls != 0 {
		t.Errorf("GitHub was listed %d times, want 0 with an empty allowlist", lister.calls)
	}
}

// Reconciliation, which also runs for every installation at worker start,
// neither lists an unapproved installation's repositories nor queues its
// initial scans.
func TestReconcileSkipsUnapprovedInstallation(t *testing.T) {
	_, db := newTestHandler(t)
	ctx := context.Background()
	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: strangerInstallationID, AccountLogin: "stranger", AccountID: strangerAccountID, AccountType: "Organization",
	}); err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	lister := &fakeLister{repos: []*gh.Repository{apiRepo(6001, "big-monorepo")}}
	if err := NewReconciler(lister, testAllowedAccounts, db, testQueue(db), discardLogger()).
		Reconcile(ctx, strangerInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if lister.calls != 0 {
		t.Errorf("GitHub was listed %d times, want 0 for an unapproved installation", lister.calls)
	}
	if n := allJobs(t, db); n != 0 {
		t.Errorf("jobs = %d, want no initial scans for an unapproved installation", n)
	}
	if n := allRepos(t, db); n != 0 {
		t.Errorf("repositories = %d, want none stored for an unapproved installation", n)
	}
}

// A row from before account IDs were stored has none. Until reconciliation
// asks GitHub whose installation it is, its pushes queue nothing; once GitHub
// names an approved account, it works as before. One GitHub names as someone
// else's stays shut.
func TestInstallationWithoutAccountIDIsUnapprovedUntilReconciled(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: testInstallationID, AccountLogin: "devmind2320", AccountType: "User",
	}); err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	dispatch(t, h, pushEvent(1001, "api"))
	if n := allJobs(t, db); n != 0 {
		t.Fatalf("jobs = %d, want none before the account is known", n)
	}

	lister := &fakeLister{repos: []*gh.Repository{apiRepo(1001, "api")}}
	if err := NewReconciler(lister, testAllowedAccounts, db, testQueue(db), discardLogger()).
		Reconcile(ctx, testInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if got := installationRow(t, db, testInstallationID).AccountID; got != testAccountID {
		t.Fatalf("account ID = %d, want %d learned from GitHub", got, testAccountID)
	}
	if lister.calls != 1 {
		t.Errorf("GitHub was listed %d times, want 1 once the account is approved", lister.calls)
	}
	if n := count(t, db, `SELECT COUNT(*) FROM jobs WHERE kind = 'initial_scan'`); n != 1 {
		t.Errorf("initial scan jobs = %d, want 1", n)
	}

	dispatch(t, h, &gh.PushEvent{
		Ref: gh.String("refs/heads/trunk"), Before: gh.String("6666666666666666666666666666666666666666"),
		After: gh.String("7777777777777777777777777777777777777777"),
		Repo: &gh.PushEventRepository{
			ID: gh.Int64(1001), Name: gh.String("api"), DefaultBranch: gh.String("trunk"),
			Owner: &gh.User{Name: gh.String("devmind2320"), Login: gh.String("devmind2320")},
		},
		HeadCommit:   &gh.HeadCommit{Message: gh.String("bump deps")},
		Installation: &gh.Installation{ID: gh.Int64(testInstallationID)},
	})
	if n := count(t, db, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan'`); n != 1 {
		t.Errorf("scan jobs = %d, want the push scanned once the account is approved", n)
	}

	// The same kind of row, but GitHub says it belongs to someone else.
	if _, err := db.EnsureInstallation(ctx, strangerInstallationID, "stranger", "Organization", 0); err != nil {
		t.Fatalf("EnsureInstallation() error = %v", err)
	}
	lister = &fakeLister{repos: []*gh.Repository{apiRepo(6001, "big-monorepo")}, account: strangerAccountID}
	if err := NewReconciler(lister, testAllowedAccounts, db, testQueue(db), discardLogger()).
		Reconcile(ctx, strangerInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if got := installationRow(t, db, strangerInstallationID).AccountID; got != strangerAccountID {
		t.Errorf("account ID = %d, want %d learned from GitHub", got, strangerAccountID)
	}
	if lister.calls != 0 {
		t.Errorf("GitHub was listed %d times, want 0 for an installation GitHub names as unapproved", lister.calls)
	}
}

// Taking an account off the allowlist stops new work, but GitHub removing a
// repository from it still revokes access: that only ever takes work away.
func TestRemovalStillRevokesForAnUnapprovedInstallation(t *testing.T) {
	h, db := newTestHandler(t)
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	if _, err := db.Pool().Exec(context.Background(), `DELETE FROM jobs`); err != nil {
		t.Fatal(err)
	}

	removed := NewWebhookHandler("unused", []int64{strangerAccountID}, db, testQueue(db), discardLogger())
	dispatch(t, removed, &gh.InstallationRepositoriesEvent{
		Action:              gh.String("removed"),
		RepositoriesRemoved: []*gh.Repository{eventRepo(1001, "devmind2320/api")},
		Installation:        testInstallation(),
	})
	if got := repoByName(t, db, "api").Access; got != models.AccessRevoked {
		t.Errorf("api access = %q, want revoked", got)
	}
	if n := allJobs(t, db); n != 0 {
		t.Errorf("jobs = %d, want no reconciliation for an unapproved installation", n)
	}
}

// A push or pull request with no installation at all cannot be attributed to
// an approved account, so it is ignored rather than scanned.
func TestEventWithoutInstallationQueuesNothing(t *testing.T) {
	h, db := newTestHandler(t)
	push := pushEvent(1001, "api")
	push.Installation = nil
	pull := pullRequestEvent("opened", 7, "4444444444444444444444444444444444444444", false)
	pull.Installation = nil

	dispatch(t, h, push)
	dispatch(t, h, pull)
	if n := allJobs(t, db); n != 0 {
		t.Errorf("jobs = %d, want none for events without an installation", n)
	}
	if n := allRepos(t, db); n != 0 {
		t.Errorf("repositories = %d, want none stored for events without an installation", n)
	}
}

// A worker start queues reconciliation for the approved installation and for
// one whose account is not yet known (that job is what asks GitHub whose it
// is), but none for an installation already known to be someone else's, nor
// for a deleted one. With an empty allowlist only the unknown one is queued,
// and Reconcile itself refuses it.
func TestStartupReconciliationSkipsKnownUnapprovedInstallations(t *testing.T) {
	_, db := newTestHandler(t)
	ctx := context.Background()
	const unknownInstallationID, deletedInstallationID = 8888, 9999
	for _, installation := range []models.Installation{
		{GitHubInstallationID: testInstallationID, AccountLogin: "devmind2320", AccountID: testAccountID, AccountType: "User"},
		{GitHubInstallationID: strangerInstallationID, AccountLogin: "stranger", AccountID: strangerAccountID, AccountType: "Organization"},
		{GitHubInstallationID: unknownInstallationID, AccountLogin: "legacy", AccountType: "User"},
		{GitHubInstallationID: deletedInstallationID, AccountLogin: "devmind2320", AccountID: testAccountID, AccountType: "User"},
	} {
		if _, err := db.UpsertInstallation(ctx, installation); err != nil {
			t.Fatalf("UpsertInstallation(%d) error = %v", installation.GitHubInstallationID, err)
		}
	}
	if err := db.MarkInstallationDeleted(ctx, deletedInstallationID); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}

	queued := func() []int64 {
		t.Helper()
		rows, err := db.Pool().Query(ctx, `
			SELECT (payload->>'githubInstallationId')::bigint FROM jobs
			WHERE kind = 'reconcile_installation' ORDER BY 1`)
		if err != nil {
			t.Fatalf("list reconcile jobs: %v", err)
		}
		defer rows.Close()
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan reconcile job: %v", err)
			}
			ids = append(ids, id)
		}
		return ids
	}

	if err := NewReconciler(&fakeLister{}, testAllowedAccounts, db, testQueue(db), discardLogger()).EnqueueStartup(ctx); err != nil {
		t.Fatalf("EnqueueStartup() error = %v", err)
	}
	if got, want := queued(), []int64{testInstallationID, unknownInstallationID}; !slices.Equal(got, want) {
		t.Errorf("reconciliations queued for %v, want %v (approved and unknown only)", got, want)
	}

	if _, err := db.Pool().Exec(ctx, `DELETE FROM jobs`); err != nil {
		t.Fatal(err)
	}
	if err := NewReconciler(&fakeLister{}, nil, db, testQueue(db), discardLogger()).EnqueueStartup(ctx); err != nil {
		t.Fatalf("EnqueueStartup() error = %v", err)
	}
	if got, want := queued(), []int64{unknownInstallationID}; !slices.Equal(got, want) {
		t.Errorf("with an empty allowlist, reconciliations queued for %v, want %v", got, want)
	}
}
