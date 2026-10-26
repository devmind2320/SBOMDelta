package github

import (
	"context"
	"slices"
	"testing"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/storage"
)

// Someone else's installation: the kind anyone can create once the App is
// public. It is connected only when a test says a user signed in through it.
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

// An installation no SBOMDelta user has connected is recorded with its stable
// account ID, so it can be audited and its uninstall tracked, but nothing it
// sends queues a job, creates a scan or stores its repositories.
func TestUnconnectedInstallationIsRecordedButQueuesNothing(t *testing.T) {
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
		t.Errorf("jobs = %d, want none queued for an unconnected installation", n)
	}
	if n := allScans(t, db); n != 0 {
		t.Errorf("scans = %d, want none created for an unconnected installation", n)
	}
	if n := allRepos(t, db); n != 0 {
		t.Errorf("repositories = %d, want none stored for an unconnected installation", n)
	}

	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("deleted"), Installation: strangerInstallation()})
	if installationRow(t, db, strangerInstallationID).DeletedAt == nil {
		t.Error("uninstalling an unconnected installation was not recorded")
	}
}

// The test installation, which devmind2320 has connected, keeps today's
// behaviour: installing queues a reconciliation, and pushes and pull requests
// queue scans.
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

// A new user is not on any list: once they sign in and GitHub lists their
// installation for them, it works exactly like the owner's.
func TestAnyConnectedInstallationQueuesWork(t *testing.T) {
	h, db := newTestHandler(t)
	connect(t, db, 7002, "newcomer", strangerInstallationID)

	dispatch(t, h, &gh.InstallationEvent{
		Action:       gh.String("created"),
		Installation: strangerInstallation(),
		Repositories: []*gh.Repository{strangerRepo(6001, "big-monorepo")},
	})
	if n := reconcileJobs(t, db); n != 1 {
		t.Errorf("reconcile jobs = %d, want 1 for a connected installation", n)
	}
	dispatch(t, h, strangerPush())
	dispatch(t, h, strangerPullRequest())
	if n := count(t, db, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan'`); n != 2 {
		t.Errorf("scan jobs = %d, want one for the push and one for the pull request", n)
	}
}

// An operator's account allowlist still narrows the gate: a connected
// installation on another account queues nothing, the listed one does.
func TestAccountAllowlistNarrowsConnectedInstallations(t *testing.T) {
	_, db := newTestHandler(t)
	connect(t, db, 7002, "newcomer", strangerInstallationID)
	h := NewWebhookHandler("unused", testAllowedAccounts, db, testQueue(db), discardLogger())

	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("created"), Installation: strangerInstallation()})
	dispatch(t, h, strangerPush())
	if n := allJobs(t, db); n != 0 {
		t.Fatalf("jobs = %d, want none for an account outside the allowlist", n)
	}

	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("created"), Installation: testInstallation()})
	if n := reconcileJobs(t, db); n != 1 {
		t.Errorf("reconcile jobs = %d, want 1 for the listed account", n)
	}
}

// Reconciliation, which also runs for installations at worker start, neither
// lists an unconnected installation's repositories nor queues its initial
// scans; once a user connects it, it does both.
func TestReconcileSkipsUnconnectedInstallation(t *testing.T) {
	_, db := newTestHandler(t)
	ctx := context.Background()
	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: strangerInstallationID, AccountLogin: "stranger", AccountID: strangerAccountID, AccountType: "Organization",
	}); err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}

	lister := &fakeLister{repos: []*gh.Repository{apiRepo(6001, "big-monorepo")}}
	reconciler := NewReconciler(lister, nil, db, testQueue(db), discardLogger())
	if err := reconciler.Reconcile(ctx, strangerInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if lister.calls != 0 || allJobs(t, db) != 0 || allRepos(t, db) != 0 {
		t.Fatalf("unconnected: listed %d times, %d jobs, %d repositories; want none", lister.calls, allJobs(t, db), allRepos(t, db))
	}

	connect(t, db, 7002, "newcomer", strangerInstallationID)
	if err := reconciler.Reconcile(ctx, strangerInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if lister.calls != 1 {
		t.Errorf("GitHub was listed %d times, want 1 once connected", lister.calls)
	}
	if n := count(t, db, `SELECT COUNT(*) FROM jobs WHERE kind = 'initial_scan'`); n != 1 {
		t.Errorf("initial scan jobs = %d, want 1 once connected", n)
	}
}

// Under an account allowlist, a row from before account IDs were stored has
// none. Until reconciliation asks GitHub whose installation it is, its pushes
// queue nothing; once GitHub names a listed account, it works as before. One
// GitHub names as someone else's stays shut.
func TestInstallationWithoutAccountIDIsUnapprovedUntilReconciled(t *testing.T) {
	_, db := newTestHandler(t)
	h := NewWebhookHandler("unused", testAllowedAccounts, db, testQueue(db), discardLogger())
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

	// The same kind of row, connected, but GitHub says it is someone else's.
	connect(t, db, 7002, "newcomer", strangerInstallationID)
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

// Losing approval stops new work, but GitHub removing a repository still
// revokes access: that only ever takes work away.
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
// a connected installation, so it is ignored rather than scanned.
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

func queuedReconciliations(t *testing.T, db *storage.DB) []int64 {
	t.Helper()
	rows, err := db.Pool().Query(context.Background(), `
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

// seedInstallations records the cases a worker start or a sign-in meets: the
// owner's connected installation, someone else's connected one, an
// unconnected one, a connected one whose account is not yet known, and a
// connected one that was uninstalled.
func seedInstallations(t *testing.T, db *storage.DB) {
	t.Helper()
	ctx := context.Background()
	connect(t, db, 7002, "newcomer", strangerInstallationID, unknownInstallationID, deletedInstallationID)
	for _, installation := range []models.Installation{
		{GitHubInstallationID: testInstallationID, AccountLogin: "devmind2320", AccountID: testAccountID, AccountType: "User"},
		{GitHubInstallationID: strangerInstallationID, AccountLogin: "stranger", AccountID: strangerAccountID, AccountType: "Organization"},
		{GitHubInstallationID: unconnectedInstallationID, AccountLogin: "drive-by", AccountID: 4444, AccountType: "User"},
		{GitHubInstallationID: unknownInstallationID, AccountLogin: "legacy", AccountType: "User"},
		{GitHubInstallationID: deletedInstallationID, AccountLogin: "newcomer", AccountID: 3333, AccountType: "User"},
	} {
		if _, err := db.UpsertInstallation(ctx, installation); err != nil {
			t.Fatalf("UpsertInstallation(%d) error = %v", installation.GitHubInstallationID, err)
		}
	}
	if err := db.MarkInstallationDeleted(ctx, deletedInstallationID); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}
}

const unconnectedInstallationID, unknownInstallationID, deletedInstallationID = 6666, 8888, 9999

// A worker start queues reconciliation for every connected installation, and
// none for an unconnected or deleted one. Under an account allowlist it also
// skips a connected installation known to be on another account, but still
// queues one whose account is unknown: that job is what asks GitHub whose it
// is, and Reconcile refuses it if the answer is not a listed account.
func TestStartupReconciliationSkipsKnownUnapprovedInstallations(t *testing.T) {
	_, db := newTestHandler(t)
	ctx := context.Background()
	seedInstallations(t, db)

	if err := NewReconciler(&fakeLister{}, nil, db, testQueue(db), discardLogger()).EnqueueStartup(ctx); err != nil {
		t.Fatalf("EnqueueStartup() error = %v", err)
	}
	if got, want := queuedReconciliations(t, db), []int64{testInstallationID, strangerInstallationID, unknownInstallationID}; !slices.Equal(got, want) {
		t.Errorf("reconciliations queued for %v, want %v (every connected installation)", got, want)
	}

	if _, err := db.Pool().Exec(ctx, `DELETE FROM jobs`); err != nil {
		t.Fatal(err)
	}
	if err := NewReconciler(&fakeLister{}, testAllowedAccounts, db, testQueue(db), discardLogger()).EnqueueStartup(ctx); err != nil {
		t.Fatalf("EnqueueStartup() error = %v", err)
	}
	if got, want := queuedReconciliations(t, db), []int64{testInstallationID, unknownInstallationID}; !slices.Equal(got, want) {
		t.Errorf("with an account allowlist, reconciliations queued for %v, want %v", got, want)
	}
}

// Signing in connects the installations GitHub lists for the user, so the
// sign-in queues their reconciliation at once rather than at the next worker
// start: one job per approved installation, however often the user signs in.
// An installation SBOMDelta has not recorded yet, a deleted one or one the
// gate refuses gets none.
func TestSignInQueuesReconciliationOfListedInstallations(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	seedInstallations(t, db)
	listed := []int64{testInstallationID, strangerInstallationID, unconnectedInstallationID, deletedInstallationID, 1234}

	for range 2 {
		if err := h.QueueReconciliationAfterSignIn(ctx, listed); err != nil {
			t.Fatalf("QueueReconciliationAfterSignIn() error = %v", err)
		}
	}
	if got, want := queuedReconciliations(t, db), []int64{testInstallationID, strangerInstallationID}; !slices.Equal(got, want) {
		t.Errorf("reconciliations queued for %v, want %v once each", got, want)
	}

	if _, err := db.Pool().Exec(ctx, `DELETE FROM jobs`); err != nil {
		t.Fatal(err)
	}
	narrowed := NewWebhookHandler("unused", testAllowedAccounts, db, testQueue(db), discardLogger())
	if err := narrowed.QueueReconciliationAfterSignIn(ctx, listed); err != nil {
		t.Fatalf("QueueReconciliationAfterSignIn() error = %v", err)
	}
	if got, want := queuedReconciliations(t, db), []int64{testInstallationID}; !slices.Equal(got, want) {
		t.Errorf("with an account allowlist, reconciliations queued for %v, want %v", got, want)
	}
}
