package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
	"sbomdelta/internal/storage/storagetest"
)

const testInstallationID = 4242

// testAccountID is the GitHub account ID of devmind2320, the account the test
// installation is on, and the one account the test allowlist approves.
const testAccountID = 9901

var testAllowedAccounts = []int64{testAccountID}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestHandler opens a test database in which devmind2320 has signed in
// and connected the test installation, as in production, and returns a
// handler with no account allowlist.
func newTestHandler(t *testing.T) (*WebhookHandler, *storage.DB) {
	t.Helper()
	db := storagetest.Open(t, "test_github")
	connect(t, db, 7001, "devmind2320", testInstallationID)
	return NewWebhookHandler("unused", nil, db, testQueue(db), discardLogger()), db
}

// connect records a sign-in by login whose GitHub listing reaches one
// repository in each given installation, which is what connects an
// installation to SBOMDelta.
func connect(t *testing.T, db *storage.DB, githubUserID int64, login string, githubInstallationIDs ...int64) models.User {
	t.Helper()
	ctx := context.Background()
	user, err := db.UpsertUser(ctx, models.User{GitHubUserID: githubUserID, Login: login})
	if err != nil {
		t.Fatalf("UpsertUser(%s) error = %v", login, err)
	}
	repos := make([]models.AccessibleRepository, 0, len(githubInstallationIDs))
	for i, id := range githubInstallationIDs {
		repos = append(repos, models.AccessibleRepository{
			GitHubRepoID: githubUserID*100 + int64(i), GitHubInstallationID: id, Owner: login, Name: fmt.Sprintf("listed-%d", i),
		})
	}
	if err := db.ReplaceUserRepositories(ctx, user.ID, repos, time.Now()); err != nil {
		t.Fatalf("ReplaceUserRepositories(%s) error = %v", login, err)
	}
	return user
}

func testQueue(db *storage.DB) *queue.Queue { return queue.New(db.Pool(), time.Minute) }

func testInstallation() *gh.Installation {
	return &gh.Installation{
		ID:      gh.Int64(testInstallationID),
		Account: &gh.User{Login: gh.String("devmind2320"), ID: gh.Int64(testAccountID), Type: gh.String("User")},
	}
}

// eventRepo is the trimmed repository shape installation events carry: an ID
// and full name, but no owner object.
func eventRepo(id int64, fullName string) *gh.Repository {
	return &gh.Repository{ID: gh.Int64(id), FullName: gh.String(fullName), Name: gh.String(fullName[len("devmind2320/"):])}
}

func dispatch(t *testing.T, h *WebhookHandler, event any) {
	t.Helper()
	if err := h.dispatch(context.Background(), discardLogger(), event); err != nil {
		t.Fatalf("dispatch(%T) error = %v", event, err)
	}
}

func reconcileJobs(t *testing.T, db *storage.DB) int {
	t.Helper()
	var count int
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM jobs WHERE kind = $1`, string(queue.KindReconcileInstallation)).Scan(&count); err != nil {
		t.Fatalf("count reconcile jobs: %v", err)
	}
	return count
}

func repoByName(t *testing.T, db *storage.DB, name string) models.Repository {
	t.Helper()
	repos, err := db.ListRepositories(context.Background(), storage.AccessFilterAll)
	if err != nil {
		t.Fatalf("ListRepositories() error = %v", err)
	}
	for _, repo := range repos {
		if repo.Name == name {
			return repo
		}
	}
	t.Fatalf("repository %q not stored", name)
	return models.Repository{}
}

func addRepos(t *testing.T, h *WebhookHandler, repos ...*gh.Repository) {
	t.Helper()
	dispatch(t, h, &gh.InstallationRepositoriesEvent{
		Action:              gh.String("added"),
		RepositorySelection: gh.String("selected"),
		RepositoriesAdded:   repos,
		Installation:        testInstallation(),
	})
}

func TestInstallationRepositoriesAdded(t *testing.T) {
	h, db := newTestHandler(t)

	addRepos(t, h, eventRepo(1001, "devmind2320/api"), eventRepo(1002, "devmind2320/web"))

	for _, name := range []string{"api", "web"} {
		repo := repoByName(t, db, name)
		if repo.Owner != "devmind2320" {
			t.Errorf("%s owner = %q, want it taken from the full name", name, repo.Owner)
		}
		if repo.Access != models.AccessActive {
			t.Errorf("%s access = %q, want active", name, repo.Access)
		}
	}
	if got := reconcileJobs(t, db); got != 1 {
		t.Errorf("reconcile jobs = %d, want 1", got)
	}
}

// Removing a repository from the selection used to be logged and otherwise
// ignored, leaving it on the dashboard indefinitely.
func TestInstallationRepositoriesRemovedRevokesAndKeepsHistory(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()

	addRepos(t, h, eventRepo(1001, "devmind2320/api"), eventRepo(1002, "devmind2320/web"))
	api := repoByName(t, db, "api")
	scan, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: api.ID, CommitSHA: "2222222222222222222222222222222222222222", Trigger: models.TriggerPush,
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	dispatch(t, h, &gh.InstallationRepositoriesEvent{
		Action:              gh.String("removed"),
		RepositorySelection: gh.String("selected"),
		RepositoriesRemoved: []*gh.Repository{eventRepo(1001, "devmind2320/api")},
		Installation:        testInstallation(),
	})

	if got := repoByName(t, db, "api").Access; got != models.AccessRevoked {
		t.Errorf("api access = %q, want revoked", got)
	}
	if got := repoByName(t, db, "web").Access; got != models.AccessActive {
		t.Errorf("web access = %q, want active; only api was removed", got)
	}

	active, err := db.ListRepositories(ctx, storage.AccessFilterActive)
	if err != nil {
		t.Fatalf("ListRepositories() error = %v", err)
	}
	if len(active) != 1 || active[0].Name != "web" {
		t.Errorf("active repositories = %v, want only web", active)
	}

	stored, err := db.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error = %v; the revoked repository's scan must survive", err)
	}
	if stored.RepositoryID != api.ID {
		t.Errorf("scan repository = %d, want %d", stored.RepositoryID, api.ID)
	}

	// Adding it back restores access on the same row.
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	restored := repoByName(t, db, "api")
	if restored.ID != api.ID || restored.Access != models.AccessActive {
		t.Errorf("restored = id %d access %q, want id %d active", restored.ID, restored.Access, api.ID)
	}
}

// The event in the original report: an installation event with no
// repositories. It must record the installation, leave existing repositories
// alone, and ask for a reconciliation rather than trusting the empty list.
func TestInstallationEventWithZeroRepositories(t *testing.T) {
	h, db := newTestHandler(t)

	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	before := reconcileJobs(t, db)

	dispatch(t, h, &gh.InstallationEvent{
		Action:       gh.String("new_permissions_accepted"),
		Installation: testInstallation(),
	})

	if _, err := db.GetInstallationByGitHubID(context.Background(), testInstallationID); err != nil {
		t.Fatalf("GetInstallationByGitHubID() error = %v", err)
	}
	if got := repoByName(t, db, "api").Access; got != models.AccessActive {
		t.Errorf("api access = %q; an empty event list must not revoke anything", got)
	}
	if got := reconcileJobs(t, db) - before; got != 1 {
		t.Errorf("reconcile jobs queued = %d, want 1", got)
	}
}

func TestSuspendDoesNotQueueReconciliation(t *testing.T) {
	h, db := newTestHandler(t)

	installation := testInstallation()
	installation.SuspendedAt = &gh.Timestamp{Time: time.Now()}
	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("suspend"), Installation: installation})

	if got := reconcileJobs(t, db); got != 0 {
		t.Errorf("reconcile jobs = %d, want 0 while the installation cannot mint a token", got)
	}
}

type fakeLister struct {
	repos []*gh.Repository
	err   error
	calls int
	// account is whose installation GitHub says it is; zero means the
	// approved test account.
	account int64
}

func (f *fakeLister) ListInstallationRepositories(context.Context, int64) ([]*gh.Repository, error) {
	f.calls++
	return f.repos, f.err
}

func (f *fakeLister) InstallationAccountID(context.Context, int64) (int64, error) {
	if f.account != 0 {
		return f.account, nil
	}
	return testAccountID, nil
}

// apiRepo is the full shape GET /installation/repositories returns.
func apiRepo(id int64, name string) *gh.Repository {
	return &gh.Repository{
		ID:            gh.Int64(id),
		Name:          gh.String(name),
		FullName:      gh.String("devmind2320/" + name),
		Owner:         &gh.User{Login: gh.String("devmind2320")},
		DefaultBranch: gh.String("trunk"),
		Private:       gh.Bool(true),
	}
}

// Reconciliation fixes what the zero-repository event could not: after access
// is narrowed to one repository, the others drop off the active list.
func TestReconcileAfterNarrowingAccess(t *testing.T) {
	h, db := newTestHandler(t)
	addRepos(t, h, eventRepo(1001, "devmind2320/api"), eventRepo(1002, "devmind2320/web"))

	lister := &fakeLister{repos: []*gh.Repository{apiRepo(1002, "web"), apiRepo(1003, "docs")}}
	if err := NewReconciler(lister, testAllowedAccounts, db, testQueue(db), discardLogger()).Reconcile(context.Background(), testInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	if got := repoByName(t, db, "api").Access; got != models.AccessRevoked {
		t.Errorf("api access = %q, want revoked", got)
	}
	web := repoByName(t, db, "web")
	if web.Access != models.AccessActive || web.DefaultBranch != "trunk" || !web.Private {
		t.Errorf("web = %+v, want active and refreshed from GitHub", web)
	}
	if got := repoByName(t, db, "docs").Access; got != models.AccessActive {
		t.Errorf("docs access = %q, want active", got)
	}
}

// A failed listing must never be read as "no repositories".
func TestReconcileListingErrorChangesNothing(t *testing.T) {
	h, db := newTestHandler(t)
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))

	lister := &fakeLister{err: errors.New("github is unreachable")}
	if err := NewReconciler(lister, testAllowedAccounts, db, testQueue(db), discardLogger()).Reconcile(context.Background(), testInstallationID); err == nil {
		t.Fatal("Reconcile() succeeded, want the listing error so the job retries")
	}
	if got := repoByName(t, db, "api").Access; got != models.AccessActive {
		t.Errorf("api access = %q, want untouched after a failed listing", got)
	}
}

func TestReconcileSkipsUnusableInstallations(t *testing.T) {
	_, db := newTestHandler(t)
	ctx := context.Background()
	lister := &fakeLister{}
	reconciler := NewReconciler(lister, testAllowedAccounts, db, testQueue(db), discardLogger())

	// Unknown: the installation event that creates it has not landed yet.
	if err := reconciler.Reconcile(ctx, 999); err != nil {
		t.Fatalf("Reconcile(unknown) error = %v", err)
	}

	if _, err := db.UpsertInstallation(ctx, models.Installation{
		GitHubInstallationID: testInstallationID, AccountLogin: "devmind2320", AccountID: testAccountID, AccountType: "User",
	}); err != nil {
		t.Fatalf("UpsertInstallation() error = %v", err)
	}
	if err := db.MarkInstallationDeleted(ctx, testInstallationID); err != nil {
		t.Fatalf("MarkInstallationDeleted() error = %v", err)
	}
	if err := reconciler.Reconcile(ctx, testInstallationID); err != nil {
		t.Fatalf("Reconcile(deleted) error = %v", err)
	}

	if lister.calls != 0 {
		t.Errorf("GitHub was asked %d times, want 0 for unknown or deleted installations", lister.calls)
	}
}

// pushEvent mirrors a real push payload, whose installation object carries
// only an ID: no account, no suspension state.
func pushEvent(repoID int64, name string) *gh.PushEvent {
	return &gh.PushEvent{
		Ref:    gh.String("refs/heads/main"),
		Before: gh.String("0000000000000000000000000000000000000000"),
		After:  gh.String("6666666666666666666666666666666666666666"),
		Repo: &gh.PushEventRepository{
			ID:            gh.Int64(repoID),
			Name:          gh.String(name),
			Owner:         &gh.User{Name: gh.String("devmind2320"), Login: gh.String("devmind2320")},
			DefaultBranch: gh.String("main"),
		},
		HeadCommit:   &gh.HeadCommit{Message: gh.String("bump deps")},
		Installation: &gh.Installation{ID: gh.Int64(testInstallationID)},
	}
}

// Push and pull request payloads carry a bare installation reference. Using
// it to upsert the installation blanked the account and cleared suspension.
func TestPushEventPreservesInstallationDetails(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()

	suspended := testInstallation()
	suspended.SuspendedAt = &gh.Timestamp{Time: time.Now()}
	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("suspend"), Installation: suspended})

	dispatch(t, h, pushEvent(1001, "api"))
	dispatch(t, h, &gh.PullRequestEvent{
		Action: gh.String("opened"),
		Repo: &gh.Repository{
			ID: gh.Int64(1001), Name: gh.String("api"),
			Owner: &gh.User{Login: gh.String("devmind2320")}, DefaultBranch: gh.String("main"),
		},
		PullRequest: &gh.PullRequest{
			Number: gh.Int(7), State: gh.String("open"),
			Base: &gh.PullRequestBranch{Ref: gh.String("main"), SHA: gh.String("6666666666666666666666666666666666666666")},
			Head: &gh.PullRequestBranch{SHA: gh.String("7777777777777777777777777777777777777777")},
		},
		Installation: &gh.Installation{ID: gh.Int64(testInstallationID)},
	})

	installation, err := db.GetInstallationByGitHubID(ctx, testInstallationID)
	if err != nil {
		t.Fatalf("GetInstallationByGitHubID() error = %v", err)
	}
	if installation.AccountLogin != "devmind2320" || installation.AccountType != "User" {
		t.Errorf("account = %q/%q, want devmind2320/User preserved", installation.AccountLogin, installation.AccountType)
	}
	if installation.SuspendedAt == nil {
		t.Error("suspended_at was cleared by a push or pull request event")
	}
}

func scanCount(t *testing.T, db *storage.DB) int {
	t.Helper()
	var count int
	if err := db.Pool().QueryRow(context.Background(), `SELECT COUNT(*) FROM scans`).Scan(&count); err != nil {
		t.Fatalf("count scans: %v", err)
	}
	return count
}

// A push redelivered after its repository left the installation must neither
// restore access nor queue a scan.
func TestPushForRevokedRepositoryIsIgnored(t *testing.T) {
	h, db := newTestHandler(t)

	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	dispatch(t, h, &gh.InstallationRepositoriesEvent{
		Action:              gh.String("removed"),
		RepositoriesRemoved: []*gh.Repository{eventRepo(1001, "devmind2320/api")},
		Installation:        testInstallation(),
	})

	dispatch(t, h, pushEvent(1001, "api"))

	if got := repoByName(t, db, "api").Access; got != models.AccessRevoked {
		t.Errorf("access = %q, want the revocation to survive a push", got)
	}
	if got := scanCount(t, db); got != 0 {
		t.Errorf("scans = %d, want 0 for a revoked repository", got)
	}
}

// An installation_repositories delivery arriving after an uninstall must not
// bring the installation back.
func TestInstallationRepositoriesRedeliveryDoesNotUndelete(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()

	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	dispatch(t, h, &gh.InstallationEvent{Action: gh.String("deleted"), Installation: testInstallation()})
	addRepos(t, h, eventRepo(1001, "devmind2320/api")) // the late redelivery

	installation, err := db.GetInstallationByGitHubID(ctx, testInstallationID)
	if err != nil {
		t.Fatalf("GetInstallationByGitHubID() error = %v", err)
	}
	if installation.DeletedAt == nil {
		t.Error("deleted_at was cleared by an installation_repositories redelivery")
	}
	if got := repoByName(t, db, "api").Access; got != models.AccessUninstalled {
		t.Errorf("access = %q, want uninstalled", got)
	}
}

// The reconciliation a webhook requests waits for GitHub to settle, so it
// cannot read a listing that predates the change and undo it.
func TestWebhookReconciliationIsDelayed(t *testing.T) {
	h, db := newTestHandler(t)
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))

	var delayed bool
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT bool_and(run_after > now() + interval '1 minute') FROM jobs WHERE kind = $1`,
		string(queue.KindReconcileInstallation)).Scan(&delayed); err != nil {
		t.Fatalf("read reconcile job: %v", err)
	}
	if !delayed {
		t.Error("webhook-triggered reconciliation is runnable immediately, want it delayed")
	}
}

// listerThatUninstalls simulates the installation being deleted while GitHub
// is still being paged through.
type listerThatUninstalls struct {
	db *storage.DB
}

func (listerThatUninstalls) InstallationAccountID(context.Context, int64) (int64, error) {
	return testAccountID, nil
}

func (l listerThatUninstalls) ListInstallationRepositories(ctx context.Context, id int64) ([]*gh.Repository, error) {
	if err := l.db.MarkInstallationDeleted(ctx, id); err != nil {
		return nil, err
	}
	return nil, nil // an empty list that would revoke everything if applied
}

func TestReconcileAbandonedWhenUninstalledDuringListing(t *testing.T) {
	h, db := newTestHandler(t)
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))

	if err := NewReconciler(listerThatUninstalls{db: db}, testAllowedAccounts, db, testQueue(db), discardLogger()).
		Reconcile(context.Background(), testInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v, want the reconciliation quietly abandoned", err)
	}
	if got := repoByName(t, db, "api").AccessRevokedAt; got != nil {
		t.Errorf("accessRevokedAt = %v, want nothing written for an uninstalled installation", got)
	}
}
