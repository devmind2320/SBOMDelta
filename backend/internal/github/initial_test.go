package github

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

const headSHA = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

type queuedJob struct {
	dedupeKey string
	payload   string
	runAfter  time.Time
}

func jobsOfKind(t *testing.T, db *storage.DB, kind queue.Kind) []queuedJob {
	t.Helper()
	rows, err := db.Pool().Query(context.Background(), `
		SELECT COALESCE(dedupe_key, ''), payload::text, run_after
		FROM jobs WHERE kind = $1 ORDER BY id`, string(kind))
	if err != nil {
		t.Fatalf("list %s jobs: %v", kind, err)
	}
	defer rows.Close()
	var out []queuedJob
	for rows.Next() {
		var job queuedJob
		if err := rows.Scan(&job.dedupeKey, &job.payload, &job.runAfter); err != nil {
			t.Fatalf("scan job: %v", err)
		}
		out = append(out, job)
	}
	return out
}

func scansFor(t *testing.T, db *storage.DB, repoID int64) []models.Scan {
	t.Helper()
	scans, err := db.ListScans(context.Background(), repoID, 50)
	if err != nil {
		t.Fatalf("ListScans() error = %v", err)
	}
	return scans
}

// fakeHeads answers DefaultBranchHead with a fixed result and records how it
// was asked. during, if set, runs inside the lookup, which is where a webhook
// can land while the real call is waiting on GitHub.
type fakeHeads struct {
	head   BranchHead
	err    error
	during func()

	calls        int
	installation int64
	githubRepoID int64
}

func (f *fakeHeads) DefaultBranchHead(_ context.Context, installationID, githubRepoID int64) (BranchHead, error) {
	f.calls++
	f.installation, f.githubRepoID = installationID, githubRepoID
	if f.during != nil {
		f.during()
	}
	return f.head, f.err
}

func newInitialScanner(db *storage.DB, heads HeadResolver) *InitialScanner {
	return NewInitialScanner(heads, db, testQueue(db), discardLogger())
}

func reconcile(t *testing.T, db *storage.DB, repos ...*gh.Repository) {
	t.Helper()
	lister := &fakeLister{repos: repos}
	if err := NewReconciler(lister, db, testQueue(db), discardLogger()).
		Reconcile(context.Background(), testInstallationID); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
}

// Reconciliation queues exactly one initial scan per accessible repository
// with no scan, and never for one that is already scanned or was revoked.
// Running it again, as every worker start does, must not add more.
func TestReconcileQueuesInitialScansForUnscannedRepositories(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()

	addRepos(t, h, eventRepo(1001, "devmind2320/api"), eventRepo(1002, "devmind2320/web"),
		eventRepo(1003, "devmind2320/docs"), eventRepo(1004, "devmind2320/cli"))
	web := repoByName(t, db, "web")
	if _, err := db.CreateScan(ctx, models.Scan{
		RepositoryID: web.ID, CommitSHA: headSHA, Trigger: models.TriggerPush,
	}); err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	// docs is left out of the listing, so reconciliation revokes it.
	listed := []*gh.Repository{apiRepo(1001, "api"), apiRepo(1002, "web"), apiRepo(1004, "cli")}
	reconcile(t, db, listed...)

	api, cli := repoByName(t, db, "api"), repoByName(t, db, "cli")
	if docs := repoByName(t, db, "docs"); docs.Access != models.AccessRevoked {
		t.Fatalf("docs access = %q, want revoked", docs.Access)
	}
	jobs := jobsOfKind(t, db, queue.KindInitialScan)
	if len(jobs) != 2 {
		t.Fatalf("initial scan jobs = %+v, want one each for api and cli", jobs)
	}
	for i, repo := range []models.Repository{api, cli} {
		if want := fmt.Sprintf("initial:%d", repo.ID); jobs[i].dedupeKey != want {
			t.Errorf("job %d dedupe key = %q, want %q", i, jobs[i].dedupeKey, want)
		}
		if want := fmt.Sprintf(`{"repositoryId": %d}`, repo.ID); jobs[i].payload != want {
			t.Errorf("job %d payload = %s, want %s", i, jobs[i].payload, want)
		}
	}
	if gap := jobs[1].runAfter.Sub(jobs[0].runAfter); gap < initialScanStagger-time.Second {
		t.Errorf("second initial scan runs %v after the first, want them staggered by %v", gap, initialScanStagger)
	}

	// A worker restart reconciles again while the jobs are still queued.
	reconcile(t, db, listed...)
	reconcile(t, db, listed...)
	if got := jobsOfKind(t, db, queue.KindInitialScan); len(got) != 2 {
		t.Errorf("initial scan jobs after repeated reconciliation = %d, want still 2", len(got))
	}
}

// A suspended or uninstalled installation cannot mint a token, so nothing is
// listed and no initial scan is queued for any of its repositories.
func TestReconcileQueuesNoInitialScansForUnusableInstallations(t *testing.T) {
	for _, state := range []string{"suspended", "uninstalled"} {
		t.Run(state, func(t *testing.T) {
			h, db := newTestHandler(t)
			ctx := context.Background()
			addRepos(t, h, eventRepo(1001, "devmind2320/api"))

			if state == "suspended" {
				installation := testInstallation()
				installation.SuspendedAt = &gh.Timestamp{Time: time.Now()}
				dispatch(t, h, &gh.InstallationEvent{Action: gh.String("suspend"), Installation: installation})
			} else if err := db.MarkInstallationDeleted(ctx, testInstallationID); err != nil {
				t.Fatalf("MarkInstallationDeleted() error = %v", err)
			}

			reconcile(t, db, apiRepo(1001, "api"))
			if got := jobsOfKind(t, db, queue.KindInitialScan); len(got) != 0 {
				t.Errorf("initial scan jobs = %+v, want none for a %s installation", got, state)
			}
		})
	}
}

// The job resolves the head through the repository's installation, records
// one pending initial scan at that commit and queues one scan job for it.
// Running the job again changes nothing.
func TestInitialScanQueuesOneScanAtDefaultBranchHead(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "trunk", SHA: headSHA}}
	scanner := newInitialScanner(db, heads)
	for i := 0; i < 2; i++ {
		if err := scanner.Run(ctx, api.ID); err != nil {
			t.Fatalf("Run() #%d error = %v", i+1, err)
		}
	}

	if heads.installation != testInstallationID || heads.githubRepoID != 1001 {
		t.Errorf("head resolved for installation %d repository %d, want %d repository 1001",
			heads.installation, heads.githubRepoID, testInstallationID)
	}
	if heads.calls != 1 {
		t.Errorf("GitHub asked %d times, want once: the second run finds the initial scan", heads.calls)
	}

	scans := scansFor(t, db, api.ID)
	if len(scans) != 1 {
		t.Fatalf("scans = %+v, want exactly one", scans)
	}
	scan := scans[0]
	if scan.Trigger != models.TriggerInitial || scan.CommitSHA != headSHA || scan.Status != models.ScanPending ||
		scan.BaseCommitSHA != "" || scan.PullRequestID != nil {
		t.Errorf("scan = %+v, want a pending initial scan of %s with no base", scan, headSHA)
	}

	jobs := jobsOfKind(t, db, queue.KindScan)
	if len(jobs) != 1 || jobs[0].dedupeKey != fmt.Sprintf("scan:%d", scan.ID) {
		t.Errorf("scan jobs = %+v, want one keyed scan:%d", jobs, scan.ID)
	}

	var ref string
	if err := db.Pool().QueryRow(ctx, `SELECT ref FROM commits WHERE repository_id = $1 AND sha = $2`,
		api.ID, headSHA).Scan(&ref); err != nil || ref != "refs/heads/trunk" {
		t.Errorf("commit ref = %q (err %v), want refs/heads/trunk", ref, err)
	}
}

// A job that crashed after creating its scan but before queueing it must
// queue that scan when retried, not strand it pending forever.
func TestInitialScanRetryQueuesStrandedScan(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	scan, created, err := db.CreateInitialScan(ctx, api.ID, headSHA)
	if err != nil || !created {
		t.Fatalf("CreateInitialScan() = %v, %v, want a new scan", created, err)
	}

	heads := &fakeHeads{err: errors.New("must not be called")}
	if err := newInitialScanner(db, heads).Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if heads.calls != 0 {
		t.Errorf("GitHub asked %d times, want 0", heads.calls)
	}
	jobs := jobsOfKind(t, db, queue.KindScan)
	if len(jobs) != 1 || jobs[0].dedupeKey != fmt.Sprintf("scan:%d", scan.ID) {
		t.Errorf("scan jobs = %+v, want the stranded scan %d queued", jobs, scan.ID)
	}
}

// Access lost after the job was queued -- revocation, suspension, uninstall --
// finishes the job without asking GitHub or creating a scan.
func TestInitialScanSkipsRepositoryThatLostAccess(t *testing.T) {
	for _, state := range []string{"revoked", "suspended", "uninstalled"} {
		t.Run(state, func(t *testing.T) {
			h, db := newTestHandler(t)
			ctx := context.Background()
			addRepos(t, h, eventRepo(1001, "devmind2320/api"))
			api := repoByName(t, db, "api")
			reconcile(t, db, apiRepo(1001, "api"))
			if got := jobsOfKind(t, db, queue.KindInitialScan); len(got) != 1 {
				t.Fatalf("initial scan jobs = %d, want 1 queued before access changes", len(got))
			}

			loseAccess(t, h, db, api, state)

			heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
			if err := newInitialScanner(db, heads).Run(ctx, api.ID); err != nil {
				t.Fatalf("Run() error = %v, want nil so the job is not retried", err)
			}
			if heads.calls != 0 {
				t.Errorf("GitHub asked %d times, want 0", heads.calls)
			}
			if got := scanCount(t, db); got != 0 {
				t.Errorf("scans = %d, want 0", got)
			}
		})
	}
}

// Access lost while the head was being resolved is caught before the scan is
// created.
func TestInitialScanSkipsWhenAccessLostDuringHeadLookup(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	heads.during = func() { loseAccess(t, h, db, api, "revoked") }
	if err := newInitialScanner(db, heads).Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := scanCount(t, db); got != 0 {
		t.Errorf("scans = %d, want 0", got)
	}
	if got := jobsOfKind(t, db, queue.KindScan); len(got) != 0 {
		t.Errorf("scan jobs = %d, want 0", len(got))
	}
}

func loseAccess(t *testing.T, h *WebhookHandler, db *storage.DB, repo models.Repository, state string) {
	t.Helper()
	ctx := context.Background()
	switch state {
	case "revoked":
		if _, err := db.MarkRepositoriesRevoked(ctx, *repo.InstallationID, []int64{*repo.GitHubRepoID}); err != nil {
			t.Fatalf("MarkRepositoriesRevoked() error = %v", err)
		}
	case "suspended":
		installation := testInstallation()
		installation.SuspendedAt = &gh.Timestamp{Time: time.Now()}
		dispatch(t, h, &gh.InstallationEvent{Action: gh.String("suspend"), Installation: installation})
	case "uninstalled":
		if err := db.MarkInstallationDeleted(ctx, testInstallationID); err != nil {
			t.Fatalf("MarkInstallationDeleted() error = %v", err)
		}
	}
}

// A transient GitHub failure is returned so the queue retries the job, and
// leaves nothing behind -- no scan, no empty baseline. A definitive "no head"
// (empty or unreachable repository) finishes the job, again without a scan.
func TestInitialScanHeadLookupFailures(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	transient := &fakeHeads{err: errors.New("GET /repos/devmind2320/api: 502 Bad Gateway")}
	if err := newInitialScanner(db, transient).Run(ctx, api.ID); err == nil {
		t.Fatal("Run() error = nil, want the GitHub error so the job is retried")
	}
	if got := scanCount(t, db); got != 0 {
		t.Errorf("scans after transient failure = %d, want 0", got)
	}

	empty := &fakeHeads{err: fmt.Errorf("devmind2320/api: read branch main: %w", ErrNoBranchHead)}
	if err := newInitialScanner(db, empty).Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v, want nil for a repository with no head", err)
	}
	if got := scanCount(t, db); got != 0 {
		t.Errorf("scans after no-head answer = %d, want 0", got)
	}

	// The retry, once GitHub recovers, creates the scan normally.
	recovered := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	if err := newInitialScanner(db, recovered).Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() after recovery error = %v", err)
	}
	if scans := scansFor(t, db, api.ID); len(scans) != 1 || scans[0].Trigger != models.TriggerInitial {
		t.Errorf("scans after recovery = %+v, want one initial scan", scans)
	}
}

func pushAt(repoID int64, name, sha string) *gh.PushEvent {
	event := pushEvent(repoID, name)
	event.After = gh.String(sha)
	return event
}

// A push and an initial scan of the same repository must end with one scan
// per commit and one job per scan, in whichever order they arrive, and must
// never reset a scan that already completed.
func TestPushAndInitialScanDoNotDuplicate(t *testing.T) {
	ctx := context.Background()
	heads := func() *fakeHeads {
		return &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	}

	t.Run("push first, same commit", func(t *testing.T) {
		h, db := newTestHandler(t)
		addRepos(t, h, eventRepo(1001, "devmind2320/api"))
		api := repoByName(t, db, "api")

		dispatch(t, h, pushAt(1001, "api", headSHA))
		if err := newInitialScanner(db, heads()).Run(ctx, api.ID); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		scans := scansFor(t, db, api.ID)
		if len(scans) != 1 || scans[0].Trigger != models.TriggerPush {
			t.Errorf("scans = %+v, want only the push scan", scans)
		}
		if got := jobsOfKind(t, db, queue.KindScan); len(got) != 1 {
			t.Errorf("scan jobs = %d, want 1", len(got))
		}
	})

	t.Run("initial first, push of same commit", func(t *testing.T) {
		h, db := newTestHandler(t)
		addRepos(t, h, eventRepo(1001, "devmind2320/api"))
		api := repoByName(t, db, "api")

		if err := newInitialScanner(db, heads()).Run(ctx, api.ID); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		dispatch(t, h, pushAt(1001, "api", headSHA))
		scans := scansFor(t, db, api.ID)
		if len(scans) != 1 || scans[0].Trigger != models.TriggerInitial {
			t.Errorf("scans = %+v, want only the initial scan", scans)
		}
		if got := jobsOfKind(t, db, queue.KindScan); len(got) != 1 {
			t.Errorf("scan jobs = %d, want 1: the push must reuse the queued job", len(got))
		}
	})

	t.Run("push of a newer commit lands during head lookup", func(t *testing.T) {
		h, db := newTestHandler(t)
		addRepos(t, h, eventRepo(1001, "devmind2320/api"))
		api := repoByName(t, db, "api")

		lookup := heads()
		lookup.during = func() { dispatch(t, h, pushAt(1001, "api", "7777777777777777777777777777777777777777")) }
		if err := newInitialScanner(db, lookup).Run(ctx, api.ID); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		scans := scansFor(t, db, api.ID)
		if len(scans) != 1 || scans[0].Trigger != models.TriggerPush {
			t.Errorf("scans = %+v, want only the push scan to become the baseline", scans)
		}
	})

	t.Run("completed initial scan survives a push of the same commit", func(t *testing.T) {
		h, db := newTestHandler(t)
		addRepos(t, h, eventRepo(1001, "devmind2320/api"))
		api := repoByName(t, db, "api")

		if err := newInitialScanner(db, heads()).Run(ctx, api.ID); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		scan := scansFor(t, db, api.ID)[0]
		if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: scan.ID, SBOMLocation: "s3://sboms/x"}); err != nil {
			t.Fatalf("SaveScanResult() error = %v", err)
		}
		if _, err := db.Pool().Exec(ctx, `UPDATE jobs SET status = 'succeeded', dedupe_key = NULL`); err != nil {
			t.Fatalf("finish jobs: %v", err)
		}

		dispatch(t, h, pushAt(1001, "api", headSHA))
		got, err := db.GetScan(ctx, scan.ID)
		if err != nil {
			t.Fatalf("GetScan() error = %v", err)
		}
		if got.Status != models.ScanCompleted || got.SBOMLocation != "s3://sboms/x" {
			t.Errorf("scan = %+v, want it left completed", got)
		}
		if n := len(scansFor(t, db, api.ID)); n != 1 {
			t.Errorf("scans = %d, want 1", n)
		}
		var queued int
		if err := db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan' AND status = 'queued'`).
			Scan(&queued); err != nil || queued != 0 {
			t.Errorf("queued scan jobs = %d (err %v), want 0", queued, err)
		}
	})
}

// Initial scan creation racing push scans of other commits: with the
// per-repository lock, either the initial scan is the repository's first scan
// or it is not created at all -- never alongside a push that got there first.
func TestConcurrentInitialAndPushScansCreateOneBaseline(t *testing.T) {
	_, db := newTestHandler(t)
	ctx := context.Background()

	for round := 0; round < 20; round++ {
		if _, err := db.Pool().Exec(ctx, `TRUNCATE scans RESTART IDENTITY CASCADE`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		githubID := int64(5000 + round)
		repo, err := db.UpsertRepository(ctx, models.Repository{
			GitHubRepoID: &githubID, Owner: "devmind2320", Name: fmt.Sprintf("r%d", round), DefaultBranch: "main",
		})
		if err != nil {
			t.Fatalf("UpsertRepository() error = %v", err)
		}

		var wg sync.WaitGroup
		var initialCreated bool
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, created, err := db.CreateInitialScan(ctx, repo.ID, headSHA)
			initialCreated = created
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, err := db.CreateScan(ctx, models.Scan{
				RepositoryID: repo.ID, CommitSHA: "8888888888888888888888888888888888888888", Trigger: models.TriggerPush,
			})
			errs <- err
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}

		// IDs, not created_at: created_at is the transaction start, which for
		// the loser of the lock can predate the winner's.
		scans := scansFor(t, db, repo.ID)
		sort.Slice(scans, func(i, j int) bool { return scans[i].ID < scans[j].ID })
		if initialCreated {
			// The initial scan won the lock, so it must be the first row.
			if len(scans) != 2 || scans[0].Trigger != models.TriggerInitial {
				t.Fatalf("round %d: scans = %+v, want the initial scan first", round, scans)
			}
		} else if len(scans) != 1 || scans[0].Trigger != models.TriggerPush {
			t.Fatalf("round %d: scans = %+v, want only the push scan", round, scans)
		}
	}
}

// killJobs parks every job of a kind as dead, the way three failed attempts
// would.
func killJobs(t *testing.T, db *storage.DB, kind queue.Kind) {
	t.Helper()
	if _, err := db.Pool().Exec(context.Background(),
		`UPDATE jobs SET status = 'dead', attempts = max_attempts WHERE kind = $1`, string(kind)); err != nil {
		t.Fatalf("kill %s jobs: %v", kind, err)
	}
}

// An initial_scan job that exhausted its retries used to hold initial:<id>
// forever, so no later reconciliation could queue the repository again.
func TestReconcileRecoversDeadInitialScanJob(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	reconcile(t, db, apiRepo(1001, "api"))
	killJobs(t, db, queue.KindInitialScan)

	reconcile(t, db, apiRepo(1001, "api"))
	var dead, queued int
	if err := db.Pool().QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status = 'dead'), COUNT(*) FILTER (WHERE status = 'queued')
		FROM jobs WHERE kind = 'initial_scan'`).Scan(&dead, &queued); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if dead != 1 || queued != 1 {
		t.Errorf("initial jobs dead=%d queued=%d, want the dead one kept and one fresh job", dead, queued)
	}

	// Further reconciliation while the fresh job waits adds nothing.
	reconcile(t, db, apiRepo(1001, "api"))
	if got := jobsOfKind(t, db, queue.KindInitialScan); len(got) != 2 {
		t.Errorf("initial jobs = %d, want still 2", len(got))
	}
}

// A repository whose only scans are pull request scans has no default-branch
// baseline, and one whose initial scan failed for good has none either; both
// still need an initial scan. A completed or running one does not.
func TestRepositoriesNeedingInitialScan(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"), eventRepo(1002, "devmind2320/web"),
		eventRepo(1003, "devmind2320/docs"), eventRepo(1004, "devmind2320/cli"))
	api, web, docs, cli := repoByName(t, db, "api"), repoByName(t, db, "web"), repoByName(t, db, "docs"), repoByName(t, db, "cli")

	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{RepositoryID: api.ID, Number: 1, State: "open",
		BaseSHA: "1111111111111111111111111111111111111111", HeadSHA: headSHA})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}
	if _, err := db.CreateScan(ctx, models.Scan{RepositoryID: api.ID, PullRequestID: &pr.ID,
		CommitSHA: headSHA, Trigger: models.TriggerPullRequest}); err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	failed, _, err := db.CreateInitialScan(ctx, web.ID, headSHA)
	if err != nil {
		t.Fatalf("CreateInitialScan() error = %v", err)
	}
	if err := db.MarkScanFailed(ctx, failed.ID, "clone failed"); err != nil {
		t.Fatalf("MarkScanFailed() error = %v", err)
	}
	running, _, err := db.CreateInitialScan(ctx, docs.ID, headSHA)
	if err != nil {
		t.Fatalf("CreateInitialScan() error = %v", err)
	}
	if err := db.MarkScanRunning(ctx, running.ID); err != nil {
		t.Fatalf("MarkScanRunning() error = %v", err)
	}
	if _, err := db.CreateScan(ctx, models.Scan{RepositoryID: cli.ID, CommitSHA: headSHA, Trigger: models.TriggerPush}); err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	// A push that fails is still history: it is retried on its own terms.
	if err := db.MarkScanFailed(ctx, mustLatestScan(t, db, cli.ID).ID, "boom"); err != nil {
		t.Fatalf("MarkScanFailed() error = %v", err)
	}

	repos, err := db.ListRepositoriesNeedingInitialScan(ctx, *api.InstallationID)
	if err != nil {
		t.Fatalf("ListRepositoriesNeedingInitialScan() error = %v", err)
	}
	var names []string
	for _, repo := range repos {
		names = append(names, repo.Name)
	}
	if fmt.Sprint(names) != "[api web]" {
		t.Errorf("needing initial scan = %v, want [api web]", names)
	}
}

func mustLatestScan(t *testing.T, db *storage.DB, repoID int64) models.Scan {
	t.Helper()
	scans := scansFor(t, db, repoID)
	if len(scans) == 0 {
		t.Fatalf("repository %d has no scans", repoID)
	}
	return scans[0]
}

// A pull request scan does not stop the initial scan, and the initial scan
// of the same commit is a separate default-branch row, not a conflict.
func TestInitialScanAfterPullRequestScan(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	pr, err := db.UpsertPullRequest(ctx, models.PullRequest{RepositoryID: api.ID, Number: 3, State: "open",
		BaseSHA: "1111111111111111111111111111111111111111", HeadSHA: headSHA})
	if err != nil {
		t.Fatalf("UpsertPullRequest() error = %v", err)
	}
	if _, err := db.CreateScan(ctx, models.Scan{RepositoryID: api.ID, PullRequestID: &pr.ID,
		CommitSHA: headSHA, Trigger: models.TriggerPullRequest}); err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}

	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	if err := newInitialScanner(db, heads).Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	initial, err := db.FindInitialScan(ctx, api.ID)
	if err != nil || initial.PullRequestID != nil || initial.CommitSHA != headSHA {
		t.Errorf("initial scan = %+v (err %v), want a default-branch scan of %s", initial, err, headSHA)
	}
}

// A failed initial scan whose scan job died is run again -- the same scan,
// with a fresh job -- instead of leaving the repository without a baseline.
func TestInitialScanRetriesFailedScan(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	scanner := newInitialScanner(db, heads)
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	scan := mustLatestScan(t, db, api.ID)
	if err := db.MarkScanFailed(ctx, scan.ID, "clone failed"); err != nil {
		t.Fatalf("MarkScanFailed() error = %v", err)
	}

	// While the scan job is still waiting to retry, nothing new is queued.
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := jobsOfKind(t, db, queue.KindScan); len(got) != 1 {
		t.Fatalf("scan jobs = %d, want 1 while the first can still retry", len(got))
	}

	killJobs(t, db, queue.KindScan)
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var queued int
	if err := db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan' AND status = 'queued' AND dedupe_key = $1`,
		fmt.Sprintf("scan:%d", scan.ID)).Scan(&queued); err != nil || queued != 1 {
		t.Errorf("fresh scan jobs for scan %d = %d (err %v), want 1", scan.ID, queued, err)
	}
	if n := len(scansFor(t, db, api.ID)); n != 1 {
		t.Errorf("scans = %d, want the failed scan reused, not duplicated", n)
	}
	if heads.calls != 1 {
		t.Errorf("GitHub asked %d times, want once", heads.calls)
	}

	// Once a push has given the repository history, the failed initial scan
	// is left alone.
	killJobs(t, db, queue.KindScan)
	dispatch(t, h, pushAt(1001, "api", "9999999999999999999999999999999999999999"))
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var retried int
	if err := db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan' AND status = 'queued' AND dedupe_key = $1`,
		fmt.Sprintf("scan:%d", scan.ID)).Scan(&retried); err != nil || retried != 0 {
		t.Errorf("retries of the failed initial scan after a push = %d (err %v), want 0", retried, err)
	}
}

// If GitHub now names the repository differently from the stored row, the
// worker would clone by the stale name; nothing is scanned until
// reconciliation has stored the new one.
func TestInitialScanSkipsRenamedRepository(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api-v2", Branch: "main", SHA: headSHA}}
	if err := newInitialScanner(db, heads).Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := scanCount(t, db); got != 0 {
		t.Errorf("scans = %d, want 0 for a renamed repository", got)
	}
}

// Crashing after the scan job was queued but before the initial job was
// marked done: the reclaimed job finds everything in place and adds nothing.
func TestInitialScanRerunAfterEnqueueIsNoOp(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	scanner := newInitialScanner(db, heads)
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// The scan job is picked up and starts before the initial job reruns.
	if err := db.MarkScanRunning(ctx, mustLatestScan(t, db, api.ID).ID); err != nil {
		t.Fatalf("MarkScanRunning() error = %v", err)
	}
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if n, jobs := len(scansFor(t, db, api.ID)), jobsOfKind(t, db, queue.KindScan); n != 1 || len(jobs) != 1 {
		t.Errorf("scans = %d, scan jobs = %d; want 1 and 1", n, len(jobs))
	}
}

// A pending initial scan whose scan job died before the scanner could mark
// the scan failed must not stay stranded behind the dead job's key.
func TestInitialScanRequeuesPendingScanWithDeadJob(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	scanner := newInitialScanner(db, &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}})
	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	killJobs(t, db, queue.KindScan)

	if err := scanner.Run(ctx, api.ID); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var queued int
	if err := db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan' AND status = 'queued'`).
		Scan(&queued); err != nil || queued != 1 {
		t.Errorf("queued scan jobs = %d (err %v), want 1", queued, err)
	}
}
