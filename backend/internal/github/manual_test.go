package github

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

func newManualScanner(db *storage.DB, heads HeadResolver) *ManualScanner {
	return NewManualScanner(heads, db, testQueue(db), discardLogger())
}

// A scan request creates one manual scan at the default branch head, records
// the commit, and queues the ordinary scan job the worker runs.
func TestManualScanQueuesScanAtDefaultBranchHead(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")

	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "trunk", SHA: headSHA}}
	scan, outcome, err := newManualScanner(db, heads).Request(ctx, api.ID)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if outcome != ScanQueued || scan.Trigger != models.TriggerManual || scan.CommitSHA != headSHA ||
		scan.Status != models.ScanPending || scan.RepositoryID != api.ID {
		t.Errorf("Request() = %+v, %s; want a pending manual scan of %s, queued", scan, outcome, headSHA)
	}
	if heads.installation != testInstallationID || heads.githubRepoID != 1001 {
		t.Errorf("head resolved for installation %d repository %d, want %d/1001", heads.installation, heads.githubRepoID, testInstallationID)
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

// Clicking Scan twice, or two people scanning at once, while the first scan
// waits or runs returns that scan; no second scan and no second job.
func TestManualScanDuplicateRequestsShareOneScan(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	scanner := newManualScanner(db, heads)

	first, _, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, outcome, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || outcome != ScanQueued {
		t.Errorf("second request = scan %d %s, want scan %d still queued", second.ID, outcome, first.ID)
	}

	if err := db.MarkScanRunning(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	third, outcome, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if third.ID != first.ID || outcome != ScanInProgress {
		t.Errorf("request while running = scan %d %s, want scan %d in progress", third.ID, outcome, first.ID)
	}
	if scans := scansFor(t, db, api.ID); len(scans) != 1 {
		t.Errorf("scans = %d, want 1", len(scans))
	}
	if jobs := jobsOfKind(t, db, queue.KindScan); len(jobs) != 1 {
		t.Errorf("scan jobs = %d, want 1", len(jobs))
	}
}

// A commit already scanned successfully is not scanned again: its results
// are current. A new commit on the branch gets a new scan.
func TestManualScanOfAnAlreadyScannedCommit(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	scanner := newManualScanner(db, heads)

	first, _, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveScanResult(ctx, storage.ScanResult{ScanID: first.ID}); err != nil {
		t.Fatal(err)
	}
	again, outcome, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID || outcome != ScanUpToDate || again.Status != models.ScanCompleted {
		t.Errorf("request for the same commit = scan %d %s %s, want scan %d up to date", again.ID, outcome, again.Status, first.ID)
	}
	if jobs := jobsOfKind(t, db, queue.KindScan); len(jobs) != 1 {
		t.Errorf("scan jobs = %d, want only the first", len(jobs))
	}

	heads.head.SHA = "1234567890123456789012345678901234567890"
	next, outcome, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if next.ID == first.ID || outcome != ScanQueued || next.CommitSHA != heads.head.SHA {
		t.Errorf("request after a new commit = %+v %s, want a new queued scan", next, outcome)
	}
}

// A failed scan of the same commit runs again rather than being duplicated,
// and goes back to pending so the dashboard shows it queued.
func TestManualScanRetriesAFailedScan(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	heads := &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA}}
	scanner := newManualScanner(db, heads)

	first, _, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkScanFailed(ctx, first.ID, "syft crashed"); err != nil {
		t.Fatal(err)
	}
	killJobs(t, db, queue.KindScan) // its job exhausted its retries and holds the key

	retried, outcome, err := scanner.Request(ctx, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.ID != first.ID || outcome != ScanRetried || retried.Status != models.ScanPending || retried.Error != "" {
		t.Errorf("retry = %+v %s, want scan %d pending again", retried, outcome, first.ID)
	}
	stored, err := db.GetScan(ctx, first.ID)
	if err != nil || stored.Status != models.ScanPending || stored.Error != "" {
		t.Errorf("stored scan = %+v (%v), want pending with the old error cleared", stored, err)
	}
	queued := 0
	if err := db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = 'scan' AND status = 'queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Errorf("queued scan jobs = %d, want the retry", queued)
	}
}

func TestManualScanRefusals(t *testing.T) {
	tests := []struct {
		name       string
		heads      *fakeHeads
		loseAccess string
		wantReason string
		wantLookup bool
	}{
		{"empty repository", &fakeHeads{err: fmt.Errorf("x: %w", ErrNoBranchHead)}, "", NotScannableNoBranchHead, false},
		{"renamed on GitHub", &fakeHeads{head: BranchHead{Owner: "devmind2320", Name: "api-v2", Branch: "main", SHA: headSHA}}, "", NotScannableRenamed, false},
		{"access revoked", &fakeHeads{err: errors.New("must not be called")}, "revoked", NotScannableNoAccess, false},
		{"installation suspended", &fakeHeads{err: errors.New("must not be called")}, "suspended", NotScannableNoAccess, false},
		{"GitHub unreachable", &fakeHeads{err: errors.New("HTTP 502")}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, db := newTestHandler(t)
			ctx := context.Background()
			addRepos(t, h, eventRepo(1001, "devmind2320/api"))
			api := repoByName(t, db, "api")
			if tt.loseAccess != "" {
				loseAccess(t, h, db, api, tt.loseAccess)
			}

			_, _, err := newManualScanner(db, tt.heads).Request(ctx, api.ID)
			var refused *NotScannableError
			switch {
			case tt.wantLookup:
				if !errors.Is(err, ErrHeadLookupFailed) || errors.As(err, &refused) {
					t.Errorf("err = %v, want a retryable head lookup failure", err)
				}
			case !errors.As(err, &refused) || refused.Reason != tt.wantReason:
				t.Errorf("err = %v, want NotScannableError %s", err, tt.wantReason)
			}
			if scans := scansFor(t, db, api.ID); len(scans) != 0 {
				t.Errorf("a refused request created scans: %+v", scans)
			}
			if jobs := jobsOfKind(t, db, queue.KindScan); len(jobs) != 0 {
				t.Errorf("a refused request queued jobs: %+v", jobs)
			}
		})
	}
}

// Access lost while GitHub was being asked stops the request too.
func TestManualScanAccessLostDuringLookup(t *testing.T) {
	h, db := newTestHandler(t)
	ctx := context.Background()
	addRepos(t, h, eventRepo(1001, "devmind2320/api"))
	api := repoByName(t, db, "api")
	heads := &fakeHeads{
		head:   BranchHead{Owner: "devmind2320", Name: "api", Branch: "main", SHA: headSHA},
		during: func() { loseAccess(t, h, db, api, "revoked") },
	}
	_, _, err := newManualScanner(db, heads).Request(ctx, api.ID)
	var refused *NotScannableError
	if !errors.As(err, &refused) || refused.Reason != NotScannableNoAccess {
		t.Errorf("err = %v, want no_access", err)
	}
	if scans := scansFor(t, db, api.ID); len(scans) != 0 {
		t.Errorf("scans = %+v, want none", scans)
	}
}
