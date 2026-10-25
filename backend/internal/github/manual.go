package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

// ScanOutcome says what a scan request did.
type ScanOutcome string

const (
	// ScanQueued: a scan of the default branch head is waiting for the worker,
	// whether this request created it or an earlier one did.
	ScanQueued ScanOutcome = "queued"
	// ScanInProgress: that commit is being scanned right now.
	ScanInProgress ScanOutcome = "in_progress"
	// ScanUpToDate: that commit was already scanned successfully; its results
	// are current, so nothing is run again.
	ScanUpToDate ScanOutcome = "up_to_date"
	// ScanRetried: an earlier scan of that commit failed and was queued again.
	ScanRetried ScanOutcome = "retried"
)

// ErrHeadLookupFailed wraps a failure to ask GitHub for the default branch
// head that may clear up on retry: GitHub unreachable, rate limiting, a 5xx.
var ErrHeadLookupFailed = errors.New("could not resolve the default branch head")

// NotScannableError is a scan request that cannot be met as things stand, with
// a fixed reason the dashboard can explain. Retrying will not help until the
// repository itself changes.
type NotScannableError struct {
	Reason string
}

func (e *NotScannableError) Error() string { return "repository cannot be scanned: " + e.Reason }

// Reasons for NotScannableError.
const (
	NotScannableNoAccess     = "no_access"      // the App can no longer reach it
	NotScannableNoBranchHead = "no_branch_head" // empty, or no default branch
	NotScannableRenamed      = "renamed"        // GitHub's name differs from the stored one
)

// ManualScanner scans a repository's default branch head when someone asks.
// It follows the same steps as InitialScanner -- resolve the head as the
// installation, re-check access, record the commit, create the scan through
// the deduplicating CreateScan, queue the existing scan job -- so the worker
// runs it exactly like any other scan.
type ManualScanner struct {
	heads  HeadResolver
	db     *storage.DB
	queue  *queue.Queue
	logger *slog.Logger
}

func NewManualScanner(heads HeadResolver, db *storage.DB, q *queue.Queue, logger *slog.Logger) *ManualScanner {
	return &ManualScanner{heads: heads, db: db, queue: q, logger: logger}
}

// Request scans the repository's default branch head. The caller has already
// checked that the requesting user may access the repository.
//
// One scan exists per commit, so asking twice while a scan is waiting or
// running returns that scan, and asking again for a commit that was already
// scanned successfully returns that result rather than repeating it.
func (m *ManualScanner) Request(ctx context.Context, repositoryID int64) (models.Scan, ScanOutcome, error) {
	repo, err := m.db.GetRepository(ctx, repositoryID)
	if err != nil {
		return models.Scan{}, "", err
	}
	logger := m.logger.With("repo", repo.FullName(), "repository", repo.ID)

	if !repo.Accessible() || repo.GitHubRepoID == nil {
		return models.Scan{}, "", &NotScannableError{Reason: NotScannableNoAccess}
	}
	installationID, err := m.db.GetInstallationIDForRepo(ctx, repo.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return models.Scan{}, "", &NotScannableError{Reason: NotScannableNoAccess}
	}
	if err != nil {
		return models.Scan{}, "", err
	}

	head, err := m.heads.DefaultBranchHead(ctx, installationID, *repo.GitHubRepoID)
	if errors.Is(err, ErrNoBranchHead) {
		return models.Scan{}, "", &NotScannableError{Reason: NotScannableNoBranchHead}
	}
	if err != nil {
		return models.Scan{}, "", fmt.Errorf("%w: %w", ErrHeadLookupFailed, err)
	}
	// The worker clones by the stored owner/name; if GitHub now uses another
	// name, cloning could reach a different repository. The installation's
	// next reconciliation stores the new name.
	if !strings.EqualFold(head.FullName(), repo.FullName()) {
		return models.Scan{}, "", &NotScannableError{Reason: NotScannableRenamed}
	}

	// The lookup was a network round trip; access may have changed meanwhile.
	repo, err = m.db.GetRepository(ctx, repo.ID)
	if err != nil {
		return models.Scan{}, "", err
	}
	if !repo.Accessible() {
		return models.Scan{}, "", &NotScannableError{Reason: NotScannableNoAccess}
	}

	if err := m.db.UpsertCommit(ctx, models.Commit{
		RepositoryID: repo.ID, SHA: head.SHA, Ref: "refs/heads/" + head.Branch,
	}); err != nil {
		return models.Scan{}, "", err
	}
	scan, err := m.db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID, CommitSHA: head.SHA, Trigger: models.TriggerManual,
	})
	if err != nil {
		return models.Scan{}, "", err
	}

	switch scan.Status {
	case models.ScanCompleted:
		logger.Info("scan requested for a commit already scanned", "scan", scan.ID, "commit", short(head.SHA))
		return scan, ScanUpToDate, nil
	case models.ScanRunning:
		return scan, ScanInProgress, nil
	case models.ScanFailed:
		requeued, err := m.db.RequeueFailedScan(ctx, scan.ID)
		if err != nil {
			return models.Scan{}, "", err
		}
		if requeued {
			scan.Status, scan.Error, scan.StartedAt, scan.FinishedAt = models.ScanPending, "", nil, nil
		}
		if err := requeueScan(ctx, m.queue, logger, scan, repo.FullName()); err != nil {
			return models.Scan{}, "", err
		}
		return scan, ScanRetried, nil
	}

	// Pending: created here, or by an earlier request or push and not yet
	// picked up. Queueing is idempotent per scan, so a repeated request
	// returns the same scan without adding a second job.
	if err := requeueScan(ctx, m.queue, logger, scan, repo.FullName()); err != nil {
		return models.Scan{}, "", err
	}
	return scan, ScanQueued, nil
}
