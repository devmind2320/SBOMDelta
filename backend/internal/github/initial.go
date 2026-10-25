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

// HeadResolver is the part of the GitHub API an initial scan needs. *App
// satisfies it; tests substitute a fixed answer.
type HeadResolver interface {
	DefaultBranchHead(ctx context.Context, installationID, githubRepoID int64) (BranchHead, error)
}

// InitialScanner gives a repository the App can reach its first scan, at the
// head of its default branch, so it does not sit empty until someone pushes.
//
// It runs on the worker, never in a webhook handler: resolving the head is a
// GitHub API round trip, and webhook deliveries must answer quickly.
type InitialScanner struct {
	heads  HeadResolver
	db     *storage.DB
	queue  *queue.Queue
	logger *slog.Logger
}

func NewInitialScanner(heads HeadResolver, db *storage.DB, q *queue.Queue, logger *slog.Logger) *InitialScanner {
	return &InitialScanner{heads: heads, db: db, queue: q, logger: logger}
}

// Run handles one initial_scan job. Returning nil finishes the job; returning
// an error retries it with backoff, which is reserved for failures that may
// clear up -- GitHub being unreachable or rate limiting, a database error.
// Nothing is ever recorded in place of a scan that could not be created, so a
// failed lookup cannot leave behind an empty baseline.
func (s *InitialScanner) Run(ctx context.Context, repositoryID int64) error {
	repo, err := s.db.GetRepository(ctx, repositoryID)
	if errors.Is(err, storage.ErrNotFound) {
		s.logger.Info("skipping initial scan of deleted repository", "repository", repositoryID)
		return nil
	}
	if err != nil {
		return err
	}
	logger := s.logger.With("repo", repo.FullName(), "repository", repo.ID)

	// Access can change between reconciliation and this job running.
	if !repo.Accessible() {
		logger.Info("skipping initial scan of inaccessible repository", "access", repo.Access)
		return nil
	}

	existing, err := s.db.FindInitialScan(ctx, repo.ID)
	found := err == nil
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	// A retry after a crash between creating the scan and queueing it finds
	// the scan pending here and only queues it.
	if found && existing.Status == models.ScanPending {
		return s.requeue(ctx, logger, existing, repo.FullName())
	}

	needed, err := s.db.NeedsInitialScan(ctx, repo.ID)
	if err != nil {
		return err
	}
	if !needed {
		logger.Info("skipping initial scan: repository already has default-branch history")
		return nil
	}
	if found {
		// Only a failed initial scan reaches here: running and completed
		// ones count as history. Run it again rather than adding another.
		return s.requeue(ctx, logger, existing, repo.FullName())
	}

	installationID, err := s.db.GetInstallationIDForRepo(ctx, repo.ID)
	if errors.Is(err, storage.ErrNotFound) || repo.GitHubRepoID == nil {
		logger.Info("skipping initial scan: repository has no GitHub installation")
		return nil
	}
	if err != nil {
		return err
	}

	head, err := s.heads.DefaultBranchHead(ctx, installationID, *repo.GitHubRepoID)
	if errors.Is(err, ErrNoBranchHead) {
		// An empty repository is scanned by the push that gives it a first
		// commit; one the installation can no longer see is revoked by the
		// next reconciliation, which also re-queues this job if it is still
		// reachable with no history.
		logger.Info("skipping initial scan: no default branch head", "reason", err)
		return nil
	}
	if err != nil {
		return err
	}
	// The worker clones by the stored owner/name. If GitHub now calls the
	// repository something else, cloning could reach the wrong repository;
	// the next reconciliation stores the new name and queues this again.
	if !strings.EqualFold(head.FullName(), repo.FullName()) {
		logger.Info("skipping initial scan: repository was renamed", "github_name", head.FullName())
		return nil
	}

	// The lookup took a network round trip; access may have been revoked or
	// the installation suspended meanwhile.
	repo, err = s.db.GetRepository(ctx, repo.ID)
	if err != nil {
		return err
	}
	if !repo.Accessible() {
		logger.Info("skipping initial scan: access lost while resolving head", "access", repo.Access)
		return nil
	}

	if err := s.db.UpsertCommit(ctx, models.Commit{
		RepositoryID: repo.ID,
		SHA:          head.SHA,
		Ref:          "refs/heads/" + head.Branch,
	}); err != nil {
		return err
	}

	scan, created, err := s.db.CreateInitialScan(ctx, repo.ID, head.SHA)
	if err != nil {
		return err
	}
	if !created {
		// A push scan landed while the head was being resolved. It becomes
		// the baseline instead.
		logger.Info("skipping initial scan: another scan was created first")
		return nil
	}
	logger.Info("created initial scan", "scan", scan.ID, "branch", head.Branch, "commit", short(head.SHA))
	return enqueuePendingScan(ctx, s.queue, logger, scan, repo.FullName())
}

// requeue queues an existing pending or failed initial scan. Its scan job may
// never have been queued (a crash), may still be queued or retrying -- it
// keeps its key, so this is a no-op -- or may have exhausted its retries and
// still hold the scan's dedupe key, which is released here so the scan is not
// stranded. A finished job released its key already.
func (s *InitialScanner) requeue(ctx context.Context, logger *slog.Logger, scan models.Scan, fullName string) error {
	dedupeKey := fmt.Sprintf("scan:%d", scan.ID)
	if _, err := s.queue.ReleaseDeadDedupeKey(ctx, dedupeKey); err != nil {
		return err
	}
	jobID, err := s.queue.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: scan.ID}, dedupeKey)
	if err != nil {
		return err
	}
	if jobID == 0 {
		logger.Info("initial scan job already queued", "scan", scan.ID)
		return nil
	}
	logger.Info("queued initial scan", "scan", scan.ID, "status", scan.Status, "job", jobID,
		"repo", fullName, "commit", short(scan.CommitSHA))
	return nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
