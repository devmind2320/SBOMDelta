package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

// RepositoryLister is the part of the GitHub API reconciliation needs. *App
// satisfies it; tests substitute a fixed list.
type RepositoryLister interface {
	ListInstallationRepositories(ctx context.Context, installationID int64) ([]*gh.Repository, error)
}

// Reconciler brings stored repository access in line with what GitHub says an
// installation can reach right now.
//
// Webhooks alone are not enough. An installation event can arrive with an
// empty repository list, a removal can be delivered while the server is down,
// and nothing is ever redelivered after GitHub gives up retrying. Asking
// GitHub directly is the only source of truth that cannot drift.
type Reconciler struct {
	lister RepositoryLister
	db     *storage.DB
	queue  *queue.Queue
	logger *slog.Logger
}

func NewReconciler(lister RepositoryLister, db *storage.DB, q *queue.Queue, logger *slog.Logger) *Reconciler {
	return &Reconciler{lister: lister, db: db, queue: q, logger: logger}
}

// initialScanStagger spaces out initial scans across every installation.
// Installing the App on an account with hundreds of repositories, or a worker
// starting with several such installations, would otherwise put hundreds of
// clones at the front of the queue at once, and every push and pull request
// scan would wait behind them.
const initialScanStagger = 15 * time.Second

// Reconcile re-reads one installation's repositories, then queues an initial
// scan for every accessible repository that has never been scanned. If GitHub
// cannot be reached it returns the error and changes nothing; it never treats
// a failed listing as "no repositories", which would revoke everything.
func (r *Reconciler) Reconcile(ctx context.Context, githubInstallationID int64) error {
	logger := r.logger.With("installation", githubInstallationID)

	installation, err := r.db.GetInstallationByGitHubID(ctx, githubInstallationID)
	if errors.Is(err, storage.ErrNotFound) {
		// The installation event that creates the row has not been processed
		// yet. It enqueues its own reconciliation, so there is nothing to do.
		logger.Info("skipping reconciliation of unknown installation")
		return nil
	}
	if err != nil {
		return err
	}
	if installation.DeletedAt != nil || installation.SuspendedAt != nil {
		// No token can be minted. Access is already reported as uninstalled
		// or suspended from the installation row itself.
		logger.Info("skipping reconciliation of unusable installation",
			"deleted", installation.DeletedAt != nil, "suspended", installation.SuspendedAt != nil)
		return nil
	}

	listedAt, err := r.db.Now(ctx)
	if err != nil {
		return err
	}
	listed, err := r.lister.ListInstallationRepositories(ctx, githubInstallationID)
	if err != nil {
		return err
	}

	repos := make([]models.Repository, 0, len(listed))
	for _, repo := range listed {
		model, err := repositoryFromGitHub(installation.ID, repo, installation.AccountLogin)
		if err != nil {
			return fmt.Errorf("reconcile installation %d: %w", githubInstallationID, err)
		}
		repos = append(repos, model)
	}

	result, err := r.db.ReconcileInstallationRepositories(ctx, installation.ID, repos, listedAt)
	if errors.Is(err, storage.ErrInstallationUnusable) {
		// Uninstalled or suspended while GitHub was being paged through. The
		// listing is no longer meaningful, and access is already reported
		// from the installation row.
		logger.Info("abandoned reconciliation: installation became unusable during listing")
		return nil
	}
	if err != nil {
		return err
	}
	logger.Info("reconciled installation repositories",
		"account", installation.AccountLogin, "accessible", result.Accessible, "revoked", result.Revoked)

	return r.enqueueInitialScans(ctx, logger, installation.ID)
}

// enqueueInitialScans queues one initial_scan job per repository with no
// default-branch history. The dedupe key makes this safe to repeat: every
// worker start and every webhook reconciles again, and a repository whose job
// is still queued, running or waiting to retry is not queued a second time.
//
// A job that exhausted its retries would hold its key forever, so its key is
// released first and the repository gets a fresh job. That retries a
// persistent failure once per reconciliation -- worker starts and
// installation webhooks -- never in a tight loop.
func (r *Reconciler) enqueueInitialScans(ctx context.Context, logger *slog.Logger, installationID int64) error {
	repos, err := r.db.ListRepositoriesNeedingInitialScan(ctx, installationID)
	if err != nil {
		return err
	}

	queued := 0
	for _, repo := range repos {
		dedupeKey := fmt.Sprintf("initial:%d", repo.ID)
		if _, err := r.queue.ReleaseDeadDedupeKey(ctx, dedupeKey); err != nil {
			return err
		}
		jobID, err := r.queue.EnqueueSpaced(ctx, queue.KindInitialScan,
			queue.InitialScanPayload{RepositoryID: repo.ID}, dedupeKey, initialScanStagger)
		if err != nil {
			return err
		}
		if jobID != 0 {
			queued++
		}
	}
	if len(repos) > 0 {
		logger.Info("queued initial scans", "needing", len(repos), "queued", queued)
	}
	return nil
}
