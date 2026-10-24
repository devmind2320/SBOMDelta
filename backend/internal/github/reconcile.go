package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	gh "github.com/google/go-github/v66/github"

	"sbomdelta/internal/models"
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
	logger *slog.Logger
}

func NewReconciler(lister RepositoryLister, db *storage.DB, logger *slog.Logger) *Reconciler {
	return &Reconciler{lister: lister, db: db, logger: logger}
}

// Reconcile re-reads one installation's repositories. If GitHub cannot be
// reached it returns the error and changes nothing; it never treats a failed
// listing as "no repositories", which would revoke everything.
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
	return nil
}
