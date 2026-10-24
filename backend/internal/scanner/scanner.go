// Package scanner runs the end-to-end analysis for one commit: clone, generate
// an SBOM, archive it, diff it against the right baseline, persist the result,
// and report back to GitHub.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"sbomdelta/internal/config"
	"sbomdelta/internal/diff"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/storage"
)

type Scanner struct {
	db        *storage.DB
	blob      *storage.BlobStore
	app       *ghapp.App
	generator *sbom.Generator
	cfg       config.Scanner
	logger    *slog.Logger
}

func New(db *storage.DB, blob *storage.BlobStore, app *ghapp.App, generator *sbom.Generator, cfg config.Scanner, logger *slog.Logger) *Scanner {
	return &Scanner{db: db, blob: blob, app: app, generator: generator, cfg: cfg, logger: logger}
}

// Run executes one scan. Failures are recorded on the scan row and reported on
// the check run before being returned, so the queue's retry logic and the
// user-visible state stay in agreement.
func (s *Scanner) Run(ctx context.Context, scanID int64) error {
	scan, err := s.db.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("load scan %d: %w", scanID, err)
	}
	repo, err := s.db.GetRepository(ctx, scan.RepositoryID)
	if err != nil {
		return fmt.Errorf("load repository for scan %d: %w", scanID, err)
	}

	logger := s.logger.With("scan", scanID, "repo", repo.FullName(), "commit", short(scan.CommitSHA))

	// Access can be revoked between queueing and running. That is permanent
	// as far as this scan is concerned, so record it on the scan and finish
	// the job instead of letting the queue retry it into the dead letter.
	if !repo.Accessible() {
		cause := fmt.Sprintf("SBOMDelta no longer has access to %s (%s)", repo.FullName(), repo.Access)
		logger.Warn("skipping scan of inaccessible repository", "access", repo.Access)
		return s.db.MarkScanFailed(ctx, scan.ID, cause)
	}

	logger.Info("starting scan", "trigger", scan.Trigger)

	access, err := s.resolveAccess(ctx, repo)
	if err != nil {
		return err
	}

	checkRunID := s.openCheckRun(ctx, logger, scan, repo, access)

	if err := s.db.MarkScanRunning(ctx, scan.ID); err != nil {
		return err
	}

	result, err := s.execute(ctx, logger, scan, repo, access)
	if err != nil {
		s.recordFailure(ctx, logger, scan, repo, access, checkRunID, err)
		return err
	}

	if checkRunID != 0 {
		baseline := result.BaseScanID == nil
		if err := s.app.CompleteCheckRun(ctx, access.installationID, checkRunID, repo, result.Diff, baseline); err != nil {
			// The analysis is saved; a check-run write failure should not
			// invalidate it, so log and move on.
			logger.Error("could not publish check run result", "error", err)
		}
	}

	logger.Info("scan complete",
		"components", len(result.Components),
		"added", len(result.Diff.Added),
		"updated", len(result.Diff.Updated),
		"removed", len(result.Diff.Removed))
	return nil
}

// execute is the part of the pipeline that can fail loudly; Run wraps it with
// state transitions and reporting.
func (s *Scanner) execute(ctx context.Context, logger *slog.Logger, scan models.Scan, repo models.Repository, access repoAccess) (*storage.ScanResult, error) {
	components, location, digest, err := s.buildSBOM(ctx, logger, scan.ID, scan.CommitSHA, repo, access)
	if err != nil {
		return nil, err
	}

	baseScanID, baseComponents, err := s.resolveBase(ctx, logger, scan, repo, access)
	if err != nil {
		return nil, err
	}

	comparison := diff.Compare(baseComponents, components)

	result := &storage.ScanResult{
		ScanID:       scan.ID,
		BaseScanID:   baseScanID,
		SBOMLocation: location,
		SBOMSHA256:   digest,
		Components:   components,
		Diff:         comparison,
	}
	if err := s.db.SaveScanResult(ctx, *result); err != nil {
		return nil, err
	}
	return result, nil
}

// buildSBOM clones the commit, runs the generator over it and archives the raw
// document. The working tree is removed whether or not the scan succeeds.
func (s *Scanner) buildSBOM(ctx context.Context, logger *slog.Logger, scanID int64, commitSHA string, repo models.Repository, access repoAccess) (components []sbom.Component, location, digest string, err error) {
	cloneURL, err := s.cloneURL(ctx, repo, access)
	if err != nil {
		return nil, "", "", err
	}

	dir, err := sbom.WorkDir(s.cfg, scanID)
	if err != nil {
		return nil, "", "", err
	}
	defer func() {
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			logger.Error("could not clean up work directory", "dir", dir, "error", removeErr)
		}
	}()

	started := time.Now()
	if err := sbom.Clone(ctx, s.cfg, cloneURL, commitSHA, dir); err != nil {
		return nil, "", "", fmt.Errorf("clone %s at %s: %w", repo.FullName(), short(commitSHA), err)
	}
	logger.Debug("cloned repository", "duration", time.Since(started))

	started = time.Now()
	document, err := s.generator.Generate(ctx, dir)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate sbom for %s: %w", short(commitSHA), err)
	}
	logger.Debug("generated sbom", "duration", time.Since(started), "components", len(document.Components), "tool", document.Tool)

	location, digest, err = s.blob.PutSBOM(ctx, storage.SBOMKey(repo.ID, commitSHA), document.Raw)
	if err != nil {
		return nil, "", "", err
	}
	return document.Components, location, digest, nil
}

// resolveBase decides what this scan is measured against.
//
//   - A pull request is compared against its base commit, so the diff shows
//     only what the PR itself changes.
//   - A push is compared against the previous tip of the default branch.
//   - When neither exists, the scan is the repository's baseline and there is
//     nothing to diff against.
//
// A nil component slice (as opposed to an empty one) tells the diff engine
// this is a baseline rather than a repository that genuinely had no
// dependencies.
func (s *Scanner) resolveBase(ctx context.Context, logger *slog.Logger, scan models.Scan, repo models.Repository, access repoAccess) (*int64, []sbom.Component, error) {
	if scan.BaseCommitSHA != "" {
		base, err := s.db.CompletedScanForCommit(ctx, repo.ID, scan.BaseCommitSHA)
		switch {
		case err == nil:
		case errors.Is(err, storage.ErrNotFound):
			// The base commit predates this app's installation, or landed
			// while the worker was down. Scan it now so the comparison is
			// against the real base rather than against nothing.
			logger.Info("base commit has no scan; backfilling", "base", short(scan.BaseCommitSHA))
			base, err = s.backfill(ctx, logger, repo, scan.BaseCommitSHA, access)
			if err != nil {
				logger.Warn("could not backfill base commit; treating this scan as a baseline",
					"base", short(scan.BaseCommitSHA), "error", err)
				return nil, nil, nil
			}
		default:
			return nil, nil, err
		}

		components, err := s.db.ListComponents(ctx, base.ID)
		if err != nil {
			return nil, nil, err
		}
		return &base.ID, components, nil
	}

	base, err := s.db.LatestCompletedScan(ctx, repo.ID, scan.ID, scan.CreatedAt)
	if errors.Is(err, storage.ErrNotFound) {
		logger.Info("no previous scan; recording baseline")
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	components, err := s.db.ListComponents(ctx, base.ID)
	if err != nil {
		return nil, nil, err
	}
	return &base.ID, components, nil
}

// backfill materializes a scan for a commit that was never scanned. It records
// components only: a backfilled commit is a reference point, not a drift event
// in its own right, so it is never diffed and never reported to GitHub.
func (s *Scanner) backfill(ctx context.Context, logger *slog.Logger, repo models.Repository, commitSHA string, access repoAccess) (models.Scan, error) {
	scan, err := s.db.CreateScan(ctx, models.Scan{
		RepositoryID: repo.ID,
		CommitSHA:    commitSHA,
		Trigger:      models.TriggerBackfill,
	})
	if err != nil {
		return models.Scan{}, err
	}
	if scan.Status == models.ScanCompleted {
		return scan, nil
	}

	if err := s.db.MarkScanRunning(ctx, scan.ID); err != nil {
		return models.Scan{}, err
	}

	components, location, digest, err := s.buildSBOM(ctx, logger, scan.ID, commitSHA, repo, access)
	if err != nil {
		if markErr := s.db.MarkScanFailed(ctx, scan.ID, err.Error()); markErr != nil {
			logger.Error("could not mark backfill scan failed", "scan", scan.ID, "error", markErr)
		}
		return models.Scan{}, err
	}

	if err := s.db.SaveScanResult(ctx, storage.ScanResult{
		ScanID:       scan.ID,
		SBOMLocation: location,
		SBOMSHA256:   digest,
		Components:   components,
	}); err != nil {
		return models.Scan{}, err
	}

	scan.Status = models.ScanCompleted
	logger.Info("backfilled base scan", "scan", scan.ID, "components", len(components))
	return scan, nil
}

func (s *Scanner) openCheckRun(ctx context.Context, logger *slog.Logger, scan models.Scan, repo models.Repository, access repoAccess) int64 {
	if scan.Trigger == models.TriggerBackfill || scan.Trigger == models.TriggerManual {
		return 0
	}
	// A manually registered repository has no installation to post a check as.
	if access.anonymous {
		return 0
	}
	if scan.GitHubCheckRunID != nil {
		return *scan.GitHubCheckRunID
	}

	checkRunID, err := s.app.StartCheckRun(ctx, access.installationID, repo, scan.CommitSHA)
	if err != nil {
		// A missing check is a degraded experience, not a reason to skip the
		// analysis; the dashboard still gets the result.
		logger.Warn("could not open check run", "error", err)
		return 0
	}
	if err := s.db.SetScanCheckRunID(ctx, scan.ID, checkRunID); err != nil {
		logger.Error("could not store check run id", "error", err)
	}
	return checkRunID
}

func (s *Scanner) recordFailure(ctx context.Context, logger *slog.Logger, scan models.Scan, repo models.Repository, access repoAccess, checkRunID int64, cause error) {
	// The caller's context may already be cancelled by a shutdown; failure
	// bookkeeping still needs to reach the database.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	if err := s.db.MarkScanFailed(ctx, scan.ID, cause.Error()); err != nil {
		logger.Error("could not mark scan failed", "error", err)
	}
	if checkRunID != 0 {
		if err := s.app.FailCheckRun(ctx, access.installationID, checkRunID, repo, cause.Error()); err != nil {
			logger.Error("could not report scan failure to github", "error", err)
		}
	}
}

// repoAccess says how the worker reaches a repository's source.
type repoAccess struct {
	installationID int64
	// anonymous marks a repository registered by hand rather than through the
	// GitHub App: it is cloned without credentials and gets no check run,
	// because there is no installation to act as.
	anonymous bool
	cloneURL  string
}

// resolveAccess decides whether this repository is reached through a GitHub
// App installation or cloned anonymously.
func (s *Scanner) resolveAccess(ctx context.Context, repo models.Repository) (repoAccess, error) {
	installationID, err := s.db.GetInstallationIDForRepo(ctx, repo.ID)
	if err == nil {
		if s.app == nil {
			return repoAccess{}, fmt.Errorf(
				"%s is managed by a GitHub installation but this worker has GitHub disabled", repo.FullName())
		}
		return repoAccess{installationID: installationID}, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return repoAccess{}, fmt.Errorf("look up installation for %s: %w", repo.FullName(), err)
	}

	if repo.CloneURL == "" {
		return repoAccess{}, fmt.Errorf(
			"%s has no GitHub installation and no clone url, so there is nothing to clone", repo.FullName())
	}
	return repoAccess{anonymous: true, cloneURL: repo.CloneURL}, nil
}

// cloneURL mints a credentialed URL for App-managed repositories and uses the
// stored public URL for manually registered ones.
func (s *Scanner) cloneURL(ctx context.Context, repo models.Repository, access repoAccess) (string, error) {
	if access.anonymous {
		return access.cloneURL, nil
	}
	token, err := s.app.InstallationToken(ctx, access.installationID)
	if err != nil {
		return "", err
	}
	return ghapp.CloneURL(repo.Owner, repo.Name, token), nil
}

func short(sha string) string {
	if len(sha) <= 7 {
		return sha
	}
	return sha[:7]
}
