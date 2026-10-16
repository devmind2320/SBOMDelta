package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/diff"
	"sbomdelta/internal/models"
	"sbomdelta/internal/sbom"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// UpsertInstallation records a GitHub App installation, or refreshes it when
// the app is reinstalled on the same account.
func (db *DB) UpsertInstallation(ctx context.Context, in models.Installation) (models.Installation, error) {
	const query = `
		INSERT INTO installations (github_installation_id, account_login, account_type, suspended_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (github_installation_id) DO UPDATE
		SET account_login = EXCLUDED.account_login,
		    account_type  = EXCLUDED.account_type,
		    suspended_at  = EXCLUDED.suspended_at,
		    deleted_at    = NULL,
		    updated_at    = now()
		RETURNING id, github_installation_id, account_login, account_type, suspended_at, deleted_at`

	var out models.Installation
	err := db.pool.QueryRow(ctx, query, in.GitHubInstallationID, in.AccountLogin, in.AccountType, in.SuspendedAt).
		Scan(&out.ID, &out.GitHubInstallationID, &out.AccountLogin, &out.AccountType, &out.SuspendedAt, &out.DeletedAt)
	if err != nil {
		return models.Installation{}, fmt.Errorf("upsert installation: %w", err)
	}
	return out, nil
}

// MarkInstallationDeleted soft-deletes an installation so that historical scan
// data survives an uninstall.
func (db *DB) MarkInstallationDeleted(ctx context.Context, githubInstallationID int64) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE installations SET deleted_at = now(), updated_at = now() WHERE github_installation_id = $1`,
		githubInstallationID)
	if err != nil {
		return fmt.Errorf("mark installation deleted: %w", err)
	}
	return nil
}

const repositoryColumns = `
	id, installation_id, github_repo_id, owner, name, default_branch, private,
	COALESCE(clone_url, ''), created_at`

func repositoryTargets(repo *models.Repository) []any {
	return []any{
		&repo.ID, &repo.InstallationID, &repo.GitHubRepoID, &repo.Owner, &repo.Name,
		&repo.DefaultBranch, &repo.Private, &repo.CloneURL, &repo.CreatedAt,
	}
}

// UpsertManualRepository registers a repository that is not managed by the
// GitHub App. It is keyed on owner/name because there is no GitHub repo ID to
// key on, and it never clears an existing installation link: adopting a
// manually added repository into the App later should not lose its history.
func (db *DB) UpsertManualRepository(ctx context.Context, repo models.Repository) (models.Repository, error) {
	const query = `
		INSERT INTO repositories (owner, name, default_branch, private, clone_url)
		VALUES ($1, $2, $3, false, $4)
		ON CONFLICT (owner, name) DO UPDATE
		SET default_branch = EXCLUDED.default_branch,
		    clone_url      = EXCLUDED.clone_url,
		    updated_at     = now()
		RETURNING ` + repositoryColumns

	var out models.Repository
	err := db.pool.QueryRow(ctx, query, repo.Owner, repo.Name, repo.DefaultBranch, repo.CloneURL).
		Scan(repositoryTargets(&out)...)
	if err != nil {
		return models.Repository{}, fmt.Errorf("upsert manual repository: %w", err)
	}
	return out, nil
}

// UpsertRepository records a repository, keyed on GitHub's numeric repo ID so
// that a rename or transfer updates the existing row instead of orphaning it.
func (db *DB) UpsertRepository(ctx context.Context, repo models.Repository) (models.Repository, error) {
	const query = `
		INSERT INTO repositories (installation_id, github_repo_id, owner, name, default_branch, private)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (github_repo_id) DO UPDATE
		SET installation_id = COALESCE(EXCLUDED.installation_id, repositories.installation_id),
		    owner           = EXCLUDED.owner,
		    name            = EXCLUDED.name,
		    default_branch  = EXCLUDED.default_branch,
		    private         = EXCLUDED.private,
		    updated_at      = now()
		RETURNING ` + repositoryColumns

	var out models.Repository
	err := db.pool.QueryRow(ctx, query,
		repo.InstallationID, repo.GitHubRepoID, repo.Owner, repo.Name, repo.DefaultBranch, repo.Private,
	).Scan(repositoryTargets(&out)...)
	if err != nil {
		return models.Repository{}, fmt.Errorf("upsert repository: %w", err)
	}
	return out, nil
}

func (db *DB) GetRepository(ctx context.Context, id int64) (models.Repository, error) {
	const query = `SELECT ` + repositoryColumns + ` FROM repositories WHERE id = $1`

	var out models.Repository
	err := db.pool.QueryRow(ctx, query, id).Scan(repositoryTargets(&out)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Repository{}, ErrNotFound
	}
	if err != nil {
		return models.Repository{}, fmt.Errorf("get repository: %w", err)
	}
	return out, nil
}

func (db *DB) ListRepositories(ctx context.Context) ([]models.Repository, error) {
	const query = `SELECT ` + repositoryColumns + ` FROM repositories ORDER BY owner, name`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()

	repos := make([]models.Repository, 0)
	for rows.Next() {
		var repo models.Repository
		if err := rows.Scan(repositoryTargets(&repo)...); err != nil {
			return nil, fmt.Errorf("scan repository: %w", err)
		}
		repos = append(repos, repo)
	}
	return repos, rows.Err()
}

// GetInstallationIDForRepo returns the GitHub installation ID that grants
// access to a repository, which is what the worker needs to mint a token.
func (db *DB) GetInstallationIDForRepo(ctx context.Context, repositoryID int64) (int64, error) {
	const query = `
		SELECT i.github_installation_id
		FROM repositories r
		JOIN installations i ON i.id = r.installation_id
		WHERE r.id = $1 AND i.deleted_at IS NULL`

	var installationID int64
	err := db.pool.QueryRow(ctx, query, repositoryID).Scan(&installationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get installation for repo: %w", err)
	}
	return installationID, nil
}

func (db *DB) UpsertCommit(ctx context.Context, commit models.Commit) error {
	const query = `
		INSERT INTO commits (repository_id, sha, ref, author_login, author_email, message, committed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (repository_id, sha) DO UPDATE
		SET ref          = COALESCE(NULLIF(EXCLUDED.ref, ''), commits.ref),
		    author_login = COALESCE(NULLIF(EXCLUDED.author_login, ''), commits.author_login),
		    author_email = COALESCE(NULLIF(EXCLUDED.author_email, ''), commits.author_email),
		    message      = COALESCE(NULLIF(EXCLUDED.message, ''), commits.message)`

	_, err := db.pool.Exec(ctx, query, commit.RepositoryID, commit.SHA, commit.Ref,
		commit.AuthorLogin, commit.AuthorEmail, commit.Message, commit.CommittedAt)
	if err != nil {
		return fmt.Errorf("upsert commit: %w", err)
	}
	return nil
}

func (db *DB) UpsertPullRequest(ctx context.Context, pr models.PullRequest) (models.PullRequest, error) {
	const query = `
		INSERT INTO pull_requests (repository_id, number, title, author_login, state, base_ref, base_sha, head_sha)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (repository_id, number) DO UPDATE
		SET title      = EXCLUDED.title,
		    state      = EXCLUDED.state,
		    base_ref   = EXCLUDED.base_ref,
		    base_sha   = EXCLUDED.base_sha,
		    head_sha   = EXCLUDED.head_sha,
		    updated_at = now()
		RETURNING id, repository_id, number, title, author_login, state, base_ref, base_sha, head_sha`

	var out models.PullRequest
	err := db.pool.QueryRow(ctx, query, pr.RepositoryID, pr.Number, pr.Title, pr.AuthorLogin,
		pr.State, pr.BaseRef, pr.BaseSHA, pr.HeadSHA,
	).Scan(&out.ID, &out.RepositoryID, &out.Number, &out.Title, &out.AuthorLogin, &out.State,
		&out.BaseRef, &out.BaseSHA, &out.HeadSHA)
	if err != nil {
		return models.PullRequest{}, fmt.Errorf("upsert pull request: %w", err)
	}
	return out, nil
}

const scanColumns = `
	id, repository_id, pull_request_id, base_scan_id, commit_sha, base_commit_sha, trigger, status,
	COALESCE(sbom_location, ''), COALESCE(sbom_sha256, ''), component_count, risk_score, risk_delta,
	github_check_run_id, COALESCE(error, ''), enriched_at, started_at, finished_at, created_at`

func scanScan(row pgx.Row) (models.Scan, error) {
	var out models.Scan
	var baseCommitSHA *string
	err := row.Scan(&out.ID, &out.RepositoryID, &out.PullRequestID, &out.BaseScanID, &out.CommitSHA,
		&baseCommitSHA, &out.Trigger, &out.Status, &out.SBOMLocation, &out.SBOMSHA256, &out.ComponentCount,
		&out.RiskScore, &out.RiskDelta, &out.GitHubCheckRunID, &out.Error, &out.EnrichedAt,
		&out.StartedAt, &out.FinishedAt, &out.CreatedAt)
	if err != nil {
		return models.Scan{}, err
	}
	if baseCommitSHA != nil {
		out.BaseCommitSHA = *baseCommitSHA
	}
	return out, nil
}

// CreateScan inserts a pending scan. Re-delivering the same webhook returns
// the existing scan rather than creating a duplicate, which is what makes the
// whole pipeline safe to retry.
func (db *DB) CreateScan(ctx context.Context, scan models.Scan) (models.Scan, error) {
	const insert = `
		INSERT INTO scans (repository_id, pull_request_id, commit_sha, base_commit_sha, trigger, status)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, 'pending')
		ON CONFLICT (repository_id, commit_sha, (COALESCE(pull_request_id, 0))) DO NOTHING
		RETURNING ` + scanColumns

	row := db.pool.QueryRow(ctx, insert, scan.RepositoryID, scan.PullRequestID, scan.CommitSHA,
		scan.BaseCommitSHA, scan.Trigger)
	out, err := scanScan(row)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return models.Scan{}, fmt.Errorf("create scan: %w", err)
	}

	// DO NOTHING suppressed the RETURNING clause: the scan already exists.
	const existing = `
		SELECT ` + scanColumns + `
		FROM scans
		WHERE repository_id = $1 AND commit_sha = $2 AND COALESCE(pull_request_id, 0) = COALESCE($3::bigint, 0)`
	out, err = scanScan(db.pool.QueryRow(ctx, existing, scan.RepositoryID, scan.CommitSHA, scan.PullRequestID))
	if err != nil {
		return models.Scan{}, fmt.Errorf("load existing scan: %w", err)
	}
	return out, nil
}

func (db *DB) GetScan(ctx context.Context, id int64) (models.Scan, error) {
	out, err := scanScan(db.pool.QueryRow(ctx, `SELECT `+scanColumns+` FROM scans WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Scan{}, ErrNotFound
	}
	if err != nil {
		return models.Scan{}, fmt.Errorf("get scan: %w", err)
	}
	return out, nil
}

// LatestCompletedScan finds the scan to diff against: the most recent
// successful scan of the same repository, excluding pull-request scans (whose
// dependency sets are proposals, not the state of the branch) and excluding
// the scan being run.
func (db *DB) LatestCompletedScan(ctx context.Context, repositoryID, excludeScanID int64, before time.Time) (models.Scan, error) {
	const query = `
		SELECT ` + scanColumns + `
		FROM scans
		WHERE repository_id = $1
		  AND id <> $2
		  AND status = 'completed'
		  AND pull_request_id IS NULL
		  AND created_at <= $3
		ORDER BY created_at DESC, id DESC
		LIMIT 1`

	out, err := scanScan(db.pool.QueryRow(ctx, query, repositoryID, excludeScanID, before))
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Scan{}, ErrNotFound
	}
	if err != nil {
		return models.Scan{}, fmt.Errorf("latest completed scan: %w", err)
	}
	return out, nil
}

// CompletedScanForCommit finds a finished scan of a specific commit, used to
// resolve a pull request's base without re-scanning it.
func (db *DB) CompletedScanForCommit(ctx context.Context, repositoryID int64, commitSHA string) (models.Scan, error) {
	const query = `
		SELECT ` + scanColumns + `
		FROM scans
		WHERE repository_id = $1 AND commit_sha = $2 AND status = 'completed'
		ORDER BY pull_request_id NULLS FIRST, created_at DESC
		LIMIT 1`

	out, err := scanScan(db.pool.QueryRow(ctx, query, repositoryID, commitSHA))
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Scan{}, ErrNotFound
	}
	if err != nil {
		return models.Scan{}, fmt.Errorf("completed scan for commit: %w", err)
	}
	return out, nil
}

func (db *DB) ListScans(ctx context.Context, repositoryID int64, limit int) ([]models.Scan, error) {
	const query = `
		SELECT ` + scanColumns + `
		FROM scans WHERE repository_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2`

	rows, err := db.pool.Query(ctx, query, repositoryID, limit)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	scans := make([]models.Scan, 0, limit)
	for rows.Next() {
		scan, err := scanScan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

func (db *DB) MarkScanRunning(ctx context.Context, scanID int64) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE scans SET status = 'running', started_at = COALESCE(started_at, now()), error = NULL WHERE id = $1`,
		scanID)
	if err != nil {
		return fmt.Errorf("mark scan running: %w", err)
	}
	return nil
}

func (db *DB) MarkScanFailed(ctx context.Context, scanID int64, cause string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE scans SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`,
		scanID, cause)
	if err != nil {
		return fmt.Errorf("mark scan failed: %w", err)
	}
	return nil
}

func (db *DB) SetScanCheckRunID(ctx context.Context, scanID, checkRunID int64) error {
	_, err := db.pool.Exec(ctx, `UPDATE scans SET github_check_run_id = $2 WHERE id = $1`, scanID, checkRunID)
	if err != nil {
		return fmt.Errorf("set check run id: %w", err)
	}
	return nil
}

// ScanResult is everything a finished scan produces, written in one
// transaction so a scan is never half-persisted.
type ScanResult struct {
	ScanID       int64
	BaseScanID   *int64
	SBOMLocation string
	SBOMSHA256   string
	Components   []sbom.Component
	Diff         *diff.Result
}

// SaveScanResult stores the component projection and drift events and flips
// the scan to completed. Re-running a scan replaces its previous projection.
func (db *DB) SaveScanResult(ctx context.Context, result ScanResult) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin scan result tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A retried scan re-derives everything; clear the old projection so the
	// unique constraints do not fight the retry.
	if _, err := tx.Exec(ctx, `DELETE FROM components WHERE scan_id = $1`, result.ScanID); err != nil {
		return fmt.Errorf("clear components: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM drift_events WHERE scan_id = $1`, result.ScanID); err != nil {
		return fmt.Errorf("clear drift events: %w", err)
	}

	if len(result.Components) > 0 {
		rows := make([][]any, 0, len(result.Components))
		for _, component := range result.Components {
			licenses := component.Licenses
			if licenses == nil {
				licenses = []string{}
			}
			rows = append(rows, []any{
				result.ScanID, component.PURL, component.Name, component.Version, component.Ecosystem,
				component.Type, nullIfEmpty(component.LicenseExpression), licenses, component.Direct,
			})
		}
		_, err = tx.CopyFrom(ctx,
			pgx.Identifier{"components"},
			[]string{"scan_id", "purl", "name", "version", "ecosystem", "type", "license_expression", "licenses", "direct"},
			pgx.CopyFromRows(rows))
		if err != nil {
			return fmt.Errorf("copy components: %w", err)
		}
	}

	if result.Diff != nil {
		changes := result.Diff.Changes()
		if len(changes) > 0 {
			rows := make([][]any, 0, len(changes))
			for _, change := range changes {
				rows = append(rows, []any{
					result.ScanID, result.BaseScanID, string(change.Type), change.Identity, change.PURL,
					change.Name, change.Ecosystem, nullIfEmpty(change.OldVersion), nullIfEmpty(change.NewVersion),
					nullIfEmpty(string(change.Direction)),
				})
			}
			_, err = tx.CopyFrom(ctx,
				pgx.Identifier{"drift_events"},
				[]string{"scan_id", "base_scan_id", "change_type", "identity", "purl", "name", "ecosystem",
					"old_version", "new_version", "direction"},
				pgx.CopyFromRows(rows))
			if err != nil {
				return fmt.Errorf("copy drift events: %w", err)
			}
		}
	}

	const finish = `
		UPDATE scans
		SET status          = 'completed',
		    base_scan_id    = $2,
		    sbom_location   = $3,
		    sbom_sha256     = $4,
		    component_count = $5,
		    error           = NULL,
		    finished_at     = now()
		WHERE id = $1`
	if _, err := tx.Exec(ctx, finish, result.ScanID, result.BaseScanID, result.SBOMLocation,
		result.SBOMSHA256, len(result.Components)); err != nil {
		return fmt.Errorf("finish scan: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit scan result: %w", err)
	}
	return nil
}

// ListComponents returns the stored component projection for a scan. The
// worker uses it to diff against a base scan without re-downloading its SBOM.
func (db *DB) ListComponents(ctx context.Context, scanID int64) ([]sbom.Component, error) {
	const query = `
		SELECT purl, name, version, ecosystem, COALESCE(type, ''),
		       COALESCE(license_expression, ''), licenses, direct
		FROM components WHERE scan_id = $1 ORDER BY purl`

	rows, err := db.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("list components: %w", err)
	}
	defer rows.Close()

	components := make([]sbom.Component, 0)
	for rows.Next() {
		var component sbom.Component
		if err := rows.Scan(&component.PURL, &component.Name, &component.Version, &component.Ecosystem,
			&component.Type, &component.LicenseExpression, &component.Licenses, &component.Direct); err != nil {
			return nil, fmt.Errorf("scan component: %w", err)
		}
		component.Identity, _, _, _ = sbom.ParseIdentity(component.PURL)
		components = append(components, component)
	}
	return components, rows.Err()
}

func (db *DB) ListDriftEvents(ctx context.Context, scanID int64) ([]models.DriftEvent, error) {
	const query = `
		SELECT id, scan_id, base_scan_id, change_type::text, identity, purl, name, ecosystem,
		       COALESCE(old_version, ''), COALESCE(new_version, ''), COALESCE(direction, ''),
		       risk_delta, created_at
		FROM drift_events WHERE scan_id = $1
		ORDER BY change_type, identity`

	rows, err := db.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("list drift events: %w", err)
	}
	defer rows.Close()

	events := make([]models.DriftEvent, 0)
	for rows.Next() {
		var event models.DriftEvent
		if err := rows.Scan(&event.ID, &event.ScanID, &event.BaseScanID, &event.ChangeType, &event.Identity,
			&event.PURL, &event.Name, &event.Ecosystem, &event.OldVersion, &event.NewVersion,
			&event.Direction, &event.RiskDelta, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan drift event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// RecordWebhookDelivery registers a delivery ID. It reports false when the
// delivery has been seen before, which is how replays are dropped.
func (db *DB) RecordWebhookDelivery(ctx context.Context, deliveryID, event, action string) (bool, error) {
	tag, err := db.pool.Exec(ctx,
		`INSERT INTO webhook_deliveries (delivery_id, event, action) VALUES ($1, $2, $3)
		 ON CONFLICT (delivery_id) DO NOTHING`,
		deliveryID, event, nullIfEmpty(action))
	if err != nil {
		return false, fmt.Errorf("record webhook delivery: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// ListPullRequests returns a repository's pull requests, each with the
// headline numbers from its most recent scan. The lateral join keeps this to
// one round trip rather than one query per pull request.
func (db *DB) ListPullRequests(ctx context.Context, repositoryID int64, limit int) ([]models.PullRequestSummary, error) {
	const query = `
		SELECT pr.id, pr.repository_id, pr.number, COALESCE(pr.title, ''), COALESCE(pr.author_login, ''),
		       pr.state, COALESCE(pr.base_ref, ''), pr.base_sha, pr.head_sha,
		       latest.id, latest.status, latest.risk_delta, latest.component_count,
		       COUNT(d.id) FILTER (WHERE d.change_type = 'added')   AS added,
		       COUNT(d.id) FILTER (WHERE d.change_type = 'updated') AS updated,
		       COUNT(d.id) FILTER (WHERE d.change_type = 'removed') AS removed
		FROM pull_requests pr
		LEFT JOIN LATERAL (
			SELECT id, status, risk_delta, component_count
			FROM scans
			WHERE pull_request_id = pr.id
			ORDER BY created_at DESC, id DESC
			LIMIT 1
		) latest ON true
		LEFT JOIN drift_events d ON d.scan_id = latest.id
		WHERE pr.repository_id = $1
		GROUP BY pr.id, pr.repository_id, pr.number, pr.title, pr.author_login, pr.state,
		         pr.base_ref, pr.base_sha, pr.head_sha,
		         latest.id, latest.status, latest.risk_delta, latest.component_count
		ORDER BY pr.number DESC
		LIMIT $2`

	rows, err := db.pool.Query(ctx, query, repositoryID, limit)
	if err != nil {
		return nil, fmt.Errorf("list pull requests: %w", err)
	}
	defer rows.Close()

	summaries := make([]models.PullRequestSummary, 0)
	for rows.Next() {
		var summary models.PullRequestSummary
		if err := rows.Scan(&summary.ID, &summary.RepositoryID, &summary.Number, &summary.Title,
			&summary.AuthorLogin, &summary.State, &summary.BaseRef, &summary.BaseSHA, &summary.HeadSHA,
			&summary.ScanID, &summary.ScanStatus, &summary.RiskDelta, &summary.ComponentCount,
			&summary.Added, &summary.Updated, &summary.Removed); err != nil {
			return nil, fmt.Errorf("scan pull request summary: %w", err)
		}
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

// GetPullRequest loads one pull request with its latest scan numbers.
func (db *DB) GetPullRequest(ctx context.Context, id int64) (models.PullRequestSummary, error) {
	const query = `
		SELECT pr.id, pr.repository_id, pr.number, COALESCE(pr.title, ''), COALESCE(pr.author_login, ''),
		       pr.state, COALESCE(pr.base_ref, ''), pr.base_sha, pr.head_sha,
		       latest.id, latest.status, latest.risk_delta, latest.component_count,
		       COUNT(d.id) FILTER (WHERE d.change_type = 'added')   AS added,
		       COUNT(d.id) FILTER (WHERE d.change_type = 'updated') AS updated,
		       COUNT(d.id) FILTER (WHERE d.change_type = 'removed') AS removed
		FROM pull_requests pr
		LEFT JOIN LATERAL (
			SELECT id, status, risk_delta, component_count
			FROM scans
			WHERE pull_request_id = pr.id
			ORDER BY created_at DESC, id DESC
			LIMIT 1
		) latest ON true
		LEFT JOIN drift_events d ON d.scan_id = latest.id
		WHERE pr.id = $1
		GROUP BY pr.id, pr.repository_id, pr.number, pr.title, pr.author_login, pr.state,
		         pr.base_ref, pr.base_sha, pr.head_sha,
		         latest.id, latest.status, latest.risk_delta, latest.component_count`

	var summary models.PullRequestSummary
	err := db.pool.QueryRow(ctx, query, id).Scan(&summary.ID, &summary.RepositoryID, &summary.Number,
		&summary.Title, &summary.AuthorLogin, &summary.State, &summary.BaseRef, &summary.BaseSHA,
		&summary.HeadSHA, &summary.ScanID, &summary.ScanStatus, &summary.RiskDelta,
		&summary.ComponentCount, &summary.Added, &summary.Updated, &summary.Removed)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.PullRequestSummary{}, ErrNotFound
	}
	if err != nil {
		return models.PullRequestSummary{}, fmt.Errorf("get pull request: %w", err)
	}
	return summary, nil
}

// ListVulnerabilities returns the advisories affecting a scan's components,
// most severe first. It returns an empty slice until Phase 4 populates the
// table, which is a real answer rather than an error.
func (db *DB) ListVulnerabilities(ctx context.Context, scanID int64) ([]models.Vulnerability, error) {
	const query = `
		SELECT v.id, v.component_id, v.osv_id, v.aliases, COALESCE(v.severity, ''), v.cvss_score,
		       COALESCE(v.cvss_vector, ''), COALESCE(v.summary, ''), COALESCE(v.fixed_version, ''),
		       v.published_at, c.purl, c.name, c.version, c.ecosystem
		FROM vulnerabilities v
		JOIN components c ON c.id = v.component_id
		WHERE c.scan_id = $1
		ORDER BY CASE upper(COALESCE(v.severity, ''))
		             WHEN 'CRITICAL' THEN 1
		             WHEN 'HIGH'     THEN 2
		             WHEN 'MODERATE' THEN 3
		             WHEN 'MEDIUM'   THEN 3
		             WHEN 'LOW'      THEN 4
		             ELSE 5
		         END,
		         v.cvss_score DESC NULLS LAST, c.name, v.osv_id`

	rows, err := db.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities: %w", err)
	}
	defer rows.Close()

	vulnerabilities := make([]models.Vulnerability, 0)
	for rows.Next() {
		var vulnerability models.Vulnerability
		if err := rows.Scan(&vulnerability.ID, &vulnerability.ComponentID, &vulnerability.OSVID,
			&vulnerability.Aliases, &vulnerability.Severity, &vulnerability.CVSSScore,
			&vulnerability.CVSSVector, &vulnerability.Summary, &vulnerability.FixedVersion,
			&vulnerability.PublishedAt, &vulnerability.PURL, &vulnerability.Name,
			&vulnerability.Version, &vulnerability.Ecosystem); err != nil {
			return nil, fmt.Errorf("scan vulnerability: %w", err)
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return vulnerabilities, rows.Err()
}
