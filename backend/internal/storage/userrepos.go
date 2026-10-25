package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/models"
)

// ReplaceUserRepositories records the repositories GitHub reported for a user
// at sign-in, replacing the previous list entirely: a repository the user
// lost access to since their last sign-in disappears from it.
func (db *DB) ReplaceUserRepositories(ctx context.Context, userID int64, repos []models.AccessibleRepository, listedAt time.Time) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace user repositories: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM user_repositories WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear user repositories: %w", err)
	}
	if len(repos) > 0 {
		rows := make([][]any, 0, len(repos))
		for _, repo := range repos {
			rows = append(rows, []any{userID, repo.GitHubRepoID, repo.GitHubInstallationID,
				repo.Owner, repo.Name, repo.Private, nullIfEmpty(repo.DefaultBranch), listedAt})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"user_repositories"},
			[]string{"user_id", "github_repo_id", "github_installation_id", "owner", "name", "private", "default_branch", "listed_at"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store user repositories: %w", err)
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET repos_listed_at = $2, repos_list_error = NULL WHERE id = $1`, userID, listedAt); err != nil {
		return fmt.Errorf("record repository listing: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit user repositories: %w", err)
	}
	return nil
}

// ClearUserRepositories empties a user's list and records why it could not be
// read. A stale list is never kept in place of one GitHub would not give: it
// could still grant a repository the user has since lost.
func (db *DB) ClearUserRepositories(ctx context.Context, userID int64, reason string, at time.Time) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin clear user repositories: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM user_repositories WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear user repositories: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET repos_listed_at = $2, repos_list_error = $3 WHERE id = $1`, userID, at, reason); err != nil {
		return fmt.Errorf("record repository listing failure: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit clear user repositories: %w", err)
	}
	return nil
}

// RepositoryListing says when a user's repository list was last read from
// GitHub, and the reason it failed if it did. Both are empty before the
// first sign-in that reads it.
type RepositoryListing struct {
	ListedAt *time.Time `json:"listedAt,omitempty"`
	Error    string     `json:"error,omitempty"`
}

func (db *DB) UserRepositoryListing(ctx context.Context, userID int64) (RepositoryListing, error) {
	var out RepositoryListing
	err := db.pool.QueryRow(ctx,
		`SELECT repos_listed_at, COALESCE(repos_list_error, '') FROM users WHERE id = $1`, userID).
		Scan(&out.ListedAt, &out.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return RepositoryListing{}, ErrNotFound
	}
	if err != nil {
		return RepositoryListing{}, fmt.Errorf("read repository listing: %w", err)
	}
	return out, nil
}

// userCanAccess is the authorization rule for every repository-scoped read
// and write: the repository is in the user's list from GitHub. $1 is the
// user; table names the repositories table as the query refers to it.
// Manually registered repositories have no GitHub ID and match no one.
func userCanAccess(table string) string {
	return `EXISTS (SELECT 1 FROM user_repositories ur
	        WHERE ur.user_id = $1 AND ur.github_repo_id = ` + table + `.github_repo_id)`
}

// aliasedRepositoryColumns and aliasedRepositoryAccess are repositoryColumns
// and repositoryAccess for queries that join the repositories table as r.
var (
	aliasedRepositoryAccess  = strings.ReplaceAll(repositoryAccess, "repositories.", "r.")
	aliasedRepositoryColumns = `
	r.id, r.installation_id, r.github_repo_id, r.owner, r.name, r.default_branch, r.private,
	COALESCE(r.clone_url, ''), r.created_at, r.access_revoked_at, ` + aliasedRepositoryAccess
)

// CanAccessRepository reports whether a user may see a repository and its
// scans. A repository that does not exist is simply not accessible.
func (db *DB) CanAccessRepository(ctx context.Context, userID, repositoryID int64) (bool, error) {
	var ok bool
	err := db.pool.QueryRow(ctx,
		`SELECT `+userCanAccess("r")+` FROM repositories r WHERE r.id = $2`, userID, repositoryID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check repository access: %w", err)
	}
	return ok, nil
}

// ListRepositoriesForUser is ListRepositories limited to the repositories the
// user may see.
func (db *DB) ListRepositoriesForUser(ctx context.Context, userID int64, filter AccessFilter) ([]models.Repository, error) {
	where, err := accessFilterClause(filter)
	if err != nil {
		return nil, err
	}
	query := `
		SELECT ` + repositoryColumns + `
		FROM repositories
		WHERE ` + userCanAccess("repositories") + where + `
		ORDER BY owner, name`

	rows, err := db.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list repositories for user: %w", err)
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

// latestBranchScan and lastCompletedScan pick a repository's newest scan
// outside pull requests -- in any state, or completed only. Backfilled base
// scans are internal and never shown as "the latest". Both expect the
// repository in scope as r.
const (
	latestBranchScan = `
		SELECT s.id, s.status, s.trigger, s.commit_sha, s.component_count, COALESCE(s.error, ''),
		       s.created_at, s.finished_at, s.base_scan_id
		FROM scans s
		WHERE s.repository_id = r.id AND s.pull_request_id IS NULL AND s.trigger <> 'backfill'
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1`
	lastCompletedScan = `
		SELECT s.id, s.status, s.trigger, s.commit_sha, s.component_count, COALESCE(s.error, ''),
		       s.created_at, s.finished_at, s.base_scan_id
		FROM scans s
		WHERE s.repository_id = r.id AND s.pull_request_id IS NULL AND s.trigger <> 'backfill'
		  AND s.status = 'completed'
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1`
)

// nullableScan receives a LEFT JOIN LATERAL scan, which is all NULL when the
// repository has none.
type nullableScan struct {
	id             *int64
	status         *models.ScanStatus
	trigger        *models.ScanTrigger
	commitSHA      *string
	componentCount *int
	errorText      *string
	createdAt      *time.Time
	finishedAt     *time.Time
	baseScanID     *int64
}

func (n *nullableScan) targets() []any {
	return []any{&n.id, &n.status, &n.trigger, &n.commitSHA, &n.componentCount, &n.errorText,
		&n.createdAt, &n.finishedAt, &n.baseScanID}
}

func (n *nullableScan) summary() *models.ScanSummary {
	if n.id == nil {
		return nil
	}
	return &models.ScanSummary{
		ID: *n.id, Status: *n.status, Trigger: *n.trigger, CommitSHA: *n.commitSHA,
		ComponentCount: *n.componentCount, Error: RedactSecrets(*n.errorText), CreatedAt: *n.createdAt, FinishedAt: n.finishedAt,
	}
}

// ListUserRepositories returns one page of a user's repositories from
// GitHub, sorted by owner and name, with the total that match search (a
// case-insensitive substring of owner/name).
//
// Each row carries its latest branch scan in any state and its last
// completed one, whose finish time is "last scanned" and which a failed
// rescan never replaces.
//
// With untrackedOnly, repositories the user already tracks are left out; the
// total counts the same set. The dashboard lists every repository, tracked
// or not, so it does not use it.
func (db *DB) ListUserRepositories(ctx context.Context, userID int64, search string, untrackedOnly bool, limit, offset int) ([]models.UserRepository, int, error) {
	pattern := "%" + escapeLike(strings.ToLower(strings.TrimSpace(search))) + "%"

	// A repository is tracked when its stored row is in the user's tracked
	// list; one not stored yet cannot have been tracked.
	trackedFilter := ""
	if untrackedOnly {
		trackedFilter = `
		  AND NOT EXISTS (
			SELECT 1 FROM repositories tr
			JOIN user_tracked_repositories tt ON tt.repository_id = tr.id AND tt.user_id = ur.user_id
			WHERE tr.github_repo_id = ur.github_repo_id)`
	}

	var total int
	if err := db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_repositories ur
		WHERE ur.user_id = $1 AND lower(ur.owner || '/' || ur.name) LIKE $2 ESCAPE '\'`+trackedFilter,
		userID, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count user repositories: %w", err)
	}

	query := `
		SELECT ur.github_repo_id, ur.github_installation_id, ur.owner, ur.name, ur.private,
		       COALESCE(ur.default_branch, ''),
		       r.id, CASE WHEN r.id IS NULL THEN NULL ELSE ` + aliasedRepositoryAccess + ` END,
		       t.repository_id IS NOT NULL,
		       ls.id, ls.status, ls.trigger, ls.commit_sha, ls.component_count, ls.error,
		       ls.created_at, ls.finished_at, ls.base_scan_id,
		       lc.id, lc.status, lc.trigger, lc.commit_sha, lc.component_count, lc.error,
		       lc.created_at, lc.finished_at, lc.base_scan_id
		FROM user_repositories ur
		LEFT JOIN repositories r ON r.github_repo_id = ur.github_repo_id
		LEFT JOIN user_tracked_repositories t ON t.user_id = ur.user_id AND t.repository_id = r.id
		LEFT JOIN LATERAL (` + latestBranchScan + `) ls(id, status, trigger, commit_sha, component_count, error,
		                                               created_at, finished_at, base_scan_id) ON r.id IS NOT NULL
		LEFT JOIN LATERAL (` + lastCompletedScan + `) lc(id, status, trigger, commit_sha, component_count, error,
		                                                created_at, finished_at, base_scan_id) ON r.id IS NOT NULL
		WHERE ur.user_id = $1 AND lower(ur.owner || '/' || ur.name) LIKE $2 ESCAPE '\'` + trackedFilter + `
		ORDER BY lower(ur.owner), lower(ur.name), ur.github_repo_id
		LIMIT $3 OFFSET $4`

	rows, err := db.pool.Query(ctx, query, userID, pattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list user repositories: %w", err)
	}
	defer rows.Close()

	out := make([]models.UserRepository, 0)
	for rows.Next() {
		var repo models.UserRepository
		var latest, completed nullableScan
		targets := append([]any{
			&repo.GitHubRepoID, &repo.GitHubInstallationID, &repo.Owner, &repo.Name, &repo.Private,
			&repo.DefaultBranch, &repo.RepositoryID, &repo.Access, &repo.Tracked,
		}, latest.targets()...)
		targets = append(targets, completed.targets()...)
		if err := rows.Scan(targets...); err != nil {
			return nil, 0, fmt.Errorf("scan user repository: %w", err)
		}
		repo.LatestScan = latest.summary()
		repo.LastCompletedScan = completed.summary()
		out = append(out, repo)
	}
	return out, total, rows.Err()
}

// ListAllRepositoryOverviews is ListUserRepositories for local development
// with sign-in disabled, where the one local user may see every repository
// (see the API's canAccess): every stored repository SBOMDelta can still
// reach, in the same shape, with nothing tracked since there is no user to
// track for. Repositories registered without a GitHub ID have githubRepoId 0.
func (db *DB) ListAllRepositoryOverviews(ctx context.Context, search string, limit, offset int) ([]models.UserRepository, int, error) {
	pattern := "%" + escapeLike(strings.ToLower(strings.TrimSpace(search))) + "%"
	where := `WHERE r.access_revoked_at IS NULL AND lower(r.owner || '/' || r.name) LIKE $1 ESCAPE '\'`

	var total int
	if err := db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM repositories r `+where, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count repositories: %w", err)
	}

	query := `
		SELECT COALESCE(r.github_repo_id, 0), COALESCE(i.github_installation_id, 0), r.owner, r.name, r.private,
		       COALESCE(r.default_branch, ''), r.id, ` + aliasedRepositoryAccess + `,
		       ls.id, ls.status, ls.trigger, ls.commit_sha, ls.component_count, ls.error,
		       ls.created_at, ls.finished_at, ls.base_scan_id,
		       lc.id, lc.status, lc.trigger, lc.commit_sha, lc.component_count, lc.error,
		       lc.created_at, lc.finished_at, lc.base_scan_id
		FROM repositories r
		LEFT JOIN installations i ON i.id = r.installation_id
		LEFT JOIN LATERAL (` + latestBranchScan + `) ls(id, status, trigger, commit_sha, component_count, error,
		                                               created_at, finished_at, base_scan_id) ON true
		LEFT JOIN LATERAL (` + lastCompletedScan + `) lc(id, status, trigger, commit_sha, component_count, error,
		                                                created_at, finished_at, base_scan_id) ON true
		` + where + `
		ORDER BY lower(r.owner), lower(r.name), r.id
		LIMIT $2 OFFSET $3`

	rows, err := db.pool.Query(ctx, query, pattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()

	out := make([]models.UserRepository, 0)
	for rows.Next() {
		var repo models.UserRepository
		var latest, completed nullableScan
		targets := append([]any{
			&repo.GitHubRepoID, &repo.GitHubInstallationID, &repo.Owner, &repo.Name, &repo.Private,
			&repo.DefaultBranch, &repo.RepositoryID, &repo.Access,
		}, latest.targets()...)
		targets = append(targets, completed.targets()...)
		if err := rows.Scan(targets...); err != nil {
			return nil, 0, fmt.Errorf("scan repository: %w", err)
		}
		repo.LatestScan = latest.summary()
		repo.LastCompletedScan = completed.summary()
		out = append(out, repo)
	}
	return out, total, rows.Err()
}

// TrackRepository adds a repository to a user's tracked list. Tracking it
// again is not an error.
func (db *DB) TrackRepository(ctx context.Context, userID, repositoryID int64) error {
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO user_tracked_repositories (user_id, repository_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, userID, repositoryID); err != nil {
		return fmt.Errorf("track repository: %w", err)
	}
	return nil
}

// UntrackRepository removes a repository from a user's tracked list, and
// reports whether it was there. Its scan history is kept.
func (db *DB) UntrackRepository(ctx context.Context, userID, repositoryID int64) (bool, error) {
	tag, err := db.pool.Exec(ctx,
		`DELETE FROM user_tracked_repositories WHERE user_id = $1 AND repository_id = $2`, userID, repositoryID)
	if err != nil {
		return false, fmt.Errorf("untrack repository: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListTrackedRepositories returns the repositories a user tracks and still
// has access to, newest tracked first, with their latest and last completed
// scans and that completed scan's dependency changes.
func (db *DB) ListTrackedRepositories(ctx context.Context, userID int64) ([]models.TrackedRepository, error) {
	query := `
		SELECT ` + aliasedRepositoryColumns + `, t.tracked_at,
		       ls.id, ls.status, ls.trigger, ls.commit_sha, ls.component_count, ls.error,
		       ls.created_at, ls.finished_at, ls.base_scan_id,
		       lc.id, lc.status, lc.trigger, lc.commit_sha, lc.component_count, lc.error,
		       lc.created_at, lc.finished_at, lc.base_scan_id,
		       COALESCE(d.added, 0), COALESCE(d.updated, 0), COALESCE(d.removed, 0)
		FROM user_tracked_repositories t
		JOIN repositories r ON r.id = t.repository_id
		LEFT JOIN LATERAL (` + latestBranchScan + `) ls(id, status, trigger, commit_sha, component_count, error,
		                                               created_at, finished_at, base_scan_id) ON true
		LEFT JOIN LATERAL (` + lastCompletedScan + `) lc(id, status, trigger, commit_sha, component_count, error,
		                                                created_at, finished_at, base_scan_id) ON true
		LEFT JOIN LATERAL (
			SELECT COUNT(*) FILTER (WHERE change_type = 'added')   AS added,
			       COUNT(*) FILTER (WHERE change_type = 'updated') AS updated,
			       COUNT(*) FILTER (WHERE change_type = 'removed') AS removed
			FROM drift_events WHERE scan_id = lc.id) d ON lc.id IS NOT NULL
		WHERE t.user_id = $1 AND ` + userCanAccess("r") + `
		ORDER BY t.tracked_at DESC, r.id DESC`

	rows, err := db.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list tracked repositories: %w", err)
	}
	defer rows.Close()

	out := make([]models.TrackedRepository, 0)
	for rows.Next() {
		var tracked models.TrackedRepository
		var latest, completed nullableScan
		targets := append(repositoryTargets(&tracked.Repository), &tracked.TrackedAt)
		targets = append(targets, latest.targets()...)
		targets = append(targets, completed.targets()...)
		targets = append(targets, &tracked.Added, &tracked.Updated, &tracked.Removed)
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("scan tracked repository: %w", err)
		}
		tracked.LatestScan = latest.summary()
		tracked.LastCompletedScan = completed.summary()
		tracked.Baseline = tracked.LastCompletedScan != nil && completed.baseScanID == nil
		out = append(out, tracked)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	summaries := make([]*models.ScanSummary, 0, 2*len(out))
	for i := range out {
		summaries = append(summaries, out[i].LatestScan, out[i].LastCompletedScan)
	}
	if err := db.attachInsights(ctx, summaries...); err != nil {
		return nil, err
	}
	return out, nil
}

// IsTracked reports whether a user tracks a repository.
func (db *DB) IsTracked(ctx context.Context, userID, repositoryID int64) (bool, error) {
	var tracked bool
	if err := db.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM user_tracked_repositories WHERE user_id = $1 AND repository_id = $2)`,
		userID, repositoryID).Scan(&tracked); err != nil {
		return false, fmt.Errorf("check tracking: %w", err)
	}
	return tracked, nil
}

// ListRecentScans returns the newest scans of the repositories a user
// tracks and can still access ("Last scans"), across branches and pull
// requests, with what each found. Backfilled base scans are internal and
// left out. With allRepositories (sign-in disabled for local development)
// every repository's scans are listed. repositoryID, when non-zero, limits
// the list to one repository.
func (db *DB) ListRecentScans(ctx context.Context, userID int64, allRepositories bool, repositoryID int64, limit int) ([]models.ScanOverview, error) {
	scope := `JOIN user_tracked_repositories t ON t.repository_id = r.id AND t.user_id = $1
		WHERE ` + userCanAccess("r")
	if allRepositories {
		scope = `WHERE $1::bigint IS NOT NULL`
	}
	query := `
		SELECT s.id, s.status, s.trigger, s.commit_sha, s.component_count, COALESCE(s.error, ''),
		       s.created_at, s.finished_at,
		       r.id, r.owner, r.name, r.default_branch, COALESCE(c.ref, ''),
		       s.pull_request_id, pr.number, COALESCE(pr.title, ''), s.base_scan_id
		FROM scans s
		JOIN repositories r ON r.id = s.repository_id
		LEFT JOIN commits c ON c.repository_id = s.repository_id AND c.sha = s.commit_sha
		LEFT JOIN pull_requests pr ON pr.id = s.pull_request_id
		` + scope + `
		  AND s.trigger <> 'backfill'
		  AND ($2::bigint = 0 OR r.id = $2)
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT $3`

	rows, err := db.pool.Query(ctx, query, userID, repositoryID, limit)
	if err != nil {
		return nil, fmt.Errorf("list recent scans: %w", err)
	}
	defer rows.Close()
	out := make([]models.ScanOverview, 0)
	for rows.Next() {
		var o models.ScanOverview
		if err := rows.Scan(&o.ID, &o.Status, &o.Trigger, &o.CommitSHA, &o.ComponentCount, &o.Error,
			&o.CreatedAt, &o.FinishedAt, &o.RepositoryID, &o.Owner, &o.Name, &o.DefaultBranch, &o.Ref,
			&o.PullRequestID, &o.PullRequestNumber, &o.PullRequestTitle, &o.BaseScanID); err != nil {
			return nil, fmt.Errorf("scan recent scan: %w", err)
		}
		o.Error = RedactSecrets(o.Error)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := make([]int64, len(out))
	for i := range out {
		ids[i] = out[i].ID
	}
	insights, err := db.scanInsights(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		insight := insights[out[i].ID]
		out[i].Vulnerabilities = insight.vulnerabilities
		out[i].Risk = insight.risk
		out[i].Added, out[i].Updated, out[i].Removed = insight.added, insight.updated, insight.removed
		out[i].Baseline = out[i].Status == models.ScanCompleted && insight.baseline
	}
	return out, nil
}

// RepositoryIDForPullRequest returns the repository a pull request belongs
// to, for authorizing reads of it.
func (db *DB) RepositoryIDForPullRequest(ctx context.Context, pullRequestID int64) (int64, error) {
	var id int64
	err := db.pool.QueryRow(ctx, `SELECT repository_id FROM pull_requests WHERE id = $1`, pullRequestID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("look up pull request repository: %w", err)
	}
	return id, nil
}

// RepositoryIDForScan returns the repository a scan belongs to.
func (db *DB) RepositoryIDForScan(ctx context.Context, scanID int64) (int64, error) {
	var id int64
	err := db.pool.QueryRow(ctx, `SELECT repository_id FROM scans WHERE id = $1`, scanID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("look up scan repository: %w", err)
	}
	return id, nil
}

// RequeueFailedScan returns a failed scan to pending so it can run again,
// and reports whether it did. Scans in any other state are left alone.
func (db *DB) RequeueFailedScan(ctx context.Context, scanID int64) (bool, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE scans SET status = 'pending', error = NULL, started_at = NULL, finished_at = NULL
		WHERE id = $1 AND status = 'failed'`, scanID)
	if err != nil {
		return false, fmt.Errorf("requeue failed scan: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}
