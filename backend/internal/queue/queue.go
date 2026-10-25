// Package queue is a Postgres-backed job queue.
//
// Using Postgres rather than Redis keeps the deployment to one stateful
// service and, more usefully here, lets a job be enqueued in the same
// transaction as the row it refers to. Dequeuing uses FOR UPDATE SKIP LOCKED,
// so many workers can drain one table without blocking each other.
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Kind identifies what a job does.
type Kind string

const (
	// KindScan runs the full pipeline for one commit: clone, generate SBOM,
	// diff against the base, persist, report to GitHub.
	KindScan Kind = "scan"
	// KindReconcileInstallation re-reads an installation's repository list
	// from GitHub and brings stored access in line with it.
	KindReconcileInstallation Kind = "reconcile_installation"
	// KindInitialScan gives a repository that has never been scanned its
	// first scan, at the head of its default branch.
	KindInitialScan Kind = "initial_scan"
)

// ErrNoJobs signals that the queue is empty right now.
var ErrNoJobs = errors.New("no jobs available")

// Job is one unit of work.
type Job struct {
	ID          int64
	Kind        Kind
	Payload     json.RawMessage
	Attempts    int
	MaxAttempts int
	DedupeKey   string
}

// ScanPayload is the body of a KindScan job.
type ScanPayload struct {
	ScanID int64 `json:"scanId"`
}

// ReconcileInstallationPayload is the body of a KindReconcileInstallation job.
type ReconcileInstallationPayload struct {
	GitHubInstallationID int64 `json:"githubInstallationId"`
}

// InitialScanPayload is the body of a KindInitialScan job.
type InitialScanPayload struct {
	RepositoryID int64 `json:"repositoryId"`
}

// Queue reads and writes the jobs table.
type Queue struct {
	pool        *pgxpool.Pool
	lockTimeout time.Duration
}

func New(pool *pgxpool.Pool, lockTimeout time.Duration) *Queue {
	return &Queue{pool: pool, lockTimeout: lockTimeout}
}

// Enqueue adds a job. A non-empty dedupeKey collapses repeat submissions: the
// second enqueue of the same key is a no-op, which is what keeps a redelivered
// webhook from scanning the same commit twice.
func (q *Queue) Enqueue(ctx context.Context, kind Kind, payload any, dedupeKey string) (int64, error) {
	return q.EnqueueAfter(ctx, kind, payload, dedupeKey, 0)
}

// EnqueueAfter is Enqueue for a job that should not run until delay has
// passed.
func (q *Queue) EnqueueAfter(ctx context.Context, kind Kind, payload any, dedupeKey string, delay time.Duration) (int64, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal job payload: %w", err)
	}

	const query = `
		INSERT INTO jobs (kind, payload, dedupe_key, run_after)
		VALUES ($1, $2, NULLIF($3, ''), now() + make_interval(secs => $4))
		ON CONFLICT (dedupe_key) DO NOTHING
		RETURNING id`

	var id int64
	err = q.pool.QueryRow(ctx, query, string(kind), body, dedupeKey, delay.Seconds()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil // Already queued; nothing more to do.
	}
	if err != nil {
		return 0, fmt.Errorf("enqueue %s job: %w", kind, err)
	}
	return id, nil
}

// EnqueueSpaced is Enqueue for background work that must not arrive as a
// burst: the job runs spacing after the latest job of the same kind still
// waiting in the queue, or now if none is. Spacing is measured across every
// caller, so two installations reconciled at once interleave their jobs
// rather than each starting its own burst at the same moment.
func (q *Queue) EnqueueSpaced(ctx context.Context, kind Kind, payload any, dedupeKey string, spacing time.Duration) (int64, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal job payload: %w", err)
	}

	tx, err := q.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin spaced enqueue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serializes spaced enqueues of one kind, so concurrent callers cannot
	// read the same latest run_after and schedule on top of each other.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('sbomdelta.jobs.spaced.' || $1, 0))`,
		string(kind)); err != nil {
		return 0, fmt.Errorf("lock spaced enqueue: %w", err)
	}

	const query = `
		INSERT INTO jobs (kind, payload, dedupe_key, run_after)
		SELECT $1, $2, NULLIF($3, ''), GREATEST(now(),
			COALESCE((SELECT max(run_after) FROM jobs WHERE kind = $1 AND status = 'queued')
			         + make_interval(secs => $4), now()))
		ON CONFLICT (dedupe_key) DO NOTHING
		RETURNING id`

	var id int64
	err = tx.QueryRow(ctx, query, string(kind), body, dedupeKey, spacing.Seconds()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil // Already queued; nothing more to do.
	}
	if err != nil {
		return 0, fmt.Errorf("enqueue %s job: %w", kind, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit spaced enqueue: %w", err)
	}
	return id, nil
}

// ReleaseDeadDedupeKey frees a dedupe key held by a job that exhausted its
// retries, so the same work can be queued again. The dead job itself is kept
// for inspection. A key held by a queued, running or retrying job is left
// alone. It reports whether a key was released.
func (q *Queue) ReleaseDeadDedupeKey(ctx context.Context, dedupeKey string) (bool, error) {
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs
		SET dedupe_key = NULL, updated_at = now()
		WHERE dedupe_key = $1 AND status = 'dead'`, dedupeKey)
	if err != nil {
		return false, fmt.Errorf("release dead dedupe key: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Dequeue claims the oldest runnable job for this worker. Jobs whose lock has
// outlived lockTimeout are reclaimed: a worker that was killed mid-job must
// not strand its work forever.
func (q *Queue) Dequeue(ctx context.Context, workerID string) (*Job, error) {
	const query = `
		WITH claimed AS (
			SELECT id
			FROM jobs
			-- make_interval takes seconds rather than a string, so a Go
			-- duration never has to survive Postgres interval parsing.
			WHERE (status = 'queued' AND run_after <= now())
			   OR (status = 'running' AND locked_at < now() - make_interval(secs => $2))
			ORDER BY run_after, id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE jobs
		SET status     = 'running',
		    attempts   = jobs.attempts + 1,
		    locked_at  = now(),
		    locked_by  = $1,
		    updated_at = now()
		FROM claimed
		WHERE jobs.id = claimed.id
		RETURNING jobs.id, jobs.kind, jobs.payload, jobs.attempts, jobs.max_attempts,
		          COALESCE(jobs.dedupe_key, '')`

	var job Job
	var kind string
	err := q.pool.QueryRow(ctx, query, workerID, q.lockTimeout.Seconds()).
		Scan(&job.ID, &kind, &job.Payload, &job.Attempts, &job.MaxAttempts, &job.DedupeKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoJobs
	}
	if err != nil {
		return nil, fmt.Errorf("dequeue job: %w", err)
	}
	job.Kind = Kind(kind)
	return &job, nil
}

// Succeed marks a job done. The dedupe key is cleared so that a later,
// genuinely new request for the same target can be queued again -- a commit
// re-scanned after a policy change, for instance.
func (q *Queue) Succeed(ctx context.Context, jobID int64) error {
	_, err := q.pool.Exec(ctx, `
		UPDATE jobs
		SET status = 'succeeded', dedupe_key = NULL, last_error = NULL, locked_by = NULL, updated_at = now()
		WHERE id = $1`, jobID)
	if err != nil {
		return fmt.Errorf("mark job succeeded: %w", err)
	}
	return nil
}

// Fail records an error and either schedules a retry with exponential backoff
// or, once attempts are exhausted, parks the job as dead for inspection.
func (q *Queue) Fail(ctx context.Context, job *Job, cause error) error {
	if job.Attempts >= job.MaxAttempts {
		_, err := q.pool.Exec(ctx, `
			UPDATE jobs
			SET status = 'dead', last_error = $2, locked_by = NULL, updated_at = now()
			WHERE id = $1`, job.ID, cause.Error())
		if err != nil {
			return fmt.Errorf("mark job dead: %w", err)
		}
		return nil
	}

	backoff := retryBackoff(job.Attempts)
	_, err := q.pool.Exec(ctx, `
		UPDATE jobs
		SET status     = 'queued',
		    last_error = $2,
		    run_after  = now() + make_interval(secs => $3),
		    locked_at  = NULL,
		    locked_by  = NULL,
		    updated_at = now()
		WHERE id = $1`, job.ID, cause.Error(), backoff.Seconds())
	if err != nil {
		return fmt.Errorf("reschedule job: %w", err)
	}
	return nil
}

// retryBackoff grows 30s, 2m, 8m, ... capped at 30 minutes. External
// dependencies (GitHub, the OSV API) mostly recover within that window.
func retryBackoff(attempts int) time.Duration {
	const base = 30 * time.Second
	const ceiling = 30 * time.Minute

	backoff := base
	for i := 1; i < attempts; i++ {
		backoff *= 4
		if backoff >= ceiling {
			return ceiling
		}
	}
	return backoff
}

// Stats summarizes queue depth for the health endpoint.
type Stats struct {
	Queued  int `json:"queued"`
	Running int `json:"running"`
	Dead    int `json:"dead"`
}

func (q *Queue) Stats(ctx context.Context) (Stats, error) {
	const query = `
		SELECT
			COUNT(*) FILTER (WHERE status = 'queued'),
			COUNT(*) FILTER (WHERE status = 'running'),
			COUNT(*) FILTER (WHERE status = 'dead')
		FROM jobs`

	var stats Stats
	if err := q.pool.QueryRow(ctx, query).Scan(&stats.Queued, &stats.Running, &stats.Dead); err != nil {
		return Stats{}, fmt.Errorf("queue stats: %w", err)
	}
	return stats, nil
}
