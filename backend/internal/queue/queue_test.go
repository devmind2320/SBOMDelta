package queue_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

// See internal/storage/store_test.go for how to point TEST_DATABASE_URL at a
// throwaway database.
func newTestQueue(t *testing.T, lockTimeout time.Duration) *queue.Queue {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping queue integration tests")
	}

	ctx := context.Background()
	db, err := storage.Open(ctx, url)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if _, err := db.Pool().Exec(ctx, `TRUNCATE jobs RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate jobs: %v", err)
	}
	return queue.New(db.Pool(), lockTimeout)
}

func TestEnqueueDequeueSucceed(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	jobID, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 7}, "scan:7")
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if jobID == 0 {
		t.Fatal("Enqueue() returned 0 for a new job")
	}

	job, err := q.Dequeue(ctx, "worker-a")
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if job.Kind != queue.KindScan {
		t.Errorf("kind = %q, want %q", job.Kind, queue.KindScan)
	}
	if job.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", job.Attempts)
	}

	// A claimed job must be invisible to every other worker.
	if _, err := q.Dequeue(ctx, "worker-b"); !errors.Is(err, queue.ErrNoJobs) {
		t.Errorf("second Dequeue() error = %v, want ErrNoJobs", err)
	}

	if err := q.Succeed(ctx, job.ID); err != nil {
		t.Fatalf("Succeed() error = %v", err)
	}
}

// The dedupe key is what stops a redelivered webhook from scanning the same
// commit twice.
func TestEnqueueDeduplicates(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	if _, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 11}, "scan:11"); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	duplicate, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 11}, "scan:11")
	if err != nil {
		t.Fatalf("duplicate Enqueue() error = %v", err)
	}
	if duplicate != 0 {
		t.Errorf("duplicate Enqueue() = %d, want 0", duplicate)
	}

	stats, err := q.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Queued != 1 {
		t.Errorf("queued = %d, want 1", stats.Queued)
	}
}

// An empty dedupe key means "always queue this", so unrelated jobs are not
// collapsed into one by a shared NULL.
func TestEnqueueWithoutDedupeKey(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		id, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: int64(i)}, "")
		if err != nil {
			t.Fatalf("Enqueue() error = %v", err)
		}
		if id == 0 {
			t.Fatalf("Enqueue() %d was deduplicated against a NULL key", i)
		}
	}

	stats, err := q.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Queued != 3 {
		t.Errorf("queued = %d, want 3", stats.Queued)
	}
}

// A retry is rescheduled into the future, so it must not come straight back.
func TestFailReschedulesWithBackoff(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	if _, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 21}, "scan:21"); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	job, err := q.Dequeue(ctx, "worker-a")
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if err := q.Fail(ctx, job, errors.New("syft exited 1")); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}

	if _, err := q.Dequeue(ctx, "worker-a"); !errors.Is(err, queue.ErrNoJobs) {
		t.Errorf("Dequeue() error = %v, want ErrNoJobs while the backoff is pending", err)
	}

	stats, err := q.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Queued != 1 || stats.Running != 0 {
		t.Errorf("stats = %+v, want one queued and none running", stats)
	}
}

func TestFailParksJobAfterMaxAttempts(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	if _, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 31}, "scan:31"); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	job, err := q.Dequeue(ctx, "worker-a")
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}

	job.Attempts = job.MaxAttempts // Simulate an exhausted retry budget.
	if err := q.Fail(ctx, job, errors.New("permanent failure")); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}

	stats, err := q.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Dead != 1 {
		t.Errorf("dead = %d, want 1", stats.Dead)
	}
	if _, err := q.Dequeue(ctx, "worker-a"); !errors.Is(err, queue.ErrNoJobs) {
		t.Error("a dead job was handed back out")
	}
}

// A worker that dies mid-job must not strand it: another worker reclaims the
// job once its lock outlives the timeout.
func TestDequeueReclaimsAbandonedJobs(t *testing.T) {
	q := newTestQueue(t, time.Nanosecond)
	ctx := context.Background()

	if _, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 41}, "scan:41"); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	first, err := q.Dequeue(ctx, "worker-that-dies")
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}

	reclaimed, err := q.Dequeue(ctx, "worker-that-lives")
	if err != nil {
		t.Fatalf("reclaiming Dequeue() error = %v", err)
	}
	if reclaimed.ID != first.ID {
		t.Errorf("reclaimed job = %d, want the abandoned %d", reclaimed.ID, first.ID)
	}
	// The attempt counter has to advance, or a job that reliably kills its
	// worker would be retried forever.
	if reclaimed.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", reclaimed.Attempts)
	}
}

// Succeed clears the dedupe key so the same target can be scanned again later.
func TestSucceedReleasesDedupeKey(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	if _, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 51}, "scan:51"); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	job, err := q.Dequeue(ctx, "worker-a")
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if err := q.Succeed(ctx, job.ID); err != nil {
		t.Fatalf("Succeed() error = %v", err)
	}

	requeued, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 51}, "scan:51")
	if err != nil {
		t.Fatalf("re-Enqueue() error = %v", err)
	}
	if requeued == 0 {
		t.Error("re-enqueue was blocked by the completed job's dedupe key")
	}
}

// Jobs are drained oldest-first so a busy queue cannot starve early work.
func TestDequeueIsFIFO(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	var ids []int64
	for i := 0; i < 3; i++ {
		id, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: int64(i)}, "")
		if err != nil {
			t.Fatalf("Enqueue() error = %v", err)
		}
		ids = append(ids, id)
	}

	for i, want := range ids {
		job, err := q.Dequeue(ctx, "worker-a")
		if err != nil {
			t.Fatalf("Dequeue() %d error = %v", i, err)
		}
		if job.ID != want {
			t.Errorf("job %d = %d, want %d", i, job.ID, want)
		}
	}
}

// A dead job's dedupe key blocks the same work from ever being queued again
// unless it is released. Releasing must not touch a key a live job holds.
func TestReleaseDeadDedupeKey(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	if _, err := q.Enqueue(ctx, queue.KindInitialScan, queue.InitialScanPayload{RepositoryID: 9}, "initial:9"); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if released, err := q.ReleaseDeadDedupeKey(ctx, "initial:9"); err != nil || released {
		t.Fatalf("ReleaseDeadDedupeKey() on a queued job = %v, %v; want false, nil", released, err)
	}
	if id, _ := q.Enqueue(ctx, queue.KindInitialScan, queue.InitialScanPayload{RepositoryID: 9}, "initial:9"); id != 0 {
		t.Fatal("a queued job's key was released")
	}

	job, err := q.Dequeue(ctx, "worker-a")
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	job.Attempts = job.MaxAttempts
	if err := q.Fail(ctx, job, errors.New("github unavailable")); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
	if id, _ := q.Enqueue(ctx, queue.KindInitialScan, queue.InitialScanPayload{RepositoryID: 9}, "initial:9"); id != 0 {
		t.Fatal("precondition: a dead job should still hold its key")
	}

	if released, err := q.ReleaseDeadDedupeKey(ctx, "initial:9"); err != nil || !released {
		t.Fatalf("ReleaseDeadDedupeKey() = %v, %v; want true, nil", released, err)
	}
	if id, err := q.Enqueue(ctx, queue.KindInitialScan, queue.InitialScanPayload{RepositoryID: 9}, "initial:9"); err != nil || id == 0 {
		t.Errorf("re-Enqueue() after release = %d, %v; want a new job", id, err)
	}
	stats, err := q.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Dead != 1 || stats.Queued != 1 {
		t.Errorf("stats = %+v, want the dead job kept for inspection beside the new one", stats)
	}
}

// Spaced jobs of one kind run one spacing apart, measured from the latest one
// still queued: only the first is runnable now, and a later call (another
// installation's reconciliation) lines up behind them instead of at now.
func TestEnqueueSpaced(t *testing.T) {
	q := newTestQueue(t, 15*time.Minute)
	ctx := context.Background()

	for i := int64(1); i <= 3; i++ {
		id, err := q.EnqueueSpaced(ctx, queue.KindInitialScan, queue.InitialScanPayload{RepositoryID: i},
			fmt.Sprintf("initial:%d", i), time.Hour)
		if err != nil || id == 0 {
			t.Fatalf("EnqueueSpaced(%d) = %d, %v", i, id, err)
		}
	}
	if id, err := q.EnqueueSpaced(ctx, queue.KindInitialScan, queue.InitialScanPayload{RepositoryID: 1},
		"initial:1", time.Hour); err != nil || id != 0 {
		t.Errorf("duplicate EnqueueSpaced() = %d, %v; want deduplicated", id, err)
	}
	// Other kinds are not held back by spaced jobs.
	if _, err := q.Enqueue(ctx, queue.KindScan, queue.ScanPayload{ScanID: 1}, ""); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	var kinds []queue.Kind
	for {
		job, err := q.Dequeue(ctx, "worker-a")
		if errors.Is(err, queue.ErrNoJobs) {
			break
		}
		if err != nil {
			t.Fatalf("Dequeue() error = %v", err)
		}
		kinds = append(kinds, job.Kind)
	}
	if len(kinds) != 2 {
		t.Errorf("runnable now = %v, want the first spaced job and the scan only", kinds)
	}
}
