// Package worker drains the job queue.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"sbomdelta/internal/config"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/scanner"
)

type Worker struct {
	id      string
	queue   *queue.Queue
	scanner *scanner.Scanner
	cfg     config.Worker
	logger  *slog.Logger
}

func New(id string, q *queue.Queue, s *scanner.Scanner, cfg config.Worker, logger *slog.Logger) *Worker {
	return &Worker{id: id, queue: q, scanner: s, cfg: cfg, logger: logger}
}

// Run starts cfg.Concurrency loops and blocks until ctx is cancelled. Each
// loop finishes the job it is holding before exiting, so a rolling deploy does
// not abandon a scan mid-clone.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("worker started", "id", w.id, "concurrency", w.cfg.Concurrency)

	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			w.loop(ctx, slot)
		}(i)
	}

	wg.Wait()
	w.logger.Info("worker stopped", "id", w.id)
	return nil
}

func (w *Worker) loop(ctx context.Context, slot int) {
	logger := w.logger.With("slot", slot)
	timer := time.NewTimer(w.cfg.PollInterval)
	defer timer.Stop()

	for {
		job, err := w.queue.Dequeue(ctx, fmt.Sprintf("%s#%d", w.id, slot))
		switch {
		case err == nil:
			w.process(ctx, logger, job)
			continue // Keep draining while there is work.
		case errors.Is(err, queue.ErrNoJobs):
		case ctx.Err() != nil:
			return
		default:
			logger.Error("could not dequeue job", "error", err)
		}

		timer.Reset(w.cfg.PollInterval)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (w *Worker) process(ctx context.Context, logger *slog.Logger, job *queue.Job) {
	logger = logger.With("job", job.ID, "kind", job.Kind, "attempt", job.Attempts)

	err := w.handle(ctx, job)
	if err == nil {
		if err := w.queue.Succeed(ctx, job.ID); err != nil {
			logger.Error("could not mark job succeeded", "error", err)
		}
		return
	}

	logger.Error("job failed", "error", err)
	// Bookkeeping must survive the shutdown that may have caused the failure,
	// otherwise the job stays locked until the reaper reclaims it.
	failCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if failErr := w.queue.Fail(failCtx, job, err); failErr != nil {
		logger.Error("could not record job failure", "error", failErr)
	}
}

func (w *Worker) handle(ctx context.Context, job *queue.Job) error {
	switch job.Kind {
	case queue.KindScan:
		var payload queue.ScanPayload
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return fmt.Errorf("decode scan payload: %w", err)
		}
		if payload.ScanID == 0 {
			return errors.New("scan job carried no scan id")
		}
		return w.scanner.Run(ctx, payload.ScanID)
	default:
		return fmt.Errorf("unknown job kind %q", job.Kind)
	}
}
