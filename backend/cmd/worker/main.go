// Command worker drains the scan queue: clone, SBOM, diff, report.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"sbomdelta/internal/config"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/sbom"
	"sbomdelta/internal/scanner"
	"sbomdelta/internal/storage"
	"sbomdelta/internal/worker"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(logger); err != nil {
		logger.Error("worker exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadWorker()
	if err != nil {
		return err
	}

	generator := sbom.NewGenerator(cfg.Scanner)
	// Fail fast: a worker without syft would otherwise burn through every
	// job's retry budget before anyone noticed.
	if err := generator.Check(ctx); err != nil {
		return err
	}
	// Same reasoning for git: a stale binary fails every clone with a
	// confusing error rather than at startup.
	if err := sbom.CheckGit(ctx, cfg.Scanner); err != nil {
		return err
	}

	db, err := storage.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	blob, err := storage.NewBlobStore(ctx, cfg.Blob)
	if err != nil {
		return err
	}

	jobs := queue.New(db.Pool(), cfg.Worker.LockTimeout)

	// With GitHub disabled there are no credentials to build a client from.
	// The scanner treats a nil app as "manual scans only" and fails loudly if
	// a scan actually needs an installation token.
	var app *ghapp.App
	if cfg.GitHub.Disabled {
		logger.Warn("GitHub integration disabled; only manual scans will run")
	} else {
		app = ghapp.NewApp(cfg.GitHub)
	}

	pipeline := scanner.New(db, blob, app, generator, cfg.Scanner, logger)

	var reconciler *ghapp.Reconciler
	var initial *ghapp.InitialScanner
	if app != nil {
		reconciler = ghapp.NewReconciler(app, db, jobs, logger)
		initial = ghapp.NewInitialScanner(app, db, jobs, logger)
		// A webhook missed while nothing was listening is never redelivered
		// once GitHub stops retrying, so re-read every installation's
		// repository list each time a worker starts. Reconciliation also
		// queues initial scans for repositories that have never been scanned.
		if err := enqueueReconciliation(ctx, db, jobs, logger); err != nil {
			return err
		}
	}

	return worker.New(workerID(), jobs, pipeline, reconciler, initial, cfg.Worker, logger).Run(ctx)
}

func enqueueReconciliation(ctx context.Context, db *storage.DB, jobs *queue.Queue, logger *slog.Logger) error {
	installations, err := db.ListUsableInstallations(ctx)
	if err != nil {
		return err
	}
	for _, id := range installations {
		if _, err := jobs.Enqueue(ctx, queue.KindReconcileInstallation,
			queue.ReconcileInstallationPayload{GitHubInstallationID: id}, ""); err != nil {
			return err
		}
	}
	logger.Info("queued startup repository reconciliation", "installations", len(installations))
	return nil
}

// workerID identifies which process holds a job lock, which is what makes a
// stuck job traceable back to a specific container.
func workerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "worker"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}
