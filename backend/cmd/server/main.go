// Command server runs the HTTP API and the GitHub webhook receiver.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sbomdelta/internal/api"
	"sbomdelta/internal/auth"
	"sbomdelta/internal/config"
	ghapp "sbomdelta/internal/github"
	"sbomdelta/internal/queue"
	"sbomdelta/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(logger); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadAPI()
	if err != nil {
		return err
	}

	db, err := storage.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	// The server owns migrations so that a deploy brings the schema forward
	// once, before any worker starts querying tables that may not exist yet.
	if err := db.Migrate(ctx, logger); err != nil {
		return err
	}

	blob, err := storage.NewBlobStore(ctx, cfg.Blob)
	if err != nil {
		return err
	}

	jobs := queue.New(db.Pool(), cfg.Worker.LockTimeout)
	authService := auth.New(cfg.Auth, cfg.GitHub.APIBaseURL, db, logger)
	var webhook http.Handler
	// scans stays a nil interface, not a typed nil, when GitHub is disabled,
	// so the API can tell scanning is unavailable.
	var scans api.ScanRequester
	if cfg.GitHub.Disabled {
		logger.Info("GitHub integration disabled for local development")
		webhook = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "GitHub integration is disabled for local development", http.StatusServiceUnavailable)
		})
	} else {
		handler := ghapp.NewWebhookHandler(cfg.GitHub.WebhookSecret, cfg.GitHub.AllowedInstallationAccounts, db, jobs, logger)
		webhook = handler
		// Signing in is what connects an installation; reconcile the ones the
		// sign-in listed so a new installation is stored and scanned at once.
		authService.OnInstallationsListed(handler.QueueReconciliationAfterSignIn)
		if len(cfg.GitHub.AllowedInstallationAccounts) > 0 {
			logger.Info("installations restricted to ALLOWED_INSTALLATION_ACCOUNTS", "accounts", len(cfg.GitHub.AllowedInstallationAccounts))
		}
		// A scan request resolves the default branch head as the installation,
		// as initial scans do on the worker, then queues the usual scan job.
		scans = ghapp.NewManualScanner(ghapp.NewApp(cfg.GitHub), db, jobs, logger)
	}
	switch {
	case cfg.Auth.Disabled:
		logger.Warn("dashboard sign-in disabled for local development; every request is treated as signed in")
	case len(cfg.Auth.AllowedLogins) > 0:
		logger.Info("sign-in restricted to ALLOWED_GITHUB_LOGINS", "logins", len(cfg.Auth.AllowedLogins))
	default:
		logger.Info("sign-in open to any GitHub account; each sees only what GitHub grants it")
	}
	handler := api.New(db, blob, jobs, authService, scans, logger).Routes(webhook)

	server := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: handler,
		// GitHub webhook bodies are small and the read endpoints are quick;
		// generous timeouts here would only help slowloris clients.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.HTTPAddr, "env", cfg.Env)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
