// Package storagetest opens an isolated, migrated database for integration
// tests outside the storage package.
package storagetest

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/storage"
)

// Open returns a migrated database whose tables live in their own schema.
//
// `go test ./...` runs packages in parallel against the same
// TEST_DATABASE_URL, and every package truncates its tables between tests.
// Giving each package a schema of its own keeps one package's truncate from
// wiping rows out from under another's test. The test is skipped when
// TEST_DATABASE_URL is unset; never point it at a database you care about.
func Open(t *testing.T, schema string) *storage.DB {
	t.Helper()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = admin.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+pgx.Identifier{schema}.Sanitize())
	_ = admin.Close(ctx)
	if err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}

	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	query := parsed.Query()
	// pgx passes unrecognised URL parameters through as runtime parameters,
	// so every pooled connection starts with this search_path.
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	db, err := storage.Open(ctx, parsed.String())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if _, err := db.Pool().Exec(ctx, `
		TRUNCATE installations, repositories, commits, pull_requests, scans,
		         components, drift_events, vulnerabilities, webhook_deliveries, jobs,
		         sessions, users, user_repositories, user_tracked_repositories
		RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return db
}
