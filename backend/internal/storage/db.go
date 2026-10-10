// Package storage owns all Postgres access and the SBOM blob store.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"sbomdelta/migrations"
)

// DB wraps a pgx pool. It is safe for concurrent use.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and verifies the connection before returning, so
// that a bad DATABASE_URL fails at startup rather than on the first request.
func Open(ctx context.Context, databaseURL string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Pool() *pgxpool.Pool { return db.pool }

func (db *DB) Close() { db.pool.Close() }

func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// advisoryLockKey is an arbitrary constant unique to this application; it stops
// two instances starting at once from applying the same migration twice.
const advisoryLockKey int64 = 8021_0001

// Migrate applies every embedded .up.sql file that has not run yet, in
// filename order, each inside its own transaction.
func (db *DB) Migrate(ctx context.Context, logger *slog.Logger) error {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Best effort: releasing the lock is also implicit on disconnect.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, advisoryLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     TEXT        PRIMARY KEY,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := make(map[string]struct{})
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[version] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate schema_migrations: %w", err)
	}

	versions, err := upMigrations()
	if err != nil {
		return err
	}

	for _, version := range versions {
		if _, done := applied[version]; done {
			continue
		}
		statements, err := migrations.FS.ReadFile(version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(statements)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
		logger.Info("applied migration", "version", version)
	}
	return nil
}

func upMigrations() ([]string, error) {
	entries, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)
	return entries, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint error.
// Several call sites treat a duplicate as a benign no-op (a replayed webhook,
// a re-enqueued job) rather than a failure.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}
