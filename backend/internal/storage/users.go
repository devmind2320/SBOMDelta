package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/models"
)

// UpsertUser records a GitHub user who has just signed in, keyed on GitHub's
// numeric ID, refreshing the login and avatar that may have changed since.
func (db *DB) UpsertUser(ctx context.Context, user models.User) (models.User, error) {
	const query = `
		INSERT INTO users (github_user_id, login, avatar_url)
		VALUES ($1, $2, NULLIF($3, ''))
		ON CONFLICT (github_user_id) DO UPDATE
		SET login         = EXCLUDED.login,
		    avatar_url    = EXCLUDED.avatar_url,
		    updated_at    = now(),
		    last_login_at = now()
		RETURNING id, github_user_id, login, COALESCE(avatar_url, '')`

	var out models.User
	err := db.pool.QueryRow(ctx, query, user.GitHubUserID, user.Login, user.AvatarURL).
		Scan(&out.ID, &out.GitHubUserID, &out.Login, &out.AvatarURL)
	if err != nil {
		return models.User{}, fmt.Errorf("upsert user: %w", err)
	}
	return out, nil
}

// CreateSession stores a session under the hash of its token. Expired
// sessions are swept at the same time; signing in is rare enough that this
// is all the housekeeping the table needs.
func (db *DB) CreateSession(ctx context.Context, tokenHash []byte, userID int64, expiresAt time.Time) error {
	if _, err := db.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`); err != nil {
		return fmt.Errorf("sweep expired sessions: %w", err)
	}
	if _, err := db.pool.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expiresAt); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// SessionUser returns the user a session belongs to, or ErrNotFound when the
// session does not exist or has expired. Expiry is judged by the database
// clock, the same one that wrote expires_at's neighbours.
func (db *DB) SessionUser(ctx context.Context, tokenHash []byte) (models.User, error) {
	const query = `
		SELECT u.id, u.github_user_id, u.login, COALESCE(u.avatar_url, '')
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`

	var out models.User
	err := db.pool.QueryRow(ctx, query, tokenHash).Scan(&out.ID, &out.GitHubUserID, &out.Login, &out.AvatarURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.User{}, ErrNotFound
	}
	if err != nil {
		return models.User{}, fmt.Errorf("look up session: %w", err)
	}
	return out, nil
}

// DeleteSession ends a session. Deleting one that does not exist is not an
// error: signing out twice is still signed out.
func (db *DB) DeleteSession(ctx context.Context, tokenHash []byte) error {
	if _, err := db.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
