-- Dashboard sign-in.
--
-- People sign in through the GitHub App's user authorization flow. Their
-- GitHub token is used once, to learn who they are, and is never stored:
-- repository access still comes only from installation tokens.
CREATE TABLE users (
    id             BIGSERIAL PRIMARY KEY,
    -- The numeric ID is stable across renames; the login is display only.
    github_user_id BIGINT      NOT NULL UNIQUE,
    login          TEXT        NOT NULL,
    avatar_url     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per signed-in browser. The cookie carries a random token; only its
-- SHA-256 is stored, so a copy of this table cannot be replayed as a session.
CREATE TABLE sessions (
    token_hash BYTEA       PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
