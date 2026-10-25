-- Which repositories each signed-in user may see, and which they track.
--
-- At sign-in, while the user's GitHub token is still in hand, the server asks
-- GitHub which repositories the user can reach through the App's
-- installations and records that list here. The token itself is still never
-- stored. Every repository, scan and SBOM request is checked against this
-- list, so one user never reads another user's private repository data.
CREATE TABLE user_repositories (
    user_id                BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- GitHub's numeric IDs, which survive renames and transfers. Joined to
    -- repositories.github_repo_id; no foreign key, because the installation's
    -- reconciliation may not have stored the repository yet.
    github_repo_id         BIGINT      NOT NULL,
    github_installation_id BIGINT      NOT NULL,
    owner                  TEXT        NOT NULL,
    name                   TEXT        NOT NULL,
    private                BOOLEAN     NOT NULL,
    default_branch         TEXT,
    listed_at              TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, github_repo_id)
);

CREATE INDEX user_repositories_repo_idx ON user_repositories (github_repo_id);

-- When the list was last read from GitHub, and why reading it failed if it
-- did. A failed read clears the list rather than keeping a stale one.
ALTER TABLE users
    ADD COLUMN repos_listed_at  TIMESTAMPTZ,
    ADD COLUMN repos_list_error TEXT;

-- Repositories a user chose to scan, shown under "Tracked Repos".
CREATE TABLE user_tracked_repositories (
    user_id       BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    repository_id BIGINT      NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    tracked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, repository_id)
);
