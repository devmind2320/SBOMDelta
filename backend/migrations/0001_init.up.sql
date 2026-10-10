-- SBOMDelta initial schema.
--
-- Design notes:
--   * Large CycloneDX documents live in blob storage; Postgres holds the
--     queryable projection of them (components, drift, findings).
--   * `jobs` is the async work queue, drained with FOR UPDATE SKIP LOCKED so
--     that webhook delivery never blocks on a repository clone.
--   * `webhook_deliveries` gives us idempotency: GitHub retries deliveries and
--     at-least-once delivery must not produce duplicate scans.

CREATE TABLE installations (
    id                     BIGSERIAL PRIMARY KEY,
    github_installation_id BIGINT      NOT NULL UNIQUE,
    account_login          TEXT        NOT NULL,
    account_type           TEXT        NOT NULL DEFAULT 'User',
    suspended_at           TIMESTAMPTZ,
    deleted_at             TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE repositories (
    id              BIGSERIAL PRIMARY KEY,
    installation_id BIGINT      REFERENCES installations (id) ON DELETE SET NULL,
    github_repo_id  BIGINT      NOT NULL UNIQUE,
    owner           TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    default_branch  TEXT        NOT NULL DEFAULT 'main',
    private         BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner, name)
);

CREATE TABLE commits (
    id            BIGSERIAL PRIMARY KEY,
    repository_id BIGINT      NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    sha           TEXT        NOT NULL,
    ref           TEXT,
    author_login  TEXT,
    author_email  TEXT,
    message       TEXT,
    committed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, sha)
);

CREATE TABLE pull_requests (
    id            BIGSERIAL PRIMARY KEY,
    repository_id BIGINT      NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    number        INTEGER     NOT NULL,
    title         TEXT,
    author_login  TEXT,
    state         TEXT        NOT NULL DEFAULT 'open',
    base_ref      TEXT,
    base_sha      TEXT        NOT NULL,
    head_sha      TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, number)
);

CREATE TYPE scan_status  AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE scan_trigger AS ENUM ('push', 'pull_request', 'manual', 'backfill');

CREATE TABLE scans (
    id                  BIGSERIAL PRIMARY KEY,
    repository_id       BIGINT       NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    pull_request_id     BIGINT       REFERENCES pull_requests (id) ON DELETE SET NULL,
    -- The scan this one is diffed against. NULL for the first scan of a repo.
    base_scan_id        BIGINT       REFERENCES scans (id) ON DELETE SET NULL,
    commit_sha          TEXT         NOT NULL,
    base_commit_sha     TEXT,
    trigger             scan_trigger NOT NULL,
    status              scan_status  NOT NULL DEFAULT 'pending',
    sbom_location       TEXT,
    sbom_sha256         TEXT,
    component_count     INTEGER      NOT NULL DEFAULT 0,
    risk_score          NUMERIC(10, 2),
    risk_delta          NUMERIC(10, 2),
    github_check_run_id BIGINT,
    error               TEXT,
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- One scan per (repo, commit, PR-or-branch). A commit pushed to a branch and
-- then opened as a PR legitimately gets two scans: the PR one is diffed
-- against the merge base, the push one against the previous commit.
CREATE UNIQUE INDEX scans_dedupe_idx
    ON scans (repository_id, commit_sha, (COALESCE(pull_request_id, 0)));

CREATE INDEX scans_repo_created_idx ON scans (repository_id, created_at DESC);
CREATE INDEX scans_pr_idx           ON scans (pull_request_id) WHERE pull_request_id IS NOT NULL;

CREATE TABLE components (
    id                 BIGSERIAL PRIMARY KEY,
    scan_id            BIGINT  NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    purl               TEXT    NOT NULL,
    name               TEXT    NOT NULL,
    version            TEXT    NOT NULL,
    ecosystem          TEXT    NOT NULL,
    type               TEXT,
    license_expression TEXT,
    licenses           TEXT[]  NOT NULL DEFAULT '{}',
    direct             BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (scan_id, purl)
);

CREATE INDEX components_purl_idx      ON components (purl);
CREATE INDEX components_ecosystem_idx ON components (ecosystem, name);

CREATE TYPE drift_change AS ENUM ('added', 'removed', 'updated');

CREATE TABLE drift_events (
    id           BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    base_scan_id BIGINT        REFERENCES scans (id) ON DELETE SET NULL,
    change_type  drift_change  NOT NULL,
    -- Version-less PURL, e.g. pkg:npm/lodash. This is the dependency identity
    -- the diff engine matches on.
    identity     TEXT          NOT NULL,
    purl         TEXT          NOT NULL,
    name         TEXT          NOT NULL,
    ecosystem    TEXT          NOT NULL,
    old_version  TEXT,
    new_version  TEXT,
    direction    TEXT,
    risk_delta   NUMERIC(10, 2) NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    UNIQUE (scan_id, change_type, purl)
);

CREATE INDEX drift_events_scan_idx     ON drift_events (scan_id);
CREATE INDEX drift_events_identity_idx ON drift_events (identity);

-- Populated in Phase 4 (OSV enrichment); created now so the projection layer
-- has a stable target.
CREATE TABLE vulnerabilities (
    id            BIGSERIAL PRIMARY KEY,
    component_id  BIGINT      NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    osv_id        TEXT        NOT NULL,
    aliases       TEXT[]      NOT NULL DEFAULT '{}',
    severity      TEXT,
    cvss_score    NUMERIC(4, 1),
    cvss_vector   TEXT,
    summary       TEXT,
    fixed_version TEXT,
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (component_id, osv_id)
);

CREATE INDEX vulnerabilities_severity_idx ON vulnerabilities (severity);

CREATE TYPE job_status AS ENUM ('queued', 'running', 'succeeded', 'failed', 'dead');

CREATE TABLE jobs (
    id           BIGSERIAL PRIMARY KEY,
    kind         TEXT        NOT NULL,
    payload      JSONB       NOT NULL,
    status       job_status  NOT NULL DEFAULT 'queued',
    attempts     INTEGER     NOT NULL DEFAULT 0,
    max_attempts INTEGER     NOT NULL DEFAULT 3,
    run_after    TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at    TIMESTAMPTZ,
    locked_by    TEXT,
    last_error   TEXT,
    -- Collapses duplicate work, e.g. two pushes to the same commit.
    dedupe_key   TEXT UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX jobs_dequeue_idx ON jobs (run_after) WHERE status = 'queued';
CREATE INDEX jobs_reap_idx    ON jobs (locked_at) WHERE status = 'running';

-- GitHub delivers at least once; this table makes replays no-ops.
CREATE TABLE webhook_deliveries (
    delivery_id TEXT        PRIMARY KEY,
    event       TEXT        NOT NULL,
    action      TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
