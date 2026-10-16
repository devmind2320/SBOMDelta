-- Repositories registered by hand, without the GitHub App.
--
-- The scan pipeline is useful on its own: point it at a public repository and
-- it produces the same SBOM, diff and drift history. Those repositories have
-- no GitHub installation to authenticate as and no numeric GitHub repo ID, so
-- the ID becomes nullable and the clone source becomes explicit.
--
-- Postgres allows duplicate NULLs under a UNIQUE constraint, so the existing
-- uniqueness on github_repo_id still holds for App-managed repositories.
ALTER TABLE repositories ALTER COLUMN github_repo_id DROP NOT NULL;
ALTER TABLE repositories ADD COLUMN clone_url TEXT;
