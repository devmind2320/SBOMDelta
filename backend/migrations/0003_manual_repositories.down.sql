DELETE FROM repositories WHERE github_repo_id IS NULL;
ALTER TABLE repositories DROP COLUMN IF EXISTS clone_url;
ALTER TABLE repositories ALTER COLUMN github_repo_id SET NOT NULL;
