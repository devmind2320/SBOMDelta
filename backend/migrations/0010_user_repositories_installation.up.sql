-- Whether any SBOMDelta user's GitHub listing includes an installation.
--
-- An installation queues automatic work (reconciliation, initial, push and
-- pull request scans) only once a signed-in user has connected it, so every
-- installation webhook asks this. The table is small, but the question is
-- asked on every push.
CREATE INDEX IF NOT EXISTS user_repositories_installation_idx ON user_repositories (github_installation_id);
