DROP TABLE IF EXISTS user_tracked_repositories;
ALTER TABLE users
    DROP COLUMN IF EXISTS repos_list_error,
    DROP COLUMN IF EXISTS repos_listed_at;
DROP TABLE IF EXISTS user_repositories;
