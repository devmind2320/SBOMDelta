-- Scans queued because a repository became reachable and had never been
-- scanned, rather than because of a push, pull request or manual request.
--
-- Postgres allows ADD VALUE inside a transaction (the runner wraps every file
-- in one) as long as the new value is not used before that transaction
-- commits, which nothing here does.
ALTER TYPE scan_trigger ADD VALUE IF NOT EXISTS 'initial';
