-- Postgres cannot remove a value from an enum, so the type is rebuilt without
-- it, and every initial scan is relabelled manual so its row and history
-- survive. That is lossy: afterwards nothing distinguishes a scan queued
-- automatically from one a person asked for. 'manual' is the least wrong
-- label, because both kinds were not caused by a webhook and post no check
-- run, but it is not the same meaning.
--
-- Run by hand only, with every worker running code that writes 'initial'
-- stopped first. The column change rewrites the scans table under an
-- exclusive lock, and, like the other down migrations, this leaves the
-- schema_migrations row in place: delete it too if 0005 should run again.
ALTER TYPE scan_trigger RENAME TO scan_trigger_0005;
CREATE TYPE scan_trigger AS ENUM ('push', 'pull_request', 'manual', 'backfill');
ALTER TABLE scans
    ALTER COLUMN trigger TYPE scan_trigger
    USING (CASE trigger WHEN 'initial' THEN 'manual' ELSE trigger::text END)::scan_trigger;
DROP TYPE scan_trigger_0005;
