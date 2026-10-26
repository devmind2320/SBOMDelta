-- The GitHub account an installation belongs to, by GitHub's numeric ID.
--
-- ALLOWED_INSTALLATION_ACCOUNTS names accounts by this ID, not by login: a
-- login can be renamed and then claimed by someone else, the ID cannot. Push
-- and pull request payloads carry only the installation's ID, so the account
-- is recorded here from installation events. Rows from before this column
-- stay NULL until reconciliation asks GitHub for the account; until then they
-- are treated as unapproved and queue no work.
ALTER TABLE installations ADD COLUMN account_id BIGINT;
