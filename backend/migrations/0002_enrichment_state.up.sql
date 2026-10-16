-- Records when OSV enrichment last ran for a scan.
--
-- Without this the API cannot tell "we checked and found nothing" from "we
-- never checked", and those two render identically as an empty vulnerability
-- list. Reporting the second as the first would be the dashboard claiming a
-- clean bill of health it has not earned.
ALTER TABLE scans ADD COLUMN enriched_at TIMESTAMPTZ;
