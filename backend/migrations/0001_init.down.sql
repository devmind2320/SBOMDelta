DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS drift_events;
DROP TABLE IF EXISTS components;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS pull_requests;
DROP TABLE IF EXISTS commits;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS installations;

DROP TYPE IF EXISTS job_status;
DROP TYPE IF EXISTS drift_change;
DROP TYPE IF EXISTS scan_trigger;
DROP TYPE IF EXISTS scan_status;
