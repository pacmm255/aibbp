-- Rollback active testing engine tables.

DROP TABLE IF EXISTS browser_screenshots;
DROP TABLE IF EXISTS active_test_steps;
DROP TABLE IF EXISTS active_findings;
DROP TABLE IF EXISTS http_traffic_log;
DROP TABLE IF EXISTS test_accounts;
DROP TABLE IF EXISTS active_test_sessions;
