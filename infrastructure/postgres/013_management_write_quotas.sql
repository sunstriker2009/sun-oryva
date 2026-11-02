-- ORYVA backend v1: PostgreSQL-backed, cross-replica management write quotas.
-- Apply after 012_viewer_preparation_audit.sql before starting updated API replicas.
-- No identity, credentials, tokens or raw subject IDs are stored.
CREATE TABLE IF NOT EXISTS oryva.management_write_quotas (
    subject_key char(64) PRIMARY KEY,
    window_start timestamptz NOT NULL,
    request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 120),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT management_write_quotas_subject_key_check
        CHECK (subject_key ~ '^[0-9A-F]{64}$')
);

CREATE INDEX IF NOT EXISTS management_write_quotas_updated_at_idx
    ON oryva.management_write_quotas (updated_at);

REVOKE ALL ON oryva.management_write_quotas FROM PUBLIC;

COMMENT ON TABLE oryva.management_write_quotas IS
    'Cross-replica management POST quota counters keyed by SHA-256 of authenticated partition; prune expired rows operationally.';
