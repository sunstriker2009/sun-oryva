-- ORYVA browser admission quota: shared PostgreSQL fixed-minute counters.
-- No raw client IP, email, invitation token or Keycloak subject is stored.
-- All API replicas MUST use the same secret HMAC key (provided outside Git).
CREATE TABLE IF NOT EXISTS oryva.browser_admission_quotas (
    scope text NOT NULL,
    partition_key text NOT NULL,
    window_start timestamptz NOT NULL,
    request_count integer NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope, partition_key),
    CONSTRAINT browser_admission_scope_key_check CHECK (
        (scope = 'global' AND partition_key = 'global') OR
        (scope = 'ip' AND partition_key ~ '^[0-9A-F]{64}$')
    ),
    CONSTRAINT browser_admission_count_check CHECK (request_count BETWEEN 1 AND 1001)
);
REVOKE ALL ON oryva.browser_admission_quotas FROM PUBLIC;
COMMENT ON TABLE oryva.browser_admission_quotas IS
    'Opt-in browser admission: keyed HMAC of client IP or IPv6 /64, plus a global counter. No raw address or bearer data.';
