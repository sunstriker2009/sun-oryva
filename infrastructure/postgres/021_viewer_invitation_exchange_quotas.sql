-- ORYVA backend v1: internal, cross-replica invitation exchange attempt quota.
-- Apply after 020. A viewer-specific fixed window bounds online guessing and
-- resource consumption, but a public browser endpoint additionally requires
-- trusted-proxy-aware IP throttling, CSRF and origin protection.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_exchange_quotas (
    viewer_id uuid PRIMARY KEY
        REFERENCES oryva.viewer_accounts(id) ON DELETE CASCADE,
    window_started_at timestamptz NOT NULL,
    attempt_count integer NOT NULL,
    CONSTRAINT viewer_invitation_exchange_quota_count_check
        CHECK (attempt_count BETWEEN 1 AND 33)
);

REVOKE ALL ON oryva.viewer_invitation_exchange_quotas FROM PUBLIC;

COMMENT ON TABLE oryva.viewer_invitation_exchange_quotas IS
    'Internal fixed 60-second, 32-attempt per-viewer exchange throttle; 33 is the saturated sentinel. No token, email, IP or Keycloak identity is stored.';
