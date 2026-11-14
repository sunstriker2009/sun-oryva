-- Apply through a reviewed deployment migration before enabling OIDC routes.
-- Keep encrypted transaction payloads only; do not store PKCE verifiers or nonces in plaintext.
CREATE TABLE IF NOT EXISTS oidc_browser_transactions (
    state_hash char(64) PRIMARY KEY,
    browser_binding_hash char(64) NOT NULL,
    sealed_payload text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    CONSTRAINT oidc_browser_transactions_expiry CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS ix_oidc_browser_transactions_expiry
    ON oidc_browser_transactions (expires_at);
-- Operational cleanup: DELETE WHERE expires_at < now() - interval '1 day';
