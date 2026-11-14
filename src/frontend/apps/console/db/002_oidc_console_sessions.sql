-- Proposed migration; apply through reviewed deployment process.
CREATE TABLE IF NOT EXISTS oidc_console_sessions (
  session_hash char(64) PRIMARY KEY,
  subject varchar(256) NOT NULL,
  issuer varchar(2048) NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  CONSTRAINT oidc_console_sessions_expiry CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS ix_oidc_console_sessions_expiry ON oidc_console_sessions(expires_at);
CREATE INDEX IF NOT EXISTS ix_oidc_console_sessions_subject ON oidc_console_sessions(issuer, subject);
-- Purge expired rows on a scheduled maintenance task after operational retention.
