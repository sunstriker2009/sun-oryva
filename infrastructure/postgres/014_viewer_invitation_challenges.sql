-- ORYVA backend v1: durable, one-use email-ownership challenge foundation.
-- Apply after 013_management_write_quotas.sql. This is NOT an invitation API.
-- Store SHA-256 digests only; never persist plaintext bearer tokens.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_challenges (
    id uuid PRIMARY KEY,
    viewer_id uuid NOT NULL REFERENCES oryva.viewer_accounts(id) ON DELETE RESTRICT,
    token_digest char(64) NOT NULL UNIQUE,
    recipient_email text NOT NULL,
    issued_by_subject text NOT NULL,
    issued_by_role text NOT NULL
        CONSTRAINT viewer_invitation_issuer_role_check
        CHECK (issued_by_role IN ('master', 'admin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT viewer_invitation_digest_check
        CHECK (token_digest ~ '^[0-9A-F]{64}$'),
    CONSTRAINT viewer_invitation_email_check
        CHECK (length(trim(recipient_email)) > 0),
    CONSTRAINT viewer_invitation_actor_check
        CHECK (length(trim(issued_by_subject)) > 0),
    CONSTRAINT viewer_invitation_expiry_check
        CHECK (expires_at > created_at AND
               expires_at <= created_at + interval '15 minutes'),
    CONSTRAINT viewer_invitation_terminal_check
        CHECK (consumed_at IS NULL OR revoked_at IS NULL),
    CONSTRAINT viewer_invitation_consumed_check
        CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CONSTRAINT viewer_invitation_revoked_check
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

-- Expired but unrevoked rows still occupy this slot: reissue must explicitly
-- revoke the previous challenge under the viewer row lock before insertion.
CREATE UNIQUE INDEX IF NOT EXISTS viewer_invitation_one_outstanding_idx
    ON oryva.viewer_invitation_challenges(viewer_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS viewer_invitation_expiry_idx
    ON oryva.viewer_invitation_challenges(expires_at);

REVOKE ALL ON oryva.viewer_invitation_challenges FROM PUBLIC;

COMMENT ON TABLE oryva.viewer_invitation_challenges IS
    'Internal one-use, 15-minute email-ownership challenge ledger. No email sender, public redemption, Keycloak verification, credential write or activation is enabled.';
