-- ORYVA backend v1: internal, one-time invitation-to-browser-secret exchange.
-- Apply after 019_viewer_invitation_smtp_handoff.sql. No public endpoint,
-- Keycloak emailVerified mutation, credential enrollment or activation.
-- Store only SHA-256 digests; the browser secret must never enter PostgreSQL.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_browser_sessions (
    id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE
        REFERENCES oryva.viewer_invitation_challenges(id) ON DELETE RESTRICT,
    viewer_id uuid NOT NULL
        REFERENCES oryva.viewer_accounts(id) ON DELETE RESTRICT,
    session_digest char(64) NOT NULL UNIQUE,
    subject_snapshot text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT viewer_invitation_browser_digest_check
        CHECK (session_digest ~ '^[0-9A-F]{64}$'),
    CONSTRAINT viewer_invitation_browser_subject_check
        CHECK (length(btrim(subject_snapshot)) > 0),
    CONSTRAINT viewer_invitation_browser_expiry_check
        CHECK (expires_at > created_at AND
               expires_at <= created_at + interval '5 minutes'),
    CONSTRAINT viewer_invitation_browser_revocation_check
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX IF NOT EXISTS viewer_invitation_browser_active_idx
    ON oryva.viewer_invitation_browser_sessions(viewer_id)
    WHERE revoked_at IS NULL;

-- Database-enforced invalidation, including an identity/email change that is
-- later reverted. This closes the change-away/change-back replay window.
CREATE OR REPLACE FUNCTION oryva.revoke_viewer_invitation_browser_on_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IS DISTINCT FROM NEW.state
       OR OLD.email IS DISTINCT FROM NEW.email
       OR OLD.keycloak_subject_id IS DISTINCT FROM NEW.keycloak_subject_id THEN
        UPDATE oryva.viewer_invitation_browser_sessions
        SET revoked_at = clock_timestamp()
        WHERE viewer_id = NEW.id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS viewer_invitation_browser_identity_changed
    ON oryva.viewer_accounts;
CREATE TRIGGER viewer_invitation_browser_identity_changed
    AFTER UPDATE OF state, email, keycloak_subject_id
    ON oryva.viewer_accounts
    FOR EACH ROW
    EXECUTE FUNCTION oryva.revoke_viewer_invitation_browser_on_change();

REVOKE ALL ON oryva.viewer_invitation_browser_sessions FROM PUBLIC;

COMMENT ON TABLE oryva.viewer_invitation_browser_sessions IS
    'Internal five-minute digest-only browser exchange. Possession of this secret is not Keycloak email verification, a login, a password reset or authorization to activate a user.';
