-- ORYVA backend v1: internal browser-secret rotation/revocation audit.
-- Apply after 022. Not a public cookie/session endpoint, login, email proof,
-- Keycloak credential grant or account activation.
-- No bearer secret, digest, recipient address or subject is recorded.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_browser_session_audit (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL,
    viewer_id uuid NOT NULL,
    event_type text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT browser_session_audit_event_check
        CHECK (event_type IN ('rotated', 'revoked'))
);

-- Deliberately no session FK: security audit evidence must survive operational
-- purging of expired browser sessions. Correlation is by opaque UUID only.
CREATE INDEX IF NOT EXISTS viewer_invitation_browser_session_audit_session_idx
    ON oryva.viewer_invitation_browser_session_audit(session_id, recorded_at);

CREATE OR REPLACE FUNCTION oryva.reject_browser_session_audit_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Browser session audit is append-only';
END;
$$;

DO $browser_session_audit_trigger$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'oryva.viewer_invitation_browser_session_audit'::regclass
          AND tgname = 'browser_session_audit_immutable'
    ) THEN
        CREATE TRIGGER browser_session_audit_immutable
            BEFORE UPDATE OR DELETE ON oryva.viewer_invitation_browser_session_audit
            FOR EACH ROW EXECUTE FUNCTION oryva.reject_browser_session_audit_mutation();
    END IF;
END $browser_session_audit_trigger$;

REVOKE ALL ON oryva.viewer_invitation_browser_session_audit FROM PUBLIC;
COMMENT ON TABLE oryva.viewer_invitation_browser_session_audit IS
    'Append-only internal rotation/revocation events. Opaque session/viewer UUIDs only; not authentication, verified email, credential enrollment or activation.';
