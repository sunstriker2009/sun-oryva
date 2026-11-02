-- ORYVA backend v1: append-only, transactionally committed invitation events.
-- Apply after 014_viewer_invitation_challenges.sql.
-- Intentionally no foreign key: audit must survive challenge retention/purge.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    challenge_id uuid NOT NULL,
    viewer_id uuid NOT NULL,
    event_type text NOT NULL
        CONSTRAINT viewer_invitation_audit_event_check
        CHECK (event_type IN ('issued', 'revoked', 'consumed')),
    actor_subject text,
    actor_role text,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT viewer_invitation_audit_actor_check CHECK (
        (event_type IN ('issued', 'revoked')
         AND length(trim(coalesce(actor_subject, ''))) > 0
         AND coalesce(actor_role, '') IN ('master', 'admin'))
        OR
        (event_type = 'consumed' AND actor_subject IS NULL AND actor_role IS NULL)
    ),
    CONSTRAINT viewer_invitation_audit_one_event UNIQUE (challenge_id, event_type)
);

CREATE INDEX IF NOT EXISTS viewer_invitation_audit_viewer_idx
    ON oryva.viewer_invitation_audit(viewer_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION oryva.reject_viewer_invitation_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'viewer invitation audit is append-only'
        USING ERRCODE = 'P0001';
END;
$$;

DROP TRIGGER IF EXISTS viewer_invitation_audit_immutable
    ON oryva.viewer_invitation_audit;
CREATE TRIGGER viewer_invitation_audit_immutable
    BEFORE UPDATE OR DELETE ON oryva.viewer_invitation_audit
    FOR EACH ROW EXECUTE FUNCTION oryva.reject_viewer_invitation_audit_mutation();

REVOKE ALL ON oryva.viewer_invitation_audit FROM PUBLIC;

COMMENT ON TABLE oryva.viewer_invitation_audit IS
    'Append-only invitation issue/reissue-revocation and bearer-consumption events. No plaintext tokens, digests, recipient email, passwords or Keycloak credentials. Consumed event proves token possession only, never account verification or activation.';
