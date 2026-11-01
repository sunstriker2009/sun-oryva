-- M5: durable viewer realm-role assignment. No activation, credentials or enablement.
-- Apply after 007_viewer_authorization.sql before exposing assignment routes.
ALTER TABLE oryva.viewer_accounts
    DROP CONSTRAINT IF EXISTS viewer_accounts_state_check;
ALTER TABLE oryva.viewer_accounts
    ADD CONSTRAINT viewer_accounts_state_check
    CHECK (state IN ('reserved', 'prepared', 'role_assignment_pending',
                    'role_assigned', 'active', 'deactivated'));
ALTER TABLE oryva.viewer_accounts
    DROP CONSTRAINT IF EXISTS viewer_accounts_subject_required;
ALTER TABLE oryva.viewer_accounts
    ADD CONSTRAINT viewer_accounts_subject_required
    CHECK (state NOT IN ('prepared', 'role_assignment_pending', 'role_assigned',
                        'active', 'deactivated')
           OR keycloak_subject_id IS NOT NULL);

CREATE TABLE IF NOT EXISTS oryva.viewer_provisioning_audit (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provisioning_id uuid NOT NULL REFERENCES oryva.viewer_accounts(id) ON DELETE RESTRICT,
    event_type text NOT NULL CHECK (event_type IN ('role_assignment_pending', 'role_assigned')),
    actor_subject text NOT NULL CHECK (length(trim(actor_subject)) > 0),
    actor_role text NOT NULL CHECK (actor_role IN ('master', 'admin')),
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS viewer_provisioning_audit_by_reservation
    ON oryva.viewer_provisioning_audit (provisioning_id, event_id);

CREATE OR REPLACE FUNCTION oryva.reject_viewer_provisioning_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ORYVA viewer provisioning audit records are append-only';
END;
$$;
DROP TRIGGER IF EXISTS viewer_provisioning_audit_append_only ON oryva.viewer_provisioning_audit;
CREATE TRIGGER viewer_provisioning_audit_append_only
    BEFORE UPDATE OR DELETE ON oryva.viewer_provisioning_audit
    FOR EACH ROW EXECUTE FUNCTION oryva.reject_viewer_provisioning_audit_mutation();
DROP TRIGGER IF EXISTS viewer_provisioning_audit_no_truncate ON oryva.viewer_provisioning_audit;
CREATE TRIGGER viewer_provisioning_audit_no_truncate
    BEFORE TRUNCATE ON oryva.viewer_provisioning_audit
    FOR EACH STATEMENT EXECUTE FUNCTION oryva.reject_viewer_provisioning_audit_mutation();

COMMENT ON TABLE oryva.viewer_provisioning_audit IS
    'Append-only transactional viewer role-assignment history; no credentials or tokens.';
COMMENT ON TABLE oryva.viewer_accounts IS
    'Viewer identity registry; role_assigned remains disabled and cannot authorize viewer APIs.';
