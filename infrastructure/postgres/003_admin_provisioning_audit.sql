-- M4: append-only, database-committed audit of admin provisioning transitions.
-- Apply after 002_admin_provisioning.sql and before enabling management endpoints.
-- Contains no credentials, access tokens, or raw HTTP payloads.
CREATE TABLE IF NOT EXISTS oryva.admin_provisioning_audit (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provisioning_id uuid NOT NULL REFERENCES oryva.admin_provisioning(id) ON DELETE RESTRICT,
    event_type text NOT NULL CHECK (event_type IN
        ('reserved', 'reconciliation_required', 'subject_bound', 'prepared')),
    actor_subject text NOT NULL CHECK (length(trim(actor_subject)) > 0),
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_provisioning_audit_by_reservation
    ON oryva.admin_provisioning_audit (provisioning_id, event_id);

CREATE OR REPLACE FUNCTION oryva.reject_admin_provisioning_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ORYVA provisioning audit records are append-only';
END;
$$;

DROP TRIGGER IF EXISTS admin_provisioning_audit_append_only
    ON oryva.admin_provisioning_audit;
CREATE TRIGGER admin_provisioning_audit_append_only
    BEFORE UPDATE OR DELETE ON oryva.admin_provisioning_audit
    FOR EACH ROW EXECUTE FUNCTION oryva.reject_admin_provisioning_audit_mutation();

DROP TRIGGER IF EXISTS admin_provisioning_audit_no_truncate
    ON oryva.admin_provisioning_audit;
CREATE TRIGGER admin_provisioning_audit_no_truncate
    BEFORE TRUNCATE ON oryva.admin_provisioning_audit
    FOR EACH STATEMENT EXECUTE FUNCTION oryva.reject_admin_provisioning_audit_mutation();

COMMENT ON TABLE oryva.admin_provisioning_audit IS
    'Append-only, transactionally committed ORYVA admin provisioning transitions; never store secrets.';
