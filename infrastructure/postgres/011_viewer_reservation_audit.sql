-- ORYVA backend v1: audit the original viewer reservation atomically with
-- its PostgreSQL identity row, before any external Keycloak operation.
-- Apply after 010_viewer_deactivation.sql. Existing historical reservations
-- are not retroactively attributed to an actor.
ALTER TABLE oryva.viewer_provisioning_audit
    DROP CONSTRAINT IF EXISTS viewer_provisioning_audit_event_type_check;
ALTER TABLE oryva.viewer_provisioning_audit
    ADD CONSTRAINT viewer_provisioning_audit_event_type_check
    CHECK (event_type IN ('reserved', 'role_assignment_pending', 'role_assigned',
                         'activation_pending', 'active',
                         'deactivation_pending', 'deactivated'));

COMMENT ON TABLE oryva.viewer_provisioning_audit IS
    'Append-only viewer reservation, role, activation and revocation events. New reservations and their audit entries are inserted atomically; no passwords or tokens.';
