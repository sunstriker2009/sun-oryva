-- ORYVA backend v1: append-only preparation completion audit.
-- Apply after 011_viewer_reservation_audit.sql; safe to reapply.
-- Historical prepared reservations are not backfilled with fabricated actors.
ALTER TABLE oryva.viewer_provisioning_audit
    DROP CONSTRAINT IF EXISTS viewer_provisioning_audit_event_type_check;
ALTER TABLE oryva.viewer_provisioning_audit
    ADD CONSTRAINT viewer_provisioning_audit_event_type_check
    CHECK (event_type IN ('reserved', 'prepared',
                         'role_assignment_pending', 'role_assigned',
                         'activation_pending', 'active',
                         'deactivation_pending', 'deactivated'));

COMMENT ON TABLE oryva.viewer_provisioning_audit IS
    'Append-only viewer reservation, verified preparation, role, activation and revocation history. Reservation and preparation state transitions are atomic with actor-attributed audit; no credentials or tokens.';
