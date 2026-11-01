-- M4: durable activation intent; apply after 004_admin_role_assignment.sql.
-- The Keycloak write must only occur after the pending state and audit commit.
ALTER TABLE oryva.admin_provisioning
    DROP CONSTRAINT IF EXISTS admin_provisioning_state_check;
ALTER TABLE oryva.admin_provisioning
    ADD CONSTRAINT admin_provisioning_state_check
    CHECK (state IN ('reserved', 'reconciliation_required', 'prepared',
                    'role_assignment_pending', 'role_assigned',
                    'activation_pending', 'active'));
ALTER TABLE oryva.admin_provisioning
    DROP CONSTRAINT IF EXISTS admin_provisioning_subject_state;
ALTER TABLE oryva.admin_provisioning
    ADD CONSTRAINT admin_provisioning_subject_state
    CHECK (state NOT IN ('prepared', 'role_assignment_pending', 'role_assigned',
                        'activation_pending', 'active')
           OR keycloak_subject_id IS NOT NULL);
ALTER TABLE oryva.admin_provisioning_audit
    DROP CONSTRAINT IF EXISTS admin_provisioning_audit_event_type_check;
ALTER TABLE oryva.admin_provisioning_audit
    ADD CONSTRAINT admin_provisioning_audit_event_type_check
    CHECK (event_type IN ('reserved', 'reconciliation_required', 'subject_bound',
                         'prepared', 'role_assignment_pending', 'role_assigned',
                         'activation_pending', 'active'));
COMMENT ON TABLE oryva.admin_provisioning IS
    'ORYVA admin provisioning with durable role assignment and activation reconciliation.';
