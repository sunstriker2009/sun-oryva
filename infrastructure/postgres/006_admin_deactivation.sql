-- M4: fail-closed, database-first admin revocation.
-- Apply after 005_admin_activation.sql, before exposing deactivation API.
ALTER TABLE oryva.admin_provisioning
    DROP CONSTRAINT IF EXISTS admin_provisioning_state_check;
ALTER TABLE oryva.admin_provisioning
    ADD CONSTRAINT admin_provisioning_state_check
    CHECK (state IN ('reserved', 'reconciliation_required', 'prepared',
                    'role_assignment_pending', 'role_assigned',
                    'activation_pending', 'active',
                    'deactivation_pending', 'deactivated'));
ALTER TABLE oryva.admin_provisioning
    DROP CONSTRAINT IF EXISTS admin_provisioning_subject_state;
ALTER TABLE oryva.admin_provisioning
    ADD CONSTRAINT admin_provisioning_subject_state
    CHECK (state NOT IN ('prepared', 'role_assignment_pending', 'role_assigned',
                        'activation_pending', 'active',
                        'deactivation_pending', 'deactivated')
           OR keycloak_subject_id IS NOT NULL);
ALTER TABLE oryva.admin_provisioning_audit
    DROP CONSTRAINT IF EXISTS admin_provisioning_audit_event_type_check;
ALTER TABLE oryva.admin_provisioning_audit
    ADD CONSTRAINT admin_provisioning_audit_event_type_check
    CHECK (event_type IN ('reserved', 'reconciliation_required', 'subject_bound',
                         'prepared', 'role_assignment_pending', 'role_assigned',
                         'activation_pending', 'active',
                         'deactivation_pending', 'deactivated'));
COMMENT ON TABLE oryva.admin_provisioning IS
    'ORYVA admin lifecycle: database revocation precedes Keycloak disable/logout.';
