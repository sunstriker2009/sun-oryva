-- M5: fail-closed viewer revocation; apply after 009_viewer_activation.sql.
-- PostgreSQL deactivation_pending immediately denies previously issued JWTs.
ALTER TABLE oryva.viewer_accounts
    DROP CONSTRAINT IF EXISTS viewer_accounts_state_check;
ALTER TABLE oryva.viewer_accounts
    ADD CONSTRAINT viewer_accounts_state_check
    CHECK (state IN ('reserved', 'prepared', 'role_assignment_pending',
                    'role_assigned', 'activation_pending', 'active',
                    'deactivation_pending', 'deactivated'));
ALTER TABLE oryva.viewer_accounts
    DROP CONSTRAINT IF EXISTS viewer_accounts_subject_required;
ALTER TABLE oryva.viewer_accounts
    ADD CONSTRAINT viewer_accounts_subject_required
    CHECK (state NOT IN ('prepared', 'role_assignment_pending', 'role_assigned',
                        'activation_pending', 'active', 'deactivation_pending',
                        'deactivated') OR keycloak_subject_id IS NOT NULL);
ALTER TABLE oryva.viewer_provisioning_audit
    DROP CONSTRAINT IF EXISTS viewer_provisioning_audit_event_type_check;
ALTER TABLE oryva.viewer_provisioning_audit
    ADD CONSTRAINT viewer_provisioning_audit_event_type_check
    CHECK (event_type IN ('role_assignment_pending', 'role_assigned',
                         'activation_pending', 'active',
                         'deactivation_pending', 'deactivated'));
COMMENT ON TABLE oryva.viewer_accounts IS
    'Viewer lifecycle: database revocation precedes Keycloak disable and logout.';
COMMENT ON TABLE oryva.viewer_provisioning_audit IS
    'Append-only viewer role, activation and deactivation audit; no secrets.';
