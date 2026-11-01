-- M5: durable viewer activation intent and actor-attributed audit.
-- Apply after 008_viewer_role_assignment.sql. A viewer is authorized only
-- after Keycloak enablement has been independently verified and 'active' committed.
ALTER TABLE oryva.viewer_accounts
    DROP CONSTRAINT IF EXISTS viewer_accounts_state_check;
ALTER TABLE oryva.viewer_accounts
    ADD CONSTRAINT viewer_accounts_state_check
    CHECK (state IN ('reserved', 'prepared', 'role_assignment_pending',
                    'role_assigned', 'activation_pending', 'active', 'deactivated'));
ALTER TABLE oryva.viewer_accounts
    DROP CONSTRAINT IF EXISTS viewer_accounts_subject_required;
ALTER TABLE oryva.viewer_accounts
    ADD CONSTRAINT viewer_accounts_subject_required
    CHECK (state NOT IN ('prepared', 'role_assignment_pending', 'role_assigned',
                        'activation_pending', 'active', 'deactivated')
           OR keycloak_subject_id IS NOT NULL);

ALTER TABLE oryva.viewer_provisioning_audit
    DROP CONSTRAINT IF EXISTS viewer_provisioning_audit_event_type_check;
ALTER TABLE oryva.viewer_provisioning_audit
    ADD CONSTRAINT viewer_provisioning_audit_event_type_check
    CHECK (event_type IN ('role_assignment_pending', 'role_assigned',
                         'activation_pending', 'active'));

COMMENT ON TABLE oryva.viewer_accounts IS
    'Viewer provisioning: activation_pending denies access until Keycloak verification and committed active state.';
COMMENT ON TABLE oryva.viewer_provisioning_audit IS
    'Append-only actor-attributed viewer role and activation history; no credentials or tokens.';
