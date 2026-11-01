-- M4: immutable ownership reservation for an admin provisioning attempt.
-- Apply via controlled migration before enabling the admin preparation endpoint.
CREATE SCHEMA IF NOT EXISTS oryva;
CREATE TABLE IF NOT EXISTS oryva.admin_provisioning (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    email text NOT NULL,
    requested_by_subject text NOT NULL,
    keycloak_subject_id text UNIQUE,
    state text NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved', 'prepared', 'reconciliation_required')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admin_provisioning_username_nonempty CHECK (length(trim(username)) > 0),
    CONSTRAINT admin_provisioning_email_nonempty CHECK (length(trim(email)) > 0),
    CONSTRAINT admin_provisioning_actor_nonempty CHECK (length(trim(requested_by_subject)) > 0),
    CONSTRAINT admin_provisioning_subject_state CHECK (
        state <> 'prepared' OR keycloak_subject_id IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS admin_provisioning_email_ci
    ON oryva.admin_provisioning (lower(email));
COMMENT ON TABLE oryva.admin_provisioning IS
    'Tracks ORYVA-owned disabled admin preparation; no role assignment or activation.';
