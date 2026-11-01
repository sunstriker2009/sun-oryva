-- M5: database-backed viewer authorization foundation.
-- Apply before enabling any viewer endpoint. No public write/activation API exists.
CREATE SCHEMA IF NOT EXISTS oryva;
CREATE TABLE IF NOT EXISTS oryva.viewer_accounts (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    email text NOT NULL,
    requested_by_subject text NOT NULL,
    requested_by_role text NOT NULL
        CHECK (requested_by_role IN ('master', 'admin')),
    keycloak_subject_id text UNIQUE,
    state text NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved', 'prepared', 'active', 'deactivated')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT viewer_accounts_username_nonempty CHECK (length(trim(username)) > 0),
    CONSTRAINT viewer_accounts_email_nonempty CHECK (length(trim(email)) > 0),
    CONSTRAINT viewer_accounts_actor_nonempty CHECK (length(trim(requested_by_subject)) > 0),
    CONSTRAINT viewer_accounts_subject_required CHECK
        (state NOT IN ('prepared', 'active', 'deactivated')
         OR keycloak_subject_id IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS viewer_accounts_email_ci
    ON oryva.viewer_accounts (lower(email));
CREATE INDEX IF NOT EXISTS viewer_accounts_active_subject
    ON oryva.viewer_accounts (keycloak_subject_id)
    WHERE state = 'active';
COMMENT ON TABLE oryva.viewer_accounts IS
    'Viewer authorization registry; a Keycloak viewer role alone grants no access. No provisioning writes are exposed yet.';
