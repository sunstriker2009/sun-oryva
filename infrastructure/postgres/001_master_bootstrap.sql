-- ORYVA application master bootstrap reservation.
-- This table is ORYVA-owned state, separate from Keycloak identity credentials.
-- PostgreSQL enforces one reservation per deployment database.
CREATE SCHEMA IF NOT EXISTS oryva;

CREATE TABLE IF NOT EXISTS oryva.master_bootstrap (
    singleton_id smallint PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    state text NOT NULL CHECK (state IN ('pending', 'active')),
    subject_id text UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    CONSTRAINT master_state_consistency CHECK (
        (state = 'pending' AND subject_id IS NULL AND activated_at IS NULL)
        OR (state = 'active' AND subject_id IS NOT NULL AND activated_at IS NOT NULL)
    )
);

COMMENT ON TABLE oryva.master_bootstrap IS
'At most one application master identity reservation; Keycloak admin is unrelated.';
