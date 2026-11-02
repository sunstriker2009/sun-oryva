-- ORYVA backend v1: bind invitation possession to the exact Keycloak identity
-- that was prepared at issuance. Apply after 015_viewer_invitation_audit.sql.
-- A missing or changed subject fails closed; never infer an identity from email.
ALTER TABLE oryva.viewer_invitation_challenges
    ADD COLUMN IF NOT EXISTS keycloak_subject_snapshot text;

-- Never silently rebind a previously issued, still-live bearer challenge to
-- the current subject: the original identity cannot be reconstructed.
-- Operators must explicitly revoke/reconcile such challenges, with an
-- attributable audit event, before running this migration.
DO $legacy_guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM oryva.viewer_invitation_challenges
        WHERE keycloak_subject_snapshot IS NULL
          AND consumed_at IS NULL AND revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'unresolved legacy invitation challenges must be revoked and audited before subject binding migration';
    END IF;
END $legacy_guard$;

-- Backfill existing terminal challenges only when their viewer is still bound.
-- An unbound legacy challenge causes NOT NULL to fail rather than migrating
-- it into an apparently valid invitation for a different identity.
UPDATE oryva.viewer_invitation_challenges AS challenge
SET keycloak_subject_snapshot = viewer.keycloak_subject_id
FROM oryva.viewer_accounts AS viewer
WHERE challenge.viewer_id = viewer.id
  AND challenge.keycloak_subject_snapshot IS NULL
  AND viewer.keycloak_subject_id IS NOT NULL;

ALTER TABLE oryva.viewer_invitation_challenges
    ALTER COLUMN keycloak_subject_snapshot SET NOT NULL;

DO $subject_guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'oryva.viewer_invitation_challenges'::regclass
          AND conname = 'viewer_invitation_subject_snapshot_check'
    ) THEN
        ALTER TABLE oryva.viewer_invitation_challenges
            ADD CONSTRAINT viewer_invitation_subject_snapshot_check
            CHECK (length(btrim(keycloak_subject_snapshot)) > 0);
    END IF;
END $subject_guard$;

COMMENT ON COLUMN oryva.viewer_invitation_challenges.keycloak_subject_snapshot IS
    'Keycloak subject bound at challenge issuance; redemption fails if viewer subject changes. Not a credential or proof of email ownership.';
