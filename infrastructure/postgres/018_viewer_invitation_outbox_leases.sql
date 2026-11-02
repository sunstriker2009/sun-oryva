-- ORYVA backend v1: non-dispatching, fenced PostgreSQL outbox claims.
-- Apply after 017, BEFORE deploying the matching application code.
-- No SMTP, link generation, account activation or Keycloak credential writes.
ALTER TABLE oryva.viewer_invitation_outbox
    ADD COLUMN IF NOT EXISTS lease_id uuid,
    ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0;

ALTER TABLE oryva.viewer_invitation_outbox
    DROP CONSTRAINT IF EXISTS invitation_outbox_state_check,
    DROP CONSTRAINT IF EXISTS invitation_outbox_cancel_check,
    DROP CONSTRAINT IF EXISTS invitation_outbox_lease_check,
    DROP CONSTRAINT IF EXISTS invitation_outbox_attempt_check;

ALTER TABLE oryva.viewer_invitation_outbox
    ADD CONSTRAINT invitation_outbox_state_check
        CHECK (state IN ('pending', 'leased', 'cancelled')),
    ADD CONSTRAINT invitation_outbox_lease_check CHECK (
        (state = 'pending' AND lease_id IS NULL AND lease_expires_at IS NULL
            AND cancelled_at IS NULL) OR
        (state = 'leased' AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL
            AND cancelled_at IS NULL) OR
        (state = 'cancelled' AND lease_id IS NULL AND lease_expires_at IS NULL
            AND cancelled_at IS NOT NULL)
    ),
    ADD CONSTRAINT invitation_outbox_attempt_check
        CHECK (attempt_count BETWEEN 0 AND 5);

CREATE INDEX IF NOT EXISTS invitation_outbox_claim_idx
    ON oryva.viewer_invitation_outbox(next_attempt_at, created_at)
    WHERE state IN ('pending', 'leased');
REVOKE ALL ON oryva.viewer_invitation_outbox FROM PUBLIC;
COMMENT ON TABLE oryva.viewer_invitation_outbox IS
    'Encrypted invitation delivery foundation with fenced, expiring worker claims; no SMTP sender, email proof, credential enrollment or activation.';
