-- ORYVA backend v1: SMTP acceptance ledger and terminal outbox state.
-- Apply after migration 018. "sent" means accepted by an SMTP relay, NOT inbox delivery.
ALTER TABLE oryva.viewer_invitation_outbox
    ADD COLUMN IF NOT EXISTS smtp_accepted_at timestamptz;

ALTER TABLE oryva.viewer_invitation_outbox
    DROP CONSTRAINT IF EXISTS invitation_outbox_state_check,
    DROP CONSTRAINT IF EXISTS invitation_outbox_lease_check;

ALTER TABLE oryva.viewer_invitation_outbox
    ADD CONSTRAINT invitation_outbox_state_check
        CHECK (state IN ('pending', 'leased', 'cancelled', 'sent')),
    ADD CONSTRAINT invitation_outbox_lease_check CHECK (
        (state = 'pending' AND lease_id IS NULL AND lease_expires_at IS NULL
            AND cancelled_at IS NULL AND smtp_accepted_at IS NULL) OR
        (state = 'leased' AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL
            AND cancelled_at IS NULL AND smtp_accepted_at IS NULL) OR
        (state = 'cancelled' AND lease_id IS NULL AND lease_expires_at IS NULL
            AND cancelled_at IS NOT NULL AND smtp_accepted_at IS NULL) OR
        (state = 'sent' AND lease_id IS NULL AND lease_expires_at IS NULL
            AND cancelled_at IS NULL AND smtp_accepted_at IS NOT NULL)
    );

-- No recipient address, bearer, digest, ciphertext, or SMTP transcript in audit.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_delivery_audit (
    id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type = 'smtp_accepted'),
    attempt_count integer NOT NULL CHECK (attempt_count BETWEEN 1 AND 5),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (challenge_id, event_type)
);
CREATE OR REPLACE FUNCTION oryva.reject_invitation_delivery_audit_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Invitation delivery audit is append-only';
END;
$$;
DO $audit_trigger$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'oryva.viewer_invitation_delivery_audit'::regclass
          AND tgname = 'invitation_delivery_audit_immutable'
    ) THEN
        CREATE TRIGGER invitation_delivery_audit_immutable
            BEFORE UPDATE OR DELETE ON oryva.viewer_invitation_delivery_audit
            FOR EACH ROW EXECUTE FUNCTION oryva.reject_invitation_delivery_audit_mutation();
    END IF;
END $audit_trigger$;
REVOKE ALL ON oryva.viewer_invitation_delivery_audit FROM PUBLIC;
REVOKE ALL ON oryva.viewer_invitation_outbox FROM PUBLIC;
COMMENT ON TABLE oryva.viewer_invitation_delivery_audit IS
    'Append-only SMTP relay acceptance evidence; not proof of recipient inbox delivery.';
