-- ORYVA backend v1: encrypted, non-dispatching invitation outbox foundation.
-- Apply after 016_viewer_invitation_subject_binding.sql.
-- A future SMTP worker must be separately threat-reviewed; pending is NOT sent.
CREATE TABLE IF NOT EXISTS oryva.viewer_invitation_outbox (
    challenge_id uuid PRIMARY KEY
        REFERENCES oryva.viewer_invitation_challenges(id) ON DELETE RESTRICT,
    key_id text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    auth_tag bytea NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    cancelled_at timestamptz,
    CONSTRAINT invitation_outbox_key_id_check
        CHECK (key_id ~ '^[a-zA-Z0-9._-]{1,64}$'),
    CONSTRAINT invitation_outbox_nonce_check CHECK (octet_length(nonce) = 12),
    CONSTRAINT invitation_outbox_tag_check CHECK (octet_length(auth_tag) = 16),
    CONSTRAINT invitation_outbox_ciphertext_check CHECK (octet_length(ciphertext) = 43),
    CONSTRAINT invitation_outbox_state_check CHECK (state IN ('pending', 'cancelled')),
    CONSTRAINT invitation_outbox_cancel_check
        CHECK ((state = 'pending' AND cancelled_at IS NULL) OR
               (state = 'cancelled' AND cancelled_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS invitation_outbox_pending_idx
    ON oryva.viewer_invitation_outbox(created_at)
    WHERE state = 'pending';
REVOKE ALL ON oryva.viewer_invitation_outbox FROM PUBLIC;
COMMENT ON TABLE oryva.viewer_invitation_outbox IS
    'AES-256-GCM encrypted invitation token, atomically queued with challenge and audit. No dispatcher or SMTP send is implemented. Decryption requires external key material; no keys stored here.';
