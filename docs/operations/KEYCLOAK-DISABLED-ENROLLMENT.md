# Keycloak disabled-account enrollment: negative security gate

**Status:** isolated CI regression coverage only. This does **not** authorize ORYVA invitation issuance or prove an end-to-end enrollment ceremony.

## Invariants exercised

Before the CI test setup relaxes email verification for its separate JWT direct-grant fixtures, `tests/integration/keycloak_disabled_enrollment_e2e.py` asserts that the imported ORYVA realm has self-registration disabled, password reset disabled and email verification required.

The test creates a dedicated direct-grant client and two randomly named **disabled** throwaway identities in isolated Keycloak 26.3.5:

- An unverified identity with `VERIFY_EMAIL` and `UPDATE_PASSWORD` required actions.
- An email-verified identity with no required actions, to isolate the disabled-account gate from the email and action gates.

Each receives a random, CI-only password via the Keycloak admin API solely to demonstrate that a credential does **not** make a disabled identity usable. A token request must be rejected as `invalid_grant`, must not contain an access token, and must not create an active session. The test re-reads the disabled flag, verification flag and required actions. Identities and the client are deleted in a `finally` block; no mail is sent, no user is enabled and no production system is contacted.

## Still unverified: do not implement invitations based on this test alone

The negative gate does **not** establish that Keycloak `execute-actions-email` works for disabled identities, that a delivered link can complete `VERIFY_EMAIL` or `UPDATE_PASSWORD` while disabled, or that links are single-use, expiring and safe against replay. It also does not test SMTP delivery, action-token URL origin, email enumeration, credential self-service, session invalidation or multi-replica invitation throttling.

**Next isolated test:** configure a local mail sink and staging-equivalent hostname; attempt `execute-actions-email` for an ORYVA-owned disabled candidate, capture the message without sending external email, follow the link in a browser-compatible client, and verify that account activation cannot precede verified enrollment. If Keycloak requires enablement to finish actions, design a separate fail-closed enrollment state that never grants API access before email, credential and database checks are complete. Do not silently enable an unverified identity.

The production invitation endpoint remains blocked pending this behavioral evidence and a threat review. See [the master checklist](../../MASTER-CHECKLIST.md) and [ownership-profile runbook](KEYCLOAK-USER-PROFILE.md).
