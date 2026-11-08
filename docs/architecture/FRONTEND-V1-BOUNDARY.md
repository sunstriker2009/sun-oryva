# ORYVA frontend v1 — initial boundary

## Backend freeze

The current backend is a **provisional implementation baseline**, not production
security sign-off. Keep independent email ownership proof, credential enrollment,
password recovery, external SMTP dispatch and unverified-account activation
disabled until their security gates and end-to-end tests are completed.

## Frontend core

`@sun-security/core` provides strict presentation-only role/state contracts,
default-deny capability checks and deterministic navigation. Only active
masters see admin creation/security settings; active admins see viewer
management, not admin controls; viewers see a read-only workspace. Pending,
disabled, unknown and malformed principals receive no privileged navigation.

These flags are **not authorization**. The ASP.NET Core API and Keycloak
must enforce roles, validated token subjects and database account state.
A client-provided `state: "active"` is not proof of authentication.

## Next milestones

1. OIDC Authorization Code + PKCE with vetted SDK and secure server session;
   never persist access/refresh tokens in localStorage.
2. Accessible React/Next.js shell, login/logout, loading/403/503/session-expired
   states and role-aware navigation.
3. Server-authorized user list and safe master/admin operations, audit and
   operations views. Hide unsupported recovery/enrollment actions.
4. Browser integration, accessibility and security E2E before release.

## Validation

The core package has strict TypeScript typecheck and Node unit tests. This
increment implements no login, backend authorization, credential lifecycle,
or public account activation.
