# Security Model — initial specification

**Status: planned; no enforcement implemented.**

## Roles
| Operation | Master | Admin | Viewer |
| --- | --- | --- | --- |
| Create/deactivate admins | Yes | No | No |
| Create/deactivate viewers | Yes | Yes | No |
| Change own password | Yes | Yes | Yes |
| Authorized read operations | Yes | Yes | Yes |
| Operational settings | Yes | If explicitly granted | No |
| Audit log access | Yes | If explicitly granted | No |

Exactly one master per isolated ORYVA deployment. Provision idempotently from an injected bootstrap secret; prevent duplicate masters under concurrency. Never overwrite an established password when the bootstrap secret changes. Require master password change on initial sign-in, and plan privileged MFA and recovery before production.

## Trust boundaries
All role and permission checks are server-side. Admin must never grant admin or master privileges. Management API alone may use privileged Keycloak administration credentials. Validate issuer, audience, lifetime and signing keys on every token; apply least privilege and deny by default. Business-specific company/email configuration belongs to consumers and is delegated via explicit permissions.

## Threat controls
Protect against CSRF, XSS, session fixation, account enumeration, credential stuffing and privilege escalation. Use generic sign-in failures, appropriate rate limiting, secure cookie handling and sensitive-action reauthentication. Never log tokens, passwords or bootstrap secrets. Audit actor, action, target, outcome, time and request correlation identifier, with sensitive data redacted.

## Open decisions
Identity realm isolation, role-to-permission source of truth, revocation semantics, browser BFF session design, audit retention, and master recovery must be finalized in ADRs before implementation.
