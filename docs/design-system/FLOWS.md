# Authentication and Administration Flows

## 1. Sign in
**Fields:** username/email, password. **Actions:** Sign in; show/hide password. Optional “Forgot password” only when recovery is actually configured.

**States:** idle → submitting → authenticated / invalid credentials / account disabled / rate limited / service unavailable. Avoid account enumeration: generic credential error for unknown account or incorrect password. Handle expiration and redirect only to allowlisted destinations.

## 2. Change password
Authenticated users can change their own password. **Fields:** current password, new password, confirm new password. Provide clear password requirements, mismatch feedback and success confirmation. Require recent authentication as policy dictates; revoke or rotate sessions as appropriate. Never log or retain plaintext passwords.

## 3. Master bootstrap
One **master** account is seeded at initialization with a password supplied through a secret environment configuration or secret manager. The setup flow must never display or return the seed secret. Force a password change on first sign-in where feasible. Prevent creating a second master, including concurrent requests. Rotating the bootstrap secret must not silently reset an established password.

## 4. User administration
Master can create/deactivate admins and viewers; admin can create/deactivate viewers only. User list shows name, role, state, last activity when permitted. Create user form validates role against server-issued capabilities. Confirmation for deactivation names the target. Never allow an admin to promote a viewer to admin, or to edit master status.

## 5. Administration workspace
Master/admin views include operational health, audit log explorer, email configuration and company setup as enabled by product integration. Viewer sees only permitted read-only resources. Audit events show actor, action, target, timestamp and outcome; redact sensitive fields.

## 6. Session and errors
Show a distinct session-expired screen with a safe re-authentication path. Provide 403 access-denied (not a fake 404 unless product policy requires resource concealment), 404 not found, and 503 service unavailable. Do not expose internal stack traces or authorization rules in client error details.

## Navigation sketch
```text
ORYVA
 ├─ Sign in
 ├─ My account
 │   └─ Change password
 └─ Workspace (authorized)
     ├─ Overview
     ├─ Users (master/admin with constrained actions)
     ├─ Audit logs (master/admin)
     ├─ Company settings (master/admin where granted)
     └─ Security settings (master; scope to be defined)
```

**Integration:** The identity provider may be Keycloak or another provider; the UI must not assume frontend-only enforcement. Token storage and cookie/session design require a separate security ADR before implementation.
