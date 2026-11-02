# ORYVA invitation SMTP STARTTLS transport — operator gate

**Scope:** An opt-in, unregistered transport implementation only. No hosted
dispatcher, automatic delivery, external email, public invitation route,
browser ownership proof, password enrollment, Keycloak activation or production
deployment is enabled by this change.

## Transport contract

`SmtpStartTlsInvitationTransport` implements the existing internal
`IViewerInvitationMailTransport` interface. It uses .NET SMTP with
`EnableSsl = true`, requiring the server to advertise STARTTLS and the
runtime to validate its certificate chain and hostname. There is **no**
plaintext fallback, custom certificate-validation callback or implicit TLS
(port 465) support. Use a dedicated submission relay on port 587 (or another
explicitly approved STARTTLS port). The relay must require authenticated
submission. The client supplies an explicit username/password and disables
default machine credentials.

A trusted deployment component must supply the host, port, single sender
mailbox and SMTP credentials from an external secret manager. Do not put
passwords in appsettings, CI output, source files, issue bodies or logs.
Do not allow an HTTP request, viewer or tenant to select SMTP hosts, senders
or credentials. Protect outbound SMTP with network egress policy and verify
that relay DNS and certificate names match the intended operator-controlled
service. Never install global TLS validation bypasses.

The transport rejects display-name and multi-recipient addresses, including
comma-separated destinations, so a malformed viewer record cannot send a
bearer to extra mailboxes. The message is plain text, includes a short-lived
one-time code rather than a clickable bearer URL, and explicitly states that
enrollment is not yet available. All transport failures are redacted without
inner exceptions. Caller cancellation propagates; an internal 10-second
bound prevents routine indefinite network waits. The enclosing transaction-
held handoff retains its independent expiry, subject, viewer state, lease and
recipient checks.

## Validation and limitations

The isolated unit/SMTP protocol tests require that a relay without STARTTLS
and a relay presenting a self-signed untrusted certificate **both fail before
AUTH, MAIL FROM, RCPT TO or DATA**. They also check invalid configuration,
single-recipient enforcement and exception redaction. Existing PostgreSQL/
Mailpit E2E still exercises only the loopback-only test adapter. No real
external relay is contacted by CI.

This does **not** establish successful authenticated delivery through a
production relay, deliverability to the recipient, mailbox ownership or
browser credential enrollment. SMTP acceptance is ambiguous if PostgreSQL
commit fails; the existing fenced retries may duplicate an email, and the
single-use expiring challenge remains authoritative.

## Release checklist (not yet satisfied)

- [ ] Provision approved relay with valid CA-trusted STARTTLS certificate,
      hostname verification, authenticated submission, secret rotation and
      restricted egress; test actual relay acceptance in staging.
- [ ] Define monitored outbox age, expiry, rejection, retry, attempt exhaustion
      and relay errors with redacted diagnostics and incident response.
- [ ] Approve per-identity and IP invitation/recovery quotas and retention.
- [ ] Validate browser email-proof exchange, CSRF/session protections, replay,
      expiry, credential enrollment in disabled Keycloak state and guarded
      activation against real Keycloak; do not enable unverified identities.
- [ ] Complete least-privilege database/Keycloak grants, operator recovery
      runbooks, security review and release gates.

The sole master creates admins; only master/admin manage viewers; viewers
remain read-only. No change to role or account activation semantics is made.
