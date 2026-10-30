# ORYVA Design System v1.0 — Foundation

**Status:** PROPOSED · **Scope:** authentication and administration UX · **Product:** ORYVA by Sun

ORYVA's design system is a reusable visual and interaction foundation for identity, access and security interfaces. The ORYVA repository is the **product design and implementation source of truth**; SUN ecosystem retains high-level brand governance. App-specific React components belong in the ORYVA frontend package (`@sun-security/ui` proposed; naming subject to implementation review).

## Principles
1. **Trust first:** recognizable identity, no misleading states or decorative security claims.
2. **Calm clarity:** clear labels, restrained motion, readable hierarchy.
3. **Accessible by default:** keyboard operation, focus visibility, contrast, screen-reader announcements.
4. **Secure by design:** no secrets in URLs, analytics, browser storage, logs, or untrusted UI messages.
5. **Themeable:** semantic tokens, not hard-coded component colors; dark default with light and high-contrast support planned.
6. **Composability:** frontend components must be identity-provider agnostic and compatible with server-enforced authorization.

## Contents
- [Design foundations](FOUNDATIONS.md)
- [Component contracts](COMPONENTS.md)
- [Authentication and administration flows](FLOWS.md)
- [Accessibility and security acceptance criteria](QUALITY-GATES.md)
- [Design tokens JSON](tokens/oryva.dark.tokens.json)
- [CSS custom properties](tokens/oryva.dark.css)

## Status and boundaries
The SUN and ORYVA vector marks remain **logo candidates**; do not imply that the artwork is legally cleared or formally approved. This package is a design specification, **not implemented screens** or a working auth system. Authorization decisions must always be enforced on the backend.

## Planned packages
- `@sun-security/tokens`: generated theme assets, semantic colors, spacing and typography.
- `@sun-security/ui`: framework components and forms.
- `Sun.Security.*`: server-side contracts and implementation, independently versioned.

## Initial roles
- **Master:** sole seeded account; can create/deactivate admins and viewers and access all administrative functions.
- **Admin:** can manage viewers and operational settings, but cannot create or elevate admins.
- **Viewer:** read-only access to explicitly authorized resources.

Roles are **server policy**, not a CSS or frontend visibility feature. The sole-master invariant, bootstrapping secret and change-password rules must be enforced server-side.
