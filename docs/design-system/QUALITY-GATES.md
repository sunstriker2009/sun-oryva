# Quality Gates and Acceptance Criteria

## Accessibility
- Target WCAG 2.2 AA. Normal text ≥ 4.5:1, large text ≥ 3:1, essential UI indicators ≥ 3:1 against adjacent colors.
- Keyboard-only flows for all tasks, visible focus, logical tab order, focus restoration after dialogs.
- Programmatic labels, error descriptions and status announcements; do not communicate state by color alone.
- Responsive at 320 CSS px and 200% zoom; reduced-motion preferences respected.
- Test screen readers (NVDA/VoiceOver), automated accessibility checks, and manual keyboard navigation.

## Security
- Authorization is enforced by the API and identity provider; frontend role gating is UX only.
- Protect against CSRF/XSS/session fixation as appropriate to the chosen architecture.
- Do not expose passwords, access tokens, recovery tokens or bootstrap secrets in logs, analytics, URLs, or error telemetry.
- Rate limit credential flows; generic invalid-credentials messaging to avoid enumeration.
- Enforce sole-master invariant in durable backend logic.
- Reauthenticate for sensitive changes; define session invalidation behavior.
- Audit administrative changes and credential-management outcomes without sensitive values.

## Functional
- Every form has idle, pending, success, error and offline/unavailable behavior.
- Loading and destructive states are understandable without color or animation.
- All actions have a server-confirmed outcome; duplicate requests are handled safely.
- Component tokens can be swapped without editing component-specific color literals.
- No undocumented dependencies on MarketPilot AI; ORYVA stays standalone and reusable.

## Definition of done
A component is not “production ready” until it has tests for keyboard operation, state handling, error paths, contrast and integration with backend permissions. A design mockup alone does not satisfy this gate.
