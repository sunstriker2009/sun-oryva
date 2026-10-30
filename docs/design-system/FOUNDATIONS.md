# Design Foundations

## Brand application
The ORYVA symbol conveys a protective boundary and central light. Use the [candidate vector artwork in SUN ecosystem](https://github.com/sunstriker2009/sun-ecosystem/tree/main/branding/assets/vector) without stretching, distortion or recoloring outside approved theme variants. Avoid glowing effects on form controls; reserve subtle luminous gold for branding and primary actions.

## Typography
- Preferred UI family: Inter, fallback `system-ui, -apple-system, Segoe UI, sans-serif`.
- Scale: 12/14/16/18/24/32 px. Body 16 px, small helper 14 px, page heading 32 px.
- Weights: regular 400, medium 500, semibold 600, bold 700.
- Body line height 1.5; headings 1.2–1.3.

## Layout and spacing
- Spacing scale: 4, 8, 12, 16, 24, 32, 48, 64 px.
- Input/control minimum height: 44 px; primary button 44 px minimum.
- Border radius: 8 px controls, 12 px cards, 16 px dialogs.
- Authentication panel: max-width 420 px, 24–32 px padding, centered with generous breathing room.
- Administration shell: responsive sidebar (240 px desktop), top bar, content width capped at 1280 px.
- Breakpoints: mobile < 640 px, tablet 640–1023 px, desktop ≥ 1024 px. Never rely on breakpoint alone for accessibility.

## Color semantics
See `tokens/oryva.dark.tokens.json`. Brand colors are distinct from semantic states. **Gold is an action/brand accent, not a universal warning color.** Text and icon contrast must be validated against actual rendered surfaces; the palette is provisional until tested.

## Motion and elevation
- Transition durations: fast 120 ms, normal 200 ms; no essential information conveyed by animation.
- Respect `prefers-reduced-motion`; disable nonessential motion.
- Use borders and subtle shadows to define layers; do not depend solely on shadow.

## Iconography and language
- Stroke-based icons, 20–24 px, accessible labels for icon-only actions.
- Prefer explicit language: “Change password”, “Deactivate viewer”, “Session expired”.
- Avoid ambiguous “Submit” and security theater such as unverified “100% secure” claims.

## Responsive interaction
- Forms single column on mobile; no horizontal scroll at 320 CSS px for ordinary content.
- Touch targets at least 24 × 24 CSS px (prefer 44 × 44), with adequate spacing.
- Password visibility toggle is a button with state announced to assistive technology.
