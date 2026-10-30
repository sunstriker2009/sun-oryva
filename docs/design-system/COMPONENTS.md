# Component Contracts (v1)

All components are **specified**, not implemented. Components accept semantic variants and controlled state; authorization and data validation occur on the server.

| Component | Purpose | Required states and behavior |
|---|---|---|
| `OryvaLogo` | Brand identity | compact/full; dark/light; alt text or decorative |
| `Button` | Actions | primary/secondary/quiet/danger; hover/focus/disabled/loading; no duplicate submit |
| `TextField` | Input | label, hint, required, error, disabled, autocomplete; stable id and describedby |
| `PasswordField` | Credential entry | reveal/hide, caps-lock hint where feasible, password manager compatibility |
| `Checkbox` | Binary preference | label, keyboard toggle, error |
| `Select` | Controlled choice | label, help/error; native semantics preferred |
| `Alert` | Status | info/success/warning/error; appropriate live-region priority |
| `Toast` | Transient feedback | nonblocking, pause/dismiss, not sole source of critical information |
| `Dialog` | Confirmation | accessible name, focus trap/restore, escape behavior, destructive confirmation |
| `DataTable` | User/session lists | headings, sorting, filtering, pagination, empty/loading/error states |
| `StatusBadge` | Lifecycle status | active/inactive/pending/locked; text plus color |
| `Navigation` | App shell | active state, keyboard access, responsive collapse |
| `EmptyState` | No data | explanation and next available action |
| `Skeleton` | Loading | reduced-motion safe; not substitute for accessible progress |

## Form rules
- Show field errors adjacent to the field and provide an error summary on submit.
- Preserve safe inputs on validation failure; clear password fields when appropriate to avoid unintended exposure.
- Use `autocomplete=username`, `current-password`, and `new-password` appropriately.
- Password rules should be communicated before submission; avoid arbitrary composition rules unless required by policy.
- Submit buttons remain responsive to keyboard and assistive technology; use pending state and deduplication instead of inaccessible disabled-only patterns.

## Operational feedback
- No confirmation toast may claim success until the server confirms the action.
- Destructive actions require a clearly named target and consequence.
- Display an opaque correlation/request ID for errors when available, never credentials or tokens.

## Components to defer
Custom date pickers, charts, advanced data grids, drag-and-drop role editors, and bespoke animation libraries are out of v1 scope.
