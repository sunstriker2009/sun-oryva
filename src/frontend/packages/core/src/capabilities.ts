/**
 * ORYVA client presentation capabilities.
 *
 * These flags control navigation and UI affordances only. Never use them to
 * authorize API calls. The backend must independently validate JWT subject,
 * role, database account state and every privileged operation.
 */
export type OryvaRole = "master" | "admin" | "viewer";
export type OryvaAccountState = "active" | "disabled" | "pending" | "unknown";
export type OryvaCapability =
  | "viewWorkspace"
  | "viewUsers"
  | "createAdmin"
  | "createViewer"
  | "deactivateAdmin"
  | "deactivateViewer"
  | "viewAudit"
  | "viewOperations"
  | "manageSecuritySettings";

export interface OryvaPrincipal {
  readonly subject: string;
  readonly role: OryvaRole;
  readonly state: OryvaAccountState;
}

/**
 * Treats untrusted or incomplete identity data as anonymous. In particular,
 * role claims do not prove account activation or server-side authorization.
 */
export function parseOryvaPrincipal(value: unknown): OryvaPrincipal | null {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return null;
  const candidate = value as Record<string, unknown>;
  if (typeof candidate.subject !== "string" ||
      candidate.subject.trim().length === 0 ||
      candidate.subject.length > 256 ||
      !["master", "admin", "viewer"].includes(String(candidate.role)) ||
      !["active", "disabled", "pending", "unknown"].includes(String(candidate.state)))
    return null;
  return {
    subject: candidate.subject,
    role: candidate.role as OryvaRole,
    state: candidate.state as OryvaAccountState,
  };
}

const roleCapabilities: Readonly<Record<OryvaRole, readonly OryvaCapability[]>> = {
  master: [
    "viewWorkspace", "viewUsers", "createAdmin", "createViewer",
    "deactivateAdmin", "deactivateViewer", "viewAudit",
    "viewOperations", "manageSecuritySettings",
  ],
  admin: [
    "viewWorkspace", "viewUsers", "createViewer",
    "deactivateViewer", "viewAudit", "viewOperations",
  ],
  viewer: ["viewWorkspace"],
};

/** Denies every capability unless a validated, active principal is supplied. */
export function hasOryvaCapability(
  principal: OryvaPrincipal | null | undefined,
  capability: OryvaCapability,
): boolean {
  if (!principal || principal.state !== "active" ||
      typeof principal.subject !== "string" ||
      principal.subject.trim().length === 0)
    return false;
  if (!Object.prototype.hasOwnProperty.call(roleCapabilities, principal.role))
    return false;
  return roleCapabilities[principal.role].includes(capability);
}

/** Deterministic, side-effect-free navigation model; not a route guard. */
export function getOryvaNavigation(principal: OryvaPrincipal | null | undefined) {
  const entries = [
    { id: "workspace", label: "Overview", capability: "viewWorkspace" },
    { id: "users", label: "Users", capability: "viewUsers" },
    { id: "audit", label: "Audit logs", capability: "viewAudit" },
    { id: "operations", label: "Operations", capability: "viewOperations" },
    { id: "security", label: "Security settings", capability: "manageSecuritySettings" },
  ] as const;
  return entries.filter(entry => hasOryvaCapability(principal, entry.capability));
}
