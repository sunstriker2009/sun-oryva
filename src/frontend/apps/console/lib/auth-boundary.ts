/**
 * ORYVA console server authorization boundary.
 *
 * Deliberately fail-closed until a vetted OIDC authorization-code + PKCE
 * integration can establish a server-validated principal and session.
 * Do not accept a browser-supplied role, cookie JSON, or decoded JWT as proof.
 */
export type ServerAuthorization =
  | { readonly kind: "unauthenticated" }
  | { readonly kind: "unavailable" }
  | { readonly kind: "authorized"; readonly subject: string; readonly role: "master" | "admin" | "viewer" };

export type ProtectedResource = "workspace" | "users" | "audit" | "security";

export function canAccessResource(
  authorization: ServerAuthorization,
  resource: ProtectedResource,
): boolean {
  if (authorization.kind !== "authorized" || authorization.subject.trim() === "")
    return false;
  switch (resource) {
    case "workspace": return true;
    case "users":
    case "audit": return authorization.role === "master" || authorization.role === "admin";
    case "security": return authorization.role === "master";
  }
}

/**
 * A concrete trusted session resolver must replace this before enabling
 * authentication. Returning unavailable prevents accidental exposure.
 */
export async function resolveServerAuthorization(): Promise<ServerAuthorization> {
  return { kind: "unavailable" };
}
