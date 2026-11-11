import { redirect } from "next/navigation";
import { canAccessResource, resolveServerAuthorization } from "./auth-boundary";
import type { ProtectedResource } from "./auth-boundary";

/** Server component guard. Never authorize a resource from client-side role UI. */
export async function requireServerResource(resource: ProtectedResource): Promise<void> {
  const authorization = await resolveServerAuthorization();
  if (authorization.kind === "unavailable") redirect("/status");
  if (authorization.kind !== "authorized") redirect("/");
  if (!canAccessResource(authorization, resource)) redirect("/access-denied");
}
