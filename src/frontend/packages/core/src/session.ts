import { getOryvaNavigation, parseOryvaPrincipal } from "./capabilities.js";
import type { OryvaPrincipal } from "./capabilities.js";

/**
 * A session *display* snapshot supplied by a trusted application backend.
 * Never deserialize a JWT or infer authentication from this data on the client.
 * The server must validate the actual session on every protected request.
 */
export type OryvaSessionView =
  | { readonly status: "anonymous"; readonly principal: null }
  | { readonly status: "authenticated"; readonly principal: OryvaPrincipal }
  | { readonly status: "expired"; readonly principal: null }
  | { readonly status: "unavailable"; readonly principal: null };

const anonymous: OryvaSessionView = Object.freeze({ status: "anonymous", principal: null });

export function parseOryvaSessionView(value: unknown): OryvaSessionView {
  if (!value || typeof value !== "object" || Array.isArray(value)) return anonymous;
  const candidate = value as Record<string, unknown>;
  switch (candidate.status) {
    case "authenticated": {
      const principal = parseOryvaPrincipal(candidate.principal);
      if (!principal || principal.state !== "active") return anonymous;
      return { status: "authenticated", principal };
    }
    case "expired": return { status: "expired", principal: null };
    case "unavailable": return { status: "unavailable", principal: null };
    default: return anonymous;
  }
}

export type OryvaSessionScreen =
  | "sign-in"
  | "workspace"
  | "session-expired"
  | "service-unavailable";

export function getOryvaSessionScreen(session: OryvaSessionView): OryvaSessionScreen {
  switch (session.status) {
    case "authenticated": return "workspace";
    case "expired": return "session-expired";
    case "unavailable": return "service-unavailable";
    default: return "sign-in";
  }
}

/** UI-only navigation: empty unless an active, server-asserted session is displayed. */
export function getOryvaSessionNavigation(session: OryvaSessionView) {
  return getOryvaNavigation(session.status === "authenticated" ? session.principal : null);
}

/**
 * Rejects external, protocol-relative, encoded, backslash, and control-character
 * destinations. Use only with a same-origin application router.
 */
export function safeOryvaReturnPath(value: unknown, fallback = "/"): string {
  if (typeof value !== "string" || !value.startsWith("/") ||
      value.startsWith("//") || value.includes("\\") ||
      /[\u0000-\u001f\u007f]/.test(value) ||
      /%(?:2f|5c|0[0-9a-f]|1[0-9a-f]|7f)/i.test(value))
    return fallback;
  try {
    const parsed = new URL(value, "https://oryva.invalid");
    if (parsed.origin !== "https://oryva.invalid" || !parsed.pathname.startsWith("/"))
      return fallback;
    return parsed.pathname + parsed.search + parsed.hash;
  } catch {
    return fallback;
  }
}
