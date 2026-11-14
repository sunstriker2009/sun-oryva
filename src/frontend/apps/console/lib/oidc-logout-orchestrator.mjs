import { readSessionCookie } from "./oidc-session-store.mjs";
import { oidcLogoutResponse } from "./oidc-http-response.mjs";

const fail = () => new Error("OIDC logout unavailable");

/**
 * Server-only POST logout boundary. The HTTP route must not expose GET logout.
 * Origin is compared against the deployment's configured canonical origin,
 * never inferred from attacker-controlled Host/X-Forwarded-* headers.
 */
export async function completeOidcLogout({
  method, origin, expectedOrigin, cookieHeader, sessionStore,
}) {
  if (method !== "POST" || typeof origin !== "string" ||
      typeof expectedOrigin !== "string" || !sessionStore ||
      typeof sessionStore.revoke !== "function") throw fail();
  let received, expected;
  try {
    received = new URL(origin);
    expected = new URL(expectedOrigin);
  } catch { throw fail(); }
  if (received.origin !== expected.origin ||
      received.href !== received.origin + "/" ||
      expected.href !== expected.origin + "/" ||
      !["https:", "http:"].includes(expected.protocol) ||
      (expected.protocol === "http:" &&
        !["localhost", "127.0.0.1", "[::1]"].includes(expected.hostname)))
    throw fail();

  // Missing or ambiguous credentials must not trigger a database mutation.
  // An expired/revoked but syntactically valid session still receives clearing
  // cookies; revocation is idempotent.
  let token;
  try { token = readSessionCookie(cookieHeader); } catch { return oidcLogoutResponse(); }
  try {
    await sessionStore.revoke({ token });
  } catch {
    // Never claim logout succeeded if the database could not revoke a live
    // session: the caller must return a generic error and retry.
    throw fail();
  }
  return oidcLogoutResponse();
}
