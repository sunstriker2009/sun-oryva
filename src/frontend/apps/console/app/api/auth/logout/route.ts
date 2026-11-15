import { readOidcRuntimeConfig } from "../../../../lib/oidc-runtime-config.mjs";
import { createOidcSessionStore, readSessionCookie } from "../../../../lib/oidc-session-store.mjs";
import { oidcLogoutResponse } from "../../../../lib/oidc-http-response.mjs";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const unavailable = () => new Response(null, {
  status: 503,
  headers: { "Cache-Control": "no-store", "Pragma": "no-cache" },
});

/**
 * Local logout is POST-only and requires a same-origin browser request.
 * Revoke the opaque session server-side before expiring browser cookies.
 * Do not redirect to an untrusted return URL or accept GET logout.
 */
export async function POST(request: Request) {
  let pool;
  try {
    const config = readOidcRuntimeConfig();
    const origin = request.headers.get("origin");
    // Require the request target itself to be the configured public endpoint.
    // An Origin header alone does not authenticate a forwarded Host or URL.
    const target = new URL(request.url);
    if (target.origin !== config.consoleOrigin ||
        target.pathname !== "/api/auth/logout" ||
        target.search !== "" || target.hash !== "" ||
        origin !== config.consoleOrigin ||
        request.headers.get("sec-fetch-site") === "cross-site")
      return new Response(null, { status: 403, headers: { "Cache-Control": "no-store" } });

    const cookieHeader = request.headers.get("cookie") ?? "";
    let token: string | null = null;
    try { token = readSessionCookie(cookieHeader); }
    catch {
      // Missing/invalid session: still expire browser cookies.
      return oidcLogoutResponse();
    }
    const { Pool } = await import("pg");
    pool = new Pool({ connectionString: config.databaseConnectionString, max: 1,
      connectionTimeoutMillis: 3000, idleTimeoutMillis: 1000 });
    await createOidcSessionStore(pool).revoke({ token });
    return oidcLogoutResponse();
  } catch {
    // A failed database revocation must not be represented as successful logout.
    return unavailable();
  } finally {
    if (pool) await pool.end().catch(() => {});
  }
}
