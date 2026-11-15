import { loadOidcRuntimeConfig } from "../../../lib/oidc-runtime-config.mjs";
import { createOidcTransactionStore } from "../../../lib/oidc-transaction-store.mjs";
import { createOidcPayloadProtector } from "../../../lib/oidc-payload-protector.mjs";
import { createOidcSessionStore } from "../../../lib/oidc-session-store.mjs";
import { completeOidcCallback } from "../../../lib/oidc-callback-orchestrator.mjs";
import { oidcCallbackResponse } from "../../../lib/oidc-http-response.mjs";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * The exact redirect target is pinned by readOidcRuntimeConfig to
 * /auth/callback. Never reflect provider-controlled query values.
 * Always clear the short-lived browser binding, including on failure.
 */
export async function GET(request: Request) {
  let pool;
  try {
    const { config, metadata } = await loadOidcRuntimeConfig();
    const url = new URL(request.url);
    if (url.origin !== config.consoleOrigin || url.pathname !== "/auth/callback")
      return oidcCallbackResponse();
    const { Pool } = await import("pg");
    pool = new Pool({ connectionString: config.databaseConnectionString, max: 1,
      connectionTimeoutMillis: 3000, idleTimeoutMillis: 1000 });
    const result = await completeOidcCallback({
      query: url.searchParams,
      cookieHeader: request.headers.get("cookie") ?? "",
      transactionStore: createOidcTransactionStore(pool, config.bindingHmacKey),
      payloadProtector: createOidcPayloadProtector(config.encryptionKey),
      sessionStore: createOidcSessionStore(pool),
      oidc: {
        issuer: config.issuer,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        tokenEndpoint: metadata.tokenEndpoint,
        jwksUri: metadata.jwksUri,
        allowLoopbackHttp: config.allowLoopbackHttp,
      },
    });
    return oidcCallbackResponse(result.cookie);
  } catch {
    // Do not expose provider errors, tokens, session IDs or exception details.
    return oidcCallbackResponse();
  } finally {
    if (pool) await pool.end().catch(() => {});
  }
}
