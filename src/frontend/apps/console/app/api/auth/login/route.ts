import { loadOidcRuntimeConfig } from "../../../../lib/oidc-runtime-config.mjs";
import { createOidcTransactionStore } from "../../../../lib/oidc-transaction-store.mjs";
import { createOidcPayloadProtector } from "../../../../lib/oidc-payload-protector.mjs";
import { initiateOidcLogin } from "../../../../lib/oidc-login-initiation.mjs";
import { oidcAuthorizationResponse } from "../../../../lib/oidc-http-response.mjs";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const unavailable = () => new Response(null, {
  status: 503,
  headers: { "Cache-Control": "no-store", "Pragma": "no-cache" },
});

/** Server-owned authorization initiation; no user-controlled redirect targets. */
export async function GET() {
  let pool;
  try {
    const { config, metadata } = await loadOidcRuntimeConfig();
    const { Pool } = await import("pg");
    pool = new Pool({ connectionString: config.databaseConnectionString, max: 1,
      connectionTimeoutMillis: 3000, idleTimeoutMillis: 1000 });
    const transactionStore = createOidcTransactionStore(pool, config.bindingHmacKey);
    const payloadProtector = createOidcPayloadProtector(config.encryptionKey);
    const { authorizationUrl, cookie } = await initiateOidcLogin({
      config, metadata, transactionStore, payloadProtector,
    });
    return oidcAuthorizationResponse(authorizationUrl, cookie, metadata.authorizationEndpoint);
  } catch {
    return unavailable();
  } finally {
    if (pool) await pool.end().catch(() => {});
  }
}
