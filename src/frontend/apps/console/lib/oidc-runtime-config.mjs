import { discoverOidcMetadata } from "./oidc-discovery.mjs";

const fail = () => new Error("OIDC runtime configuration unavailable");
const httpsUrl = (value, loopback = false) => {
  if (typeof value !== "string" || value.trim() !== value ||
      /[\\\u0000-\u001f\u007f]/.test(value)) throw fail();
  let url;
  try { url = new URL(value); } catch { throw fail(); }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(loopback && local && url.protocol === "http:")) ||
      url.username || url.password || url.hash || url.search || !url.hostname) throw fail();
  return url;
};
const key = value => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw fail();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw fail();
  return bytes;
};

/**
 * Only server-owned environment variables are accepted. Do not expose this
 * configuration to NEXT_PUBLIC_* or serialize secret keys to client code.
 */
export function readOidcRuntimeConfig(env = process.env) {
  if (!env || env.ORYVA_OIDC_ENABLED !== "true") throw fail();
  const allowLoopbackHttp = env.NODE_ENV !== "production" &&
    env.ORYVA_OIDC_ALLOW_LOOPBACK_HTTP === "true";
  const issuer = httpsUrl(env.ORYVA_OIDC_ISSUER, allowLoopbackHttp);
  const redirect = httpsUrl(env.ORYVA_OIDC_REDIRECT_URI, allowLoopbackHttp);
  const origin = httpsUrl(env.ORYVA_CONSOLE_ORIGIN, allowLoopbackHttp);
  if (origin.pathname !== "/" || redirect.origin !== origin.origin ||
      redirect.pathname !== "/auth/callback" || redirect.search ||
      issuer.pathname.endsWith("/") || issuer.href.endsWith("/")) throw fail();
  const clientId = env.ORYVA_OIDC_CLIENT_ID;
  if (typeof clientId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(clientId))
    throw fail();
  const databaseConnectionString = env.ORYVA_OIDC_DATABASE_URL;
  let database;
  try { database = new URL(databaseConnectionString); } catch { throw fail(); }
  if (!["postgres:", "postgresql:"].includes(database.protocol) ||
      !database.hostname || !database.pathname || database.pathname === "/" ||
      database.hash || database.searchParams.has("sslmode") &&
        !["verify-full"].includes(database.searchParams.get("sslmode"))) throw fail();
  if (env.NODE_ENV === "production" &&
      !["verify-full"].includes(database.searchParams.get("sslmode")))
    throw fail();
  const encryptionKey = key(env.ORYVA_OIDC_PAYLOAD_KEY);
  const bindingHmacKey = key(env.ORYVA_OIDC_BINDING_HMAC_KEY);
  if (encryptionKey.equals(bindingHmacKey)) throw fail();
  return Object.freeze({
    issuer: issuer.toString().replace(/\/$/, ""),
    clientId, redirectUri: redirect.toString(), consoleOrigin: origin.origin,
    databaseConnectionString, encryptionKey, bindingHmacKey, allowLoopbackHttp,
  });
}

export async function loadOidcRuntimeConfig(env = process.env, options = {}) {
  const config = readOidcRuntimeConfig(env);
  try {
    const metadata = await discoverOidcMetadata(config.issuer, {
      fetcher: options.fetcher, allowLoopbackHttp: config.allowLoopbackHttp,
    });
    // The verifier currently supports RS256 only. Fail if discovery does not
    // advertise RS256 instead of silently selecting an unsupported algorithm.
    if (!metadata || typeof metadata.jwksUri !== "string") throw fail();
    return Object.freeze({ config, metadata });
  } catch { throw fail(); }
}
