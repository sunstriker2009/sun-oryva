/**
 * Server-only OIDC discovery. Fetches and validates identity-provider metadata.
 * Does not authenticate users or establish a session.
 */
function httpsUrl(value, allowLoopbackHttp) {
  if (typeof value !== "string" || value.trim() !== value ||
      /[\u0000-\u001f\u007f\\]/.test(value)) throw new Error("Invalid OIDC URL");
  let url;
  try { url = new URL(value); } catch { throw new Error("Invalid OIDC URL"); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(allowLoopbackHttp && loopback && url.protocol === "http:"))
    throw new Error("OIDC endpoint must use HTTPS");
  if (url.username || url.password || url.hash || url.search || !url.hostname)
    throw new Error("OIDC endpoint contains forbidden URL components");
  return url;
}

export function validateOidcMetadata(metadata, expectedIssuer, options = {}) {
  const allowLoopback = options.allowLoopbackHttp === true;
  const issuer = httpsUrl(expectedIssuer, allowLoopback);
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata) ||
      metadata.issuer !== issuer.href.replace(/\/$/, ""))
    throw new Error("OIDC issuer mismatch");
  const endpoints = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
  for (const key of endpoints) httpsUrl(metadata[key], allowLoopback);
  if (!Array.isArray(metadata.response_types_supported) ||
      !metadata.response_types_supported.includes("code"))
    throw new Error("OIDC code response unsupported");
  if (!Array.isArray(metadata.id_token_signing_alg_values_supported) ||
      !metadata.id_token_signing_alg_values_supported.includes("RS256"))
    throw new Error("OIDC signing algorithm unsupported");
  if (metadata.code_challenge_methods_supported !== undefined &&
      (!Array.isArray(metadata.code_challenge_methods_supported) ||
       !metadata.code_challenge_methods_supported.includes("S256")))
    throw new Error("OIDC PKCE S256 unsupported");
  return Object.freeze({
    issuer: metadata.issuer,
    authorizationEndpoint: metadata.authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    jwksUri: metadata.jwks_uri,
  });
}

export async function discoverOidcMetadata(issuer, options = {}) {
  const url = httpsUrl(issuer, options.allowLoopbackHttp === true);
  if (url.search || url.pathname.endsWith("/")) throw new Error("Invalid canonical issuer");
  // OIDC Discovery 1.0: append /.well-known/openid-configuration to issuer.
  const discoveryUrl = url.href + "/.well-known/openid-configuration";
  const fetcher = options.fetcher ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
  try {
    const response = await fetcher(discoveryUrl, {
      method: "GET", redirect: "error", cache: "no-store",
      headers: { accept: "application/json" }, signal: controller.signal,
    });
    if (!response.ok) throw new Error("OIDC discovery unavailable");
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("application/json"))
      throw new Error("OIDC discovery returned non-JSON content");
    const raw = await response.text();
    if (raw.length > 65536) throw new Error("OIDC discovery response too large");
    return validateOidcMetadata(JSON.parse(raw), issuer, options);
  } finally {
    clearTimeout(timeout);
  }
}
