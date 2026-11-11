/**
 * Public OIDC client configuration validation.
 * This is not an authentication implementation: use a vetted OIDC client
 * for authorization code + PKCE, state/nonce, and callback verification.
 */
export interface OryvaOidcPublicConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly postLogoutRedirectUri: string;
  readonly scope: "openid profile email";
}

function normalizedHttpsUrl(value: unknown, allowLoopbackHttp: boolean): URL {
  if (typeof value !== "string" || value.trim() !== value ||
      value.length > 2048 || /[\\u0000-\\u001f\\u007f\\\\]/.test(value))
    throw new Error("Invalid OIDC URL");
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("Invalid OIDC URL"); }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "https:" &&
      !(allowLoopbackHttp && url.protocol === "http:" && loopback))
    throw new Error("OIDC URL requires HTTPS");
  if (url.username || url.password || url.hash || !url.hostname ||
      (url.port && !/^\\d+$/.test(url.port)))
    throw new Error("OIDC URL has forbidden components");
  return url;
}

export function parseOryvaOidcPublicConfig(
  value: unknown,
  options: { readonly allowLoopbackHttp?: boolean } = {},
): OryvaOidcPublicConfig {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid OIDC configuration");
  const config = value as Record<string, unknown>;
  if (typeof config.clientId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(config.clientId))
    throw new Error("Invalid public client identifier");
  const allowLoopback = options.allowLoopbackHttp === true;
  const issuer = normalizedHttpsUrl(config.issuer, allowLoopback);
  if (issuer.search || issuer.pathname.endsWith("/"))
    throw new Error("Issuer must be a canonical URL without query or trailing slash");
  const redirect = normalizedHttpsUrl(config.redirectUri, allowLoopback);
  const logout = normalizedHttpsUrl(config.postLogoutRedirectUri, allowLoopback);
  if (redirect.origin !== logout.origin)
    throw new Error("Redirect origins must match");
  if (redirect.search || logout.search)
    throw new Error("Redirect URIs must not include query strings");
  if (redirect.origin === issuer.origin && redirect.pathname === issuer.pathname)
    throw new Error("Redirect URI cannot equal issuer");
  return Object.freeze({
    issuer: issuer.href,
    clientId: config.clientId,
    redirectUri: redirect.href,
    postLogoutRedirectUri: logout.href,
    scope: "openid profile email",
  });
}

/** Only accepts exact pre-registered redirect URIs, not arbitrary return URLs. */
export function isOryvaRegisteredRedirect(
  candidate: unknown,
  config: OryvaOidcPublicConfig,
): boolean {
  return typeof candidate === "string" &&
    (candidate === config.redirectUri || candidate === config.postLogoutRedirectUri);
}
