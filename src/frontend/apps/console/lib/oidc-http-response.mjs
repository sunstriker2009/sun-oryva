import { clearOidcBindingCookie } from "./oidc-browser-binding.mjs";
import { expiredSessionCookie } from "./oidc-session-store.mjs";

const fail = () => new Error("OIDC HTTP response unavailable");
const headers = Object.freeze({
  "cache-control": "no-store, max-age=0",
  "pragma": "no-cache",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
});

/** Convert a server-generated cookie descriptor to a Set-Cookie header.
 * Cookie names, values and options are deliberately NOT caller-controlled.
 */
export function serializeOidcCookie(cookie) {
  if (!cookie || !["__Host-oryva-oidc-binding", "__Host-oryva-session"].includes(cookie.name) ||
      typeof cookie.value !== "string" ||
      !/^[A-Za-z0-9_-]{0,128}$/.test(cookie.value) ||
      cookie.options?.secure !== true || cookie.options?.httpOnly !== true ||
      cookie.options?.path !== "/" || cookie.options?.sameSite !== "lax" ||
      !Number.isSafeInteger(cookie.options?.maxAge) ||
      cookie.options.maxAge < 0 || cookie.options.maxAge > 1800 ||
      Object.hasOwn(cookie.options, "domain")) throw fail();
  return cookie.name + "=" + cookie.value +
    "; Path=/; Max-Age=" + cookie.options.maxAge +
    "; Secure; HttpOnly; SameSite=Lax";
}

/** A 303 callback redirect prevents query parameters from remaining visible.
 * The caller must only supply a locally approved relative destination.
 */
export function oidcRedirectResponse(destination, cookies = []) {
  if (!["/", "/status", "/access-denied"].includes(destination) ||
      !Array.isArray(cookies) || cookies.length > 2) throw fail();
  const h = new Headers(headers);
  h.set("location", destination);
  for (const cookie of cookies) h.append("set-cookie", serializeOidcCookie(cookie));
  return new Response(null, { status: 303, headers: h });
}

/** Callback success and failure always expire the short-lived binding cookie. */
export function oidcCallbackResponse(sessionCookie = null) {
  return oidcRedirectResponse(sessionCookie ? "/" : "/status",
    sessionCookie ? [clearOidcBindingCookie(), sessionCookie] :
      [clearOidcBindingCookie()]);
}

/** Never reflect a user-provided redirect destination. */
export function oidcLogoutResponse() {
  return oidcRedirectResponse("/", [
    clearOidcBindingCookie(), expiredSessionCookie(),
  ]);
}

/** GET-only authorization initiation response with a verified provider URL. */
export function oidcAuthorizationResponse(authorizationUrl, bindingCookie, allowedEndpoint) {
  let target, endpoint;
  try {
    target = new URL(authorizationUrl);
    endpoint = new URL(allowedEndpoint);
  } catch { throw fail(); }
  if (target.username || target.password || endpoint.username || endpoint.password ||
      target.origin !== endpoint.origin || target.pathname !== endpoint.pathname ||
      endpoint.search || endpoint.hash || target.hash ||
      (target.protocol !== "https:" && !(target.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname))) ||
      target.searchParams.getAll("response_type").length !== 1 ||
      target.searchParams.get("response_type") !== "code" ||
      target.searchParams.getAll("code_challenge_method").length !== 1 ||
      target.searchParams.get("code_challenge_method") !== "S256" ||
      target.searchParams.getAll("state").length !== 1 ||
      target.searchParams.getAll("nonce").length !== 1 ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(target.searchParams.get("nonce") ?? "") ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(target.searchParams.get("state") ?? "") ||
      target.searchParams.getAll("client_id").length !== 1 ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(target.searchParams.get("client_id") ?? "") ||
      target.searchParams.getAll("redirect_uri").length !== 1 ||
      target.searchParams.getAll("scope").length !== 1 ||
      !target.searchParams.get("scope")?.split(" ").includes("openid") ||
      target.searchParams.getAll("code_challenge").length !== 1 ||
      !/^[A-Za-z0-9_-]{43}$/.test(target.searchParams.get("code_challenge") ?? "")) throw fail();
  // A malformed callback URI must never leave the final HTTP boundary.
  // Exact callback allowlisting is enforced upstream by runtime configuration.
  let callback;
  try { callback = new URL(target.searchParams.get("redirect_uri")); }
  catch { throw fail(); }
  if (callback.username || callback.password || callback.hash ||
      callback.search || callback.pathname !== "/auth/callback" ||
      (callback.protocol !== "https:" && !(callback.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(callback.hostname)))) throw fail();
  const h = new Headers(headers);
  h.set("location", target.toString());
  h.append("set-cookie", serializeOidcCookie(bindingCookie));
  return new Response(null, { status: 302, headers: h });
}
