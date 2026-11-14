import { createBrowserBinding } from "./oidc-transaction-store.mjs";

export const OIDC_BINDING_COOKIE = "__Host-oryva-oidc-binding";
export const OIDC_BINDING_MAX_AGE = 300;
const fail = () => new Error("OIDC browser binding unavailable");
const valid = value => typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);

export function createOidcBindingCookie({ secure = true } = {}) {
  if (secure !== true) throw fail();
  const value = createBrowserBinding();
  return Object.freeze({
    name: OIDC_BINDING_COOKIE,
    value,
    options: Object.freeze({
      httpOnly: true, secure: true, sameSite: "strict",
      path: "/", maxAge: OIDC_BINDING_MAX_AGE,
    }),
  });
}

/** Reject duplicate cookie names and malformed values instead of trusting the first one. */
export function readOidcBindingCookie(cookieHeader) {
  if (typeof cookieHeader !== "string" || cookieHeader.length > 8192) throw fail();
  const matching = cookieHeader.split(";").map(x => x.trim()).filter(x =>
    x.startsWith(OIDC_BINDING_COOKIE + "="));
  if (matching.length !== 1) throw fail();
  const parts = matching[0].split("=");
  if (parts.length !== 2 || parts[0] !== OIDC_BINDING_COOKIE || !valid(parts[1]))
    throw fail();
  return parts[1];
}

export function clearOidcBindingCookie() {
  return Object.freeze({
    name: OIDC_BINDING_COOKIE,
    value: "",
    options: Object.freeze({
      httpOnly: true, secure: true, sameSite: "strict",
      path: "/", maxAge: 0,
    }),
  });
}

/**
 * Bind transaction issuance and callback consumption to the same browser.
 * The store HMACs this cookie and atomically consumes the transaction.
 * Caller must separately validate state and callback before exchanging code.
 */
export async function issueBrowserBoundTransaction({ store, state, sealedPayload }) {
  if (!store || typeof store.issue !== "function") throw fail();
  const cookie = createOidcBindingCookie();
  await store.issue({ state, browserBinding: cookie.value, sealedPayload });
  return cookie;
}

export async function consumeBrowserBoundTransaction({ store, state, cookieHeader }) {
  if (!store || typeof store.consume !== "function") throw fail();
  const browserBinding = readOidcBindingCookie(cookieHeader);
  try {
    return await store.consume({ state, browserBinding });
  } catch { throw fail(); }
}
