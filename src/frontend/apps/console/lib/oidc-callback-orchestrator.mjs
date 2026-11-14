import { validateOidcCallback } from "./oidc-callback.mjs";
import { consumeBrowserBoundTransaction } from "./oidc-browser-binding.mjs";
import { exchangeAuthorizationCode } from "./oidc-token-exchange.mjs";
import { verifyOidcIdToken } from "./oidc-id-token.mjs";

const fail = () => new Error("OIDC callback unavailable");

/**
 * Server-only callback orchestration. All dependencies are injected to avoid
 * exposing an HTTP endpoint before configuration and deployment gates exist.
 * Transaction consumption is atomic and happens BEFORE the token request.
 */
export async function completeOidcCallback({
  query, cookieHeader, transactionStore, payloadProtector, sessionStore,
  oidc, fetcher = fetch, now = Math.floor(Date.now() / 1000),
  exchange = exchangeAuthorizationCode, verify = verifyOidcIdToken,
}) {
  if (!(query instanceof URLSearchParams) || !transactionStore ||
      !payloadProtector || typeof payloadProtector.open !== "function" ||
      !sessionStore || typeof sessionStore.create !== "function" ||
      !oidc || typeof oidc !== "object" || !Number.isSafeInteger(now)) throw fail();
  // Fail before consumption on malformed callback or provider error.
  if (query.has("error") || query.getAll("state").length !== 1 ||
      query.getAll("code").length !== 1 ||
      query.has("id_token") || query.has("access_token") || query.has("token") ||
      (query.has("session_state") && query.getAll("session_state").length !== 1))
    throw fail();
  const state = query.get("state");
  if (typeof state !== "string" || !/^[A-Za-z0-9_-]{43,128}$/.test(state)) throw fail();
  try {
    const sealedPayload = await consumeBrowserBoundTransaction({
      store: transactionStore, state, cookieHeader,
    });
    const { verifier, nonce } = payloadProtector.open(sealedPayload);
    // Existing callback parser also validates code syntax and state; its
    // transaction age is already enforced atomically by PostgreSQL.
    const checked = validateOidcCallback(query, {
      state, nonce, verifier, consumed: false, createdAt: now * 1000,
    }, now * 1000);
    if (!checked.ok) throw fail();
    const tokens = await exchange({
      endpoint: oidc.tokenEndpoint, clientId: oidc.clientId,
      redirectUri: oidc.redirectUri, code: checked.code,
      verifier, fetcher, allowLoopbackHttp: oidc.allowLoopbackHttp === true,
    });
    const identity = await verify({
      idToken: tokens.idToken, issuer: oidc.issuer, audience: oidc.clientId,
      nonce, jwksUri: oidc.jwksUri, fetcher, now,
      allowLoopbackHttp: oidc.allowLoopbackHttp === true,
    });
    if (identity.issuer !== oidc.issuer ||
        typeof identity.subject !== "string" || !identity.subject ||
        identity.audience !== oidc.clientId ||
        !Number.isSafeInteger(identity.expiresAt) || identity.expiresAt <= now)
      throw fail();
    // Sessions carry identity ONLY. Role/active status must be queried from
    // the trusted ORYVA backend for every privileged request.
    const session = await sessionStore.create({
      subject: identity.subject, issuer: identity.issuer,
    });
    if (!session || !session.cookie || typeof session.token !== "string")
      throw fail();
    return Object.freeze({ cookie: session.cookie });
  } catch { throw fail(); }
}
