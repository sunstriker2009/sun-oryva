import { timingSafeEqual } from "node:crypto";

const opaque = value => typeof value === "string" && /^[A-Za-z0-9_-]{43,128}$/.test(value);
const code = value => typeof value === "string" && value.length >= 1 &&
  value.length <= 4096 && /^[A-Za-z0-9._~+\/-]+$/.test(value);

function sameSecret(left, right) {
  if (!opaque(left) || !opaque(right)) return false;
  const a = Buffer.from(left, "utf8"), b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Validate a code-flow callback against an independently retrieved,
 * browser-bound, unexpired and unconsumed server transaction.
 *
 * This function does NOT prove the authorization code or tokens are valid.
 * A vetted OIDC client must perform the token exchange and validation.
 */
export function validateOidcCallback(query, transaction, now = Date.now()) {
  if (!(query instanceof URLSearchParams) || !transaction ||
      transaction.consumed !== false || !Number.isSafeInteger(transaction.createdAt) ||
      !Number.isSafeInteger(now) || transaction.createdAt > now ||
      now - transaction.createdAt > 300000)
    return { ok: false, reason: "invalid_transaction" };

  if (query.has("error")) return { ok: false, reason: "provider_error" };
  if (query.getAll("state").length !== 1 || query.getAll("code").length !== 1 ||
      query.has("id_token") || query.has("access_token") || query.has("token") ||
      query.has("session_state") && query.getAll("session_state").length !== 1)
    return { ok: false, reason: "invalid_callback" };
  if (!sameSecret(query.get("state"), transaction.state) ||
      !opaque(transaction.nonce) || !opaque(transaction.verifier))
    return { ok: false, reason: "invalid_state" };
  const authorizationCode = query.get("code");
  if (!code(authorizationCode)) return { ok: false, reason: "invalid_callback" };
  return { ok: true, code: authorizationCode };
}
