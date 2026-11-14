import { createPublicKey, verify, timingSafeEqual } from "node:crypto";

const fail = () => new Error("OIDC ID token verification failed");
const segment = s => typeof s === "string" && /^[A-Za-z0-9_-]+$/.test(s) &&
  Buffer.from(s, "base64url").toString("base64url") === s;
const decode = s => {
  if (!segment(s) || s.length > 32768) throw fail();
  try { return JSON.parse(Buffer.from(s, "base64url").toString("utf8")); }
  catch { throw fail(); }
};
const secretEqual = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};
const safeHttps = (input, allowLoopbackHttp) => {
  let url;
  try { url = new URL(input); } catch { throw fail(); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(allowLoopbackHttp && loopback && url.protocol === "http:")) ||
      !url.hostname || url.username || url.password || url.hash || url.search) throw fail();
  return url;
};

/**
 * Strict RS256 ID-token verifier for a pinned issuer/client and trusted JWKS URI.
 * This intentionally supports only RS256, not dynamic token-selected algorithms.
 * Must run on the server; never authorize a role from an unverified token claim.
 */
export async function verifyOidcIdToken({
  idToken, issuer, audience, nonce, jwksUri,
  fetcher = fetch, now = Math.floor(Date.now() / 1000),
  allowLoopbackHttp = false,
}) {
  if (typeof idToken !== "string" || idToken.length > 16384 ||
      typeof issuer !== "string" || typeof audience !== "string" || !audience ||
      typeof nonce !== "string" || nonce.length < 43 || nonce.length > 128 ||
      !Number.isSafeInteger(now)) throw fail();
  const jwksUrl = safeHttps(jwksUri, allowLoopbackHttp);
  safeHttps(issuer, allowLoopbackHttp);
  const parts = idToken.split(".");
  if (parts.length !== 3 || !parts.every(segment)) throw fail();
  const header = decode(parts[0]), claims = decode(parts[1]);
  if (!header || typeof header !== "object" || Array.isArray(header) ||
      header.alg !== "RS256" || typeof header.kid !== "string" ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(header.kid) ||
      header.crit !== undefined || header.jku !== undefined ||
      header.jwk !== undefined || header.x5u !== undefined ||
      !claims || typeof claims !== "object" || Array.isArray(claims)) throw fail();
  const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
  if (claims.iss !== issuer || !Array.isArray(audiences) ||
      audiences.length < 1 || !audiences.every(x => typeof x === "string") ||
      !audiences.includes(audience) ||
      (audiences.length > 1 && claims.azp !== audience) ||
      !secretEqual(claims.nonce, nonce) ||
      typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 256 ||
      !Number.isSafeInteger(claims.iat) || claims.iat > now + 60 ||
      !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
      claims.exp - claims.iat > 86400 ||
      (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now)) ||
      (claims.auth_time !== undefined && !Number.isSafeInteger(claims.auth_time)))
    throw fail();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetcher(jwksUrl.toString(), {
      method: "GET", redirect: "error", cache: "no-store",
      headers: { accept: "application/json" }, signal: controller.signal,
    });
    if (!response.ok || !(response.headers.get("content-type") ?? "").toLowerCase().includes("application/json"))
      throw fail();
    const body = await response.text();
    if (body.length > 65536) throw fail();
    const jwks = JSON.parse(body);
    if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length > 32) throw fail();
    const keys = jwks.keys.filter(k => k && k.kid === header.kid && k.kty === "RSA" &&
      (k.alg === undefined || k.alg === "RS256") &&
      (k.use === undefined || k.use === "sig") &&
      (k.key_ops === undefined || (Array.isArray(k.key_ops) && k.key_ops.includes("verify"))) &&
      typeof k.n === "string" && typeof k.e === "string");
    if (keys.length !== 1) throw fail();
    const publicKey = createPublicKey({ key: { kty: "RSA", n: keys[0].n, e: keys[0].e }, format: "jwk" });
    if (publicKey.asymmetricKeyType !== "rsa" || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)
      throw fail();
    if (!verify("RSA-SHA256", Buffer.from(parts[0] + "." + parts[1], "ascii"),
      publicKey, Buffer.from(parts[2], "base64url"))) throw fail();
    return Object.freeze({ subject: claims.sub, issuer: claims.iss, audience, expiresAt: claims.exp });
  } catch { throw fail(); } finally { clearTimeout(timer); }
}
