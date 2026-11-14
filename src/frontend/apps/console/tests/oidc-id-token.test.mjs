import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { verifyOidcIdToken } from "../lib/oidc-id-token.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" };
const now = 1794650000, issuer = "https://id.example.test/realms/oryva", audience = "oryva-console", nonce = "n".repeat(43);
const b64 = x => Buffer.from(JSON.stringify(x)).toString("base64url");
const issue = (claims = {}, header = {}) => {
  const h = b64({ alg: "RS256", kid: "test-key", typ: "JWT", ...header });
  const p = b64({ iss: issuer, aud: audience, sub: "user-1", nonce, iat: now - 10, exp: now + 300, ...claims });
  return h + "." + p + "." + sign("RSA-SHA256", Buffer.from(h + "." + p), privateKey).toString("base64url");
};
const fetcher = async () => new Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } });
const options = { issuer, audience, nonce, jwksUri: issuer + "/protocol/openid-connect/certs", now, fetcher };
test("verifies signed token and returns minimal identity", async () => {
  assert.deepEqual(await verifyOidcIdToken({ ...options, idToken: issue() }), {
    subject: "user-1", issuer, audience, expiresAt: now + 300,
  });
});
test("rejects incorrect signature, issuer, audience, nonce and expiry", async () => {
  const cases = [issue({ iss: "https://evil.test" }), issue({ aud: "other" }),
    issue({ nonce: "x".repeat(43) }), issue({ exp: now }),
    issue({ iat: now + 100 }), issue({ aud: [audience, "other"] }),
    issue({}, { alg: "HS256" }), issue({}, { jku: "https://evil.test/keys" })];
  for (const idToken of cases)
    await assert.rejects(verifyOidcIdToken({ ...options, idToken }), /verification failed/);
  const valid = issue();
  const [h, p, s] = valid.split(".");
  const tampered = h + "." + p + "." + (s[0] === "A" ? "B" : "A") + s.slice(1);
  await assert.rejects(verifyOidcIdToken({ ...options, idToken: tampered }), /verification failed/);
});
test("rejects wrong JWKS key, duplicates and unsafe endpoints", async () => {
  for (const keys of [[], [jwk, jwk], [{ ...jwk, kid: "different" }]]) {
    await assert.rejects(verifyOidcIdToken({ ...options, idToken: issue(),
      fetcher: async () => new Response(JSON.stringify({ keys }), { headers: { "content-type": "application/json" } }) }), /verification failed/);
  }
  await assert.rejects(verifyOidcIdToken({ ...options, idToken: issue(), jwksUri: "http://evil.test/jwks" }), /verification failed/);
});
test("rejects HTTP errors and malformed JWKS responses", async () => {
  for (const response of [new Response("no", { status: 503 }),
    new Response("not-json", { headers: { "content-type": "application/json" } }),
    new Response(JSON.stringify({ keys: [] }), { headers: { "content-type": "text/plain" } })]) {
    await assert.rejects(verifyOidcIdToken({ ...options, idToken: issue(), fetcher: async () => response.clone() }), /verification failed/);
  }
});
