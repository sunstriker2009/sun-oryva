import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { createOidcTransaction, buildOidcAuthorizationUrl } from "../lib/oidc-transaction.mjs";

test("creates unpredictable distinct state nonce and PKCE verifier", () => {
  const first = createOidcTransaction(), second = createOidcTransaction();
  assert.notEqual(first.state, second.state);
  assert.notEqual(first.nonce, first.state);
  assert.notEqual(first.verifier, second.verifier);
  assert.equal(first.challenge,
    createHash("sha256").update(first.verifier, "ascii").digest("base64url"));
});
test("authorization URL uses code+S256 and exact callback", () => {
  const tx = createOidcTransaction();
  const url = new URL(buildOidcAuthorizationUrl({
    clientId: "oryva-web", redirectUri: "https://console.example.test/api/auth/callback",
  }, { authorizationEndpoint: "https://identity.example.test/authorize" }, tx));
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("state"), tx.state);
  assert.equal(url.searchParams.get("nonce"), tx.nonce);
  assert.equal(url.searchParams.get("redirect_uri"),
    "https://console.example.test/api/auth/callback");
  assert.equal(url.searchParams.has("code_verifier"), false);
  assert.equal(url.searchParams.has("client_secret"), false);
});
test("rejects malformed transaction and unsafe endpoints", () => {
  const tx = createOidcTransaction();
  const config = { clientId: "oryva", redirectUri: "https://console.example.test/callback" };
  assert.throws(() => buildOidcAuthorizationUrl(config,
    { authorizationEndpoint: "http://evil.example/authorize" }, tx));
  assert.throws(() => buildOidcAuthorizationUrl(config,
    { authorizationEndpoint: "https://identity.example.test/authorize?redirect=evil" }, tx));
  assert.throws(() => buildOidcAuthorizationUrl(config,
    { authorizationEndpoint: "https://identity.example.test/authorize" }, { ...tx, state: "bad" }));
});
