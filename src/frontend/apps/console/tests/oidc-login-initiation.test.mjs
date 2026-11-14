import test from "node:test";
import assert from "node:assert/strict";
import { initiateOidcLogin } from "../lib/oidc-login-initiation.mjs";
import { createOidcPayloadProtector } from "../lib/oidc-payload-protector.mjs";

const protector = createOidcPayloadProtector(Buffer.alloc(32, 7));
const config = { clientId: "oryva-console", redirectUri: "https://console.example.test/auth/callback" };
const metadata = { authorizationEndpoint: "https://id.example.test/realms/oryva/protocol/openid-connect/auth" };
function fixture() {
  const issued = [];
  const transactionStore = { async issue(value) { issued.push(value); } };
  return { issued, transactionStore, config, metadata, payloadProtector: protector };
}
test("persists sealed secrets and binding before returning authorization redirect", async () => {
  const f = fixture();
  const result = await initiateOidcLogin(f);
  const url = new URL(result.authorizationUrl);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("client_id"), config.clientId);
  assert.equal(url.searchParams.get("redirect_uri"), config.redirectUri);
  assert.equal(f.issued.length, 1);
  assert.equal(f.issued[0].state, url.searchParams.get("state"));
  assert.equal(f.issued[0].browserBinding, result.cookie.value);
  assert.equal(result.cookie.options.httpOnly, true);
  assert.equal(result.cookie.options.secure, true);
  const decrypted = protector.open(f.issued[0].sealedPayload);
  assert.equal(decrypted.nonce, url.searchParams.get("nonce"));
  assert.equal(decrypted.verifier.length, 43);
  assert.equal(result.authorizationUrl.includes(decrypted.verifier), false);
  assert.equal(result.authorizationUrl.includes(f.issued[0].sealedPayload), false);
  assert.equal(Object.hasOwn(result, "transaction"), false);
});
test("fresh logins produce independent states, challenges and cookies", async () => {
  const f = fixture();
  const a = await initiateOidcLogin(f), b = await initiateOidcLogin(f);
  assert.notEqual(new URL(a.authorizationUrl).searchParams.get("state"), new URL(b.authorizationUrl).searchParams.get("state"));
  assert.notEqual(new URL(a.authorizationUrl).searchParams.get("code_challenge"), new URL(b.authorizationUrl).searchParams.get("code_challenge"));
  assert.notEqual(a.cookie.value, b.cookie.value);
});
test("database failure or unsafe authorization endpoint never returns redirect", async () => {
  const f = fixture();
  await assert.rejects(initiateOidcLogin({ ...f, transactionStore: {
    async issue() { throw Error("private database failure"); },
  }}), e => e.message === "OIDC login initiation unavailable");
  await assert.rejects(initiateOidcLogin({ ...f, metadata: {
    authorizationEndpoint: "http://evil.example.test/auth",
  }}), /unavailable/);
  assert.equal(f.issued.length, 0);
});
test("invalid transaction fails before persistence", async () => {
  const f = fixture();
  await assert.rejects(initiateOidcLogin({ ...f, generate: () => ({
    state: "bad", nonce: "bad", verifier: "bad", challenge: "bad",
  }) }), /unavailable/);
  assert.equal(f.issued.length, 0);
});
