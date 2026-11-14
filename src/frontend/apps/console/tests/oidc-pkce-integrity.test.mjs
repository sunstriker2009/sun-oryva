import test from "node:test";
import assert from "node:assert/strict";
import { createOidcTransaction, buildOidcAuthorizationUrl } from "../lib/oidc-transaction.mjs";

const config = { clientId: "oryva-console", redirectUri: "https://console.example.test/auth/callback" };
const metadata = { authorizationEndpoint: "https://id.example.test/realms/oryva/protocol/openid-connect/auth" };

test("generated PKCE challenge is bound to the verifier", () => {
  const transaction = createOidcTransaction();
  const url = new URL(buildOidcAuthorizationUrl(config, metadata, transaction));
  assert.equal(url.searchParams.get("code_challenge"), transaction.challenge);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
});
test("rejects mismatched PKCE challenge before redirect", () => {
  const transaction = createOidcTransaction();
  assert.throws(() => buildOidcAuthorizationUrl(config, metadata, {
    ...transaction, challenge: createOidcTransaction().challenge,
  }), /Invalid PKCE challenge/);
});
test("rejects credential-bearing authorization endpoints", () => {
  const transaction = createOidcTransaction();
  assert.throws(() => buildOidcAuthorizationUrl(config, {
    authorizationEndpoint: "https://user:password@id.example.test/auth",
  }, transaction), /Unexpected authorization endpoint parameters/);
});
