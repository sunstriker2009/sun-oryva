import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverOidcMetadata, validateOidcMetadata } from "../lib/oidc-discovery.mjs";

const issuer = "https://identity.example.test/realms/oryva";
const metadata = {
  issuer,
  authorization_endpoint: issuer + "/protocol/openid-connect/auth",
  token_endpoint: issuer + "/protocol/openid-connect/token",
  jwks_uri: issuer + "/protocol/openid-connect/certs",
  response_types_supported: ["code"],
  id_token_signing_alg_values_supported: ["RS256"],
  code_challenge_methods_supported: ["S256"],
};
test("validates strict issuer and required OIDC endpoints", () => {
  assert.equal(validateOidcMetadata(metadata, issuer).issuer, issuer);
  assert.throws(() => validateOidcMetadata({ ...metadata, issuer: "https://evil.test" }, issuer));
  assert.throws(() => validateOidcMetadata({ ...metadata, jwks_uri: "http://evil.test/jwks" }, issuer));
  assert.throws(() => validateOidcMetadata({ ...metadata, response_types_supported: ["token"] }, issuer));
  assert.throws(() => validateOidcMetadata({ ...metadata, id_token_signing_alg_values_supported: ["none"] }, issuer));
  assert.throws(() => validateOidcMetadata({ ...metadata, code_challenge_methods_supported: ["plain"] }, issuer));
});
test("discovery rejects redirects and validates JSON response", async () => {
  let requested;
  const fetcher = async (url, init) => {
    requested = { url, init };
    return new Response(JSON.stringify(metadata), { status: 200,
      headers: { "content-type": "application/json" } });
  };
  assert.equal((await discoverOidcMetadata(issuer, { fetcher })).issuer, issuer);
  assert.equal(requested.url, issuer + "/.well-known/openid-configuration");
  assert.equal(requested.init.redirect, "error");
  assert.equal(requested.init.cache, "no-store");
  await assert.rejects(discoverOidcMetadata(issuer, {
    fetcher: async () => new Response("<html/>", { headers: { "content-type": "text/html" } }),
  }));
});
test("rejects insecure discovery and mismatched metadata", async () => {
  await assert.rejects(discoverOidcMetadata("http://identity.example.test/realm"));
  await assert.rejects(discoverOidcMetadata(issuer, {
    fetcher: async () => new Response(JSON.stringify({ ...metadata, issuer: "https://evil.test" }),
      { headers: { "content-type": "application/json" } }),
  }));
});
