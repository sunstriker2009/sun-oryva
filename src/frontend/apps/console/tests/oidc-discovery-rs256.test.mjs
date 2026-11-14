import test from "node:test";
import assert from "node:assert/strict";
import { validateOidcMetadata } from "../lib/oidc-discovery.mjs";
import { loadOidcRuntimeConfig } from "../lib/oidc-runtime-config.mjs";

const issuer = "https://id.example.test/realms/oryva";
const metadata = {
  issuer, authorization_endpoint: issuer + "/protocol/openid-connect/auth",
  token_endpoint: issuer + "/protocol/openid-connect/token",
  jwks_uri: issuer + "/protocol/openid-connect/certs",
  response_types_supported: ["code"], code_challenge_methods_supported: ["S256"],
  id_token_signing_alg_values_supported: ["RS256"],
};
test("accepts RS256 issuer metadata", () => {
  assert.equal(validateOidcMetadata(metadata, issuer).issuer, issuer);
});
test("rejects issuers that advertise only PS256 or ES256", () => {
  for (const algorithms of [["PS256"], ["ES256"], ["PS256", "ES256"], []]) {
    assert.throws(() => validateOidcMetadata({
      ...metadata, id_token_signing_alg_values_supported: algorithms,
    }, issuer), /unsupported/);
  }
});
test("rejects unsupported signing algorithms during runtime discovery", async () => {
  const env = {
    NODE_ENV: "production", ORYVA_OIDC_ENABLED: "true",
    ORYVA_OIDC_ISSUER: issuer, ORYVA_OIDC_REDIRECT_URI: "https://console.example.test/auth/callback",
    ORYVA_CONSOLE_ORIGIN: "https://console.example.test",
    ORYVA_OIDC_CLIENT_ID: "oryva-console",
    ORYVA_OIDC_DATABASE_URL: "postgresql://user:pass@db.example.test/oryva?sslmode=verify-full",
    ORYVA_OIDC_PAYLOAD_KEY: Buffer.alloc(32, 7).toString("base64url"),
    ORYVA_OIDC_BINDING_HMAC_KEY: Buffer.alloc(32, 9).toString("base64url"),
  };
  await assert.rejects(loadOidcRuntimeConfig(env, {
    fetcher: async () => new Response(JSON.stringify({
      ...metadata, id_token_signing_alg_values_supported: ["ES256"],
    }), { headers: { "content-type": "application/json" } }),
  }), /unavailable/);
});
