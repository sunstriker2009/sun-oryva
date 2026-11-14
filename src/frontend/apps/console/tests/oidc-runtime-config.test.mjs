import test from "node:test";
import assert from "node:assert/strict";
import { readOidcRuntimeConfig, loadOidcRuntimeConfig } from "../lib/oidc-runtime-config.mjs";

const keyA = Buffer.alloc(32, 7).toString("base64url");
const keyB = Buffer.alloc(32, 9).toString("base64url");
const env = {
  NODE_ENV: "production", ORYVA_OIDC_ENABLED: "true",
  ORYVA_OIDC_ISSUER: "https://id.example.test/realms/oryva",
  ORYVA_OIDC_REDIRECT_URI: "https://console.example.test/auth/callback",
  ORYVA_CONSOLE_ORIGIN: "https://console.example.test",
  ORYVA_OIDC_CLIENT_ID: "oryva-console",
  ORYVA_OIDC_DATABASE_URL: "postgresql://user:password@db.example.test/oryva?sslmode=verify-full",
  ORYVA_OIDC_PAYLOAD_KEY: keyA, ORYVA_OIDC_BINDING_HMAC_KEY: keyB,
};
test("loads production-safe server-only configuration", () => {
  const value = readOidcRuntimeConfig(env);
  assert.equal(value.issuer, env.ORYVA_OIDC_ISSUER);
  assert.equal(value.consoleOrigin, env.ORYVA_CONSOLE_ORIGIN);
  assert.equal(value.encryptionKey.length, 32);
  assert.equal(value.bindingHmacKey.length, 32);
  assert.equal(Object.hasOwn(value, "NEXT_PUBLIC_KEY"), false);
});
test("rejects disabled, weak keys, untrusted origin and insecure PostgreSQL", () => {
  const changes = [
    { ORYVA_OIDC_ENABLED: "false" },
    { ORYVA_OIDC_PAYLOAD_KEY: keyB },
    { ORYVA_OIDC_PAYLOAD_KEY: "weak" },
    { ORYVA_OIDC_REDIRECT_URI: "https://evil.test/auth/callback" },
    { ORYVA_OIDC_REDIRECT_URI: "https://console.example.test/other" },
    { ORYVA_OIDC_ISSUER: "http://id.example.test/realms/oryva" },
    { ORYVA_OIDC_DATABASE_URL: "postgres://user:pass@db.example.test/oryva?sslmode=require" },
    { ORYVA_OIDC_DATABASE_URL: "postgres://user:pass@db.example.test/oryva" },
  ];
  for (const change of changes)
    assert.throws(() => readOidcRuntimeConfig({ ...env, ...change }), /unavailable/);
});
test("discovery is required and failures remain generic", async () => {
  await assert.rejects(loadOidcRuntimeConfig(env, {
    fetcher: async () => new Response("unavailable", { status: 503 }),
  }), /unavailable/);
});
