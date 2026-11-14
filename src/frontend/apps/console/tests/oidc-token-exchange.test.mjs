import test from "node:test";
import assert from "node:assert/strict";
import { exchangeAuthorizationCode } from "../lib/oidc-token-exchange.mjs";

const args = { endpoint: "https://id.example.test/token", clientId: "oryva-console", redirectUri: "https://app.example.test/callback", code: "abc", verifier: "x".repeat(43) };
const response = (data, status = 200, headers = { "content-type": "application/json" }) =>
  new Response(JSON.stringify(data), { status, headers });
const valid = { id_token: "header.payload.signature", access_token: "opaque", token_type: "Bearer", expires_in: 300 };

test("sends authorization code via form POST, never in URL", async () => {
  const result = await exchangeAuthorizationCode({ ...args, fetcher: async (url, init) => {
    assert.equal(url, args.endpoint);
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    assert.equal(init.cache, "no-store");
    const body = new URLSearchParams(init.body);
    assert.equal(body.get("grant_type"), "authorization_code");
    assert.equal(body.get("code_verifier"), args.verifier);
    assert.equal(body.get("redirect_uri"), args.redirectUri);
    assert.equal(body.get("code"), args.code);
    assert.equal(body.get("client_id"), args.clientId);
    return response(valid);
  }});
  assert.equal(result.idToken, valid.id_token);
  assert.equal(result.accessToken, valid.access_token);
});

test("rejects insecure and credential-bearing endpoints", async () => {
  for (const endpoint of ["http://id.example.test/token", "https://user:pass@id.example.test/token", "https://id.example.test/token?secret=1", "https://id.example.test/token#x"]) {
    await assert.rejects(exchangeAuthorizationCode({ ...args, endpoint, fetcher: () => { throw Error("must not call"); } }), /unavailable/);
  }
});

test("rejects error, invalid token shape and oversized responses", async () => {
  for (const fetcher of [
    async () => response(valid, 400),
    async () => response({ ...valid, token_type: "Basic" }),
    async () => response({ ...valid, expires_in: 0 }),
    async () => new Response("not json", { headers: { "content-type": "text/plain" } }),
    async () => response({ ...valid, access_token: "x".repeat(70000) }),
    async () => new Response("{}", { headers: { "content-type": "application/json", "content-length": "999999" } }),
  ]) await assert.rejects(exchangeAuthorizationCode({ ...args, fetcher }), /unavailable/);
});

test("rejects bad verifier, callback URI and timeout before sending", async () => {
  for (const overrides of [{ verifier: "weak" }, { redirectUri: "http://app.example.test/callback" }, { timeoutMs: 20000 }]) {
    await assert.rejects(exchangeAuthorizationCode({ ...args, ...overrides, fetcher: () => { throw Error("must not call"); } }), /unavailable/);
  }
});

test("allows explicit loopback HTTP in local development only", async () => {
  const result = await exchangeAuthorizationCode({ ...args, endpoint: "http://localhost:8080/token", redirectUri: "http://localhost:3000/callback", allowLoopbackHttp: true, fetcher: async () => response(valid) });
  assert.equal(result.expiresIn, 300);
});
