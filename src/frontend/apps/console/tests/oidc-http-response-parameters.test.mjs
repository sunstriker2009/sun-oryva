import test from "node:test";
import assert from "node:assert/strict";
import { oidcAuthorizationResponse } from "../lib/oidc-http-response.mjs";
import { createOidcBindingCookie } from "../lib/oidc-browser-binding.mjs";

const endpoint = "https://identity.example.test/realms/oryva/auth";
const cookie = createOidcBindingCookie();
const url = () => {
  const u = new URL(endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("state", "s".repeat(43));
  u.searchParams.set("nonce", "n".repeat(43));
  u.searchParams.set("client_id", "oryva-console");
  u.searchParams.set("redirect_uri", "https://console.example.test/auth/callback");
  u.searchParams.set("scope", "openid profile");
  u.searchParams.set("code_challenge", "c".repeat(43));
  return u;
};
test("allows exactly one OIDC response type and PKCE method", () => {
  assert.equal(oidcAuthorizationResponse(url().toString(), cookie, endpoint).status, 302);
});
test("rejects duplicate security parameters even if the first value is valid", () => {
  for (const [name, value] of [["response_type", "token"], ["code_challenge_method", "plain"]]) {
    const u = url(); u.searchParams.append(name, value);
    assert.throws(() => oidcAuthorizationResponse(u.toString(), cookie, endpoint), /unavailable/);
  }
});
test("rejects embedded credentials in target or configured endpoint", () => {
  const u = url(); u.username = "injected";
  assert.throws(() => oidcAuthorizationResponse(u.toString(), cookie, endpoint), /unavailable/);
  assert.throws(() => oidcAuthorizationResponse(url().toString(), cookie,
    "https://user:password@identity.example.test/realms/oryva/auth"), /unavailable/);
});

test("rejects unsafe callback redirect URIs at the final HTTP boundary", () => {
  for (const value of [
    "javascript:alert(1)", "http://remote.example.test/callback",
    "https://user:pass@console.example.test/auth/callback",
    "https://console.example.test/auth/callback#fragment",
    "https://console.example.test/auth/callback?token=leak",
    "/auth/callback",
  ]) {
    const u = url(); u.searchParams.set("redirect_uri", value);
    assert.throws(() => oidcAuthorizationResponse(u.toString(), cookie, endpoint), /unavailable/);
  }
});
