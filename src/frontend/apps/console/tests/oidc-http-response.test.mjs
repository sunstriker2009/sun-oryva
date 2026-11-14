import test from "node:test";
import assert from "node:assert/strict";
import { createOidcBindingCookie, OIDC_BINDING_COOKIE } from "../lib/oidc-browser-binding.mjs";
import { sessionCookie, SESSION_COOKIE } from "../lib/oidc-session-store.mjs";
import { oidcAuthorizationResponse, oidcCallbackResponse, oidcLogoutResponse,
  oidcRedirectResponse, serializeOidcCookie } from "../lib/oidc-http-response.mjs";

const endpoint = "https://id.example.test/realms/oryva/protocol/openid-connect/auth";
const url = endpoint + "?response_type=code&code_challenge_method=S256&state=" +
  "s".repeat(43) + "&nonce=" + "n".repeat(43) +
  "&client_id=oryva-console&redirect_uri=https%3A%2F%2Fconsole.example.test%2Fauth%2Fcallback" +
  "&scope=openid%20profile%20email&code_challenge=" + "c".repeat(43);
test("authorization response redirects without leaking browser binding to URL", () => {
  const cookie = createOidcBindingCookie();
  const response = oidcAuthorizationResponse(url, cookie, endpoint);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), url);
  assert.match(response.headers.get("set-cookie"), /Secure; HttpOnly; SameSite=Lax/);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("location").includes(cookie.value), false);
});
test("callback success clears binding and creates only opaque session cookie", () => {
  const response = oidcCallbackResponse(sessionCookie("t".repeat(43)));
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/");
  const set = response.headers.get("set-cookie");
  assert.ok(set.includes(OIDC_BINDING_COOKIE + "="));
  assert.ok(set.includes(SESSION_COOKIE + "="));
  assert.ok(set.includes("Max-Age=0"));
});
test("callback failure clears binding and logout expires both cookies", () => {
  const failure = oidcCallbackResponse();
  assert.equal(failure.headers.get("location"), "/status");
  assert.ok(failure.headers.get("set-cookie").includes("Max-Age=0"));
  const logout = oidcLogoutResponse();
  assert.equal(logout.status, 303);
  assert.ok(logout.headers.get("set-cookie").includes(SESSION_COOKIE + "="));
  assert.ok(logout.headers.get("set-cookie").includes(OIDC_BINDING_COOKIE + "="));
});
test("rejects open redirects, unsafe providers and malformed cookie descriptors", () => {
  const cookie = createOidcBindingCookie();
  for (const destination of ["//evil.test", "https://evil.test", "/\\evil.test", "/auth/callback"]) {
    assert.throws(() => oidcRedirectResponse(destination), /unavailable/);
  }
  for (const bad of [url.replace("https://id.example.test", "https://evil.test"),
    url.replace("https:", "http:"), url + "#fragment"]) {
    assert.throws(() => oidcAuthorizationResponse(bad, cookie, endpoint), /unavailable/);
  }
  assert.throws(() => serializeOidcCookie({ ...cookie, value: "bad; injected=1" }), /unavailable/);
  assert.throws(() => serializeOidcCookie({
    ...cookie, options: { ...cookie.options, domain: "evil.test" },
  }), /unavailable/);
});

test("rejects duplicate, missing or malformed critical OIDC redirect parameters", () => {
  const cookie = createOidcBindingCookie();
  for (const name of ["client_id", "redirect_uri", "scope", "code_challenge", "state", "nonce"]) {
    const duplicate = url + "&" + name + "=attacker";
    assert.throws(() => oidcAuthorizationResponse(duplicate, cookie, endpoint), /unavailable/);
    const removed = new URL(url);
    removed.searchParams.delete(name);
    assert.throws(() => oidcAuthorizationResponse(removed.toString(), cookie, endpoint), /unavailable/);
  }
  for (const [name, value] of [["scope", "profile email"], ["code_challenge", "short"],
    ["client_id", "bad client"], ["state", "short"], ["nonce", "short"]]) {
    const invalid = new URL(url);
    invalid.searchParams.set(name, value);
    assert.throws(() => oidcAuthorizationResponse(invalid.toString(), cookie, endpoint), /unavailable/);
  }
});
