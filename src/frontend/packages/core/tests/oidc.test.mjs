import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOryvaOidcPublicConfig, isOryvaRegisteredRedirect } from "../dist/index.js";

const base = {
  issuer: "https://identity.example.test/realms/oryva",
  clientId: "oryva-web",
  redirectUri: "https://console.example.test/auth/callback",
  postLogoutRedirectUri: "https://console.example.test/signed-out",
};
test("accepts canonical HTTPS public OIDC settings", () => {
  const config = parseOryvaOidcPublicConfig(base);
  assert.equal(config.scope, "openid profile email");
  assert.equal(isOryvaRegisteredRedirect(base.redirectUri, config), true);
  assert.equal(isOryvaRegisteredRedirect("https://evil.example", config), false);
  assert.equal(isOryvaRegisteredRedirect(base.redirectUri + "?next=evil", config), false);
});
test("rejects insecure, ambiguous, or credential-bearing endpoints", () => {
  const invalid = [
    { issuer: "http://identity.example.test/realms/oryva" },
    { issuer: "https://user:password@identity.example.test/realms/oryva" },
    { issuer: "https://identity.example.test/realms/oryva/" },
    { issuer: "https://identity.example.test/realms/oryva?x=1" },
    { redirectUri: "https://evil.example/auth/callback" ,
      postLogoutRedirectUri: base.postLogoutRedirectUri },
    { redirectUri: "//evil.example/callback" },
    { redirectUri: "https://console.example.test/callback#fragment" },
    { redirectUri: "https://console.example.test/callback?next=evil" },
    { clientId: "" },
    { clientId: "oryva client" },
  ];
  for (const override of invalid)
    assert.throws(() => parseOryvaOidcPublicConfig({ ...base, ...override }));
});
test("loopback HTTP requires explicit development-only opt-in", () => {
  const local = {
    ...base, issuer: "http://localhost:8080/realms/oryva",
    redirectUri: "http://localhost:3000/auth/callback",
    postLogoutRedirectUri: "http://localhost:3000/signed-out",
  };
  assert.throws(() => parseOryvaOidcPublicConfig(local));
  assert.equal(parseOryvaOidcPublicConfig(local, { allowLoopbackHttp: true }).clientId,
    "oryva-web");
  assert.throws(() => parseOryvaOidcPublicConfig({
    ...local, issuer: "http://identity.internal/realms/oryva",
  }, { allowLoopbackHttp: true }));
});
