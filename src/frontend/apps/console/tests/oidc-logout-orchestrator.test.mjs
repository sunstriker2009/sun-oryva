import test from "node:test";
import assert from "node:assert/strict";
import { completeOidcLogout } from "../lib/oidc-logout-orchestrator.mjs";

const origin = "https://console.example.test";
const token = Buffer.alloc(32, 3).toString("base64url");
const cookieHeader = "__Host-oryva-session=" + token;
const fixture = () => {
  const revoked = [];
  return { revoked, sessionStore: { async revoke(args) { revoked.push(args); return true; } } };
};
test("POST with matching canonical origin revokes before clearing session", async () => {
  const f = fixture();
  const response = await completeOidcLogout({
    method: "POST", origin, expectedOrigin: origin, cookieHeader, sessionStore: f.sessionStore,
  });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/");
  assert.equal(f.revoked.length, 1);
  assert.equal(f.revoked[0].token, token);
  assert.match(response.headers.get("set-cookie"), /Max-Age=0/);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
});
test("rejects GET and cross-origin requests without revocation", async () => {
  for (const [method, requestOrigin] of [["GET", origin], ["POST", "https://evil.test"],
    ["POST", "https://console.example.test.evil.test"], ["POST", "null"]]) {
    const f = fixture();
    await assert.rejects(completeOidcLogout({
      method, origin: requestOrigin, expectedOrigin: origin, cookieHeader,
      sessionStore: f.sessionStore,
    }), /unavailable/);
    assert.equal(f.revoked.length, 0);
  }
});
test("missing or duplicate session cookies clear without revoking", async () => {
  for (const header of ["", cookieHeader + "; " + cookieHeader]) {
    const f = fixture();
    const response = await completeOidcLogout({
      method: "POST", origin, expectedOrigin: origin, cookieHeader: header,
      sessionStore: f.sessionStore,
    });
    assert.equal(response.status, 303);
    assert.equal(f.revoked.length, 0);
  }
});
test("database failure does not return success redirect", async () => {
  await assert.rejects(completeOidcLogout({
    method: "POST", origin, expectedOrigin: origin, cookieHeader,
    sessionStore: { async revoke() { throw Error("database credentials"); } },
  }), e => e.message === "OIDC logout unavailable");
});
