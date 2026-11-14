import test from "node:test";
import assert from "node:assert/strict";
import { createOidcBindingCookie, readOidcBindingCookie, clearOidcBindingCookie, issueBrowserBoundTransaction, consumeBrowserBoundTransaction, OIDC_BINDING_COOKIE } from "../lib/oidc-browser-binding.mjs";

test("issues unique Secure HttpOnly host-only short-lived cookie", () => {
  const a = createOidcBindingCookie(), b = createOidcBindingCookie();
  assert.equal(a.name, OIDC_BINDING_COOKIE);
  assert.notEqual(a.value, b.value);
  assert.equal(a.options.secure, true);
  assert.equal(a.options.httpOnly, true);
  assert.equal(a.options.sameSite, "strict");
  assert.equal(a.options.path, "/");
  assert.equal(a.options.maxAge, 300);
  assert.equal(Object.hasOwn(a.options, "domain"), false);
  assert.throws(() => createOidcBindingCookie({ secure: false }), /unavailable/);
});
test("rejects absent, duplicated, malformed and oversized cookie headers", () => {
  const cookie = createOidcBindingCookie();
  const pair = `${cookie.name}=${cookie.value}`;
  assert.equal(readOidcBindingCookie(`other=123; ${pair}`), cookie.value);
  for (const header of ["", "other=123", `${pair}; ${pair}`, `${cookie.name}=short`, `${pair}=extra`, "a".repeat(8193)])
    assert.throws(() => readOidcBindingCookie(header), /unavailable/);
  assert.equal(clearOidcBindingCookie().options.maxAge, 0);
});
test("passes only server-generated binding into store and fails closed on mismatch", async () => {
  let issued;
  const store = {
    async issue(value) { issued = value; },
    async consume({ state, browserBinding }) {
      if (state !== issued.state || browserBinding !== issued.browserBinding) throw Error("denied");
      return issued.sealedPayload;
    },
  };
  const cookie = await issueBrowserBoundTransaction({ store, state: "s".repeat(43), sealedPayload: "encrypted" });
  assert.equal(issued.browserBinding, cookie.value);
  assert.equal(await consumeBrowserBoundTransaction({
    store, state: issued.state, cookieHeader: `${cookie.name}=${cookie.value}`,
  }), "encrypted");
  const other = createOidcBindingCookie();
  await assert.rejects(consumeBrowserBoundTransaction({
    store, state: issued.state, cookieHeader: `${other.name}=${other.value}`,
  }), /unavailable/);
});
