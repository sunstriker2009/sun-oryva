import assert from "node:assert/strict";
import { test } from "node:test";
import { createOidcTransaction } from "../lib/oidc-transaction.mjs";
import { validateOidcCallback } from "../lib/oidc-callback.mjs";

const now = 1000000;
function fixture() {
  const tx = createOidcTransaction();
  return { tx: { ...tx, createdAt: now - 1000, consumed: false },
    query: new URLSearchParams({ state: tx.state, code: "abc123XYZ" }) };
}
test("accepts a single code and matching state from a live server transaction", () => {
  const { tx, query } = fixture();
  assert.deepEqual(validateOidcCallback(query, tx, now), { ok: true, code: "abc123XYZ" });
});
test("rejects missing, mismatched and duplicated state", () => {
  const { tx, query } = fixture();
  query.set("state", createOidcTransaction().state);
  assert.equal(validateOidcCallback(query, tx, now).ok, false);
  query.set("state", tx.state); query.append("state", tx.state);
  assert.equal(validateOidcCallback(query, tx, now).ok, false);
  query.delete("state");
  assert.equal(validateOidcCallback(query, tx, now).ok, false);
});
test("rejects replay, expiry, future timestamps and absent transaction", () => {
  const { tx, query } = fixture();
  for (const candidate of [{ ...tx, consumed: true }, { ...tx, createdAt: now - 300001 },
    { ...tx, createdAt: now + 1 }, null]) {
    assert.equal(validateOidcCallback(query, candidate, now).ok, false);
  }
});
test("rejects provider errors, duplicate codes and implicit-flow tokens", () => {
  const { tx, query } = fixture();
  query.set("error", "access_denied");
  assert.equal(validateOidcCallback(query, tx, now).reason, "provider_error");
  query.delete("error"); query.append("code", "another");
  assert.equal(validateOidcCallback(query, tx, now).ok, false);
  query.delete("code"); query.set("code", "abc123XYZ"); query.set("id_token", "forbidden");
  assert.equal(validateOidcCallback(query, tx, now).ok, false);
});
