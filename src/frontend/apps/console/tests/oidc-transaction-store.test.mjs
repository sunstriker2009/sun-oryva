import test from "node:test";
import assert from "node:assert/strict";
import { createOidcTransactionStore, createBrowserBinding } from "../lib/oidc-transaction-store.mjs";

const state = "s".repeat(43), binding = "b".repeat(43);
const sealedPayload = Buffer.alloc(64, 7).toString("base64");
function fakeDb() {
  const rows = new Map();
  return { rows, async query(sql, params) {
    if (sql.includes("INSERT")) {
      const [hash, browser, payload, now] = params;
      if (rows.has(hash)) return { rowCount: 0, rows: [] };
      rows.set(hash, { browser, payload, created: new Date(now).getTime(), expiry: new Date(now).getTime() + 300000, consumed: false });
      return { rowCount: 1, rows: [{ state_hash: hash }] };
    }
    const [hash, browser, now] = params;
    const row = rows.get(hash), at = new Date(now).getTime();
    if (!row || row.browser !== browser || row.consumed || at < row.created || at >= row.expiry)
      return { rowCount: 0, rows: [] };
    row.consumed = true;
    return { rowCount: 1, rows: [{ sealed_payload: row.payload }] };
  }};
}
test("issue hashes browser binding and state, never stores raw values", async () => {
  const db = fakeDb(), store = createOidcTransactionStore(db, Buffer.alloc(32, 9));
  await store.issue({ state, browserBinding: binding, sealedPayload });
  assert.equal(db.rows.has(state), false);
  assert.equal(db.rows.size, 1);
  assert.equal(await store.consume({ state, browserBinding: binding }), sealedPayload);
  await assert.rejects(store.consume({ state, browserBinding: binding }), /unavailable/);
});
test("parallel consumes yield exactly one winner", async () => {
  const store = createOidcTransactionStore(fakeDb(), Buffer.alloc(32, 9));
  await store.issue({ state, browserBinding: binding, sealedPayload });
  const results = await Promise.allSettled(Array.from({ length: 32 }, () => store.consume({ state, browserBinding: binding })));
  assert.equal(results.filter(x => x.status === "fulfilled").length, 1);
});
test("wrong browser, expiry and duplicate state fail closed", async () => {
  const store = createOidcTransactionStore(fakeDb(), Buffer.alloc(32, 9));
  const now = new Date("2026-11-14T00:00:00Z");
  await store.issue({ state, browserBinding: binding, sealedPayload, now });
  await assert.rejects(store.issue({ state, browserBinding: binding, sealedPayload, now }), /unavailable/);
  await assert.rejects(store.consume({ state, browserBinding: "c".repeat(43), now }), /unavailable/);
  await assert.rejects(store.consume({ state, browserBinding: binding, now: new Date(now.getTime() + 300000) }), /unavailable/);
});
test("rejects invalid inputs and db errors without disclosing details", async () => {
  const store = createOidcTransactionStore({ query: async () => { throw Error("private database detail"); } }, Buffer.alloc(32, 9));
  await assert.rejects(store.issue({ state, browserBinding: binding, sealedPayload }), e => e.message === "OIDC transaction unavailable");
  await assert.rejects(store.consume({ state, browserBinding: binding }), e => e.message === "OIDC transaction unavailable");
  await assert.rejects(store.issue({ state, browserBinding: binding, sealedPayload: "invalid%%" }), /unavailable/);
  assert.match(createBrowserBinding(), /^[A-Za-z0-9_-]{43}$/);
});
