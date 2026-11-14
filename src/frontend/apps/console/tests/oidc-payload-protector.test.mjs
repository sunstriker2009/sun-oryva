import test from "node:test";
import assert from "node:assert/strict";
import { createOidcPayloadProtector } from "../lib/oidc-payload-protector.mjs";

const key = Buffer.alloc(32, 7);
const verifier = "v".repeat(43), nonce = "n".repeat(43);

test("encrypts and decrypts transaction secrets without plaintext persistence", () => {
  const protector = createOidcPayloadProtector(key);
  const sealed = protector.seal({ verifier, nonce });
  assert.deepEqual(protector.open(sealed), { verifier, nonce });
  assert.equal(sealed.includes(verifier), false);
  assert.notEqual(sealed, protector.seal({ verifier, nonce }));
});
test("rejects tampered, truncated and unsupported version payloads", () => {
  const protector = createOidcPayloadProtector(key);
  const raw = Buffer.from(protector.seal({ verifier, nonce }), "base64");
  for (const index of [0, 1, 13, 29, raw.length - 1]) {
    const tampered = Buffer.from(raw);
    tampered[index] ^= 1;
    assert.throws(() => protector.open(tampered.toString("base64")), /unavailable/);
  }
  assert.throws(() => protector.open(raw.subarray(0, 20).toString("base64")), /unavailable/);
});
test("rejects incorrect key, malformed inputs and noncanonical encoding", () => {
  const protector = createOidcPayloadProtector(key);
  const sealed = protector.seal({ verifier, nonce });
  assert.throws(() => createOidcPayloadProtector(Buffer.alloc(16)), /unavailable/);
  assert.throws(() => protector.seal({ verifier: "short", nonce }), /unavailable/);
  assert.throws(() => protector.open(sealed + " "), /unavailable/);
  assert.throws(() => createOidcPayloadProtector(Buffer.alloc(32, 8)).open(sealed), /unavailable/);
});
test("works with the sealedPayload contract of the transaction store", async () => {
  const protector = createOidcPayloadProtector(key);
  const { createOidcTransactionStore } = await import("../lib/oidc-transaction-store.mjs");
  let record;
  const db = { async query(sql, params) {
    if (sql.includes("INSERT")) {
      record = { hash: params[0], browser: params[1], payload: params[2] };
      return { rowCount: 1, rows: [{ state_hash: record.hash }] };
    }
    if (record && params[0] === record.hash && params[1] === record.browser) {
      const payload = record.payload;
      record = undefined;
      return { rowCount: 1, rows: [{ sealed_payload: payload }] };
    }
    return { rowCount: 0, rows: [] };
  }};
  const store = createOidcTransactionStore(db, Buffer.alloc(32, 9));
  const state = "s".repeat(43), browserBinding = "b".repeat(43);
  await store.issue({ state, browserBinding, sealedPayload: protector.seal({ verifier, nonce }) });
  const encrypted = await store.consume({ state, browserBinding });
  assert.deepEqual(protector.open(encrypted), { verifier, nonce });
});
