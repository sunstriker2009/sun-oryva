import test from "node:test";
import assert from "node:assert/strict";
import { completeOidcCallback } from "../lib/oidc-callback-orchestrator.mjs";
import { createOidcPayloadProtector } from "../lib/oidc-payload-protector.mjs";
import { createOidcTransactionStore } from "../lib/oidc-transaction-store.mjs";
import { createOidcBindingCookie } from "../lib/oidc-browser-binding.mjs";

const state = "s".repeat(43), verifier = "v".repeat(43), nonce = "n".repeat(43);
const oidc = {
  issuer: "https://id.example.test/realms/oryva", clientId: "oryva-console",
  redirectUri: "https://console.example.test/auth/callback",
  tokenEndpoint: "https://id.example.test/token", jwksUri: "https://id.example.test/certs",
};
const payloadProtector = createOidcPayloadProtector(Buffer.alloc(32, 7));
const query = new URLSearchParams({ state, code: "valid-code" });
function fixture() {
  const records = new Map(), calls = [];
  const db = { async query(sql, args) {
    if (sql.includes("INSERT")) {
      if (records.has(args[0])) return { rowCount: 0, rows: [] };
      records.set(args[0], { binding: args[1], payload: args[2], used: false });
      return { rowCount: 1, rows: [{ state_hash: args[0] }] };
    }
    const record = records.get(args[0]);
    if (!record || record.binding !== args[1] || record.used)
      return { rowCount: 0, rows: [] };
    record.used = true;
    calls.push("consume");
    return { rowCount: 1, rows: [{ sealed_payload: record.payload }] };
  }};
  const transactionStore = createOidcTransactionStore(db, Buffer.alloc(32, 9));
  const cookie = createOidcBindingCookie();
  const cookieHeader = cookie.name + "=" + cookie.value;
  const sessionStore = { async create({ subject, issuer }) {
    calls.push("session");
    return { token: "t".repeat(43), cookie: { name: "__Host-oryva-session", value: "t".repeat(43) } };
  }};
  const exchange = async ({ verifier: supplied }) => {
    assert.equal(supplied, verifier);
    calls.push("exchange");
    return { idToken: "opaque-id-token" };
  };
  const verify = async ({ nonce: supplied }) => {
    assert.equal(supplied, nonce);
    calls.push("verify");
    return { subject: "subject-1", issuer: oidc.issuer, audience: oidc.clientId, expiresAt: 1794650300 };
  };
  return { calls, transactionStore, cookieHeader, sessionStore, exchange, verify,
    async issue() {
      await transactionStore.issue({ state, browserBinding: cookie.value,
        sealedPayload: payloadProtector.seal({ verifier, nonce }) });
    },
    args: { query, cookieHeader, transactionStore, payloadProtector, sessionStore, oidc,
      exchange, verify, now: 1794650000 },
  };
}
test("consumes transaction before exchange, validates identity before creating session", async () => {
  const f = fixture(); await f.issue();
  const result = await completeOidcCallback(f.args);
  assert.equal(result.cookie.name, "__Host-oryva-session");
  assert.deepEqual(f.calls, ["consume", "exchange", "verify", "session"]);
  await assert.rejects(completeOidcCallback(f.args), /unavailable/);
  assert.deepEqual(f.calls, ["consume", "exchange", "verify", "session"]);
});
test("wrong browser binding cannot exchange or create a session", async () => {
  const f = fixture(); await f.issue();
  await assert.rejects(completeOidcCallback({ ...f.args,
    cookieHeader: createOidcBindingCookie().name + "=" + createOidcBindingCookie().value }), /unavailable/);
  assert.deepEqual(f.calls, []);
});
test("invalid provider callback fails before consuming transaction", async () => {
  const f = fixture(); await f.issue();
  await assert.rejects(completeOidcCallback({ ...f.args,
    query: new URLSearchParams({ state, error: "access_denied" }) }), /unavailable/);
  assert.deepEqual(f.calls, []);
  await completeOidcCallback(f.args);
});
test("invalid verified identity fails closed without session", async () => {
  const f = fixture(); await f.issue();
  await assert.rejects(completeOidcCallback({ ...f.args,
    verify: async () => ({ subject: "subject-1", issuer: "https://evil.test",
      audience: oidc.clientId, expiresAt: 1794650300 }) }), /unavailable/);
  assert.deepEqual(f.calls, ["consume", "exchange"]);
  await assert.rejects(completeOidcCallback(f.args), /unavailable/);
});
test("token exchange failure consumes transaction but never creates session", async () => {
  const f = fixture(); await f.issue();
  await assert.rejects(completeOidcCallback({ ...f.args,
    exchange: async () => { throw Error("sensitive token error"); } }),
    e => e.message === "OIDC callback unavailable");
  assert.deepEqual(f.calls, ["consume"]);
});
