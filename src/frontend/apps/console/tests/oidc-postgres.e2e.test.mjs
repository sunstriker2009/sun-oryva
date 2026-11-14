import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Client } from "pg";
import { createOidcTransactionStore } from "../lib/oidc-transaction-store.mjs";
import { createOidcPayloadProtector } from "../lib/oidc-payload-protector.mjs";

const connectionString = process.env.ORYVA_OIDC_TEST_DATABASE_URL;
const schemaPath = fileURLToPath(new URL("../db/001_oidc_browser_transactions.sql", import.meta.url));
const state = "s".repeat(43), browserBinding = "b".repeat(43);
const protector = createOidcPayloadProtector(Buffer.alloc(32, 7));
const sealedPayload = protector.seal({ verifier: "v".repeat(43), nonce: "n".repeat(43) });

test("real PostgreSQL OIDC transaction schema and concurrency", { skip: !connectionString }, async () => {
  const admin = new Client({ connectionString });
  await admin.connect();
  // Test DB must be isolated: schema objects are created in a private test schema.
  const schema = "oryva_oidc_test_" + process.pid;
  if (!/^oryva_oidc_test_\d+$/.test(schema)) throw Error("Unsafe test schema");
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.query(`SET search_path TO "${schema}"`);
    const ddl = await readFile(schemaPath, "utf8");
    await admin.query(ddl);
    await admin.query(ddl); // idempotence
    const clients = await Promise.all(Array.from({ length: 8 }, async () => {
      const client = new Client({ connectionString });
      await client.connect();
      await client.query(`SET search_path TO "${schema}"`);
      return client;
    }));
    try {
      const store = createOidcTransactionStore(admin, Buffer.alloc(32, 9));
      await store.issue({ state, browserBinding, sealedPayload });
      await assert.rejects(store.issue({ state, browserBinding, sealedPayload }), /unavailable/);
      await assert.rejects(store.consume({ state, browserBinding: "c".repeat(43) }), /unavailable/);
      const results = await Promise.allSettled(Array.from({ length: 32 }, (_, i) =>
        createOidcTransactionStore(clients[i % clients.length], Buffer.alloc(32, 9))
          .consume({ state, browserBinding })));
      const winners = results.filter(x => x.status === "fulfilled");
      assert.equal(winners.length, 1);
      assert.deepEqual(protector.open(winners[0].value), { verifier: "v".repeat(43), nonce: "n".repeat(43) });
      await assert.rejects(store.consume({ state, browserBinding }), /unavailable/);
      const future = new Date(Date.now() + 301000);
      const otherState = "t".repeat(43);
      await store.issue({ state: otherState, browserBinding, sealedPayload });
      await assert.rejects(store.consume({ state: otherState, browserBinding, now: future }), /unavailable/);
      const count = await admin.query("SELECT count(*)::integer AS count, count(consumed_at)::integer AS consumed FROM oidc_browser_transactions");
      assert.equal(count.rows[0].count, 2);
      assert.equal(count.rows[0].consumed, 1);
    } finally {
      await Promise.all(clients.map(c => c.end()));
    }
  } finally {
    await admin.query("SET search_path TO public");
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin.end();
  }
});
