import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Client } from "pg";
import { createOidcSessionStore } from "../lib/oidc-session-store.mjs";

const connectionString = process.env.ORYVA_OIDC_TEST_DATABASE_URL;
const ddlPath = fileURLToPath(new URL("../db/002_oidc_console_sessions.sql", import.meta.url));

test("PostgreSQL session lifecycle, cross-connection revocation and expiry", { skip: !connectionString }, async () => {
  const admin = new Client({ connectionString });
  await admin.connect();
  const schema = "oryva_session_test_" + process.pid;
  if (!/^oryva_session_test_\d+$/.test(schema)) throw Error("Unsafe schema");
  const clients = [];
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.query(`SET search_path TO "${schema}"`);
    const ddl = await readFile(ddlPath, "utf8");
    await admin.query(ddl);
    await admin.query(ddl);
    for (let i = 0; i < 8; i++) {
      const client = new Client({ connectionString });
      await client.connect();
      clients.push(client);
      await client.query(`SET search_path TO "${schema}"`);
    }
    const creator = createOidcSessionStore(admin);
    const now = new Date();
    const { token, cookie } = await creator.create({ subject: "subject-1", issuer: "https://id.example.test", now });
    assert.equal(cookie.options.httpOnly, true);
    assert.equal(cookie.options.secure, true);
    assert.equal(cookie.options.maxAge, 1800);
    const stored = await admin.query("SELECT session_hash, subject, issuer FROM oidc_console_sessions");
    assert.equal(stored.rowCount, 1);
    assert.notEqual(stored.rows[0].session_hash, token);
    assert.equal(stored.rows[0].subject, "subject-1");
    const readers = clients.map(c => createOidcSessionStore(c));
    const identities = await Promise.all(readers.map(store => store.resolve({ token, now })));
    assert.equal(identities.length, 8);
    assert.ok(identities.every(x => x.subject === "subject-1" && x.issuer === "https://id.example.test"));
    const revoked = await Promise.all(readers.map(store => store.revoke({ token, now })));
    assert.equal(revoked.filter(Boolean).length, 1);
    await assert.rejects(creator.resolve({ token, now }), /unavailable/);
    await Promise.all(readers.map(store => assert.rejects(store.resolve({ token, now }), /unavailable/)));
    const { token: expiring } = await creator.create({ subject: "subject-2", issuer: "https://id.example.test", now });
    await assert.rejects(creator.resolve({ token: expiring, now: new Date(now.getTime() + 1800000) }), /unavailable/);
    const { token: other } = await creator.create({ subject: "subject-3", issuer: "https://id.example.test", now });
    assert.deepEqual(await creator.resolve({ token: other, now }), {
      subject: "subject-3", issuer: "https://id.example.test",
    });
    const badToken = "x".repeat(43);
    await assert.rejects(creator.resolve({ token: badToken, now }), /unavailable/);
  } finally {
    await Promise.allSettled(clients.map(c => c.end()));
    await admin.query("SET search_path TO public");
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin.end();
  }
});
