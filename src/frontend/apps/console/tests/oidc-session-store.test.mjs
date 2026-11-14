import test from "node:test";
import assert from "node:assert/strict";
import { createOidcSessionStore, sessionCookie, expiredSessionCookie, readSessionCookie } from "../lib/oidc-session-store.mjs";

function database() {
  const rows = new Map();
  return { rows, async query(sql, params) {
    if (sql.includes("INSERT")) {
      rows.set(params[0], { subject: params[1], issuer: params[2],
        created: Date.parse(params[3]), expires: Date.parse(params[3]) + 1800000, revoked: false });
      return { rowCount: 1, rows: [{ session_hash: params[0] }] };
    }
    const row = rows.get(params[0]);
    if (sql.includes("SELECT")) {
      const time = Date.parse(params[1]);
      return row && !row.revoked && row.created <= time && time < row.expires ?
        { rowCount: 1, rows: [{ subject: row.subject, issuer: row.issuer }] } :
        { rowCount: 0, rows: [] };
    }
    if (!row || row.revoked) return { rowCount: 0, rows: [] };
    row.revoked = true;
    return { rowCount: 1, rows: [{ session_hash: params[0] }] };
  }};
}
test("issues random opaque cookie and stores only its digest", async () => {
  const db = database(), store = createOidcSessionStore(db);
  const a = await store.create({ subject: "user-1", issuer: "https://id.example.test" });
  const b = await store.create({ subject: "user-1", issuer: "https://id.example.test" });
  assert.notEqual(a.token, b.token);
  assert.equal(db.rows.has(a.token), false);
  assert.equal(db.rows.size, 2);
  assert.equal(a.cookie.options.httpOnly, true);
  assert.equal(a.cookie.options.secure, true);
  assert.equal(a.cookie.options.sameSite, "lax");
  assert.equal(Object.hasOwn(a.cookie.options, "domain"), false);
  assert.deepEqual(await store.resolve({ token: a.token }), { subject: "user-1", issuer: "https://id.example.test" });
  assert.equal(readSessionCookie(`other=x; ${a.cookie.name}=${a.cookie.value}`), a.token);
  assert.equal(expiredSessionCookie().options.maxAge, 0);
  assert.equal(await store.revoke({ token: a.token }), true);
  await assert.rejects(store.resolve({ token: a.token }), /unavailable/);
  assert.equal(await store.revoke({ token: a.token }), false);
});
test("rejects expired sessions, invalid cookies and database errors", async () => {
  const store = createOidcSessionStore(database());
  const now = new Date("2026-11-14T00:00:00Z");
  const { token } = await store.create({ subject: "user", issuer: "https://id.example.test", now });
  await assert.rejects(store.resolve({ token, now: new Date(now.getTime() + 1800000) }), /unavailable/);
  const pair = `__Host-oryva-session=${token}`;
  for (const value of ["", "other=abc", pair + "; " + pair, "__Host-oryva-session=short", "x".repeat(8193)])
    assert.throws(() => readSessionCookie(value), /unavailable/);
  assert.throws(() => sessionCookie("short"), /unavailable/);
  const failing = createOidcSessionStore({ query: async () => { throw Error("private database secret"); } });
  await assert.rejects(failing.create({ subject: "user", issuer: "https://id.example.test" }),
    e => e.message === "OIDC session unavailable");
});
