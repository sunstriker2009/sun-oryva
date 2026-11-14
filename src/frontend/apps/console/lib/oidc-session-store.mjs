import { createHash, randomBytes } from "node:crypto";

const fail = () => new Error("OIDC session unavailable");
const validToken = s => typeof s === "string" && /^[A-Za-z0-9_-]{43}$/.test(s);
const hash = s => createHash("sha256").update(s, "utf8").digest("hex");

export const SESSION_COOKIE = "__Host-oryva-session";
export const SESSION_LIFETIME_SECONDS = 1800;

export function sessionCookie(token) {
  if (!validToken(token)) throw fail();
  return Object.freeze({
    name: SESSION_COOKIE, value: token,
    options: Object.freeze({ httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: SESSION_LIFETIME_SECONDS }),
  });
}

export function expiredSessionCookie() {
  return Object.freeze({
    name: SESSION_COOKIE, value: "",
    options: Object.freeze({ httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 0 }),
  });
}

export function readSessionCookie(header) {
  if (typeof header !== "string" || header.length > 8192) throw fail();
  const values = header.split(";").map(x => x.trim()).filter(x => x.startsWith(SESSION_COOKIE + "="));
  if (values.length !== 1) throw fail();
  const parts = values[0].split("=");
  if (parts.length !== 2 || !validToken(parts[1])) throw fail();
  return parts[1];
}

/**
 * Opaque, server-side session store. The principal is an identity only:
 * consumers MUST resolve current roles, active status and permissions through
 * the trusted backend on every privileged request.
 */
export function createOidcSessionStore(db) {
  if (!db || typeof db.query !== "function") throw fail();
  return Object.freeze({
    async create({ subject, issuer, now = new Date() }) {
      if (typeof subject !== "string" || !subject || subject.length > 256 ||
          typeof issuer !== "string" || !issuer || issuer.length > 2048 ||
          !(now instanceof Date) || !Number.isFinite(now.getTime())) throw fail();
      const token = randomBytes(32).toString("base64url");
      try {
        const result = await db.query(
          `INSERT INTO oidc_console_sessions
           (session_hash, subject, issuer, created_at, expires_at)
           VALUES ($1, $2, $3, $4, $4::timestamptz + interval '30 minutes')
           RETURNING session_hash`,
          [hash(token), subject, issuer, now.toISOString()]
        );
        if (result.rowCount !== 1) throw fail();
        return Object.freeze({ token, cookie: sessionCookie(token) });
      } catch { throw fail(); }
    },
    async resolve({ token, now = new Date() }) {
      if (!validToken(token) || !(now instanceof Date) || !Number.isFinite(now.getTime())) throw fail();
      try {
        const result = await db.query(
          `SELECT subject, issuer FROM oidc_console_sessions
           WHERE session_hash = $1 AND revoked_at IS NULL
             AND created_at <= $2 AND expires_at > $2`,
          [hash(token), now.toISOString()]
        );
        if (result.rowCount !== 1 || typeof result.rows?.[0]?.subject !== "string" ||
            !result.rows[0].subject || typeof result.rows[0].issuer !== "string" ||
            !result.rows[0].issuer) throw fail();
        return Object.freeze({ subject: result.rows[0].subject, issuer: result.rows[0].issuer });
      } catch { throw fail(); }
    },
    async revoke({ token, now = new Date() }) {
      if (!validToken(token) || !(now instanceof Date) || !Number.isFinite(now.getTime())) throw fail();
      try {
        const result = await db.query(
          `UPDATE oidc_console_sessions SET revoked_at = $2
           WHERE session_hash = $1 AND revoked_at IS NULL
           RETURNING session_hash`,
          [hash(token), now.toISOString()]
        );
        return result.rowCount === 1;
      } catch { throw fail(); }
    },
  });
}
