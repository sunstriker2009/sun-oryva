import { createHash, createHmac, randomBytes } from "node:crypto";

const opaque = value => typeof value === "string" && /^[A-Za-z0-9_-]{43,128}$/.test(value);
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const keyed = (key, value) => createHmac("sha256", key).update(value, "utf8").digest("hex");
const invalid = () => new Error("OIDC transaction unavailable");

/**
 * PostgreSQL-backed, cross-replica single-use OIDC transaction repository.
 * db.query(sql, params) must use parameterized queries; no SQL interpolation.
 * The caller must encrypt transaction secrets before passing sealedPayload.
 * browserBinding is an independent random HttpOnly cookie secret.
 */
export function createOidcTransactionStore(db, hmacKey) {
  if (!db || typeof db.query !== "function" ||
      !Buffer.isBuffer(hmacKey) || hmacKey.length < 32) throw invalid();

  return Object.freeze({
    async issue({ state, browserBinding, sealedPayload, now = new Date() }) {
      if (!opaque(state) || !opaque(browserBinding) ||
          typeof sealedPayload !== "string" || sealedPayload.length < 32 ||
          sealedPayload.length > 16384 || !/^[A-Za-z0-9+/]+={0,2}$/.test(sealedPayload) ||
          !(now instanceof Date) || !Number.isFinite(now.getTime())) throw invalid();
      const stateHash = digest(state);
      const bindingHash = keyed(hmacKey, browserBinding);
      try {
        const result = await db.query(
          `INSERT INTO oidc_browser_transactions
           (state_hash, browser_binding_hash, sealed_payload, created_at, expires_at)
           VALUES ($1, $2, $3, $4, $4::timestamptz + interval '5 minutes')
           ON CONFLICT (state_hash) DO NOTHING
           RETURNING state_hash`,
          [stateHash, bindingHash, sealedPayload, now.toISOString()]
        );
        if (result.rowCount !== 1) throw invalid();
      } catch { throw invalid(); }
    },
    async consume({ state, browserBinding, now = new Date() }) {
      if (!opaque(state) || !opaque(browserBinding) ||
          !(now instanceof Date) || !Number.isFinite(now.getTime())) throw invalid();
      try {
        const result = await db.query(
          `UPDATE oidc_browser_transactions
           SET consumed_at = $3
           WHERE state_hash = $1 AND browser_binding_hash = $2
             AND consumed_at IS NULL AND created_at <= $3 AND expires_at > $3
           RETURNING sealed_payload`,
          [digest(state), keyed(hmacKey, browserBinding), now.toISOString()]
        );
        if (result.rowCount !== 1 || typeof result.rows?.[0]?.sealed_payload !== "string")
          throw invalid();
        return result.rows[0].sealed_payload;
      } catch { throw invalid(); }
    },
  });
}

export function createBrowserBinding() {
  return randomBytes(32).toString("base64url");
}
