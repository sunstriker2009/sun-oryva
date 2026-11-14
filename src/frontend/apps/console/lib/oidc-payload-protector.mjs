import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const AAD = Buffer.from("ORYVA:OIDC:TRANSACTION:v1", "utf8");
const fail = () => new Error("OIDC transaction payload unavailable");
const opaque = value => typeof value === "string" && /^[A-Za-z0-9_-]{43,128}$/.test(value);
const canonical = value => typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value) &&
  Buffer.from(value, "base64url").toString("base64url") === value;

/**
 * AES-256-GCM authenticated encryption of server-side OIDC transaction secrets.
 * Keep key material in a secrets manager; never persist plaintext verifiers/nonces.
 * State and browser binding are checked separately by the transaction store.
 */
export function createOidcPayloadProtector(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw fail();
  const secret = Buffer.from(key);
  return Object.freeze({
    seal({ verifier, nonce }) {
      if (!opaque(verifier) || !opaque(nonce)) throw fail();
      const iv = randomBytes(12);
      try {
        const cipher = createCipheriv("aes-256-gcm", secret, iv);
        cipher.setAAD(AAD);
        const plaintext = Buffer.from(JSON.stringify({ verifier, nonce }), "utf8");
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([Buffer.from([1]), iv, tag, ciphertext]).toString("base64");
      } catch { throw fail(); }
    },
    open(sealed) {
      if (typeof sealed !== "string" || sealed.length < 44 || sealed.length > 16384 ||
          !/^[A-Za-z0-9+/]+={0,2}$/.test(sealed)) throw fail();
      try {
        const raw = Buffer.from(sealed, "base64");
        if (raw.toString("base64") !== sealed || raw.length < 30 || raw[0] !== 1) throw fail();
        const decipher = createDecipheriv("aes-256-gcm", secret, raw.subarray(1, 13));
        decipher.setAAD(AAD);
        decipher.setAuthTag(raw.subarray(13, 29));
        const plaintext = Buffer.concat([decipher.update(raw.subarray(29)), decipher.final()]);
        const parsed = JSON.parse(plaintext.toString("utf8"));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
            Object.keys(parsed).sort().join(",") !== "nonce,verifier" ||
            !opaque(parsed.verifier) || !opaque(parsed.nonce)) throw fail();
        return Object.freeze({ verifier: parsed.verifier, nonce: parsed.nonce });
      } catch { throw fail(); }
    },
  });
}
