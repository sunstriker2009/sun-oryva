import { randomBytes, createHash } from "node:crypto";

const base64url = value => Buffer.from(value).toString("base64url");

/** Server-generated, short-lived PKCE transaction. Never log or persist verifier in browser JS. */
export function createOidcTransaction() {
  const verifier = base64url(randomBytes(32));
  return Object.freeze({
    verifier,
    challenge: base64url(createHash("sha256").update(verifier, "ascii").digest()),
    state: base64url(randomBytes(32)),
    nonce: base64url(randomBytes(32)),
  });
}

export function buildOidcAuthorizationUrl(config, metadata, transaction) {
  if (!config || !metadata || !transaction) throw new Error("OIDC setup incomplete");
  if (typeof metadata.authorizationEndpoint !== "string" ||
      typeof config.redirectUri !== "string" ||
      typeof config.clientId !== "string")
    throw new Error("OIDC setup incomplete");
  const url = new URL(metadata.authorizationEndpoint);
  if (url.protocol !== "https:" && url.hostname !== "localhost" &&
      url.hostname !== "127.0.0.1" && url.hostname !== "[::1]")
    throw new Error("Insecure authorization endpoint");
  if (url.search || url.hash) throw new Error("Unexpected authorization endpoint parameters");
  for (const key of ["verifier", "challenge", "state", "nonce"]) {
    if (typeof transaction[key] !== "string" ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(transaction[key]))
      throw new Error("Invalid PKCE transaction");
  }
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("state", transaction.state);
  url.searchParams.set("nonce", transaction.nonce);
  url.searchParams.set("code_challenge", transaction.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}
