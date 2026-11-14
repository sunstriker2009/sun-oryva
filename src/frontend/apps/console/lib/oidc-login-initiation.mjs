import { createOidcTransaction, buildOidcAuthorizationUrl } from "./oidc-transaction.mjs";
import { issueBrowserBoundTransaction } from "./oidc-browser-binding.mjs";

const fail = () => new Error("OIDC login initiation unavailable");

/**
 * Server-only initiation. Persist the transaction BEFORE returning an
 * authorization URL. No public route is registered by this component.
 */
export async function initiateOidcLogin({
  config, metadata, transactionStore, payloadProtector,
  generate = createOidcTransaction,
}) {
  if (!config || !metadata || !transactionStore ||
      typeof transactionStore.issue !== "function" ||
      !payloadProtector || typeof payloadProtector.seal !== "function" ||
      typeof generate !== "function") throw fail();
  try {
    const transaction = generate();
    if (!transaction || typeof transaction !== "object") throw fail();
    // Validate all URL inputs and PKCE values before writing to PostgreSQL.
    const authorizationUrl = buildOidcAuthorizationUrl(config, metadata, transaction);
    const sealedPayload = payloadProtector.seal({
      verifier: transaction.verifier, nonce: transaction.nonce,
    });
    const cookie = await issueBrowserBoundTransaction({
      store: transactionStore, state: transaction.state, sealedPayload,
    });
    // The caller must set the Secure HttpOnly binding cookie on the redirect
    // response; never include transaction secrets in HTML or client JSON.
    return Object.freeze({ authorizationUrl, cookie });
  } catch { throw fail(); }
}
