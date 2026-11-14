/**
 * Isolated server-side OAuth authorization-code token transport.
 * Not a login implementation: caller must atomically consume a browser-bound
 * transaction first, and a vetted OIDC verifier must validate ID/access tokens.
 */
export async function exchangeAuthorizationCode({ endpoint, clientId, redirectUri, code, verifier, fetcher = fetch, timeoutMs = 5000, allowLoopbackHttp = false }) {
  const invalid = () => new Error("OIDC token exchange unavailable");
  let url;
  try { url = new URL(endpoint); } catch { throw invalid(); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(allowLoopbackHttp && loopback && url.protocol === "http:")) ||
      url.username || url.password || url.hash || url.search || !url.hostname) throw invalid();
  if (![clientId, redirectUri, code, verifier].every(x => typeof x === "string" && x.length > 0) ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(verifier) || code.length > 4096) throw invalid();
  let callback;
  try { callback = new URL(redirectUri); } catch { throw invalid(); }
  if ((callback.protocol !== "https:" && !(allowLoopbackHttp && loopback && callback.protocol === "http:")) ||
      callback.hash || callback.username || callback.password) throw invalid();
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15000) throw invalid();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: redirectUri,
      client_id: clientId, code_verifier: verifier,
    });
    const response = await fetcher(url.toString(), {
      method: "POST", redirect: "error", cache: "no-store",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(), signal: controller.signal,
    });
    if (!response.ok || !(response.headers.get("content-type") ?? "").toLowerCase().includes("application/json"))
      throw invalid();
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > 65536)) throw invalid();
    // Bound streaming reads even when Content-Length is absent or false.
    const reader = response.body?.getReader();
    if (!reader) throw invalid();
    const chunks = []; let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65536) throw invalid();
        chunks.push(value);
      }
    } finally { await reader.cancel().catch(() => {}); }
    const bytes = Buffer.concat(chunks.map(c => Buffer.from(c)));
    const data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!data || typeof data !== "object" || Array.isArray(data) ||
        typeof data.id_token !== "string" || data.id_token.length < 1 ||
        typeof data.access_token !== "string" || data.access_token.length < 1 ||
        data.token_type !== "Bearer" || !Number.isSafeInteger(data.expires_in) ||
        data.expires_in <= 0 || data.expires_in > 86400) throw invalid();
    return Object.freeze({
      idToken: data.id_token, accessToken: data.access_token,
      tokenType: data.token_type, expiresIn: data.expires_in,
    });
  } catch { throw invalid(); } finally { clearTimeout(timeout); }
}
