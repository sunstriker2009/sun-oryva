import { NextResponse } from "next/server";
import { parseOryvaOidcPublicConfig } from "@sun-security/core";

export const dynamic = "force-dynamic";

const headers = { "Cache-Control": "no-store", "Pragma": "no-cache" };

/**
 * Exposes only public, validated OIDC client metadata.
 * This does not establish an authenticated session or trust browser claims.
 */
export async function GET() {
  try {
    const config = parseOryvaOidcPublicConfig({
      issuer: process.env.ORYVA_OIDC_ISSUER,
      clientId: process.env.ORYVA_OIDC_CLIENT_ID,
      redirectUri: process.env.ORYVA_OIDC_REDIRECT_URI,
      postLogoutRedirectUri: process.env.ORYVA_OIDC_POST_LOGOUT_REDIRECT_URI,
    }, { allowLoopbackHttp: process.env.NODE_ENV !== "production" });
    return NextResponse.json(config, { headers });
  } catch {
    return NextResponse.json({ status: "unavailable" }, { status: 503, headers });
  }
}
