import { NextResponse } from "next/server";
import { resolveServerAuthorization } from "../../../lib/auth-boundary";

export const dynamic = "force-dynamic";

/**
 * This endpoint never discloses a principal until server authentication is
 * implemented. Avoid cacheable authenticated responses.
 */
export async function GET() {
  const auth = await resolveServerAuthorization();
  if (auth.kind === "unavailable")
    return NextResponse.json({ status: "unavailable" }, {
      status: 503,
      headers: { "Cache-Control": "no-store", "Pragma": "no-cache" },
    });
  if (auth.kind === "unauthenticated")
    return NextResponse.json({ status: "anonymous" }, {
      status: 401,
      headers: { "Cache-Control": "no-store", "Pragma": "no-cache" },
    });
  return NextResponse.json({ status: "authenticated" }, {
    headers: { "Cache-Control": "no-store", "Pragma": "no-cache" },
  });
}
