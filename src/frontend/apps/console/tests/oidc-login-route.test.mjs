import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const route = readFileSync(new URL("../app/api/auth/login/route.ts", import.meta.url), "utf8");

test("login route wires validated discovery, persistent single-use state and server-side secrets", () => {
  for (const name of ["loadOidcRuntimeConfig", "createOidcTransactionStore",
    "createOidcPayloadProtector", "initiateOidcLogin", "oidcAuthorizationResponse"]) {
    assert.match(route, new RegExp(name));
  }
  assert.match(route, /export const runtime = "nodejs"/);
  assert.match(route, /connectionTimeoutMillis: 3000/);
  assert.match(route, /await pool\.end\(\)/);
  assert.doesNotMatch(route, /request\.nextUrl|searchParams|NEXT_PUBLIC_/);
  assert.match(route, /status: 503/);
});
