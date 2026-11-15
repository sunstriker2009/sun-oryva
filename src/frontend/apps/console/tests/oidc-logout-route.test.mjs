import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const route = readFileSync(new URL("../app/api/auth/logout/route.ts", import.meta.url), "utf8");

test("logout requires same-origin POST and revokes server-side session before clearing cookies", () => {
  assert.match(route, /export async function POST/);
  assert.doesNotMatch(route, /export async function GET/);
  assert.match(route, /origin !== config\.consoleOrigin/);
  assert.match(route, /target\.origin !== config\.consoleOrigin/);
  assert.match(route, /target\.pathname !== "\/api\/auth\/logout"/);
  assert.match(route, /target\.search !== ""/);
  assert.match(route, /target\.hash !== ""/);
  assert.match(route, /sec-fetch-site/);
  assert.match(route, /readSessionCookie/);
  assert.match(route, /createOidcSessionStore\(pool\)\.revoke/);
  assert.match(route, /oidcLogoutResponse/);
  assert.match(route, /status: 503/);
  assert.match(route, /await pool\.end\(\)/);
  assert.doesNotMatch(route, /nextUrl|searchParams|returnTo|NEXT_PUBLIC_/);
});
