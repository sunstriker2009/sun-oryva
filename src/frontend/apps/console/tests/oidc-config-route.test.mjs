import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const source = readFileSync(join(new URL("../", import.meta.url).pathname, "app/api/auth/config/route.ts"), "utf8");

test("OIDC public configuration route validates settings and fails closed", () => {
  assert.match(source, /parseOryvaOidcPublicConfig/);
  assert.match(source, /process\.env\.ORYVA_OIDC_ISSUER/);
  assert.match(source, /process\.env\.ORYVA_OIDC_CLIENT_ID/);
  assert.match(source, /process\.env\.ORYVA_OIDC_REDIRECT_URI/);
  assert.match(source, /process\.env\.ORYVA_OIDC_POST_LOGOUT_REDIRECT_URI/);
  assert.match(source, /NODE_ENV !== "production"/);
  assert.match(source, /status: 503/);
  assert.match(source, /"Cache-Control": "no-store"/);
  assert.doesNotMatch(source, /CLIENT_SECRET|PRIVATE_KEY|ACCESS_TOKEN|REFRESH_TOKEN/);
});
