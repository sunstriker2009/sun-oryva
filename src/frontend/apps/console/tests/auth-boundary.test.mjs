import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const read = path => readFileSync(join(root, path), "utf8");
test("all protected pages invoke server-side resource guards", () => {
  for (const resource of ["workspace", "users", "audit", "security"]) {
    const page = read(`app/${resource}/page.tsx`);
    assert.match(page, new RegExp(`requireServerResource\\("${resource}"\\)`));
  }
});
test("default resolver denies all access and session endpoint disables caching", () => {
  const boundary = read("lib/auth-boundary.ts");
  assert.match(boundary, /return \{ kind: "unavailable" \}/);
  const endpoint = read("app/api/session/route.ts");
  assert.match(endpoint, /"Cache-Control": "no-store"/);
  assert.match(endpoint, /status: 503/);
});
test("role gate only grants master security and master-admin user/audit access", () => {
  const source = read("lib/auth-boundary.ts");
  assert.match(source, /case "security": return authorization.role === "master"/);
  assert.match(source, /authorization.role === "master" \|\| authorization.role === "admin"/);
});
