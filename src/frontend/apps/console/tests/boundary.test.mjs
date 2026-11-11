import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../app/", import.meta.url);
test("public console has no credential form or unguarded administration routes", () => {
  const pages = readdirSync(root).filter(x => !x.startsWith("."));
  assert.equal(pages.includes("login"), false);
  const home = readFileSync(join(root.pathname, "page.tsx"), "utf8");
  assert.match(home, /Authentication integration pending/);
  assert.doesNotMatch(home, /<form|type="password"/);

  for (const resource of ["workspace", "users", "audit", "security"]) {
    assert.ok(pages.includes(resource), `Expected protected route ${resource}`);
    const page = readFileSync(join(root.pathname, resource, "page.tsx"), "utf8");
    assert.ok(page.includes(`await requireServerResource("${resource}")`),
      `Route ${resource} must enforce its server-side guard`);
  }
  const resolver = readFileSync(new URL("../lib/auth-boundary.ts", import.meta.url), "utf8");
  assert.match(resolver, /return \{ kind: "unavailable" \}/);
});
