import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../app/", import.meta.url);
test("public console has no login form or administrative route", () => {
  const pages = readdirSync(root).filter(x => !x.startsWith("."));
  assert.equal(pages.includes("admin"), false);
  assert.equal(pages.includes("api"), false);
  assert.equal(pages.includes("login"), false);
  const home = readFileSync(join(root.pathname, "page.tsx"), "utf8");
  assert.match(home, /Authentication integration pending/);
  assert.doesNotMatch(home, /<form|type="password"/);
});
