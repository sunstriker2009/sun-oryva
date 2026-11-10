import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOryvaSessionView, getOryvaSessionScreen,
  getOryvaSessionNavigation, safeOryvaReturnPath } from "../dist/index.js";

const master = { subject: "master-1", role: "master", state: "active" };
test("session display fails closed for malformed, pending and disabled identities", () => {
  for (const principal of [null, {}, { ...master, state: "pending" },
    { ...master, state: "disabled" }, { ...master, role: "superuser" }]) {
    const session = parseOryvaSessionView({ status: "authenticated", principal });
    assert.equal(session.status, "anonymous");
    assert.deepEqual(getOryvaSessionNavigation(session), []);
  }
});
test("session status maps to distinct safe UI states", () => {
  assert.equal(getOryvaSessionScreen(parseOryvaSessionView({ status: "expired" })),
    "session-expired");
  assert.equal(getOryvaSessionScreen(parseOryvaSessionView({ status: "unavailable" })),
    "service-unavailable");
  const session = parseOryvaSessionView({ status: "authenticated", principal: master });
  assert.equal(getOryvaSessionScreen(session), "workspace");
  assert.ok(getOryvaSessionNavigation(session).some(x => x.id === "security"));
});
test("return paths reject external and ambiguous redirect targets", () => {
  for (const value of ["https://evil.example", "//evil.example", "/\\evil.example",
    "/%2f%2fevil.example", "/%5cevil.example", "/foo\nbar", "", null])
    assert.equal(safeOryvaReturnPath(value), "/");
  assert.equal(safeOryvaReturnPath("/workspace?tab=users#top"),
    "/workspace?tab=users#top");
  assert.equal(safeOryvaReturnPath("/x", "/safe"), "/x");
});
