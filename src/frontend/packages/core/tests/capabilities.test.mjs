import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOryvaPrincipal, hasOryvaCapability, getOryvaNavigation } from "../dist/index.js";

const p = (role, state = "active") => ({ subject: "subject-1", role, state });
test("invalid and unverified principals fail closed", () => {
  for (const value of [null, {}, [], { subject: "", role: "master", state: "active" },
    { subject: "x", role: "owner", state: "active" }])
    assert.equal(parseOryvaPrincipal(value), null);
  for (const state of ["disabled", "pending", "unknown"]) {
    const identity = parseOryvaPrincipal(p("master", state));
    assert.equal(hasOryvaCapability(identity, "createAdmin"), false);
    assert.deepEqual(getOryvaNavigation(identity), []);
  }
  assert.equal(hasOryvaCapability(null, "viewWorkspace"), false);
});
test("only active master has admin creation and security settings", () => {
  for (const role of ["master", "admin", "viewer"]) {
    const identity = parseOryvaPrincipal(p(role));
    assert.equal(hasOryvaCapability(identity, "createAdmin"), role === "master");
    assert.equal(hasOryvaCapability(identity, "manageSecuritySettings"), role === "master");
  }
});
test("admin can manage viewers but not admins; viewer sees read-only workspace", () => {
  const admin = parseOryvaPrincipal(p("admin"));
  const viewer = parseOryvaPrincipal(p("viewer"));
  assert.equal(hasOryvaCapability(admin, "createViewer"), true);
  assert.equal(hasOryvaCapability(admin, "deactivateViewer"), true);
  assert.equal(hasOryvaCapability(admin, "deactivateAdmin"), false);
  assert.equal(hasOryvaCapability(viewer, "createViewer"), false);
  assert.deepEqual(getOryvaNavigation(viewer).map(x => x.id), ["workspace"]);
  assert.deepEqual(getOryvaNavigation(admin).map(x => x.id),
    ["workspace", "users", "audit", "operations"]);
});
