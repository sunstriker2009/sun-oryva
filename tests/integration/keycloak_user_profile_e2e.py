#!/usr/bin/env python3
"""Isolated Keycloak E2E for the production ownership-profile configuration tool."""

import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "infrastructure" / "keycloak"))
from ensure_oryva_user_profile import ensure_profile, validate_profile  # noqa: E402

base = os.environ.get("ORYVA_KEYCLOAK_URL", "http://127.0.0.1:8080").rstrip("/")
username = os.environ["ORYVA_TEST_KEYCLOAK_ADMIN"]
password = os.environ["ORYVA_TEST_KEYCLOAK_PASSWORD"]


def call(path, token=None, method="GET", payload=None, form=False):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        if form:
            data = urlencode(payload).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
    with urlopen(Request(base + path, data=data, headers=headers, method=method), timeout=20) as response:
        body = response.read()
        return response.status, json.loads(body) if body else None


def must_reject(profile):
    try:
        validate_profile(profile)
    except RuntimeError:
        return
    raise AssertionError("Unsafe ownership profile unexpectedly accepted")


status, credentials = call("/realms/master/protocol/openid-connect/token", method="POST", form=True,
                           payload={"grant_type": "password", "client_id": "admin-cli",
                                    "username": username, "password": password})
assert status == 200
admin_token = credentials["access_token"]
assert ensure_profile(base, "oryva", admin_token, apply=True) in (True, False)
assert ensure_profile(base, "oryva", admin_token, apply=False) is False
assert ensure_profile(base, "oryva", admin_token, apply=True) is False
print("PASS production profile tool applies, verifies and remains idempotent")

unsafe = {"attributes": [
    {"name": name, "multivalued": False,
     "permissions": {"view": ["admin", "user"], "edit": ["admin"]}}
    for name in ("oryva.bootstrap.owner", "oryva.provisioning.id")
]}
must_reject(unsafe)
unsafe["attributes"][0]["permissions"]["view"] = ["admin"]
unsafe["attributes"].append(dict(unsafe["attributes"][0]))
must_reject(unsafe)
print("PASS unsafe user-visible and duplicate ownership attributes fail closed")

probe_name = "oryva-profile-e2e-" + uuid.uuid4().hex[:12]
marker = str(uuid.uuid4())
probe_id = None
try:
    status, _ = call("/admin/realms/oryva/users", admin_token, "POST", {
        "username": probe_name,
        "email": probe_name + "@example.invalid",
        "enabled": False,
        "emailVerified": False,
        "attributes": {
            "oryva.bootstrap.owner": [marker],
            "oryva.provisioning.id": [marker],
        },
    })
    assert status == 201
    _, found = call("/admin/realms/oryva/users?" + urlencode({"username": probe_name, "exact": "true"}),
                    admin_token)
    assert len(found) == 1
    probe_id = found[0]["id"]
    _, detail = call("/admin/realms/oryva/users/" + probe_id, admin_token)
    assert detail["enabled"] is False
    for name in ("oryva.bootstrap.owner", "oryva.provisioning.id"):
        assert detail.get("attributes", {}).get(name) == [marker]
    print("PASS both ownership markers persist on an isolated disabled test identity")
finally:
    if probe_id:
        status, _ = call("/admin/realms/oryva/users/" + probe_id, admin_token, "DELETE")
        assert status == 204
