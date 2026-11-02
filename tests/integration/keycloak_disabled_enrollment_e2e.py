#!/usr/bin/env python3
"""Fail-closed Keycloak enrollment preflight against an isolated CI realm.

This is a *negative* test, not proof that invitation links work. No email is
sent, no identity is enabled, and no production credentials are used.
"""
import json
import os
import secrets
import uuid
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = os.environ.get("ORYVA_KEYCLOAK_URL", "http://127.0.0.1:8080").rstrip("/")
REALM = "oryva"


def call(path, method="GET", payload=None, token=None, form=False, reject=False):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        data = (urlencode(payload) if form else json.dumps(payload)).encode()
        headers["Content-Type"] = (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    request = Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read()
            status = response.status
    except HTTPError as error:
        if not reject:
            raise
        status = error.code
        raw = error.read()
    body = json.loads(raw) if raw else {}
    return status, body


status, response = call(
    "/realms/master/protocol/openid-connect/token",
    "POST",
    {"grant_type": "password", "client_id": "admin-cli",
     "username": os.environ["ORYVA_TEST_KEYCLOAK_ADMIN"],
     "password": os.environ["ORYVA_TEST_KEYCLOAK_PASSWORD"]},
    form=True,
)
assert status == 200
admin_token = response["access_token"]
status, realm = call("/admin/realms/" + REALM, token=admin_token)
assert status == 200
assert realm.get("registrationAllowed") is False
assert realm.get("resetPasswordAllowed") is False
assert realm.get("verifyEmail") is True, "Run before the CI direct-grant setup alters the realm"

suffix = uuid.uuid4().hex[:12]
client_name = "oryva-enrollment-negative-" + suffix
client_id = None
user_ids = []
try:
    status, _ = call("/admin/realms/oryva/clients", "POST", {
        "clientId": client_name, "enabled": True, "protocol": "openid-connect",
        "publicClient": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": True,
    }, token=admin_token)
    assert status == 201
    _, clients = call("/admin/realms/oryva/clients?" + urlencode({"clientId": client_name}),
                      token=admin_token)
    assert len(clients) == 1
    client_id = clients[0]["id"]

    for verified, actions in (
        (False, ["VERIFY_EMAIL", "UPDATE_PASSWORD"]),
        (True, []),
    ):
        username = "oryva-disabled-probe-" + uuid.uuid4().hex[:12]
        password = secrets.token_urlsafe(32)
        status, _ = call("/admin/realms/oryva/users", "POST", {
            "username": username, "email": username + "@example.invalid",
            "enabled": False, "emailVerified": verified,
            "requiredActions": actions,
        }, token=admin_token)
        assert status == 201
        _, users = call("/admin/realms/oryva/users?" +
                        urlencode({"username": username, "exact": "true"}),
                        token=admin_token)
        assert len(users) == 1
        user_id = users[0]["id"]
        user_ids.append(user_id)

        # A random CI-only credential tests the disabled gate independently of
        # missing credentials. It is never logged or sent to production.
        status, _ = call("/admin/realms/oryva/users/" + user_id + "/reset-password",
                         "PUT", {"type": "password", "value": password,
                                 "temporary": False}, token=admin_token)
        assert status == 204

        status, result = call("/realms/oryva/protocol/openid-connect/token",
                              "POST", {"grant_type": "password", "client_id": client_name,
                                       "username": username, "password": password},
                              form=True, reject=True)
        assert status in (400, 401), "Disabled identity unexpectedly authenticated"
        assert isinstance(result, dict) and "access_token" not in result
        assert result.get("error") == "invalid_grant", "Unexpected token error contract"

        _, detail = call("/admin/realms/oryva/users/" + user_id, token=admin_token)
        assert detail["enabled"] is False
        assert detail["emailVerified"] is verified
        assert set(detail.get("requiredActions", [])) == set(actions)
        _, sessions = call("/admin/realms/oryva/users/" + user_id + "/sessions",
                           token=admin_token)
        assert sessions == [], "Disabled test identity has an active session"

    print("PASS disabled enrolled and unenrolled CI identities cannot authenticate")
    print("PASS email-verification and required-action state remain unchanged")
finally:
    for user_id in user_ids:
        status, _ = call("/admin/realms/oryva/users/" + user_id,
                         "DELETE", token=admin_token)
        assert status == 204
    if client_id:
        status, _ = call("/admin/realms/oryva/clients/" + client_id,
                         "DELETE", token=admin_token)
        assert status == 204
