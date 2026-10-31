#!/usr/bin/env python3
"""Container-backed Keycloak master realm-role mapping integration smoke test."""
import json
import http.client
import socket
import os
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("ORYVA_KEYCLOAK_URL", "http://127.0.0.1:8080").rstrip("/")
REALM = "oryva"
ADMIN = os.environ["ORYVA_TEST_KEYCLOAK_ADMIN"]
PASSWORD = os.environ["ORYVA_TEST_KEYCLOAK_PASSWORD"]


def request(path, method="GET", data=None, token=None, content_type="application/json"):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as response:
        body = response.read()
        return response.status, dict(response.headers), json.loads(body) if body else None


def token():
    form = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN, "password": PASSWORD
    }).encode()
    return request("/realms/master/protocol/openid-connect/token", "POST",
                   form, content_type="application/x-www-form-urlencoded")[2]["access_token"]


def main():
    for attempt in range(60):
        try:
            access = token()
            break
        except (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout,
                http.client.HTTPException):
            if attempt == 59:
                raise
            time.sleep(2)

    role = request(f"/admin/realms/{REALM}/roles/master", token=access)[2]
    assert role["name"] == "master" and role["id"]
    username = "oryva-role-test"
    status, _, _ = request(f"/admin/realms/{REALM}/users", "POST",
                           json.dumps({"username": username, "enabled": False}).encode(), access)
    assert status == 201
    users = request(f"/admin/realms/{REALM}/users?username={username}&exact=true",
                    token=access)[2]
    assert len(users) == 1
    subject = users[0]["id"]
    mapping_path = f"/admin/realms/{REALM}/users/{subject}/role-mappings/realm"
    status, _, _ = request(mapping_path, "POST", json.dumps([role]).encode(), access)
    assert status == 204
    assigned = request(mapping_path, token=access)[2]
    assert any(item["id"] == role["id"] for item in assigned)
    members = request(f"/admin/realms/{REALM}/roles/master/users", token=access)[2]
    assert len(members) == 1 and members[0]["id"] == subject and not members[0]["enabled"]
    # Simulate the enablement transport after verifying sole direct membership.
    user_path = f"/admin/realms/{REALM}/users/{subject}"
    status, _, _ = request(user_path, "PUT", json.dumps({"enabled": True}).encode(), access)
    assert status == 204
    enabled_user = request(user_path, token=access)[2]
    assert enabled_user["id"] == subject and enabled_user["enabled"] is True
    enabled_members = request(f"/admin/realms/{REALM}/roles/master/users", token=access)[2]
    assert len(enabled_members) == 1
    assert enabled_members[0]["id"] == subject and enabled_members[0]["enabled"] is True

    # Repeated enablement is idempotent at the Keycloak transport level.
    status, _, _ = request(user_path, "PUT", json.dumps({"enabled": True}).encode(), access)
    assert status == 204
    repeated = request(user_path, token=access)[2]
    assert repeated["id"] == subject and repeated["enabled"] is True

    # Confirm another identity cannot be mistaken for the direct role member.
    second_name = "oryva-nonmaster-test"
    status, _, _ = request(f"/admin/realms/{REALM}/users", "POST",
                           json.dumps({"username": second_name, "enabled": False}).encode(), access)
    assert status == 201
    other = request(f"/admin/realms/{REALM}/users?username={second_name}&exact=true",
                    token=access)[2]
    assert len(other) == 1 and other[0]["id"] != subject
    other_roles = request(
        f"/admin/realms/{REALM}/users/{other[0]['id']}/role-mappings/realm", token=access)[2]
    assert all(item["id"] != role["id"] for item in other_roles)
    print("PASS: Keycloak role mapping, enablement, retry and unrelated identity isolation")


if __name__ == "__main__":
    main()
