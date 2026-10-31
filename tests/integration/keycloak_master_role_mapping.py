#!/usr/bin/env python3
"""Container-backed Keycloak master realm-role mapping integration smoke test."""
import json
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
        except (urllib.error.URLError, TimeoutError, KeyError):
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
    print("PASS: disabled Keycloak subject has exactly one direct master role mapping")


if __name__ == "__main__":
    main()
