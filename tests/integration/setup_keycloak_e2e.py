#!/usr/bin/env python3
"""Configure isolated Keycloak test service account; CI-only credentials."""
import json
import os
import urllib.parse
import urllib.request

base = os.environ.get("ORYVA_KEYCLOAK_URL", "http://127.0.0.1:8080")
admin = os.environ["ORYVA_TEST_KEYCLOAK_ADMIN"]
password = os.environ["ORYVA_TEST_KEYCLOAK_PASSWORD"]
secret = os.environ["ORYVA_TEST_CLIENT_SECRET"]

def call(path, method="GET", data=None, token=None, content_type="application/json"):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = response.read()
        return response.status, json.loads(payload) if payload else None

form = urllib.parse.urlencode({
    "grant_type": "password", "client_id": "admin-cli",
    "username": admin, "password": password
}).encode()
token = call("/realms/master/protocol/openid-connect/token", "POST", form,
             content_type="application/x-www-form-urlencoded")[1]["access_token"]
client = {
    "clientId": "oryva-e2e-bootstrap", "enabled": True, "protocol": "openid-connect",
    "publicClient": False, "serviceAccountsEnabled": True,
    "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
    "secret": secret
}
status, _ = call("/admin/realms/oryva/clients", "POST", json.dumps(client).encode(), token)
assert status == 201
clients = call("/admin/realms/oryva/clients?clientId=oryva-e2e-bootstrap", token=token)[1]
assert len(clients) == 1
service_user = call(
    f"/admin/realms/oryva/clients/{clients[0]['id']}/service-account-user",
    token=token)[1]
realm_management = call("/admin/realms/oryva/clients?clientId=realm-management", token=token)[1]
assert len(realm_management) == 1
roles = call(
    f"/admin/realms/oryva/clients/{realm_management[0]['id']}/roles", token=token)[1]
needed = {"manage-users", "view-users", "query-users", "view-realm"}
assigned = [role for role in roles if role["name"] in needed]
assert {r["name"] for r in assigned} == needed
path = f"/admin/realms/oryva/users/{service_user['id']}/role-mappings/clients/{realm_management[0]['id']}"
status, _ = call(path, "POST", json.dumps(assigned).encode(), token)
assert status == 204
print("PASS configured isolated service account")
