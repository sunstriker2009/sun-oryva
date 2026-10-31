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
# Keycloak 26 does not apply this custom user-profile component from realm import.
# Configure the effective profile through the supported Admin API.
profile_path = "/admin/realms/oryva/users/profile"
profile = call(profile_path, token=token)[1]
attributes = profile.setdefault("attributes", [])
owner_name = "oryva.bootstrap.owner"
if not any(a.get("name") == owner_name for a in attributes):
    attributes.append({
        "name": owner_name,
        "multivalued": False,
        "permissions": {"view": ["admin"], "edit": ["admin"]}
    })
    status, _ = call(profile_path, "PUT", json.dumps(profile).encode(), token)
    assert status == 200, f"Unexpected Keycloak profile update status: {status}"

# Verify the effective Keycloak user-profile configuration, not merely realm JSON.
profile = call("/admin/realms/oryva/users/profile", token=token)[1]
ownership = next((a for a in profile.get("attributes", [])
                  if a.get("name") == "oryva.bootstrap.owner"), None)
if ownership is None:
    raise RuntimeError("Effective Keycloak user profile lacks oryva.bootstrap.owner")
permissions = ownership.get("permissions", {})
if "admin" not in permissions.get("view", []) or "admin" not in permissions.get("edit", []):
    raise RuntimeError("Bootstrap ownership attribute lacks admin view/edit permissions")
print("PASS effective Keycloak user profile permits bootstrap ownership attribute")

# Validate persistence with a throwaway identity before running the real bootstrap.
probe_username = "oryva-profile-probe"
probe_marker = "profile-persistence-test"
probe = {
    "username": probe_username, "enabled": False,
    "attributes": {"oryva.bootstrap.owner": [probe_marker]}
}
status, _ = call("/admin/realms/oryva/users", "POST", json.dumps(probe).encode(), token)
assert status == 201
found = call("/admin/realms/oryva/users?username=" + probe_username + "&exact=true",
             token=token)[1]
assert len(found) == 1
probe_id = found[0]["id"]
try:
    detail = call(f"/admin/realms/oryva/users/{probe_id}", token=token)[1]
    if detail.get("attributes", {}).get("oryva.bootstrap.owner") != [probe_marker]:
        raise RuntimeError("Keycloak did not persist or expose bootstrap ownership marker")
    print("PASS Keycloak ownership attribute persisted and is readable")
finally:
    call(f"/admin/realms/oryva/users/{probe_id}", "DELETE", token=token)

print("PASS configured isolated service account")


# Dedicated public test client with password grant enabled only for isolated CI.
# Explicit audience mapper ensures the API's aud validation is exercised.
api_client = {
    "clientId": "oryva-e2e-api", "enabled": True, "protocol": "openid-connect",
    "publicClient": True, "standardFlowEnabled": False,
    "directAccessGrantsEnabled": True, "fullScopeAllowed": True,
    "protocolMappers": [{
        "name": "oryva-api-audience", "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": "oryva-api",
            "access.token.claim": "true",
            "id.token.claim": "false"
        }
    }]
}
status, _ = call("/admin/realms/oryva/clients", "POST",
                 json.dumps(api_client).encode(), token)
assert status == 201
print("PASS dedicated CI JWT client and API audience configured")
