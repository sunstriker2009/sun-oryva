#!/usr/bin/env python3
"""Observe disabled-account Keycloak action-link behavior with a CI-only SMTP sink.

This is a behavioral probe, NOT a passing invitation/enrollment ceremony.
Never use a real mailbox, enable an identity, or log action-token URLs.
"""
import html
import json
import os
import re
import time
import uuid
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

BASE = os.environ.get("ORYVA_KEYCLOAK_URL", "http://127.0.0.1:8080").rstrip("/")
MAILPIT = os.environ.get("ORYVA_TEST_MAILPIT_URL", "http://127.0.0.1:8025").rstrip("/")
assert BASE == "http://127.0.0.1:8080", "Probe requires isolated local Keycloak"
assert MAILPIT == "http://127.0.0.1:8025", "Probe requires isolated local mail sink"


def request(url, method="GET", data=None, token=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = None if data is None else json.dumps(data).encode("utf-8")
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


def api(path, method="GET", data=None, token=None):
    status, raw = request(BASE + path, method, data, token)
    return status, json.loads(raw) if raw else None


def mailpit(path):
    status, raw = request(MAILPIT + path)
    assert status == 200, "Mail sink API unavailable"
    return json.loads(raw)


def messages_for(address):
    items = mailpit("/api/v1/messages?limit=50").get("messages", [])
    return [item for item in items if any(
        address == recipient.get("Address") for recipient in item.get("To", [])
    )]


def find_action_url(message):
    # HTML may encode query-string ampersands; never print the token or URL.
    candidates = re.findall(
        r"https?://[^\s<>\"']+",
        html.unescape((message.get("HTML") or "") + "\n" + (message.get("Text") or "")),
    )
    for candidate in candidates:
        candidate = candidate.rstrip(").,;")
        parsed = urlsplit(candidate)
        expected = urlsplit(BASE)
        if (parsed.scheme, parsed.netloc) == (expected.scheme, expected.netloc) and (
            parsed.path.startswith("/realms/oryva/login-actions/action-token")
        ) and "key=" in parsed.query:
            return candidate
    raise AssertionError("No same-origin Keycloak action-token URL in sink message")


def assert_disabled(user_id, token):
    status, user = api("/admin/realms/oryva/users/" + user_id, token=token)
    assert status == 200 and user["enabled"] is False, "Probe identity became enabled"
    status, sessions = api("/admin/realms/oryva/users/" + user_id + "/sessions", token=token)
    assert status == 200 and sessions == [], "Probe identity gained a session"
    status, credentials = api("/admin/realms/oryva/users/" + user_id + "/credentials", token=token)
    assert status == 200 and not any(c.get("type") == "password" for c in credentials), (
        "Probe identity unexpectedly acquired a password"
    )
    return user


def main():
    from urllib.parse import urlencode
    form = urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ["ORYVA_TEST_KEYCLOAK_ADMIN"],
        "password": os.environ["ORYVA_TEST_KEYCLOAK_PASSWORD"],
    }).encode()
    req = Request(BASE + "/realms/master/protocol/openid-connect/token", data=form,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urlopen(req, timeout=15) as response:
        admin_token = json.load(response)["access_token"]

    status, realm = api("/admin/realms/oryva", token=admin_token)
    assert status == 200 and realm["verifyEmail"] is True
    assert realm["registrationAllowed"] is False and realm["resetPasswordAllowed"] is False
    original_smtp = realm.get("smtpServer")
    realm["smtpServer"] = {
        "host": "oryva-e2e-mailpit", "port": "1025",
        "from": "oryva-e2e@example.invalid", "fromDisplayName": "ORYVA CI",
        "ssl": "false", "starttls": "false", "auth": "false",
    }
    status, _ = api("/admin/realms/oryva", "PUT", realm, admin_token)
    assert status == 204, "Cannot configure isolated SMTP sink"

    user_id = None
    try:
        suffix = uuid.uuid4().hex
        username = "oryva-disabled-action-" + suffix[:16]
        email = username + "@example.invalid"
        status, _ = api("/admin/realms/oryva/users", "POST", {
            "username": username, "email": email, "enabled": False,
            "emailVerified": False, "requiredActions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
        }, admin_token)
        assert status == 201
        status, users = api("/admin/realms/oryva/users?" + urlencode({
            "username": username, "exact": "true",
        }), token=admin_token)
        assert status == 200 and len(users) == 1
        user_id = users[0]["id"]
        assert_disabled(user_id, admin_token)

        status, _ = api(
            "/admin/realms/oryva/users/" + user_id +
            "/execute-actions-email?lifespan=300",
            "PUT", ["VERIFY_EMAIL", "UPDATE_PASSWORD"], admin_token,
        )
        if status in (400, 403):
            assert not messages_for(email), "Rejected action request still sent email"
            print("OBSERVED Keycloak rejects disabled-user execute-actions-email")
        else:
            assert status == 204, "Unexpected Keycloak action-email response"
            items = []
            for _ in range(30):
                items = messages_for(email)
                if items:
                    break
                time.sleep(1)
            assert len(items) == 1, "Expected exactly one isolated invitation message"
            message = mailpit("/api/v1/message/" + items[0]["ID"])
            action_url = find_action_url(message)
            # Follow only the same-origin action URL. No forms or credentials are submitted.
            status, raw = request(action_url)
            assert status in (200, 400, 401, 403), "Unexpected action-link HTTP response"
            assert b"access_token" not in raw, "Action-link response unexpectedly contains token"
            print("OBSERVED disabled-user action email delivered to isolated sink")
            print("OBSERVED first action-link GET completed without credential submission")
        detail = assert_disabled(user_id, admin_token)
        assert detail["emailVerified"] is False, "Email unexpectedly verified by probe"
        assert set(detail.get("requiredActions", [])) == {"VERIFY_EMAIL", "UPDATE_PASSWORD"}
        print("PASS disabled identity stayed unverified, credential-free and session-free")
    finally:
        if user_id:
            status, _ = api("/admin/realms/oryva/users/" + user_id,
                            "DELETE", token=admin_token)
            assert status == 204
        status, current = api("/admin/realms/oryva", token=admin_token)
        assert status == 200
        if original_smtp is None:
            current.pop("smtpServer", None)
        else:
            current["smtpServer"] = original_smtp
        status, _ = api("/admin/realms/oryva", "PUT", current, admin_token)
        assert status == 204


if __name__ == "__main__":
    main()
