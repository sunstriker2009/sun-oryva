#!/usr/bin/env python3
"""Check or explicitly install ORYVA's admin-only Keycloak ownership attributes.

No credentials are created, no users are enabled, and no realm-wide security
settings are relaxed. A short-lived management token is supplied via environment.
"""

import argparse
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

OWNERSHIP_ATTRIBUTES = ("oryva.bootstrap.owner", "oryva.provisioning.id")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_url(base_url):
    parsed = urlsplit(base_url)
    if (not parsed.netloc or parsed.username or parsed.password or parsed.query or
            parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Supply a Keycloak origin URL without credentials, paths or query parameters.")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
    ):
        raise ValueError("HTTPS is required except for a local isolated Keycloak instance.")
    return base_url.rstrip("/")


def _profile_request(base_url, realm, token, method="GET", payload=None):
    url = base_url + "/admin/realms/" + quote(realm, safe="") + "/users/profile"
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, headers=headers, data=data, method=method)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            if response.status not in (200, 204):
                raise RuntimeError(f"Keycloak profile {method} returned HTTP {response.status}.")
            body = response.read()
            return json.loads(body) if body else None
    except HTTPError as exc:
        raise RuntimeError(f"Keycloak profile {method} returned HTTP {exc.code}.") from None
    except URLError:
        raise RuntimeError(f"Keycloak profile {method} was unreachable.") from None


def _attributes(profile):
    if not isinstance(profile, dict) or not isinstance(profile.get("attributes"), list):
        raise RuntimeError("Keycloak returned an invalid user-profile document.")
    attributes = profile["attributes"]
    if not all(isinstance(a, dict) and isinstance(a.get("name"), str) for a in attributes):
        raise RuntimeError("Keycloak user profile contains malformed attributes.")
    return attributes


def _inspect(profile):
    attributes = _attributes(profile)
    missing = []
    for name in OWNERSHIP_ATTRIBUTES:
        matches = [a for a in attributes if a["name"] == name]
        if len(matches) > 1:
            raise RuntimeError(f"Duplicate reserved ownership attribute: {name}.")
        if not matches:
            missing.append(name)
            continue
        item = matches[0]
        permissions = item.get("permissions")
        if (item.get("multivalued") is not False or
                not isinstance(permissions, dict) or
                permissions.get("view") != ["admin"] or
                permissions.get("edit") != ["admin"]):
            raise RuntimeError(f"Unsafe existing ownership attribute: {name}; manual review required.")
    return missing


def validate_profile(profile):
    """Fail closed on missing, duplicated, or user-editable ownership markers."""
    missing = _inspect(profile)
    if missing:
        raise RuntimeError("Missing Keycloak ownership attributes: " + ", ".join(missing))


def ensure_profile(base_url, realm, token, *, apply=False):
    """Return True only if missing attributes were installed by explicit apply."""
    base_url = _validate_url(base_url)
    if not realm or "/" in realm or not token or not token.strip():
        raise ValueError("A realm name and a nonempty management token are required.")
    profile = _profile_request(base_url, realm, token)
    missing = _inspect(profile)
    if missing and not apply:
        raise RuntimeError("Missing Keycloak ownership attributes: " + ", ".join(missing))
    if missing:
        for name in missing:
            profile["attributes"].append({
                "name": name,
                "multivalued": False,
                "permissions": {"view": ["admin"], "edit": ["admin"]},
            })
        _profile_request(base_url, realm, token, method="PUT", payload=profile)
    # A successful write response is not evidence of the effective configuration.
    validate_profile(_profile_request(base_url, realm, token))
    return bool(missing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Install missing attributes only; unsafe existing settings fail closed")
    args = parser.parse_args()
    base_url = os.environ.get("ORYVA_KEYCLOAK_URL", "")
    realm = os.environ.get("ORYVA_KEYCLOAK_REALM", "oryva")
    token = os.environ.get("ORYVA_KEYCLOAK_ADMIN_TOKEN", "")
    changed = ensure_profile(base_url, realm, token, apply=args.apply)
    print("PASS ORYVA ownership profile is admin-only (updated)" if changed else
          "PASS ORYVA ownership profile is admin-only (unchanged)")


if __name__ == "__main__":
    main()
