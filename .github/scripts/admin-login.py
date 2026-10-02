"""Drives the Admin Console's login on the admin URL, as a browser would, without one.

Exits 0 only when the master realm's login form posts to ADMIN_URL and the administrator's
credentials come back as an authorization code for the console. Reads the credentials from the
.env in the working directory, which is deploy/dev in CI.

Cookies are carried by hand: Keycloak marks them Secure, a browser still sends them to
http://localhost because that is a secure context, and a stdlib cookie jar would not.
"""

import base64
import hashlib
import html
import http.client
import os
import re
import secrets
import sys
import urllib.parse


def env_file(path=".env"):
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key] = value
    return values


admin = os.environ["ADMIN_URL"].rstrip("/")
settings = env_file()
user = settings.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
password = settings["KC_BOOTSTRAP_ADMIN_PASSWORD"]
cookies = {}


def send(method, url, body=None):
    parts = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=20)
    headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    target = parts.path + ("?" + parts.query if parts.query else "")
    connection.request(method, target, body, headers)
    response = connection.getresponse()
    page = response.read().decode("utf-8", "replace")
    for name, value in response.getheaders():
        if name.lower() == "set-cookie":
            key, _, rest = value.partition("=")
            content = rest.split(";", 1)[0]
            if content:
                cookies[key] = content
            else:
                cookies.pop(key, None)
    return response, page


verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
query = urllib.parse.urlencode({
    "client_id": "security-admin-console",
    "redirect_uri": admin + "/admin/master/console/",
    "response_type": "code",
    "scope": "openid",
    "state": "ci",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
})

response, page = send("GET", admin + "/realms/master/protocol/openid-connect/auth?" + query)
match = re.search(r'action="([^"]*login-actions/authenticate[^"]*)"', page)
if response.status != 200 or not match:
    sys.exit(f"no login form on the admin URL: {response.status} {page[:400]}")

action = html.unescape(match.group(1))
if not action.startswith(admin + "/"):
    sys.exit(f"the admin login form posts to {action.split('?')[0]}, not to the admin URL {admin}")

form = urllib.parse.urlencode({"username": user, "password": password, "credentialId": ""})
response, page = send("POST", action, form)
location = response.getheader("Location") or ""
if response.status != 302 or "code=" not in location:
    sys.exit(f"the admin login answered {response.status} (Location {location.split('?')[0]!r}): {page[:400]}")

print(f"admin login completed on {admin}")
