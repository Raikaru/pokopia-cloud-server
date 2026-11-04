"""Contract tests for optional Discord sign-in on the account portal (portal.py).

They run the real portal (Portal and Handler on a loopback port, with its SQLite database and PKI in
a temporary directory) and drive it the way a browser and launcher.py do. Discord is simulated only
where the portal reaches it, portal.discord_https: the simulation checks every request as Discord's
OAuth2 server would (client credentials, PKCE S256, single-use codes, redirect URI, bearer token) and
the browser's visit to Discord's consent page is played by FakeDiscord.authorize. No Discord
application or credentials are involved. Time inside portal.py is a Clock the tests move forward.

Every secret Discord hands out (client secret, codes, access and refresh tokens, PKCE verifiers) is
checked after each test to appear in no portal log record, response or database row; assertion
messages never include them. Run from this directory with the portal dependencies installed:

    python -m unittest test_discord_auth
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import gc
import hashlib
import hmac
import http.client
import io
import itertools
import json
import logging
import os
import re
import secrets
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import portal
import server

ORIGIN = "https://portal.test"
RP_ID = "portal.test"
REDIRECT_URI = ORIGIN + "/auth/discord/callback"
CLIENT_ID = "1234567890123456789"
CLIENT_SECRET = "fake-client-secret-Q9w8E7r6T5y4U3i2"
# Discord's published endpoints; a request anywhere else is a violation.
AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
TOKEN_URL = "https://discord.com/api/oauth2/token"
USER_URLS = ("https://discord.com/api/users/@me", "https://discord.com/api/v10/users/@me")
ISSUER = "https://discord.com"
DISCORD_COOKIE = "__Host-discord-oauth"  # binds a sign-in to the browser that started it
DISCORD_LINK_COOKIE = "__Host-discord-link"  # holds Discord's answer until the page finishes linking
AUTHORIZE_PARAMETERS = {"response_type", "client_id", "scope", "state", "redirect_uri", "code_challenge",
                        "code_challenge_method"}
PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def with_query(url: str, **changes: str | None) -> str:
    """`url` with query parameters replaced, added, or (for None) removed."""
    parts = urlsplit(url)
    query = {name: values[0] for name, values in parse_qs(parts.query, keep_blank_values=True).items()}
    for name, value in changes.items():
        if value is None:
            query.pop(name, None)
        else:
            query[name] = value
    return parts._replace(query=urlencode(query)).geturl()


def parse_set_cookie(header: str) -> tuple[str, str, dict[str, str]]:
    first, *attributes = header.split(";")
    name, _, value = first.strip().partition("=")
    parsed = {}
    for attribute in attributes:
        key, _, attribute_value = attribute.strip().partition("=")
        parsed[key.lower()] = attribute_value
    return name, value, parsed


class Clock:
    """Stands in for the time module inside portal.py, so that tests can move time forward."""

    def __init__(self) -> None:
        self.offset = 0.0

    def time(self) -> float:
        return time.time() + self.offset

    def monotonic(self) -> float:
        return time.monotonic() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def __getattr__(self, name: str):
        return getattr(time, name)


class Records(logging.Handler):
    """Everything portal.py logs during a test, formatted with tracebacks."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.texts: list[str] = []
        self.lock_texts = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        text = self.format(record)
        with self.lock_texts:
            self.texts.append(text)


class Passkey:
    """A software authenticator with one discoverable P-256 credential ("none" attestation, user
    verified), as a browser's passkey provider answers navigator.credentials."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.user_handle = b""
        self.sign_count = 0

    @property
    def id(self) -> str:
        return b64url(self.credential_id)

    def public_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"),
                            -3: numbers.y.to_bytes(32, "big")})

    @staticmethod
    def client_data(kind: str, challenge: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False}).encode()

    def create(self, options: dict) -> dict:
        self.user_handle = unb64url(options["user"]["id"])
        auth_data = (hashlib.sha256(options["rp"]["id"].encode()).digest() + bytes([0x45])  # UP, UV, AT
                     + struct.pack(">I", self.sign_count) + bytes(16)
                     + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.public_key())
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": self.id, "rawId": self.id, "type": "public-key",
                "response": {"clientDataJSON": b64url(self.client_data("webauthn.create", options["challenge"])),
                             "attestationObject": b64url(attestation), "transports": ["internal"]}}

    def get(self, options: dict) -> dict:
        self.sign_count += 1
        auth_data = (hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x05])  # UP, UV
                     + struct.pack(">I", self.sign_count))
        client_data = self.client_data("webauthn.get", options["challenge"])
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": self.id, "rawId": self.id, "type": "public-key",
                "response": {"clientDataJSON": b64url(client_data), "authenticatorData": b64url(auth_data),
                             "signature": b64url(signature), "userHandle": b64url(self.user_handle)}}


class Launcher:
    """A PC running `launcher.py link`: a P-256 key that stays on it, its CSR and a PKCE verifier."""

    def __init__(self, name: str = "Gaming PC") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "launcher")])).sign(self.key, hashes.SHA256())
        self.csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        self.verifier = secrets.token_urlsafe(48)
        self.request = {
            "port": 49152,
            "state": secrets.token_urlsafe(16),
            "challenge": b64url(hashlib.sha256(self.verifier.encode()).digest()),
            "csr": hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest(),
            "name": name,
        }


class Response:
    def __init__(self, status: int, headers: http.client.HTTPMessage, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def json(self) -> dict:
        return json.loads(self.body)

    @property
    def error(self) -> str:
        """The portal's error message, for assertion messages (it never carries secrets)."""
        try:
            return str(self.json().get("error"))
        except ValueError:
            return f"HTTP {self.status}"

    @property
    def location(self) -> str:
        return self.headers.get("Location", "")

    def cookie(self, name: str) -> dict[str, str] | None:
        """The attributes of the Set-Cookie for `name`, with its value under "value"."""
        for header in self.headers.get_all("Set-Cookie") or []:
            cookie_name, value, attributes = parse_set_cookie(header)
            if cookie_name == name:
                return {"value": value, **attributes}
        return None

    @property
    def result(self) -> str | None:
        """The outcome the Discord callback reports to the page: the "discord" fragment parameter."""
        if self.status != 303:
            return None
        return parse_qs(urlsplit(self.location).fragment).get("discord", [None])[0]

    def text(self) -> str:
        headers = "\n".join(f"{name}: {value}" for name, value in self.headers.items())
        return headers + "\n" + self.body.decode("utf-8", "replace")


class Browser:
    """A browser on the portal's origin behind the reverse proxy: keeps the cookies the portal sets
    and sends them back, and sends its Origin with API calls as fetch() does."""

    def __init__(self, test: PortalTest, address: str) -> None:
        self.test = test
        self.address = address
        self.cookies: dict[str, str] = {}
        self.timeout = 10.0  # seconds a request may take

    def request(self, method: str, path: str, body: dict | None = None, origin: str | None = ORIGIN) -> Response:
        headers = {"X-Forwarded-For": self.address}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            if origin is not None:
                headers["Origin"] = origin
        connection = http.client.HTTPConnection("127.0.0.1", self.test.port, timeout=self.timeout)
        try:
            connection.request(method, path, data, headers)
            raw = connection.getresponse()
            response = Response(raw.status, raw.headers, raw.read())
        finally:
            connection.close()
        for header in raw.headers.get_all("Set-Cookie") or []:
            name, value, attributes = parse_set_cookie(header)
            if attributes.get("max-age") == "0":
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        self.test.responses.append(response)
        return response

    def get(self, path: str) -> Response:
        return self.request("GET", path)

    def post(self, path: str, body: dict, origin: str | None = ORIGIN) -> Response:
        return self.request("POST", path, body, origin)

    def open(self, url: str) -> Response:
        """Follows Discord's redirect back to the portal."""
        parts = urlsplit(url)
        self.test.assertEqual(f"{parts.scheme}://{parts.netloc}", ORIGIN)
        return self.get(parts.path + ("?" + parts.query if parts.query else ""))

    def copy(self, address: str | None = None) -> Browser:
        """Another tab or a replaying attacker holding the same cookies."""
        other = Browser(self.test, address or self.address)
        other.cookies = dict(self.cookies)
        return other


class FakeDiscord:
    """Discord's consent page, OAuth2 token endpoint and user API, reached only through
    portal.discord_https. Requests Discord would refuse because the portal got the protocol wrong are
    recorded as violations; a code that is unknown or already used is refused as Discord does."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.test = test
        self.lock = threading.Condition()
        self.violations: list[str] = []
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        self.refresh_tokens: list[str] = []
        self.verifiers: list[str] = []
        self.states: list[str] = []
        self.token_requests = 0
        self.user_requests = 0
        self.token_changes: dict = {}  # merged into the token response
        self.outage = False
        self.held = 0
        self.hold_limit = 0
        self.released = threading.Event()
        self.snowflakes = itertools.count(80351110224678912, 7919)

    def new_user(self, username: str, **fields) -> dict:
        """A Discord account as GET /users/@me describes it."""
        return {"id": str(next(self.snowflakes)), "username": username, "global_name": username.title(),
                "discriminator": "0", "avatar": None, **fields}

    def secrets(self) -> list[tuple[str, str]]:
        credentials = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        with self.lock:
            return ([("client secret", CLIENT_SECRET), ("client credential header", credentials)]
                    + [("authorization code", code) for code in self.codes]
                    + [("access token", token) for token in self.tokens]
                    + [("refresh token", token) for token in self.refresh_tokens]
                    + [("PKCE verifier", verifier) for verifier in self.verifiers])

    # The browser at Discord

    def authorize(self, url: str, user: dict | None = None, deny: bool = False) -> str:
        """What Discord's consent page does with the portal's authorization request: checks it,
        and sends the browser back to the redirect URI with a code (or access_denied)."""
        test = self.test
        parts = urlsplit(url)
        test.assertEqual(f"{parts.scheme}://{parts.netloc}{parts.path}", AUTHORIZE_URL)
        query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
        test.assertTrue(all(len(values) == 1 for values in query.values()), "repeated authorization parameter")
        params = {name: values[0] for name, values in query.items()}
        test.assertTrue(AUTHORIZE_PARAMETERS <= set(params) <= AUTHORIZE_PARAMETERS | {"prompt"},
                        f"authorization parameters {sorted(params)}")
        test.assertEqual(params["response_type"], "code")
        test.assertEqual(params["client_id"], CLIENT_ID)
        test.assertEqual(params["scope"], "identify")
        test.assertEqual(params["redirect_uri"], REDIRECT_URI)
        test.assertEqual(params["code_challenge_method"], "S256")
        test.assertRegex(params["code_challenge"], PKCE_CHALLENGE)
        test.assertRegex(params["state"], r"^[A-Za-z0-9_-]{32,128}$")
        with self.lock:
            self.states.append(params["state"])
        if deny:
            return params["redirect_uri"] + "?" + urlencode({
                "error": "access_denied", "error_description": "The resource owner or authorization server denied "
                "the request", "state": params["state"], "iss": ISSUER})
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.codes[code] = {"user": user, "challenge": params["code_challenge"], "scope": params["scope"],
                                "redirect_uri": params["redirect_uri"], "used": False}
        return params["redirect_uri"] + "?" + urlencode({"code": code, "state": params["state"], "iss": ISSUER})

    # Discord's servers

    def hold(self, count: int) -> None:
        """The next `count` requests that reach Discord wait there until release()."""
        with self.lock:
            self.held, self.hold_limit = 0, count
            self.released.clear()

    def wait_held(self, count: int) -> None:
        with self.lock:
            if not self.lock.wait_for(lambda: self.held >= count, timeout=10):
                self.test.fail(f"{count} Discord requests were expected in flight, {self.held} arrived")

    def release(self) -> None:
        self.released.set()

    def violation(self, problem: str) -> portal.DiscordRefused:
        with self.lock:
            self.violations.append(problem)
        return portal.DiscordRefused(problem)

    def https(self, opener, url: str, headers: dict, body: bytes | None) -> bytes:
        with self.lock:
            hold = self.held < self.hold_limit
            if hold:
                self.held += 1
                self.lock.notify_all()
        if hold:
            self.released.wait(30)
        headers = {name.lower(): value for name, value in headers.items()}
        if self.outage:
            raise portal.DiscordUnavailable("Discord is unavailable")
        if url == TOKEN_URL:
            return self.token(headers, body)
        if url in USER_URLS:
            return self.user(headers, body)
        raise self.violation("request to an address that is not a Discord API endpoint")

    def token(self, headers: dict, body: bytes | None) -> bytes:
        if body is None:
            raise self.violation("token request without a body")
        if headers.get("content-type", "").split(";")[0].strip() != "application/x-www-form-urlencoded":
            raise self.violation("token request that is not form-encoded")
        expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if not hmac.compare_digest(headers.get("authorization", ""), expected):
            raise self.violation("token request without the application's client credentials")
        form = parse_qs(body.decode(), keep_blank_values=True)
        if any(len(values) != 1 for values in form.values()):
            raise self.violation("token request with a repeated parameter")
        form = {name: values[0] for name, values in form.items()}
        if form.get("grant_type") != "authorization_code" or not {"code", "redirect_uri", "code_verifier"} <= set(form):
            raise self.violation("token request that is not an authorization code grant with PKCE")
        if "scope" in form:
            raise self.violation("token request asking for a scope")
        with self.lock:
            self.token_requests += 1
            grant = self.codes.get(form["code"])
            if grant is None or grant["used"]:
                raise portal.DiscordRefused("invalid_grant")
            grant["used"] = True
            self.verifiers.append(form["code_verifier"])
        if form["redirect_uri"] != grant["redirect_uri"]:
            raise self.violation("token request with another redirect URI")
        if b64url(hashlib.sha256(form["code_verifier"].encode()).digest()) != grant["challenge"]:
            raise self.violation("token request whose PKCE verifier does not match the challenge")
        access, refresh = secrets.token_urlsafe(30), secrets.token_urlsafe(30)
        with self.lock:
            self.tokens[access] = grant["user"]
            self.refresh_tokens.append(refresh)
        return json.dumps({"access_token": access, "token_type": "Bearer", "expires_in": 604800,
                           "refresh_token": refresh, "scope": grant["scope"], **self.token_changes}).encode()

    def user(self, headers: dict, body: bytes | None) -> bytes:
        if body is not None:
            raise self.violation("user request with a body")
        authorization = headers.get("authorization", "")
        with self.lock:
            user = self.tokens.get(authorization[len("Bearer "):]) if authorization.startswith("Bearer ") else None
            self.user_requests += 1
        if user is None:
            raise self.violation("user request without an access token Discord issued")
        return json.dumps(user).encode()


V1_SCHEMA = """
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    user_handle BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
);
CREATE TABLE passkeys (
    credential_id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    added_with BLOB
);
CREATE INDEX passkeys_account ON passkeys(account_id);
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    linked_with BLOB NOT NULL
);
CREATE INDEX devices_account ON devices(account_id);
CREATE TABLE sessions (
    token_sha256 BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    credential_id BLOB NOT NULL,
    signed_in_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE link_codes (
    code_sha256 BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    credential_id BLOB NOT NULL,
    code_challenge TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    device_name TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE deleted_accounts (
    id TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL
);
"""  # portal.py's schema version 1, before Discord sign-in


class PortalTest(unittest.TestCase):
    """A portal with Discord sign-in configured, on a loopback port, with its own database and PKI."""

    discord_configured = True

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        with contextlib.redirect_stdout(io.StringIO()):
            portal.init_pki(self.root / "pki", "ingress.test")
        self.db_path = self.root / "auth.db"
        self.id_file, self.secret_file = self.root / "discord-client-id", self.root / "discord-client-secret"
        self.id_file.write_text(CLIENT_ID + "\n")
        self.secret_file.write_text(CLIENT_SECRET + "\n")
        if os.name == "posix":
            self.id_file.chmod(0o600)
            self.secret_file.chmod(0o600)

        self.clock = Clock()
        self.patch(portal, "time", self.clock)
        self.discord = FakeDiscord(self)
        self.patch(portal, "discord_https", self.discord.https)
        self.records = Records()
        logger = logging.getLogger("portal")
        level, propagate = logger.level, logger.propagate
        logger.addHandler(self.records)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False  # nothing the portal logs reaches the test output
        self.addCleanup(lambda: (logger.removeHandler(self.records), logger.setLevel(level),
                                 setattr(logger, "propagate", propagate)))
        self.responses: list[Response] = []
        self.addresses = itertools.count(10)
        self.httpd: ThreadingHTTPServer | None = None
        self.prepare_database()
        self.start_portal(self.portal_args(discord=self.discord_configured))
        self.addCleanup(self.stop_portal)

    def tearDown(self) -> None:
        self.assertEqual(self.discord.violations, [], "the portal sent Discord a request it would refuse")
        logs = "\n".join(self.records.texts)
        responses = "\n".join(response.text() for response in self.responses)
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            database = "\n".join(conn.iterdump())
        for label, value in self.discord.secrets():
            self.assertFalse(value in logs, f"a Discord {label} appears in the portal's log")
            self.assertFalse(value in responses, f"a Discord {label} appears in a portal response")
            self.assertFalse(value in database, f"a Discord {label} is stored in the database")
            self.assertFalse(value.encode().hex() in database.lower(), f"a Discord {label} is stored in the database")
        for state in self.discord.states:
            self.assertFalse(state in logs, "an OAuth state appears in the portal's log")

    def prepare_database(self) -> None:
        """Runs before the portal first opens the database."""

    def patch(self, target, name: str, value) -> None:
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    # The portal

    def portal_args(self, discord: bool = True, **options) -> argparse.Namespace:
        args = argparse.Namespace(
            db=self.db_path, pki_dir=self.root / "pki", rp_id=RP_ID, origin=ORIGIN, rp_name="Pokopia Cloud",
            ingress_host="ingress.test", ingress_port=443, ingress_name="", closed=False, max_accounts=1000,
            max_signups_per_day=50, device_days=180, trusted_proxy=["127.0.0.1", "::1"],
            discord_client_id_file=self.id_file if discord else None,
            discord_client_secret_file=self.secret_file if discord else None, discord_proxy=None)
        vars(args).update(options)
        return args

    def start_portal(self, args: argparse.Namespace) -> None:
        self.portal = portal.Portal(args)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), portal.Handler)
        httpd.daemon_threads = True
        httpd.portal = self.portal
        self.thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.httpd, self.port = httpd, httpd.server_address[1]

    def stop_portal(self) -> None:
        if self.httpd is None:
            return
        self.discord.release()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        self.portal.db.close()
        self.httpd = None

    def restart_portal(self, discord: bool = True, **options) -> None:
        self.stop_portal()
        self.start_portal(self.portal_args(discord, **options))

    def browser(self) -> Browser:
        """A browser on a network of its own, so the per-address rate limits of one test's browsers
        do not interact."""
        number = next(self.addresses)
        return Browser(self, f"198.51.{number // 250}.{number % 250 + 1}")

    def query(self, sql: str, *params) -> list[sqlite3.Row]:
        """Reads the database as server.py and the administration commands do: another connection."""
        with contextlib.closing(sqlite3.connect(self.db_path, timeout=5)) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql, params).fetchall()

    def count(self, table: str) -> int:
        return self.query(f"SELECT COUNT(*) FROM {table}")[0][0]

    def admin(self, command: str, identifier: str) -> None:
        """`portal.py <command> --db auth.db <identifier>`."""
        with contextlib.redirect_stdout(io.StringIO()):
            portal.admin(argparse.Namespace(command=command, db=self.db_path, id=identifier))

    # Passkeys

    def passkey_signup(self, browser: Browser, name: str = "Passkey user") -> tuple[str, Passkey]:
        begin = browser.post("/api/register/begin", {"name": name})
        self.assertEqual(begin.status, 200, begin.error)
        passkey = Passkey()
        finish = browser.post("/api/register/finish", {"ceremony": begin.json()["ceremony"],
                                                       "credential": passkey.create(begin.json()["options"])})
        self.assertEqual(finish.status, 200, finish.error)
        return finish.json()["account"], passkey

    def passkey_login(self, browser: Browser, passkey: Passkey) -> Response:
        begin = browser.post("/api/login/begin", {})
        self.assertEqual(begin.status, 200, begin.error)
        return browser.post("/api/login/finish", {"ceremony": begin.json()["ceremony"],
                                                  "credential": passkey.get(begin.json()["options"])})

    def passkey_add(self, browser: Browser, begin: Response, passkey: Passkey) -> Response:
        """Answers a /api/passkeys/begin prompt with a new passkey."""
        return browser.post("/api/passkeys/finish", {"ceremony": begin.json()["ceremony"],
                                                     "credential": passkey.create(begin.json()["options"])})

    def assert_needs_passkey(self, response: Response) -> None:
        """Refused until the browser signs in with a passkey."""
        self.assertEqual(response.status, 401)
        self.assertEqual((response.json().get("signIn"), response.json().get("signInWith")), (True, "passkey"))

    # Discord

    def discord_start(self, browser: Browser, intent: str, **body) -> str:
        response = browser.post("/api/discord/start", {"intent": intent, **body})
        self.assertEqual(response.status, 200, response.error)
        return response.json()["redirect"]

    def discord_flow(self, browser: Browser, intent: str, user: dict, deny: bool = False, **body) -> Response:
        """Starts a Discord sign-in, consents (or not) at Discord and returns the callback's answer."""
        return browser.open(self.discord.authorize(self.discord_start(browser, intent, **body), user, deny))

    def discord_signup(self, browser: Browser, user: dict, name: str = "Discord user") -> str:
        response = self.discord_flow(browser, "signup", user, name=name)
        self.assertEqual(response.result, "created")
        return self.account(browser)["id"]

    def discord_link(self, browser: Browser, user: dict) -> None:
        """Links `user` to the browser's account: Discord's answer is held by the callback, and the
        page finishes with a same-origin POST that carries the session."""
        self.assert_callback(self.discord_flow(browser, "link", user), "link-pending")
        response = self.link_finish(browser)
        self.assertEqual(response.status, 200, response.error)
        self.assertEqual(response.json(), {"result": "linked"})

    def link_finish(self, browser: Browser, origin: str | None = ORIGIN) -> Response:
        """The page's POST after a "link-pending" callback. Once Discord sign-in is on and the
        request is same-origin, whatever the answer, both Discord cookies are cleared: the held
        answer is used up."""
        response = browser.post("/api/discord/link/finish", {}, origin=origin)
        if origin == ORIGIN and response.status != 404:
            for name in (DISCORD_COOKIE, DISCORD_LINK_COOKIE):
                cleared = response.cookie(name)
                self.assertTrue(cleared is not None and cleared["max-age"] == "0", f"{name} is not cleared")
        self.assertIsNone(response.cookie(portal.SESSION_COOKIE), "finishing a link changed the session")
        return response

    def unlink(self, browser: Browser, shown: dict | None = None, **options) -> Response:
        """The page's "Unlink Discord" button: sends the account ID and Discord ID the page shows
        (`shown`, an /api/account answer the page loaded; by default the current one)."""
        if shown is None:
            shown = self.account(browser)
        return browser.post("/api/discord/unlink", {"account": shown["id"],
                                                    "discord_id": (shown["discord"] or {}).get("id", ""), **options})

    def account(self, browser: Browser) -> dict:
        response = browser.get("/api/account")
        self.assertEqual(response.status, 200, response.error)
        return response.json()

    def assert_signed_out(self, browser: Browser) -> None:
        self.assertEqual(browser.get("/api/account").status, 401)

    def assert_callback(self, response: Response, result: str, session: bool = False) -> None:
        """A callback answer: a redirect to the page with `result`; the OAuth cookie cleared, except
        for "link-pending", which sets the Strict cookie the page's finishing POST needs; and a
        session cookie only when `session`."""
        self.assertEqual(response.status, 303)
        self.assertEqual(response.result, result)
        location = urlsplit(response.location)
        self.assertEqual((location.scheme, location.netloc), ("", ""), "the callback redirects off the portal")
        oauth = response.cookie(DISCORD_COOKIE)
        link = response.cookie(DISCORD_LINK_COOKIE)
        if result == "link-pending":
            self.assertIsNone(oauth, "the OAuth cookie changed before linking finished")
            self.assertIsNotNone(link, "no link cookie")
            self.assertEqual(link["path"], "/")
            self.assertIn("secure", link)
            self.assertIn("httponly", link)
            self.assertEqual(link["samesite"].lower(), "strict")
            self.assertNotIn("domain", link)
            self.assertTrue(0 < int(link["max-age"]) <= portal.DISCORD_LINK_SECONDS)
        else:
            self.assertIsNotNone(oauth, "the callback leaves the OAuth cookie")
            self.assertEqual(oauth["max-age"], "0")
            self.assertIsNone(link, "a link cookie without a link")
        cookie = response.cookie(portal.SESSION_COOKIE)
        if session:
            self.assertIsNotNone(cookie, "no session cookie")
            self.assertNotEqual(cookie.get("max-age"), "0")
            self.assertEqual(cookie.get("path"), "/")
            self.assertIn("secure", cookie)
            self.assertIn("httponly", cookie)
            self.assertEqual(cookie.get("samesite", "").lower(), "strict")
            self.assertNotIn("domain", cookie)
        else:
            self.assertTrue(cookie is None or cookie.get("max-age") == "0", "a session cookie was set")

    # Launchers

    def approve(self, browser: Browser, launcher: Launcher) -> str:
        """Approves the launcher's link request; returns the one-time code its loopback receives."""
        response = browser.post("/api/link/approve", launcher.request)
        self.assertEqual(response.status, 200, response.error)
        redirect = urlsplit(response.json()["redirect"])
        self.assertEqual(f"{redirect.scheme}://{redirect.netloc}{redirect.path}",
                         f"http://127.0.0.1:{launcher.request['port']}/callback")
        query = parse_qs(redirect.query)
        self.assertEqual(query["state"], [launcher.request["state"]])
        return query["code"][0]

    def redeem(self, launcher: Launcher, code: str) -> Response:
        """launcher.py's /api/link/token call: no cookies, no Origin."""
        return self.browser().post("/api/link/token", {"code": code, "verifier": launcher.verifier,
                                                       "csr": launcher.csr_pem}, origin=None)

    def redeem_while(self, launcher: Launcher, code: str, action) -> Response:
        """Redeems the code with `action` run once at the worst moment: after the portal checked the
        code, while it makes the certificate (later certificates, such as one `action` itself causes,
        are made as usual). A failure in `action` is raised here."""
        issue_certificate = portal.issue_certificate
        actions, failures = [action], []

        def issue(*args, **kwargs):
            if actions:
                run = actions.pop()
                try:
                    run()
                except BaseException as exc:  # in the portal's request thread; re-raised below
                    failures.append(exc)
            return issue_certificate(*args, **kwargs)

        with mock.patch.object(portal, "issue_certificate", issue):
            response = self.redeem(launcher, code)
        if failures:
            raise failures[0]
        return response

    def server_principal(self, certificate_pem: str) -> server.Principal | None:
        """Whose launcher server.py (--auth-db) takes this certificate for."""
        der = x509.load_pem_x509_certificate(certificate_pem.encode()).public_bytes(serialization.Encoding.DER)
        registry = server.AuthRegistry(self.db_path)
        try:
            return registry.principal(der)
        finally:
            registry.db.close()


class DisabledByDefaultTest(PortalTest):
    """Without Discord configuration the portal behaves as before: passkeys only."""

    discord_configured = False

    def test_discord_routes_are_off_and_passkeys_work(self) -> None:
        browser = self.browser()
        self.assertIs(browser.get("/api/config").json()["discord"], False)
        for intent in ("signin", "signup", "link"):
            response = browser.post("/api/discord/start", {"intent": intent, "name": "Nelly"})
            self.assertEqual(response.status, 404, intent)
            self.assertIsNone(response.cookie(DISCORD_COOKIE))
        self.assertEqual(browser.get("/auth/discord/callback?code=abc&state=" + "s" * 43 + "&iss=" + ISSUER).status, 404)

        account_id, passkey = self.passkey_signup(browser, "Nelly")
        info = self.account(browser)
        self.assertEqual(info["id"], account_id)
        self.assertIsNone(info["discord"])
        self.assertEqual(info["signed_in_with"], {"type": "passkey", "id": passkey.id})
        other = self.browser()
        self.assertEqual(self.passkey_login(other, passkey).status, 200)
        self.assertEqual(self.account(other)["id"], account_id)
        self.assertEqual(browser.post("/api/discord/unlink", {}).status, 400)
        self.assertEqual(self.unlink(browser).status, 409)
        self.assertEqual(self.link_finish(browser).status, 404)
        self.assertEqual(info["discord_enabled"], False)
        self.assertEqual((self.discord.token_requests, self.discord.user_requests), (0, 0))

    def test_portal_started_with_the_old_options_has_discord_off(self) -> None:
        args = self.portal_args(discord=False)
        for name in ("discord_client_id_file", "discord_client_secret_file", "discord_proxy"):
            delattr(args, name)
        self.stop_portal()
        self.start_portal(args)
        browser = self.browser()
        self.assertIs(browser.get("/api/config").json()["discord"], False)
        account_id, _ = self.passkey_signup(browser)
        self.assertEqual(self.account(browser)["id"], account_id)

    def test_incomplete_or_invalid_configuration_stops_the_portal_without_echoing_it(self) -> None:
        secret_like = "Zq8Wx7Ec6Rv5Tb4Yn3Um2"
        id_file, secret_file = self.root / "bad-id", self.root / "bad-secret"

        def refused(content: tuple[str, str] | None = None, **options) -> str:
            if content is not None:
                id_file.write_text(content[0])
                secret_file.write_text(content[1])
                if os.name == "posix":
                    id_file.chmod(0o600)
                    secret_file.chmod(0o600)
                options = {"discord_client_id_file": id_file, "discord_client_secret_file": secret_file, **options}
            with self.assertRaises(SystemExit) as raised:
                portal.Portal(self.portal_args(discord=False, **options))
            return str(raised.exception.code)

        for case, content in {
            "secret with a space": (CLIENT_ID, secret_like + " tail"),
            "secret too short": (CLIENT_ID, secret_like[:8]),
            "client id not a snowflake": ("discord-app-" + secret_like, CLIENT_SECRET),
            "empty client id": ("", CLIENT_SECRET),
        }.items():
            with self.subTest(case=case):
                self.assertFalse(secret_like[:8] in refused(content), "the error repeats the file's content")
        for case, options in {
            "client id file alone": {"discord_client_id_file": self.id_file},
            "client secret file alone": {"discord_client_secret_file": self.secret_file},
            "proxy alone": {"discord_proxy": "http://127.0.0.1:3128"},
            "missing file": {"discord_client_id_file": self.root / "missing", "discord_client_secret_file": self.secret_file},
        }.items():
            with self.subTest(case=case):
                self.assertFalse(CLIENT_SECRET in refused(**options), "the error repeats the client secret")
        for proxy in ("http://user:" + secret_like + "@127.0.0.1:3128", "https://127.0.0.1:3128", "http://127.0.0.1"):
            with self.subTest(proxy=proxy):
                self.assertFalse(secret_like in refused((CLIENT_ID, CLIENT_SECRET), discord_proxy=proxy),
                                 "the error repeats the proxy password")
        if os.name == "posix":
            self.secret_file.chmod(0o644)
            self.assertFalse(CLIENT_SECRET in refused(discord_client_id_file=self.id_file,
                                                      discord_client_secret_file=self.secret_file),
                             "the error repeats the client secret")


class DiscordSignInTest(PortalTest):
    # Sign-up and sign-in

    def test_new_account_then_repeat_sign_in_reaches_the_same_account(self) -> None:
        self.assertIs(self.browser().get("/api/config").json()["discord"], True)
        user = self.discord.new_user("nelly")
        browser = self.browser()
        response = self.discord_flow(browser, "signup", user, name="Nelly")
        self.assert_callback(response, "created", session=True)
        self.assertEqual(urlsplit(response.location).path, "/")
        info = self.account(browser)
        account_id = info["id"]
        self.assertEqual(info["name"], "Nelly")
        self.assertEqual(info["passkeys"], [])
        self.assertEqual(info["discord"]["id"], user["id"])
        self.assertTrue(info["discord"]["current"])
        self.assertIsNone(info["discord"]["added_with"])
        self.assertEqual(info["signed_in_with"], {"type": "discord", "id": user["id"]})
        handle = self.query("SELECT user_handle FROM accounts WHERE id = ?", account_id)[0][0]
        self.assertEqual(len(handle), 32)
        self.assertEqual((self.discord.token_requests, self.discord.user_requests), (1, 1))

        self.assertEqual(browser.post("/api/logout", {}).status, 200)
        self.assert_signed_out(browser)
        # The numeric ID decides, not the name: Discord names change.
        renamed = dict(user, username="nelly_renamed", global_name="Someone Else")
        response = self.discord_flow(browser, "signin", renamed)
        self.assert_callback(response, "signed-in", session=True)
        self.assertEqual(self.account(browser)["id"], account_id)
        laptop = self.browser()
        self.assert_callback(self.discord_flow(laptop, "signin", user), "signed-in", session=True)
        self.assertEqual(self.account(laptop)["id"], account_id)
        self.assertEqual(self.count("accounts"), 1)

        # Signing out on one browser leaves the other signed in.
        self.assertEqual(laptop.post("/api/logout", {}).status, 200)
        self.assert_signed_out(laptop)
        self.assertEqual(self.account(browser)["id"], account_id)

        # Signing up again with the same Discord account creates nothing.
        again = self.browser()
        self.assert_callback(self.discord_flow(again, "signup", user, name="Nelly again"), "already-linked")
        self.assert_signed_out(again)
        self.assertEqual(self.count("accounts"), 1)

    def test_sessions_of_discord_sign_ins_expire(self) -> None:
        browser = self.browser()
        self.discord_signup(browser, self.discord.new_user("nelly"))
        self.clock.advance(portal.SESSION_SECONDS + 1)
        self.assert_signed_out(browser)

    def test_authorization_request_asks_only_for_identify(self) -> None:
        browser = self.browser()
        response = browser.post("/api/discord/start", {"intent": "signin"})
        self.assertEqual(response.status, 200, response.error)
        redirect = response.json()["redirect"]
        cookie = response.cookie(DISCORD_COOKIE)
        self.assertIsNotNone(cookie, "no OAuth cookie")
        self.assertEqual(cookie["path"], "/")
        self.assertIn("secure", cookie)
        self.assertIn("httponly", cookie)
        self.assertEqual(cookie["samesite"].lower(), "lax")
        self.assertNotIn("domain", cookie)
        self.assertTrue(0 < int(cookie["max-age"]) <= portal.DISCORD_FLOW_SECONDS)
        self.assertGreaterEqual(len(cookie["value"]), 32)

        params = {name: values[0] for name, values in parse_qs(urlsplit(redirect).query).items()}
        self.assertEqual(params["scope"], "identify")
        self.assertEqual(params["redirect_uri"], REDIRECT_URI)
        second = browser.post("/api/discord/start", {"intent": "signin"}).json()["redirect"]
        second_params = {name: values[0] for name, values in parse_qs(urlsplit(second).query).items()}
        self.assertNotEqual(second_params["state"], params["state"])
        self.assertNotEqual(second_params["code_challenge"], params["code_challenge"])
        self.assertNotEqual(cookie["value"], params["state"])

        user = self.discord.new_user("nelly")
        self.discord_signup(self.browser(), user)
        callback = self.discord.authorize(second, user)
        self.assert_callback(browser.open(callback), "signed-in", session=True)
        # The verifier only ever went to Discord's token endpoint.
        self.assertEqual(len(self.discord.verifiers), 2)
        self.assertFalse(self.discord.verifiers[-1] in redirect + second, "the PKCE verifier is in the URL")

    def test_wider_or_missing_scope_is_refused(self) -> None:
        user = self.discord.new_user("nelly")
        account_id = self.discord_signup(self.browser(), user)
        for changes in ({"scope": "identify guilds"}, {"scope": "identify email"}, {"scope": "bot identify"},
                        {"scope": ""}, {"token_type": "mac"}):
            with self.subTest(changes=changes):
                self.discord.token_changes = changes
                for intent, body in (("signin", {}), ("signup", {"name": "Wide"})):
                    browser = self.browser()
                    self.assert_callback(self.discord_flow(browser, intent, user, **body), "failed")
                    self.assert_signed_out(browser)
        self.discord.token_changes = {}
        self.assertEqual([row[0] for row in self.query("SELECT id FROM accounts")], [account_id])

    def test_identity_is_never_merged_into_a_passkey_account(self) -> None:
        passkey_browser = self.browser()
        passkey_account, passkey = self.passkey_signup(passkey_browser, "nelly")
        # Same name, display name and an email: none of it associates accounts.
        user = self.discord.new_user("nelly", global_name="nelly", email="nelly@example.org", verified=True)
        browser = self.browser()
        self.assert_callback(self.discord_flow(browser, "signin", user), "not-linked")
        self.assert_signed_out(browser)
        self.assertEqual(self.count("discord_identities"), 0)

        self.assert_callback(self.discord_flow(browser, "signup", user, name="nelly"), "created", session=True)
        discord_account = self.account(browser)
        self.assertNotEqual(discord_account["id"], passkey_account)
        self.assertEqual(discord_account["passkeys"], [])
        original = self.account(passkey_browser)
        self.assertEqual(original["id"], passkey_account)
        self.assertIsNone(original["discord"])
        self.assertEqual([key["id"] for key in original["passkeys"]], [passkey.id])
        self.assertEqual(self.passkey_login(self.browser(), passkey).json()["account"], passkey_account)

    def test_discord_only_account_adds_just_its_first_passkey_with_discord(self) -> None:
        user = self.discord.new_user("nelly")
        browser = self.browser()
        account_id = self.discord_signup(browser, user)
        # Two passkey prompts opened at once with the Discord session: only the first finishes.
        begins = [browser.post("/api/passkeys/begin", {}) for _ in range(2)]
        for begin in begins:
            self.assertEqual(begin.status, 200, begin.error)
        passkey, intruder = Passkey(), Passkey()
        added = self.passkey_add(browser, begins[0], passkey)
        self.assertEqual(added.status, 200, added.error)
        self.assert_needs_passkey(self.passkey_add(browser, begins[1], intruder))
        self.assertEqual([(key["id"], key["added_type"], key["added_with"]) for key in self.account(browser)["passkeys"]],
                         [(passkey.id, "discord", user["id"])])
        self.assertEqual(self.passkey_login(self.browser(), intruder).status, 400)
        # From now on passkeys change only with a passkey sign-in.
        self.assert_needs_passkey(browser.post("/api/passkeys/begin", {}))
        self.assert_needs_passkey(browser.post("/api/passkeys/delete", {"passkey": passkey.id}))
        other = self.browser()
        self.assertEqual(self.passkey_login(other, passkey).json()["account"], account_id)
        # With a passkey the account can let go of Discord.
        self.assertEqual(self.unlink(other).status, 200)
        self.assert_signed_out(browser)
        self.assert_callback(self.discord_flow(self.browser(), "signin", user), "not-linked")
        self.assertEqual(self.account(other)["id"], account_id)

    # The OAuth state and its cookie

    def test_callback_only_completes_in_the_browser_that_started_it(self) -> None:
        user = self.discord.new_user("nelly")
        victim, attacker = self.browser(), self.browser()
        callback = self.discord.authorize(self.discord_start(victim, "signup", name="Nelly"), user)
        # The callback opened without the OAuth cookie (another browser, or one that never started)
        # fails, and uses up the state: the code is never redeemed.
        self.assert_callback(attacker.open(callback), "expired")
        self.assert_signed_out(attacker)
        self.assert_callback(victim.open(callback), "expired")
        self.assert_signed_out(victim)
        self.assertEqual((self.discord.token_requests, self.count("accounts")), (0, 0))

        # Each browser's cookie only goes with its own state.
        first, second = self.browser(), self.browser()
        first_callback = self.discord.authorize(self.discord_start(first, "signup", name="First"), user)
        self.discord.authorize(self.discord_start(second, "signup", name="Second"), user)
        self.assert_callback(second.open(first_callback), "expired")
        self.assert_signed_out(second)
        self.assertEqual((self.discord.token_requests, self.count("accounts")), (0, 0))

        # A forged or tampered cookie does not help either.
        third = self.browser()
        third_callback = self.discord.authorize(self.discord_start(third, "signup", name="Third"), user)
        third.cookies[DISCORD_COOKIE] = secrets.token_urlsafe(32)
        self.assert_callback(third.open(third_callback), "expired")
        fourth = self.browser()
        self.discord_start(fourth, "signup", name="Fourth")
        self.assert_callback(fourth.open(with_query(third_callback, state=secrets.token_urlsafe(32))), "expired")
        self.assertEqual((self.discord.token_requests, self.count("accounts")), (0, 0))

    def test_callback_cannot_be_replayed(self) -> None:
        user = self.discord.new_user("nelly")
        account_id = self.discord_signup(self.browser(), user)
        browser = self.browser()
        callback = self.discord.authorize(self.discord_start(browser, "signin"), user)
        oauth_cookie = browser.cookies[DISCORD_COOKIE]
        self.assert_callback(browser.open(callback), "signed-in", session=True)
        replay = self.browser()
        replay.cookies[DISCORD_COOKIE] = oauth_cookie
        self.assert_callback(replay.open(callback), "expired")
        self.assert_signed_out(replay)
        self.assertEqual(self.discord.token_requests, 2)

        # Two requests with the same state at once: one completes.
        browser = self.browser()
        callback = self.discord.authorize(self.discord_start(browser, "signin"), user)
        tabs = [browser.copy(), browser.copy()]
        barrier = threading.Barrier(2)
        responses: list[Response | None] = [None, None]

        def open_tab(index: int) -> None:
            barrier.wait(5)
            responses[index] = tabs[index].open(callback)

        threads = [threading.Thread(target=open_tab, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.assertEqual(sorted(response.result for response in responses), ["expired", "signed-in"])
        winner = tabs[[response.result for response in responses].index("signed-in")]
        self.assertEqual(self.account(winner)["id"], account_id)
        self.assertEqual(self.discord.token_requests, 3)

    def test_issuer_denial_and_malformed_callbacks_fail(self) -> None:
        user = self.discord.new_user("nelly")
        self.discord_signup(self.browser(), user)
        before = self.discord.token_requests
        cases = {
            "issuer of another server": lambda url: with_query(url, iss="https://discord.example"),
            "issuer over http": lambda url: with_query(url, iss="http://discord.com"),
            "no issuer": lambda url: with_query(url, iss=None),
            "no code": lambda url: with_query(url, code=None),
            "repeated code": lambda url: url + "&code=" + secrets.token_urlsafe(24),
            "repeated state": lambda url: url + "&state=" + parse_qs(urlsplit(url).query)["state"][0],
            "other error": lambda url: with_query(url, code=None, error="server_error"),
        }
        for case, tamper in cases.items():
            with self.subTest(case=case):
                browser = self.browser()
                callback = tamper(self.discord.authorize(self.discord_start(browser, "signin"), user))
                self.assert_callback(browser.open(callback), "failed")
                self.assert_signed_out(browser)
        self.assertEqual(self.discord.token_requests, before)

        # Declining at Discord cancels, and the state is used up.
        browser = self.browser()
        redirect = self.discord_start(browser, "signin")
        oauth_cookie = browser.cookies[DISCORD_COOKIE]
        denied = self.discord.authorize(redirect, user, deny=True)
        self.assert_callback(browser.open(denied), "cancelled")
        browser.cookies[DISCORD_COOKIE] = oauth_cookie
        late = self.discord.authorize(redirect, user)
        self.assertEqual(parse_qs(urlsplit(late).query)["state"], parse_qs(urlsplit(denied).query)["state"])
        self.assert_callback(browser.open(late), "expired")
        self.assert_signed_out(browser)

        # A code Discord does not know, and Discord being down.
        browser = self.browser()
        callback = self.discord.authorize(self.discord_start(browser, "signin"), user)
        self.assert_callback(browser.open(with_query(callback, code=secrets.token_urlsafe(24))), "failed")
        self.assert_signed_out(browser)
        self.discord.outage = True
        browser = self.browser()
        self.assert_callback(self.discord_flow(browser, "signin", user), "unavailable")
        self.assert_signed_out(browser)

    def test_flow_expires(self) -> None:
        user = self.discord.new_user("nelly")
        self.discord_signup(self.browser(), user)
        before = self.discord.token_requests
        browser = self.browser()
        callback = self.discord.authorize(self.discord_start(browser, "signin"), user)
        self.clock.advance(portal.DISCORD_FLOW_SECONDS + 1)
        self.assert_callback(browser.open(callback), "expired")
        self.assert_signed_out(browser)
        self.assertEqual(self.discord.token_requests, before)

    def test_cross_origin_start_is_refused(self) -> None:
        browser = self.browser()
        for origin in ("https://evil.example", None, "http://portal.test"):
            with self.subTest(origin=origin):
                response = browser.post("/api/discord/start", {"intent": "signin"}, origin=origin)
                self.assertEqual(response.status, 403)
                self.assertIsNone(response.cookie(DISCORD_COOKIE))
        self.assertEqual(browser.post("/api/discord/start", {"intent": "admin"}).status, 400)

    # Explicit linking

    def test_linking_needs_a_recent_passkey_sign_in_of_the_account(self) -> None:
        user = self.discord.new_user("nelly")
        anonymous = self.browser()
        response = anonymous.post("/api/discord/start", {"intent": "link"})
        self.assertEqual(response.status, 401)
        self.assertIsNone(response.cookie(DISCORD_COOKIE))

        browser = self.browser()
        account_id, passkey = self.passkey_signup(browser, "Nelly")
        self.clock.advance(portal.RECENT_SIGN_IN_SECONDS + 1)
        response = browser.post("/api/discord/start", {"intent": "link"})
        self.assertEqual(response.status, 401)
        self.assertEqual((response.json().get("signIn"), response.json().get("signInWith")), (True, "passkey"))
        self.assertIsNone(response.cookie(DISCORD_COOKIE))

        def link_pending(browser: Browser) -> None:
            callback = self.discord.authorize(self.discord_start(browser, "link"), user)
            self.assert_callback(browser.open(callback), "link-pending")

        # The callback alone links nothing: Discord's answer waits for the page's POST.
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        link_pending(browser)
        self.assertEqual(self.count("discord_identities"), 0)
        # A cross-site POST cannot finish it, nor use it up.
        self.assertEqual(self.link_finish(browser, origin="https://evil.example").status, 403)
        self.assertEqual(self.count("discord_identities"), 0)
        # Without the OAuth cookie of the browser that started, it is refused and used up.
        held = dict(browser.cookies)
        del browser.cookies[DISCORD_COOKIE]
        self.assertEqual(self.link_finish(browser).status, 400)
        browser.cookies.update(held)
        self.assertEqual(self.link_finish(browser).status, 400)
        self.assertEqual(self.count("discord_identities"), 0)

        # Discord's answer expires.
        link_pending(browser)
        self.clock.advance(portal.DISCORD_LINK_SECONDS + 1)
        self.assertEqual(self.link_finish(browser).status, 400)
        # The sign-in turns stale before the page finishes.
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        self.clock.advance(portal.RECENT_SIGN_IN_SECONDS - portal.DISCORD_LINK_SECONDS // 2)
        link_pending(browser)
        self.clock.advance(portal.DISCORD_LINK_SECONDS // 2 + 1)
        self.assertEqual(self.link_finish(browser).status, 403)
        # Signed out meanwhile.
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        link_pending(browser)
        self.assertEqual(browser.post("/api/logout", {}).status, 200)
        self.assertEqual(self.link_finish(browser).status, 403)
        # Signed in again meanwhile: the same account, but not the session that started.
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        link_pending(browser)
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        self.assertEqual(self.link_finish(browser).status, 403)
        # Signed in to another account meanwhile, in another tab: neither account gets it, and the
        # used-up answer cannot be replayed.
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        callback = self.discord.authorize(self.discord_start(browser, "link"), user)
        other_account, other_passkey = self.passkey_signup(browser, "Other")
        self.assert_callback(browser.open(callback), "link-pending")
        held = dict(browser.cookies)
        response = self.link_finish(browser)
        self.assertEqual(response.status, 403)
        self.assertNotIn("signIn", response.json())
        browser.cookies.update(held)
        self.assertEqual(self.link_finish(browser).status, 400)
        self.assertIsNone(self.account(browser)["discord"])
        self.assertEqual(self.count("discord_identities"), 0)

        # Recent and the same session from start to finish: linked, and the session goes on.
        self.assertEqual(self.passkey_login(browser, passkey).status, 200)
        session = browser.cookies[portal.SESSION_COOKIE]
        self.discord_link(browser, user)
        self.assertEqual(browser.cookies[portal.SESSION_COOKIE], session)
        info = self.account(browser)
        self.assertEqual((info["id"], info["signed_in_with"]), (account_id, {"type": "passkey", "id": passkey.id}))
        self.assertEqual(info["discord"]["id"], user["id"])
        self.assertEqual(info["discord"]["added_with"], passkey.id)
        self.assertFalse(info["discord"]["current"])
        self.assertEqual([tuple(row) for row in self.query("SELECT discord_id, account_id FROM discord_identities")],
                         [(user["id"], account_id)])
        elsewhere = self.browser()
        self.assert_callback(self.discord_flow(elsewhere, "signin", user), "signed-in", session=True)
        info = self.account(elsewhere)
        self.assertEqual((info["id"], info["signed_in_with"]), (account_id, {"type": "discord", "id": user["id"]}))
        self.assertTrue(info["discord"]["current"])

        # A Discord sign-in does not count for linking: that takes a passkey.
        response = elsewhere.post("/api/discord/start", {"intent": "link"})
        self.assertEqual((response.status, response.json().get("signInWith")), (400, "passkey"))
        self.assertIsNone(response.cookie(DISCORD_COOKIE))

        # The other account, signed in with its passkey, links a Discord account of its own.
        other_browser = self.browser()
        self.assertEqual(self.passkey_login(other_browser, other_passkey).status, 200)
        second = self.discord.new_user("second")
        self.discord_link(other_browser, second)
        info = self.account(other_browser)
        self.assertEqual((info["id"], info["discord"]["id"]), (other_account, second["id"]))

    def test_identity_linked_to_an_account_cannot_be_linked_again(self) -> None:
        user = self.discord.new_user("nelly")
        owner = self.discord_signup(self.browser(), user)
        browser = self.browser()
        account_id, _ = self.passkey_signup(browser, "Taker")
        self.assert_callback(self.discord_flow(browser, "link", user), "link-pending")
        self.assertEqual(self.link_finish(browser).status, 409)
        self.assertIsNone(self.account(browser)["discord"])
        self.assertEqual([tuple(row) for row in self.query("SELECT discord_id, account_id FROM discord_identities")],
                         [(user["id"], owner)])

        # An account has one Discord identity.
        second = self.discord.new_user("second")
        self.discord_link(browser, second)
        response = browser.post("/api/discord/start", {"intent": "link"})
        self.assertEqual(response.status, 409)
        self.assertIsNone(response.cookie(DISCORD_COOKIE))
        self.assertEqual(self.account(browser)["discord"]["id"], second["id"])
        self.assertEqual(self.query("SELECT account_id FROM discord_identities WHERE discord_id = ?",
                                    second["id"])[0][0], account_id)

        # Two link flows of one account in two tabs: the second Discord account is not added.
        racer = self.browser()
        racer_account, _ = self.passkey_signup(racer, "Racer")
        tabs = [racer.copy(), racer.copy()]
        first, third = self.discord.new_user("first"), self.discord.new_user("third")
        first_callback = self.discord.authorize(self.discord_start(tabs[0], "link"), first)
        third_callback = self.discord.authorize(self.discord_start(tabs[1], "link"), third)
        self.assert_callback(tabs[0].open(first_callback), "link-pending")
        self.assert_callback(tabs[1].open(third_callback), "link-pending")
        finished = self.link_finish(tabs[0])
        self.assertEqual(finished.status, 200, finished.error)
        self.assertEqual(self.link_finish(tabs[1]).status, 409)
        self.assertEqual(self.account(racer)["discord"]["id"], first["id"])
        self.assertEqual(self.query("SELECT account_id FROM discord_identities WHERE discord_id = ?", third["id"]), [])
        self.assertEqual(self.query("SELECT account_id FROM discord_identities WHERE discord_id = ?",
                                    first["id"])[0][0], racer_account)

    def test_concurrent_links_of_one_identity_link_one_account(self) -> None:
        user = self.discord.new_user("nelly")
        browsers = [self.browser(), self.browser()]
        for number, browser in enumerate(browsers):
            self.passkey_signup(browser, f"Account {number}")
            callback = self.discord.authorize(self.discord_start(browser, "link"), user)
            self.assert_callback(browser.open(callback), "link-pending")
        barrier = threading.Barrier(2)
        responses: list[Response | None] = [None, None]

        def finish(index: int) -> None:
            barrier.wait(5)
            responses[index] = browsers[index].post("/api/discord/link/finish", {})

        threads = [threading.Thread(target=finish, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.assertEqual(sorted(response.status for response in responses), [200, 409])
        winner = browsers[[response.status for response in responses].index(200)]
        self.assertEqual(self.query("SELECT account_id FROM discord_identities WHERE discord_id = ?", user["id"])[0][0],
                         self.account(winner)["id"])
        self.assertEqual(self.count("discord_identities"), 1)

    # Account state

    def test_disabled_account_cannot_sign_in_with_discord(self) -> None:
        user = self.discord.new_user("nelly")
        browser = self.browser()
        account_id = self.discord_signup(browser, user)
        launcher = Launcher()
        code = self.approve(browser, launcher)
        self.admin("disable", account_id)
        self.assert_signed_out(browser)
        other = self.browser()
        self.assert_callback(self.discord_flow(other, "signin", user), "not-linked")
        self.assert_signed_out(other)
        self.assertEqual(self.redeem(launcher, code).status, 400)  # disabling dropped the pending approval
        self.assertEqual(self.count("devices"), 0)

        # A passkey account with Discord linked, disabled: Discord does not get around it.
        linked_browser = self.browser()
        linked_account, passkey = self.passkey_signup(linked_browser, "Linked")
        linked_user = self.discord.new_user("linked")
        self.discord_link(linked_browser, linked_user)
        self.admin("disable", linked_account)
        self.assert_callback(self.discord_flow(self.browser(), "signin", linked_user), "not-linked")
        self.assertEqual(self.passkey_login(self.browser(), passkey).status, 400)

        self.admin("enable", account_id)
        again = self.browser()
        self.assert_callback(self.discord_flow(again, "signin", user), "signed-in", session=True)
        self.assertEqual(self.account(again)["id"], account_id)

    def test_closed_sign_up_still_lets_existing_accounts_sign_in(self) -> None:
        user = self.discord.new_user("nelly")
        account_id = self.discord_signup(self.browser(), user)
        passkey_account, passkey = self.passkey_signup(self.browser(), "Passkey")
        self.restart_portal(closed=True)
        browser = self.browser()
        response = browser.post("/api/discord/start", {"intent": "signup", "name": "Newcomer"})
        self.assertEqual(response.status, 403)
        self.assertIsNone(response.cookie(DISCORD_COOKIE))
        self.assertEqual(browser.post("/api/register/begin", {"name": "Newcomer"}).status, 403)
        self.assert_callback(self.discord_flow(browser, "signin", user), "signed-in", session=True)
        self.assertEqual(self.account(browser)["id"], account_id)
        self.assertEqual(self.passkey_login(self.browser(), passkey).json()["account"], passkey_account)
        self.assertEqual(self.count("accounts"), 2)

    def test_admission_is_checked_again_when_discord_returns(self) -> None:
        browser = self.browser()
        callback = self.discord.authorize(self.discord_start(browser, "signup", name="Late"),
                                          self.discord.new_user("late"))
        self.portal.registration_open = False
        self.assert_callback(browser.open(callback), "signup-refused")
        self.assert_signed_out(browser)
        self.assertEqual(self.count("accounts"), 0)

        self.restart_portal(max_accounts=1)
        self.discord_signup(self.browser(), self.discord.new_user("first"))
        response = self.browser().post("/api/discord/start", {"intent": "signup", "name": "Second"})
        self.assertEqual(response.status, 403)
        self.assertEqual(self.count("accounts"), 1)

    def test_removed_accounts_free_their_identity(self) -> None:
        user = self.discord.new_user("nelly")
        deleted = self.discord_signup(self.browser(), user)
        self.admin("delete", deleted)
        self.assertEqual(self.count("discord_identities"), 0)
        self.assertEqual([row[0] for row in self.query("SELECT id FROM deleted_accounts")], [deleted])
        browser = self.browser()
        self.assert_callback(self.discord_flow(browser, "signin", user), "not-linked")
        recreated = self.discord_signup(browser, user)
        self.assertNotEqual(recreated, deleted)

        # An account that never linked a launcher is pruned with its identity.
        self.clock.advance(portal.UNLINKED_ACCOUNT_SECONDS + 1)
        self.portal.prune_unlinked()
        self.assertEqual((self.count("accounts"), self.count("discord_identities")), (0, 0))
        self.assert_signed_out(browser)
        self.assert_callback(self.discord_flow(self.browser(), "signin", user), "not-linked")

    def test_discord_sessions_need_discord_configured(self) -> None:
        user = self.discord.new_user("nelly")
        discord_browser = self.browser()
        account_id = self.discord_signup(discord_browser, user)
        passkey_browser = self.browser()
        self.passkey_signup(passkey_browser)
        self.restart_portal(discord=False)
        self.assert_signed_out(discord_browser)
        self.assertEqual(passkey_browser.get("/api/account").status, 200)
        self.assertEqual(self.query("SELECT account_id FROM discord_identities")[0][0], account_id)

    # Unlinking and the last sign-in method

    def test_unlinking_ends_discord_sessions_and_keeps_a_sign_in_method(self) -> None:
        user = self.discord.new_user("nelly")
        passkey_browser = self.browser()
        account_id, passkey = self.passkey_signup(passkey_browser, "Nelly")
        self.discord_link(passkey_browser, user)
        discord_browser = self.browser()
        self.assert_callback(self.discord_flow(discord_browser, "signin", user), "signed-in", session=True)

        response = self.unlink(discord_browser)
        self.assertEqual((response.status, response.json().get("signIn"), response.json().get("signInWith")),
                         (400, True, "passkey"))
        self.clock.advance(portal.RECENT_SIGN_IN_SECONDS + 1)
        self.assertEqual(self.unlink(passkey_browser).status, 401)
        self.assertEqual(self.account(passkey_browser)["discord"]["id"], user["id"])
        self.assertEqual(passkey_browser.post("/api/discord/unlink", {"account": account_id}).status, 400)

        self.assertEqual(self.passkey_login(passkey_browser, passkey).status, 200)
        page = self.account(passkey_browser)
        response = self.unlink(passkey_browser, page, revoke_launchers=False)
        self.assertEqual(response.status, 200, response.error)
        self.assertEqual(response.json(), {"revoked_launchers": 0})
        self.assertIsNone(self.account(passkey_browser)["discord"])
        self.assert_signed_out(discord_browser)
        self.assert_callback(self.discord_flow(self.browser(), "signin", user), "not-linked")
        self.assertEqual(self.unlink(passkey_browser, page).status, 409)  # that page is out of date now

        # Discord-only: unlinking would lock the account out.
        only_browser = self.browser()
        only_user = self.discord.new_user("only")
        only_account = self.discord_signup(only_browser, only_user)
        self.assertEqual(self.unlink(only_browser).status, 403)
        self.assertEqual(self.account(only_browser)["discord"]["id"], only_user["id"])
        self.assertNotEqual(only_account, account_id)

    def test_unlink_from_a_page_of_another_account_changes_nothing(self) -> None:
        browser = self.browser()
        alice_account, _ = self.passkey_signup(browser, "Alice")
        alice_user = self.discord.new_user("alice")
        self.discord_link(browser, alice_user)
        alice_page = self.account(browser)
        # The same browser then signs in to Bob's account in another tab; Bob has Discord linked too,
        # with a launcher linked and one approved through it.
        bob_account, _ = self.passkey_signup(browser, "Bob")
        bob_user = self.discord.new_user("bob")
        self.discord_link(browser, bob_user)
        bob_page = self.account(browser)
        bob_discord = self.browser()
        self.assert_callback(self.discord_flow(bob_discord, "signin", bob_user), "signed-in", session=True)
        launcher = Launcher()
        linked = self.redeem(launcher, self.approve(bob_discord, launcher))
        self.assertEqual(linked.status, 200, linked.error)
        pending = Launcher("Pending PC")
        code = self.approve(bob_discord, pending)

        # Alice's page, still open in the first tab, asks to unlink and revoke launchers.
        response = self.unlink(browser, alice_page, revoke_launchers=True)
        self.assertEqual(response.status, 409)
        self.assertNotIn("signIn", response.json())
        # Pages that show another account, or another Discord account, than the session has.
        self.assertEqual(self.unlink(browser, dict(bob_page, id=alice_account), revoke_launchers=True).status, 409)
        self.assertEqual(self.unlink(browser, dict(bob_page, discord={"id": alice_user["id"]}),
                                     revoke_launchers=True).status, 409)
        # Nothing changed for either account.
        self.assertEqual(sorted(tuple(row) for row in self.query("SELECT discord_id, account_id FROM discord_identities")),
                         sorted([(alice_user["id"], alice_account), (bob_user["id"], bob_account)]))
        self.assertEqual(self.account(bob_discord)["id"], bob_account)
        self.assertEqual(self.server_principal(linked.json()["certificate"]),
                         server.Principal(bob_account, linked.json()["device"]))
        redeemed = self.redeem(pending, code)
        self.assertEqual(redeemed.status, 200, redeemed.error)

        # Bob's own page unlinks Bob's Discord account, and only that.
        response = self.unlink(browser, bob_page, revoke_launchers=True)
        self.assertEqual(response.status, 200, response.error)
        self.assertEqual(response.json(), {"revoked_launchers": 2})
        self.assert_signed_out(bob_discord)
        self.assertEqual([tuple(row) for row in self.query("SELECT discord_id, account_id FROM discord_identities")],
                         [(alice_user["id"], alice_account)])

    def test_discord_session_cannot_change_the_passkeys_of_an_account_with_one(self) -> None:
        user = self.discord.new_user("nelly")
        passkey_browser = self.browser()
        account_id, passkey = self.passkey_signup(passkey_browser, "Nelly")
        self.discord_link(passkey_browser, user)
        discord_browser = self.browser()
        self.assert_callback(self.discord_flow(discord_browser, "signin", user), "signed-in", session=True)
        # Someone holding only the Discord account can neither add a passkey of their own nor
        # remove the owner's, not even by answering a prompt the owner's session opened.
        self.assert_needs_passkey(discord_browser.post("/api/passkeys/begin", {}))
        self.assert_needs_passkey(discord_browser.post("/api/passkeys/delete", {"passkey": passkey.id}))
        begin = passkey_browser.post("/api/passkeys/begin", {})
        self.assertEqual(begin.status, 200, begin.error)
        intruder = Passkey()
        self.assert_needs_passkey(self.passkey_add(discord_browser, begin, intruder))
        self.assertEqual(self.passkey_login(self.browser(), intruder).status, 400)
        self.assertEqual([key["id"] for key in self.account(passkey_browser)["passkeys"]], [passkey.id])
        self.assertEqual(self.passkey_login(self.browser(), passkey).json()["account"], account_id)

        # The owner's only passkey stays even with Discord linked; their passkey session adds more.
        response = passkey_browser.post("/api/passkeys/delete", {"passkey": passkey.id})
        self.assertEqual(response.status, 403)
        second = Passkey()
        added = self.passkey_add(passkey_browser, passkey_browser.post("/api/passkeys/begin", {}), second)
        self.assertEqual(added.status, 200, added.error)
        self.assertEqual({(key["id"], key["added_type"], key["added_with"])
                          for key in self.account(passkey_browser)["passkeys"]},
                         {(passkey.id, None, None), (second.id, "passkey", passkey.id)})
        self.assert_needs_passkey(discord_browser.post("/api/passkeys/delete", {"passkey": second.id}))
        self.assertEqual(self.passkey_login(self.browser(), second).json()["account"], account_id)

    # Launchers approved through Discord

    def test_launcher_linked_through_discord_sign_in(self) -> None:
        user = self.discord.new_user("nelly")
        account_id = self.discord_signup(self.browser(), user)
        launcher = Launcher()
        browser = self.browser()
        # The launcher's link request survives the trip to Discord.
        response = self.discord_flow(browser, "signin", user, link=launcher.request)
        self.assert_callback(response, "signed-in", session=True)
        location = urlsplit(response.location)
        self.assertEqual(location.path, "/link")
        self.assertEqual({name: values[0] for name, values in parse_qs(location.query).items()},
                         {name: str(value) for name, value in launcher.request.items()})

        code = self.approve(browser, launcher)
        redeemed = self.redeem(launcher, code)
        self.assertEqual(redeemed.status, 200, redeemed.error)
        result = redeemed.json()
        self.assertEqual(result["account"], account_id)
        certificate = x509.load_pem_x509_certificate(result["certificate"].encode())
        self.assertEqual(certificate.public_key().public_numbers(), launcher.key.public_key().public_numbers())
        self.assertEqual(self.server_principal(result["certificate"]), server.Principal(account_id, result["device"]))
        device = next(device for device in self.account(browser)["devices"] if device["id"] == result["device"])
        self.assertEqual((device["linked_type"], device["linked_with"]), ("discord", user["id"]))
        self.assertEqual(self.redeem(launcher, code).status, 400)  # single use

        # A code redeemed twice at once makes one launcher.
        again = Launcher("Second PC")
        code = self.approve(browser, again)
        inner: list[Response] = []
        outer = self.redeem_while(again, code, lambda: inner.append(self.redeem(again, code)))
        self.assertEqual(sorted([outer.status, inner[0].status]), [200, 400])
        self.assertEqual(len([device for device in self.account(browser)["devices"] if device["name"] == "Second PC"]), 1)

        # A link request that is malformed is refused before leaving for Discord.
        bad = dict(launcher.request, challenge="short")
        self.assertEqual(self.browser().post("/api/discord/start", {"intent": "signin", "link": bad}).status, 400)

    def test_link_code_approved_with_a_removed_identity_is_refused(self) -> None:
        user = self.discord.new_user("nelly")
        passkey_browser = self.browser()
        account_id, _ = self.passkey_signup(passkey_browser, "Nelly")
        other_browser = self.browser()
        other_account, _ = self.passkey_signup(other_browser, "Other")
        self.discord_link(passkey_browser, user)
        discord_browser = self.browser()

        def sign_in_with_discord() -> None:
            self.assert_callback(self.discord_flow(discord_browser, "signin", user), "signed-in", session=True)

        def unlink() -> None:
            response = self.unlink(passkey_browser)
            self.assertEqual(response.status, 200, response.error)

        sign_in_with_discord()
        linked = Launcher("Linked PC")
        linked_result = self.redeem(linked, self.approve(discord_browser, linked))
        self.assertEqual(linked_result.status, 200, linked_result.error)
        certificate = linked_result.json()["certificate"]
        pending = Launcher("Pending PC")
        code = self.approve(discord_browser, pending)

        response = self.unlink(passkey_browser, revoke_launchers=True)
        self.assertEqual(response.status, 200, response.error)
        self.assertEqual(response.json(), {"revoked_launchers": 1})
        self.assertEqual(self.redeem(pending, code).status, 400)
        self.assert_signed_out(discord_browser)
        self.assertIsNone(self.server_principal(certificate))
        devices = self.account(passkey_browser)["devices"]
        self.assertEqual(len(devices), 1)
        self.assertIsNotNone(devices[0]["revoked"])

        # Without revoke_launchers, launchers stay linked.
        self.discord_link(passkey_browser, user)
        sign_in_with_discord()
        kept = Launcher("Kept PC")
        kept_result = self.redeem(kept, self.approve(discord_browser, kept))
        self.assertEqual(kept_result.status, 200, kept_result.error)
        response = self.unlink(passkey_browser, revoke_launchers=False)
        self.assertEqual(response.json(), {"revoked_launchers": 0})
        self.assertEqual(self.server_principal(kept_result.json()["certificate"]),
                         server.Principal(account_id, kept_result.json()["device"]))
        self.assertEqual(self.count("devices"), 2)

        # While a launcher's certificate is being made, after its code was checked, Discord is:
        def relink_here() -> None:
            unlink()
            self.discord_link(passkey_browser, user)

        def relink_elsewhere() -> None:
            unlink()
            self.discord_link(other_browser, user)

        for case, action, owner in (("unlinked", unlink, None), ("unlinked and linked again", relink_here, account_id),
                                    ("moved to another account", relink_elsewhere, other_account)):
            with self.subTest(case=case):
                if not self.account(passkey_browser)["discord"]:
                    self.discord_link(passkey_browser, user)
                sign_in_with_discord()
                racing = Launcher("Racing PC")
                code = self.approve(discord_browser, racing)
                response = self.redeem_while(racing, code, action)
                self.assertEqual(response.status, 400)
                self.assertNotIn("certificate", response.json())
                self.assertEqual(self.redeem(racing, code).status, 400)
                self.assertEqual(self.count("devices"), 2)
                self.assert_signed_out(discord_browser)
                self.assertEqual([row[0] for row in self.query(
                    "SELECT account_id FROM discord_identities WHERE discord_id = ?", user["id"])],
                    [] if owner is None else [owner])
        self.assertEqual(self.account(other_browser)["devices"], [])

    # Discord's latency

    def test_waiting_on_discord_blocks_nothing_else(self) -> None:
        user = self.discord.new_user("nelly")
        self.discord_signup(self.browser(), user)
        passkey_browser = self.browser()
        _, passkey = self.passkey_signup(passkey_browser)
        browser = self.browser()
        callback = self.discord.authorize(self.discord_start(browser, "signin"), user)
        self.discord.hold(1)
        responses: list[Response] = []
        thread = threading.Thread(target=lambda: responses.append(browser.open(callback)))
        thread.start()
        try:
            self.discord.wait_held(1)
            # Discord holds the exchange for 30 seconds; these must not wait for it.
            other = self.browser()
            other.timeout = passkey_browser.timeout = 5
            try:
                self.assertEqual(self.passkey_login(other, passkey).status, 200)
                self.assertEqual(passkey_browser.get("/api/account").status, 200)
                self.assertEqual(self.browser().get("/api/config").status, 200)
            except TimeoutError:
                self.fail("the portal stopped answering while a Discord request was in flight")
        finally:
            self.discord.release()
            thread.join(15)
        self.assert_callback(responses[0], "signed-in", session=True)

    def test_concurrent_exchanges_are_bounded(self) -> None:
        limit = portal.DISCORD_MAX_CONCURRENT
        browsers = [self.browser() for _ in range(limit + 1)]
        callbacks = [self.discord.authorize(self.discord_start(browser, "signin"),
                                            self.discord.new_user(f"user{number}"))
                     for number, browser in enumerate(browsers)]
        self.discord.hold(limit)
        results: list[str | None] = [None] * limit
        threads = [threading.Thread(target=lambda index=index: results.__setitem__(
            index, browsers[index].open(callbacks[index]).result)) for index in range(limit)]
        for thread in threads:
            thread.start()
        try:
            self.discord.wait_held(limit)
            self.assert_callback(browsers[limit].open(callbacks[limit]), "busy")
        finally:
            self.discord.release()
            for thread in threads:
                thread.join(15)
        self.assertEqual(results, ["not-linked"] * limit)


class MigrationTest(PortalTest):
    """A version 1 database (passkeys only) is migrated in place with everything kept."""

    def prepare_database(self) -> None:
        now = int(time.time())
        self.alice_key, self.alice_second_key, self.bob_key = Passkey(), Passkey(), Passkey()
        self.alice_key.user_handle = self.alice_second_key.user_handle = secrets.token_bytes(32)
        self.bob_key.user_handle = secrets.token_bytes(32)
        self.alice_key.sign_count = 7
        ca_cert = x509.load_pem_x509_certificate((self.root / "pki" / "device-ca.crt").read_bytes())
        ca_key = serialization.load_pem_private_key((self.root / "pki" / "device-ca.key").read_bytes(), None)
        self.certificates = {}
        for device in ("dev-alice", "dev-alice-revoked", "dev-bob"):
            key = ec.generate_private_key(ec.SECP256R1())
            self.certificates[device] = portal.pem(portal.issue_certificate(
                ca_key, ca_cert, key.public_key(), device, 30)).decode()

        def fingerprint(device: str) -> str:
            der = x509.load_pem_x509_certificate(self.certificates[device].encode()).public_bytes(
                serialization.Encoding.DER)
            return hashlib.sha256(der).hexdigest()

        self.session_token = secrets.token_urlsafe(32)
        self.launcher = Launcher("Old PC")
        self.link_code = secrets.token_urlsafe(32)
        self.v1_rows = {
            "accounts": [("acct-alice", self.alice_key.user_handle, "Alice", now - 5000, None),
                         ("acct-bob", self.bob_key.user_handle, "Bob", now - 4000, now - 100)],
            "passkeys": [(self.alice_key.credential_id, "acct-alice", self.alice_key.public_key(), 7, now - 5000,
                          now - 200, None),
                         (self.alice_second_key.credential_id, "acct-alice", self.alice_second_key.public_key(), 0,
                          now - 3000, None, self.alice_key.credential_id),
                         (self.bob_key.credential_id, "acct-bob", self.bob_key.public_key(), 0, now - 4000, None,
                          None)],
            "devices": [("dev-alice", "acct-alice", "Desk", fingerprint("dev-alice"), now - 4500, now + 86400 * 30,
                         None, self.alice_key.credential_id),
                        ("dev-alice-revoked", "acct-alice", "Old laptop", fingerprint("dev-alice-revoked"),
                         now - 4400, now + 86400 * 30, now - 300, self.alice_second_key.credential_id),
                        ("dev-bob", "acct-bob", "Bob's PC", fingerprint("dev-bob"), now - 3900, now + 86400 * 30,
                         None, self.bob_key.credential_id)],
            "sessions": [(portal.sha256(self.session_token), "acct-alice", self.alice_key.credential_id, now - 60,
                          now + 1700)],
            "link_codes": [(portal.sha256(self.link_code), "acct-alice", self.alice_key.credential_id,
                            self.launcher.request["challenge"], self.launcher.request["csr"], "Old PC", now + 250)],
            "deleted_accounts": [("acct-carol", now - 50)],
        }
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(V1_SCHEMA)
            for table, rows in self.v1_rows.items():
                for row in rows:
                    conn.execute(f"INSERT INTO {table} VALUES ({', '.join('?' * len(row))})", row)
            conn.execute("PRAGMA user_version = 1")
            conn.commit()

    def v1_columns(self, table: str) -> list[tuple]:
        columns = {
            "accounts": "id, user_handle, name, created_at, disabled_at",
            "passkeys": "credential_id, account_id, public_key, sign_count, created_at, last_used_at, added_with",
            "devices": "id, account_id, name, cert_sha256, created_at, expires_at, revoked_at, linked_with",
            "sessions": "token_sha256, account_id, credential_id, signed_in_at, expires_at",
            "link_codes": "code_sha256, account_id, credential_id, code_challenge, csr_sha256, device_name, expires_at",
            "deleted_accounts": "id, deleted_at",
        }[table]
        return sorted(tuple(row) for row in self.query(f"SELECT {columns} FROM {table}"))

    def test_existing_passkey_data_is_kept(self) -> None:
        self.assertEqual(self.query("PRAGMA user_version")[0][0], 2)
        for table, rows in self.v1_rows.items():
            self.assertEqual(self.v1_columns(table), sorted(rows), table)
        self.assertEqual(self.count("discord_identities"), 0)
        self.assertEqual({row[0] for row in self.query("SELECT auth_type FROM sessions")}, {"passkey"})
        self.assertEqual({row[0] for row in self.query("SELECT auth_type FROM link_codes")}, {"passkey"})
        self.assertEqual(self.query("PRAGMA foreign_key_check"), [])
        self.assertEqual(self.query("PRAGMA integrity_check")[0][0], "ok")

        # server.py reads the migrated database as before.
        self.assertEqual(self.server_principal(self.certificates["dev-alice"]), server.Principal("acct-alice", "dev-alice"))
        self.assertIsNone(self.server_principal(self.certificates["dev-alice-revoked"]))
        self.assertIsNone(self.server_principal(self.certificates["dev-bob"]))
        registry = server.AuthRegistry(self.db_path)
        try:
            self.assertEqual(registry.deleted_accounts(), {"acct-carol"})
        finally:
            registry.db.close()

        # The session signed in before the migration goes on.
        browser = self.browser()
        browser.cookies[portal.SESSION_COOKIE] = self.session_token
        info = self.account(browser)
        self.assertEqual(info["id"], "acct-alice")
        self.assertEqual(info["signed_in_with"], {"type": "passkey", "id": self.alice_key.id})
        self.assertIsNone(info["discord"])
        passkeys = {key["id"]: key for key in info["passkeys"]}
        self.assertEqual(set(passkeys), {self.alice_key.id, self.alice_second_key.id})
        self.assertIsNone(passkeys[self.alice_key.id]["added_with"])
        self.assertEqual((passkeys[self.alice_second_key.id]["added_type"],
                          passkeys[self.alice_second_key.id]["added_with"]), ("passkey", self.alice_key.id))
        devices = {device["id"]: device for device in info["devices"]}
        self.assertEqual((devices["dev-alice"]["linked_type"], devices["dev-alice"]["linked_with"]),
                         ("passkey", self.alice_key.id))
        self.assertIsNotNone(devices["dev-alice-revoked"]["revoked"])

        # The launcher approval made before the migration can still be redeemed.
        redeemed = self.redeem(self.launcher, self.link_code)
        self.assertEqual(redeemed.status, 200, redeemed.error)
        device = next(device for device in self.account(browser)["devices"] if device["id"] == redeemed.json()["device"])
        self.assertEqual((device["linked_type"], device["linked_with"]), ("passkey", self.alice_key.id))

        # The passkeys still sign in (the sign count carries on); the disabled account's do not.
        for passkey in (self.alice_key, self.alice_second_key):
            response = self.passkey_login(self.browser(), passkey)
            self.assertEqual(response.status, 200, response.error)
            self.assertEqual(response.json()["account"], "acct-alice")
        self.assertEqual(self.passkey_login(self.browser(), self.bob_key).status, 400)

        # And the account can now link Discord.
        user = self.discord.new_user("alice")
        self.discord_link(browser, user)
        self.assert_callback(self.discord_flow(self.browser(), "signin", user), "signed-in", session=True)

        # Opening the migrated database again changes nothing.
        before = {table: self.v1_columns(table) for table in self.v1_rows}
        self.restart_portal()
        self.assertEqual(self.query("PRAGMA user_version")[0][0], 2)
        self.assertEqual({table: self.v1_columns(table) for table in self.v1_rows}, before)
        self.assertEqual(self.account(browser)["discord"]["id"], user["id"])

    def test_database_of_an_unknown_version_is_left_alone(self) -> None:
        future = self.root / "future.db"
        with contextlib.closing(sqlite3.connect(future)) as conn:
            conn.executescript(V1_SCHEMA)
            conn.execute("PRAGMA user_version = 99")
            conn.commit()
        original = future.read_bytes()
        with self.assertRaises(SystemExit):
            portal.open_database(future)
        gc.collect()  # the refused connection is closed, so the temporary directory can go
        self.assertEqual(future.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
