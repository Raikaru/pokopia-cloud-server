#!/usr/bin/env python3
"""Account portal for a Pokopia Cloud server: passkey accounts and launcher linking.

Anyone who can open the portal can create an account with a passkey (WebAuthn) and then link the
PCs that run launcher.py to it. Linking hands the launcher a client certificate for a key that never
leaves that PC, signed by the device CA. server.py in client-certificate mode (--client-ca and
--auth-db) only accepts connections that present one of these certificates, and authorizes every
call by the account the certificate's device belongs to (the devices table of this database).

Linking follows OAuth for native apps (RFC 8252 with PKCE, RFC 7636): the launcher opens
/link?port=&state=&challenge=&csr=&name= in the browser; after a passkey sign-in and an explicit
approval the browser is sent to http://127.0.0.1:<port>/callback with a one-time code; the launcher
redeems the code at /api/link/token with the PKCE verifier and a CSR whose SHA-256 the approval named.
A code is single use, expires after LINK_CODE_SECONDS and only ever reaches the approving PC.

The portal speaks plain HTTP on a loopback port. Browsers only offer passkeys to secure contexts and
bind them to a host name, so it must sit behind a reverse proxy that serves it as --origin with a
publicly trusted certificate (for example Caddy), and --rp-id must be that host name or a parent of
it. Changing the RP ID later makes every passkey unusable.

Subcommands:
  init-pki       create the device CA, the ingress CA and the ingress server certificate
  serve          run the portal
  accounts       list accounts
  disable        disable an account (its launchers are refused, its sessions end)
  enable         re-enable an account
  revoke-device  revoke one linked launcher
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json_dict
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

log = logging.getLogger("portal")

CEREMONY_SECONDS = 300  # a passkey prompt must be answered within this
SESSION_SECONDS = 1800  # browser sessions are short; the portal is only used to link and manage
RECENT_SIGN_IN_SECONDS = 600  # passkey changes and launcher linking need a sign-in this recent
LINK_CODE_SECONDS = 300
MAX_BODY = 64 * 1024
MAX_PENDING_CEREMONIES = 10000
MAX_PASSKEYS = 10
MAX_DEVICES = 10  # linked launchers that are neither revoked nor expired
# An account that never links a launcher has no game data; it is removed after this, which frees
# its place under --max-accounts.
UNLINKED_ACCOUNT_SECONDS = 7 * 86400
PRUNE_INTERVAL_SECONDS = 600
SESSION_COOKIE = "__Host-session"
PKCE = re.compile(r"[A-Za-z0-9_-]{43}")  # BASE64URL(SHA-256(verifier)), RFC 7636 S256
VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
STATE = re.compile(r"[A-Za-z0-9_-]{16,128}")
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
HOST_NAME = re.compile(r"(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")

SECURITY_HEADERS = [
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
     "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Cache-Control", "no-store"),
]

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    user_handle BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
);
CREATE TABLE IF NOT EXISTS passkeys (
    credential_id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    added_with BLOB  -- the passkey whose sign-in added this one; NULL for the first
);
CREATE INDEX IF NOT EXISTS passkeys_account ON passkeys(account_id);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    linked_with BLOB NOT NULL  -- the passkey whose sign-in approved the link
);
CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);
CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    credential_id BLOB NOT NULL,  -- the passkey it signed in with; it ends with that passkey
    signed_in_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS link_codes (
    code_sha256 BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    credential_id BLOB NOT NULL,  -- the passkey of the approving session
    code_challenge TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    device_name TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
-- Accounts an operator deleted. server.py purges their game data.
CREATE TABLE IF NOT EXISTS deleted_accounts (
    id TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL
);
"""


class ApiError(Exception):
    def __init__(self, status: int, message: str, sign_in: bool = False):
        super().__init__(message)
        self.status = status
        self.message = message
        self.sign_in = sign_in  # the page should ask for a passkey sign-in and try again


def sha256(data: str | bytes) -> bytes:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).digest()


def new_id(prefix: str) -> str:
    return prefix + base64.b32encode(secrets.token_bytes(15)).decode().lower()


def clean_name(value: object, limit: int) -> str:
    """A display name: 1 to `limit` characters, whitespace collapsed, no control or format
    characters (which could hide or reorder text in the account page)."""
    if not isinstance(value, str):
        raise ApiError(400, "Enter a name.")
    value = " ".join(value.split())
    if not value or len(value) > limit or any(
            unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co", "Cn") for char in value):
        raise ApiError(400, f"Names are 1 to {limit} characters, without control characters.")
    return value


def open_database(path: Path) -> sqlite3.Connection:
    # Rollback-journal mode (not WAL) so that server.py can read the file with a read-only
    # connection, without write access to -wal/-shm files.
    conn = sqlite3.connect(path, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION and conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]:
        raise SystemExit(f"{path} has schema version {version}, not {SCHEMA_VERSION}; it was made by "
                         "another version of portal.py")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return conn


def delete_account(conn: sqlite3.Connection, account_id: str, tombstone: bool) -> None:
    """Removes an account with its passkeys, sessions, link codes and launchers. A tombstone makes
    server.py purge the account's game data."""
    for table in ("sessions", "link_codes", "passkeys", "devices"):
        conn.execute(f"DELETE FROM {table} WHERE account_id = ?", (account_id,))
    conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    if tombstone:
        conn.execute("INSERT OR IGNORE INTO deleted_accounts (id, deleted_at) VALUES (?, ?)",
                     (account_id, int(time.time())))


# --- Certificates ------------------------------------------------------------------------------


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def make_ca(common_name: str, days: int) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_certificate(ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate, public_key,
                      common_name: str, days: int, server_name: str | None = None) -> x509.Certificate:
    """A leaf certificate: for TLS clients, or for TLS servers named `server_name`."""
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(min(now + datetime.timedelta(days=days), ca_cert.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH if server_name else ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
    )
    if server_name:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(server_name)]),
                                        critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_new(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), mode)
    with os.fdopen(fd, "wb") as file:
        file.write(data)


PKI_FILES = ("device-ca.key", "device-ca.crt", "ingress-ca.key", "ingress-ca.crt", "ingress.key",
             "ingress.crt")


def init_pki(directory: Path, ingress_name: str) -> None:
    """Creates the CAs and the ingress certificate once; never overwrites them."""
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    existing = [name for name in PKI_FILES if (directory / name).exists()]
    if existing:
        sys.exit(f"refusing to overwrite {', '.join(existing)} in {directory}")
    device_key, device_cert = make_ca("Pokopia Cloud Device CA", 3650)
    ingress_ca_key, ingress_ca_cert = make_ca("Pokopia Cloud Ingress CA", 3650)
    ingress_key = ec.generate_private_key(ec.SECP256R1())
    ingress_cert = issue_certificate(ingress_ca_key, ingress_ca_cert, ingress_key.public_key(),
                                     ingress_name, 3650, server_name=ingress_name)
    write_new(directory / "device-ca.key", key_pem(device_key), 0o600)
    write_new(directory / "device-ca.crt", pem(device_cert), 0o644)
    write_new(directory / "ingress-ca.key", key_pem(ingress_ca_key), 0o600)
    write_new(directory / "ingress-ca.crt", pem(ingress_ca_cert), 0o644)
    # server.py, running as another user in the portal's group, reads the ingress key.
    write_new(directory / "ingress.key", key_pem(ingress_key), 0o640)
    write_new(directory / "ingress.crt", pem(ingress_cert), 0o644)
    print(f"Created {', '.join(PKI_FILES)} in {directory}.")
    print("server.py needs device-ca.crt (--client-ca), ingress.crt (--cert) and ingress.key (--key);")
    print("ingress.key is readable by this directory's group for that. The portal needs device-ca.key,")
    print("device-ca.crt and ingress-ca.crt. ingress-ca.key is only needed to issue a new ingress")
    print("certificate; keep it offline.")


# --- Portal state ------------------------------------------------------------------------------


class Ceremonies:
    """WebAuthn challenges waiting for their passkey response: single use, CEREMONY_SECONDS."""

    def __init__(self) -> None:
        self.pending: dict[str, tuple[float, str, dict]] = {}
        self.lock = threading.Lock()

    def put(self, kind: str, data: dict) -> str:
        ceremony = secrets.token_urlsafe(24)
        now = time.monotonic()
        with self.lock:
            if len(self.pending) >= MAX_PENDING_CEREMONIES:
                self.pending = {key: value for key, value in self.pending.items() if value[0] > now}
                if len(self.pending) >= MAX_PENDING_CEREMONIES:
                    raise ApiError(503, "The server is busy. Try again in a few minutes.")
            self.pending[ceremony] = (now + CEREMONY_SECONDS, kind, data)
        return ceremony

    def take(self, ceremony: object, kind: str) -> dict:
        with self.lock:
            entry = self.pending.pop(ceremony, None) if isinstance(ceremony, str) else None
        if entry is None or entry[0] < time.monotonic() or entry[1] != kind:
            raise ApiError(400, "This request expired. Try again.")
        return entry[2]


class RateLimiter:
    """Sliding-window request counts per (bucket, client address)."""

    def __init__(self) -> None:
        self.hits: dict[tuple[str, str], list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, bucket: str, client: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self.lock:
            if len(self.hits) > 100000:
                # Every window is at most an hour.
                self.hits = {key: times for key, times in self.hits.items() if times[-1] > now - 3600}
            times = [hit for hit in self.hits.get((bucket, client), []) if hit > now - window]
            allowed = len(times) < limit
            if allowed:
                times.append(now)
            self.hits[(bucket, client)] = times
            return allowed


class Portal:
    def __init__(self, args: argparse.Namespace):
        self.db = open_database(args.db)
        self.lock = threading.RLock()  # serializes all use of self.db
        self.rp_id = args.rp_id
        self.rp_name = args.rp_name
        self.origin = args.origin
        self.registration_open = not args.closed
        self.max_accounts = args.max_accounts
        self.max_signups_per_day = args.max_signups_per_day
        self.device_days = args.device_days
        self.last_prune = float("-inf")
        self.trusted_proxies = set(args.trusted_proxy)
        self.ingress = {"host": args.ingress_host, "port": args.ingress_port,
                        "server_name": args.ingress_name or args.ingress_host}
        pki = args.pki_dir
        self.device_ca_cert = x509.load_pem_x509_certificate((pki / "device-ca.crt").read_bytes())
        self.device_ca_key = serialization.load_pem_private_key((pki / "device-ca.key").read_bytes(), None)
        if self.device_ca_key.public_key().public_numbers() != self.device_ca_cert.public_key().public_numbers():
            raise SystemExit("device-ca.key does not belong to device-ca.crt")
        self.ingress["ca"] = (pki / "ingress-ca.crt").read_text("ascii")
        x509.load_pem_x509_certificate(self.ingress["ca"].encode())
        self.ceremonies = Ceremonies()
        self.limiter = RateLimiter()

    def admission_problem(self, conn: sqlite3.Connection) -> str | None:
        """Why no account can be created now: registration is closed, --max-accounts enabled
        accounts exist, or --max-signups-per-day were created within a day. Disabled and deleted
        accounts do not count towards --max-accounts. Call with self.lock held."""
        if not self.registration_open:
            return "This server is not accepting new accounts."
        enabled = conn.execute("SELECT COUNT(*) FROM accounts WHERE disabled_at IS NULL").fetchone()[0]
        if enabled >= self.max_accounts:
            return "This server is full and not accepting new accounts."
        recent = conn.execute("SELECT COUNT(*) FROM accounts WHERE created_at > ?",
                              (int(time.time()) - 86400,)).fetchone()[0]
        if recent >= self.max_signups_per_day:
            return "This server has had too many new accounts today. Try again tomorrow."
        return None

    def prune_unlinked(self) -> None:
        """Removes, at most every PRUNE_INTERVAL_SECONDS, the accounts older than
        UNLINKED_ACCOUNT_SECONDS that never linked a launcher. They never reached the server, so
        they have no game data."""
        with self.lock:
            if time.monotonic() - self.last_prune < PRUNE_INTERVAL_SECONDS:
                return
            self.last_prune = time.monotonic()
            with self.db as conn:
                stale = [row[0] for row in conn.execute(
                    "SELECT id FROM accounts WHERE created_at < ? AND NOT EXISTS "
                    "(SELECT 1 FROM devices WHERE devices.account_id = accounts.id)",
                    (int(time.time()) - UNLINKED_ACCOUNT_SECONDS,))]
                for account_id in stale:
                    delete_account(conn, account_id, tombstone=False)
        if stale:
            log.info("removed %d account(s) that never linked a launcher", len(stale))

    def active_devices(self, account_id: str, now: int) -> int:
        with self.lock:
            return self.db.execute(
                "SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at IS NULL AND expires_at > ?",
                (account_id, now)).fetchone()[0]

    def passkey_ids(self, account_id: str) -> list[bytes]:
        with self.lock:
            return [row[0] for row in self.db.execute(
                "SELECT credential_id FROM passkeys WHERE account_id = ?", (account_id,))]

    def registration_options(self, user_handle: bytes, name: str, exclude: list[bytes]):
        return generate_registration_options(
            rp_id=self.rp_id, rp_name=self.rp_name, user_name=name, user_id=user_handle,
            user_display_name=name, timeout=CEREMONY_SECONDS * 1000,
            exclude_credentials=[PublicKeyCredentialDescriptor(id=credential) for credential in exclude],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED))

    def verify_registration(self, pending: dict, credential: dict):
        try:
            return verify_registration_response(
                credential=credential, expected_challenge=pending["challenge"],
                expected_rp_id=self.rp_id, expected_origin=self.origin,
                require_user_verification=True)
        except Exception as exc:  # any failure means the passkey is not verified
            log.info("passkey registration not verified: %s", exc)
            raise ApiError(400, "The passkey could not be verified.") from None


# --- HTTP --------------------------------------------------------------------------------------


def credential_of(body: dict) -> dict:
    credential = body.get("credential")
    if not isinstance(credential, dict):
        raise ApiError(400, "Missing passkey response.")
    return credential


class Handler(BaseHTTPRequestHandler):
    server_version = "pokopia-portal"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    @property
    def portal(self) -> Portal:
        return self.server.portal

    def log_message(self, format: str, *args) -> None:
        log.info("%s %s", self.client_ip(), format % args)

    def client_ip(self) -> str:
        peer = self.client_address[0]
        headers = getattr(self, "headers", None)  # missing when the request line was malformed
        if peer in self.portal.trusted_proxies and headers is not None:
            forwarded = headers.get("X-Forwarded-For", "").split(",")[-1].strip()
            if forwarded:
                return forwarded
        return peer

    # Responses

    def send(self, status: int, body: bytes, content_type: str,
             headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in [*SECURITY_HEADERS, *(headers or [])]:
            self.send_header(name, value)
        if status >= 400:
            # The request body may not have been read; never reuse the connection.
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, value: dict) -> None:
        self.send(status, json.dumps(value).encode(), "application/json", self.cookies)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/link"):
            self.send(200, PAGE_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self.send(200, APP_JS.encode(), "text/javascript; charset=utf-8")
        elif path == "/app.css":
            self.send(200, APP_CSS.encode(), "text/css; charset=utf-8")
        elif path == "/api/account":
            self.run_api(Handler.account_info)
        else:
            self.send(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        route = POST_ROUTES.get(urlsplit(self.path).path)
        if route is None:
            self.send(404, b"not found\n", "text/plain; charset=utf-8")
            return
        self.run_api(*route, post=True)

    def run_api(self, handler, from_browser: bool = True, post: bool = False) -> None:
        self.cookies: list[tuple[str, str]] = []
        try:
            body: dict = {}
            if post:
                if not self.portal.limiter.allow("post", self.client_ip(), 120, 60):
                    raise ApiError(429, "Too many requests. Try again in a minute.")
                # Browser calls carry the session cookie; the Origin check and the JSON content type
                # (which a cross-site form cannot send) stop cross-site requests.
                if from_browser and self.headers.get("Origin") != self.portal.origin:
                    raise ApiError(403, "Cross-origin request refused.")
                body = self.read_json()
            self.send_json(200, handler(self, body))
        except ApiError as exc:
            self.send_json(exc.status, {"error": exc.message, **({"signIn": True} if exc.sign_in else {})})
        except Exception:
            log.exception("%s failed", self.path)
            self.send_json(500, {"error": "Internal error."})

    def read_json(self) -> dict:
        if self.headers.get_content_type() != "application/json":
            raise ApiError(415, "Expected JSON.")
        length = self.headers.get("Content-Length", "")
        if not length.isdigit():
            raise ApiError(411, "Content-Length required.")
        if int(length) > MAX_BODY:
            raise ApiError(413, "Request too large.")
        try:
            body = json.loads(self.rfile.read(int(length)))
        except ValueError:
            raise ApiError(400, "Malformed JSON.") from None
        if not isinstance(body, dict):
            raise ApiError(400, "Expected a JSON object.")
        return body

    # Sessions

    def session_token(self) -> str | None:
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel is not None else None

    @staticmethod
    def find_session(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
        """The account of a live session, with the session's credential_id and signed_in_at: the
        session unexpired, the passkey it signed in with still registered to the account, and the
        account enabled."""
        if token is None:
            return None
        return conn.execute(
            "SELECT accounts.*, sessions.credential_id, sessions.signed_in_at FROM sessions "
            "JOIN accounts ON accounts.id = sessions.account_id "
            "JOIN passkeys ON passkeys.credential_id = sessions.credential_id "
            "AND passkeys.account_id = sessions.account_id "
            "WHERE sessions.token_sha256 = ? AND sessions.expires_at > ? AND accounts.disabled_at IS NULL",
            (sha256(token), int(time.time()))).fetchone()

    @staticmethod
    def checked_session(account: sqlite3.Row | None, recent: bool) -> sqlite3.Row:
        if account is None:
            raise ApiError(401, "Sign in first.")
        if recent and account["signed_in_at"] < time.time() - RECENT_SIGN_IN_SECONDS:
            raise ApiError(401, "Confirm with your passkey first.", sign_in=True)
        return account

    def session_account(self) -> sqlite3.Row | None:
        with self.portal.lock:
            return self.find_session(self.portal.db, self.session_token())

    def require_session(self, recent: bool = False) -> sqlite3.Row:
        """The signed-in account, for reading. With `recent`, the sign-in must be at most
        RECENT_SIGN_IN_SECONDS old, as for changing passkeys and linking launchers."""
        return self.checked_session(self.session_account(), recent)

    @contextlib.contextmanager
    def session_transaction(self, recent: bool = False):
        """A write transaction for a signed-in change: BEGIN IMMEDIATE (so no other request, nor
        the administration commands in another process, can change the account in between), then
        the session read again inside it, so a passkey removed or an account disabled by a
        concurrent request stops this one. Yields (connection, account)."""
        token = self.session_token()
        with self.portal.lock, self.portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            yield conn, self.checked_session(self.find_session(conn, token), recent)

    def start_session(self, conn: sqlite3.Connection, account_id: str, credential_id: bytes) -> None:
        """Signs in with a passkey, inside the caller's transaction (so a passkey removed meanwhile
        cannot leave a session behind)."""
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute("INSERT INTO sessions (token_sha256, account_id, credential_id, signed_in_at, expires_at) "
                     "VALUES (?, ?, ?, ?, ?)", (sha256(token), account_id, credential_id, now, now + SESSION_SECONDS))
        self.cookies.append(("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_SECONDS}; "
                                           "Secure; HttpOnly; SameSite=Strict"))

    # Sign-up and sign-in

    def register_begin(self, body: dict) -> dict:
        portal = self.portal
        portal.prune_unlinked()
        if not portal.limiter.allow("register", self.client_ip(), 10, 3600):
            raise ApiError(429, "Too many sign-ups from your network. Try again later.")
        name = clean_name(body.get("name"), 32)
        with portal.lock:
            problem = portal.admission_problem(portal.db)
        if problem is not None:
            raise ApiError(403, problem)
        user_handle = secrets.token_bytes(32)
        options = portal.registration_options(user_handle, name, [])
        ceremony = portal.ceremonies.put("register", {"challenge": options.challenge,
                                                      "user_handle": user_handle, "name": name})
        return {"ceremony": ceremony, "options": options_to_json_dict(options)}

    def register_finish(self, body: dict) -> dict:
        portal = self.portal
        pending = portal.ceremonies.take(body.get("ceremony"), "register")
        verified = portal.verify_registration(pending, credential_of(body))
        account_id = new_id("acct-")
        now = int(time.time())
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            if (problem := portal.admission_problem(conn)) is not None:
                raise ApiError(403, problem)
            conn.execute("INSERT INTO accounts (id, user_handle, name, created_at) VALUES (?, ?, ?, ?)",
                         (account_id, pending["user_handle"], pending["name"], now))
            try:
                conn.execute("INSERT INTO passkeys (credential_id, account_id, public_key, sign_count, created_at) "
                             "VALUES (?, ?, ?, ?, ?)",
                             (verified.credential_id, account_id, verified.credential_public_key,
                              verified.sign_count, now))
            except sqlite3.IntegrityError:
                raise ApiError(409, "This passkey is already registered.") from None
            self.start_session(conn, account_id, verified.credential_id)
        log.info("registered account %s", account_id)
        return {"account": account_id}

    def login_begin(self, body: dict) -> dict:
        if not self.portal.limiter.allow("login", self.client_ip(), 30, 600):
            raise ApiError(429, "Too many sign-in attempts. Try again in a few minutes.")
        options = generate_authentication_options(
            rp_id=self.portal.rp_id, timeout=CEREMONY_SECONDS * 1000,
            user_verification=UserVerificationRequirement.REQUIRED)
        ceremony = self.portal.ceremonies.put("login", {"challenge": options.challenge})
        return {"ceremony": ceremony, "options": options_to_json_dict(options)}

    def login_finish(self, body: dict) -> dict:
        portal = self.portal
        pending = portal.ceremonies.take(body.get("ceremony"), "login")
        credential = credential_of(body)
        try:
            credential_id = base64url_to_bytes(credential.get("rawId"))
        except (TypeError, ValueError, AttributeError):
            raise ApiError(400, "Malformed passkey response.") from None
        with portal.lock:
            row = portal.db.execute(
                "SELECT passkeys.public_key, passkeys.sign_count, accounts.id, accounts.user_handle "
                "FROM passkeys JOIN accounts ON accounts.id = passkeys.account_id "
                "WHERE passkeys.credential_id = ? AND accounts.disabled_at IS NULL",
                (credential_id,)).fetchone()
        if row is None:
            raise ApiError(400, "This passkey is not registered here.")
        response = credential.get("response")
        handle = response.get("userHandle") if isinstance(response, dict) else None
        if handle is not None:
            try:
                same_user = hmac.compare_digest(base64url_to_bytes(handle), row["user_handle"])
            except (TypeError, ValueError):
                same_user = False
            if not same_user:
                raise ApiError(400, "The passkey could not be verified.")
        try:
            verified = verify_authentication_response(
                credential=credential, expected_challenge=pending["challenge"],
                expected_rp_id=portal.rp_id, expected_origin=portal.origin,
                credential_public_key=row["public_key"],
                credential_current_sign_count=row["sign_count"], require_user_verification=True)
        except Exception as exc:  # any failure means the sign-in is not verified
            log.info("passkey sign-in not verified: %s", exc)
            raise ApiError(400, "The passkey could not be verified.") from None
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            # In the same transaction as the session: a passkey removed after the check above
            # updates nothing here and leaves no session behind.
            if not conn.execute("UPDATE passkeys SET sign_count = ?, last_used_at = ? "
                                "WHERE credential_id = ? AND account_id = ?",
                                (verified.new_sign_count, int(time.time()), credential_id, row["id"])).rowcount:
                raise ApiError(400, "This passkey is not registered here.")
            self.start_session(conn, row["id"], credential_id)
        return {"account": row["id"]}

    def logout(self, body: dict) -> dict:
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            pass
        if (morsel := cookie.get(SESSION_COOKIE)) is not None:
            with self.portal.lock, self.portal.db as conn:
                conn.execute("DELETE FROM sessions WHERE token_sha256 = ?", (sha256(morsel.value),))
        self.cookies.append(("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"))
        return {}

    # Account management

    def account_info(self, body: dict) -> dict:
        account = self.require_session()
        with self.portal.lock:
            passkeys = self.portal.db.execute(
                "SELECT credential_id, created_at, last_used_at, added_with FROM passkeys WHERE account_id = ? "
                "ORDER BY created_at", (account["id"],)).fetchall()
            devices = self.portal.db.execute(
                "SELECT id, name, created_at, expires_at, revoked_at, linked_with FROM devices "
                "WHERE account_id = ? ORDER BY created_at DESC", (account["id"],)).fetchall()

        def passkey_id(credential_id: bytes | None) -> str | None:
            return bytes_to_base64url(credential_id) if credential_id is not None else None

        return {
            "id": account["id"],
            "name": account["name"],
            "created": account["created_at"],
            "passkeys": [{"id": passkey_id(row["credential_id"]), "created": row["created_at"],
                          "last_used": row["last_used_at"], "added_with": passkey_id(row["added_with"]),
                          "current": row["credential_id"] == account["credential_id"]} for row in passkeys],
            "devices": [{"id": row["id"], "name": row["name"], "created": row["created_at"],
                         "expires": row["expires_at"], "revoked": row["revoked_at"],
                         "linked_with": passkey_id(row["linked_with"])} for row in devices],
        }

    def passkey_begin(self, body: dict) -> dict:
        account = self.require_session(recent=True)
        existing = self.portal.passkey_ids(account["id"])
        if len(existing) >= MAX_PASSKEYS:
            raise ApiError(403, f"An account can have at most {MAX_PASSKEYS} passkeys.")
        options = self.portal.registration_options(account["user_handle"], account["name"], existing)
        ceremony = self.portal.ceremonies.put("add", {"challenge": options.challenge,
                                                      "account": account["id"]})
        return {"ceremony": ceremony, "options": options_to_json_dict(options)}

    def passkey_finish(self, body: dict) -> dict:
        account = self.require_session(recent=True)
        portal = self.portal
        pending = portal.ceremonies.take(body.get("ceremony"), "add")
        if pending["account"] != account["id"]:
            raise ApiError(400, "This request expired. Try again.")
        verified = portal.verify_registration(pending, credential_of(body))
        with self.session_transaction(recent=True) as (conn, current):
            if current["id"] != account["id"]:
                raise ApiError(400, "This request expired. Try again.")
            if conn.execute("SELECT COUNT(*) FROM passkeys WHERE account_id = ?",
                            (current["id"],)).fetchone()[0] >= MAX_PASSKEYS:
                raise ApiError(403, f"An account can have at most {MAX_PASSKEYS} passkeys.")
            try:
                conn.execute("INSERT INTO passkeys (credential_id, account_id, public_key, sign_count, created_at, "
                             "added_with) VALUES (?, ?, ?, ?, ?, ?)",
                             (verified.credential_id, current["id"], verified.credential_public_key,
                              verified.sign_count, int(time.time()), current["credential_id"]))
            except sqlite3.IntegrityError:
                raise ApiError(409, "This passkey is already registered.") from None
        return {}

    def passkey_delete(self, body: dict) -> dict:
        """Removes a passkey, and in the same transaction every session that signed in with it and
        every launcher approval those sessions left pending; with "revoke_launchers" also the
        launchers linked through it. Inside that transaction the session is read again: it must
        still be live, recent, and signed in with another passkey, which therefore stays. Of two
        sessions removing each other's passkeys at once, the second finds its own passkey gone."""
        try:
            credential_id = base64url_to_bytes(body.get("passkey"))
        except (TypeError, ValueError, AttributeError):
            raise ApiError(400, "Unknown passkey.") from None
        revoke_launchers = body.get("revoke_launchers") is True
        now = int(time.time())
        with self.session_transaction(recent=True) as (conn, account):
            if credential_id == account["credential_id"]:
                raise ApiError(400, "Sign in with another of your passkeys to remove this one.", sign_in=True)
            deleted = conn.execute("DELETE FROM passkeys WHERE credential_id = ? AND account_id = ?",
                                   (credential_id, account["id"])).rowcount
            if not deleted:
                raise ApiError(404, "Unknown passkey.")
            conn.execute("DELETE FROM sessions WHERE credential_id = ?", (credential_id,))
            conn.execute("DELETE FROM link_codes WHERE credential_id = ?", (credential_id,))
            revoked = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE linked_with = ? AND account_id = ? AND revoked_at IS NULL",
                (now, credential_id, account["id"])).rowcount if revoke_launchers else 0
        log.info("account %s removed a passkey and revoked %d launcher(s) linked with it", account["id"], revoked)
        return {"revoked_launchers": revoked}

    def device_revoke(self, body: dict) -> dict:
        device = body.get("device")
        if not isinstance(device, str):
            raise ApiError(400, "Unknown launcher.")
        with self.session_transaction() as (conn, account):
            revoked = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
                (int(time.time()), device, account["id"])).rowcount
        if not revoked:
            raise ApiError(404, "Unknown launcher.")
        log.info("account %s revoked device %s", account["id"], device)
        return {}

    # Launcher linking

    def link_approve(self, body: dict) -> dict:
        port, state = body.get("port"), body.get("state")
        challenge, csr_sha256 = body.get("challenge"), body.get("csr")
        if not (isinstance(port, int) and 1024 <= port <= 65535 and isinstance(state, str)
                and STATE.fullmatch(state) and isinstance(challenge, str) and PKCE.fullmatch(challenge)
                and isinstance(csr_sha256, str) and SHA256_HEX.fullmatch(csr_sha256)):
            raise ApiError(400, "This link request is malformed. Start linking again from the launcher.")
        name = clean_name(body.get("name"), 64)
        now = int(time.time())
        code = secrets.token_urlsafe(32)
        with self.session_transaction(recent=True) as (conn, account):
            if conn.execute("SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at IS NULL "
                            "AND expires_at > ?", (account["id"], now)).fetchone()[0] >= MAX_DEVICES:
                raise ApiError(403, f"An account can have at most {MAX_DEVICES} linked launchers. Revoke one first.")
            conn.execute("DELETE FROM link_codes WHERE expires_at <= ?", (now,))
            conn.execute("INSERT INTO link_codes (code_sha256, account_id, credential_id, code_challenge, "
                         "csr_sha256, device_name, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (sha256(code), account["id"], account["credential_id"], challenge, csr_sha256, name,
                          now + LINK_CODE_SECONDS))
        return {"redirect": f"http://127.0.0.1:{port}/callback?" + urlencode({"code": code, "state": state})}

    def link_token(self, body: dict) -> dict:
        """Called by the launcher, not the browser: redeems a link code for a device certificate."""
        portal = self.portal
        if not portal.limiter.allow("link", self.client_ip(), 30, 600):
            raise ApiError(429, "Too many requests. Try again in a few minutes.")
        code, verifier, csr_pem = body.get("code"), body.get("verifier"), body.get("csr")
        if not (isinstance(code, str) and isinstance(verifier, str) and VERIFIER.fullmatch(verifier)
                and isinstance(csr_pem, str) and len(csr_pem) <= 8192):
            raise ApiError(400, "Malformed link request.")
        now = int(time.time())
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM link_codes WHERE code_sha256 = ?", (sha256(code),)).fetchone()
            conn.execute("DELETE FROM link_codes WHERE code_sha256 = ?", (sha256(code),))
        if row is None or row["expires_at"] <= now:
            raise ApiError(400, "The link code is invalid or expired. Start linking again.")
        challenge = base64.urlsafe_b64encode(sha256(verifier)).rstrip(b"=").decode()
        if not hmac.compare_digest(challenge, row["code_challenge"]):
            raise ApiError(400, "The link code is invalid or expired. Start linking again.")
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError:
            raise ApiError(400, "Malformed certificate request.") from None
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        if not hmac.compare_digest(hashlib.sha256(csr_der).hexdigest(), row["csr_sha256"]):
            raise ApiError(400, "The certificate request is not the one that was approved.")
        public_key = csr.public_key()
        if not (csr.is_signature_valid and isinstance(public_key, ec.EllipticCurvePublicKey)
                and public_key.curve.name == "secp256r1"):
            raise ApiError(400, "The certificate request needs a P-256 key and a valid signature.")
        device_id = new_id("dev-")
        cert = issue_certificate(portal.device_ca_key, portal.device_ca_cert, public_key, device_id,
                                 portal.device_days)
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            account = conn.execute("SELECT disabled_at FROM accounts WHERE id = ?",
                                   (row["account_id"],)).fetchone()
            if account is None or account["disabled_at"] is not None:
                raise ApiError(403, "This account is disabled.")
            if not conn.execute("SELECT 1 FROM passkeys WHERE credential_id = ? AND account_id = ?",
                                (row["credential_id"], row["account_id"])).fetchone():
                raise ApiError(400, "The passkey that approved this link was removed. Start linking again.")
            active = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at IS NULL AND expires_at > ?",
                (row["account_id"], now)).fetchone()[0]
            if active >= MAX_DEVICES:
                raise ApiError(403, f"An account can have at most {MAX_DEVICES} linked launchers.")
            conn.execute("INSERT INTO devices (id, account_id, name, cert_sha256, created_at, expires_at, "
                         "linked_with) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (device_id, row["account_id"], row["device_name"], fingerprint, now,
                          int(cert.not_valid_after_utc.timestamp()), row["credential_id"]))
        log.info("account %s linked device %s", row["account_id"], device_id)
        return {
            "account": row["account_id"],
            "device": device_id,
            "certificate": pem(cert).decode(),
            "ingress": portal.ingress,
        }


# Path -> (handler, called by the portal page in a browser)
POST_ROUTES = {
    "/api/register/begin": (Handler.register_begin, True),
    "/api/register/finish": (Handler.register_finish, True),
    "/api/login/begin": (Handler.login_begin, True),
    "/api/login/finish": (Handler.login_finish, True),
    "/api/logout": (Handler.logout, True),
    "/api/passkeys/begin": (Handler.passkey_begin, True),
    "/api/passkeys/finish": (Handler.passkey_finish, True),
    "/api/passkeys/delete": (Handler.passkey_delete, True),
    "/api/devices/revoke": (Handler.device_revoke, True),
    "/api/link/approve": (Handler.link_approve, True),
    "/api/link/token": (Handler.link_token, False),
}


# --- Page --------------------------------------------------------------------------------------

PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pokopia Cloud account</title>
<link rel="stylesheet" href="/app.css">
<script src="/app.js" defer></script>
</head>
<body>
<main>
<h1>Pokopia Cloud account</h1>
<p id="status" role="status"></p>
<section id="signed-out" hidden>
  <h2>Sign in</h2>
  <p>Use the passkey you created for this server.</p>
  <button id="login" type="button">Sign in with a passkey</button>
  <h2>Create an account</h2>
  <form id="register-form">
    <label for="name">Name shown on your passkey</label>
    <input id="name" maxlength="32" required autocomplete="username">
    <button type="submit">Create an account with a passkey</button>
  </form>
</section>
<section id="link" hidden>
  <h2>Link a launcher</h2>
  <p>The launcher on <strong id="link-name"></strong> asks to play with your account.
     Its key fingerprint is <code id="link-fingerprint"></code>; the launcher window shows the same value.</p>
  <p>Only approve this if you started linking in the launcher on this computer just now.</p>
  <button id="link-approve" type="button">Approve</button>
  <button id="link-cancel" type="button" class="secondary">Cancel</button>
</section>
<section id="account" hidden>
  <h2>Your account</h2>
  <p><span id="account-name"></span> (<code id="account-id"></code>)</p>
  <h3>Linked launchers</h3>
  <ul id="devices"></ul>
  <h3>Passkeys</h3>
  <ul id="passkeys"></ul>
  <button id="add-passkey" type="button">Add a backup passkey</button>
  <button id="logout" type="button" class="secondary">Sign out</button>
</section>
</main>
</body>
</html>
"""

APP_CSS = """body { font-family: system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #1b1d21; }
main { max-width: 40rem; margin: 2rem auto; padding: 0 1rem; }
section { background: #fff; border: 1px solid #d9dce1; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
label { display: block; margin: 0.5rem 0 0.25rem; }
input { font: inherit; padding: 0.4rem; width: 100%; box-sizing: border-box; margin-bottom: 0.75rem; }
button { font: inherit; padding: 0.45rem 0.9rem; border-radius: 6px; border: 1px solid #2457c5; background: #2457c5; color: #fff; cursor: pointer; }
button.secondary { background: #fff; color: #2457c5; }
li { margin: 0.4rem 0; }
li button { margin-left: 0.5rem; padding: 0.2rem 0.6rem; }
#status:empty { display: none; }
#status { background: #fff7d6; border: 1px solid #e8d48a; border-radius: 6px; padding: 0.5rem 0.75rem; }
"""

APP_JS = r""""use strict";

const $ = (id) => document.getElementById(id);
let link = (() => {
  if (location.pathname !== "/link") return null;
  const params = new URLSearchParams(location.search);
  const fields = ["port", "state", "challenge", "csr", "name"];
  if (!fields.every((field) => params.get(field))) return null;
  return Object.fromEntries(fields.map((field) => [field, params.get(field)]));
})();

function status(text) { $("status").textContent = text || ""; }

function b64urlToBuf(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buffer) {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function api(path, body) {
  const init = body === undefined
    ? {method: "GET", credentials: "same-origin"}
    : {method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/json"},
       body: JSON.stringify(body)};
  const response = await fetch(path, init);
  let data = {};
  try { data = await response.json(); } catch (error) { /* not JSON */ }
  if (!response.ok) {
    const error = new Error(data.error || `Request failed (${response.status}).`);
    error.status = response.status;
    error.signIn = data.signIn === true;  // a recent passkey sign-in is needed; see run()
    throw error;
  }
  return data;
}

function creationOptions(options) {
  return {...options, challenge: b64urlToBuf(options.challenge),
    user: {...options.user, id: b64urlToBuf(options.user.id)},
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({...c, id: b64urlToBuf(c.id)}))};
}

function requestOptions(options) {
  return {...options, challenge: b64urlToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({...c, id: b64urlToBuf(c.id)}))};
}

function registrationJSON(credential) {
  const response = credential.response;
  return {id: credential.id, rawId: bufToB64url(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    response: {clientDataJSON: bufToB64url(response.clientDataJSON),
      attestationObject: bufToB64url(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() : []}};
}

function assertionJSON(credential) {
  const response = credential.response;
  return {id: credential.id, rawId: bufToB64url(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    response: {clientDataJSON: bufToB64url(response.clientDataJSON),
      authenticatorData: bufToB64url(response.authenticatorData),
      signature: bufToB64url(response.signature),
      userHandle: response.userHandle ? bufToB64url(response.userHandle) : null}};
}

function fingerprint(hex) {
  return /^[0-9a-f]{64}$/.test(hex) ? hex.slice(0, 16).toUpperCase().match(/.{4}/g).join(" ") : "(invalid)";
}

function when(seconds) { return new Date(seconds * 1000).toLocaleString(); }

function item(text, button, onClick) {
  const li = document.createElement("li");
  li.textContent = text;
  if (button) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "secondary";
    b.textContent = button;
    b.addEventListener("click", () => run(onClick));
    li.append(b);
  }
  return li;
}

function renderDevices(devices, labels) {
  const now = Date.now() / 1000;
  $("devices").replaceChildren(...(devices.length ? devices.map((d) => {
    if (d.revoked) return item(`${d.name}: revoked ${when(d.revoked)}`);
    if (d.expires <= now) return item(`${d.name}: expired ${when(d.expires)}; link it again`);
    const approved = labels[d.linked_with] ? `approved with ${labels[d.linked_with]}` : "approved with a removed passkey";
    return item(`${d.name}: linked ${when(d.created)} (${approved}), valid until ${when(d.expires)}`, "Revoke", async () => {
      if (!confirm(`Revoke ${d.name}? It is disconnected and must be linked again.`)) return;
      await api("/api/devices/revoke", {device: d.id});
      await refresh();
      status("Launcher revoked.");
    });
  }) : [item("None yet. Run the launcher's link command to add this PC.")]));
}

function renderPasskeys(passkeys, devices, labels) {
  $("passkeys").replaceChildren(...passkeys.map((p) => {
    const added = p.added_with ? ` with ${labels[p.added_with] || "a removed passkey"}` : "";
    const current = p.current ? " (you signed in with it)" : "";
    return item(`${labels[p.id]}${current}: added ${when(p.created)}${added}, last used ${p.last_used ? when(p.last_used) : "never"}`,
      passkeys.length > 1 ? "Remove" : null, async () => {
        if (!confirm(`Remove ${labels[p.id]}? Browsers signed in with it are signed out.`)) return;
        const linked = devices.filter((d) => d.linked_with === p.id && !d.revoked).length;
        const revoke = linked > 0 && confirm(`${linked} launcher(s) were approved with ${labels[p.id]}. ` +
          "Revoke them too? Do this if someone else may have used this passkey.");
        const result = await api("/api/passkeys/delete", {passkey: p.id, revoke_launchers: revoke});
        await refresh();
        status(`Passkey removed${result.revoked_launchers ? `; ${result.revoked_launchers} launcher(s) revoked` : ""}.`);
      });
  }));
}

function show(section) {
  $("signed-out").hidden = section !== "signed-out";
  $("account").hidden = section !== "account";
  $("link").hidden = !(section === "account" && link);
}

async function refresh() {
  let account;
  try {
    account = await api("/api/account");
  } catch (error) {
    if (error.status !== 401) throw error;
    show("signed-out");
    if (link) status("Sign in, or create an account, to link the launcher.");
    return;
  }
  const labels = Object.fromEntries(account.passkeys.map((p, i) => [p.id, `Passkey ${i + 1}`]));
  $("account-name").textContent = account.name;
  $("account-id").textContent = account.id;
  renderDevices(account.devices, labels);
  renderPasskeys(account.passkeys, account.devices, labels);
  if (link) {
    $("link-name").textContent = link.name;
    $("link-fingerprint").textContent = fingerprint(link.csr);
  }
  show("account");
}

function report(error) {
  status(error.name === "NotAllowedError" ? "The passkey request was cancelled or timed out." : error.message);
}

// Changing passkeys and linking launchers need a recent sign-in; the server then asks for one
// (signIn), and the task is tried again once after it.
async function run(task, retried = false) {
  status("");
  try {
    await task();
  } catch (error) {
    if (!error.signIn || retried) return report(error);
    status("Confirm with your passkey to continue.");
    try {
      await login();
    } catch (again) {
      return report(again);
    }
    return run(task, true);
  }
}

async function register() {
  const begin = await api("/api/register/begin", {name: $("name").value});
  const credential = await navigator.credentials.create({publicKey: creationOptions(begin.options)});
  await api("/api/register/finish", {ceremony: begin.ceremony, credential: registrationJSON(credential)});
  await refresh();
  status("Account created. Consider adding a backup passkey: without a passkey the account cannot be recovered.");
}

async function login() {
  const begin = await api("/api/login/begin", {});
  const credential = await navigator.credentials.get({publicKey: requestOptions(begin.options)});
  await api("/api/login/finish", {ceremony: begin.ceremony, credential: assertionJSON(credential)});
  await refresh();
}

async function addPasskey() {
  const begin = await api("/api/passkeys/begin", {});
  const credential = await navigator.credentials.create({publicKey: creationOptions(begin.options)});
  await api("/api/passkeys/finish", {ceremony: begin.ceremony, credential: registrationJSON(credential)});
  await refresh();
  status("Passkey added.");
}

async function approveLink() {
  const result = await api("/api/link/approve", {port: Number(link.port), state: link.state,
    challenge: link.challenge, csr: link.csr, name: link.name});
  link = null;
  $("link").hidden = true;
  status("Approved. Handing over to the launcher; you can close this tab afterwards.");
  location.assign(result.redirect);
}

document.addEventListener("DOMContentLoaded", () => {
  if (!window.PublicKeyCredential) status("This browser does not support passkeys.");
  $("register-form").addEventListener("submit", (event) => { event.preventDefault(); run(register); });
  $("login").addEventListener("click", () => run(login));
  $("add-passkey").addEventListener("click", () => run(addPasskey));
  $("logout").addEventListener("click", () => run(async () => { await api("/api/logout", {}); await refresh(); }));
  $("link-approve").addEventListener("click", () => run(approveLink));
  $("link-cancel").addEventListener("click", () => {
    link = null;
    $("link").hidden = true;
    history.replaceState(null, "", "/");
    status("Linking cancelled.");
  });
  run(refresh);
});
"""


# --- Commands ----------------------------------------------------------------------------------


def check_origin(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    origin = urlsplit(args.origin)
    host = origin.hostname or ""
    if (origin.scheme != "https" and host != "localhost") or origin.path not in ("", "/") \
            or origin.query or origin.fragment or origin.username or origin.password:
        parser.error("--origin must look like https://pokopia.example.org")
    if host != args.rp_id and not host.endswith("." + args.rp_id):
        parser.error("--rp-id must be the --origin host name or a parent domain of it")
    args.origin = f"{origin.scheme}://{origin.netloc.lower()}"


def serve(args: argparse.Namespace) -> None:
    portal = Portal(args)
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    httpd.portal = portal
    log.info("portal for %s (RP ID %s) on http://%s:%d; registration %s; launchers connect to %s:%d as %s",
             portal.origin, portal.rp_id, args.bind, args.port,
             "open" if portal.registration_open else "closed", portal.ingress["host"],
             portal.ingress["port"], portal.ingress["server_name"])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def admin(args: argparse.Namespace) -> None:
    db = open_database(args.db)
    now = int(time.time())
    if args.command == "accounts":
        rows = db.execute(
            "SELECT accounts.id, accounts.name, accounts.created_at, accounts.disabled_at, "
            "(SELECT COUNT(*) FROM passkeys WHERE account_id = accounts.id), "
            "(SELECT COUNT(*) FROM devices WHERE account_id = accounts.id AND revoked_at IS NULL "
            "AND expires_at > ?) FROM accounts ORDER BY accounts.created_at", (now,)).fetchall()
        for row in rows:
            created = datetime.datetime.fromtimestamp(row[2], datetime.timezone.utc).strftime("%Y-%m-%d")
            state = "disabled" if row[3] else "active"
            print(f"{row[0]}  {created}  {state:8}  passkeys={row[4]} launchers={row[5]}  {row[1]}")
        return
    with db:
        if args.command == "disable":
            changed = db.execute("UPDATE accounts SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL",
                                 (now, args.id)).rowcount
            db.execute("DELETE FROM sessions WHERE account_id = ?", (args.id,))
            db.execute("DELETE FROM link_codes WHERE account_id = ?", (args.id,))
        elif args.command == "enable":
            changed = db.execute("UPDATE accounts SET disabled_at = NULL WHERE id = ?", (args.id,)).rowcount
        elif args.command == "delete":
            changed = db.execute("SELECT COUNT(*) FROM accounts WHERE id = ?", (args.id,)).fetchone()[0]
            if changed:
                delete_account(db, args.id, tombstone=True)
        else:  # revoke-device
            changed = db.execute("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                                 (now, args.id)).rowcount
    print(f"{args.command} {args.id}: {'done' if changed else 'nothing changed'}")
    if args.command in ("disable", "delete", "revoke-device") and changed:
        print("server.py drops its connections within 30 seconds.")
    if args.command == "delete" and changed:
        print("server.py deletes the account's islands and other game data within a minute.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Account portal for a Pokopia Cloud server.")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init-pki", help="create the device CA, ingress CA and ingress certificate")
    init.add_argument("--pki-dir", type=Path, required=True)
    init.add_argument("--ingress-name", required=True,
                      help="host name launchers use for server.py, e.g. pokopia.example.org")

    run = commands.add_parser("serve", help="run the portal")
    run.add_argument("--db", type=Path, required=True, help="account database (created if missing)")
    run.add_argument("--pki-dir", type=Path, required=True, help="directory written by init-pki")
    run.add_argument("--rp-id", required=True, help="WebAuthn RP ID, e.g. pokopia.example.org")
    run.add_argument("--origin", required=True, help="public origin, e.g. https://pokopia.example.org")
    run.add_argument("--rp-name", default="Pokopia Cloud", help="name browsers show for passkeys")
    run.add_argument("--ingress-host", required=True, help="host launchers connect to for server.py")
    run.add_argument("--ingress-port", type=int, required=True, help="TLS port of server.py")
    run.add_argument("--ingress-name", default="",
                     help="name in the ingress certificate (default: --ingress-host)")
    run.add_argument("--bind", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    run.add_argument("--port", type=int, default=8780, help="listen port (default 8780)")
    run.add_argument("--trusted-proxy", action="append", default=["127.0.0.1", "::1"],
                     help="address whose X-Forwarded-For is believed (default 127.0.0.1 and ::1)")
    run.add_argument("--closed", action="store_true", help="refuse new accounts")
    run.add_argument("--max-accounts", type=int, default=1000,
                     help="enabled accounts at most; disabled and deleted ones do not count (default 1000)")
    run.add_argument("--max-signups-per-day", type=int, default=50,
                     help="new accounts per 24 hours across all networks (default 50)")
    run.add_argument("--device-days", type=int, default=180, help="validity of launcher certificates")

    for command, help_text in (("accounts", "list accounts"), ("disable", "disable an account"),
                               ("enable", "re-enable an account"),
                               ("delete", "delete an account; server.py then purges its game data"),
                               ("revoke-device", "revoke a launcher")):
        sub = commands.add_parser(command, help=help_text)
        sub.add_argument("--db", type=Path, required=True)
        if command != "accounts":
            sub.add_argument("id")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if os.name == "posix":
        # The database and keys stay within the portal's user and group (server.py's user is a
        # member of that group and reads auth.db and ingress.key).
        os.umask(0o027)
    if args.command == "init-pki":
        if not HOST_NAME.fullmatch(args.ingress_name):
            parser.error("--ingress-name must be a DNS name")
        init_pki(args.pki_dir, args.ingress_name.lower())
    elif args.command == "serve":
        check_origin(parser, args)
        if not (args.ingress_name or HOST_NAME.fullmatch(args.ingress_host)):
            parser.error("--ingress-name is required when --ingress-host is not a DNS name")
        serve(args)
    else:
        admin(args)


if __name__ == "__main__":
    main()
