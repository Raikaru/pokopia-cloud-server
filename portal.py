#!/usr/bin/env python3
"""Account portal for a Pokopia Cloud server: passkey (and optional Discord) accounts and launcher linking.

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

Discord sign-in is optional and off unless --discord-client-id-file and --discord-client-secret-file
are given. It is OAuth 2.0 with the authorization code flow, PKCE (S256) and the RFC 9207 issuer
check, and asks Discord only for the "identify" scope: all the portal keeps is the stable numeric
Discord user ID. A Discord identity signs in to the one account it is linked to; it is linked when
an account is created with it, or explicitly by a signed-in user with a recent passkey sign-in.
Nothing is ever matched by user name, display name or e-mail, and no existing account is ever
joined to a Discord identity on its own. Access tokens are used once to read the user ID and are
never stored or logged; refresh tokens are ignored. The Discord application must list
<--origin>/auth/discord/callback as its only redirect URI. The portal reaches discord.com through
--discord-proxy, or else the https_proxy/no_proxy environment variables.

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
import dataclasses
import datetime
import hashlib
import hmac
import http.client
import http.cookies
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import stat
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

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
# Request lines are logged with every query cut off: Discord's callback carries the authorization
# code and the state in its query, and neither may reach a log.
LOGGED_QUERY = re.compile(r"\?\S*")

# Discord sign-in. Only these fixed HTTPS URLs are contacted or redirected to; nothing from a request
# ever chooses where the portal sends the client secret or a token.
DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_USER_URL = "https://discord.com/api/v10/users/@me"  # a pinned API version
DISCORD_ISSUER = "https://discord.com"  # RFC 9207 "iss" that every authorization answer must carry
DISCORD_SCOPE = "identify"  # the only scope asked for, and the only one a token may come back with
DISCORD_CALLBACK_PATH = "/auth/discord/callback"
# Binds a sign-in flow to the browser that started it: HttpOnly, Secure, host-only (the __Host-
# prefix), and SameSite=Lax so that the top-level redirect back from Discord carries it.
DISCORD_COOKIE = "__Host-discord-oauth"
DISCORD_FLOW_SECONDS = 600  # Discord must send the browser back within this; state and cookie expire
# Linking Discord ends in a same-origin POST from the page (/api/discord/link/finish), which carries
# the SameSite=Strict session cookie that the redirect back from Discord does not: Discord's answer
# waits for it this long, single use, under a handle in this Strict cookie.
DISCORD_LINK_COOKIE = "__Host-discord-link"
DISCORD_LINK_SECONDS = 120
DISCORD_HTTP_SECONDS = 10  # timeout of every socket operation of a call to Discord, and its deadline
DISCORD_MAX_RESPONSE = 64 * 1024  # a larger answer from Discord is refused
DISCORD_MAX_CONCURRENT = 8  # sign-ins talking to Discord at once; more are refused, not queued
DISCORD_ID = re.compile(r"[1-9][0-9]{0,19}")  # a user ID (snowflake): an unsigned 64-bit number
DISCORD_CLIENT_ID = re.compile(r"[1-9][0-9]{16,19}")
DISCORD_CLIENT_SECRET = re.compile(r"[A-Za-z0-9_-]{16,128}")
DISCORD_CODE = re.compile(r"[\x21-\x7e]{1,512}")
DISCORD_ACCESS_TOKEN = re.compile(r"[\x21-\x7e]{1,2048}")
FLOW_STATE = re.compile(r"[A-Za-z0-9_-]{32}")  # a Ceremonies key: secrets.token_urlsafe(24)
CONFIG_FILE_BYTES = 4096

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

# What a session signed in with, what approved a link code or a launcher, and what added a passkey,
# is a tagged credential reference: a type, 'passkey' or 'discord', and then the passkey's credential
# ID (a BLOB) or the Discord user ID (TEXT), each in a column of its own. CHECK constraints allow
# exactly the column of the type, so a passkey and a Discord identity can never be mistaken for one
# another, whatever their bytes. server.py reads accounts, devices and deleted_accounts; the columns
# it uses are the same in every version.
SCHEMA_VERSION = 2
ACCOUNTS_TABLE = """CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    user_handle BLOB NOT NULL UNIQUE,  -- the WebAuthn user handle, made for every account
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
)"""
PASSKEYS_TABLE = """CREATE TABLE passkeys (
    credential_id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    added_type TEXT,  -- the sign-in that added this one; all three NULL if it created the account
    added_with BLOB,  -- that passkey
    added_discord TEXT,  -- that Discord identity
    CHECK ((added_type IS NULL AND added_with IS NULL AND added_discord IS NULL)
        OR (added_type = 'passkey' AND added_with IS NOT NULL AND added_discord IS NULL)
        OR (added_type = 'discord' AND added_discord IS NOT NULL AND added_with IS NULL))
)"""
PASSKEYS_INDEX = "CREATE INDEX passkeys_account ON passkeys(account_id)"
DEVICES_TABLE = """CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    linked_type TEXT NOT NULL,  -- the sign-in that approved the link:
    linked_with BLOB,  -- a passkey
    linked_discord TEXT,  -- or a Discord identity
    CHECK ((linked_type = 'passkey' AND linked_with IS NOT NULL AND linked_discord IS NULL)
        OR (linked_type = 'discord' AND linked_discord IS NOT NULL AND linked_with IS NULL))
)"""
DEVICES_INDEX = "CREATE INDEX devices_account ON devices(account_id)"
SESSIONS_TABLE = """CREATE TABLE sessions (
    token_sha256 BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    auth_type TEXT NOT NULL,  -- what it signed in with; it ends with that passkey or Discord identity:
    credential_id BLOB,  -- a passkey
    discord_id TEXT,  -- or a Discord identity
    signed_in_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    CHECK ((auth_type = 'passkey' AND credential_id IS NOT NULL AND discord_id IS NULL)
        OR (auth_type = 'discord' AND discord_id IS NOT NULL AND credential_id IS NULL))
)"""
LINK_CODES_TABLE = """CREATE TABLE link_codes (
    code_sha256 BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    auth_type TEXT NOT NULL,  -- what the approving session signed in with:
    credential_id BLOB,  -- a passkey
    discord_id TEXT,  -- or a Discord identity
    code_challenge TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    device_name TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    CHECK ((auth_type = 'passkey' AND credential_id IS NOT NULL AND discord_id IS NULL)
        OR (auth_type = 'discord' AND discord_id IS NOT NULL AND credential_id IS NULL))
)"""
DISCORD_IDENTITIES_TABLE = """CREATE TABLE discord_identities (
    discord_id TEXT PRIMARY KEY,  -- Discord's stable numeric user ID; never a user name or e-mail
    account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),  -- at most one per account
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    added_with BLOB,  -- the passkey whose sign-in linked it; NULL if the account was created with it
    CHECK (length(discord_id) BETWEEN 1 AND 20 AND discord_id NOT GLOB '*[^0-9]*'
        AND discord_id NOT GLOB '0*')
)"""
DELETED_ACCOUNTS_TABLE = """CREATE TABLE deleted_accounts (  -- server.py purges their game data
    id TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL
)"""
# A new database: every statement in one transaction.
SCHEMA = (ACCOUNTS_TABLE, PASSKEYS_TABLE, PASSKEYS_INDEX, DEVICES_TABLE, DEVICES_INDEX, SESSIONS_TABLE,
          LINK_CODES_TABLE, DISCORD_IDENTITIES_TABLE, DELETED_ACCOUNTS_TABLE)
# Version 1 (passkeys only) to 2, in one transaction: the tables holding credential references are
# rebuilt with their rows, every reference tagged 'passkey'; accounts and deleted_accounts stay.
MIGRATE_FROM_1 = (
    "ALTER TABLE passkeys RENAME TO passkeys_v1",
    PASSKEYS_TABLE,
    "INSERT INTO passkeys (credential_id, account_id, public_key, sign_count, created_at, last_used_at, "
    "added_type, added_with) SELECT credential_id, account_id, public_key, sign_count, created_at, "
    "last_used_at, CASE WHEN added_with IS NULL THEN NULL ELSE 'passkey' END, added_with FROM passkeys_v1",
    "DROP TABLE passkeys_v1",
    PASSKEYS_INDEX,
    "ALTER TABLE devices RENAME TO devices_v1",
    DEVICES_TABLE,
    "INSERT INTO devices (id, account_id, name, cert_sha256, created_at, expires_at, revoked_at, linked_type, "
    "linked_with) SELECT id, account_id, name, cert_sha256, created_at, expires_at, revoked_at, 'passkey', "
    "linked_with FROM devices_v1",
    "DROP TABLE devices_v1",
    DEVICES_INDEX,
    "ALTER TABLE sessions RENAME TO sessions_v1",
    SESSIONS_TABLE,
    "INSERT INTO sessions (token_sha256, account_id, auth_type, credential_id, signed_in_at, expires_at) "
    "SELECT token_sha256, account_id, 'passkey', credential_id, signed_in_at, expires_at FROM sessions_v1",
    "DROP TABLE sessions_v1",
    "ALTER TABLE link_codes RENAME TO link_codes_v1",
    LINK_CODES_TABLE,
    "INSERT INTO link_codes (code_sha256, account_id, auth_type, credential_id, code_challenge, csr_sha256, "
    "device_name, expires_at) SELECT code_sha256, account_id, 'passkey', credential_id, code_challenge, "
    "csr_sha256, device_name, expires_at FROM link_codes_v1",
    "DROP TABLE link_codes_v1",
    DISCORD_IDENTITIES_TABLE,
)
MIGRATIONS = {1: MIGRATE_FROM_1}


class ApiError(Exception):
    def __init__(self, status: int, message: str, sign_in: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        # 'passkey' or 'discord': the page should ask for that sign-in and try again
        self.sign_in = sign_in


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
    """Opens the account database: creates it, or migrates it from an earlier schema version, in one
    transaction that also sets the version. A version this portal.py does not know is refused."""
    conn = sqlite3.connect(path, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row

    def stored() -> tuple[int, int]:
        return (conn.execute("PRAGMA user_version").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0])

    def unknown(version: int) -> SystemExit:
        return SystemExit(f"{path} has schema version {version}, not {SCHEMA_VERSION}; it was made by "
                          "another version of portal.py")

    version, tables = stored()
    if tables and version != SCHEMA_VERSION and version not in MIGRATIONS:
        raise unknown(version)
    # Rollback-journal mode (not WAL) so that server.py can read the file with a read-only
    # connection, without write access to -wal/-shm files.
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA foreign_keys = ON")
    if tables and version == SCHEMA_VERSION:
        return conn
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        version, tables = stored()  # again: another process may have created or migrated it meanwhile
        if not tables:
            statements = SCHEMA
        elif version in MIGRATIONS:
            statements = MIGRATIONS[version]
            log.info("migrating %s from schema version %d to %d", path, version, SCHEMA_VERSION)
        elif version == SCHEMA_VERSION:
            statements = ()
        else:
            raise unknown(version)
        for statement in statements:
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return conn


def delete_account(conn: sqlite3.Connection, account_id: str, tombstone: bool) -> None:
    """Removes an account with its passkeys, Discord identity, sessions, link codes and launchers. A
    tombstone makes server.py purge the account's game data."""
    for table in ("sessions", "link_codes", "passkeys", "discord_identities", "devices"):
        conn.execute(f"DELETE FROM {table} WHERE account_id = ?", (account_id,))
    conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    if tombstone:
        conn.execute("INSERT OR IGNORE INTO deleted_accounts (id, deleted_at) VALUES (?, ?)",
                     (account_id, int(time.time())))


def credential_columns(auth_type: str, credential: bytes | str) -> tuple[str, bytes | None, str | None]:
    """A tagged credential reference as its three columns: the type, the passkey credential ID, the
    Discord user ID."""
    if auth_type == "passkey" and isinstance(credential, bytes):
        return auth_type, credential, None
    if auth_type == "discord" and isinstance(credential, str):
        return auth_type, None, credential
    raise ValueError("not a credential reference")



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
    """Requests waiting for their answer, single use, each kept for `lifetime` seconds: WebAuthn
    challenges waiting for the passkey response, Discord sign-ins waiting for Discord's redirect."""

    def __init__(self, lifetime: int) -> None:
        self.lifetime = lifetime
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
            self.pending[ceremony] = (now + self.lifetime, kind, data)
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


# --- Discord -----------------------------------------------------------------------------------


class DiscordUnavailable(Exception):
    """Discord could not be reached, did not answer in time, or answered 429 or 5xx. The message
    never holds request or answer content."""


class DiscordRefused(Exception):
    """Discord answered, but not with what a sign-in needs. The message never holds request or
    answer content."""


@dataclasses.dataclass(frozen=True)
class DiscordConfig:
    """The Discord application the portal signs in with; the secret stays out of every repr."""
    client_id: str
    client_secret: str = dataclasses.field(repr=False)
    redirect_uri: str
    opener: urllib.request.OpenerDirector = dataclasses.field(repr=False, compare=False)


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Discord's token and user endpoints do not redirect. Following a redirect could send the
    client secret, an authorization code or a token to another URL, so a redirect is an error
    (urllib then raises HTTPError with the 3xx status)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def discord_opener(proxy: str | None) -> urllib.request.OpenerDirector:
    """HTTPS for the calls to Discord: certificates verified against the system trust store, no
    redirects, and through `proxy` (an HTTP proxy that tunnels with CONNECT, so TLS still ends at
    discord.com) or else urllib's standard proxy settings (https_proxy, no_proxy)."""
    if proxy is None:
        proxies = {key: value for key, value in urllib.request.getproxies().items() if key == "https"}
    else:
        proxies = {"https": proxy}
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        RefuseRedirects())


def check_proxy(proxy: str) -> str:
    try:
        parts = urlsplit(proxy)
        valid = (parts.scheme == "http" and bool(parts.hostname) and parts.port is not None
                 and parts.username is None and parts.password is None and parts.path in ("", "/")
                 and not parts.query and not parts.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise SystemExit("--discord-proxy must look like http://127.0.0.1:3128: an HTTP proxy that tunnels "
                         "HTTPS with CONNECT, without credentials (give those in https_proxy instead)")
    return f"http://{parts.netloc}"


def read_config_file(path: Path, option: str, pattern: re.Pattern, private: bool) -> str:
    """The one value in a configuration file, surrounding white space removed. On POSIX a `private`
    file must not be accessible to group or others, and no file may be writable by them. Errors
    name the option and the file, never the content."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise SystemExit(f"{option} {path}: cannot be opened ({exc.strerror})") from None
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"{option} {path}: not a regular file")
        if os.name == "posix" and info.st_mode & (0o077 if private else 0o022):
            raise SystemExit(f"{option} {path}: must not be {'accessible' if private else 'writable'} by group "
                             f"or others (chmod {'600' if private else '644'})")
        data = file.read(CONFIG_FILE_BYTES + 1)
    try:
        value = data.decode("ascii").strip() if len(data) <= CONFIG_FILE_BYTES else ""
    except UnicodeDecodeError:
        value = ""
    if not pattern.fullmatch(value):
        raise SystemExit(f"{option} {path}: does not hold a valid value")
    return value


def load_discord_config(id_file: Path, secret_file: Path, origin: str, proxy: str | None) -> DiscordConfig:
    return DiscordConfig(
        client_id=read_config_file(Path(id_file), "--discord-client-id-file", DISCORD_CLIENT_ID, private=False),
        client_secret=read_config_file(Path(secret_file), "--discord-client-secret-file", DISCORD_CLIENT_SECRET,
                                       private=True),
        redirect_uri=origin + DISCORD_CALLBACK_PATH,
        opener=discord_opener(None if proxy is None else check_proxy(proxy)))


def discord_config(args: argparse.Namespace) -> DiscordConfig | None:
    """Discord sign-in is enabled only by both files with valid values; one alone is an error."""
    id_file = getattr(args, "discord_client_id_file", None)
    secret_file = getattr(args, "discord_client_secret_file", None)
    proxy = getattr(args, "discord_proxy", None)
    if id_file is None and secret_file is None:
        if proxy is not None:
            raise SystemExit("--discord-proxy needs --discord-client-id-file and --discord-client-secret-file")
        return None
    if id_file is None or secret_file is None:
        raise SystemExit("Discord sign-in needs both --discord-client-id-file and --discord-client-secret-file")
    return load_discord_config(id_file, secret_file, args.origin, proxy)


def discord_https(opener: urllib.request.OpenerDirector, url: str, headers: dict[str, str],
                  body: bytes | None) -> bytes:
    """One call to Discord: a POST of `body`, or a GET. `url` is DISCORD_TOKEN_URL or DISCORD_USER_URL,
    never one taken from a request. Returns the body of a 200 answer of at most DISCORD_MAX_RESPONSE
    bytes; every socket operation times out after DISCORD_HTTP_SECONDS, and reading the answer stops
    at that deadline. Raises DiscordUnavailable or DiscordRefused, without the original exception
    (whose message could quote the request or the answer)."""
    if url not in (DISCORD_TOKEN_URL, DISCORD_USER_URL):
        raise ValueError("not a Discord API URL")
    request = urllib.request.Request(
        url, data=body, method="GET" if body is None else "POST",
        headers={**headers, "Accept": "application/json", "User-Agent": "pokopia-portal"})
    deadline = time.monotonic() + DISCORD_HTTP_SECONDS
    try:
        with opener.open(request, timeout=DISCORD_HTTP_SECONDS) as response:
            data = bytearray()
            while chunk := response.read(16384):
                data += chunk
                if len(data) > DISCORD_MAX_RESPONSE:
                    raise DiscordRefused("answer too large")
                if time.monotonic() > deadline:
                    raise DiscordUnavailable("answer too slow")
            if response.status != 200:
                raise DiscordRefused(f"HTTP {response.status}")
            return bytes(data)
    except urllib.error.HTTPError as exc:
        with contextlib.suppress(Exception):
            exc.close()
        failure = DiscordUnavailable if exc.code == 429 or exc.code >= 500 else DiscordRefused
        raise failure(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
        raise DiscordUnavailable(type(exc).__name__) from None


def discord_json(data: bytes) -> dict:
    try:
        value = json.loads(data)
    except ValueError:
        raise DiscordRefused("malformed answer") from None
    if not isinstance(value, dict):
        raise DiscordRefused("malformed answer")
    return value


class Portal:
    def __init__(self, args: argparse.Namespace):
        self.discord = discord_config(args)  # None: Discord sign-in is off
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
        self.ceremonies = Ceremonies(CEREMONY_SECONDS)
        self.discord_flows = Ceremonies(DISCORD_FLOW_SECONDS)  # keyed by the OAuth state
        self.discord_links = Ceremonies(DISCORD_LINK_SECONDS)  # keyed by DISCORD_LINK_COOKIE
        self.discord_slots = threading.BoundedSemaphore(DISCORD_MAX_CONCURRENT)
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

    def discord_identity(self, code: str, verifier: str) -> str:
        """The Discord user ID behind an authorization code. The code and the PKCE verifier are
        exchanged for an access token, which must be a Bearer token for exactly the identify scope;
        it reads /users/@me once and is then dropped: never stored, logged or refreshed (a refresh
        token in the answer is ignored). It is not revoked either: Discord revokes every token of the
        user's authorization at once, which would break a sign-in of the same user in progress
        elsewhere. Only the numeric user ID is taken from the answer. Raises DiscordUnavailable or
        DiscordRefused. Never call with self.lock held: this waits for Discord."""
        discord = self.discord
        basic = base64.b64encode(f"{discord.client_id}:{discord.client_secret}".encode()).decode()
        answer = discord_json(discord_https(
            discord.opener, DISCORD_TOKEN_URL,
            {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": discord.redirect_uri,
                       "code_verifier": verifier}).encode()))
        token, token_type = answer.get("access_token"), answer.get("token_type")
        if not (isinstance(token_type, str) and token_type.lower() == "bearer" and isinstance(token, str)
                and DISCORD_ACCESS_TOKEN.fullmatch(token) and answer.get("scope") == DISCORD_SCOPE):
            raise DiscordRefused("not a Bearer token for exactly the identify scope")
        user = discord_json(discord_https(discord.opener, DISCORD_USER_URL, {"Authorization": f"Bearer {token}"},
                                          None))
        del token, answer
        discord_id = user.get("id")
        if not (isinstance(discord_id, str) and DISCORD_ID.fullmatch(discord_id) and int(discord_id) < 2 ** 64):
            raise DiscordRefused("no user ID")
        return discord_id


# --- HTTP --------------------------------------------------------------------------------------


def credential_of(body: dict) -> dict:
    credential = body.get("credential")
    if not isinstance(credential, dict):
        raise ApiError(400, "Missing passkey response.")
    return credential


def link_request(value: object) -> dict:
    """A launcher's link request (the parameters of /link): the loopback port of its callback, its
    state, its PKCE challenge, the SHA-256 of its CSR, and the PC's name."""
    if not isinstance(value, dict):
        raise ApiError(400, "This link request is malformed. Start linking again from the launcher.")
    port, state = value.get("port"), value.get("state")
    challenge, csr_sha256 = value.get("challenge"), value.get("csr")
    if not (isinstance(port, int) and 1024 <= port <= 65535
            and isinstance(state, str) and STATE.fullmatch(state) and isinstance(challenge, str)
            and PKCE.fullmatch(challenge) and isinstance(csr_sha256, str) and SHA256_HEX.fullmatch(csr_sha256)):
        raise ApiError(400, "This link request is malformed. Start linking again from the launcher.")
    return {"port": port, "state": state, "challenge": challenge, "csr": csr_sha256,
            "name": clean_name(value.get("name"), 64)}


class Handler(BaseHTTPRequestHandler):
    server_version = "pokopia-portal"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    @property
    def portal(self) -> Portal:
        return self.server.portal

    def log_message(self, format: str, *args) -> None:
        # Also how http.server logs request lines and its errors: every query is cut off.
        log.info("%s %s", self.client_ip(), LOGGED_QUERY.sub("?[query]", format % args))

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
        elif path == "/api/config":
            self.run_api(Handler.config)
        elif path == DISCORD_CALLBACK_PATH:
            self.discord_callback()
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
            self.send_json(exc.status, {"error": exc.message,
                                        **({"signIn": True, "signInWith": exc.sign_in} if exc.sign_in else {})})
        except Exception:
            log.exception("%s failed", urlsplit(self.path).path)
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

    def cookie(self, name: str) -> str | None:
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(name)
        return morsel.value if morsel is not None else None

    def session_token(self) -> str | None:
        return self.cookie(SESSION_COOKIE)

    def session_sha256(self) -> bytes | None:
        token = self.session_token()
        return None if token is None else sha256(token)

    def find_session(self, conn: sqlite3.Connection, token_sha256: bytes | None) -> sqlite3.Row | None:
        """The account of a live session, with the session's auth_type, credential_id, discord_id
        and signed_in_at: the session unexpired, the account enabled, and what it signed in with
        still the account's: its passkey, or its Discord identity while Discord sign-in is on."""
        if token_sha256 is None:
            return None
        return conn.execute(
            "SELECT accounts.*, sessions.auth_type, sessions.credential_id, sessions.discord_id, "
            "sessions.signed_in_at FROM sessions JOIN accounts ON accounts.id = sessions.account_id "
            "WHERE sessions.token_sha256 = ? AND sessions.expires_at > ? AND accounts.disabled_at IS NULL "
            "AND ((sessions.auth_type = 'passkey' AND EXISTS (SELECT 1 FROM passkeys "
            "WHERE passkeys.credential_id = sessions.credential_id AND passkeys.account_id = sessions.account_id)) "
            "OR (sessions.auth_type = 'discord' AND ? AND EXISTS (SELECT 1 FROM discord_identities "
            "WHERE discord_identities.discord_id = sessions.discord_id "
            "AND discord_identities.account_id = sessions.account_id)))",
            (token_sha256, int(time.time()), self.portal.discord is not None)).fetchone()

    @staticmethod
    def checked_session(account: sqlite3.Row | None, recent: bool) -> sqlite3.Row:
        if account is None:
            raise ApiError(401, "Sign in first.")
        if recent and account["signed_in_at"] < time.time() - RECENT_SIGN_IN_SECONDS:
            if account["auth_type"] == "discord":
                raise ApiError(401, "Confirm with Discord first.", sign_in="discord")
            raise ApiError(401, "Confirm with your passkey first.", sign_in="passkey")
        return account

    def session_account(self) -> sqlite3.Row | None:
        with self.portal.lock:
            return self.find_session(self.portal.db, self.session_sha256())

    def require_session(self, recent: bool = False) -> sqlite3.Row:
        """The signed-in account, for reading. With `recent`, the sign-in must be at most
        RECENT_SIGN_IN_SECONDS old, as for changing passkeys and linking launchers or Discord."""
        return self.checked_session(self.session_account(), recent)

    @contextlib.contextmanager
    def session_transaction(self, recent: bool = False):
        """A write transaction for a signed-in change: BEGIN IMMEDIATE (so no other request, nor
        the administration commands in another process, can change the account in between), then
        the session read again inside it, so a passkey removed, Discord unlinked or an account
        disabled by a concurrent request stops this one. Yields (connection, account)."""
        token_sha256 = self.session_sha256()
        with self.portal.lock, self.portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            yield conn, self.checked_session(self.find_session(conn, token_sha256), recent)

    def start_session(self, conn: sqlite3.Connection, account_id: str, auth_type: str,
                      credential: bytes | str) -> None:
        """Signs in with a passkey (`credential` its ID) or a Discord identity (the Discord user ID),
        inside the caller's transaction (so one removed meanwhile cannot leave a session behind)."""
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute("INSERT INTO sessions (token_sha256, account_id, auth_type, credential_id, discord_id, "
                     "signed_in_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (sha256(token), account_id, *credential_columns(auth_type, credential), now,
                      now + SESSION_SECONDS))
        self.cookies.append(("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_SECONDS}; "
                                           "Secure; HttpOnly; SameSite=Strict"))

    def ensure_sign_in_method(self, conn: sqlite3.Connection, account_id: str) -> None:
        """Refuses (and so rolls back) a change that would leave an account without a passkey and
        without a Discord identity: no way to sign in again."""
        if not conn.execute("SELECT EXISTS (SELECT 1 FROM passkeys WHERE account_id = ?) "
                            "OR EXISTS (SELECT 1 FROM discord_identities WHERE account_id = ?)",
                            (account_id, account_id)).fetchone()[0]:
            raise ApiError(403, "An account must keep a way to sign in.")

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
            self.start_session(conn, account_id, "passkey", verified.credential_id)
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
            self.start_session(conn, row["id"], "passkey", credential_id)
        return {"account": row["id"]}

    def logout(self, body: dict) -> dict:
        if (token_sha256 := self.session_sha256()) is not None:
            with self.portal.lock, self.portal.db as conn:
                conn.execute("DELETE FROM sessions WHERE token_sha256 = ?", (token_sha256,))
        self.cookies.append(("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"))
        return {}

    # Account management

    def config(self, body: dict) -> dict:
        """What the page needs to know before anyone signs in."""
        return {"discord": self.portal.discord is not None}

    def account_info(self, body: dict) -> dict:
        account = self.require_session()
        with self.portal.lock:
            passkeys = self.portal.db.execute(
                "SELECT credential_id, created_at, last_used_at, added_type, added_with, added_discord FROM passkeys "
                "WHERE account_id = ? ORDER BY created_at", (account["id"],)).fetchall()
            devices = self.portal.db.execute(
                "SELECT id, name, created_at, expires_at, revoked_at, linked_type, linked_with, linked_discord "
                "FROM devices WHERE account_id = ? ORDER BY created_at DESC", (account["id"],)).fetchall()
            discord = self.portal.db.execute(
                "SELECT discord_id, created_at, last_used_at, added_with FROM discord_identities WHERE account_id = ?",
                (account["id"],)).fetchone()

        def passkey_id(credential_id: bytes | None) -> str | None:
            return bytes_to_base64url(credential_id) if credential_id is not None else None

        def reference(auth_type: str | None, credential_id: bytes | None, discord_id: str | None) -> str | None:
            """A tagged credential reference as the page names it: the passkey ID or the Discord user ID."""
            return passkey_id(credential_id) if auth_type == "passkey" else discord_id

        return {
            "id": account["id"],
            "name": account["name"],
            "created": account["created_at"],
            "signed_in_with": {"type": account["auth_type"], "id": reference(
                account["auth_type"], account["credential_id"], account["discord_id"])},
            "discord_enabled": self.portal.discord is not None,
            "discord": None if discord is None else {
                "id": discord["discord_id"], "created": discord["created_at"], "last_used": discord["last_used_at"],
                "added_with": passkey_id(discord["added_with"]),
                "current": account["auth_type"] == "discord" and account["discord_id"] == discord["discord_id"]},
            "passkeys": [{"id": passkey_id(row["credential_id"]), "created": row["created_at"],
                          "last_used": row["last_used_at"], "added_type": row["added_type"],
                          "added_with": reference(row["added_type"], row["added_with"], row["added_discord"]),
                          "current": account["auth_type"] == "passkey"
                          and row["credential_id"] == account["credential_id"]} for row in passkeys],
            "devices": [{"id": row["id"], "name": row["name"], "created": row["created_at"],
                         "expires": row["expires_at"], "revoked": row["revoked_at"], "linked_type": row["linked_type"],
                         "linked_with": reference(row["linked_type"], row["linked_with"], row["linked_discord"])}
                        for row in devices],
        }

    def require_passkey_session(self, conn: sqlite3.Connection, account: sqlite3.Row) -> None:
        """Adding or removing a passkey of an account that has one needs a sign-in with a passkey:
        otherwise a Discord sign-in alone (a lesser factor) could add a passkey of its own and then
        remove the owner's. An account with no passkey (created with Discord) may add its first with
        its Discord session; callers check this inside their transaction, so two such adds at once
        cannot both pass."""
        if account["auth_type"] != "passkey" and conn.execute(
                "SELECT 1 FROM passkeys WHERE account_id = ?", (account["id"],)).fetchone():
            raise ApiError(401, "Confirm with your passkey first.", sign_in="passkey")

    def passkey_begin(self, body: dict) -> dict:
        account = self.require_session(recent=True)
        with self.portal.lock:
            self.require_passkey_session(self.portal.db, account)
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
            self.require_passkey_session(conn, current)
            if conn.execute("SELECT COUNT(*) FROM passkeys WHERE account_id = ?",
                            (current["id"],)).fetchone()[0] >= MAX_PASSKEYS:
                raise ApiError(403, f"An account can have at most {MAX_PASSKEYS} passkeys.")
            try:
                conn.execute("INSERT INTO passkeys (credential_id, account_id, public_key, sign_count, created_at, "
                             "added_type, added_with, added_discord) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             (verified.credential_id, current["id"], verified.credential_public_key,
                              verified.sign_count, int(time.time()), current["auth_type"], current["credential_id"],
                              current["discord_id"]))
            except sqlite3.IntegrityError:
                raise ApiError(409, "This passkey is already registered.") from None
        return {}

    def passkey_delete(self, body: dict) -> dict:
        """Removes a passkey, and in the same transaction every session that signed in with it and
        every launcher approval those sessions left pending; with "revoke_launchers" also the
        launchers linked through it. Inside that transaction the session is read again: it must
        still be live, recent, and signed in with another passkey, which therefore stays (a Discord
        sign-in never removes passkeys). Of two sessions removing each other's passkeys at once, the
        second finds its own passkey gone."""
        try:
            credential_id = base64url_to_bytes(body.get("passkey"))
        except (TypeError, ValueError, AttributeError):
            raise ApiError(400, "Unknown passkey.") from None
        revoke_launchers = body.get("revoke_launchers") is True
        now = int(time.time())
        with self.session_transaction(recent=True) as (conn, account):
            self.require_passkey_session(conn, account)
            if credential_id == account["credential_id"]:
                if conn.execute("SELECT 1 FROM passkeys WHERE account_id = ? AND credential_id != ?",
                                (account["id"], credential_id)).fetchone():
                    raise ApiError(400, "Sign in with another of your passkeys to remove this one.", sign_in="passkey")
                raise ApiError(403, "This is your only passkey. Add another passkey before removing it.")
            deleted = conn.execute("DELETE FROM passkeys WHERE credential_id = ? AND account_id = ?",
                                   (credential_id, account["id"])).rowcount
            if not deleted:
                raise ApiError(404, "Unknown passkey.")
            conn.execute("DELETE FROM sessions WHERE auth_type = 'passkey' AND credential_id = ?", (credential_id,))
            conn.execute("DELETE FROM link_codes WHERE auth_type = 'passkey' AND credential_id = ?", (credential_id,))
            revoked = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE linked_type = 'passkey' AND linked_with = ? "
                "AND account_id = ? AND revoked_at IS NULL",
                (now, credential_id, account["id"])).rowcount if revoke_launchers else 0
            self.ensure_sign_in_method(conn, account["id"])
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
        request = link_request(body)
        now = int(time.time())
        code = secrets.token_urlsafe(32)
        with self.session_transaction(recent=True) as (conn, account):
            if conn.execute("SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at IS NULL "
                            "AND expires_at > ?", (account["id"], now)).fetchone()[0] >= MAX_DEVICES:
                raise ApiError(403, f"An account can have at most {MAX_DEVICES} linked launchers. Revoke one first.")
            conn.execute("DELETE FROM link_codes WHERE expires_at <= ?", (now,))
            conn.execute("INSERT INTO link_codes (code_sha256, account_id, auth_type, credential_id, discord_id, "
                         "code_challenge, csr_sha256, device_name, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (sha256(code), account["id"], account["auth_type"], account["credential_id"],
                          account["discord_id"], request["challenge"], request["csr"], request["name"],
                          now + LINK_CODE_SECONDS))
        return {"redirect": f"http://127.0.0.1:{request['port']}/callback?"
                            + urlencode({"code": code, "state": request["state"]})}

    def link_token(self, body: dict) -> dict:
        """Called by the launcher, not the browser: redeems a link code for a device certificate.
        A wrong PKCE verifier or certificate request uses the code up. A good one is used up only
        in the transaction that records the launcher, after the certificate is made: there the code
        is read again and must still exist (removing a passkey, unlinking Discord, disabling or
        deleting the account deletes the codes they approved, so none can come back), and of two
        redemptions at once only the first finds it. A failure while making the certificate leaves
        the code as it was."""
        portal = self.portal
        if not portal.limiter.allow("link", self.client_ip(), 30, 600):
            raise ApiError(429, "Too many requests. Try again in a few minutes.")
        code, verifier, csr_pem = body.get("code"), body.get("verifier"), body.get("csr")
        if not (isinstance(code, str) and isinstance(verifier, str) and VERIFIER.fullmatch(verifier)
                and isinstance(csr_pem, str) and len(csr_pem) <= 8192):
            raise ApiError(400, "Malformed link request.")
        code_sha256 = sha256(code)
        invalid = "The link code is invalid or expired. Start linking again."

        def refuse(status: int, message: str) -> ApiError:
            """Uses the code up and returns the error to raise."""
            with portal.lock, portal.db as conn:
                conn.execute("DELETE FROM link_codes WHERE code_sha256 = ?", (code_sha256,))
            return ApiError(status, message)

        now = int(time.time())
        with portal.lock:
            row = portal.db.execute("SELECT * FROM link_codes WHERE code_sha256 = ?", (code_sha256,)).fetchone()
        if row is None or row["expires_at"] <= now:
            raise refuse(400, invalid)
        challenge = base64.urlsafe_b64encode(sha256(verifier)).rstrip(b"=").decode()
        if not hmac.compare_digest(challenge, row["code_challenge"]):
            raise refuse(400, invalid)
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError:
            raise refuse(400, "Malformed certificate request.") from None
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        if not hmac.compare_digest(hashlib.sha256(csr_der).hexdigest(), row["csr_sha256"]):
            raise refuse(400, "The certificate request is not the one that was approved.")
        public_key = csr.public_key()
        if not (csr.is_signature_valid and isinstance(public_key, ec.EllipticCurvePublicKey)
                and public_key.curve.name == "secp256r1"):
            raise refuse(400, "The certificate request needs a P-256 key and a valid signature.")
        device_id = new_id("dev-")
        cert = issue_certificate(portal.device_ca_key, portal.device_ca_cert, public_key, device_id,
                                 portal.device_days)
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        now = int(time.time())
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT * FROM link_codes WHERE code_sha256 = ?", (code_sha256,)).fetchone()
            if current is None or current["expires_at"] <= now or tuple(current) != tuple(row):
                raise ApiError(400, invalid)
            conn.execute("DELETE FROM link_codes WHERE code_sha256 = ?", (code_sha256,))
            account = conn.execute("SELECT disabled_at FROM accounts WHERE id = ?",
                                   (row["account_id"],)).fetchone()
            if account is None or account["disabled_at"] is not None:
                raise ApiError(403, "This account is disabled.")
            # What approved the link must still be the account's: that passkey, or that Discord
            # identity while Discord sign-in is on.
            if row["auth_type"] == "passkey":
                if not conn.execute("SELECT 1 FROM passkeys WHERE credential_id = ? AND account_id = ?",
                                    (row["credential_id"], row["account_id"])).fetchone():
                    raise ApiError(400, "The passkey that approved this link was removed. Start linking again.")
            elif portal.discord is None or not conn.execute(
                    "SELECT 1 FROM discord_identities WHERE discord_id = ? AND account_id = ?",
                    (row["discord_id"], row["account_id"])).fetchone():
                raise ApiError(400, "The Discord account that approved this link was unlinked. Start linking again.")
            active = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at IS NULL AND expires_at > ?",
                (row["account_id"], now)).fetchone()[0]
            if active >= MAX_DEVICES:
                raise ApiError(403, f"An account can have at most {MAX_DEVICES} linked launchers.")
            conn.execute("INSERT INTO devices (id, account_id, name, cert_sha256, created_at, expires_at, "
                         "linked_type, linked_with, linked_discord) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (device_id, row["account_id"], row["device_name"], fingerprint, now,
                          int(cert.not_valid_after_utc.timestamp()), row["auth_type"], row["credential_id"],
                          row["discord_id"]))
        log.info("account %s linked device %s", row["account_id"], device_id)
        return {
            "account": row["account_id"],
            "device": device_id,
            "certificate": pem(cert).decode(),
            "ingress": portal.ingress,
        }

    # Discord sign-in

    def discord_start(self, body: dict) -> dict:
        """Starts signing in with Discord ("signin"), creating an account with it ("signup"), or
        linking it to the signed-in account ("link", which needs a recent passkey sign-in, and
        remembers that session). Answers with the URL of Discord's consent page. The flow stays on
        the server under a fresh random state (single use, DISCORD_FLOW_SECONDS) with a fresh PKCE
        verifier, and is bound to this browser by DISCORD_COOKIE. A launcher's link request ("link":
        the /link parameters) rides along, so that the page comes back to it."""
        portal = self.portal
        discord = portal.discord
        if discord is None:
            raise ApiError(404, "Discord sign-in is not enabled on this server.")
        if not portal.limiter.allow("discord", self.client_ip(), 30, 600):
            raise ApiError(429, "Too many sign-in attempts. Try again in a few minutes.")
        intent = body.get("intent")
        flow = {"intent": intent, "link": None if body.get("link") is None else link_request(body["link"])}
        if intent == "signup":
            # As register_begin; register_finish's checks happen again in discord_sign_up.
            portal.prune_unlinked()
            if not portal.limiter.allow("register", self.client_ip(), 10, 3600):
                raise ApiError(429, "Too many sign-ups from your network. Try again later.")
            flow["name"] = clean_name(body.get("name"), 32)
            with portal.lock:
                problem = portal.admission_problem(portal.db)
            if problem is not None:
                raise ApiError(403, problem)
        elif intent == "link":
            token_sha256 = self.session_sha256()
            with portal.lock:
                account = self.checked_session(self.find_session(portal.db, token_sha256), recent=True)
                linked = portal.db.execute("SELECT 1 FROM discord_identities WHERE account_id = ?",
                                           (account["id"],)).fetchone()
            if account["auth_type"] != "passkey":
                raise ApiError(400, "Sign in with a passkey to link Discord.", sign_in="passkey")
            if linked:
                raise ApiError(409, "Your account already has a Discord account linked.")
            flow.update(account=account["id"], session=token_sha256)
        elif intent != "signin":
            raise ApiError(400, "Unknown sign-in request.")
        verifier = secrets.token_urlsafe(64)  # 86 characters; RFC 7636 allows 43 to 128
        browser = secrets.token_urlsafe(32)
        flow.update(verifier=verifier, browser=sha256(browser))
        state = portal.discord_flows.put("discord", flow)
        self.cookies.append(("Set-Cookie", f"{DISCORD_COOKIE}={browser}; Path=/; Max-Age={DISCORD_FLOW_SECONDS}; "
                                           "Secure; HttpOnly; SameSite=Lax"))
        challenge = base64.urlsafe_b64encode(sha256(verifier)).rstrip(b"=").decode()
        return {"redirect": DISCORD_AUTHORIZE_URL + "?" + urlencode({
            "response_type": "code", "client_id": discord.client_id, "scope": DISCORD_SCOPE, "state": state,
            "redirect_uri": discord.redirect_uri, "code_challenge": challenge, "code_challenge_method": "S256"})}

    def discord_callback(self) -> None:
        """Where Discord sends the browser back: a GET, as a top-level navigation from discord.com,
        so the SameSite=Strict session cookie is not sent but the Lax DISCORD_COOKIE is. Always
        clears that cookie and redirects to the page (to /link with the launcher's request when the
        flow carried one) with one fixed result name in the fragment. The authorization code, the
        state and Discord's answers never reach a response, a log line or an exception message:
        request lines are logged without their query (log_message), and a failure here is logged
        by exception type and code location only."""
        if self.portal.discord is None:
            self.send(404, b"not found\n", "text/plain; charset=utf-8")
            return
        clear = ("Set-Cookie", f"{DISCORD_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
        self.cookies = []
        flow: dict = {}
        try:
            result = self.discord_result(flow)
        except Exception as exc:
            frame = exc.__traceback__
            while frame.tb_next is not None:
                frame = frame.tb_next
            code = frame.tb_frame.f_code
            log.error("Discord callback failed: %s in %s (%s line %d)", type(exc).__name__, code.co_name,
                      os.path.basename(code.co_filename), frame.tb_lineno)
            result = "failed"
            self.cookies = []
        if result != "link-pending":  # a pending link still needs this browser binding to finish
            self.cookies.insert(0, clear)
        link = flow.get("link")
        target = "/link?" + urlencode(link) if link else "/"
        self.send(303, b"", "text/plain; charset=utf-8", [("Location", f"{target}#discord={result}"), *self.cookies])

    def discord_result(self, flow_out: dict) -> str:
        """Checks Discord's answer and acts on it; returns the result name for the page. The flow
        found is copied into `flow_out`, for where the page goes next."""
        portal = self.portal
        if not portal.limiter.allow("discord-callback", self.client_ip(), 30, 600):
            return "busy"
        try:
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=8)
        except ValueError:
            return "failed"
        if any(len(values) != 1 for values in query.values()):
            return "failed"
        params = {name: values[0] for name, values in query.items()}
        state = params.get("state", "")
        if not FLOW_STATE.fullmatch(state):
            return "expired"
        try:
            flow = portal.discord_flows.take(state, "discord")  # single use: gone whatever comes next
        except ApiError:
            return "expired"
        flow_out.update(flow)
        # Bound to the browser that started it: a callback URL opened in another browser (someone
        # else's sign-in planted on this one, or a leaked URL replayed) has no matching cookie.
        browser = self.cookie(DISCORD_COOKIE)
        if browser is None or not hmac.compare_digest(sha256(browser), flow["browser"]):
            return "expired"
        if params.get("iss") != DISCORD_ISSUER:  # RFC 9207: the answer is Discord's, not another server's
            return "failed"
        if "error" in params:
            return "cancelled" if params["error"] == "access_denied" else "failed"
        code = params.get("code", "")
        if not DISCORD_CODE.fullmatch(code):
            return "failed"
        if not portal.discord_slots.acquire(blocking=False):
            return "busy"
        try:
            discord_id = portal.discord_identity(code, flow["verifier"])
        except DiscordUnavailable as exc:
            log.warning("Discord sign-in: Discord unavailable (%s)", exc)
            return "unavailable"
        except DiscordRefused as exc:
            log.warning("Discord sign-in refused: %s", exc)
            return "failed"
        finally:
            portal.discord_slots.release()
        finish = {"signin": self.discord_sign_in, "signup": self.discord_sign_up, "link": self.discord_link}
        return finish[flow["intent"]](flow, discord_id)

    def discord_sign_in(self, flow: dict, discord_id: str) -> str:
        """Signs in to the enabled account the Discord identity is linked to. An identity linked to
        no account creates or joins none: accounts are never matched by name or e-mail."""
        now = int(time.time())
        with self.portal.lock, self.portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT accounts.id FROM discord_identities JOIN accounts ON accounts.id = discord_identities.account_id "
                "WHERE discord_identities.discord_id = ? AND accounts.disabled_at IS NULL", (discord_id,)).fetchone()
            if row is None:
                return "not-linked"
            conn.execute("UPDATE discord_identities SET last_used_at = ? WHERE discord_id = ?", (now, discord_id))
            self.start_session(conn, row["id"], "discord", discord_id)
        return "signed-in"

    def discord_sign_up(self, flow: dict, discord_id: str) -> str:
        """Creates an account with the Discord identity, under the same admission rules as a passkey
        sign-up (checked again here, in the transaction that creates it), and signs in to it."""
        portal = self.portal
        account_id = new_id("acct-")
        now = int(time.time())
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM discord_identities WHERE discord_id = ?", (discord_id,)).fetchone():
                return "already-linked"
            if portal.admission_problem(conn) is not None:
                return "signup-refused"
            conn.execute("INSERT INTO accounts (id, user_handle, name, created_at) VALUES (?, ?, ?, ?)",
                         (account_id, secrets.token_bytes(32), flow["name"], now))
            conn.execute("INSERT INTO discord_identities (discord_id, account_id, created_at, last_used_at) "
                         "VALUES (?, ?, ?, ?)", (discord_id, account_id, now, now))
            self.start_session(conn, account_id, "discord", discord_id)
        log.info("registered account %s with Discord", account_id)
        return "created"

    def discord_link(self, flow: dict, discord_id: str) -> str:
        """Holds Discord's answer for linking until the page finishes it (discord_link_finish).
        This navigation from Discord carries no SameSite=Strict session cookie, so the session
        signed in in this browser now cannot be checked here: another tab could have signed in to
        another account since linking started. The answer waits DISCORD_LINK_SECONDS, single use,
        under a random handle in a Strict cookie; only the Discord user ID is kept, never the code or
        a token."""
        handle = self.portal.discord_links.put("link", {
            "discord_id": discord_id, "account": flow["account"], "session": flow["session"],
            "browser": flow["browser"]})
        self.cookies.append(("Set-Cookie", f"{DISCORD_LINK_COOKIE}={handle}; Path=/; Max-Age={DISCORD_LINK_SECONDS}; "
                                           "Secure; HttpOnly; SameSite=Strict"))
        return "link-pending"

    def discord_link_finish(self, body: dict) -> dict:
        """Finishes linking Discord, as a same-origin POST from the page right after Discord's
        redirect. Links the Discord identity held by discord_link only if this browser is the one
        that started linking (DISCORD_COOKIE), and its session now is exactly the one that started
        it (same token), still live, recent, signed in with a passkey and of the same account. An
        identity linked to any account is not moved. The held answer is used up either way."""
        portal = self.portal
        if portal.discord is None:
            raise ApiError(404, "Discord sign-in is not enabled on this server.")
        handle, browser = self.cookie(DISCORD_LINK_COOKIE), self.cookie(DISCORD_COOKIE)
        self.cookies += [
            ("Set-Cookie", f"{DISCORD_LINK_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"),
            ("Set-Cookie", f"{DISCORD_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")]
        try:
            pending = portal.discord_links.take(handle, "link")
        except ApiError:
            raise ApiError(400, "Linking Discord expired. Link Discord again.") from None
        if browser is None or not hmac.compare_digest(sha256(browser), pending["browser"]):
            raise ApiError(400, "Linking Discord expired. Link Discord again.")
        token_sha256 = self.session_sha256()
        switched = ApiError(403, "This browser is no longer signed in with the session that started linking "
                                 "Discord. Sign in again, then link Discord.")
        if token_sha256 is None or not hmac.compare_digest(token_sha256, pending["session"]):
            raise switched
        now = int(time.time())
        with portal.lock, portal.db as conn:
            conn.execute("BEGIN IMMEDIATE")
            session = self.find_session(conn, token_sha256)
            if (session is None or session["id"] != pending["account"] or session["auth_type"] != "passkey"
                    or session["signed_in_at"] < now - RECENT_SIGN_IN_SECONDS):
                raise switched
            if conn.execute("SELECT 1 FROM discord_identities WHERE account_id = ?", (session["id"],)).fetchone():
                raise ApiError(409, "Your account already has a Discord account linked.")
            if conn.execute("SELECT 1 FROM discord_identities WHERE discord_id = ?",
                            (pending["discord_id"],)).fetchone():
                raise ApiError(409, "This Discord account already belongs to an account here.")
            conn.execute("INSERT INTO discord_identities (discord_id, account_id, created_at, added_with) "
                         "VALUES (?, ?, ?, ?)", (pending["discord_id"], session["id"], now, session["credential_id"]))
        log.info("account %s linked a Discord account", session["id"])
        return {"result": "linked"}

    def discord_unlink(self, body: dict) -> dict:
        """Unlinks the account's Discord identity, and in the same transaction ends every session
        that signed in with it and every launcher approval those left pending; with
        "revoke_launchers" also revokes the launchers linked through it. Needs a recent sign-in with
        a passkey, which therefore stays as a way to sign in."""
        revoke_launchers = body.get("revoke_launchers") is True
        now = int(time.time())
        expected_account, expected_discord = body.get("account"), body.get("discord_id")
        if not (isinstance(expected_account, str) and isinstance(expected_discord, str)):
            raise ApiError(400, "Malformed request.")
        with self.session_transaction(recent=True) as (conn, account):
            identity = conn.execute("SELECT discord_id FROM discord_identities WHERE account_id = ?",
                                    (account["id"],)).fetchone()
            # What the user confirmed on the page: this account and this Discord identity. A page
            # left over from another account (this browser has signed in again since, perhaps
            # during the confirmation the request needed) or another Discord identity is refused.
            if (account["id"] != expected_account or identity is None
                    or identity["discord_id"] != expected_discord):
                raise ApiError(409, "This page is out of date. Reload it and try again.")
            if not conn.execute("SELECT 1 FROM passkeys WHERE account_id = ?", (account["id"],)).fetchone():
                raise ApiError(403, "Add a passkey before unlinking Discord: an account needs a way to sign in.")
            if account["auth_type"] != "passkey":
                raise ApiError(400, "Sign in with a passkey to unlink Discord.", sign_in="passkey")
            discord_id = identity["discord_id"]
            conn.execute("DELETE FROM discord_identities WHERE discord_id = ? AND account_id = ?",
                         (discord_id, account["id"]))
            conn.execute("DELETE FROM sessions WHERE auth_type = 'discord' AND discord_id = ?", (discord_id,))
            conn.execute("DELETE FROM link_codes WHERE auth_type = 'discord' AND discord_id = ?", (discord_id,))
            revoked = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE linked_type = 'discord' AND linked_discord = ? "
                "AND account_id = ? AND revoked_at IS NULL",
                (now, discord_id, account["id"])).rowcount if revoke_launchers else 0
            self.ensure_sign_in_method(conn, account["id"])
        log.info("account %s unlinked Discord and revoked %d launcher(s) linked with it", account["id"], revoked)
        return {"revoked_launchers": revoked}


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
    "/api/discord/start": (Handler.discord_start, True),
    "/api/discord/unlink": (Handler.discord_unlink, True),
    "/api/discord/link/finish": (Handler.discord_link_finish, True),
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
  <p>Use the passkey you created for this server<span class="discord-only" hidden>, or Discord if your
     account has it linked</span>.</p>
  <button id="login" type="button">Sign in with a passkey</button>
  <button id="discord-login" type="button" class="secondary discord-only" hidden>Sign in with Discord</button>
  <h2>Create an account</h2>
  <form id="register-form">
    <label for="name">Account name (also shown on your passkey)</label>
    <input id="name" maxlength="32" required autocomplete="username">
    <button type="submit">Create an account with a passkey</button>
    <button id="discord-register" type="button" class="secondary discord-only" hidden>Create an account with Discord</button>
  </form>
  <p class="note discord-only" hidden>The server keeps your Discord user ID, not your Discord password.
     Discord also returns basic profile information, which the server does not keep. To use Discord with an
     existing account, sign in with your passkey and link Discord there.</p>
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
  <div id="discord-section" hidden>
    <h3>Discord</h3>
    <ul id="discord"></ul>
    <button id="discord-link" type="button" class="secondary">Link Discord</button>
  </div>
  <p><button id="logout" type="button" class="secondary">Sign out</button></p>
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
.note { color: #4a4f57; font-size: 0.9em; }
[hidden] { display: none !important; }
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

// What came back from Discord: the server redirects here with one fixed result name in the
// fragment, which is shown as a fixed message (never as text from the URL) and then removed.
const DISCORD_RESULTS = {
  "signed-in": "Signed in with Discord.",
  "created": "Account created with Discord. Consider adding a passkey too, so that you can still sign in without Discord.",
  "linked": "Discord linked. You can now sign in with it.",
  "link-pending": "Finishing linking Discord…",
  "cancelled": "Discord sign-in was cancelled.",
  "expired": "This Discord sign-in expired or was started in another browser. Try again.",
  "failed": "Discord sign-in failed. Try again.",
  "unavailable": "Discord could not be reached. Try again later.",
  "busy": "Too many Discord sign-ins right now. Try again in a few minutes.",
  "not-linked": "No account here uses this Discord account. Create one, or sign in with your passkey and link Discord.",
  "already-linked": "This Discord account already belongs to an account here; sign in with Discord to use that one.",
  "signup-refused": "This server is not accepting new accounts right now.",
};
// The result name, or null.
const discordResult = (() => {
  const match = /^#discord=([a-z-]+)$/.exec(location.hash);
  if (!match) return null;
  history.replaceState(null, "", location.pathname + location.search);
  return Object.prototype.hasOwnProperty.call(DISCORD_RESULTS, match[1]) ? match[1] : null;
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
    error.signIn = data.signIn === true;  // a recent sign-in is needed; see run()
    error.signInWith = data.signInWith;  // with "passkey" or "discord"
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

// Names a tagged credential reference (what a session signed in with, what approved a launcher or
// added a passkey) the way the account page lists it.
function credentialLabel(account, labels) {
  return (type, id) => type === "discord"
    ? (account.discord && account.discord.id === id ? "Discord" : "a Discord account that was unlinked")
    : (labels[id] || "a removed passkey");
}

function renderDevices(devices, label) {
  const now = Date.now() / 1000;
  $("devices").replaceChildren(...(devices.length ? devices.map((d) => {
    if (d.revoked) return item(`${d.name}: revoked ${when(d.revoked)}`);
    if (d.expires <= now) return item(`${d.name}: expired ${when(d.expires)}; link it again`);
    const approved = `approved with ${label(d.linked_type, d.linked_with)}`;
    return item(`${d.name}: linked ${when(d.created)} (${approved}), valid until ${when(d.expires)}`, "Revoke", async () => {
      if (!confirm(`Revoke ${d.name}? It is disconnected and must be linked again.`)) return;
      await api("/api/devices/revoke", {device: d.id});
      await refresh();
      status("Launcher revoked.");
    });
  }) : [item("None yet. Run the launcher's link command to add this PC.")]));
}

function renderPasskeys(account, labels, label) {
  const passkeys = account.passkeys;
  // The server asks for a passkey sign-in (other than the passkey removed) when one is needed; see run().
  const removable = passkeys.length > 1;
  $("passkeys").replaceChildren(...(passkeys.length ? passkeys.map((p) => {
    const added = p.added_type ? ` with ${label(p.added_type, p.added_with)}` : "";
    const current = p.current ? " (you signed in with it)" : "";
    return item(`${labels[p.id]}${current}: added ${when(p.created)}${added}, last used ${p.last_used ? when(p.last_used) : "never"}`,
      removable ? "Remove" : null, async () => {
        if (!confirm(`Remove ${labels[p.id]}? Browsers signed in with it are signed out.`)) return;
        const linked = account.devices.filter((d) => d.linked_type === "passkey" && d.linked_with === p.id && !d.revoked).length;
        const revoke = linked > 0 && confirm(`${linked} launcher(s) were approved with ${labels[p.id]}. ` +
          "Revoke them too? Do this if someone else may have used this passkey.");
        const result = await api("/api/passkeys/delete", {passkey: p.id, revoke_launchers: revoke});
        await refresh();
        status(`Passkey removed${result.revoked_launchers ? `; ${result.revoked_launchers} launcher(s) revoked` : ""}.`);
      });
  }) : [item("None yet. Add one, so that you can also sign in without Discord.")]));
  $("add-passkey").textContent = passkeys.length ? "Add a backup passkey" : "Add a passkey";
}

function renderDiscord(account, labels) {
  const d = account.discord;
  $("discord-section").hidden = !(d || account.discord_enabled);
  $("discord-link").hidden = Boolean(d) || !account.discord_enabled;
  if (!d) {
    $("discord").replaceChildren(item("Not linked. Link your Discord account to sign in with it too."));
    return;
  }
  const current = d.current ? " (you signed in with it)" : "";
  const added = d.added_with ? ` with ${labels[d.added_with] || "a removed passkey"}` : " (the account was created with it)";
  const off = account.discord_enabled ? "" : " Discord sign-in is turned off on this server for now.";
  $("discord").replaceChildren(item(
    `Discord user ID ${d.id}${current}: linked ${when(d.created)}${added}, last used ${d.last_used ? when(d.last_used) : "never"}.${off}`,
    account.passkeys.length ? "Unlink" : null, async () => {
      if (!confirm("Unlink Discord? Browsers signed in with it are signed out, and it can no longer sign in to this account.")) return;
      const linked = account.devices.filter((x) => x.linked_type === "discord" && x.linked_with === d.id && !x.revoked).length;
      const revoke = linked > 0 && confirm(`${linked} launcher(s) were approved with Discord. ` +
        "Revoke them too? Do this if someone else may have used your Discord account.");
      // The account and Discord identity shown and confirmed here; the server refuses any other.
      const result = await api("/api/discord/unlink", {account: account.id, discord_id: d.id, revoke_launchers: revoke});
      await refresh();
      status(`Discord unlinked${result.revoked_launchers ? `; ${result.revoked_launchers} launcher(s) revoked` : ""}.`);
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
  const label = credentialLabel(account, labels);
  $("account-name").textContent = account.name;
  $("account-id").textContent = account.id;
  renderDevices(account.devices, label);
  renderPasskeys(account, labels, label);
  renderDiscord(account, labels);
  if (link) {
    $("link-name").textContent = link.name;
    $("link-fingerprint").textContent = fingerprint(link.csr);
  }
  show("account");
}

function report(error) {
  status(error.name === "NotAllowedError" ? "The passkey request was cancelled or timed out." : error.message);
}

// Changing passkeys or Discord and linking launchers need a recent sign-in; the server then asks
// for one (signIn). After a passkey sign-in the task is tried again once; a Discord sign-in is a
// round trip through Discord's page, after which the page comes back here and asks to try again.
async function run(task, retried = false) {
  status("");
  try {
    await task();
  } catch (error) {
    if (!error.signIn || retried) return report(error);
    if (error.signInWith === "discord") {
      status("Confirm with Discord to continue, then try again.");
      try {
        await discordStart("signin");
      } catch (again) {
        report(again);
      }
      return;
    }
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

// Leaves for Discord's consent page. Discord sends the browser back to the server, which redirects
// to this page (to /link with the launcher's request, if one is pending) with the result.
async function discordStart(intent, extra = {}) {
  const result = await api("/api/discord/start",
    {...extra, intent, link: link ? {...link, port: Number(link.port)} : null});
  if (typeof result.redirect !== "string" || !result.redirect.startsWith("https://discord.com/oauth2/authorize?")) {
    throw new Error("Unexpected answer from the server.");
  }
  location.assign(result.redirect);
}

async function registerWithDiscord() {
  if (!$("register-form").reportValidity()) return;
  await discordStart("signup", {name: $("name").value});
}

async function start() {
  const enabled = (await api("/api/config")).discord === true;
  for (const element of document.querySelectorAll(".discord-only")) element.hidden = !enabled;
  await refresh();
  if (discordResult === "link-pending") {
    // Discord answered; linking finishes here, where the request carries this browser's session,
    // which the server compares with the one that started linking.
    status(DISCORD_RESULTS["link-pending"]);
    await api("/api/discord/link/finish", {});
    await refresh();
    status(DISCORD_RESULTS.linked);
  } else if (discordResult) {
    status(DISCORD_RESULTS[discordResult]);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (!window.PublicKeyCredential) status("This browser does not support passkeys.");
  $("register-form").addEventListener("submit", (event) => { event.preventDefault(); run(register); });
  $("login").addEventListener("click", () => run(login));
  $("add-passkey").addEventListener("click", () => run(addPasskey));
  $("logout").addEventListener("click", () => run(async () => { await api("/api/logout", {}); await refresh(); }));
  $("link-approve").addEventListener("click", () => run(approveLink));
  $("discord-login").addEventListener("click", () => run(() => discordStart("signin")));
  $("discord-register").addEventListener("click", () => run(registerWithDiscord));
  $("discord-link").addEventListener("click", () => run(() => discordStart("link")));
  $("link-cancel").addEventListener("click", () => {
    link = null;
    $("link").hidden = true;
    history.replaceState(null, "", "/");
    status("Linking cancelled.");
  });
  run(start);
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
    log.info("portal for %s (RP ID %s) on http://%s:%d; registration %s; Discord sign-in %s; launchers connect "
             "to %s:%d as %s", portal.origin, portal.rp_id, args.bind, args.port,
             "open" if portal.registration_open else "closed", "on" if portal.discord else "off",
             portal.ingress["host"], portal.ingress["port"], portal.ingress["server_name"])
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
            "AND expires_at > ?), EXISTS (SELECT 1 FROM discord_identities WHERE account_id = accounts.id) "
            "FROM accounts ORDER BY accounts.created_at", (now,)).fetchall()
        for row in rows:
            created = datetime.datetime.fromtimestamp(row[2], datetime.timezone.utc).strftime("%Y-%m-%d")
            state = "disabled" if row[3] else "active"
            print(f"{row[0]}  {created}  {state:8}  passkeys={row[4]} discord={'yes' if row[6] else 'no'} "
                  f"launchers={row[5]}  {row[1]}")
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
    run.add_argument("--discord-client-id-file", type=Path,
                     help="file holding the Discord application's client ID; together with "
                          "--discord-client-secret-file this turns on Discord sign-in (off by default)")
    run.add_argument("--discord-client-secret-file", type=Path,
                     help="file holding the Discord application's client secret; on POSIX it must be "
                          "accessible to the portal's user only (mode 600)")
    run.add_argument("--discord-proxy",
                     help="HTTP proxy, http://host:port, that tunnels the portal's HTTPS calls to discord.com "
                          "with CONNECT (default: the https_proxy and no_proxy environment variables)")

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
