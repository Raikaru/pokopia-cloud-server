#!/usr/bin/env python3
"""Pokopia Cloud launcher: links this PC to an account and connects the emulator to the server.

  launcher.py link --portal https://pokopia.example.org
  launcher.py install-ca --emulator-user-dir "%APPDATA%\\eden"
  launcher.py run
  launcher.py status

link opens the account portal in the browser. There you sign in with your passkey (or create an
account) and approve this PC; the portal then issues a client certificate for a key that is created
here and never leaves this PC. On Windows the private keys are stored encrypted, with the passphrase
protected by DPAPI for the current Windows user.

run is a local gateway for the emulator. The emulator's DNS redirect sends npln.nintendo.net and
npln.srv.nintendo.net to 127.0.0.1, where the gateway accepts TLS on port 443 with a certificate
from its own CA (install-ca copies that CA into the emulator). It passes the decrypted bytes of each
connection unchanged to the server over a second TLS connection, which presents this PC's client
certificate and only accepts the server certificate the portal vouched for. The server authorizes
everything the game does by the account behind that certificate.

The gateway's CA private key is discarded right after it signs the gateway certificate, so no other
certificate can ever be issued under the CA the emulator trusts.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import platform
import secrets
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("launcher")

# The names the game dials, as in server.cnf: <tenant>.lp1.t.npln.srv.nintendo.net,
# gamesync.npln.nintendo.net and storage.npln.nintendo.net.
GAME_NAMES = ["*.npln.nintendo.net", "npln.nintendo.net", "*.npln.srv.nintendo.net",
              "*.t.npln.srv.nintendo.net", "*.lp1.t.npln.srv.nintendo.net"]
LINK_TIMEOUT_SECONDS = 600
CONNECT_TIMEOUT_SECONDS = 15
RENEW_WARNING_DAYS = 14
CHUNK = 65536


def default_home() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "PokopiaLauncher"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "pokopia-launcher"


def make_home(home: Path) -> None:
    """Creates the launcher's directory, readable by its owner only on POSIX systems (on Windows,
    %LOCALAPPDATA% is already private to the user)."""
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        home.chmod(0o700)


def write_file(path: Path, data: bytes, private: bool = False) -> None:
    """Replaces `path` atomically; private files are created readable by their owner only."""
    temp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(temp, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    os.replace(temp, path)


# --- Private keys at rest ------------------------------------------------------------------------

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR,
                                          ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_void_p,
                                            ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _CRYPTPROTECT_UI_FORBIDDEN = 0x1

    def _dpapi(data: bytes, protect: bool) -> bytes:
        buffer = ctypes.create_string_buffer(data, len(data))
        source = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        result = _DataBlob()
        if protect:
            ok = _crypt32.CryptProtectData(ctypes.byref(source), "Pokopia launcher key", None, None,
                                           None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(result))
        else:
            ok = _crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None,
                                             _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(result))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(result.pbData, result.cbData)
        finally:
            _kernel32.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))


def save_private_key(path: Path, key) -> None:
    """Windows: PKCS#8 PEM encrypted with a random passphrase, which DPAPI protects for the current
    user in <key>.dpapi. Elsewhere: an unencrypted PEM readable by its owner only."""
    if os.name == "nt":
        passphrase = secrets.token_urlsafe(32).encode()
        write_file(path.with_name(path.name + ".dpapi"), _dpapi(passphrase, protect=True), private=True)
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()
    write_file(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       encryption), private=True)


def key_password(path: Path) -> bytes | None:
    protected = path.with_name(path.name + ".dpapi")
    if os.name == "nt" and protected.exists():
        return _dpapi(protected.read_bytes(), protect=False)
    if b"ENCRYPTED" in path.read_bytes():
        sys.exit(f"{path} is encrypted but its passphrase is missing; run the link command again")
    return None


# --- Local gateway certificate -------------------------------------------------------------------


def ensure_gateway_cert(home: Path) -> bool:
    """Creates the gateway CA and certificate unless they exist; returns whether it created them.

    RSA 2048 and the extensions of ca.cnf and server.cnf, the combination tested with the emulator.
    """
    cert_path, key_path, ca_path = home / "gateway.crt", home / "gateway.key", home / "gateway-ca.der"
    if cert_path.exists() and key_path.exists() and ca_path.exists():
        return False
    make_home(home)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            f"Pokopia Launcher Gateway CA {secrets.token_hex(4)}")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.lp1.t.npln.srv.nintendo.net")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                              ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in GAME_NAMES]),
                       critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    save_private_key(key_path, key)
    write_file(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    write_file(ca_path, ca_cert.public_bytes(serialization.Encoding.DER))
    return True


# --- Linking -----------------------------------------------------------------------------------


class CallbackReceiver:
    """The loopback redirect target of the portal (RFC 8252): receives the one-time link code."""

    def __init__(self, state: str):
        receiver = self
        self.code: str | None = None

        class Handler(BaseHTTPRequestHandler):
            timeout = 10  # a connection that sends nothing must not stall the wait loop

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                query = parse_qs(parts.query)
                code = (query.get("code") or [""])[0]
                got_state = (query.get("state") or [""])[0]
                if parts.path != "/callback" or not code or receiver.code is not None \
                        or not hmac.compare_digest(got_state.encode(), state.encode()):
                    self.reply(400, "This link request does not belong to the launcher that is waiting.")
                    return
                receiver.code = code
                self.reply(200, "Approval received. Return to the launcher window; you can close this tab.")

            def reply(self, status: int, text: str) -> None:
                body = ("<!doctype html><meta charset=utf-8><title>Pokopia launcher</title>"
                        f"<p>{html.escape(text)}</p>").encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.timeout = 1
        self.port = self.httpd.server_address[1]

    def wait(self, seconds: float) -> str | None:
        deadline = time.monotonic() + seconds
        try:
            while self.code is None and time.monotonic() < deadline:
                self.httpd.handle_request()
        finally:
            self.httpd.server_close()
        return self.code


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read()).get("error")
        except (ValueError, AttributeError):
            message = None
        sys.exit(f"The portal refused the request: {message or exc}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        sys.exit(f"Could not reach the portal: {exc}")


def link(args: argparse.Namespace) -> None:
    portal = args.portal.rstrip("/")
    parts = urlsplit(portal)
    if parts.scheme != "https" or not parts.hostname or parts.path or parts.query or parts.fragment:
        sys.exit("--portal must look like https://pokopia.example.org")
    home: Path = args.home
    make_home(home)

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pokopia-launcher")]))
           .sign(key, hashes.SHA256()))
    csr_sha256 = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    name = " ".join((args.name or platform.node() or "PC").split())[:64] or "PC"

    receiver = CallbackReceiver(state)
    url = f"{portal}/link?" + urlencode({"port": receiver.port, "state": state, "challenge": challenge,
                                         "csr": csr_sha256, "name": name})
    fingerprint = " ".join(csr_sha256[i:i + 4] for i in range(0, 16, 4)).upper()
    print(f"Linking this PC as {name!r}. The portal must show the key fingerprint {fingerprint}.")
    print(f"If no browser opens, open this address on this PC:\n  {url}")
    webbrowser.open(url)
    code = receiver.wait(LINK_TIMEOUT_SECONDS)
    if code is None:
        sys.exit("Timed out waiting for the approval in the browser.")

    result = post_json(f"{portal}/api/link/token", {
        "code": code, "verifier": verifier,
        "csr": csr.public_bytes(serialization.Encoding.PEM).decode()})
    try:
        cert = x509.load_pem_x509_certificate(result["certificate"].encode())
        ingress = result["ingress"]
        x509.load_pem_x509_certificate(ingress["ca"].encode())
        config = {"portal": portal, "account": str(result["account"]), "device": str(result["device"]),
                  "ingress": {"host": str(ingress["host"]), "port": int(ingress["port"]),
                              "server_name": str(ingress["server_name"])}}
    except (KeyError, TypeError, ValueError) as exc:
        sys.exit(f"The portal sent an unusable answer: {exc}")
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        sys.exit("The portal issued a certificate for a different key.")

    save_private_key(home / "device.key", key)
    write_file(home / "device.crt", cert.public_bytes(serialization.Encoding.PEM))
    write_file(home / "ingress-ca.pem", ingress["ca"].encode())
    write_file(home / "launcher.json", json.dumps(config, indent=1).encode())
    print(f"Linked as device {config['device']} of account {config['account']}, valid until "
          f"{cert.not_valid_after_utc:%Y-%m-%d}. A launcher linked earlier stays valid until you revoke it "
          f"on the portal.")
    if ensure_gateway_cert(home):
        print("Created the gateway certificate. Run install-ca once for every emulator user directory.")


# --- Gateway -----------------------------------------------------------------------------------


def load_config(home: Path) -> dict:
    try:
        return json.loads((home / "launcher.json").read_text("utf-8"))
    except FileNotFoundError:
        sys.exit(f"This PC is not linked yet ({home / 'launcher.json'} is missing); run the link command.")


def device_expiry(home: Path) -> datetime.datetime:
    cert = x509.load_pem_x509_certificate((home / "device.crt").read_bytes())
    return cert.not_valid_after_utc


def upstream_context(home: Path, alpn: str | None) -> ssl.SSLContext:
    """TLS to the server: the client certificate, and only the server certificate the portal's
    ingress CA issued for the configured name."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cadata=(home / "ingress-ca.pem").read_text("ascii"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    key = home / "device.key"
    context.load_cert_chain(home / "device.crt", key, password=key_password(key))
    if alpn:
        context.set_alpn_protocols([alpn])
    return context


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(CHUNK):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass


async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ingress: dict,
                  upstream: dict[str | None, ssl.SSLContext]) -> None:
    """Relays one emulator connection to the server. Both sides negotiate the same application
    protocol (ALPN), so the server sees the game's HTTP/2 or HTTP/1.1 exactly as sent."""
    ssl_object = writer.get_extra_info("ssl_object")
    alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
    try:
        remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(
            ingress["host"], ingress["port"], ssl=upstream.get(alpn, upstream[None]),
            server_hostname=ingress["server_name"]), CONNECT_TIMEOUT_SECONDS)
    except (OSError, asyncio.TimeoutError) as exc:
        log.warning("could not connect to %s:%s: %s", ingress["host"], ingress["port"], exc)
        writer.close()
        return
    log.debug("relaying a connection (alpn=%s)", alpn)
    tasks = [asyncio.create_task(pipe(reader, remote_writer)),
             asyncio.create_task(pipe(remote_reader, writer))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        remote_writer.close()
        writer.close()


async def gateway(args: argparse.Namespace) -> None:
    home: Path = args.home
    config = load_config(home)
    ingress = config["ingress"]
    remaining = device_expiry(home) - datetime.datetime.now(datetime.timezone.utc)
    if remaining.total_seconds() <= 0:
        sys.exit("This PC's certificate has expired; run the link command again.")
    if remaining.days < RENEW_WARNING_DAYS:
        log.warning("this PC's certificate expires in %d days; run the link command again soon",
                    remaining.days)
    if ensure_gateway_cert(home):
        log.warning("created a new gateway certificate; run install-ca before starting the emulator")
    upstream = {alpn: upstream_context(home, alpn) for alpn in ("h2", "http/1.1", None)}
    local = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    local.minimum_version = ssl.TLSVersion.TLSv1_2
    local.load_cert_chain(home / "gateway.crt", home / "gateway.key",
                          password=key_password(home / "gateway.key"))
    local.set_alpn_protocols(["h2", "http/1.1"])

    async def on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await forward(reader, writer, ingress, upstream)

    for port in args.port or [443]:
        try:
            await asyncio.start_server(on_connection, args.listen, port, ssl=local)
        except OSError as exc:
            sys.exit(f"Cannot listen on {args.listen}:{port}: {exc}. Is another server (such as a "
                     f"local server.py) using it?")
        log.info("gateway on %s:%d", args.listen, port)
    log.info("relaying to %s:%d as device %s of account %s", ingress["host"], ingress["port"],
             config["device"], config["account"])
    # Short sleeps keep Ctrl+C responsive on Windows.
    while True:
        await asyncio.sleep(1)


# --- Other commands ----------------------------------------------------------------------------


def install_ca(args: argparse.Namespace) -> None:
    user_dir: Path = args.emulator_user_dir
    if not user_dir.is_dir():
        sys.exit(f"{user_dir} is not a directory")
    ensure_gateway_cert(args.home)
    certs = user_dir / "certs"
    certs.mkdir(exist_ok=True)
    target = certs / "pokopia-launcher-gateway-ca.der"
    shutil.copyfile(args.home / "gateway-ca.der", target)
    print(f"Copied the gateway CA to {target}.")
    print("With the emulator closed, set these keys in the [Services] section of its qt-config.ini:")
    print("  custom_dns_redirect_enabled=true")
    print('  custom_dns_redirect_domains="npln.srv.nintendo.net,npln.nintendo.net"')
    print("  custom_dns_redirect_address=127.0.0.1")
    print("and the matching \\default=false lines (see README).")


def status(args: argparse.Namespace) -> None:
    config = load_config(args.home)
    print(f"portal   {config['portal']}")
    print(f"account  {config['account']}")
    print(f"device   {config['device']} (certificate valid until {device_expiry(args.home):%Y-%m-%d %H:%M} UTC)")
    print(f"server   {config['ingress']['host']}:{config['ingress']['port']} "
          f"as {config['ingress']['server_name']}")
    print(f"gateway  CA {'present' if (args.home / 'gateway-ca.der').exists() else 'missing'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Pokopia Cloud launcher.")
    parser.add_argument("--home", type=Path, default=default_home(),
                        help=f"where keys and settings are kept (default {default_home()})")
    parser.add_argument("-v", "--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    link_parser = commands.add_parser("link", help="link this PC to your account")
    link_parser.add_argument("--portal", required=True, help="e.g. https://pokopia.example.org")
    link_parser.add_argument("--name", help="name of this PC on the portal (default: computer name)")
    ca_parser = commands.add_parser("install-ca", help="make an emulator trust the gateway")
    ca_parser.add_argument("--emulator-user-dir", type=Path, required=True)
    run_parser = commands.add_parser("run", help="run the gateway for the emulator")
    run_parser.add_argument("--listen", default="127.0.0.1", help="loopback address (default 127.0.0.1)")
    run_parser.add_argument("--port", type=int, action="append", help="listen port (default 443); repeatable")
    commands.add_parser("status", help="show the link and certificate state")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    if args.command == "link":
        link(args)
    elif args.command == "install-ca":
        install_ca(args)
    elif args.command == "status":
        status(args)
    else:
        try:
            loopback = ipaddress.ip_address(args.listen).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            # Anyone who can connect to the gateway acts with this PC's account.
            parser.error("--listen must be a loopback address")
        try:
            asyncio.run(gateway(args))
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
