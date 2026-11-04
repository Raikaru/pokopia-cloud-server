#!/usr/bin/env python3
"""Pokopia Cloud launcher: links this PC to an account and connects the emulator to the server.

  launcher.py                     same as play
  launcher.py play [--emulator EXE] [--game FILE]
  launcher.py link [--portal https://pokopia.example.org]
  launcher.py configure --user-dir DIR
  launcher.py run
  launcher.py status

play does everything a tester needs, asking only for what it cannot find: it links this PC if it is
not linked yet (or its link expired), checks that the server accepts this PC, checks that the chosen
emulator is a compatible build, configures its existing profile with consent, starts the gateway
and emulator, and stops the gateway when the emulator exits.

link opens the account portal in the browser. There you sign in with your passkey (or create an
account) and approve this PC; the portal then issues a client certificate for a key that is created
here and never leaves this PC. On Windows the private keys are stored encrypted, with the passphrase
protected by DPAPI for the current Windows user.

run is a local gateway for the emulator. The emulator redirects npln.nintendo.net and
npln.srv.nintendo.net to 127.0.0.1 and maps HTTPS to the gateway on port 18443.
The gateway accepts TLS with a certificate from its own CA, which configure installs in the emulator.
It passes the decrypted bytes of each connection unchanged to the server over a second
TLS connection, which presents this PC's client certificate and only accepts the server certificate
the portal vouched for. The server authorizes everything the game does by the account behind that
certificate.

The gateway's CA private key is discarded right after it signs the gateway certificate, so no other
certificate can ever be issued under the CA the emulator trusts.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import codecs
import datetime
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import mmap
import os
import platform
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import certifi
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

# The emulator maps guest HTTPS connections to this unprivileged local gateway.
GATEWAY_ADDRESS = "127.0.0.1"
GATEWAY_PORT = 18443
REDIRECT_DOMAINS = "npln.srv.nintendo.net,npln.nintendo.net"
GATEWAY_CA_NAME = "pokopia-launcher-gateway-ca.der"
# The emulator writes values that contain one of these characters in double quotes (and drops the
# quotes when it reads them), for compatibility with QSettings: Config::AdjustOutputString.
INI_SPECIAL_CHARACTERS = "!#$%^&*|;'\",<>?`~="

# The compatible emulator build that ships with the launcher, in the launcher's own folder.
EMULATOR_NAME = "eglantine.exe" if os.name == "nt" else "eglantine"
# Strings a compatible emulator build contains: the names of its private-server settings and the
# header of the unsigned private-server account token it sends instead of a Nintendo one.
EMULATOR_FEATURES = {
    b"private_server_enabled": "the private-server integration",
    b"private_server_domains": "the private-server DNS redirect",
    b"private_server_gateway": "the private-server gateway",
    b"private_server_gateway_port": "the unprivileged private-server gateway port",
    b"private_server_ca": "the private-server CA setting",
    b"private_server_relay": "the relay-only network restriction",
    b"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.": "the private-server account token",
}
# The log message of an earlier local-only test build, which blocks every public address and with it
# the relay that game traffic between players goes through.
LOCAL_ONLY_BUILD = b"VPS test blocked non-private guest destination"
# Emulators of the same family keep keys and firmware in the same layout under %APPDATA%.
KEY_SOURCE_PROFILES = ("eden", "yuzu", "citron", "suyu", "sudachi")
STATUS_DLL_NOT_FOUND = 0xC0000135
VC_REDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"


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


def program_dir() -> Path:
    """The launcher's own folder: that of the .exe when it is packaged, else that of this script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def bundled_portal() -> str | None:
    """The portal address packaged into the launcher as portal.txt (next to this script when it is
    not packaged), or None."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    try:
        return (base / "portal.txt").read_text("utf-8").strip() or None
    except FileNotFoundError:
        return None


def choose_relay(given: str | None) -> str:
    """Use the operator's explicitly configured relay; never fall back to direct connections."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    try:
        relay = given or (base / "relay.txt").read_text("utf-8").strip()
    except FileNotFoundError:
        relay = given
    if not relay:
        sys.exit("No relay configured: pass --relay or package the operator's relay.txt.")
    try:
        address, ports = relay.split(":", 1)
        ip = ipaddress.IPv4Address(address)
        if ip.is_unspecified or ip.is_multicast or int(ip) == 0xFFFFFFFF:
            raise ValueError("invalid relay address")
        for item in ports.split(","):
            bounds = item.split("-")
            if len(bounds) not in (1, 2) or any(
                not part.isascii() or not part.isdigit() or
                (len(part) > 1 and part.startswith("0")) for part in bounds
            ):
                raise ValueError("invalid port")
            first, last = int(bounds[0]), int(bounds[-1])
            if not 1 <= first <= last <= 65535:
                raise ValueError("invalid port range")
    except ValueError:
        sys.exit("Invalid relay: use IPv4:port[,first-last], for example 203.0.113.10:3478,49160-49200.")
    return relay


def interactive() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def ask(question: str) -> bool:
    """Asks a yes/no question in the console; Enter means yes."""
    if not interactive():
        sys.exit(f"{question} The launcher needs an answer to go on; run it in a console window.")
    while True:
        answer = input(f"{question} [Y/n] ").strip().lower()
        if answer in ("", "y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def child_environment() -> dict[str, str]:
    env = os.environ.copy()
    if getattr(sys, "frozen", False) and sys.platform.startswith("linux"):
        original = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if original is None:
            env.pop("LD_LIBRARY_PATH", None)
        else:
            env["LD_LIBRARY_PATH"] = original
    return env


def choose_file(title: str, kinds: list[tuple[str, str]]) -> Path | None:
    """Asks for a file in an Open dialog, or in the console if Tk is missing; None if none chosen."""
    if not interactive():
        return None
    try:
        import tkinter
        from tkinter import filedialog
    except ImportError:
        tkinter = None
    if tkinter is not None:
        try:
            root = tkinter.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            try:
                chosen = filedialog.askopenfilename(parent=root, title=title,
                                                    filetypes=kinds + [("All files", "*")])
            finally:
                root.destroy()
            return Path(chosen) if chosen else None
        except tkinter.TclError:
            pass
    answer = input(f"{title} (type its path or drag it here, then press Enter; Enter alone skips): ").strip()
    if len(answer) >= 2 and answer[0] == answer[-1] and answer[0] in ("'", '"'):
        answer = answer[1:-1]
    return Path(answer) if answer else None


def load_settings(home: Path) -> dict:
    """The emulator and game that play uses (play.json), kept apart from the link in launcher.json."""
    path = home / "play.json"
    try:
        return json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        sys.exit(f"{path} is damaged ({exc}); delete it and start again.")


def save_settings(home: Path, settings: dict) -> None:
    write_file(home / "play.json", json.dumps(settings, indent=1).encode())


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
    # The portal has a publicly trusted certificate. It is checked against certifi's CA bundle, which
    # is packaged with the launcher, instead of the Windows store: there an expired cross-signed
    # intermediate (such as the ISRG Root X2 one that expired in 2025) can make OpenSSL 1.1.1 build an
    # expired chain and reject a certificate that browsers accept.
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read()).get("error")
        except (ValueError, AttributeError):
            message = None
        sys.exit(f"The portal refused the request: {message or exc}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        sys.exit(f"Could not reach the portal: {exc}")


def check_portal(portal: str) -> str:
    portal = portal.strip().rstrip("/")
    parts = urlsplit(portal)
    if parts.scheme != "https" or not parts.hostname or parts.path or parts.query or parts.fragment:
        sys.exit(f"The portal address must look like https://pokopia.example.org, not {portal!r}.")
    return portal


def choose_portal(given: str | None) -> str:
    """--portal, else the address packaged with the launcher, else one typed in the console."""
    portal = given or bundled_portal()
    if portal is None:
        if not interactive():
            sys.exit("No portal address: pass --portal https://... or package portal.txt with the launcher.")
        portal = input("Portal address the operator gave you (https://...): ")
    return check_portal(portal)


def link(home: Path, portal: str, name: str | None = None) -> dict:
    """Links this PC and returns its new launcher.json."""
    make_home(home)

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pokopia-launcher")]))
           .sign(key, hashes.SHA256()))
    csr_sha256 = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    name = " ".join((name or platform.node() or "PC").split())[:64] or "PC"

    receiver = CallbackReceiver(state)
    url = f"{portal}/link?" + urlencode({"port": receiver.port, "state": state, "challenge": challenge,
                                         "csr": csr_sha256, "name": name})
    fingerprint = " ".join(csr_sha256[i:i + 4] for i in range(0, 16, 4)).upper()
    print(f"Linking this PC as {name!r}. The portal must show the key fingerprint {fingerprint}.")
    print(f"If no browser opens, open this address on this PC:\n  {url}")
    if getattr(sys, "frozen", False) and sys.platform.startswith("linux"):
        try:
            subprocess.Popen(["xdg-open", url], env=child_environment())
        except OSError:
            pass  # The URL is printed above for manual opening.
    else:
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
    return config


# --- Gateway -----------------------------------------------------------------------------------


def read_config(home: Path) -> dict | None:
    """launcher.json, or None if this PC is not linked."""
    try:
        return json.loads((home / "launcher.json").read_text("utf-8"))
    except FileNotFoundError:
        return None


def load_config(home: Path) -> dict:
    config = read_config(home)
    if config is None:
        sys.exit(f"This PC is not linked yet ({home / 'launcher.json'} is missing); run the link command.")
    return config


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


async def start_gateway(home: Path, listen: str, ports: list[int]) -> list[asyncio.AbstractServer]:
    """Listens for the emulator on `listen` and relays each connection to the server."""
    config = load_config(home)
    ingress = config["ingress"]
    remaining = device_expiry(home) - datetime.datetime.now(datetime.timezone.utc)
    if remaining.total_seconds() <= 0:
        sys.exit("This PC's certificate has expired; run the link command again.")
    if remaining.days < RENEW_WARNING_DAYS:
        log.warning("this PC's certificate expires in %d days; run the link command again soon",
                    remaining.days)
    if ensure_gateway_cert(home):
        log.warning("created a new gateway certificate; run the configure command before starting the "
                    "emulator")
    upstream = {alpn: upstream_context(home, alpn) for alpn in ("h2", "http/1.1", None)}
    local = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    local.minimum_version = ssl.TLSVersion.TLSv1_2
    local.load_cert_chain(home / "gateway.crt", home / "gateway.key",
                          password=key_password(home / "gateway.key"))
    local.set_alpn_protocols(["h2", "http/1.1"])

    async def on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await forward(reader, writer, ingress, upstream)

    servers = []
    for port in ports:
        try:
            servers.append(await asyncio.start_server(on_connection, listen, port, ssl=local))
        except OSError as exc:
            sys.exit(f"Cannot listen on {listen}:{port}: {exc}. Another program, such as a local "
                     f"server.py or a web server, is using that port; close it and try again.")
        log.info("gateway on %s:%d", listen, port)
    log.info("relaying to %s:%d as device %s of account %s", ingress["host"], ingress["port"],
             config["device"], config["account"])
    return servers


async def gateway(args: argparse.Namespace) -> None:
    await start_gateway(args.home, args.listen, args.port or [GATEWAY_PORT])
    # Short sleeps keep Ctrl+C responsive on Windows.
    while True:
        await asyncio.sleep(1)


async def check_server(home: Path, ingress: dict) -> str | None:
    """Connects to the server once as this PC. Returns why the server refused this PC, or None if it
    accepted it; exits if the server cannot be reached at all."""
    address = f"{ingress['host']}:{ingress['port']}"
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            ingress["host"], ingress["port"], ssl=upstream_context(home, "h2"),
            server_hostname=ingress["server_name"]), CONNECT_TIMEOUT_SECONDS)
    except ssl.SSLCertVerificationError as exc:
        sys.exit(f"The server at {address} did not present the certificate the portal vouched for "
                 f"({exc.verify_message}); ask the operator.")
    except ssl.SSLError as exc:
        return f"the TLS handshake failed ({exc.reason or exc})"
    except (OSError, asyncio.TimeoutError) as exc:
        sys.exit(f"Cannot reach the server at {address}: {str(exc) or 'timed out'}. Check this PC's "
                 f"internet connection, or ask the operator whether the server is running.")
    try:
        # The server starts every HTTP/2 connection it accepts with its SETTINGS frame.
        data = await asyncio.wait_for(reader.read(1), CONNECT_TIMEOUT_SECONDS)
    except ssl.SSLError as exc:
        return f"it rejected this PC's certificate ({exc.reason or exc})"
    except OSError as exc:
        return f"it dropped the connection ({exc})"
    except asyncio.TimeoutError:
        sys.exit(f"The server at {address} accepted the connection but sent nothing for "
                 f"{CONNECT_TIMEOUT_SECONDS} seconds; ask the operator.")
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), CONNECT_TIMEOUT_SECONDS)
        except (OSError, asyncio.TimeoutError):
            pass
    if not data:
        return ("it closed the connection at once: this PC's link was revoked or has expired, its "
                "account is disabled, or the account has too many connections open")
    return None


async def play_session(home: Path, emulator: Path, game: Path | None) -> int:
    """Runs the gateway while the emulator runs; returns the emulator's exit code."""
    servers = await start_gateway(home, GATEWAY_ADDRESS, [GATEWAY_PORT])
    command = [str(emulator)] + (["-g", str(game)] if game else [])
    try:
        process = await asyncio.create_subprocess_exec(
            *command, cwd=str(emulator_directory(emulator)), env=child_environment())
    except OSError as exc:
        sys.exit(f"Could not start {emulator}: {exc}")
    print("The emulator is running. Keep this window open while you play; it closes when the emulator "
          "does.")
    try:
        return await process.wait()
    finally:
        for server in servers:
            server.close()


# --- Emulator ----------------------------------------------------------------------------------


def check_emulator(exe: Path) -> None:
    """Exits unless `exe` is a compatible emulator build (EMULATOR_FEATURES)."""
    try:
        with exe.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as image:
            missing = [what for marker, what in EMULATOR_FEATURES.items() if image.find(marker) < 0]
            local_only = image.find(LOCAL_ONLY_BUILD) >= 0
    except (OSError, ValueError) as exc:
        sys.exit(f"Cannot read {exe}: {exc}")
    if missing:
        sys.exit(f"{exe} is not a compatible emulator build: it lacks {', '.join(missing)}. "
                 "Install a build with private-server support; the launcher cannot add it.")
    if local_only:
        sys.exit(f"{exe} is a local-only test build: it blocks every public address, including the relay.")


def emulator_running(exe: Path) -> bool:
    """Whether `exe` is running: Windows refuses to open a running program for writing (a sharing
    violation). Opening it this way changes nothing."""
    if os.name != "nt":
        return False
    try:
        with exe.open("r+b"):
            return False
    except OSError as exc:
        return getattr(exc, "winerror", None) == 32


def emulator_directory(exe: Path) -> Path:
    """The portable profile belongs next to a macOS app bundle, not inside it."""
    if sys.platform == "darwin" and exe.parent.name == "MacOS" and \
            exe.parent.parent.name == "Contents" and exe.parent.parent.parent.suffix == ".app":
        return exe.parent.parent.parent.parent
    return exe.parent


def ini_string(value: str) -> str:
    """A string the way the emulator writes it to its config (Config::AdjustOutputString)."""
    value = value.replace("\\", "/")
    return f'"{value}"' if any(character in value for character in INI_SPECIAL_CHARACTERS) else value


def emulator_settings(ca_path: Path, relay: str) -> dict[str, str]:
    """The [Services] keys of qt-config.ini that send the game to the gateway and make the emulator
    trust it. Each setting needs its "\\default=false" key, or the emulator uses its default."""
    values = {}
    for key, value in (("airplane_mode", "false"),
                       ("private_server_enabled", "true"),
                       ("private_server_domains", ini_string(REDIRECT_DOMAINS)),
                       ("private_server_gateway", GATEWAY_ADDRESS),
                       ("private_server_gateway_port", str(GATEWAY_PORT)),
                       ("private_server_ca", ini_string(str(ca_path.resolve()))),
                       ("private_server_relay", ini_string(relay))):
        values[f"{key}\\default"] = "false"
        values[key] = value
    return values


def same_ini_value(a: str, b: str) -> bool:
    """Whether the emulator reads both values the same: it drops double quotes, and none of the
    values set here (booleans, host names, an address and a Windows path) depend on case."""
    return a.strip().replace('"', "").lower() == b.strip().replace('"', "").lower()


def update_ini(text: str, section: str, values: dict[str, str]) -> tuple[str, list[str]]:
    """Sets `values` in `section` of an INI file's text and leaves every other line as it was.
    Returns the new text and one line per change. Section and key names match regardless of case,
    as in the emulator's INI parser (SimpleIni)."""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    names = {key.lower(): key for key in values}
    found: set[str] = set()
    changes: list[str] = []
    in_section, insert_at = False, None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped[1:-1].strip().lower() == section.lower()
            if in_section:
                insert_at = index + 1
            continue
        if not in_section or not stripped or stripped[0] in ";#":
            continue
        insert_at = index + 1
        key, separator, old = line.partition("=")
        name = names.get(key.strip().lower())
        if not separator or name is None:
            continue
        found.add(name)
        if not same_ini_value(old, values[name]):
            lines[index] = f"{name}={values[name]}"
            changes.append(f"{name}: {old.strip()} -> {values[name]}")
    missing = [key for key in values if key not in found]
    if missing:
        added = [f"{key}={values[key]}" for key in missing]
        changes += [f"{key}: (not set) -> {values[key]}" for key in missing]
        if insert_at is None:
            if lines and lines[-1].strip():
                lines.append("")
            lines += [f"[{section}]"] + added
        else:
            lines[insert_at:insert_at] = added
    return newline.join(lines) + newline, changes


def configure_user_dir(home: Path, user_dir: Path, relay: str,
                       config_dir: Path | None = None) -> None:
    """Configure an existing emulator profile; back up and ask before changing an existing config."""
    ensure_gateway_cert(home)
    ca = (home / "gateway-ca.der").read_bytes()
    ca_path = user_dir / "certs" / GATEWAY_CA_NAME
    if not ca_path.is_file() or ca_path.read_bytes() != ca:
        ca_path.parent.mkdir(parents=True, exist_ok=True)
        write_file(ca_path, ca)
        print(f"Installed the gateway CA as {ca_path}.")

    ini = (config_dir or user_dir / "config") / "qt-config.ini"
    values = emulator_settings(ca_path, relay)
    try:
        original = ini.read_bytes()
    except FileNotFoundError:
        ini.parent.mkdir(parents=True, exist_ok=True)
        write_file(ini, update_ini("", "Services", values)[0].encode())
        print(f"Created {ini} with the settings that send the game to the gateway.")
        return
    bom = codecs.BOM_UTF8 if original.startswith(codecs.BOM_UTF8) else b""
    try:
        text = original[len(bom):].decode("utf-8")
    except UnicodeDecodeError as exc:
        sys.exit(f"{ini} is not UTF-8 text ({exc}); nothing was changed.")
    updated, changes = update_ini(text, "Services", values)
    if not changes:
        return
    print(f"The emulator settings in {ini} need these changes in [Services]:")
    for change in changes:
        print(f"  {change}")
    if not ask("Change them? The current file is kept as a copy next to it."):
        sys.exit("Left the emulator settings as they were; without these changes the game cannot reach "
                 "the server.")
    backup = ini.with_name(f"{ini.name}.before-pokopia-{time.strftime('%Y%m%d-%H%M%S')}")
    with backup.open("xb") as file:
        file.write(original)
    write_file(ini, bom + updated.encode())
    print(f"Updated {ini}; the previous version is {backup}.")


def import_keys_and_firmware(user_dir: Path) -> None:
    """Offers to copy the tester's decryption keys and firmware from the profile of an emulator of the
    same family into `user_dir` if it has none, and otherwise says how to install them."""
    keys = user_dir / "keys"
    firmware = user_dir / "nand" / "system" / "Contents" / "registered"
    need_keys = not (keys / "prod.keys").is_file()
    need_firmware = not firmware.is_dir() or not any(firmware.iterdir())
    if not need_keys and not need_firmware:
        return
    if os.name == "nt":
        base = Path(os.environ["APPDATA"]) if os.environ.get("APPDATA") else None
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    sources = [base / name for name in KEY_SOURCE_PROFILES] if base else []
    source = next((path for path in sources if (path / "keys" / "prod.keys").is_file()), None)
    if source is not None:
        source_firmware = source / "nand" / "system" / "Contents" / "registered"
        copy_keys = need_keys
        copy_firmware = need_firmware and source_firmware.is_dir() and any(source_firmware.iterdir())
        items = " and ".join(item for item, wanted in (("decryption keys", copy_keys),
                                                         ("firmware", copy_firmware)) if wanted)
        if items and ask(f"Copy your {items} from {source} into the emulator profile in {user_dir}? "
                         f"Nothing in {source} changes."):
            if copy_keys:
                keys.mkdir(parents=True, exist_ok=True)
                for path in sorted((source / "keys").glob("*.keys")):
                    if not (keys / path.name).exists():
                        shutil.copy2(path, keys / path.name)
                need_keys = False
            if copy_firmware:
                print("Copying the firmware...")
                if firmware.is_dir():
                    firmware.rmdir()  # empty, and copytree needs a new directory
                shutil.copytree(source_firmware, firmware)
                need_firmware = False
            print(f"Copied the {items}.")
    if need_keys:
        print("The emulator profile has no decryption keys yet: in the emulator, choose Tools > Install "
              "Decryption Keys and pick your prod.keys.")
    if need_firmware:
        print("The emulator profile has no firmware: if the game needs it, choose Tools > Install "
              "Firmware in the emulator.")


def find_emulator(given: Path | None, settings: dict) -> Path:
    """Use the explicit or previously selected emulator, or ask the player to select one."""
    def executable(path: Path) -> Path:
        if sys.platform == "darwin" and path.suffix == ".app" and path.is_dir():
            return path / "Contents" / "MacOS" / "eglantine"
        return path

    if given is not None:
        candidate = executable(given)
        if not candidate.is_file():
            sys.exit(f"{candidate} does not exist.")
        return candidate.resolve()
    saved = Path(settings["emulator"]) if settings.get("emulator") else None
    if saved is not None and saved.is_file():
        return saved.resolve()
    chosen = choose_file(f"Choose your compatible emulator executable ({EMULATOR_NAME})",
                         [("Programs", "*.exe")] if os.name == "nt" else [("All files", "*")])
    candidate = executable(chosen) if chosen else None
    if candidate is None or not candidate.is_file():
        sys.exit("No emulator chosen. Select your existing compatible emulator or pass --emulator.")
    return candidate.resolve()


def find_game(given: Path | None, settings: dict) -> Path | None:
    """--game, else the one used last time, else one the tester chooses; None opens the emulator
    without starting a game."""
    if given is not None:
        if not given.is_file():
            sys.exit(f"{given} does not exist.")
        return given.resolve()
    if settings.get("game") and Path(settings["game"]).is_file():
        return Path(settings["game"])
    chosen = choose_file("Choose your Pokopia game file (Cancel opens the emulator without a game)",
                         [("Switch games", "*.nsp *.xci *.nca"), ("All files", "*")])
    if chosen is None:
        return None
    if not chosen.is_file():
        sys.exit(f"{chosen} does not exist.")
    return chosen.resolve()


# --- Commands ----------------------------------------------------------------------------------


def emulator_profile(exe: Path) -> tuple[Path, Path]:
    """Resolve the portable or standard Eglantine profile without creating a new portable profile."""
    portable = emulator_directory(exe) / "user"
    if portable.is_dir():
        return portable, portable / "config"
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        data = base / "eden"
        return data, data / "config"
    data_base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    config_base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return data_base / "eden", config_base / "eden"


def play(args: argparse.Namespace) -> None:
    home: Path = args.home
    make_home(home)
    config = read_config(home)
    if config is None:
        print("This PC is not linked to an account yet. In the browser window that opens, sign in (or "
              "create an account) and approve this PC.")
        config = link(home, choose_portal(args.portal))
    elif device_expiry(home) <= datetime.datetime.now(datetime.timezone.utc):
        print("This PC's link has expired; linking it again.")
        config = link(home, config["portal"])
    reason = asyncio.run(check_server(home, config["ingress"]))
    if reason is not None:
        print(f"The server did not accept this PC: {reason}.")
        if not ask("Link this PC again in the browser?"):
            sys.exit("This PC cannot play until it is linked again.")
        config = link(home, config["portal"])
        reason = asyncio.run(check_server(home, config["ingress"]))
        if reason is not None:
            sys.exit(f"The server still does not accept this PC: {reason}. Ask the operator whether your "
                     f"account is enabled.")

    settings = load_settings(home)
    emulator = find_emulator(args.emulator, settings)
    check_emulator(emulator)
    if emulator_running(emulator):
        sys.exit(f"Close the emulator ({emulator}) first, then start the launcher again: the emulator "
                 f"saves its settings when it exits, which would undo the launcher's changes.")
    user_dir, config_dir = emulator_profile(emulator)
    try:
        print(f"Using the emulator's existing profile: {user_dir}")
        configure_user_dir(home, user_dir, choose_relay(args.relay), config_dir)
    except OSError as exc:
        sys.exit(f"Cannot set up the emulator profile in {user_dir}: {exc}")
    game = find_game(args.game, settings)
    save_settings(home, {"emulator": str(emulator), "game": str(game) if game else None})

    code = asyncio.run(play_session(home, emulator, game)) & 0xFFFFFFFF
    if code == STATUS_DLL_NOT_FOUND:
        sys.exit(f"{emulator.name} could not start because a DLL it needs is missing, most likely the "
                 f"Microsoft Visual C++ Redistributable (x64). Install it from {VC_REDIST_URL} and try "
                 f"again.")
    if code:
        print(f"The emulator exited with code {code:#x}. If it crashed, its log is in {user_dir / 'log'}.")


def run_play(args: argparse.Namespace) -> None:
    """play, keeping the console window open after a failure so that its message can be read."""

    def pause() -> None:
        if interactive():
            try:
                input("Press Enter to close this window.")
            except EOFError:
                pass

    try:
        play(args)
    except KeyboardInterrupt:
        pass
    except SystemExit as exc:
        if exc.code in (None, 0):
            raise
        print(exc.code, file=sys.stderr)
        pause()
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        pause()
        sys.exit(1)


def configure(args: argparse.Namespace) -> None:
    user_dir: Path = args.user_dir
    if not user_dir.is_dir():
        sys.exit(f"{user_dir} is not a directory")
    print("The emulator that uses this directory must be closed: it saves its settings when it exits.")
    try:
        configure_user_dir(args.home, user_dir, choose_relay(args.relay))
    except OSError as exc:
        sys.exit(f"Cannot set up the emulator profile in {user_dir}: {exc}")
    print(f"{user_dir} sends the game to the gateway on {GATEWAY_ADDRESS}:{GATEWAY_PORT}.")


def status(args: argparse.Namespace) -> None:
    config = load_config(args.home)
    settings = load_settings(args.home)
    print(f"portal   {config['portal']}")
    print(f"account  {config['account']}")
    print(f"device   {config['device']} (certificate valid until {device_expiry(args.home):%Y-%m-%d %H:%M} UTC)")
    print(f"server   {config['ingress']['host']}:{config['ingress']['port']} "
          f"as {config['ingress']['server_name']}")
    print(f"gateway  CA {'present' if (args.home / 'gateway-ca.der').exists() else 'missing'}")
    print(f"emulator {settings.get('emulator') or 'not chosen yet'}")
    print(f"game     {settings.get('game') or 'not chosen yet'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Pokopia Cloud launcher. Without a command, it runs play.")
    parser.add_argument("--home", type=Path, default=default_home(),
                        help=f"where keys and settings are kept (default {default_home()})")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.set_defaults(portal=None, emulator=None, game=None, relay=None)
    commands = parser.add_subparsers(dest="command")
    play_parser = commands.add_parser("play", help="link if needed, set up the emulator and play (default)")
    play_parser.add_argument("--portal", help="portal address, if none is packaged with the launcher")
    play_parser.add_argument("--emulator", type=Path,
                             help="path to the existing compatible emulator; asks if not provided or saved")
    play_parser.add_argument("--game", type=Path, help="game file to start (default: the one used last time)")
    play_parser.add_argument("--relay", help="operator's relay policy (default: packaged relay.txt)")
    link_parser = commands.add_parser("link", help="link this PC to your account")
    link_parser.add_argument("--portal", help="e.g. https://pokopia.example.org (default: the address "
                                              "packaged with the launcher)")
    link_parser.add_argument("--name", help="name of this PC on the portal (default: computer name)")
    configure_parser = commands.add_parser("configure", help="make an emulator trust the gateway and send "
                                                             "the game to it")
    configure_parser.add_argument("--user-dir", type=Path, required=True,
                                  help="the emulator's user directory, such as the user folder next to it")
    configure_parser.add_argument("--relay", help="operator's relay policy (default: packaged relay.txt)")
    run_parser = commands.add_parser("run", help="run the gateway for the emulator")
    run_parser.add_argument("--listen", default=GATEWAY_ADDRESS, help=f"loopback address (default {GATEWAY_ADDRESS})")
    run_parser.add_argument("--port", type=int, action="append",
                            help=f"listen port (default {GATEWAY_PORT}); repeatable")
    commands.add_parser("status", help="show the link and certificate state")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    if args.command in (None, "play"):
        run_play(args)
    elif args.command == "link":
        link(args.home, choose_portal(args.portal), args.name)
    elif args.command == "configure":
        configure(args)
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
