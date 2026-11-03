#!/usr/bin/env python3
"""Local NPLN backend for Pokemon Pokopia Cloud Islands.

Every TLS port (default 443 and 8443) serves:
  * gRPC over HTTP/2 for nn.npln.auth.v1.Auth, nn.npln.ugcstore.v1.Ugcstore,
    nn.npln.matchmaking.v1.GameSessionService and nn.npln.gamesync.v1.Gamesync (live documents
    shared by the players of a game session, kept in memory), plus keep-alive-only maintenance
    and friends subscriptions.
  * Island storage over HTTP/1.1 or HTTP/2: resumable uploads at /upload/<id> with Google Cloud
    Storage semantics (the real service hands out GCS signed URLs) and downloads at
    /download/<id>. --http-port also serves storage over plain HTTP.

A UDP STUN responder (default port 3478) is the ICE server AllocateIceServerSet hands out, so
WebRTC peers on this PC gather candidates without reaching a public STUN server. Every datagram it
receives is logged with its source, and every Binding response with the address it reports.

Eden resolves *.npln.nintendo.net and *.npln.srv.nintendo.net to 127.0.0.1; the game dials
<tenant>.lp1.t.npln.srv.nintendo.net:443. Every GameSession names gamesync.npln.nintendo.net and
the first TLS port as its host:port, the Gamesync endpoint the game dials once it has the session.
Gamesync documents, global values, transactions, deferred writes and KeepUserSession calls belong
to one game session, so several islands can be open at once. The game names its documents without
their game session (docs/__gs/f, docs/__us/<id>, ...), so every Gamesync call is routed by the user
session its gamesync token was issued for, which must still be in its game session and belong to
the token's user. A call without such a token fails; none falls back to another game session.
Each user session that opens Gamesync KeepUserSession gets a docs/__us/<user session id> document,
which the game waits for before it leaves the "Communicating" screen, and its game session's
docs/__gs/f (fixed) and docs/__gs/m (mutable) documents are created if they do not exist yet.
Every target the game registers is acknowledged with TargetChange UPDATED, which the game waits
for, before its documents and LISTED.
A user session is dropped once its game has had no KeepUserSession call open for
USER_SESSION_GRACE_SECONDS, or when its user joins another game session. Its deferred writes are
then applied, its KeepUserSession calls end and the gamesync documents named after it are deleted.
A game session left empty is dropped with its creation tickets and all of its gamesync state.
Message layouts follow
https://github.com/kinnay/NPLN-Protocols (latest/proto). Methods without a handler get an empty
message, so the game sees default values. Every call is logged; -v dumps payloads. Session
descriptions (SDP) in gamesync documents are logged with their candidates when written and with
their size and digest when delivered; -v adds every byte of them.

Local mode (default) authenticates nobody and is for one PC or a trusted LAN. In client-certificate
mode (--client-ca, --auth-db) every TLS connection must present a device certificate that
portal.py issued to a passkey account; players connect through launcher.py, which relays the
emulator's connections unchanged. Every call is authorized by that account (AuthRegistry): tokens
carry it, NPLN users and upload sessions belong to it, Ugcstore documents follow the rules in
Backend.check_document_access, and matchmaking only acts for its users and checks session passwords.

Certificate (self-signed, CA:TRUE so it can be installed as its own trust anchor):
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -not_before 20250101000000Z \\
    -not_after 20351231235959Z -keyout server.key -out server.crt \\
    -subj "/CN=*.npln.nintendo.net" \\
    -addext "subjectAltName=DNS:*.npln.nintendo.net,DNS:npln.nintendo.net,\\
DNS:*.npln.srv.nintendo.net,DNS:*.t.npln.srv.nintendo.net,DNS:*.lp1.t.npln.srv.nintendo.net,\\
DNS:localhost,IP:127.0.0.1" \\
    -addext "basicConstraints=critical,CA:TRUE" \\
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \\
    -addext "extendedKeyUsage=serverAuth"
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import contextvars
import ctypes
import base64
import errno
import hashlib
import hmac
import ipaddress
import itertools
import json
import logging
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import sys
import tarfile
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, BinaryIO, Callable, Iterable
from urllib.parse import quote, urlsplit

try:
    import fcntl  # POSIX: F_FULLFSYNC on macOS
except ImportError:
    fcntl = None

import h11
import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions

log = logging.getLogger("npln")

TOKEN_TTL_SECONDS = 28800
KEEP_ALIVE_SECONDS = 30
ICE_SERVER_TTL_SECONDS = 3600
GAMESYNC_TRANSACTION_SECONDS = 270  # unfinished gamesync transactions are dropped after this
# A user session whose game has had no KeepUserSession call open for this long (since its last call
# ended, or since it joined if it never opened one) is dropped, and a game session left empty with
# it. Otherwise a game that quits leaves its session behind, and once relaunched it finds its island
# hosted by that session (QueryGameSessions, then ListUserSessions naming itself) and reports a
# communication error instead of creating a new session. The game opens KeepUserSession within a
# second of joining.
USER_SESSION_GRACE_SECONDS = 10
DEFAULT_TLS_PORTS = (443, 8443)
# The game connects to GameSession.host:port for Gamesync and checks the certificate against this
# name whatever the host. An empty host fails the connection at once with UNAVAILABLE (2321-4992).
GAMESYNC_HOST = "gamesync.npln.nintendo.net"

# Client-certificate mode (--client-ca, --auth-db; see AuthRegistry). Every connection belongs to
# the account of the device certificate it presented, and these limits apply per account.
MAX_USERS_PER_ACCOUNT = 16
MAX_UPLOADS_PER_ACCOUNT = 8  # the oldest unimported upload session is dropped for a new one
MAX_ALIASES_PER_USER = 8
MAX_DOCUMENTS_PER_USER = 64
MAX_CONNECTIONS_PER_ACCOUNT = 32
ACCOUNT_STATE_BYTES = 256 * 1024  # what the account's users, documents and aliases add to state.json
ACCOUNT_BLOB_BYTES = 128 * 1024 * 1024  # attachments and upload sessions
# Island and session passwords. A wrong guess counts against the guessing account, its network and
# the island or game session it targets: (allowed wrong guesses, window in seconds). A full window
# refuses further guesses until its oldest entry ages out, so a lockout ends one window after the
# guessing stops. An account that gave a target's current password within GUESS_TRUST_SECONDS is
# not counted against or held back by the target's count; its account and network counts still
# apply, and a new password ends the trust.
GUESS_LIMITS = {"account": (10, 600), "network": (30, 600), "target": (60, 3600)}
GUESS_TRUST_SECONDS = 30 * 86400
# How long a right island password lets the caller find the island's game session and read its
# StageData, as long as the password does not change.
PASSWORD_GRANT_SECONDS = 600
# The Ugcstore documents the game uses: tenants/<t>/documents/users/<u>/(public|private)/<name>.
USER_DOCUMENT = re.compile(r"(tenants/[^/]+)/documents/users/([^/]+)/(public|private)/(.+)")

# Resource limits, in every mode. The island's StageData upload was 2.8 MB.
MAX_GRPC_MESSAGE_BYTES = 4 * 1024 * 1024  # one gRPC message after decompression (gRPC's default)
MAX_STORAGE_REQUEST_BYTES = 32 * 1024 * 1024  # the body of one storage request
MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # one uploaded object
# Request data one connection holds: bodies, bidirectional calls' queued messages, parsed messages.
MAX_CONNECTION_BUFFER_BYTES = 48 * 1024 * 1024
MAX_BUFFERED_BYTES = 256 * 1024 * 1024  # the same across all connections
MAX_BIDI_CALLS_PER_CONNECTION = 8  # the game opens one
MAX_INBOUND_QUEUE_BYTES = 8 * 1024 * 1024  # decoded messages a bidirectional call has not read yet
INBOUND_MESSAGE_OVERHEAD = 64  # queue entry and bytes-object overhead, including empty messages
MAX_MESSAGE_FIELDS = 65536  # fields of one decoded protobuf message; a nested message is its own
# What a parsed protobuf message (Msg) counts against the request budgets while anything holds it:
# MSG_BASE_BYTES, its size (the values are copies) and MSG_FIELD_BYTES per field, which covers the
# measured worst case of about 260 bytes (every field a new number holding a short byte string).
MSG_BASE_BYTES = 512
MSG_FIELD_BYTES = 288
MAX_RESPONSE_BYTES_PER_CONNECTION = 48 * 1024 * 1024  # response data waiting for a client to read
MAX_PENDING_RESPONSE_BYTES = 256 * 1024 * 1024  # the same across all connections
SEND_STALL_SECONDS = 60  # a stream whose client grants no window for this long is reset
DOWNLOAD_CHUNK_BYTES = 64 * 1024  # downloads are read from disk and sent in pieces of this size
MAX_DOWNLOADS_PER_CONNECTION = 4
MAX_DOWNLOADS = 256  # open downloads across all connections; each holds a file open
MAX_NAME_BYTES = 512  # user, document, alias, Gamesync and target names, and MIME types
STATE_OVERHEAD_BYTES = 128  # what a record adds to state.json beside its names and fields
MAX_SESSION_PROPERTIES_BYTES = 64 * 1024  # a game session's properties; the game's were 0.4 KB
# One game session's Gamesync state in memory. Documents, global values and deferred writes, names
# included, may take MAX_GAMESYNC_BYTES in MAX_GAMESYNC_RECORDS records. Transactions and watch
# targets have fixed caps, so with names of at most MAX_NAME_BYTES they stay within about 8 MiB
# (transactions) and 1 MiB per KeepUserSession call (targets).
MAX_GAMESYNC_BYTES = 16 * 1024 * 1024
MAX_GAMESYNC_RECORDS = 4096
MAX_GAMESYNC_TRANSACTIONS = 64
MAX_TRANSACTION_READS = 256  # documents one transaction may read
MAX_WATCHERS_PER_MEMBER = 4  # KeepUserSession calls open for one user session; the game opens one
MAX_WATCH_TARGETS = 32  # per KeepUserSession call
MAX_TARGET_DOCUMENTS = 64
MAX_WATCHER_BACKLOG_BYTES = 32 * 1024 * 1024  # KeepUserSession responses waiting for a slow reader
DEFAULT_MAX_STORAGE_BYTES = 10 * 1024 ** 3  # --max-storage-mb: all documents, attachments, uploads
MIN_FREE_DISK_BYTES = 1024 ** 3  # storage stops growing when the data disk has less free space
# STUN answers anyone: per source address and in total, per second; log lines per minute; and the
# attributes and characters one log line describes.
STUN_REQUESTS_PER_ADDRESS = 20
STUN_REQUESTS_TOTAL = 1000
STUN_LOG_LINES_PER_MINUTE = 60
STUN_LOGGED_ATTRIBUTES = 16
STUN_LOG_LINE_CHARS = 1024

# gRPC status codes.
OK = 0
INVALID_ARGUMENT = 3
NOT_FOUND = 5
ALREADY_EXISTS = 6
PERMISSION_DENIED = 7
RESOURCE_EXHAUSTED = 8
FAILED_PRECONDITION = 9
ABORTED = 10
INTERNAL = 13
UNAUTHENTICATED = 16
STATUS_NAMES = {
    OK: "OK",
    INVALID_ARGUMENT: "INVALID_ARGUMENT",
    NOT_FOUND: "NOT_FOUND",
    ALREADY_EXISTS: "ALREADY_EXISTS",
    PERMISSION_DENIED: "PERMISSION_DENIED",
    RESOURCE_EXHAUSTED: "RESOURCE_EXHAUSTED",
    FAILED_PRECONDITION: "FAILED_PRECONDITION",
    ABORTED: "ABORTED",
    INTERNAL: "INTERNAL",
    UNAUTHENTICATED: "UNAUTHENTICATED",
}

# Enum values from matchmaking/v1/resources.proto.
TICKET_PENDING = 1
TICKET_SUCCEEDED = 2
TICKET_CANCELLED = 3
GAME_SESSION_ACTIVE = 2
USER_SESSION_ACTIVE = 2
STUN_PROTOCOL_UDP = 1

# Enum values from gamesync/v1/resources.proto.
DOCUMENT_CHANGE_EXIST = 1
DOCUMENT_CHANGE_UPDATED = 2
DOCUMENT_CHANGE_DELETED = 3
# The game waits, with no timeout, for TARGET_CHANGE_UPDATED (FAILED fails the wait) before it
# relies on a target it registered; LISTED only marks the end of the initial listing.
TARGET_CHANGE_UPDATED = 1
TARGET_CHANGE_LISTED = 2
TARGET_CHANGE_DELETED = 3
DOCUMENT_CHANGE_NAMES = {DOCUMENT_CHANGE_EXIST: "EXIST", DOCUMENT_CHANGE_UPDATED: "UPDATED",
                         DOCUMENT_CHANGE_DELETED: "DELETED"}
TARGET_CHANGE_NAMES = {TARGET_CHANGE_UPDATED: "UPDATED", TARGET_CHANGE_LISTED: "LISTED",
                       TARGET_CHANGE_DELETED: "DELETED", 4: "FAILED"}
NULL_VALUE = b"\x08\x00"  # common.Value{null_value: NULL_VALUE}
# Gamesync keeps a document per user session at docs/__us/<user session id>. Right after opening
# KeepUserSession the game watches its own and waits, with no timeout, until it is delivered
# ("Communicating"). The game reads uid, st, att, ltc, tn, ussid and ucsid but only writes att and
# tn, so the server creates the document.
GAMESYNC_USER_SESSION_DOCS = "docs/__us/"
# The game session's fixed document, which the game fetches once. It reads gsid, addr, p, mcn,
# maxu and rs (gsid, addr, mcn: string; p, maxu: integer; rs: bytes) and never writes it, so the
# server creates it. maxu is the session's maximum user count: it sizes the table the host assigns
# member slot indexes from, and the game writes bfmax = maxu - 1. gsid, addr and p are taken to be
# the GameSession id, host and port; mcn and rs are left out, their meaning is unknown.
GAMESYNC_GAME_SESSION_FIXED_DOC = "docs/__gs/f"
# The game session's mutable document, watched as target "SessionMutableData". The game reads cp,
# ip, pw, ebf, bfmin, bfmax and prp (cp, ip, ebf: boolean; pw: string; bfmin, bfmax: integer; prp:
# map). cp, ip, pw and prp look like GameSession can_participate, is_public, password and
# properties; ebf, bfmin and bfmax look like backfill settings. The game writes only ebf, bfmin,
# bfmax and prp.<key>, so the server creates it with cp, ip, pw and prp.
GAMESYNC_GAME_SESSION_MUTABLE_DOC = "docs/__gs/m"
# The P2P session layer keeps play group "All" under docs/__pgn/All. The game writes all of these
# documents itself once its targets are acknowledged, so the server must not create them:
#   __pgn/All/__pus/<user session id>: uid, ussid, ucsid, upcsid (max(global __upcsidn, 20000) + 1,
#     stored back into __upcsidn) and pgn.
#   __pgn/All/__stu/<user session id> (messages to one user session) and __stg/All (messages to
#     the whole group): sender suid, susid, sussid and suscid, plus pl (bytes) or mp (map).

# STUN (RFC 5389).
STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_XOR_MAPPED_ADDRESS = 0x0020
STUN_FINGERPRINT = 0x8028
STUN_FINGERPRINT_XOR = 0x5354554E
STUN_USERNAME = 0x0006
STUN_SOFTWARE = 0x8022
STUN_ATTRIBUTE_NAMES = {
    0x0001: "MAPPED-ADDRESS",
    0x0003: "CHANGE-REQUEST",
    STUN_USERNAME: "USERNAME",
    0x0008: "MESSAGE-INTEGRITY",
    STUN_XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    0x0024: "PRIORITY",
    0x0025: "USE-CANDIDATE",
    STUN_SOFTWARE: "SOFTWARE",
    STUN_FINGERPRINT: "FINGERPRINT",
    0x8029: "ICE-CONTROLLED",
    0x802A: "ICE-CONTROLLING",
}

# Session descriptions (SDP, RFC 8866) start with a version line; the game's start with "v=1".
SDP_START = re.compile(rb"v=\d+\r?\n")

# Island addresses use this alphabet in the game (e.g. "JW7MXKP2").
ALIAS_ALPHABET = "0123456789BCDFGHJKLMNPQRSTVWXY"
ALIAS_LENGTH = 8

ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
ID_PATTERN = re.compile(r"[a-z2-7]{20}")
CONTENT_RANGE = re.compile(r"bytes\s+(?:(\d+)-(\d+)|\*)/(\d+|\*)")
HTTP2_PREFACE_START = b"PRI "
GRPC_MESSAGE_SAFE = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) != "%")


class GrpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# --- Protobuf wire format ---------------------------------------------------------------------


def _varint(value: int) -> bytes:
    value &= (1 << 64) - 1
    out = bytearray()
    while value > 0x7F:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf) or shift > 63:
            raise ValueError("malformed varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, pos
        shift += 7


def encode(*fields: tuple[int, object]) -> bytes:
    """Encodes (field number, value) pairs; repeat a number for repeated fields.

    int/bool become varints, float a double and str UTF-8. bytes are written as-is, which is
    how already-encoded submessages are embedded. None values are omitted.
    """
    out = bytearray()
    for number, value in fields:
        if value is None:
            continue
        if isinstance(value, (bool, int)):
            out += _varint(number << 3) + _varint(int(value))
        elif isinstance(value, float):
            out += _varint(number << 3 | 1) + struct.pack("<d", value)
        else:
            data = value.encode() if isinstance(value, str) else bytes(value)
            out += _varint(number << 3 | 2) + _varint(len(data)) + data
    return bytes(out)


# The connection (H2Session) whose call the current task is handling, set by Server.handle_grpc
# and inherited by tasks the handler starts. Messages parsed meanwhile count against its request
# budgets (Msg). None elsewhere: at startup, in tests, in background tasks and while deferred
# Gamesync writes are applied (Backend.gamesync_fire_deferments).
request_budget: contextvars.ContextVar[H2Session | None] = contextvars.ContextVar("request_budget", default=None)


def message_cost(size: int, fields: int) -> int:
    """What a parsed message of `size` bytes and `fields` fields counts against request budgets."""
    return MSG_BASE_BYTES + size + MSG_FIELD_BYTES * fields


class Msg:
    """A message decoded without its schema: field number -> (wire type, value) in wire order.

    A message holds Python objects for each field, many times the bytes it came from, so one
    parsed while a call is handled (request_budget) counts message_cost against the connection's
    request budgets from the moment it is parsed until the last reference to it goes (__del__):
    while a handler, a paused generator or a nested call still holds it, and no longer once a
    cancelled or finished call has dropped it. A message that would not fit is refused while it
    is parsed, with RESOURCE_EXHAUSTED, and one of more than MAX_MESSAGE_FIELDS fields is
    malformed (ValueError)."""

    def __init__(self, buf: bytes = b""):
        self.fields: dict[int, list[tuple[int, int | bytes]]] = {}
        self.budget: H2Session | None = None  # what this message counts against, once parsed
        self.cost = 0
        budget = request_budget.get() if buf else None
        fitting = MAX_MESSAGE_FIELDS  # fields that fit the budget
        if budget is not None:
            fitting = (budget.request_room() - message_cost(len(buf), 0)) // MSG_FIELD_BYTES
            if fitting < 0:
                raise GrpcError(RESOURCE_EXHAUSTED, "too much request data in flight")
        count = 0
        pos = 0
        while pos < len(buf):
            count += 1
            if count > MAX_MESSAGE_FIELDS:
                raise ValueError(f"a message has more than {MAX_MESSAGE_FIELDS} fields")
            if count > fitting:
                raise GrpcError(RESOURCE_EXHAUSTED, "too much request data in flight")
            key, pos = _read_varint(buf, pos)
            number, wire = key >> 3, key & 7
            if number == 0:
                raise ValueError("field number 0")
            if wire == 0:
                value, pos = _read_varint(buf, pos)
            elif wire == 1:
                value, pos = int.from_bytes(buf[pos : pos + 8], "little"), pos + 8
            elif wire == 2:
                size, pos = _read_varint(buf, pos)
                value, pos = bytes(buf[pos : pos + size]), pos + size
            elif wire == 5:
                value, pos = int.from_bytes(buf[pos : pos + 4], "little"), pos + 4
            else:
                raise ValueError(f"unsupported wire type {wire}")
            if pos > len(buf):
                raise ValueError("truncated message")
            self.fields.setdefault(number, []).append((wire, value))
        if budget is not None:
            self.cost = message_cost(len(buf), count)
            budget.count(self.cost)
            self.budget = budget

    def __del__(self) -> None:
        if self.budget is not None:
            self.budget.uncount(self.cost)

    def _values(self, number: int, wire: int) -> list:
        return [value for w, value in self.fields.get(number, ()) if w == wire]

    def has(self, number: int) -> bool:
        return number in self.fields

    def get_int(self, number: int) -> int:
        values = self._values(number, 0)
        if not values:
            return 0
        value = values[-1]
        return value - (1 << 64) if value >= 1 << 63 else value

    def get_bool(self, number: int) -> bool:
        return self.get_int(number) != 0

    def get_fixed64(self, number: int) -> bytes | None:
        values = self._values(number, 1)
        return values[-1].to_bytes(8, "little") if values else None

    def get_fixed32(self, number: int) -> bytes | None:
        values = self._values(number, 5)
        return values[-1].to_bytes(4, "little") if values else None

    def get_bytes(self, number: int) -> bytes | None:
        values = self._values(number, 2)
        return values[-1] if values else None

    def get_str(self, number: int) -> str:
        value = self.get_bytes(number)
        return value.decode("utf-8", "replace") if value is not None else ""

    def get_msg(self, number: int) -> Msg | None:
        value = self.get_bytes(number)
        return Msg(value) if value is not None else None

    def get_raws(self, number: int) -> list[bytes]:
        return self._values(number, 2)

    def get_strs(self, number: int) -> list[str]:
        return [value.decode("utf-8", "replace") for value in self._values(number, 2)]

    def get_msgs(self, number: int) -> list[Msg]:
        return [Msg(value) for value in self._values(number, 2)]


def replace_field(msg: Msg, number: int, value: object) -> bytes:
    """Re-encodes a message with field `number` set to `value`, keeping every other field."""
    out = bytearray(encode((number, value)))
    for field, values in msg.fields.items():
        if field == number:
            continue
        for wire, item in values:
            out += _varint(field << 3 | wire)
            if wire == 0:
                out += _varint(item)
            elif wire == 2:
                out += _varint(len(item)) + item
            else:
                out += item.to_bytes(8 if wire == 1 else 4, "little")
    return bytes(out)


def _printable(value: bytes) -> str | None:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def dump(buf: bytes, depth: int = 0) -> str:
    """Renders a payload as an indented field tree for logs. What it parses counts against the
    request budgets like any message (Msg), a message for as long as its nested fields are being
    rendered; a payload or field that does not parse or would not fit is shown as bytes instead,
    so logging never changes how a call is answered."""
    lines: list[str] = []
    try:
        _dump_into(buf, depth, lines)
    except (ValueError, GrpcError):
        return f"{'  ' * depth}<{len(buf)} bytes> {buf[:64].hex()}"
    return "\n".join(lines) if lines else f"{'  ' * depth}<empty>"


def _dump_into(buf: bytes, depth: int, lines: list[str]) -> None:
    pad = "  " * depth
    message = Msg(buf)  # held, so the nested fields parsed below count on top of it
    for number, values in message.fields.items():
        for wire, value in values:
            if wire != 2:
                lines.append(f"{pad}{number}: {value}")
                continue
            text = _printable(value)
            if text is not None:
                lines.append(f"{pad}{number}: {text!r}")
                continue
            nested: list[str] = []
            try:
                if depth >= 16:
                    raise ValueError("too deep")
                _dump_into(value, depth + 1, nested)
            except (ValueError, GrpcError):
                lines.append(f"{pad}{number}: <{len(value)} bytes> {value[:64].hex()}")
                continue
            lines += [f"{pad}{number} {{", *nested, f"{pad}}}"]


def timestamp(ns: int) -> bytes:
    return encode((1, ns // 1_000_000_000), (2, ns % 1_000_000_000 or None))


def timestamp_ns(msg: Msg) -> int:
    return msg.get_int(1) * 1_000_000_000 + msg.get_int(2)


def duration(seconds: int) -> bytes:
    return encode((1, seconds))


# --- Common/value.proto MapValue fields ---------------------------------------------------------


def map_entries(data: bytes | None) -> dict[str, bytes]:
    """Decodes a MapValue into key -> encoded Value."""
    return {entry.get_str(1): entry.get_bytes(2) or b"" for entry in Msg(data or b"").get_msgs(1)}


def encode_map(entries: dict[str, bytes]) -> bytes:
    return encode(*[(1, encode((1, key), (2, value))) for key, value in entries.items()])


def split_field_path(path: str) -> list[str]:
    """Splits a dotted field path, honoring `quoted` segments."""
    parts: list[str] = []
    current = ""
    quoted = False
    i = 0
    while i < len(path):
        char = path[i]
        if char == "\\" and quoted and i + 1 < len(path):
            current += path[i + 1]
            i += 1
        elif char == "`":
            quoted = not quoted
        elif char == "." and not quoted:
            parts.append(current)
            current = ""
        else:
            current += char
        i += 1
    parts.append(current)
    return parts


def get_field(entries: dict[str, bytes], parts: list[str]) -> bytes | None:
    value = entries.get(parts[0])
    if len(parts) == 1 or value is None:
        return value
    nested = Msg(value).get_bytes(10)  # Value.map_value
    return None if nested is None else get_field(map_entries(nested), parts[1:])


def set_field(entries: dict[str, bytes], parts: list[str], value: bytes | None) -> dict[str, bytes]:
    """Returns a copy of `entries` with the field set, or deleted when `value` is None."""
    entries = dict(entries)
    if len(parts) == 1:
        if value is None:
            entries.pop(parts[0], None)
        else:
            entries[parts[0]] = value
        return entries
    current = entries.get(parts[0])
    nested = map_entries(Msg(current).get_bytes(10)) if current is not None else {}
    entries[parts[0]] = encode((10, encode_map(set_field(nested, parts[1:], value))))
    return entries


def merge_entries(entries: dict[str, bytes], incoming: dict[str, bytes]) -> dict[str, bytes]:
    """Merges `incoming` into `entries`, recursing into fields that are maps on both sides."""
    merged = dict(entries)
    for key, value in incoming.items():
        current = merged.get(key)
        nested = Msg(value).get_bytes(10)  # Value.map_value
        current_nested = Msg(current).get_bytes(10) if current is not None else None
        if nested is not None and current_nested is not None:
            value = encode((10, encode_map(merge_entries(map_entries(current_nested), map_entries(nested)))))
        merged[key] = value
    return merged


def _number(value: bytes | None) -> int | float | None:
    if value is None:
        return None
    msg = Msg(value)
    if msg.has(3):
        return msg.get_int(3)
    if (raw := msg.get_fixed64(5)) is not None:
        return struct.unpack("<d", raw)[0]
    if (raw := msg.get_fixed32(4)) is not None:
        return struct.unpack("<f", raw)[0]
    return None


def apply_transform(entries: dict[str, bytes], path: str, kind: str, operand: bytes | None,
                    now: int) -> tuple[dict[str, bytes], bytes]:
    """Applies a ugcstore FieldTransform and returns the new entries and the resulting Value."""
    parts = split_field_path(path)
    current = get_field(entries, parts)
    if kind == "request_time":
        result = encode((6, timestamp(now)))
    else:
        a, b = _number(current), _number(operand)
        if a is None or b is None:
            result = operand or b""
        elif kind == "increment":
            total = a + b
            result = encode((3, total)) if isinstance(total, int) else encode((5, float(total)))
        elif kind == "maximum":
            result = current if a >= b else operand
        else:
            result = current if a <= b else operand
    return set_field(entries, parts, result), result


def gamesync_transform(entries: dict[str, bytes], transform: Msg, globals_: dict[str, bytes],
                       now: int) -> tuple[dict[str, bytes], bytes]:
    """Applies a gamesync FieldTransform and returns the new entries and the resulting Value."""
    path = transform.get_str(1)
    if transform.has(2):  # set_server_value: REQUEST_TIME
        return apply_transform(entries, path, "request_time", None, now)
    for number, kind in ((3, "increment"), (4, "maximum"), (5, "minimum")):
        if transform.has(number):
            return apply_transform(entries, path, kind, transform.get_bytes(number), now)
    parts = split_field_path(path)
    if transform.has(6):  # load_global_value: copies a global value into the field
        value = globals_.get(transform.get_str(6), NULL_VALUE)
        return set_field(entries, parts, value), value
    if transform.has(7):  # store_global_value: copies the field into a global value
        value = get_field(entries, parts) or NULL_VALUE
        globals_[transform.get_str(7)] = value
        return entries, value
    if transform.has(8):  # clear_global_value
        return entries, globals_.pop(transform.get_str(8), NULL_VALUE)
    raise GrpcError(INVALID_ARGUMENT, f"empty transform for {path}")


# --- Tokens and ids ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def unverified_jwt_claims(token: str) -> dict | None:
    try:
        claims = json.loads(_unb64url(token.split(".")[1]))
    except (IndexError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


class TokenSigner:
    """Issues HS256 JWTs, matching the shape of the real service's tokens."""

    def __init__(self, secret: bytes):
        self.secret = secret

    def _sign(self, signing_input: str) -> str:
        return _b64url(hmac.new(self.secret, signing_input.encode(), hashlib.sha256).digest())

    def issue(self, **claims) -> str:
        header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
        payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
        return f"{header}.{payload}.{self._sign(f'{header}.{payload}')}"

    def verify(self, token: str, typ: str) -> dict | None:
        parts = token.split(".")
        if len(parts) != 3 or not hmac.compare_digest(self._sign(f"{parts[0]}.{parts[1]}"), parts[2]):
            return None
        claims = unverified_jwt_claims(token)
        if claims is None or claims.get("typ") != typ or claims.get("exp", 1 << 62) < time.time():
            return None
        return claims


def random_id() -> str:
    return "".join(secrets.choice(ID_ALPHABET) for _ in range(20))


def derived_id(*parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).digest()
    return base64.b32encode(digest).decode().lower()[:20]


def document_owner(name: str) -> str | None:
    """The user a Ugcstore document belongs to: tenants/<t>/users/<u> for
    tenants/<t>/documents/users/<u>/(public|private)/<name>, else None."""
    match = USER_DOCUMENT.fullmatch(name)
    return f"{match[1]}/users/{match[2]}" if match else None


def check_name(name: str) -> None:
    """Refuses a name over MAX_NAME_BYTES: names are kept in state.json or in memory, so their
    length must be bounded like everything else a client stores."""
    if len(name.encode()) > MAX_NAME_BYTES:
        raise GrpcError(INVALID_ARGUMENT, f"a name of {len(name.encode())} bytes is over the limit")


# --- Device accounts (client-certificate mode) -------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """The portal account, and its linked device, behind a client-certificate connection."""

    account: str
    device: str


class AuthRegistry:
    """Read-only view of the account database that portal.py writes (--auth-db).

    A device certificate counts while its devices row is neither revoked nor expired and its account
    is not disabled. The TLS handshake has already checked that the device CA (--client-ca) issued
    it; the database decides whose it is. Answers are cached for CACHE_SECONDS, which is how long a
    revocation takes to reach open connections (Server.watch_device).
    """

    CACHE_SECONDS = 30

    def __init__(self, path: Path):
        self.path = path
        self.db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=1)
        self.cache: dict[str, tuple[float, Principal | None]] = {}

    def principal(self, cert: bytes | None) -> Principal | None:
        """The account and device of a DER client certificate, or None if it does not count."""
        if not cert:
            return None
        fingerprint = hashlib.sha256(cert).hexdigest()
        now = time.monotonic()
        cached = self.cache.get(fingerprint)
        if cached is not None and cached[0] > now:
            return cached[1]
        try:
            row = self.db.execute(
                "SELECT devices.id, devices.account_id FROM devices "
                "JOIN accounts ON accounts.id = devices.account_id "
                "WHERE devices.cert_sha256 = ? AND devices.revoked_at IS NULL AND devices.expires_at > ? "
                "AND accounts.disabled_at IS NULL", (fingerprint, int(time.time()))).fetchone()
        except sqlite3.Error as exc:
            # The portal can hold the write lock for a moment; keep the last answer until then.
            log.warning("account database unavailable: %s", exc)
            return cached[1] if cached is not None else None
        principal = Principal(row[1], row[0]) if row else None
        self.cache[fingerprint] = (now + self.CACHE_SECONDS, principal)
        return principal

    def deleted_accounts(self) -> set[str] | None:
        """Accounts an operator deleted with `portal.py delete`, whose game data the server purges
        (Backend.purge_account); None while the database cannot be read."""
        try:
            return {row[0] for row in self.db.execute("SELECT id FROM deleted_accounts")}
        except sqlite3.Error as exc:
            log.warning("account database unavailable: %s", exc)
            return None


def network_of(peer: object) -> str:
    """The network a peer address belongs to for rate limits: an IPv4 address, or an IPv6 /64."""
    host = peer[0] if isinstance(peer, tuple) and peer else ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return str(host)
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


def password_version(password: str) -> str:
    """Identifies a password without keeping it, so that grants and trust end when it changes."""
    return hashlib.sha256(b"password\0" + password.encode()).hexdigest()


class GuessLimiter:
    """Counts wrong island and session passwords per account, per network and per target, within
    the GUESS_LIMITS windows, and remembers which accounts recently gave a target's password, and
    which version of it."""

    def __init__(self) -> None:
        self.failures: dict[tuple[str, str], list[float]] = {}  # (kind, key) -> monotonic times
        # (account, target) -> (monotonic time of the last success, password_version)
        self.trusted: dict[tuple[str, str], tuple[float, str]] = {}

    def recent(self, kind: str, key: str, now: float) -> list[float]:
        window = GUESS_LIMITS[kind][1]
        times = [moment for moment in self.failures.get((kind, key), []) if moment > now - window]
        if times:
            self.failures[(kind, key)] = times
        else:
            self.failures.pop((kind, key), None)
        return times

    def buckets(self, call: Call, target: str, version: str) -> list[tuple[str, str]]:
        """The counts a guess by this call at `target` goes against: always the account's and the
        network's, and the target's unless the account gave its current password recently."""
        buckets = [("account", call.principal.account), ("network", call.network)]
        trusted = self.trusted.get((call.principal.account, target))
        if trusted is None or trusted[1] != version or trusted[0] <= time.monotonic() - GUESS_TRUST_SECONDS:
            buckets.append(("target", target))
        return buckets

    def check(self, call: Call, target: str, version: str) -> None:
        now = time.monotonic()
        for kind, key in self.buckets(call, target, version):
            if len(self.recent(kind, key, now)) >= GUESS_LIMITS[kind][0]:
                raise GrpcError(RESOURCE_EXHAUSTED, "too many wrong passwords; try again later")

    def failed(self, call: Call, target: str, version: str) -> None:
        now = time.monotonic()
        if len(self.failures) > 100000:
            for kind, key in list(self.failures):
                self.recent(kind, key, now)
        for bucket in self.buckets(call, target, version):
            self.failures.setdefault(bucket, []).append(now)

    def succeeded(self, call: Call, target: str, version: str) -> None:
        now = time.monotonic()
        if len(self.trusted) > 100000:
            self.trusted = {key: value for key, value in self.trusted.items()
                            if value[0] > now - GUESS_TRUST_SECONDS}
        self.trusted[(call.principal.account, target)] = (now, version)

    def forget(self, account: str) -> None:
        self.failures.pop(("account", account), None)
        self.trusted = {key: value for key, value in self.trusted.items() if key[0] != account}


# --- Persistent state -------------------------------------------------------------------------


# errno values that mean a filesystem does not offer a kind of flush, as opposed to a flush that
# failed (EIO and the like), which is always raised.
UNSUPPORTED_SYNC_ERRNOS = frozenset(getattr(errno, name) for name in ("EINVAL", "ENOTSUP", "EOPNOTSUPP", "ENOTTY")
                                    if hasattr(errno, name))
MOVEFILE_REPLACE_EXISTING = 0x1
MOVEFILE_WRITE_THROUGH = 0x8
if os.name == "nt":
    _move_file_ex = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    _move_file_ex.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    _move_file_ex.restype = ctypes.c_int
_sync_warnings: set[str] = set()


def warn_once(key: str, message: str, *args: object) -> None:
    if key not in _sync_warnings:
        _sync_warnings.add(key)
        log.warning(message, *args)


def sync_fd(fd: int) -> bool:
    """Flushes a file to stable storage and returns whether the platform promises it is there:
    fsync on Linux and other POSIX systems, FlushFileBuffers (os.fsync) on Windows, F_FULLFSYNC on
    macOS, whose plain fsync can leave data in the drive's cache. On a macOS filesystem without
    F_FULLFSYNC only fsync is left, and this returns False. A failed flush (EIO, ...) is raised.
    Drives that ignore flush requests can lose data regardless."""
    if sys.platform == "darwin" and fcntl is not None and hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return True
        except OSError as exc:
            if exc.errno not in UNSUPPORTED_SYNC_ERRNOS:
                raise
            warn_once("F_FULLFSYNC", "this filesystem has no F_FULLFSYNC (%s); writes are not crash-safe", exc)
        os.fsync(fd)
        return False
    os.fsync(fd)
    return True


def sync_directory(path: Path) -> bool:
    """Flushes the files created, renamed or removed in a directory (POSIX) and returns whether
    that is durable. A filesystem that cannot sync directories gets a warning, once, and False;
    a failed sync is raised."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        return sync_fd(fd)
    except OSError as exc:
        if exc.errno not in UNSUPPORTED_SYNC_ERRNOS:
            raise
        warn_once(f"directory {path}", "%s cannot be synced (%s); renames there are not crash-safe", path, exc)
        return False
    finally:
        os.close(fd)


def publish(temp: Path, path: Path) -> bool:
    """Renames `temp` over `path` atomically and returns whether the rename is durable by the time
    this returns. POSIX: rename, then sync the directory. Windows cannot open a directory for that;
    there the rename is MoveFileExW with MOVEFILE_WRITE_THROUGH, which Microsoft documents as not
    returning "until the file is actually moved on the disk"."""
    if os.name == "nt":
        if not _move_file_ex(str(temp), str(path), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH):
            raise ctypes.WinError(ctypes.get_last_error())
        return True
    os.replace(temp, path)
    return sync_directory(path.parent)


def write_durably(path: Path, data: bytes) -> bool:
    """Replaces `path` with `data` atomically: a crash leaves the old file or the new one, whole.
    The new contents are flushed (sync_fd) before the rename publishes them, and the rename before
    this returns (publish). Returns whether the platform promised both. An error before the rename
    leaves `path` as it was; an error after it (a failed directory sync) means `path` may already
    hold `data`, durably or not."""
    temp = path.with_suffix(".tmp")
    with open(temp, "wb") as file:
        file.write(data)
        file.flush()
        synced = sync_fd(file.fileno())
    return publish(temp, path) and synced


class Store:
    """Users, documents, short aliases and upload sessions in state.json; blobs as files."""

    def __init__(self, root: Path):
        self.blob_dir = root / "blobs"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            # The data is secret: owner-only directories, and older files made owner-only too. New
            # files are owner-only through the umask that main() sets.
            for path in (root, self.blob_dir, *self.blob_dir.iterdir(), *root.glob("state.*")):
                try:
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except PermissionError as exc:
                    raise SystemExit(f"cannot make {path} private ({exc}); the data directory must "
                                     "belong to the server's user") from None
        self.path = root / "state.json"
        self.durable = False  # whether the platform promised that the last save is on disk (save)
        state = json.loads(self.path.read_text("utf-8")) if self.path.exists() else {}
        self.secret = bytes.fromhex(state.get("secret") or secrets.token_hex(32))
        self.users: dict[str, dict] = state.get("users", {})
        self.documents: dict[str, dict] = state.get("documents", {})
        self.aliases: dict[str, dict] = state.get("aliases", {})
        self.uploads: dict[str, dict] = state.get("uploads", {})
        for upload_id, upload in self.uploads.items():
            upload.setdefault("blob", upload_id)
        self.save()

    def state_json(self) -> str:
        state = {
            "secret": self.secret.hex(),
            "users": self.users,
            "documents": self.documents,
            "aliases": self.aliases,
            "uploads": self.uploads,
        }
        return json.dumps(state, indent=1)

    def save(self) -> None:
        """Writes state.json (write_durably). Callers delete blob files only after this returns, and
        only if the platform promised the new state is on disk (release_blob), so stored state never
        refers to a deleted file, even after a power loss."""
        self.durable = False
        self.durable = write_durably(self.path, self.state_json().encode("utf-8"))

    def blob_path(self, blob_id: str) -> Path:
        return self.blob_dir / blob_id

    def release_blob(self, blob_id: str) -> None:
        """Deletes a blob that no document attachment or upload session refers to anymore. Callers
        save the state first. Where that save is not known to be durable (a filesystem without
        directory or full syncs), the file is kept: after a power loss the previous state, which may
        still refer to it, can come back. Kept files, and a file Windows refuses to delete while a
        download still has it open, are unreferenced orphans, as after a crash."""
        if any(upload["blob"] == blob_id for upload in self.uploads.values()):
            return
        for doc in self.documents.values():
            if (doc.get("attachment") or {}).get("blob") == blob_id:
                return
        if not self.durable:
            warn_once("keep blobs", "keeping unreferenced blob files: the state cannot be saved durably here")
            return
        try:
            self.blob_path(blob_id).unlink(missing_ok=True)
        except PermissionError as exc:
            log.warning("could not delete unreferenced blob %s: %s", blob_id, exc)

    def write_blob(self, blob_id: str, data: bytes) -> None:
        """Writes a whole blob as a new file. A blob file is never rewritten in place, because a
        snapshot being served keeps the old file open and must go on reading what it captured. The
        file is flushed (write_durably) before any state that refers to it is saved. If this raises,
        the blob may already have been replaced (see write_durably): callers keep their state valid
        for either file (Storage.upload)."""
        write_durably(self.blob_path(blob_id), data)

    def snapshot(self) -> tuple[bytes, list[tuple[str, int, int]], list[str]]:
        """Captures state.json and every blob it refers to, as they are now (Linux only).

        Only the event loop thread changes the store, and this runs on it without awaiting, so the
        state and the blobs come from one moment. The blobs are held open, not copied. No blob file
        is changed in place below its captured size: write_blob writes whole blobs as new files,
        and an unfinished upload only writes or truncates past what it has received, a count that
        never goes down while the same file stays in place. Each descriptor therefore keeps reading
        the captured bytes after its blob is replaced or deleted.
        Returns the state, (blob id, descriptor, size) per blob, and a description of every
        referenced blob whose file is missing or has a size the state doesn't record for it. The
        caller closes the descriptors.
        """
        state = self.state_json().encode()
        recorded: dict[str, set[int]] = {}  # the sizes the state records for each blob
        upload_sizes = {upload["blob"]: upload["received"] for upload in self.uploads.values()}
        for blob_id, received in upload_sizes.items():
            recorded.setdefault(blob_id, set()).add(received)
        for doc in self.documents.values():
            if attachment := doc.get("attachment"):
                recorded.setdefault(attachment["blob"], set()).add(attachment["size"])
        fds: dict[str, int] = {}
        damaged = []
        try:
            for blob_id in sorted(recorded):
                try:
                    fds[blob_id] = os.open(self.blob_path(blob_id), os.O_RDONLY)
                except FileNotFoundError:
                    damaged.append(f"{blob_id} is missing")
            blobs = []
            for blob_id, fd in fds.items():
                actual = size = os.fstat(fd).st_size
                if blob_id in upload_sizes:
                    # An upload may hold more than it has received if the server stopped before it
                    # saved, and it rewrites those bytes when the upload goes on.
                    size = min(size, upload_sizes[blob_id])
                if recorded[blob_id] != {size}:
                    damaged.append(f"{blob_id} has {actual} bytes, but the state records {sorted(recorded[blob_id])}")
                blobs.append((blob_id, fd, size))
        except BaseException:
            for fd in fds.values():
                os.close(fd)
            raise
        return state, blobs, damaged


def doc_entries(doc: dict | None) -> dict[str, bytes]:
    return map_entries(base64.b64decode(doc["fields"])) if doc else {}


_KEEP = object()


def updated_document(doc: dict | None, now: int, entries: dict[str, bytes] | None = None,
                     attachment: object = _KEEP) -> dict:
    result = dict(doc) if doc else {"fields": "", "create_time": now, "attachment": None}
    if entries is not None:
        result["fields"] = base64.b64encode(encode_map(entries)).decode()
    if attachment is not _KEEP:
        result["attachment"] = attachment
    result["update_time"] = now
    return result


def masked_entries(doc: dict | None, incoming: dict[str, bytes], mask: Msg | None) -> dict[str, bytes]:
    """The fields after an update: `incoming` replaces all of them, or only the masked paths.

    A missing or empty mask, or one holding the `*` wildcard, replaces every field.
    """
    if mask is None:
        return incoming
    paths = mask.get_strs(1)
    if not paths or "*" in paths:
        return incoming
    entries = doc_entries(doc)
    for path in paths:
        parts = split_field_path(path)
        entries = set_field(entries, parts, get_field(incoming, parts))
    return entries


def encode_document(name: str, doc: dict, mask: Msg | None = None) -> bytes:
    """Encodes a Document; a read mask (FieldMask) limits it to the listed field paths.

    An empty mask, or one holding the `*` wildcard, returns every field.
    """
    fields = base64.b64decode(doc["fields"])
    paths = mask.get_strs(1) if mask is not None else []
    if paths and "*" not in paths:
        entries = map_entries(fields)
        masked: dict[str, bytes] = {}
        for path in paths:
            parts = split_field_path(path)
            value = get_field(entries, parts)
            if value is not None:
                masked = set_field(masked, parts, value)
        fields = encode_map(masked)
    return encode(
        (1, name),
        (2, fields),
        (3, timestamp(doc["create_time"])),
        (4, timestamp(doc["update_time"])),
    )


def check_precondition(name: str, doc: dict | None, precondition: Msg | None) -> None:
    if precondition is None:
        return
    if precondition.has(1):
        if precondition.get_bool(1) and doc is None:
            raise GrpcError(NOT_FOUND, f"{name} does not exist")
        if not precondition.get_bool(1) and doc is not None:
            raise GrpcError(ALREADY_EXISTS, f"{name} already exists")
    update_time = precondition.get_msg(2)
    if update_time is not None and (doc is None or doc["update_time"] != timestamp_ns(update_time)):
        raise GrpcError(FAILED_PRECONDITION, f"{name} was modified")


class Staging:
    """Uncommitted document changes of one commit."""

    def __init__(self, documents: dict[str, dict]):
        self.documents = documents
        self.changes: dict[str, dict | None] = {}
        self.imported_uploads: list[str] = []
        self.new_blobs: list[str] = []

    def get(self, name: str) -> dict | None:
        return self.changes[name] if name in self.changes else self.documents.get(name)

    def put(self, name: str, doc: dict | None) -> None:
        self.changes[name] = doc


# --- Island storage (REST) --------------------------------------------------------------------


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    # A body read from an open blob file instead: (file, offset, length). Whoever sends the
    # response closes the file.
    stream: tuple[BinaryIO, int, int] | None = None


def response(status: int, body: bytes = b"", content_type: str = "text/plain",
             headers: list[tuple[str, str]] | None = None) -> Response:
    return Response(
        status,
        [("content-type", content_type), ("content-length", str(len(body))), *(headers or [])],
        body,
    )


def document_state_bytes(name: str, doc: dict | None) -> int:
    """What a Ugcstore document adds to state.json (its attachment bytes are a blob)."""
    if doc is None:
        return 0
    return (len(name) + len(doc["fields"]) + len((doc.get("attachment") or {}).get("mime_type", ""))
            + STATE_OVERHEAD_BYTES)


def alias_state_bytes(code: str, entry: dict) -> int:
    return len(code) + len(entry["name"]) + len(entry["document"]) + len(entry["scope"] or "") + STATE_OVERHEAD_BYTES


def user_state_bytes(name: str, account: str) -> int:
    return len(name) + len(account) + STATE_OVERHEAD_BYTES


def parse_range(header: str, size: int) -> tuple[int, int] | None:
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", header.strip())
    if match is None or not (match[1] or match[2]):
        return None
    if match[1]:
        start = int(match[1])
        end = min(int(match[2]), size - 1) if match[2] else size - 1
    else:
        start, end = max(size - int(match[2]), 0), size - 1
    return (start, end) if start <= end else None


class Storage:
    def __init__(self, store: Store, base_url: str):
        self.store = store
        self.base_url = base_url
        self.max_bytes = DEFAULT_MAX_STORAGE_BYTES  # every document, attachment and upload together

    def usage(self, account: str | None = None) -> tuple[int, int]:
        """(state bytes, blob bytes) of `account`, or of everyone when it is None. State bytes are
        what its users, their documents and short aliases, and its upload sessions add to
        state.json (names, fields and per-record overhead); blob bytes are attachments and uploads."""
        users = {name: user for name, user in self.store.users.items()
                 if account is None or user.get("owner") == account}
        state = sum(user_state_bytes(name, user["account"]) for name, user in users.items())
        blobs = 0
        for name, doc in self.store.documents.items():
            if account is None or document_owner(name) in users:
                state += document_state_bytes(name, doc)
                blobs += (doc.get("attachment") or {}).get("size", 0)
        for code, entry in self.store.aliases.items():
            if account is None or document_owner(entry["document"]) in users:
                state += alias_state_bytes(code, entry)
        for upload in self.store.uploads.values():
            if account is None or upload.get("owner") == account:
                state += STATE_OVERHEAD_BYTES
                blobs += upload["received"]
        return state, blobs

    def room_for(self, account: str | None, state: int, blobs: int) -> str | None:
        """Why storing `state` more state bytes and `blobs` more attachment or upload bytes would
        break a limit: the quotas of `account` (client-certificate mode), --max-storage-mb, or the
        disk's MIN_FREE_DISK_BYTES. None if it fits; shrinking always fits."""
        growth = max(state, 0) + max(blobs, 0)
        if growth == 0:
            return None
        if account is not None:
            used_state, used_blobs = self.usage(account)
            if state > 0 and used_state + state > ACCOUNT_STATE_BYTES:
                return "the account's document quota is full"
            if blobs > 0 and used_blobs + blobs > ACCOUNT_BLOB_BYTES:
                return "the account's storage quota is full"
        if sum(self.usage()) + growth > self.max_bytes:
            return "the server's storage is full"
        if shutil.disk_usage(self.store.blob_dir).free - growth < MIN_FREE_DISK_BYTES:
            return "the server's disk is nearly full"
        return None

    def upload_uri(self, upload_id: str) -> str:
        return f"{self.base_url}/upload/{upload_id}"

    def download_uri(self, blob_id: str) -> str:
        return f"{self.base_url}/download/{blob_id}"

    def new_upload(self, owner: str | None = None) -> str:
        """A new upload session; in client-certificate mode it belongs to the account `owner`."""
        stale_uploads = []
        if owner is not None:
            # Upload sessions the game abandons are never imported. An account keeps at most
            # MAX_UPLOADS_PER_ACCOUNT of them; the oldest go first.
            owned = sorted((upload["create_time"], upload_id) for upload_id, upload in self.store.uploads.items()
                           if upload.get("owner") == owner)
            for _, stale in owned[: max(0, len(owned) - MAX_UPLOADS_PER_ACCOUNT + 1)]:
                stale_uploads.append(self.store.uploads.pop(stale)["blob"])
        upload_id = random_id()
        self.store.write_blob(upload_id, b"")
        self.store.uploads[upload_id] = {
            "blob": upload_id,
            "received": 0,
            "total": None,
            "complete": False,
            "create_time": time.time_ns(),
        }
        if owner is not None:
            self.store.uploads[upload_id]["owner"] = owner
        self.store.save()
        # Files go only once the saved state no longer refers to them (Store.release_blob).
        for stale in stale_uploads:
            self.store.release_blob(stale)
        return upload_id

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes,
               principal: Principal | None = None) -> Response:
        """Serves one storage request. In client-certificate mode `principal` is the account behind
        the connection: only the account that asked for an upload URI may use it, and attachments
        only download for the account that owns their document (see may_download)."""
        parts = urlsplit(target).path.strip("/").split("/")
        if len(parts) == 2 and ID_PATTERN.fullmatch(parts[1]):
            kind, resource = parts
            if kind == "upload" and method in ("PUT", "POST"):
                result = self.upload(resource, headers, body, principal)
            elif kind == "download" and method in ("GET", "HEAD"):
                result = self.download(resource, headers, principal)
            else:
                result = response(405, b"method not allowed\n")
        else:
            result = response(404, b"not found\n")
        log.info("storage %s %s (%d bytes, range=%s) -> %d", method, target, len(body),
                 headers.get("content-range") or headers.get("range") or "-", result.status)
        return result

    def upload(self, upload_id: str, headers: dict[str, str], body: bytes,
               principal: Principal | None = None) -> Response:
        upload = self.store.uploads.get(upload_id)
        if upload is None or (principal is not None and upload.get("owner") != principal.account):
            return response(404, b"upload session not found\n")
        if headers.get("x-goog-resumable", "").lower() == "start":
            return response(201, headers=[("location", self.upload_uri(upload_id))])
        if upload["complete"]:
            return self.upload_finished(upload_id, upload)

        content_range = headers.get("content-range")
        if content_range is None:
            if (refused := self.refuse_upload(upload_id, upload, len(body))) is not None:
                return refused
            # Publish a new backing file before changing the session. The old file and its
            # acknowledged progress remain intact through an interrupted replacement.
            replacement = random_id()
            while self.store.blob_path(replacement).exists():
                replacement = random_id()
            if not write_durably(self.store.blob_path(replacement), body):
                raise OSError("cannot durably publish replacement upload")
            self.store.uploads[upload_id] = {
                **upload, "blob": replacement, "received": len(body), "total": len(body), "complete": True,
            }
            try:
                self.store.save()
            except BaseException:
                # A failed directory sync may have published the new state. Keep both files.
                self.store.uploads[upload_id] = upload
                raise
            self.store.release_blob(upload["blob"])
            return self.upload_finished(upload_id, self.store.uploads[upload_id])
        else:
            match = CONTENT_RANGE.fullmatch(content_range.strip())
            if match is None:
                return response(400, b"malformed content-range\n")
            first, last, total = match.groups()
            if total != "*":
                if int(total) > MAX_UPLOAD_BYTES:
                    return self.discard_upload(upload_id, 413, "the upload is too large")
                upload["total"] = int(total)
            if first is not None:
                first, last = int(first), int(last)
                if last < first or len(body) != last - first + 1:
                    return response(400, b"content-range does not match the body\n")
                received = upload["received"]
                # A chunk past the stored data is dropped; the 308 tells the client where to resume.
                if first <= received:
                    if (refused := self.refuse_upload(upload_id, upload, max(received, last + 1))) is not None:
                        return refused
                    try:
                        blob = self.store.blob_path(upload["blob"]).open("r+b")
                    except FileNotFoundError:
                        return self.discard_upload(upload_id, 410, "the upload's data is missing; start again")
                    with blob:
                        size = os.fstat(blob.fileno()).st_size
                        if size >= received:
                            # Bytes past the count are left from a write whose state was never
                            # saved; they go, so the file ends where the count does.
                            blob.truncate(received)
                            blob.seek(received)
                            blob.write(body[received - first :])
                            # The bytes reach storage before the state that counts them is saved.
                            blob.flush()
                            sync_fd(blob.fileno())
                    if size < received:
                        # Closed first: Windows cannot delete an open file.
                        return self.discard_upload(upload_id, 410, "the upload's data is shorter than received; "
                                                                   "start again")
                    upload["received"] = max(received, last + 1)

        if upload["total"] is not None and upload["received"] >= upload["total"]:
            upload["complete"] = True
        self.store.save()
        if upload["complete"]:
            return self.upload_finished(upload_id, upload)
        received = upload["received"]
        return response(308, headers=[("range", f"bytes=0-{received - 1}")] if received else [])

    def refuse_upload(self, upload_id: str, upload: dict, size: int) -> Response | None:
        """None if the upload may grow to `size` bytes. Otherwise the upload can never complete, so
        it is discarded and the error response returned."""
        if size > MAX_UPLOAD_BYTES:
            return self.discard_upload(upload_id, 413, "the upload is too large")
        problem = self.room_for(upload.get("owner"), 0, size - upload["received"])
        return None if problem is None else self.discard_upload(upload_id, 507, problem)

    def discard_upload(self, upload_id: str, status: int, reason: str) -> Response:
        blob_id = self.store.uploads.pop(upload_id)["blob"]
        self.store.save()
        self.store.release_blob(blob_id)
        log.warning("discarded upload %s: %s", upload_id, reason)
        return response(status, f"{reason}\n".encode())

    @staticmethod
    def upload_finished(upload_id: str, upload: dict) -> Response:
        size = upload["received"]
        body = json.dumps({"kind": "storage#object", "name": upload_id, "size": str(size)}).encode()
        return response(200, body, "application/json",
                        [("x-goog-stored-content-length", str(size)), ("etag", f'"{upload_id}"')])

    def may_download(self, blob_id: str, principal: Principal | None) -> bool:
        """Whether `principal` may download a blob: always in local mode; in client-certificate
        mode only its own upload sessions and the attachments of documents its users own."""
        if principal is None:
            return True
        upload = self.store.uploads.get(blob_id)
        if upload is not None:
            return upload.get("owner") == principal.account
        for name, doc in self.store.documents.items():
            if (doc.get("attachment") or {}).get("blob") == blob_id:
                user = self.store.users.get(document_owner(name) or "")
                return user is not None and user.get("owner") == principal.account
        return False

    def download(self, blob_id: str, headers: dict[str, str], principal: Principal | None = None) -> Response:
        """A download: the blob is opened now and sent in DOWNLOAD_CHUNK_BYTES pieces from that open
        file (Response.stream), so a download holds one piece in memory, and a blob replaced
        meanwhile (write_blob writes a new file) does not change what it sends."""
        if not self.may_download(blob_id, principal):
            return response(404, b"no such object\n")
        upload = self.store.uploads.get(blob_id)
        if upload is not None and not upload["complete"]:
            return response(404, b"no such object\n")
        try:
            file = self.store.blob_path(upload["blob"] if upload is not None else blob_id).open("rb")
        except OSError:
            return response(404, b"no such object\n")
        size = os.fstat(file.fileno()).st_size
        headers_out = [("content-type", "application/octet-stream"), ("accept-ranges", "bytes"),
                       ("x-goog-stored-content-length", str(size))]
        range_header = headers.get("range")
        if range_header is None:
            return Response(200, [*headers_out, ("content-length", str(size))], b"", (file, 0, size))
        span = parse_range(range_header, size)
        if span is None:
            file.close()
            return response(416, headers=[("content-range", f"bytes */{size}")])
        start, end = span
        return Response(206, [*headers_out, ("content-length", str(end - start + 1)),
                              ("content-range", f"bytes {start}-{end}/{size}")], b"", (file, start, end - start + 1))


# --- NPLN services ----------------------------------------------------------------------------


@dataclass
class Call:
    path: str
    metadata: dict[str, str]
    # The account behind the connection in client-certificate mode; None in local mode.
    principal: Principal | None = None
    network: str = ""  # the caller's network (network_of) for rate limits


def paginate(names: list[str], page_size: int, page_token: str) -> tuple[list[str], str]:
    """Pages sorted names; a page token is the last name of the previous page."""
    if page_token:
        names = [name for name in names if name > page_token]
    if page_size <= 0 or len(names) <= page_size:
        return names, ""
    return names[:page_size], names[page_size - 1]


@dataclass
class UserSession:
    name: str
    user: str
    definition: bytes  # the UserDefinition the user joined with
    create_time: int
    last_seen: int  # when it joined, then when its last KeepUserSession call ended

    def encode(self) -> bytes:
        definition = Msg(self.definition)
        return encode(
            (1, self.name),
            (2, self.user),
            (3, definition.get_bytes(3)),
            (4, timestamp(self.create_time)),
            (5, USER_SESSION_ACTIVE),
            (6, definition.get_str(4) or None),
            (7, definition.get_bytes(2)),
        )


class GamesyncSpace:
    """The gamesync state of one game session. The game names documents without their game session
    (docs/__gs/f, docs/__us/<user session id>, ...), so each game session keeps its own documents,
    global values, transactions, deferments and KeepUserSession calls."""

    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}
        self.globals: dict[str, bytes] = {}
        # transaction -> (begin time, update_time of every document read in it; None if missing)
        self.transactions: dict[bytes, tuple[float, dict[str, int | None]]] = {}
        # deferment name -> (owning user session, what resolves its names (deferment_call), the
        # Deferment message as received, whose field 2 holds its WriteOperations). It stays encoded
        # until it is applied, so it holds the bytes it counts (gamesync_size) and no list per write.
        self.deferments: dict[str, tuple[str, Call, bytes]] = {}
        self.watchers: set[GamesyncWatcher] = set()
        self.sequence = itertools.count(1)  # ussid and ucsid of docs/__us documents


def deferment_call(call: Call) -> Call:
    """What a deferment keeps of the call that stored it: the metadata and account Backend.resolve
    reads, so its writes resolve their names as that call would, without holding the rest of the
    call's headers for as long as it waits."""
    metadata = {key: call.metadata[key] for key in ("npln-tenant-id", "authorization") if key in call.metadata}
    return Call("", metadata, call.principal)


def gamesync_size(docs: dict[str, dict | None], globals_: dict[str, bytes],
                  deferments: dict[str, tuple[str, Call, bytes]]) -> tuple[int, int]:
    """(bytes, records) of a game session's Gamesync documents, global values and deferred writes,
    names and per-record overhead included; documents staged as deleted (None) do not count. A
    deferment counts its encoded Deferment message, field keys and lengths included, so an empty
    write still costs what it holds, and the metadata it keeps (deferment_call)."""
    size = sum(len(name) + len(doc["fields"]) + STATE_OVERHEAD_BYTES for name, doc in docs.items() if doc is not None)
    size += sum(len(key) + len(value) + STATE_OVERHEAD_BYTES for key, value in globals_.items())
    size += sum(len(name) + len(deferment) + sum(map(len, call.metadata.values())) + STATE_OVERHEAD_BYTES
                for name, (_, call, deferment) in deferments.items())
    return size, sum(1 for doc in docs.values() if doc is not None) + len(globals_) + len(deferments)


@dataclass
class GameSession:
    name: str
    max_participants: int
    create_time: int
    host: str  # Gamesync endpoint
    port: int
    password: str = ""
    properties_raw: bytes | None = None  # encoded MapValue, passed through as the client sent it
    creator: str = ""  # the user who created it: the island's owner, who hosts it
    user_sessions: dict[str, UserSession] = field(default_factory=dict)  # by user name
    gamesync: GamesyncSpace = field(default_factory=GamesyncSpace, repr=False, compare=False)

    def encode(self, reveal_password: bool = True) -> bytes:
        """The GameSession message. In client-certificate mode only members see the password
        (Backend.encode_session)."""
        count = len(self.user_sessions)
        return encode(
            (1, self.name),
            (2, self.max_participants),
            (3, count),
            (4, count < self.max_participants),
            (5, True),
            (6, (self.password if reveal_password else "") or None),
            (7, GAME_SESSION_ACTIVE),
            (8, self.host),
            (9, self.port),
            (10, timestamp(self.create_time)),
            (11, self.properties_raw or None),
            *[(12, user_session.encode()) for user_session in self.user_sessions.values()],
        )


def session_matches(session: GameSession, filters: dict[str, bytes]) -> bool:
    """Evaluates a QueryGameSessions properties filter (field 6, a MapValue). An f_<name> entry
    holding a string value matches sessions whose property <name> is that same string; the game
    looks for an island's session this way, with f_string1 set to the ":<session id>" the host put
    in string1. Entries without a string value (f_sys_lock holds 1 while matching sys_lock 0, and
    f_int* are empty) have unknown semantics and are not evaluated."""
    properties = map_entries(session.properties_raw)
    for key, raw in filters.items():
        wanted = Msg(raw)
        if key.startswith("f_") and wanted.has(7) \
                and Msg(properties.get(key[2:]) or b"").get_str(7) != wanted.get_str(7):
            return False
    return True


@dataclass
class CreationTicket:
    name: str
    matchmaking_config: str
    definitions: list[bytes]
    session: GameSession
    matched: list[bytes]
    state: int

    def encode(self) -> bytes:
        succeeded = self.state == TICKET_SUCCEEDED
        return encode(
            (1, self.name),
            (2, self.matchmaking_config or None),
            *[(3, definition) for definition in self.definitions],
            (4, self.state),
            *[(5, matched) for matched in (self.matched if succeeded else [])],
            (6, self.session.encode() if succeeded else None),
        )


class GamesyncWatcher:
    """One KeepUserSession call: the user session that opened it, the game session whose documents
    it can watch, the targets it listens to and the responses waiting to be sent."""

    def __init__(self, session: GameSession, member: UserSession) -> None:
        self.session = session
        self.member = member
        self.joined = False  # whether a request has named its user session yet
        self.targets: dict[str, tuple[frozenset[str], str]] = {}  # id -> (documents, collection)
        self.outbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.queued = 0  # bytes of responses in the outbox
        self.error: GrpcError | None = None  # set when the server ends the call

    def covers(self, target_id: str, name: str) -> bool:
        documents, collection = self.targets[target_id]
        return name in documents or (bool(collection) and name.rpartition("/")[0] == collection)

    def send(self, message: bytes) -> None:
        """Queues a response unless the call has ended. A client that stops reading while its game
        session keeps changing would make the outbox grow without end, so once more than
        MAX_WATCHER_BACKLOG_BYTES wait, they are dropped and the call ends."""
        if self.error is not None:
            return
        self.outbox.put_nowait(message)
        self.queued += len(message)
        if self.queued > MAX_WATCHER_BACKLOG_BYTES:
            while not self.outbox.empty():
                self.outbox.get_nowait()
            self.queued = 0
            self.end(GrpcError(RESOURCE_EXHAUSTED, "the client does not read its gamesync responses"))

    def end(self, error: GrpcError) -> None:
        """Ends the call with `error` once the responses already waiting are sent."""
        if self.error is None:
            self.error = error
            self.outbox.put_nowait(None)


def wire_target_id(target_id: str) -> str:
    """The id a DocumentChange/TargetChange carries: the game parses it with strtoul, so a target
    registered as "userSessions/current/targets/1" must come back as the bare "1"."""
    return target_id.rpartition("/")[2] if "/" in target_id else target_id


def sdp_values(entries: dict[str, bytes], prefix: str = "", depth: int = 0) -> list[tuple[str, bytes]]:
    """The session descriptions among the fields of a gamesync document, with their dotted paths:
    string and bytes values that start with an SDP version line, in maps and arrays up to 16 levels
    deep. Values that do not decode are skipped."""
    found: list[tuple[str, bytes]] = []
    for key, raw in entries.items():
        try:
            found += _sdp_in_value(prefix + key, Msg(raw), depth)
        except ValueError:
            continue
    return found


def _sdp_in_value(path: str, value: Msg, depth: int) -> list[tuple[str, bytes]]:
    # common.Value: string_value 7, bytes_value 8, array_value 9 (ArrayValue.values 1), map_value 10.
    for number in (7, 8):
        data = value.get_bytes(number)
        if data is not None and SDP_START.match(data):
            return [(path, data)]
    if depth >= 16:
        return []
    if (array := value.get_msg(9)) is not None:
        return [found for index, item in enumerate(array.get_msgs(1))
                for found in _sdp_in_value(f"{path}[{index}]", item, depth + 1)]
    if value.has(10):
        return sdp_values(map_entries(value.get_bytes(10)), path + ".", depth + 1)
    return []


def describe_sdp(data: bytes) -> str:
    """Size and digest of a session description, to match what one peer wrote with what the other
    received."""
    return f"{len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()[:16]}"


def log_gamesync_sdp(changes: dict[str, dict | None], writer: str) -> None:
    """Logs the session descriptions in committed gamesync documents: their candidate lines at
    INFO, every byte at DEBUG (-v). ICE credentials (a=ice-pwd) stay out of the INFO line."""
    for name, doc in changes.items():
        if doc is None:
            continue
        for path, data in sdp_values(doc_entries(doc)):
            lines = data.decode("utf-8", "backslashreplace").splitlines(keepends=True)
            candidates = [line.rstrip() for line in lines if line.startswith("a=candidate")]
            log.info("gamesync %s %s written by %s: SDP (%s); candidates: %s", name, path, writer or "-",
                     describe_sdp(data), "; ".join(candidates) or "none")
            if log.isEnabledFor(logging.DEBUG):
                log.debug("SDP %s %s, hex %s:\n%s", name, path, data.hex(),
                          "\n".join(f"  {line!r}" for line in lines))


def describe_target(target: Msg) -> str:
    """Summarizes a gamesync Target for the log."""
    documents = (target.get_msg(2) or Msg()).get_strs(1)
    collection = (target.get_msg(3) or Msg()).get_str(1)
    watched = f"documents {documents}" if documents else f"collection {collection!r}"
    return f"{target.get_str(1)!r} on {watched}"


def describe_keep_user_session_request(req: Msg) -> str:
    """Summarizes a KeepUserSessionRequest for the log."""
    if req.has(2):
        return f"echo {req.get_str(2)!r}"
    if (update := req.get_msg(3)) is not None:
        return f"update_target {describe_target(update.get_msg(1) or Msg())}"
    if (delete := req.get_msg(4)) is not None:
        return f"delete_target {delete.get_str(1)!r}"
    return "no request"


def describe_keep_user_session_response(message: bytes) -> str:
    """Summarizes a KeepUserSessionResponse for the log."""
    msg = Msg(message)
    if msg.has(1):
        return f"echo {msg.get_str(1)!r}"
    if (change := msg.get_msg(2)) is not None:
        kind = change.get_int(2)
        document = change.get_msg(3) or Msg()
        entries = map_entries(document.get_bytes(2))
        sdp = "".join(f"; SDP {path} ({describe_sdp(data)})" for path, data in sdp_values(entries))
        return (f"document_change {DOCUMENT_CHANGE_NAMES.get(kind, kind)} {document.get_str(1)} "
                f"[{', '.join(entries)}] for target {change.get_str(1)!r}{sdp}")
    if (change := msg.get_msg(3)) is not None:
        kind = change.get_int(2)
        return f"target_change {TARGET_CHANGE_NAMES.get(kind, kind)} for target {change.get_str(1)!r}"
    return f"<{len(message)} bytes> {message[:64].hex()}"


AUTH = "/nn.npln.auth.v1.Auth/"
UGCSTORE = "/nn.npln.ugcstore.v1.Ugcstore/"
GAME_SESSIONS = "/nn.npln.matchmaking.v1.GameSessionService/"
GAMESYNC = "/nn.npln.gamesync.v1.Gamesync/"


class Backend:
    def __init__(self, store: Store, storage: Storage, max_players: int, stun: str, gamesync_port: int):
        self.store = store
        self.storage = storage
        self.signer = TokenSigner(store.secret)
        self.max_players = max_players
        self.stun = stun
        self.gamesync_port = gamesync_port
        self.sessions: dict[str, GameSession] = {}
        self.tickets: dict[str, CreationTicket] = {}
        # Client-certificate mode: (account, island owner) -> (monotonic expiry, password_version) of
        # what a right island password allows (finding the owner's game session, reading its
        # StageData), and the counts of wrong passwords.
        self.password_grants: dict[tuple[str, str], tuple[float, str]] = {}
        self.guesses = GuessLimiter()
        self.unary: dict[str, Callable[[Call, Msg], bytes]] = {
            AUTH + "CreateUser": self.create_user,
            AUTH + "IssueToken": self.issue_token,
            AUTH + "RefreshToken": self.refresh_token,
            AUTH + "IssuePrearrangedUserToken": self.issue_prearranged_user_token,
            AUTH + "IssueAnonymousUserToken": self.issue_anonymous_user_token,
            AUTH + "RefreshAnonymousUserToken": self.refresh_token,
            AUTH + "ValidateToken": self.validate_token,
            AUTH + "ListUsers": self.list_users,
            AUTH + "DeleteUser": self.delete_user,
            UGCSTORE + "GetDocument": self.get_document,
            UGCSTORE + "CommitDocuments": self.commit_documents,
            UGCSTORE + "IssueUploadUri": self.issue_upload_uri,
            UGCSTORE + "IssueAttachmentUri": self.issue_attachment_uri,
            UGCSTORE + "CreateDocumentShortAlias": self.create_document_short_alias,
            UGCSTORE + "GetDocumentShortAlias": self.get_document_short_alias,
            GAME_SESSIONS + "CreateGameSessionCreationTicket": self.create_game_session_creation_ticket,
            GAME_SESSIONS + "CancelGameSessionCreationTicket": self.cancel_game_session_creation_ticket,
            GAME_SESSIONS + "GetGameSession": self.get_game_session,
            GAME_SESSIONS + "QueryGameSessions": self.query_game_sessions,
            GAME_SESSIONS + "JoinGameSession": self.join_game_session,
            GAME_SESSIONS + "ListUserSessions": self.list_user_sessions,
            GAME_SESSIONS + "AllocateIceServerSet": self.allocate_ice_server_set,
            GAMESYNC + "IssueToken": self.gamesync_issue_token,
            GAMESYNC + "RefreshToken": self.gamesync_refresh_token,
            GAMESYNC + "GetDocument": self.gamesync_get_document,
            GAMESYNC + "ReadDocuments": self.gamesync_read_documents,
            GAMESYNC + "ListDocuments": self.gamesync_list_documents,
            GAMESYNC + "QueryCollectionIds": self.gamesync_query_collection_ids,
            GAMESYNC + "WriteDocuments": self.gamesync_write_documents,
            GAMESYNC + "LazyWriteDocuments": self.gamesync_lazy_write_documents,
            GAMESYNC + "BeginTransaction": self.gamesync_begin_transaction,
            GAMESYNC + "CommitTransaction": self.gamesync_commit_transaction,
            GAMESYNC + "RollbackTransaction": self.gamesync_rollback_transaction,
            GAMESYNC + "CreateRound": self.gamesync_create_round,
        }
        self.streams: dict[str, Callable[[Call, Msg], AsyncIterator[bytes]]] = {
            UGCSTORE + "RunQuery": self.no_results,
            UGCSTORE + "BulkGetDocuments": self.no_results,
            GAME_SESSIONS + "TrackGameSessionCreationTicket": self.track_game_session_creation_ticket,
            "/nn.npln.maintenance.v1.MaintenanceScheduleService/SubscribeMaintenanceSchedules":
                self.subscribe_maintenance_schedules,
            "/nn.npln.friends.v1.Friends/SubscribeFriendUsers": self.subscribe_friend_users,
        }
        self.bidi: dict[str, Callable[[Call, AsyncIterator[Msg]], AsyncIterator[bytes]]] = {
            GAMESYNC + "KeepUserSession": self.keep_user_session,
        }

    # Names and identities

    def resolve(self, call: Call, name: str) -> str:
        """Expands the "tenants/current" alias using the npln-tenant-id metadata, the
        "userSessions/current" alias to the user session the gamesync token was issued for and the
        "users/current" alias to the user the bearer access token was issued to."""
        tenant_id = call.metadata.get("npln-tenant-id")
        if tenant_id and (name == "tenants/current" or name.startswith("tenants/current/")):
            name = f"tenants/{tenant_id}{name[len('tenants/current'):]}"
        if name == "userSessions/current" or name.startswith("userSessions/current/"):
            user_session = (self.caller(call, "gamesync") or {}).get("user_session")
            if user_session:
                name = f"{user_session}{name[len('userSessions/current'):]}"
        if "users/current" not in name:
            return name
        caller = self.caller(call)
        if not caller or "sub" not in caller:
            return name
        user_id = caller["sub"].rpartition("/users/")[2]
        segments = name.split("/")
        for i in range(len(segments) - 1):
            if segments[i] == "users" and segments[i + 1] == "current":
                segments[i + 1] = user_id
        return "/".join(segments)

    def caller(self, call: Call, typ: str = "access") -> dict | None:
        scheme, _, token = call.metadata.get("authorization", "").partition(" ")
        return self.verify_token(call, token.strip(), typ) if scheme.lower() == "bearer" else None

    def verify_token(self, call: Call, token: str, typ: str) -> dict | None:
        """The claims of a valid token of type `typ`. In client-certificate mode the token must have
        been issued over a connection of the same account (its "own" claim), so a token is useless
        to anyone who copies it but cannot present that account's device certificate."""
        claims = self.signer.verify(token, typ)
        if claims is None or (call.principal is not None and claims.get("own") != call.principal.account):
            return None
        return claims

    @staticmethod
    def owner_claims(call: Call) -> dict:
        """Claims that bind a token to the account behind the connection it is issued on."""
        return {"own": call.principal.account} if call.principal is not None else {}

    def owns(self, call: Call, user: str) -> bool:
        """Whether the account behind the call owns NPLN user `user`; always true in local mode."""
        if call.principal is None:
            return True
        record = self.store.users.get(user)
        return record is not None and record.get("owner") == call.principal.account

    def require_caller(self, call: Call) -> dict | None:
        """The claims of the caller's access token. In client-certificate mode a valid token for a
        user of the connection's account is required; in local mode this is caller()."""
        caller = self.caller(call)
        if call.principal is None:
            return caller
        if caller is None:
            raise GrpcError(UNAUTHENTICATED, "invalid access token")
        if not self.owns(call, caller["sub"]):
            raise GrpcError(UNAUTHENTICATED, "the token's user no longer exists")
        return caller

    @staticmethod
    def account_for(call: Call, external_id_token: Msg | None) -> str:
        """Derives a stable account from the NSA id token's subject. That token is unsigned, so in
        client-certificate mode the subject only tells apart the emulator profiles of the account
        behind the connection, and never reaches the users of another account."""
        token = ""
        if external_id_token is not None:
            token = external_id_token.get_str(1) or external_id_token.get_str(2)
        claims = unverified_jwt_claims(token) or {}
        subject = str(claims.get("sub") or token)
        if call.principal is not None:
            return f"accounts/a-{derived_id('account', call.principal.account, subject)}"
        return f"accounts/a-{derived_id('account', subject)}"

    def ensure_user(self, call: Call, name: str, account: str, now: int) -> dict:
        """The user `name`, created if missing. In client-certificate mode a new user belongs to
        the account behind the call, and an existing one must already belong to it: users from
        local mode, which have no owner, are never handed to anyone."""
        user = self.store.users.get(name)
        if user is None:
            check_name(name)
            user = {"account": account, "create_time": now, "short_id": secrets.randbelow(10**10)}
            if call.principal is not None:
                owned = sum(1 for record in self.store.users.values()
                            if record.get("owner") == call.principal.account)
                if owned >= MAX_USERS_PER_ACCOUNT:
                    raise GrpcError(RESOURCE_EXHAUSTED, "this account has too many users")
                user["owner"] = call.principal.account
            if (problem := self.storage.room_for(call.principal.account if call.principal else None,
                                                 user_state_bytes(name, account), 0)) is not None:
                raise GrpcError(RESOURCE_EXHAUSTED, problem)
            self.store.users[name] = user
            log.info("registered user %s (%s)", name, account)
        elif not self.owns(call, name):
            raise GrpcError(PERMISSION_DENIED, f"{name} belongs to another account")
        user["last_login_time"] = now
        self.store.save()
        return user

    @staticmethod
    def encode_user(name: str, user: dict) -> bytes:
        return encode(
            (1, name),
            (2, user["account"]),
            (3, timestamp(user["create_time"])),
            (4, timestamp(user.get("last_login_time", user["create_time"]))),
            (5, user["short_id"]),
        )

    def encode_token(self, call: Call, user: str, account: str) -> bytes:
        now = int(time.time())
        own = self.owner_claims(call)
        access = self.signer.issue(typ="access", sub=user, acc=account, iat=now,
                                   exp=now + TOKEN_TTL_SECONDS, **own)
        refresh = self.signer.issue(typ="refresh", sub=user, acc=account, iat=now,
                                    jti=secrets.token_hex(8), **own)
        return encode((1, user), (2, access), (3, refresh), (4, duration(TOKEN_TTL_SECONDS)))

    # nn.npln.auth.v1.Auth

    def create_user(self, call: Call, req: Msg) -> bytes:
        tenant = self.resolve(call, req.get_str(1))
        name = f"{tenant}/users/u-{random_id()}"
        user = self.ensure_user(call, name, self.account_for(call, req.get_msg(3)), time.time_ns())
        return self.encode_user(name, user)

    def issue_token(self, call: Call, req: Msg) -> bytes:
        name = self.resolve(call, req.get_str(1))
        if call.principal is not None and name not in self.store.users:
            # Users come from CreateUser or IssuePrearrangedUserToken, never from a chosen name.
            raise GrpcError(NOT_FOUND, f"{name} not found")
        user = self.ensure_user(call, name, self.account_for(call, req.get_msg(2)), time.time_ns())
        return encode((1, self.encode_token(call, name, user["account"])))

    def refresh_token(self, call: Call, req: Msg) -> bytes:
        # RefreshTokenRequest and RefreshAnonymousTokenRequest both carry the token in field 2.
        claims = self.verify_token(call, req.get_str(2), "refresh")
        if claims is None or not self.owns(call, claims["sub"]):
            raise GrpcError(UNAUTHENTICATED, "invalid refresh token")
        return encode((1, self.encode_token(call, claims["sub"], claims["acc"])))

    def issue_prearranged_user_token(self, call: Call, req: Msg) -> bytes:
        tenant = self.resolve(call, req.get_str(1))
        account = self.account_for(call, req.get_msg(3))
        name = f"{tenant}/users/u-{derived_id(account, str(req.get_int(2)))}"
        user = self.ensure_user(call, name, account, time.time_ns())
        return encode((1, self.encode_user(name, user)), (2, self.encode_token(call, name, account)))

    def issue_anonymous_user_token(self, call: Call, req: Msg) -> bytes:
        if call.principal is not None:
            # One shared anonymous user would let accounts act as each other.
            raise GrpcError(PERMISSION_DENIED, "anonymous users are not available")
        tenant = self.resolve(call, req.get_str(1))
        return encode((1, self.encode_token(call, f"{tenant}/users/u-anonymous", "")))

    def validate_token(self, call: Call, req: Msg) -> bytes:
        if self.require_caller(call) is None:
            raise GrpcError(UNAUTHENTICATED, "invalid access token")
        return b""

    def list_users(self, call: Call, req: Msg) -> bytes:
        caller = self.require_caller(call)
        if caller is None:
            raise GrpcError(UNAUTHENTICATED, "invalid access token")
        return encode(*[(1, self.encode_user(name, user)) for name, user in self.store.users.items()
                        if user["account"] == caller["acc"] and self.owns(call, name)])

    def delete_user(self, call: Call, req: Msg) -> bytes:
        """Deletes a user with its documents, short aliases and attachments (delete_users)."""
        name = self.resolve(call, req.get_str(1))
        if call.principal is not None:
            self.require_caller(call)
            if not self.owns(call, name):
                raise GrpcError(NOT_FOUND, "user not found")
        if name not in self.store.users:
            raise GrpcError(NOT_FOUND, "user not found")
        blobs = self.delete_users({name})
        self.store.save()
        self.release_blobs(blobs)
        return b""

    def delete_users(self, users: set[str]) -> list[str]:
        """Removes users from their game sessions and deletes them with their documents and short
        aliases, in one synchronous step. Returns the attachment blobs to release once the caller
        has saved, so a crash in between leaves unreferenced files, never missing ones."""
        for session in list(self.sessions.values()):
            for user in users & session.user_sessions.keys():
                self.drop_user_session(session, user)
        documents = [name for name in self.store.documents if document_owner(name) in users]
        blobs = [(self.store.documents[name].get("attachment") or {}).get("blob") for name in documents]
        for name in documents:
            del self.store.documents[name]
        for code in [code for code, entry in self.store.aliases.items() if document_owner(entry["document"]) in users]:
            del self.store.aliases[code]
        for user in users:
            self.store.users.pop(user, None)
        self.password_grants = {key: grant for key, grant in self.password_grants.items() if key[1] not in users}
        return [blob for blob in blobs if blob]

    def release_blobs(self, blobs) -> None:
        """Deletes blob files the saved state no longer refers to. Always call it after
        Store.save(), never before: an interruption in between then leaves orphan files, which
        waste space, instead of state referring to files that are gone."""
        for blob in blobs:
            self.store.release_blob(blob)

    # Access control in client-certificate mode

    def check_document_access(self, call: Call, name: str, owner_only: bool = False,
                              rule_context: bytes | None = None) -> None:
        """Ugcstore access in client-certificate mode. The real service runs per-tenant rules that
        are not public; these follow what the game does. An account reads and writes the documents
        of its own users (tenants/<t>/documents/users/<u>/...). Of another account's documents it
        only reads public/ ones, private/SessionIDData given that island's password as rule context
        "password" (as when joining a Cloud Island) and, for PASSWORD_GRANT_SECONDS after that,
        private/StageData. Writes, attachment URIs and all other documents are the owner's alone.
        The account comes from the connection, so this does not depend on a bearer token."""
        if call.principal is None:
            return
        owner = document_owner(name)
        if owner is None:
            raise GrpcError(PERMISSION_DENIED, f"{name} is not a user document")
        if self.owns(call, owner):
            return
        if not owner_only:
            visibility, document = USER_DOCUMENT.fullmatch(name).group(3, 4)
            if visibility == "public":
                return
            if document == "SessionIDData" and self.check_island_password(call, owner, rule_context):
                now = time.monotonic()
                self.password_grants = {key: grant for key, grant in self.password_grants.items()
                                        if grant[0] > now}
                self.password_grants[(call.principal.account, owner)] = (
                    now + PASSWORD_GRANT_SECONDS, self.island_password_version(owner))
                return
            if document == "StageData" and self.has_grant(call, owner):
                return
        raise GrpcError(PERMISSION_DENIED, f"no access to {name}")

    def island_password(self, owner: str) -> str:
        """The password in `owner`'s private/PasswordData, or "" if there is none."""
        tenant, _, user_id = owner.partition("/users/")
        password_doc = self.store.documents.get(f"{tenant}/documents/users/{user_id}/private/PasswordData")
        return Msg(doc_entries(password_doc).get("password") or b"").get_str(7)

    def island_password_version(self, owner: str) -> str:
        return password_version(self.island_password(owner))

    def has_grant(self, call: Call, owner: str) -> bool:
        """Whether the caller's account gave `owner`'s current island password within
        PASSWORD_GRANT_SECONDS. A new or removed password ends every grant for the old one."""
        grant = self.password_grants.get((call.principal.account, owner))
        return (grant is not None and grant[0] > time.monotonic() and bool(self.island_password(owner))
                and grant[1] == self.island_password_version(owner))

    def check_island_password(self, call: Call, owner: str, rule_context: bytes | None) -> bool:
        """Whether the rule context carries the password of `owner`'s private/PasswordData."""
        offered = Msg(map_entries(rule_context).get("password") or b"").get_str(7)
        return self.check_password(call, self.island_password(owner), offered, f"island {owner}")

    def check_password(self, call: Call, expected: str, offered: str, target: str) -> bool:
        """Compares an island or game session password; an empty expected password never matches.
        Wrong guesses count against the account, its network and, unless the account gave this
        same password recently, `target` (GUESS_LIMITS); any full count refuses further guesses for
        a while."""
        version = password_version(expected)
        self.guesses.check(call, target, version)
        if expected and hmac.compare_digest(offered.encode(), expected.encode()):
            self.guesses.succeeded(call, target, version)
            return True
        self.guesses.failed(call, target, version)
        log.info("wrong password for %s from account %s (%s)", target, call.principal.account, call.network)
        return False

    def session_visible(self, call: Call, session: GameSession) -> bool:
        """Client-certificate mode: whether the caller may see a game session at all. It must have a
        user in it, or have given the current island password of the user who created it (the
        island's owner, who hosts it) within PASSWORD_GRANT_SECONDS; a grant for another member's
        island does not count. The host's properties carry the island's session id, which only the
        password-protected private/SessionIDData otherwise reveals."""
        if call.principal is None or any(self.owns(call, user) for user in session.user_sessions):
            return True
        return bool(session.creator) and self.has_grant(call, session.creator)

    def check_commit_room(self, call: Call, staging: Staging) -> None:
        """Refuses a Ugcstore commit that would break a document or storage limit (Storage.room_for,
        MAX_DOCUMENTS_PER_USER). Each upload a commit imports counts once, as apply_write refuses
        importing one twice. Shrinking commits always pass."""
        state = blobs = 0
        for name, doc in staging.changes.items():
            old = self.store.documents.get(name)
            state += document_state_bytes(name, doc) - document_state_bytes(name, old)
            blobs += (doc.get("attachment") or {}).get("size", 0) if doc else 0
            blobs -= (old.get("attachment") or {}).get("size", 0) if old else 0
        for upload_id in staging.imported_uploads:
            state -= STATE_OVERHEAD_BYTES
            blobs -= self.store.uploads[upload_id]["received"]
        account = call.principal.account if call.principal is not None else None
        problem = self.storage.room_for(account, state, blobs)
        if problem is not None:
            raise GrpcError(RESOURCE_EXHAUSTED, problem)
        if account is None:
            return
        for owner in {document_owner(name) for name, doc in staging.changes.items()
                      if doc is not None and name not in self.store.documents}:
            names = {name for name in self.store.documents if document_owner(name) == owner}
            names.update(name for name, doc in staging.changes.items() if doc is not None and document_owner(name) == owner)
            if len(names) > MAX_DOCUMENTS_PER_USER:
                raise GrpcError(RESOURCE_EXHAUSTED, f"{owner} has too many documents")

    def purge_account(self, account: str) -> None:
        """Deletes the game data of an account an operator deleted (`portal.py delete`): its users
        with their documents, short aliases and attachments (delete_users), and its upload sessions.
        One synchronous step, one save, then the files (release_blobs)."""
        users = {name for name, user in self.store.users.items() if user.get("owner") == account}
        uploads = [upload_id for upload_id, upload in self.store.uploads.items()
                   if upload.get("owner") == account]
        blobs = self.delete_users(users)
        upload_blobs = [self.store.uploads.pop(upload_id)["blob"] for upload_id in uploads]
        self.password_grants = {key: grant for key, grant in self.password_grants.items() if key[0] != account}
        self.guesses.forget(account)
        self.store.save()
        self.release_blobs([*blobs, *upload_blobs])
        log.info("purged deleted account %s: %d user(s), %d attachment(s), %d upload session(s)",
                 account, len(users), len(blobs), len(uploads))

    # nn.npln.ugcstore.v1.Ugcstore

    def get_document(self, call: Call, req: Msg) -> bytes:
        name = self.resolve(call, req.get_str(1))
        self.check_document_access(call, name, rule_context=req.get_bytes(3))
        doc = self.store.documents.get(name)
        if doc is None:
            raise GrpcError(NOT_FOUND, f"{name} not found")
        return encode_document(name, doc)

    def commit_documents(self, call: Call, req: Msg) -> bytes:
        now = time.time_ns()
        staging = Staging(self.store.documents)
        try:
            results = [self.apply_write(call, op, staging, now) for op in req.get_msgs(2)]
            self.check_commit_room(call, staging)
        except (GrpcError, ValueError):
            for blob_id in staging.new_blobs:
                self.store.blob_path(blob_id).unlink(missing_ok=True)
            raise

        replaced_blobs = set()
        for name, doc in staging.changes.items():
            old = self.store.documents.get(name)
            if old and old.get("attachment"):
                replaced_blobs.add(old["attachment"]["blob"])
            if doc is None:
                self.store.documents.pop(name, None)
            else:
                self.store.documents[name] = doc
        imported_blobs = [self.store.uploads.pop(upload_id)["blob"] for upload_id in staging.imported_uploads]
        self.store.save()
        # Files go after the save (release_blobs). An imported upload that the commit's final
        # documents no longer refer to (imported, then deleted or replaced in the same commit) goes
        # too, so no file outlives its record.
        self.release_blobs(replaced_blobs.union(staging.new_blobs, imported_blobs))
        log.info("committed %d write(s): %s", len(results), ", ".join(staging.changes) or "-")
        return encode(*[(1, result) for result in results], (2, timestamp(now)))

    def apply_write(self, call: Call, op: Msg, staging: Staging, now: int) -> bytes:
        """Stages one WriteOperation and returns its WriteResult."""
        written = encode((1, timestamp(now)))

        if (update := op.get_msg(1)) is not None:
            document = update.get_msg(1) or Msg()
            name = self.resolve(call, document.get_str(1))
            self.check_document_access(call, name, owner_only=True)
            check_name(name)
            doc = staging.get(name)
            check_precondition(name, doc, update.get_msg(3))
            incoming = map_entries(document.get_bytes(2))
            staging.put(name, updated_document(doc, now, masked_entries(doc, incoming, update.get_msg(2))))
            return written

        if (delete := op.get_msg(2)) is not None:
            name = self.resolve(call, delete.get_str(1))
            self.check_document_access(call, name, owner_only=True)
            check_precondition(name, staging.get(name), delete.get_msg(2))
            staging.put(name, None)
            return written

        if (transform := op.get_msg(6)) is not None:
            name = self.resolve(call, transform.get_str(1))
            self.check_document_access(call, name, owner_only=True)
            check_name(name)
            doc = staging.get(name)
            entries = doc_entries(doc)
            results = []
            for field_transform in transform.get_msgs(2):
                path = field_transform.get_str(1)
                if field_transform.has(2):
                    entries, result = apply_transform(entries, path, "request_time", None, now)
                else:
                    kinds = {3: "increment", 4: "maximum", 5: "minimum", 6: "increment"}
                    number = next((n for n in kinds if field_transform.has(n)), None)
                    if number is None:
                        raise GrpcError(INVALID_ARGUMENT, f"empty transform for {path}")
                    entries, result = apply_transform(entries, path, kinds[number],
                                                      field_transform.get_bytes(number), now)
                results.append(result)
            for buffered in transform.get_msgs(3):
                entries, _ = apply_transform(entries, buffered.get_str(1), "increment",
                                             buffered.get_bytes(2), now)
            staging.put(name, updated_document(doc, now, entries))
            return encode((1, timestamp(now)), *[(2, result) for result in results])

        if (attach := op.get_msg(3)) is not None:
            name = self.resolve(call, attach.get_str(1))
            self.check_document_access(call, name, owner_only=True)
            check_name(name)
            check_name(attach.get_str(4))
            doc = staging.get(name)
            has_attachment = bool(doc and doc.get("attachment"))
            if attach.has(3) and attach.get_bool(3) != has_attachment:
                raise GrpcError(FAILED_PRECONDITION, f"attachment precondition failed for {name}")
            body = attach.get_bytes(2) or b""
            if (problem := self.storage.room_for(
                    call.principal.account if call.principal is not None else None, 0, len(body))) is not None:
                raise GrpcError(RESOURCE_EXHAUSTED, problem)
            blob_id = random_id()
            self.store.write_blob(blob_id, body)
            staging.new_blobs.append(blob_id)
            attachment = {"blob": blob_id, "mime_type": attach.get_str(4), "size": len(body)}
            staging.put(name, updated_document(doc, now, attachment=attachment))
            return written

        if (unset := op.get_msg(4)) is not None:
            name = self.resolve(call, unset.get_str(1))
            self.check_document_access(call, name, owner_only=True)
            doc = staging.get(name)
            if doc and doc.get("attachment"):
                staging.put(name, updated_document(doc, now, attachment=None))
            elif not unset.get_bool(3):
                raise GrpcError(NOT_FOUND, f"{name} has no attachment")
            return written

        if (imported := op.get_msg(5)) is not None:
            name = self.resolve(call, imported.get_str(1))
            self.check_document_access(call, name, owner_only=True)
            check_name(name)
            check_name(imported.get_str(3))
            uri = imported.get_str(2)
            upload_id = urlsplit(uri).path.rstrip("/").rpartition("/")[2]
            upload = self.store.uploads.get(upload_id)
            if upload is None or not upload["complete"] or (
                    call.principal is not None and upload.get("owner") != call.principal.account):
                raise GrpcError(FAILED_PRECONDITION, f"upload {uri} is not complete")
            if upload_id in staging.imported_uploads:
                raise GrpcError(INVALID_ARGUMENT, f"upload {uri} is imported twice")
            try:
                intact = self.store.blob_path(upload["blob"]).stat().st_size == upload["received"]
            except FileNotFoundError:
                intact = False
            if not intact:
                raise GrpcError(FAILED_PRECONDITION, f"upload {uri} is damaged; upload it again")
            staging.imported_uploads.append(upload_id)
            attachment = {"blob": upload["blob"], "mime_type": imported.get_str(3),
                          "size": upload["received"]}
            staging.put(name, updated_document(staging.get(name), now, attachment=attachment))
            return written

        raise GrpcError(INVALID_ARGUMENT, "empty write operation")

    def issue_upload_uri(self, call: Call, req: Msg) -> bytes:
        owner = call.principal.account if call.principal is not None else None
        return encode((1, self.storage.upload_uri(self.storage.new_upload(owner))))

    def issue_attachment_uri(self, call: Call, req: Msg) -> bytes:
        name = self.resolve(call, req.get_str(1))
        self.check_document_access(call, name, owner_only=True)
        doc = self.store.documents.get(name)
        attachment = doc.get("attachment") if doc else None
        if attachment is None:
            raise GrpcError(NOT_FOUND, f"{name} has no attachment")
        return encode((1, self.storage.download_uri(attachment["blob"])))

    def create_document_short_alias(self, call: Call, req: Msg) -> bytes:
        parent = self.resolve(call, req.get_str(1))
        alias = req.get_msg(2) or Msg()
        document = self.resolve(call, alias.get_str(2))
        self.check_document_access(call, document, owner_only=True)
        scope = alias.get_str(3)
        code = alias.get_str(1).rpartition("/")[2].upper()
        if code and code in self.store.aliases:
            raise GrpcError(ALREADY_EXISTS, f"short alias {code} already exists")
        if not code:
            # A document keeps its address, like a Cloud Island does.
            for entry in self.store.aliases.values():
                if entry["document"] == document and entry["scope"] == scope:
                    return self.encode_alias(entry)
            while not code or code in self.store.aliases:
                code = "".join(secrets.choice(ALIAS_ALPHABET) for _ in range(ALIAS_LENGTH))
        if call.principal is not None and sum(
                1 for entry in self.store.aliases.values()
                if document_owner(entry["document"]) == document_owner(document)) >= MAX_ALIASES_PER_USER:
            raise GrpcError(RESOURCE_EXHAUSTED, "too many short aliases")
        # The game parses this as tenants/{tenant}/scopes/{scope}/documentShortAliases/{alias}
        # and aborts if any segment is missing.
        entry = {"name": f"{parent}/scopes/{scope}/documentShortAliases/{code}", "document": document,
                 "scope": scope}
        check_name(entry["name"])
        check_name(document)
        if (problem := self.storage.room_for(call.principal.account if call.principal else None,
                                             alias_state_bytes(code, entry), 0)) is not None:
            raise GrpcError(RESOURCE_EXHAUSTED, problem)
        self.store.aliases[code] = entry
        self.store.save()
        log.info("short alias %s -> %s", code, document)
        return self.encode_alias(entry)

    def get_document_short_alias(self, call: Call, req: Msg) -> bytes:
        code = req.get_str(1).rpartition("/")[2].upper()
        entry = self.store.aliases.get(code)
        if entry is None:
            raise GrpcError(NOT_FOUND, f"short alias {code} not found")
        return self.encode_alias(entry)

    @staticmethod
    def encode_alias(entry: dict) -> bytes:
        return encode((1, entry["name"]), (2, entry["document"]), (3, entry["scope"] or None))

    async def no_results(self, call: Call, req: Msg) -> AsyncIterator[bytes]:
        return
        yield

    # nn.npln.matchmaking.v1.GameSessionService

    def user_definitions(self, call: Call, definitions: list[bytes]) -> list[bytes]:
        """Rewrites each UserDefinition to name its user canonically, defaulting to the calling
        user when a request names no users. In client-certificate mode a request may only name
        users of the connection's account, so nobody can add others to a session or pull them out
        of theirs."""
        if not definitions:
            caller = self.require_caller(call)
            return [encode((1, caller["sub"]))] if caller else []
        resolved = []
        for definition in definitions:
            msg = Msg(definition)
            user = msg.get_str(1)
            canonical = self.resolve(call, user)
            if not self.owns(call, canonical):
                raise GrpcError(PERMISSION_DENIED, f"{canonical} belongs to another account")
            resolved.append(definition if canonical == user else replace_field(msg, 1, canonical))
        return resolved

    def join(self, call: Call, session: GameSession, definitions: list[bytes], now: int) -> list[bytes]:
        """Adds users to a session and returns their MatchedUserSessions."""
        matched = []
        tenant_id = call.metadata.get("npln-tenant-id", "t-15f83830-lp1")
        now_sec = now // 1_000_000_000
        for definition in definitions:
            user = self.resolve(call, Msg(definition).get_str(1))
            user_session = session.user_sessions.get(user)
            if user_session is None:
                if len(session.user_sessions) >= session.max_participants:
                    raise GrpcError(RESOURCE_EXHAUSTED, f"{session.name} is full")
                self.leave_other_sessions(user, session)
                user_session = UserSession(f"{session.name}/userSessions/{random_id()}", user,
                                           definition, now, now)
                session.user_sessions[user] = user_session
            token = self.signer.issue(typ="matchmaking", sub=user, game_session=session.name,
                                      **self.owner_claims(call),
                                      user_session=user_session.name, iat=now_sec,
                                      exp=now_sec + TOKEN_TTL_SECONDS, jti=secrets.token_hex(8),
                                      aud="0400A3A01EE4C000",
                                      iss=f"https://{tenant_id}.npln.srv.nintendo.net")
            matched.append(encode((1, definition), (2, user_session.name), (3, token)))
        return matched

    def leave_other_sessions(self, user: str, keep: GameSession) -> None:
        """A user plays in one session at a time."""
        for session in list(self.sessions.values()):
            if session is not keep:
                self.drop_user_session(session, user)

    def drop_user_session(self, session: GameSession, user: str) -> None:
        """Removes a user from a game session. While others remain in it, the user session's
        deferred gamesync writes are applied, its KeepUserSession calls end and the gamesync
        documents named after it (docs/__us/<id>, docs/__pgn/All/__pus/<id>, ...) are deleted. A
        game session left empty is dropped with its creation tickets and all of its gamesync state,
        and its remaining KeepUserSession calls end."""
        user_session = session.user_sessions.pop(user, None)
        if user_session is None:
            return
        space = session.gamesync
        log.info("dropped %s", user_session.name)
        if session.user_sessions:
            self.gamesync_fire_deferments(space, user_session.name)
            session_id = user_session.name.rpartition("/")[2]
            stale = [name for name in space.docs if name.rpartition("/")[2] == session_id]
            ending = [watcher for watcher in space.watchers if watcher.member is user_session]
        else:
            self.sessions.pop(session.name, None)
            self.tickets = {name: ticket for name, ticket in self.tickets.items() if ticket.session is not session}
            stale = list(space.docs)
            ending = list(space.watchers)
            space.globals.clear()
            space.transactions.clear()
            space.deferments.clear()
            log.info("dropped %s", session.name)
        for watcher in ending:
            space.watchers.discard(watcher)
            watcher.end(GrpcError(NOT_FOUND, f"{watcher.member.name} has left its game session"))
        for name in stale:
            del space.docs[name]
        if stale:
            self.gamesync_notify(space, dict.fromkeys(stale), set())
            log.info("gamesync deleted %s", ", ".join(stale))

    def prune_sessions(self) -> None:
        """Drops the user sessions whose game is gone; see USER_SESSION_GRACE_SECONDS."""
        cutoff = time.time_ns() - USER_SESSION_GRACE_SECONDS * 1_000_000_000
        for session in list(self.sessions.values()):
            connected = {watcher.member.name for watcher in session.gamesync.watchers}
            for user, user_session in list(session.user_sessions.items()):
                if user_session.last_seen < cutoff and user_session.name not in connected:
                    log.info("%s has had no KeepUserSession call open for %ds", user_session.name,
                             USER_SESSION_GRACE_SECONDS)
                    self.drop_user_session(session, user)

    def find_user_session(self, session_id: str) -> tuple[GameSession, UserSession] | None:
        """The matchmaking UserSession whose name ends in userSessions/<session_id>, with its
        GameSession."""
        suffix = f"/userSessions/{session_id}"
        for session in self.sessions.values():
            for user_session in session.user_sessions.values():
                if user_session.name.endswith(suffix):
                    return session, user_session
        return None

    def find_session(self, call: Call, name: str) -> GameSession:
        self.prune_sessions()
        session = self.sessions.get(self.resolve(call, name))
        if session is None:
            raise GrpcError(NOT_FOUND, f"{name} not found")
        return session

    def visible_session(self, call: Call, name: str) -> GameSession:
        """find_session, but in client-certificate mode only a session the caller may see
        (session_visible); others look missing."""
        session = self.find_session(call, name)
        if not self.session_visible(call, session):
            raise GrpcError(NOT_FOUND, f"{name} not found")
        return session

    def owned_ticket(self, call: Call, name: str) -> CreationTicket:
        """A creation ticket; in client-certificate mode only for the account of a user it was
        created for."""
        ticket = self.tickets.get(self.resolve(call, name))
        if ticket is None or (call.principal is not None and not any(
                self.owns(call, Msg(definition).get_str(1)) for definition in ticket.definitions)):
            raise GrpcError(NOT_FOUND, f"{name} not found")
        return ticket

    def encode_session(self, call: Call, session: GameSession) -> bytes:
        """A GameSession message. In client-certificate mode the password only goes to accounts
        with a user in the session, so that it guards JoinGameSession."""
        if call.principal is None:
            return session.encode()
        return session.encode(reveal_password=any(self.owns(call, user) for user in session.user_sessions))

    def create_game_session_creation_ticket(self, call: Call, req: Msg) -> bytes:
        self.prune_sessions()
        parent = self.resolve(call, req.get_str(1))
        ticket_request = req.get_msg(2) or Msg()
        definitions = self.user_definitions(call, ticket_request.get_raws(3))
        req_session = ticket_request.get_msg(6) or Msg()
        now = time.time_ns()
        if len(req_session.get_bytes(11) or b"") > MAX_SESSION_PROPERTIES_BYTES:
            raise GrpcError(INVALID_ARGUMENT, "game session properties are over the limit")
        check_name(req_session.get_str(6))
        session = GameSession(f"{parent}/gameSessions/{random_id()}", self.max_players, now,
                              GAMESYNC_HOST, self.gamesync_port,
                              password=req_session.get_str(6),
                              properties_raw=req_session.get_bytes(11),
                              creator=Msg(definitions[0]).get_str(1) if definitions else "")
        matched = self.join(call, session, definitions, now)
        self.sessions[session.name] = session
        ticket = CreationTicket(f"{parent}/gameSessionCreationTickets/{random_id()}",
                                ticket_request.get_str(2), definitions, session, matched,
                                TICKET_PENDING)
        self.tickets[ticket.name] = ticket
        log.info("created %s for %s", session.name, ", ".join(session.user_sessions) or "-")
        return ticket.encode()

    async def track_game_session_creation_ticket(self, call: Call, req: Msg) -> AsyncIterator[bytes]:
        ticket = self.owned_ticket(call, req.get_str(1))
        if ticket.state == TICKET_PENDING:
            ticket.state = TICKET_SUCCEEDED
        yield ticket.encode()

    def cancel_game_session_creation_ticket(self, call: Call, req: Msg) -> bytes:
        ticket = self.owned_ticket(call, req.get_str(1))
        ticket.state = TICKET_CANCELLED
        for definition in ticket.definitions:
            self.drop_user_session(ticket.session, self.resolve(call, Msg(definition).get_str(1)))
        return b""

    def get_game_session(self, call: Call, req: Msg) -> bytes:
        return self.encode_session(call, self.visible_session(call, req.get_str(1)))

    def query_game_sessions(self, call: Call, req: Msg) -> bytes:
        self.prune_sessions()
        tenant = self.resolve(call, req.get_str(1))
        min_vacancy = req.get_int(4)
        filters = map_entries(req.get_bytes(6))
        users = {self.resolve(call, user) for user in req.get_strs(7)}
        found = [
            session for session in self.sessions.values()
            if (not tenant or session.name.startswith(tenant + "/"))
            and session.max_participants - len(session.user_sessions) >= min_vacancy
            and (not users or users & session.user_sessions.keys())
            and session_matches(session, filters)
            and self.session_visible(call, session)
        ]
        return encode(*[(1, self.encode_session(call, session)) for session in found])

    def join_game_session(self, call: Call, req: Msg) -> bytes:
        session = self.visible_session(call, req.get_str(1))
        definitions = self.user_definitions(call, req.get_raws(3))
        # Client-certificate mode: newcomers need the session password (field 2).
        if call.principal is not None and session.password and any(
                Msg(definition).get_str(1) not in session.user_sessions for definition in definitions) \
                and not self.check_password(call, session.password, req.get_str(2), f"session {session.name}"):
            raise GrpcError(PERMISSION_DENIED, "wrong password")
        matched = self.join(call, session, definitions, time.time_ns())
        log.info("joined %s: %s", session.name, ", ".join(session.user_sessions))
        return encode(*[(1, entry) for entry in matched], (2, self.encode_session(call, session)))

    def list_user_sessions(self, call: Call, req: Msg) -> bytes:
        self.prune_sessions()
        user = self.resolve(call, req.get_str(1))
        if "/users/" not in user:
            caller = self.require_caller(call)
            user = caller["sub"] if caller else ""
        elif not self.owns(call, user):
            raise GrpcError(PERMISSION_DENIED, f"{user} belongs to another account")
        return encode(*[(1, session.user_sessions[user].encode()) for session in self.sessions.values()
                        if user in session.user_sessions])

    def allocate_ice_server_set(self, call: Call, req: Msg) -> bytes:
        tenant = self.resolve(call, req.get_str(1))
        stun = None
        if self.stun:
            host, _, port = self.stun.rpartition(":")
            stun = encode((1, host), (2, int(port)), (3, STUN_PROTOCOL_UDP))
        return encode(
            (1, f"{tenant}/iceServerSets/{random_id()}"),
            (2, stun),
            (4, duration(ICE_SERVER_TTL_SECONDS)),
            (5, timestamp(time.time_ns())),
            (6, duration(ICE_SERVER_TTL_SECONDS)),
        )

    # nn.npln.gamesync.v1.Gamesync: live documents shared by the players of a game session. They
    # are kept in memory; islands themselves are persisted through Ugcstore.

    def encode_gamesync_token(self, call: Call, user: str, user_session: str) -> bytes:
        now = int(time.time())
        own = self.owner_claims(call)
        access = self.signer.issue(typ="gamesync", sub=user, user_session=user_session, iat=now,
                                   exp=now + TOKEN_TTL_SECONDS, **own)
        refresh = self.signer.issue(typ="gamesync_refresh", sub=user, user_session=user_session,
                                    iat=now, jti=secrets.token_hex(8), **own)
        token = encode((1, user_session), (2, access), (3, refresh), (4, duration(TOKEN_TTL_SECONDS)))
        return encode((1, token))

    def gamesync_issue_token(self, call: Call, req: Msg) -> bytes:
        claims = self.verify_token(call, req.get_str(2), "matchmaking")
        if claims is None or not self.owns(call, claims["sub"]):
            raise GrpcError(UNAUTHENTICATED, "invalid matchmaking id token")
        user_session = self.resolve(call, req.get_str(1)) or claims["user_session"]
        return self.encode_gamesync_token(call, claims["sub"], user_session)

    def gamesync_refresh_token(self, call: Call, req: Msg) -> bytes:
        claims = self.verify_token(call, req.get_str(2), "gamesync_refresh")
        if claims is None or not self.owns(call, claims["sub"]):
            raise GrpcError(UNAUTHENTICATED, "invalid refresh token")
        return self.encode_gamesync_token(call, claims["sub"], claims["user_session"])

    def gamesync_member(self, user: str, name: str) -> tuple[GameSession, UserSession] | None:
        """The game session and matchmaking UserSession named `name`, a full
        tenants/<t>/gameSessions/<s>/userSessions/<id> or a relative userSessions/<id>, if that user
        session is still in its game session and belongs to `user`."""
        relative = name.startswith("userSessions/")
        session_id = name[len("userSessions/"):] if relative else name.rpartition("/userSessions/")[2]
        if not ID_PATTERN.fullmatch(session_id):
            return None
        found = self.find_user_session(session_id)
        if found is None or found[1].user != user or not (relative or found[1].name == name):
            return None
        return found

    def gamesync_route(self, call: Call) -> tuple[GameSession, UserSession]:
        """The game session whose gamesync state a call uses, and the caller's user session in it:
        the user session its gamesync token was issued for, which must still be in its game session
        and belong to the token's user. Otherwise the call fails; it never reaches the gamesync
        state of another game session."""
        claims = self.caller(call, "gamesync")
        if claims is None:
            raise GrpcError(UNAUTHENTICATED, "invalid gamesync token")
        name = claims.get("user_session") or ""
        found = self.gamesync_member(claims.get("sub") or "", name)
        if found is None:
            raise GrpcError(NOT_FOUND, f"user session {name!r} is not in a game session")
        return found

    def gamesync_read(self, space: GamesyncSpace, name: str, transaction: bytes | None) -> dict | None:
        """Reads a document, recording its version when the read belongs to a transaction (at most
        MAX_TRANSACTION_READS documents per transaction)."""
        doc = space.docs.get(name)
        if transaction:
            entry = space.transactions.get(transaction)
            if entry is None:
                raise GrpcError(INVALID_ARGUMENT, "transaction is invalid or has expired")
            if name not in entry[1]:
                check_name(name)
                if len(entry[1]) >= MAX_TRANSACTION_READS:
                    raise GrpcError(RESOURCE_EXHAUSTED, "the transaction reads too many documents")
                entry[1][name] = doc["update_time"] if doc else None
        return doc

    def gamesync_get_document(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        name = self.resolve(call, req.get_str(1))
        doc = self.gamesync_read(space, name, req.get_bytes(3))
        if doc is None:
            raise GrpcError(NOT_FOUND, f"{name} not found")
        return encode_document(name, doc, req.get_msg(2))

    def gamesync_read_documents(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        mask, transaction = req.get_msg(2), req.get_bytes(3)
        results = []
        for name in [self.resolve(call, name) for name in req.get_strs(1)]:
            doc = self.gamesync_read(space, name, transaction)
            results.append(encode((1, encode_document(name, doc, mask))) if doc else encode((2, name)))
        return encode(*[(1, result) for result in results], (2, timestamp(time.time_ns())))

    def gamesync_list_documents(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        prefix = self.resolve(call, req.get_str(1)).rstrip("/") + "/"
        found: dict[str, dict | None] = {}
        for name, doc in space.docs.items():
            if not name.startswith(prefix):
                continue
            doc_id, nested, _ = name[len(prefix):].partition("/")
            if not nested:
                found[prefix + doc_id] = doc
            elif req.get_bool(5):  # show_missing: parents that only hold subcollections
                found.setdefault(prefix + doc_id, None)
        page, next_token = paginate(sorted(found), req.get_int(2), req.get_str(3))
        mask = req.get_msg(4)
        documents = [encode_document(name, found[name], mask) if found[name] else encode((1, name))
                     for name in page]
        return encode(*[(1, document) for document in documents], (2, next_token or None))

    def gamesync_query_collection_ids(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        document = self.resolve(call, req.get_str(1)).rstrip("/")
        prefix = f"{document}/" if document else ""
        collection_ids = set()
        for name in space.docs:
            if name.startswith(prefix):
                collection_id, nested, _ = name[len(prefix):].partition("/")
                if nested:
                    collection_ids.add(collection_id)
        page, next_token = paginate(sorted(collection_ids), req.get_int(2), req.get_str(3))
        return encode(*[(1, collection_id) for collection_id in page], (2, next_token or None))

    def gamesync_write_documents(self, call: Call, req: Msg) -> bytes:
        session, member = self.gamesync_route(call)
        results, now = self.gamesync_commit(session.gamesync, member.name, call, req.get_msgs(1),
                                            req.get_msgs(2))
        return encode(*[(1, result) for result in results], (2, timestamp(now)))

    def gamesync_lazy_write_documents(self, call: Call, req: Msg) -> bytes:
        session, member = self.gamesync_route(call)
        # LazyWriteOperation numbers merge_document 1 and transform_document 2; WriteOperation
        # numbers them 2 and 3.
        writes = [Msg(encode((2, op.get_bytes(1)), (3, op.get_bytes(2)))) for op in req.get_msgs(1)]
        _, now = self.gamesync_commit(session.gamesync, member.name, call, writes, [])
        return encode((1, timestamp(now)))

    def gamesync_begin_transaction(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        now = time.monotonic()
        for transaction, (begun, _) in list(space.transactions.items()):
            if now - begun > GAMESYNC_TRANSACTION_SECONDS:
                del space.transactions[transaction]
        if len(space.transactions) >= MAX_GAMESYNC_TRANSACTIONS:
            raise GrpcError(RESOURCE_EXHAUSTED, "the game session has too many open transactions")
        transaction = secrets.token_bytes(16)
        space.transactions[transaction] = (now, {})
        return encode((1, transaction))

    def gamesync_commit_transaction(self, call: Call, req: Msg) -> bytes:
        session, member = self.gamesync_route(call)
        space = session.gamesync
        entry = space.transactions.pop(req.get_bytes(3) or b"", None)
        if entry is None:
            raise GrpcError(INVALID_ARGUMENT, "transaction is invalid or has expired")
        for name, update_time in entry[1].items():
            doc = space.docs.get(name)
            if (doc["update_time"] if doc else None) != update_time:
                raise GrpcError(ABORTED, f"{name} changed during the transaction")
        results, now = self.gamesync_commit(space, member.name, call, req.get_msgs(1), req.get_msgs(2))
        return encode(*[(1, result) for result in results], (2, timestamp(now)))

    def gamesync_rollback_transaction(self, call: Call, req: Msg) -> bytes:
        self.gamesync_route(call)[0].gamesync.transactions.pop(req.get_bytes(1) or b"", None)
        return b""

    def gamesync_create_round(self, call: Call, req: Msg) -> bytes:
        # Round's fields are undocumented; the created round is the requested one.
        return req.get_bytes(1) or b""

    def gamesync_commit(self, space: GamesyncSpace, owner: str, call: Call, writes: Iterable[Msg],
                        deferments: list[Msg]) -> tuple[list[bytes], int]:
        """Applies WriteOperations and DefermentOperations atomically to one game session's gamesync
        state and notifies its watchers. The deferments stored belong to user session `owner`.
        `writes` are applied in order as they are taken, so they may be parsed one at a time."""
        now = time.time_ns()
        staging = Staging(space.docs)
        staged_globals = dict(space.globals)
        results = [self.gamesync_apply_write(call, op, staging, staged_globals, now) for op in writes]
        staged_deferments = dict(space.deferments)
        kept = deferment_call(call) if deferments else call
        for op in deferments:
            if (update := op.get_msg(1)) is not None:
                name = self.resolve(call, (update.get_msg(1) or Msg()).get_str(1))
                staged_deferments[name] = (owner, kept, update.get_bytes(1) or b"")
            elif (delete := op.get_msg(2)) is not None:
                staged_deferments.pop(self.resolve(call, delete.get_str(1)), None)
            else:
                raise GrpcError(INVALID_ARGUMENT, "empty deferment operation")

        # Gamesync state lives in memory, so one game session may only hold so much of it:
        # documents, global values and deferred writes, names included.
        for name in [*staging.changes, *staged_globals.keys() - space.globals.keys(),
                     *staged_deferments.keys() - space.deferments.keys()]:
            check_name(name)
        size, records = gamesync_size({**space.docs, **staging.changes}, staged_globals, staged_deferments)
        if size > MAX_GAMESYNC_BYTES or records > MAX_GAMESYNC_RECORDS:
            raise GrpcError(RESOURCE_EXHAUSTED, "the game session's gamesync data is over the limit")
        created = {name for name, doc in staging.changes.items() if doc is not None and name not in space.docs}
        space.globals = staged_globals
        space.deferments = staged_deferments
        for name, doc in staging.changes.items():
            if doc is None:
                space.docs.pop(name, None)
            else:
                space.docs[name] = doc
        self.gamesync_notify(space, staging.changes, created)
        if staging.changes:
            log.info("gamesync committed %d write(s) by %s: %s", len(results), owner,
                     ", ".join(staging.changes))
            log_gamesync_sdp(staging.changes, owner)
        return results, now

    def gamesync_apply_write(self, call: Call, op: Msg, staging: Staging, globals_: dict[str, bytes],
                             now: int) -> bytes:
        """Stages one gamesync WriteOperation and returns its WriteResult."""
        if (update := op.get_msg(1)) is not None:
            document = update.get_msg(1) or Msg()
            name = self.resolve(call, document.get_str(1))
            doc = staging.get(name)
            check_precondition(name, doc, update.get_msg(3))
            entries = masked_entries(doc, map_entries(document.get_bytes(2)), update.get_msg(2))
            staging.put(name, updated_document(doc, now, entries))
            return encode((1, b""))  # UpdateResult

        if (merge := op.get_msg(2)) is not None:
            document = merge.get_msg(1) or Msg()
            name = self.resolve(call, document.get_str(1))
            doc = staging.get(name)
            entries = merge_entries(doc_entries(doc), map_entries(document.get_bytes(2)))
            staging.put(name, updated_document(doc, now, entries))
            return encode((1, b""))  # UpdateResult

        if (transform := op.get_msg(3)) is not None:
            name = self.resolve(call, transform.get_str(1))
            doc = staging.get(name)
            entries = doc_entries(doc)
            results = []
            for field_transform in transform.get_msgs(2):
                entries, result = gamesync_transform(entries, field_transform, globals_, now)
                results.append(result)
            staging.put(name, updated_document(doc, now, entries))
            return encode((2, encode(*[(1, result) for result in results])))  # TransformResult

        if (delete := op.get_msg(4)) is not None:
            name = self.resolve(call, delete.get_str(1))
            check_precondition(name, staging.get(name), delete.get_msg(2))
            staging.put(name, None)
            return encode((3, b""))  # DeleteResult

        raise GrpcError(INVALID_ARGUMENT, "empty write operation")

    def gamesync_notify(self, space: GamesyncSpace, changes: dict[str, dict | None], created: set[str]) -> None:
        for watcher in space.watchers:
            for name, doc in changes.items():
                for target_id in watcher.targets:
                    if not watcher.covers(target_id, name):
                        continue
                    if doc is None:
                        change = encode((1, wire_target_id(target_id)), (2, DOCUMENT_CHANGE_DELETED),
                                        (3, encode((1, name))))
                    else:
                        kind = DOCUMENT_CHANGE_EXIST if name in created else DOCUMENT_CHANGE_UPDATED
                        change = encode((1, wire_target_id(target_id)), (2, kind), (3, encode_document(name, doc)))
                    watcher.send(encode((2, change)))

    def gamesync_watch(self, call: Call, watcher: GamesyncWatcher, target: Msg) -> None:
        """Registers a Target, acknowledges it (UPDATED), then sends the documents it covers and
        marks it listed. A call keeps at most MAX_WATCH_TARGETS targets of at most
        MAX_TARGET_DOCUMENTS names each."""
        docs = watcher.session.gamesync.docs
        target_id = target.get_str(1)
        documents = frozenset(self.resolve(call, name) for name in (target.get_msg(2) or Msg()).get_strs(1))
        collection = self.resolve(call, (target.get_msg(3) or Msg()).get_str(1)).rstrip("/")
        for name in [target_id, collection, *documents]:
            check_name(name)
        if len(documents) > MAX_TARGET_DOCUMENTS or (
                target_id not in watcher.targets and len(watcher.targets) >= MAX_WATCH_TARGETS):
            raise GrpcError(RESOURCE_EXHAUSTED, "too many watch targets")
        watcher.targets[target_id] = (documents, collection)
        wire_id = wire_target_id(target_id)
        watcher.send(encode((3, encode((1, wire_id), (2, TARGET_CHANGE_UPDATED)))))
        covered = [name for name in sorted(docs) if watcher.covers(target_id, name)]
        for name in covered:
            document = encode_document(name, docs[name])
            change = encode((1, wire_id), (2, DOCUMENT_CHANGE_EXIST), (3, document))
            watcher.send(encode((2, change)))
        watcher.send(encode((3, encode((1, wire_id), (2, TARGET_CHANGE_LISTED)))))
        missing = sorted(documents.difference(docs))
        log.info("KeepUserSession %s: target %r lists %d document(s)%s%s", watcher.member.name,
                 target_id, len(covered), f": {', '.join(covered)}" if covered else "",
                 f"; missing: {', '.join(missing)}" if missing else "")

    def gamesync_join(self, session: GameSession, member: UserSession) -> None:
        """Creates or refreshes the docs/__us document of a user session that opened KeepUserSession:
        active (st), under a new connection sequence id (ucsid), with the user, attributes (att) and
        team (tn) of its matchmaking UserSession. ltc is left out; its format is unknown. Also
        creates the docs/__gs/f and docs/__gs/m documents of its game session if they do not exist
        yet."""
        space = session.gamesync
        now = time.time_ns()
        # common.Value fields: boolean_value 2, integer_value 3, string_value 7, map_value 10.
        seeds = {
            GAMESYNC_GAME_SESSION_FIXED_DOC: {
                "gsid": encode((7, session.name.rpartition("/")[2])),
                "addr": encode((7, session.host)),
                "p": encode((3, session.port)),
                "maxu": encode((3, session.max_participants)),
            },
            GAMESYNC_GAME_SESSION_MUTABLE_DOC: {
                "cp": encode((2, True)),
                "ip": encode((2, True)),
                "pw": encode((7, session.password)),
                "prp": encode((10, session.properties_raw or b"")),
            },
        }
        for doc_name, seed in seeds.items():
            if doc_name in space.docs:
                continue
            space.docs[doc_name] = updated_document(None, now, seed)
            self.gamesync_notify(space, {doc_name: space.docs[doc_name]}, {doc_name})
            log.info("gamesync created %s for %s", doc_name, session.name)
        name = GAMESYNC_USER_SESSION_DOCS + member.name.rpartition("/")[2]
        definition = Msg(member.definition)
        doc = space.docs.get(name)
        entries = doc_entries(doc)
        if "ussid" not in entries:
            entries["ussid"] = encode((3, next(space.sequence)))
        entries["ucsid"] = encode((3, next(space.sequence)))
        entries["uid"] = encode((7, member.user.rpartition("/")[2]))
        entries["st"] = encode((3, USER_SESSION_ACTIVE))
        entries.setdefault("att", encode((10, definition.get_bytes(2) or b"")))
        entries.setdefault("tn", encode((7, definition.get_str(4))))
        space.docs[name] = updated_document(doc, now, entries)
        self.gamesync_notify(space, {name: space.docs[name]}, set() if doc else {name})
        log.info("gamesync %s %s for %s: uid=%s ussid=%d ucsid=%d", "refreshed" if doc else "created",
                 name, session.name, Msg(entries["uid"]).get_str(7) or "-",
                 Msg(entries["ussid"]).get_int(3), Msg(entries["ucsid"]).get_int(3))

    def gamesync_fire_deferments(self, space: GamesyncSpace, user_session: str) -> None:
        """Applies the deferred writes of a user session whose KeepUserSession call ended or that
        left its game session, one deferment and one write at a time.

        They were admitted against the game session's Gamesync limit when they were stored, so
        they are parsed outside the request budget of whichever call this runs in
        (request_budget): request data that other calls hold, or that the ending call holds, must
        not cost the game session writes it already accepted. That parsing is still bounded: a
        deferment came in one gRPC message (MAX_GRPC_MESSAGE_BYTES), and the deferments are applied
        without yielding, so no other one is parsed meanwhile. A deferment whose writes fail on
        their own (malformed or empty, a failed precondition, the Gamesync limit) is logged and
        dropped: its user session may be gone, so nothing would try it again."""
        token = request_budget.set(None)
        try:
            for name, (owner, call, deferment) in list(space.deferments.items()):
                if owner != user_session:
                    continue
                del space.deferments[name]
                try:
                    writes = (Msg(write) for write in Msg(deferment).get_raws(2))
                    self.gamesync_commit(space, owner, call, writes, [])
                except (GrpcError, ValueError) as exc:
                    log.warning("deferment %s of %s failed: %s", name, user_session, exc)
                else:
                    log.info("applied deferment %s of %s", name, user_session)
        finally:
            request_budget.reset(token)

    async def keep_user_session(self, call: Call, requests: AsyncIterator[Msg]) -> AsyncIterator[bytes]:
        try:
            session, member = self.gamesync_route(call)
        except GrpcError:
            log.warning("KeepUserSession refused; metadata: %s", ", ".join(sorted(call.metadata)) or "-")
            raise
        space = session.gamesync
        if sum(1 for other in space.watchers if other.member is member) >= MAX_WATCHERS_PER_MEMBER:
            raise GrpcError(RESOURCE_EXHAUSTED, f"{member.name} has too many KeepUserSession calls open")
        watcher = GamesyncWatcher(session, member)
        space.watchers.add(watcher)
        log.info("KeepUserSession opened by %s for %s", member.user, member.name)

        async def receive() -> None:
            try:
                async for req in requests:
                    if watcher.error is not None:
                        return  # the server ended the call
                    log.info("KeepUserSession %s <- %s", member.name, describe_keep_user_session_request(req))
                    if named := self.resolve(call, req.get_str(1)):
                        found = self.gamesync_member(member.user, named)
                        if found is None or found[1] is not member:
                            raise GrpcError(PERMISSION_DENIED, f"{named} is not the user session of the gamesync token")
                        if not watcher.joined:
                            watcher.joined = True
                            self.gamesync_join(session, member)
                    if req.has(2):
                        watcher.send(encode((1, req.get_str(2))))  # echo
                    elif (update := req.get_msg(3)) is not None:
                        self.gamesync_watch(call, watcher, update.get_msg(1) or Msg())
                    elif (delete := req.get_msg(4)) is not None:
                        target_id = delete.get_str(1)
                        watcher.targets.pop(target_id, None)
                        change = encode((1, wire_target_id(target_id)), (2, TARGET_CHANGE_DELETED))
                        watcher.send(encode((3, change)))
            finally:
                watcher.outbox.put_nowait(None)  # the client closed its side: end the call

        receiver = asyncio.create_task(receive())
        sent = 0
        try:
            while (message := await watcher.outbox.get()) is not None:
                watcher.queued -= len(message)
                log.info("KeepUserSession %s -> %s", member.name, describe_keep_user_session_response(message))
                sent += 1
                yield message
            if watcher.error is not None:
                raise watcher.error
            await receiver  # re-raises a malformed request
        finally:
            if not receiver.done() or receiver.cancelled():
                reason = "the call was cancelled"
            elif (exc := receiver.exception()) is not None:
                reason = exc.message if isinstance(exc, GrpcError) else f"malformed request: {exc}"
            else:
                reason = "the client closed its side"
            if watcher.error is not None:
                reason = watcher.error.message
            receiver.cancel()
            space.watchers.discard(watcher)
            log.info("KeepUserSession %s ended (%s) after %d response(s); targets: %s",
                     member.name, reason, sent, ", ".join(watcher.targets) or "-")
            self.gamesync_fire_deferments(space, member.name)
            member.last_seen = time.time_ns()

    # Subscriptions the game keeps open; nothing is ever announced on them.

    async def subscribe_maintenance_schedules(self, call: Call, req: Msg) -> AsyncIterator[bytes]:
        while True:
            yield encode((2, b""))  # KeepAlive
            await asyncio.sleep(KEEP_ALIVE_SECONDS)

    async def subscribe_friend_users(self, call: Call, req: Msg) -> AsyncIterator[bytes]:
        while True:
            yield encode((3, duration(KEEP_ALIVE_SECONDS)))  # keep_alive_interval, no friends
            await asyncio.sleep(KEEP_ALIVE_SECONDS)


# --- gRPC over HTTP/2 -------------------------------------------------------------------------


def decode_grpc_message(flags: int, payload: bytes, encoding: str, limit: int) -> bytes:
    """One gRPC message, decompressed if its flags say so; refused once it passes `limit` bytes,
    which decompression stops at."""
    if not flags & 1:
        if len(payload) > limit:
            raise ValueError("gRPC request messages are over the limit")
        return payload
    if encoding == "gzip":
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decompressor = zlib.decompressobj()
    else:
        raise ValueError(f"unsupported grpc-encoding {encoding!r}")
    message = decompressor.decompress(payload, limit + 1)
    if len(message) > limit:
        raise ValueError("decompressed gRPC request messages are over the limit")
    if not decompressor.eof:
        raise ValueError("truncated compressed gRPC message")
    return message


def take_grpc_frames(buffer: bytearray, encoding: str, limit: int = MAX_GRPC_MESSAGE_BYTES) -> list[bytes]:
    """Removes the complete length-prefixed messages from the front of `buffer` and returns them.
    A message over MAX_GRPC_MESSAGE_BYTES, compressed or not, is refused as soon as its header or
    its decompressed output shows it, and so are messages that together decode to more than
    `limit` bytes: many small compressed messages cannot add up to more."""
    messages = []
    decoded = 0
    while len(buffer) >= 5:
        size = int.from_bytes(buffer[1:5], "big")
        if size > MAX_GRPC_MESSAGE_BYTES:
            raise ValueError(f"gRPC message of {size} bytes is over the limit")
        if len(buffer) < 5 + size:
            break
        flags = buffer[0]
        payload = bytes(buffer[5 : 5 + size])
        del buffer[: 5 + size]
        message = decode_grpc_message(flags, payload, encoding, min(MAX_GRPC_MESSAGE_BYTES, limit - decoded))
        decoded += len(message)
        messages.append(message)
    return messages


def single_grpc_message(body: bytes, encoding: str) -> bytes:
    """The request message of a unary or server-streaming call: empty for an empty body. The body
    must hold exactly one complete message; anything else is refused before more than that one
    message is decoded."""
    if not body:
        return b""
    if len(body) < 5 or len(body) != 5 + int.from_bytes(body[1:5], "big"):
        raise ValueError("the request must hold exactly one gRPC message")
    return decode_grpc_message(body[0], body[5:], encoding, MAX_GRPC_MESSAGE_BYTES)


class GrpcInbound:
    """The request messages of a bidirectional call, delivered as they arrive. Bytes still being
    decoded and decoded messages not yet read count against the connection's request budgets, its
    own and all connections' (H2Session.count). Once more than MAX_INBOUND_QUEUE_BYTES of them
    wait, the call fails, and so it does with RESOURCE_EXHAUSTED once decoding (decompression)
    would take the budgets past their limits; once it is over (discard) nothing more is kept. A
    message read (messages) counts as a parsed Msg from then on, for as long as anything holds it."""

    def __init__(self, encoding: str, session: H2Session):
        self.encoding = encoding
        self.session = session
        self.buffer = bytearray()
        self.queue: asyncio.Queue[bytes | Exception | None] = asyncio.Queue()
        self.queued = 0  # decoded messages and their per-entry overhead
        self.failed = False

    def size(self) -> int:
        return len(self.buffer) + self.queued

    def counted(self, before: int) -> None:
        """Moves the connection's budgets by how much this call's size changed since it was `before`."""
        self.session.count(self.size() - before)

    def fail(self, error: Exception) -> None:
        self.failed = True
        self.buffer.clear()
        while not self.queue.empty():
            self.queue.get_nowait()
        self.queued = 0
        self.queue.put_nowait(error)

    def feed(self, data: bytes) -> None:
        """Takes a piece of the call's request data, which on_event has made sure fits the budgets,
        and queues the messages it completes, decoded."""
        if self.failed:
            return
        before = self.size()
        room = self.session.request_room()  # how much this call's size may grow by
        self.buffer += data
        try:
            # What one batch decodes is bounded by the room left in the queue, not only per message,
            # and is checked against the budgets before any of it is queued or counted.
            messages = take_grpc_frames(self.buffer, self.encoding, MAX_INBOUND_QUEUE_BYTES - self.queued)
            held = self.size() + sum(len(message) + INBOUND_MESSAGE_OVERHEAD for message in messages)
            if held > MAX_INBOUND_QUEUE_BYTES:
                raise ValueError("too many request messages wait to be read")
            if held - before > room:
                raise GrpcError(RESOURCE_EXHAUSTED, "too much request data in flight")
            for message in messages:
                self.queue.put_nowait(message)
                self.queued += len(message) + INBOUND_MESSAGE_OVERHEAD
        except GrpcError as exc:
            self.fail(exc)
        except (ValueError, zlib.error) as exc:
            self.fail(ValueError(f"malformed request: {exc}"))
        self.counted(before)

    def close(self) -> None:
        if not self.failed:
            self.queue.put_nowait(ValueError("truncated gRPC frame") if self.buffer else None)

    def discard(self) -> None:
        """The call is over or the connection closed: drop what waits and ignore further data."""
        before = self.size()
        if not self.failed:
            self.fail(ConnectionError("the call is over"))
        self.counted(before)

    async def messages(self) -> AsyncIterator[Msg]:
        """The messages, parsed. Each moves from the queue's count to its own as a Msg (against the
        handling connection's budgets) before it is yielded, and this generator lets go of it as
        soon as the handler asks for the next one, so what stays counted is what the handler keeps."""
        while (item := await self.queue.get()) is not None:
            if isinstance(item, Exception):
                raise item
            before = self.size()
            self.queued -= len(item) + INBOUND_MESSAGE_OVERHEAD
            self.counted(before)
            if log.isEnabledFor(logging.DEBUG):
                log.debug("stream request:\n%s", dump(item, 1))
            message = Msg(item)
            del item
            yield message
            del message


class H2Stream:
    """The response side of one gRPC call."""

    def __init__(self, session: H2Session, stream_id: int):
        self.session = session
        self.stream_id = stream_id
        self.headers_sent = False

    async def send_message(self, payload: bytes) -> None:
        if not self.headers_sent:
            self.session.send_headers(self.stream_id, [(":status", "200"), ("content-type", "application/grpc")])
            self.headers_sent = True
        await self.session.send_data(self.stream_id, b"\0" + len(payload).to_bytes(4, "big") + payload)

    def finish(self, code: int, message: str = "") -> None:
        trailers = [("grpc-status", str(code))]
        if message:
            trailers.append(("grpc-message", quote(message, safe=GRPC_MESSAGE_SAFE)))
        if not self.headers_sent:  # trailers-only response
            trailers = [(":status", "200"), ("content-type", "application/grpc"), *trailers]
        self.session.send_headers(self.stream_id, trailers, end_stream=True)


class H2Session:
    def __init__(self, server: Server, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 principal: Principal | None = None):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")
        self.conn = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        self.requests: dict[int, tuple[dict[str, str], bytearray]] = {}
        self.inbound: dict[int, GrpcInbound] = {}  # bidirectional calls still receiving
        self.tasks: dict[int, asyncio.Task] = {}
        self.window_waiters: list[asyncio.Future] = []
        self.closed = False
        self.principal = principal  # the connection's account in client-certificate mode
        # Request data held: bodies (take_body_data), bidirectional calls' queued data (GrpcInbound)
        # and parsed messages (Msg).
        self.buffered = 0
        self.overloaded = ""  # why the connection is being closed for breaking a limit
        self.pending = 0  # response bytes handed to send_data and not yet sent; see send_data
        self.downloads = 0  # storage downloads being sent; see send_file

    def flush(self) -> None:
        data = self.conn.data_to_send()
        if data:
            self.writer.write(data)

    def send_headers(self, stream_id: int, headers: list[tuple[str, str]], end_stream: bool = False) -> None:
        self.conn.send_headers(stream_id, headers, end_stream=end_stream)
        self.flush()

    async def send_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        """Sends response data as the client's flow-control window allows. Data waiting this way
        is limited per connection and across connections, and a stream whose client grants no
        window for SEND_STALL_SECONDS is reset."""
        view = memoryview(data)
        if (self.pending + len(view) > MAX_RESPONSE_BYTES_PER_CONNECTION
                or self.server.pending + len(view) > MAX_PENDING_RESPONSE_BYTES):
            self.reset(stream_id)
            raise ConnectionError("too much response data waits to be sent")
        self.pending += len(view)
        self.server.pending += len(view)
        stalled_since = None
        try:
            while len(view):
                if self.closed:
                    raise ConnectionError("connection closed")
                size = min(self.conn.local_flow_control_window(stream_id), self.conn.max_outbound_frame_size, len(view))
                if size <= 0:
                    now = time.monotonic()
                    stalled_since = now if stalled_since is None else stalled_since
                    if now - stalled_since >= SEND_STALL_SECONDS:
                        self.reset(stream_id)
                        raise ConnectionError("the client stopped reading")
                    waiter = asyncio.get_running_loop().create_future()
                    self.window_waiters.append(waiter)
                    try:
                        await asyncio.wait_for(waiter, SEND_STALL_SECONDS - (now - stalled_since))
                    except asyncio.TimeoutError:
                        pass
                    continue
                stalled_since = None
                self.conn.send_data(stream_id, bytes(view[:size]))
                view = view[size:]
                self.pending -= size
                self.server.pending -= size
                self.flush()
                await drain(self.writer)
            if end_stream:
                self.conn.end_stream(stream_id)
                self.flush()
        finally:
            self.pending -= len(view)
            self.server.pending -= len(view)

    def reset(self, stream_id: int, code: int = h2.errors.ErrorCodes.CANCEL) -> None:
        """Resets a stream, unless it is already closed."""
        try:
            self.conn.reset_stream(stream_id, error_code=code)
        except h2.exceptions.ProtocolError:
            return
        self.flush()

    async def send_file(self, stream_id: int, result: Response, head_only: bool) -> None:
        """Sends a storage response whose body streams from an open blob file, a piece at a time."""
        file, offset, length = result.stream
        self.downloads += 1
        self.server.downloads += 1
        try:
            self.send_headers(stream_id, [(":status", str(result.status)), *result.headers],
                              end_stream=head_only or not length)
            if head_only:
                return
            file.seek(offset)
            while length:
                chunk = file.read(min(DOWNLOAD_CHUNK_BYTES, length))
                if not chunk:
                    log.warning("blob %s is shorter than its recorded size", file.name)
                    self.reset(stream_id)
                    return
                length -= len(chunk)
                await self.send_data(stream_id, chunk, end_stream=not length)
        finally:
            file.close()
            self.downloads -= 1
            self.server.downloads -= 1

    def wake_senders(self) -> None:
        for waiter in self.window_waiters:
            if not waiter.done():
                waiter.set_result(None)
        self.window_waiters.clear()

    async def run(self, initial: bytes = b"") -> None:
        self.conn.initiate_connection()
        self.flush()
        data = initial
        try:
            while True:
                if data:
                    try:
                        events = self.conn.receive_data(data)
                    except h2.exceptions.ProtocolError as exc:
                        log.warning("HTTP/2 protocol error from %s: %s", self.peer, exc)
                        self.flush()
                        return
                    for event in events:
                        self.on_event(event)
                    if self.overloaded:
                        log.warning("closing HTTP/2 connection from %s: %s", self.peer, self.overloaded)
                        self.conn.close_connection(error_code=h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
                        self.flush()
                        return
                    self.flush()
                data = await self.reader.read(65536)
                if not data:
                    return
        except (ConnectionError, OSError):
            pass
        finally:
            for stream_id in list(self.requests):
                self.release(stream_id)
            for inbound in self.inbound.values():
                inbound.discard()
            self.closed = True
            self.wake_senders()
            for task in self.tasks.values():
                task.cancel()
            self.writer.close()

    def on_event(self, event: h2.events.Event) -> None:
        if self.overloaded:
            return  # the connection is closing; nothing more from it is processed
        if isinstance(event, h2.events.RequestReceived):
            headers = dict(event.headers)
            if (headers.get("content-type", "").startswith("application/grpc")
                    and headers.get(":path") in self.server.backend.bidi):
                # Bidirectional calls start right away and receive their requests as they arrive.
                # What each holds counts against the connection's request budgets (GrpcInbound).
                if len(self.inbound) >= MAX_BIDI_CALLS_PER_CONNECTION:
                    self.overloaded = "too many bidirectional calls"
                    return
                inbound = GrpcInbound(headers.get("grpc-encoding", "identity"), self)
                self.inbound[event.stream_id] = inbound
                task = asyncio.create_task(self.dispatch(event.stream_id, headers, inbound))
                # A done callback runs even for a task cancelled before it started, which skips
                # dispatch's finally; so the call's queued bytes are always dropped and uncounted.
                task.add_done_callback(lambda _: inbound.discard())
                self.tasks[event.stream_id] = task
            else:
                self.requests[event.stream_id] = (headers, bytearray())
        elif isinstance(event, h2.events.DataReceived):
            if inbound := self.inbound.get(event.stream_id):
                # Data a failed call ignores is not held; see GrpcInbound.feed for what decoding adds.
                if not inbound.failed and len(event.data) > self.request_room():
                    self.overloaded = "too much request data in flight"
                    return
                inbound.feed(event.data)
            elif request := self.requests.get(event.stream_id):
                self.take_body_data(request, event.data)
            self.conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        elif isinstance(event, h2.events.StreamEnded):
            if inbound := self.inbound.pop(event.stream_id, None):
                inbound.close()
            elif request := self.requests.pop(event.stream_id, None):
                # The body stays counted (self.buffered, Server.buffered) until its call is over,
                # however long the response waits for the client; see uncount.
                headers, body = request
                size = len(body)
                task = asyncio.create_task(self.dispatch(event.stream_id, headers, bytes(body)))
                task.add_done_callback(lambda _: self.uncount(size))
                self.tasks[event.stream_id] = task
        elif isinstance(event, h2.events.StreamReset):
            self.release(event.stream_id)
            if inbound := self.inbound.pop(event.stream_id, None):
                inbound.discard()
            if task := self.tasks.pop(event.stream_id, None):
                task.cancel()
            self.wake_senders()
        elif isinstance(event, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)):
            self.wake_senders()
        elif isinstance(event, h2.events.ConnectionTerminated):
            self.closed = True
            self.wake_senders()

    def take_body_data(self, request: tuple[dict[str, str], bytearray], data: bytes) -> None:
        """Buffers data of a request body unless that would break a limit: one gRPC message
        (MAX_GRPC_MESSAGE_BYTES) or MAX_STORAGE_REQUEST_BYTES per request, and the request budgets,
        MAX_CONNECTION_BUFFER_BYTES per connection and MAX_BUFFERED_BYTES across connections, of
        bodies arriving or whose call is not over yet, bidirectional calls' queued data (GrpcInbound)
        and parsed messages (Msg). Breaking one closes the connection (run)."""
        headers, body = request
        grpc = headers.get("content-type", "").startswith("application/grpc")
        if len(body) + len(data) > (MAX_GRPC_MESSAGE_BYTES + 5 if grpc else MAX_STORAGE_REQUEST_BYTES):
            self.overloaded = "request body over the limit"
        elif (self.buffered + len(data) > MAX_CONNECTION_BUFFER_BYTES
              or self.server.buffered + len(data) > MAX_BUFFERED_BYTES):
            self.overloaded = "too much request data in flight"
        else:
            body.extend(data)
            self.buffered += len(data)
            self.server.buffered += len(data)

    def release(self, stream_id: int) -> tuple[dict[str, str], bytearray] | None:
        """Stops buffering a request body that is still arriving; returns the request if there was one."""
        request = self.requests.pop(stream_id, None)
        if request is not None:
            self.uncount(len(request[1]))
        return request

    def uncount(self, size: int) -> None:
        """Request data of `size` bytes is gone: a body was dropped or its call is over, or a parsed
        message (Msg) was let go."""
        self.buffered -= size
        self.server.buffered -= size

    def request_room(self) -> int:
        """Bytes of request data this connection may still hold, within its own and the global budget."""
        return min(MAX_CONNECTION_BUFFER_BYTES - self.buffered, MAX_BUFFERED_BYTES - self.server.buffered)

    def count(self, size: int) -> None:
        """Request data of `size` bytes is held: a parsed message (Msg), or what a bidirectional
        call holds grew (GrpcInbound; negative when it shrank)."""
        self.buffered += size
        self.server.buffered += size

    async def dispatch(self, stream_id: int, headers: dict[str, str], body: bytes | GrpcInbound) -> None:
        try:
            if headers.get("content-type", "").startswith("application/grpc"):
                await self.server.handle_grpc(H2Stream(self, stream_id), headers, body)
                return
            method = headers.get(":method", "")
            if method in ("GET", "HEAD") and (self.downloads >= MAX_DOWNLOADS_PER_CONNECTION
                                              or self.server.downloads >= MAX_DOWNLOADS):
                result = response(503, b"too many downloads at once\n")
            else:
                result = self.server.storage.handle(method, headers.get(":path", ""), headers, body,
                                                    self.principal)
            if result.stream is not None:
                await self.send_file(stream_id, result, method == "HEAD")
                return
            payload = b"" if method == "HEAD" else result.body
            self.send_headers(stream_id, [(":status", str(result.status)), *result.headers], end_stream=not payload)
            if payload:
                await self.send_data(stream_id, payload, end_stream=True)
        except (h2.exceptions.StreamClosedError, ConnectionError):
            pass
        finally:
            self.tasks.pop(stream_id, None)
            if isinstance(body, GrpcInbound):
                # The call is over: whatever its client still sends is dropped, not kept.
                body.discard()
                if self.inbound.pop(stream_id, None) is not None and not self.closed:
                    self.reset(stream_id, h2.errors.ErrorCodes.NO_ERROR)


# --- HTTP/1.1 (island storage only) ------------------------------------------------------------


async def drain(writer: asyncio.StreamWriter) -> None:
    """Waits for the transport to take what was written; a connection that takes nothing for
    SEND_STALL_SECONDS is closed."""
    try:
        await asyncio.wait_for(writer.drain(), SEND_STALL_SECONDS)
    except asyncio.TimeoutError:
        writer.close()
        raise ConnectionError("the client stopped reading") from None


async def send_file_http1(server: Server, conn: h11.Connection, writer: asyncio.StreamWriter,
                          result: Response, head_only: bool) -> None:
    """Sends a storage response whose body streams from an open blob file, a piece at a time."""
    file, offset, length = result.stream
    server.downloads += 1
    try:
        writer.write(conn.send(h11.Response(status_code=result.status, headers=result.headers)))
        if not head_only:
            file.seek(offset)
            while length:
                chunk = file.read(min(DOWNLOAD_CHUNK_BYTES, length))
                if not chunk:
                    raise ConnectionError(f"blob {file.name} is shorter than its recorded size")
                length -= len(chunk)
                writer.write(conn.send(h11.Data(data=chunk)))
                await drain(writer)
        writer.write(conn.send(h11.EndOfMessage()))
        await drain(writer)
    finally:
        file.close()
        server.downloads -= 1


async def serve_http1(server: Server, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      initial: bytes = b"", principal: Principal | None = None) -> None:
    conn = h11.Connection(h11.SERVER)
    if initial:
        conn.receive_data(initial)
    held = 0  # bytes of the body being received, counted in server.buffered

    async def refuse(reason: str) -> None:
        log.warning("refusing HTTP/1.1 request from %s: %s", writer.get_extra_info("peername"), reason)
        writer.write(conn.send(h11.Response(status_code=413, headers=[("content-length", "0"),
                                                                      ("connection", "close")])))
        writer.write(conn.send(h11.EndOfMessage()))
        await drain(writer)

    try:
        while True:
            request = None
            body = bytearray()
            while True:
                event = conn.next_event()
                if event is h11.NEED_DATA:
                    if conn.they_are_waiting_for_100_continue:
                        writer.write(conn.send(h11.InformationalResponse(status_code=100, headers=[])))
                    conn.receive_data(await reader.read(65536))
                elif isinstance(event, h11.Request):
                    request = event
                    length = next((value for name, value in event.headers if name == b"content-length"), b"0")
                    if int(length) > MAX_STORAGE_REQUEST_BYTES:
                        await refuse("request body over the limit")
                        return
                elif isinstance(event, h11.Data):
                    if len(body) + len(event.data) > MAX_STORAGE_REQUEST_BYTES:
                        await refuse("request body over the limit")
                        return
                    if server.buffered + len(event.data) > MAX_BUFFERED_BYTES:
                        await refuse("too much request data in flight")
                        return
                    body += event.data
                    held += len(event.data)
                    server.buffered += len(event.data)
                elif isinstance(event, h11.EndOfMessage):
                    break
                else:  # ConnectionClosed
                    return
            # The body stays counted in server.buffered until its response has been sent.
            data, body = bytes(body), bytearray()
            method = request.method.decode("ascii")
            headers = {name.decode("latin-1"): value.decode("latin-1") for name, value in request.headers}
            if method in ("GET", "HEAD") and server.downloads >= MAX_DOWNLOADS:
                result = response(503, b"too many downloads at once\n")
            else:
                result = server.storage.handle(method, request.target.decode("latin-1"), headers, data,
                                               principal)
            del data
            if result.stream is not None:
                await send_file_http1(server, conn, writer, result, method == "HEAD")
            else:
                writer.write(conn.send(h11.Response(status_code=result.status, headers=result.headers)))
                if method != "HEAD" and result.body:
                    writer.write(conn.send(h11.Data(data=result.body)))
                writer.write(conn.send(h11.EndOfMessage()))
                await drain(writer)
            server.buffered -= held
            held = 0
            if conn.our_state is not h11.DONE or conn.their_state is not h11.DONE:
                return
            conn.start_next_cycle()
    except h11.ProtocolError as exc:
        log.warning("HTTP/1.1 protocol error: %s", exc)
    except (ConnectionError, OSError):
        pass
    finally:
        server.buffered -= held
        writer.close()


# --- STUN -------------------------------------------------------------------------------------


def describe_stun_attributes(body: bytes) -> str:
    """Lists the attributes of a STUN message body for the log: USERNAME and SOFTWARE with their
    text, the others (MESSAGE-INTEGRITY is an HMAC) by name and length only. Anyone can send these,
    so at most STUN_LOGGED_ATTRIBUTES are described, texts are escaped and cut to 64 characters, and
    the result to STUN_LOG_LINE_CHARS."""
    described = []
    offset = 0
    while offset + 4 <= len(body):
        if len(described) == STUN_LOGGED_ATTRIBUTES:
            described.append("more attributes")
            break
        kind, length = struct.unpack_from("!HH", body, offset)
        name = STUN_ATTRIBUTE_NAMES.get(kind, f"0x{kind:04x}")
        if kind in (STUN_USERNAME, STUN_SOFTWARE):
            text = body[offset + 4 : offset + 4 + min(length, 64)].decode("utf-8", "backslashreplace")
            described.append(f"{name} {text!r}" + (f" ({length} bytes)" if length > 64 else ""))
        else:
            described.append(f"{name} ({length} bytes)")
        offset += 4 + (length + 3) // 4 * 4
    else:
        if offset < len(body):
            described.append(f"{len(body) - offset} trailing bytes")
    return (", ".join(described) or "no attributes")[:STUN_LOG_LINE_CHARS]


class StunResponder(asyncio.DatagramProtocol):
    """Answers STUN Binding requests with the sender's address, giving WebRTC peers their
    server-reflexive candidates without a public STUN server. Anyone can send to it, so it answers
    at most STUN_REQUESTS_PER_ADDRESS datagrams per source address and STUN_REQUESTS_TOTAL in total
    per second, and logs at most STUN_LOG_LINES_PER_MINUTE lines a minute plus a count of the rest."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.second = 0  # the current rate-limit second
        self.per_address: dict[str, int] = {}
        self.total = 0
        self.minute = 0  # the current log-budget minute
        self.logged = 0
        self.suppressed = 0
        self.dropped = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def allowed(self, address: str) -> bool:
        """Counts a datagram against the per-second limits; False if it must be dropped."""
        now = time.monotonic()
        if int(now) != self.second:
            self.second, self.total = int(now), 0
            self.per_address.clear()
        if int(now // 60) != self.minute:
            if self.suppressed or self.dropped:
                log.warning("STUN: %d log line(s) suppressed and %d datagram(s) dropped over the limits "
                            "in the last minute", self.suppressed, self.dropped)
            self.minute, self.logged, self.suppressed, self.dropped = int(now // 60), 0, 0, 0
        count = self.per_address.get(address, 0)
        if count >= STUN_REQUESTS_PER_ADDRESS or self.total >= STUN_REQUESTS_TOTAL:
            self.dropped += 1
            return False
        self.per_address[address] = count + 1
        self.total += 1
        return True

    def may_log(self) -> bool:
        """Takes one line of the per-minute log budget; once it is spent, counts the line as
        suppressed and returns False, so callers skip formatting it."""
        if self.logged < STUN_LOG_LINES_PER_MINUTE:
            self.logged += 1
            return True
        self.suppressed += 1
        return False

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if not self.allowed(addr[0]):
            return
        source = f"{addr[0]}:{addr[1]}"
        if len(data) < 20:
            self.ignored(data, source, "shorter than a STUN header")
            return
        kind, length, cookie = struct.unpack_from("!HHI", data)
        if kind != STUN_BINDING_REQUEST or cookie != STUN_MAGIC_COOKIE or len(data) < 20 + length:
            if kind != STUN_BINDING_REQUEST:
                reason = f"message type 0x{kind:04x}, not a Binding request"
            elif cookie != STUN_MAGIC_COOKIE:
                reason = f"cookie 0x{cookie:08x}, not the RFC 5389 magic cookie"
            else:
                reason = f"truncated: the header announces {length} attribute bytes"
            self.ignored(data, source, reason)
            return
        transaction = data[8:20]
        ip = ipaddress.ip_address(addr[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.version == 4:
            family, xor_ip = 1, (int(ip) ^ STUN_MAGIC_COOKIE).to_bytes(4, "big")
        else:
            mask = int.from_bytes(STUN_MAGIC_COOKIE.to_bytes(4, "big") + transaction, "big")
            family, xor_ip = 2, (int(ip) ^ mask).to_bytes(16, "big")
        value = struct.pack("!BBH", 0, family, addr[1] ^ (STUN_MAGIC_COOKIE >> 16)) + xor_ip
        attributes = struct.pack("!HH", STUN_XOR_MAPPED_ADDRESS, len(value)) + value
        # The length already counts FINGERPRINT, which covers everything before it.
        header = struct.pack("!HHI", STUN_BINDING_SUCCESS, len(attributes) + 8, STUN_MAGIC_COOKIE) + transaction
        fingerprint = zlib.crc32(header + attributes) ^ STUN_FINGERPRINT_XOR
        response = header + attributes + struct.pack("!HHI", STUN_FINGERPRINT, 4, fingerprint)
        self.transport.sendto(response, addr)
        if self.may_log():
            log.info("STUN Binding request from %s (transaction %s; %s) answered with XOR-MAPPED-ADDRESS %s:%d",
                     source, transaction.hex(), describe_stun_attributes(data[20 : 20 + length]), ip, addr[1])
        if log.isEnabledFor(logging.DEBUG):
            log.debug("STUN request from %s: %s; response: %s", source, data.hex(), response.hex())

    def ignored(self, data: bytes, source: str, reason: str) -> None:
        if self.may_log():
            log.info("STUN ignored %d-byte datagram from %s: %s", len(data), source, reason)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("STUN ignored datagram from %s: %s", source, data.hex())

    def error_received(self, exc: Exception) -> None:
        log.warning("STUN socket error: %r", exc)
        asyncio.get_running_loop().call_soon(self.check_reading)

    def check_reading(self) -> None:
        # The proactor (Windows) datagram transport of Python 3.10 issues no further receive after
        # a receive error such as the port-unreachable answer to a response sent to a closed port.
        transport = self.transport
        if transport is not None and not transport.is_closing() and getattr(transport, "_read_fut", True) is None:
            log.error("STUN responder no longer receives datagrams: asyncio stopped reading after that error")

    def connection_lost(self, exc: Exception | None) -> None:
        log.warning("STUN socket closed: %s", exc or "no error")


def advertised_stun(args: argparse.Namespace) -> str:
    """The STUN server AllocateIceServerSet hands out: --stun, else the built-in responder."""
    if args.stun or not args.stun_port:
        return args.stun
    host = "127.0.0.1" if args.bind in ("", "0.0.0.0", "::") else args.bind
    return f"{host}:{args.stun_port}"


# --- Backup snapshots -------------------------------------------------------------------------

SNAPSHOT_PROTOCOL = b"pokopia-snapshot 1"
SNAPSHOT_CHUNK_SIZE = 256 * 1024
# A snapshot client that takes no data for this long is dropped, closing the blobs held open for it.
# It is generous because the client may be streaming into a slow upload.
SNAPSHOT_STALL_SECONDS = 300


class SnapshotService:
    """Serves backup snapshots of the store over a Unix socket (--snapshot-socket, Linux only).

    A client that connects gets the status line "pokopia-snapshot 1 ok", "pokopia-snapshot 1 busy"
    or "pokopia-snapshot 1 denied". After "ok" comes a tar stream: data/state.json,
    data/blobs/<id> for each blob that state refers to, and last snapshot.json with the size and
    SHA-256 of each file and "damaged_blobs": every referenced blob whose file is missing or not the
    size the state records. Store.snapshot captures all of it at one moment, and other requests go
    on being served while it streams. Only root and the server's own user are served, one at a
    time. A failure closes the connection with the tar stream unfinished. snapshot.py is the client.
    """

    def __init__(self, store: Store):
        self.store = store
        self.busy = False

    async def on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            credentials = writer.get_extra_info("socket").getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", credentials)
            if uid not in (0, os.geteuid()):
                log.warning("snapshot refused to uid %d", uid)
                writer.write(SNAPSHOT_PROTOCOL + b" denied\n")
            elif self.busy:
                writer.write(SNAPSHOT_PROTOCOL + b" busy\n")
            else:
                self.busy = True
                try:
                    await self.send(writer)
                finally:
                    self.busy = False
        except (OSError, asyncio.TimeoutError) as exc:
            log.warning("snapshot not sent: %r", exc)
        finally:
            writer.close()

    async def send(self, writer: asyncio.StreamWriter) -> None:
        created = time.time()
        state, blobs, damaged = self.store.snapshot()
        try:
            sent = 0
            files: dict[str, dict] = {}

            async def put(data: bytes) -> None:
                nonlocal sent
                sent += len(data)
                writer.write(data)
                await asyncio.wait_for(writer.drain(), SNAPSHOT_STALL_SECONDS)

            async def add(name: str, size: int, read: Callable[[int, int], bytes]) -> None:
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = size, int(created), 0o600
                await put(info.tobuf(tarfile.PAX_FORMAT))
                digest = hashlib.sha256()
                offset = 0
                while offset < size:
                    chunk = read(offset, min(SNAPSHOT_CHUNK_SIZE, size - offset))
                    if not chunk:
                        raise OSError(f"{name} ended after {offset} of {size} bytes")
                    digest.update(chunk)
                    offset += len(chunk)
                    await put(chunk)
                await put(bytes(-size % tarfile.BLOCKSIZE))
                files[name] = {"size": size, "sha256": digest.hexdigest()}

            writer.write(SNAPSHOT_PROTOCOL + b" ok\n")
            await add("data/state.json", len(state), lambda offset, n: state[offset : offset + n])
            for blob_id, fd, size in blobs:
                await add(f"data/blobs/{blob_id}", size, lambda offset, n, fd=fd: os.pread(fd, n, offset))
            if damaged:
                log.warning("snapshot: damaged blobs: %s", "; ".join(damaged))
            manifest = json.dumps({"format": 1, "created": created, "files": files,
                                   "damaged_blobs": damaged}, indent=1).encode()
            await add("snapshot.json", len(manifest), lambda offset, n: manifest[offset : offset + n])
            end = bytes(2 * tarfile.BLOCKSIZE)
            await put(end + bytes(-(sent + len(end)) % tarfile.RECORDSIZE))
            log.info("snapshot sent: state, %d blob(s), %d bytes", len(blobs), sent)
        finally:
            for _, fd, _ in blobs:
                os.close(fd)


def raise_open_file_limit() -> None:
    """A snapshot holds every blob open, so lift the soft open-file limit (often 1024) to the hard one."""
    import resource  # Unix only

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


# --- Server -----------------------------------------------------------------------------------


class Server:
    def __init__(self, args: argparse.Namespace):
        self.store = Store(args.data_dir)
        self.storage = Storage(self.store, args.storage_url.rstrip("/"))
        self.storage.max_bytes = args.max_storage_mb * 1024 * 1024
        self.backend = Backend(self.store, self.storage, args.max_players, advertised_stun(args),
                               args.gamesync_port or (args.port or DEFAULT_TLS_PORTS)[0])
        # Client-certificate mode: whose each device certificate is. None in local mode.
        self.auth = AuthRegistry(args.auth_db) if args.client_ca else None
        self.connections: dict[str, int] = {}  # open connections per account
        self.buffered = 0  # request bytes held, queued (GrpcInbound) or parsed (Msg), all connections
        self.pending = 0  # response bytes waiting for clients' flow-control windows, all connections
        self.downloads = 0  # storage downloads being sent, all connections

    async def handle_grpc(self, stream: H2Stream, headers: dict[str, str], body: bytes | GrpcInbound) -> None:
        path = headers.get(":path", "")
        call = Call(path, headers, stream.session.principal, network_of(stream.session.peer))
        log.info("%s uid=%s tenant=%s", path, headers.get("uid", "-"), headers.get("npln-tenant-id", "-"))
        # Messages parsed while handling this call, the request and whatever the handler parses,
        # count against this connection for as long as they are held (Msg).
        request_budget.set(stream.session)
        request = Msg()
        if isinstance(body, GrpcInbound):
            responses = self.backend.bidi[path](call, body.messages())
        else:
            try:
                payload = single_grpc_message(body, headers.get("grpc-encoding", "identity"))
            except (ValueError, zlib.error) as exc:
                log.warning("%s: malformed request: %s", path, exc)
                stream.finish(INVALID_ARGUMENT, f"malformed request: {exc}")
                return
            try:
                request = Msg(payload)
            except ValueError as exc:
                log.warning("%s: malformed request field: %s", path, exc)
                stream.finish(INVALID_ARGUMENT, str(exc))
                return
            except GrpcError as exc:
                log.warning("%s: refused: %s", path, exc.message)
                stream.finish(exc.code, exc.message)
                return
            if log.isEnabledFor(logging.DEBUG):
                log.debug("request:\n%s", dump(payload, 1))
            del payload  # the parsed request holds copies of what it needs
            server_stream = self.backend.streams.get(path)
            responses = server_stream(call, request) if server_stream else None

        try:
            if responses is not None:
                del request  # the generator holds it as long as it needs it
                async with contextlib.aclosing(responses):
                    async for message in responses:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug("stream message:\n%s", dump(message, 1))
                        await stream.send_message(message)
            else:
                handler = self.backend.unary.get(path)
                if handler is None:
                    log.warning("no handler for %s; answering with an empty message", path)
                response_payload = handler(call, request) if handler else b""
                del request  # not held while the response waits for the client
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("response:\n%s", dump(response_payload, 1))
                await stream.send_message(response_payload)
            stream.finish(OK)
        except GrpcError as exc:
            log.info("%s -> %s: %s", path, STATUS_NAMES.get(exc.code, exc.code), exc.message)
            stream.finish(exc.code, exc.message)
        except ValueError as exc:
            log.warning("%s: malformed request field: %s", path, exc)
            stream.finish(INVALID_ARGUMENT, str(exc))
        except (h2.exceptions.StreamClosedError, ConnectionError, asyncio.CancelledError):
            raise
        except Exception:
            log.exception("%s failed", path)
            stream.finish(INTERNAL, "internal error")

    async def on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        watchdog = None
        account = None  # counted in self.connections
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            principal = None
            if self.auth is not None:
                cert = ssl_object.getpeercert(binary_form=True) if ssl_object else None
                principal = self.auth.principal(cert)
                if principal is None:
                    log.warning("connection from %s refused: its device certificate is unknown, revoked "
                                "or expired, or its account is disabled", peer)
                    writer.close()
                    return
                if self.connections.get(principal.account, 0) >= MAX_CONNECTIONS_PER_ACCOUNT:
                    log.warning("connection from %s refused: account %s has too many connections",
                                peer, principal.account)
                    writer.close()
                    return
                account = principal.account
                self.connections[account] = self.connections.get(account, 0) + 1
                log.debug("connection from %s is device %s of %s", peer, principal.device, principal.account)
                watchdog = asyncio.create_task(self.watch_device(cert, writer))
            alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
            initial = b"" if alpn else await reader.read(len(HTTP2_PREFACE_START))
            log.debug("connection from %s (alpn=%s)", peer, alpn)
            if alpn == "h2" or initial.startswith(HTTP2_PREFACE_START):
                await H2Session(self, reader, writer, principal).run(initial)
            else:
                await serve_http1(self, reader, writer, initial, principal)
        except (asyncio.IncompleteReadError, OSError) as exc:
            # Clients that connect and drop (reachability probes, retries) end up here. OSError
            # covers ConnectionResetError and ssl.SSLError.
            log.debug("connection from %s dropped: %s", peer, exc)
            writer.close()
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if account is not None:
                self.connections[account] -= 1
                if not self.connections[account]:
                    del self.connections[account]

    async def watch_device(self, cert: bytes, writer: asyncio.StreamWriter) -> None:
        """Closes a client-certificate connection once its device stops counting (revoked, expired
        or its account disabled); AuthRegistry notices within CACHE_SECONDS."""
        while not writer.is_closing():
            await asyncio.sleep(AuthRegistry.CACHE_SECONDS)
            if self.auth.principal(cert) is None:
                log.warning("closing a connection of device certificate %s: no longer authorized",
                            hashlib.sha256(cert).hexdigest()[:16])
                writer.close()
                return

    async def purge_deleted_accounts(self) -> None:
        """Client-certificate mode: purges the game data of accounts deleted on the portal
        (`portal.py delete`), at startup and then every minute."""
        while True:
            deleted = self.auth.deleted_accounts()
            if deleted:
                owners = {user.get("owner") for user in self.store.users.values()}
                owners.update(upload.get("owner") for upload in self.store.uploads.values())
                for account in deleted & owners:
                    self.backend.purge_account(account)
            await asyncio.sleep(60)


def tls_context(cert: Path, key: Path, client_ca: Path | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2", "http/1.1"])
    if client_ca is not None:
        # Client-certificate mode: the handshake fails unless the client presents a certificate the
        # device CA (portal.py) issued; AuthRegistry then decides whose it is.
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=client_ca)

    def log_sni(ssl_object: ssl.SSLObject, server_name: str | None, ctx: ssl.SSLContext) -> None:
        # Handshakes that fail after this line usually mean the client rejected the certificate.
        log.info("TLS handshake for %s", server_name)

    context.sni_callback = log_sni
    return context


async def serve(args: argparse.Namespace) -> None:
    server = Server(args)
    context = tls_context(args.cert, args.key, args.client_ca)
    purger = None  # holds the purge task, which the event loop only references weakly
    if server.auth is not None:
        log.info("client-certificate mode: device CA %s, accounts in %s", args.client_ca, args.auth_db)
        purger = asyncio.create_task(server.purge_deleted_accounts())
    listeners = []
    for port in args.port or DEFAULT_TLS_PORTS:
        listeners.append(await asyncio.start_server(server.on_connection, args.bind, port, ssl=context))
        log.info("gRPC + storage (TLS) on %s:%d", args.bind, port)
    if args.http_port:
        listeners.append(await asyncio.start_server(server.on_connection, args.bind, args.http_port))
        log.info("storage (plain HTTP) on %s:%d", args.bind, args.http_port)
    if args.stun_port:
        await asyncio.get_running_loop().create_datagram_endpoint(
            StunResponder, local_addr=(args.bind, args.stun_port))
        log.info("STUN (UDP) on %s:%d", args.bind, args.stun_port)
    if args.snapshot_socket:
        raise_open_file_limit()
        snapshots = SnapshotService(server.store)
        listeners.append(await asyncio.start_unix_server(snapshots.on_connection, args.snapshot_socket))
        os.chmod(args.snapshot_socket, 0o600)
        log.info("backup snapshots on %s", args.snapshot_socket)
    log.info("AllocateIceServerSet hands out STUN server %s", server.backend.stun or "(none)")
    log.info("upload/download URIs use %s; data in %s", server.storage.base_url, args.data_dir)
    # Short sleeps keep Ctrl+C responsive on Windows.
    while True:
        await asyncio.sleep(1)


def main() -> None:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Local NPLN backend for Pokemon Pokopia Cloud Islands.")
    parser.add_argument("--bind", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, action="append",
                        help="TLS port for gRPC and storage; repeatable (default 443 and 8443)")
    parser.add_argument("--http-port", type=int, default=0, help="also serve storage over plain HTTP")
    parser.add_argument("--storage-url", default="https://storage.npln.nintendo.net",
                        help="base URL of issued upload/download URIs")
    parser.add_argument("--cert", type=Path, default=here / "server.crt")
    parser.add_argument("--key", type=Path, default=here / "server.key")
    parser.add_argument("--data-dir", type=Path, default=here / "data")
    parser.add_argument("--max-players", type=int, default=4, help="game session capacity")
    parser.add_argument("--stun", default="",
                        help="host:port handed out by AllocateIceServerSet instead of the built-in "
                             "STUN responder, e.g. stun.l.google.com:19302")
    parser.add_argument("--stun-port", type=int, default=3478,
                        help="UDP port of the built-in STUN responder; 0 disables it (default 3478)")
    parser.add_argument("--client-ca", type=Path,
                        help="client-certificate mode: accept only connections with a certificate from "
                             "this CA (portal.py's device-ca.crt) and authorize every call by the account "
                             "of that device; needs --auth-db")
    parser.add_argument("--auth-db", type=Path, help="portal.py's account database, opened read-only")
    parser.add_argument("--gamesync-port", type=int, default=0,
                        help="Gamesync port handed to clients (default: the first --port); 443 when "
                             "clients connect through launcher.py")
    parser.add_argument("--insecure-no-auth", action="store_true",
                        help="allow a non-loopback --bind without --client-ca, for a trusted LAN only")
    parser.add_argument("--max-storage-mb", type=int, default=DEFAULT_MAX_STORAGE_BYTES // 1024 ** 2,
                        help="all Ugcstore documents, attachments and uploads together (default 10240)")
    parser.add_argument("-v", "--verbose", action="store_true", help="dump message payloads")
    parser.add_argument("--snapshot-socket", type=Path,
                        help="serve backup snapshots to root and this user on this Unix socket (Linux)")
    args = parser.parse_args()
    if args.snapshot_socket and not hasattr(socket, "SO_PEERCRED"):
        parser.error("--snapshot-socket needs Linux")
    if args.stun and not args.stun.rpartition(":")[2].isdigit():
        parser.error("--stun must be host:port")
    if (args.client_ca is None) != (args.auth_db is None):
        parser.error("--client-ca and --auth-db go together")
    if args.auth_db is not None and not args.auth_db.is_file():
        parser.error(f"--auth-db {args.auth_db} does not exist; portal.py serve creates it")
    if args.client_ca is not None and args.http_port:
        parser.error("--http-port cannot be used with --client-ca: plain HTTP carries no client certificate")
    try:
        loopback = args.bind == "localhost" or ipaddress.ip_address(args.bind).is_loopback
    except ValueError:
        loopback = False
    if args.client_ca is None and not loopback and not args.insecure_no_auth:
        parser.error("without --client-ca anyone who reaches the server can act as any user; a "
                     "non-loopback --bind needs --client-ca and --auth-db, or --insecure-no-auth "
                     "for a trusted LAN")
    if args.max_storage_mb <= 0:
        parser.error("--max-storage-mb must be positive")
    if os.name == "posix":
        os.umask(0o077)  # state.json, blobs and temporary files are secret (see Store)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    for noisy in ("asyncio", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
