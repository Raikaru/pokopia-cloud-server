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
  * Live story co-op quest events over HTTP/1.1 or HTTP/2 at /campaign/live, client-certificate
    mode only (CampaignLive): a game session's creator posts quest state transitions for its
    members, and /campaign/live/proposals queues untrusted guest changes for the creator.
    Both are memory-only (LiveJournal). Neither starting state nor durable checkpoints are served.

A UDP STUN responder (default port 3478) is the ICE server AllocateIceServerSet hands out, so
WebRTC peers on this PC gather candidates without reaching a public STUN server. Every datagram it
receives is logged with its source, and every Binding response with the address it reports.
With --turn and --turn-secret-file it also hands out a TURN server (coturn use-auth-secret) with
credentials that expire with the ICE server set (TurnServer). --relay-only, on top of that, passes
every gamesync document a player reads or watches through RelayOnly, which leaves only relay
candidates on that TURN server in session descriptions and drops what else may be signaling.

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
USER_SESSION_GRACE_SECONDS, or when its user joins another game session. Its KeepUserSession calls
end, then its deferred writes are applied and the gamesync documents named after it are deleted.
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
import functools
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
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, BinaryIO, Callable, Iterable, NamedTuple
from urllib.parse import parse_qsl, quote, urlsplit

import campaign_store

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
# How long the credentials AllocateIceServerSet hands out for --turn work: as long as the ICE server
# set says it is valid. coturn refuses them for new allocations once they expire, but keeps the
# allocations already made with them (coturn issue #1204).
TURN_CREDENTIAL_SECONDS = ICE_SERVER_TTL_SECONDS
MIN_TURN_SECRET_BYTES = 16
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
# Parsed messages applying one Gamesync deferment may hold, outside the budgets of every
# connection: what one connection may hold, so a deferment parses as its call could have.
MAX_DEFERMENT_PARSE_BYTES = MAX_CONNECTION_BUFFER_BYTES
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
MAX_FIELD_DEPTH = 20  # segments of a document field path, and levels of maps one merge goes into
STATE_OVERHEAD_BYTES = 128  # what a record adds to state.json beside its names and fields
MAX_SESSION_PROPERTIES_BYTES = 64 * 1024  # a game session's properties; the game's were 0.4 KB
# Live story co-op quest events and guest proposals (CampaignLive). A session keeps the last
# MAX_LIVE_EVENTS of each, with at most MAX_LIVE_BATCH per POST or poll. The guest queue also
# limits distinct producers per epoch; quest ids and states are restricted to the game's ranges.
CAMPAIGN_LIVE_PATH = "/campaign/live"
CAMPAIGN_PROPOSALS_PATH = "/campaign/live/proposals"
MAX_LIVE_EVENTS = 1024
MAX_LIVE_BATCH = 64
MAX_LIVE_PRODUCERS = 64
MAX_LIVE_SEQUENCE = (1 << 53) - 1
MAX_LIVE_REQUEST_BYTES = 16 * 1024  # the body of one POST; MAX_LIVE_BATCH events take about 2 KB
MAX_QUEST_ID = 1000
MAX_QUEST_STATE = 4
# One game session's Gamesync state in memory. Documents, global values and deferred writes, names
# included, may take MAX_GAMESYNC_BYTES in MAX_GAMESYNC_RECORDS records. Transactions and watch
# targets have fixed caps, so with names of at most MAX_NAME_BYTES they stay within about 8 MiB
# (transactions) and 1 MiB per KeepUserSession call (targets).
MAX_GAMESYNC_BYTES = 16 * 1024 * 1024
MAX_GAMESYNC_RECORDS = 4096
# What one Gamesync commit, or the deferred writes of a user session applied together, may copy and
# produce (GamesyncWork): twice what a game session holds, so one commit may rewrite all of it.
MAX_GAMESYNC_COMMIT_BYTES = 2 * MAX_GAMESYNC_BYTES
MAX_GAMESYNC_READ_BYTES = 2 * MAX_GAMESYNC_BYTES  # work and results of one Gamesync read
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

# Relay-only delivery (--relay-only, RelayOnly). A gamesync value is looked into when its encoded
# bytes hold SIGNALING_BYTES anywhere; a string or bytes value that is not a session description is
# dropped when its text holds SIGNALING_TEXT. Session descriptions are taken apart line by line
# (SDP_LINE) and only lines known to carry no address of the player are passed on.
SIGNALING_BYTES = re.compile(rb"(?i)candidate|raddr|rport|IN\s+IP[46]|typ\s+(?:host|srflx|prflx|relay)|v=\d")
SIGNALING_TEXT = re.compile(rb"(?i)candidate|\braddr\b|\brport\b|\bIN\s+IP[46]\b"
                            rb"|\btyp\s+(?:host|srflx|prflx|relay)\b|(?:\A|\n)\W{0,8}v=\d")
MAX_SDP_BYTES = 64 * 1024
MAX_SDP_LINES = 256
MAX_SIGNALING_DEPTH = 16  # levels of maps and arrays looked into, as sdp_values
SDP_LINE = re.compile(rb"([a-z])=([\x20-\x7e]*)")
SDP_ORIGIN = re.compile(rb"\S{1,64} ([A-Za-z0-9+/=_-]{1,64}) (\d{1,20}) IN IP[46] \S{1,64}")
SDP_TIMING = re.compile(rb"\d{1,20} \d{1,20}")
SDP_MEDIA = re.compile(rb"([a-z][a-z0-9-]{0,31}) (\d{1,5})(?:/\d{1,5})? "
                       rb"([A-Za-z0-9/_-]{1,64}(?: [A-Za-z0-9_-]{1,64}){0,64})")
SDP_BANDWIDTH = re.compile(rb"[A-Za-z-]{1,16}:\d{1,10}")
SDP_KEPT_ATTRIBUTES = re.compile(rb"""(?x)
    end-of-candidates | ice-lite | ice-mismatch | rtcp-mux | rtcp-rsize | extmap-allow-mixed
    | sendrecv | sendonly | recvonly | inactive
    | ice-(?:ufrag|pwd):[A-Za-z0-9+/]{1,256}
    | ice-options:[A-Za-z0-9+/_-]{1,64}(?:\ [A-Za-z0-9+/_-]{1,64}){0,8}
    | setup:(?:actpass|active|passive|holdconn)
    | fingerprint:[A-Za-z0-9-]{1,16}\ (?:[0-9A-Fa-f]{2}:){15,63}[0-9A-Fa-f]{2}
    | mid:[A-Za-z0-9_-]{1,32}
    | group:[A-Za-z0-9_-]{1,32}(?:\ [A-Za-z0-9_-]{1,32}){0,32}
    | sctp-port:\d{1,5} | max-message-size:\d{1,20}
    | tls-id:[A-Za-z0-9+/=_-]{1,255}
""")
SDP_CANDIDATE = re.compile(rb"candidate:([A-Za-z0-9+/]{1,32}) (\d{1,3}) ([A-Za-z]{1,16}) (\d{1,10}) (\S{1,64}) "
                           rb"(\d{1,5}) typ ([a-z]{1,16})((?: \S{1,64} \S{1,256}){0,16})")
# Candidate extensions passed on, with their values; raddr and rport are replaced, others dropped.
SDP_CANDIDATE_EXTENSIONS = {
    b"generation": re.compile(rb"\d{1,10}"),
    b"network-id": re.compile(rb"\d{1,10}"),
    b"network-cost": re.compile(rb"\d{1,10}"),
    b"ufrag": re.compile(rb"[A-Za-z0-9+/]{1,256}"),
}

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


# The request budgets the current task's parsed messages count against (Msg): the connection
# (H2Session) whose call it is handling, set by Server.handle_grpc and inherited by tasks the
# handler starts, or a ParseBudget of its own while a deferred Gamesync write is applied
# (Backend.gamesync_apply_queued). None elsewhere: at startup, in tests and in background tasks.
request_budget: contextvars.ContextVar[H2Session | ParseBudget | None] = contextvars.ContextVar(
    "request_budget", default=None)


class ParseBudget:
    """Request budgets (request_budget) for messages parsed outside any call: they may hold `size`
    bytes (message_cost) at once, whatever the connections hold, and count against nothing else."""

    def __init__(self, size: int) -> None:
        self.left = size

    def request_room(self) -> int:
        return self.left

    def count(self, size: int) -> None:
        self.left -= size

    def uncount(self, size: int) -> None:
        self.left += size


def message_cost(size: int, fields: int) -> int:
    """What a parsed message of `size` bytes and `fields` fields counts against request budgets."""
    return MSG_BASE_BYTES + size + MSG_FIELD_BYTES * fields


class Msg:
    """A message decoded without its schema: field number -> (wire type, value) in wire order.

    A message holds Python objects for each field, many times the bytes it came from, so one
    parsed while request budgets apply (request_budget) counts message_cost against them from
    the moment it is parsed until the last reference to it goes (__del__):
    while a handler, a paused generator or a nested call still holds it, and no longer once a
    cancelled or finished call has dropped it. A message that would not fit is refused while it
    is parsed, with RESOURCE_EXHAUSTED, and one of more than MAX_MESSAGE_FIELDS fields is
    malformed (ValueError)."""

    def __init__(self, buf: bytes = b""):
        self.fields: dict[int, list[tuple[int, int | bytes]]] = {}
        self.budget: H2Session | ParseBudget | None = None  # what this message counts against, once parsed
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
    """Splits a dotted field path, honoring `quoted` segments. A path may have at most
    MAX_FIELD_DEPTH segments: its field is read and set one level at a time (set_field)."""
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
    if len(parts) > MAX_FIELD_DEPTH:
        raise GrpcError(INVALID_ARGUMENT, f"a field path has more than {MAX_FIELD_DEPTH} segments")
    return parts


def get_field(entries: dict[str, bytes], parts: list[str], work: GamesyncWork | None = None) -> bytes | None:
    """The field `parts` (split_field_path) of `entries`, or None. Every map above it is decoded;
    each costs `work` (Gamesync commits) its size before it is."""
    value = entries.get(parts[0])
    if len(parts) == 1 or value is None:
        return value
    if work is not None:
        work.spend(len(value))
    nested = Msg(value).get_bytes(10)  # Value.map_value
    return None if nested is None else get_field(map_entries(nested), parts[1:], work)


def set_field(entries: dict[str, bytes], parts: list[str], value: bytes | None,
              work: GamesyncWork | None = None) -> bool:
    """Sets the field in `entries`, or deletes it when `value` is None, and returns whether
    `entries` changed. Setting a nested field makes every field above it a map, replacing whatever
    else it held; deleting one changes nothing unless every field above it is a map and it is
    there. A nested field's maps are decoded and encoded again, from its own up to the one at the
    top of `entries`; each costs `work` (Gamesync commits), before it is decoded, its size twice and
    `value`."""
    if len(parts) == 1:
        if value is not None:
            entries[parts[0]] = value
            return True
        return entries.pop(parts[0], None) is not None
    current = entries.get(parts[0])
    if current is None and value is None:
        return False
    if work is not None:
        work.spend(2 * len(current or b"") + len(value or b""))
    inner = Msg(current).get_bytes(10) if current is not None else None  # Value.map_value
    if inner is None and value is None:
        return False  # the field above it holds no map, so it is not there to delete
    nested = map_entries(inner)
    if not set_field(nested, parts[1:], value, work):
        return False
    entries[parts[0]] = encode((10, encode_map(nested)))
    return True


def merge_entries(entries: dict[str, bytes], incoming: dict[str, bytes], work: GamesyncWork,
                  depth: int = 1) -> dict[str, bytes]:
    """Merges `incoming` into `entries`, recursing into fields that are maps on both sides, at most
    MAX_FIELD_DEPTH levels deep. Each map `incoming` holds for a field `entries` also has costs
    `work` both their sizes twice before either is decoded: both are decoded, and their merged map
    is encoded again."""
    merged = dict(entries)
    for key, value in incoming.items():
        current = merged.get(key)
        nested = Msg(value).get_bytes(10)  # Value.map_value
        if nested is not None and current is not None:
            work.spend(2 * (len(current) + len(value)))
            if (current_nested := Msg(current).get_bytes(10)) is not None:
                if depth >= MAX_FIELD_DEPTH:
                    raise GrpcError(INVALID_ARGUMENT, f"a merge goes more than {MAX_FIELD_DEPTH} maps deep")
                inner = merge_entries(map_entries(current_nested), map_entries(nested), work, depth + 1)
                value = encode((10, encode_map(inner)))
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


def apply_transform(entries: dict[str, bytes], parts: list[str], kind: str, operand: bytes | None,
                    now: int, work: GamesyncWork | None = None) -> bytes:
    """Applies a ugcstore FieldTransform to field `parts` (split_field_path) of `entries` and
    returns the resulting Value. Reading and setting a nested field costs `work` (Gamesync commits)
    the maps it decodes and encodes again (get_field, set_field)."""
    current = get_field(entries, parts, work)
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
    set_field(entries, parts, result, work)
    return result


def gamesync_transform(entries: dict[str, bytes], transform: Msg, globals_: dict[str, bytes], now: int,
                       work: GamesyncWork) -> bytes:
    """Applies a gamesync FieldTransform to `entries` and returns the resulting Value. It costs
    `work` that Value, which its WriteResult copies, and for a nested field the maps it decodes and
    encodes again, each before it does (get_field, set_field)."""
    path = transform.get_str(1)
    parts = split_field_path(path)
    kinds = {3: "increment", 4: "maximum", 5: "minimum"}
    number = next((n for n in kinds if transform.has(n)), None)
    if transform.has(2):  # set_server_value: REQUEST_TIME
        result = apply_transform(entries, parts, "request_time", None, now, work)
    elif number is not None:
        result = apply_transform(entries, parts, kinds[number], transform.get_bytes(number), now, work)
    elif transform.has(6):  # load_global_value: copies a global value into the field
        result = globals_.get(transform.get_str(6), NULL_VALUE)
        set_field(entries, parts, result, work)
    elif transform.has(7):  # store_global_value: copies the field into a global value
        result = get_field(entries, parts, work) or NULL_VALUE
        globals_[transform.get_str(7)] = result
    elif transform.has(8):  # clear_global_value
        result = globals_.pop(transform.get_str(8), NULL_VALUE)
    else:
        raise GrpcError(INVALID_ARGUMENT, f"empty transform for {path}")
    work.spend(len(result))
    return result


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


def doc_entries(doc: dict | None, work: GamesyncWork | None = None) -> dict[str, bytes]:
    """The fields of a stored document. Decoding them costs `work` (Gamesync commits) their size
    first."""
    if not doc:
        return {}
    if work is not None:
        work.spend(len(doc["fields"]))
    return map_entries(base64.b64decode(doc["fields"]))


def stored_fields_size(entries: dict[str, bytes]) -> int:
    """The size of the "fields" updated_document stores for `entries`, worked out without encoding
    them."""
    size = 0
    for key, value in entries.items():
        key_size = len(key.encode())
        entry = 2 + len(_varint(key_size)) + key_size + len(_varint(len(value))) + len(value)
        size += 1 + len(_varint(entry)) + entry
    return 4 * ((size + 2) // 3)  # base64


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


def masked_entries(doc: dict | None, incoming: dict[str, bytes], mask: Msg | None,
                   work: GamesyncWork | None = None) -> dict[str, bytes]:
    """The fields after an update: `incoming` replaces all of them, or only the masked paths.

    A missing or empty mask, or one holding the `*` wildcard, replaces every field. A masked path
    `incoming` lacks is deleted, if it is there (set_field). Decoding `doc` for a mask costs `work`
    (Gamesync commits) its fields (doc_entries), and a nested path the maps it decodes on both sides
    and encodes again, each before it does (get_field, set_field).
    """
    if mask is None:
        return incoming
    paths = mask.get_strs(1)
    if not paths or "*" in paths:
        return incoming
    entries = doc_entries(doc, work)
    for path in paths:
        parts = split_field_path(path)
        set_field(entries, parts, get_field(incoming, parts, work), work)
    return entries


def read_mask_paths(mask: Msg | None) -> list[str]:
    """Decode one read mask once, including for multi-document requests."""
    paths = mask.get_strs(1) if mask is not None else []
    return [] if "*" in paths else paths


def encode_document(name: str, doc: dict, paths: list[str] | None = None,
                    work: GamesyncReadWork | None = None, relay: RelayOnly | None = None) -> bytes:
    """Encodes a Document; a read mask (FieldMask) limits it to the listed field paths, and
    relay-only delivery (RelayOnly.fields) to what may reach a player.

    An empty mask, or one holding the `*` wildcard, returns every field.
    """
    if work is not None:
        work.spend(len(doc["fields"]) + len(name) + STATE_OVERHEAD_BYTES)
    fields = base64.b64decode(doc["fields"])
    if paths:
        entries = map_entries(fields)
        masked: dict[str, bytes] = {}
        for path in paths:
            parts = split_field_path(path)
            if work is not None:
                work.spend(STATE_OVERHEAD_BYTES + len(path) +
                           len(parts) * (len(entries.get(parts[0]) or b"") +
                                         len(masked.get(parts[0]) or b"")))
            value = get_field(entries, parts)
            if value is not None:
                set_field(masked, parts, value)
        fields = encode_map(masked)
    if relay is not None:
        fields = relay.fields(fields)
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
        self.stage_download_allowed: Callable[[Principal, str], bool] | None = None

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
        """Serves storage requests with account checks, including island attachment grants."""
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
        """Allow owned blobs and StageData attachments another account may read
        (Backend.stage_attachment_allowed)."""
        if principal is None:
            return True
        upload = self.store.uploads.get(blob_id)
        if upload is not None:
            return upload.get("owner") == principal.account
        for name, doc in self.store.documents.items():
            if (doc.get("attachment") or {}).get("blob") == blob_id:
                owner = self.store.users.get(document_owner(name) or "")
                if owner is not None and owner.get("owner") == principal.account:
                    return True
                if self.stage_download_allowed is not None and self.stage_download_allowed(principal, name):
                    return True
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


class Aliases(NamedTuple):
    """What the aliases in a call's names stand for (Backend.aliases): "tenants/current" for its
    npln-tenant-id metadata, "userSessions/current" for the user session its gamesync token was
    issued for and "users/current" for the user its access token, or else its gamesync token, was
    issued to. An alias with nothing to stand for (empty) stays as it is."""

    tenant_id: str = ""
    user_session: str = ""
    user_id: str = ""

    def expand(self, name: str) -> str:
        if self.tenant_id and (name == "tenants/current" or name.startswith("tenants/current/")):
            name = f"tenants/{self.tenant_id}{name[len('tenants/current'):]}"
        if self.user_session and (name == "userSessions/current" or name.startswith("userSessions/current/")):
            name = f"{self.user_session}{name[len('userSessions/current'):]}"
        if not self.user_id or "users/current" not in name:
            return name
        segments = name.split("/")
        for i in range(len(segments) - 1):
            if segments[i] == "users" and segments[i + 1] == "current":
                segments[i + 1] = self.user_id
        return "/".join(segments)


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
    # password_version of the password of the island its game session hosts when the user joined
    island_password_version: str = ""

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


class QueuedDeferment(NamedTuple):
    """A deferment taken from GamesyncSpace.deferments to be applied (Backend.gamesync_fire_deferments)."""

    name: str
    owner: str  # the user session that stored it
    aliases: Aliases  # what the aliases in its names stood for when it was stored
    deferment: bytes  # the Deferment message as received


class QueuedDeparture(NamedTuple):
    """User session `user_session` left: the Gamesync documents named after it are to be deleted,
    once the deferments queued before are applied (Backend.gamesync_fire_deferments)."""

    user_session: str


class GamesyncSpace:
    """The gamesync state of one game session. The game names documents without their game session
    (docs/__gs/f, docs/__us/<user session id>, ...), so each game session keeps its own documents,
    global values, transactions, deferments and KeepUserSession calls."""

    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}
        self.globals: dict[str, bytes] = {}
        # transaction -> (begin time, update_time of every document read in it; None if missing)
        self.transactions: dict[bytes, tuple[float, dict[str, int | None]]] = {}
        # deferment name -> (owning user session, what the aliases in its names stood for when it
        # was stored, the Deferment message as received, whose field 2 holds its WriteOperations).
        # It stays encoded until it is applied, so it holds the bytes it counts (gamesync_size) and
        # no list per write.
        self.deferments: dict[str, tuple[str, Aliases, bytes]] = {}
        self.watchers: set[GamesyncWatcher] = set()
        self.sequence = itertools.count(1)  # ussid and ucsid of docs/__us documents
        # What KeepUserSession calls that ended and user sessions that left still have to do here,
        # in order (Backend.gamesync_fire_deferments): apply deferments taken from `deferments`,
        # which count against the Gamesync limit until then (gamesync_size), and delete the
        # documents of a user session that left after its deferments. A task of the game session
        # (`applier`) works through it one entry per turn of the event loop.
        self.queue: deque[QueuedDeferment | QueuedDeparture] = deque()
        self.applier: asyncio.Task | None = None


class GamesyncWork:
    """What a Gamesync commit, a deferment applied on its own included
    (Backend.gamesync_apply_queued), may still copy and produce (MAX_GAMESYNC_COMMIT_BYTES). Every
    write costs STATE_OVERHEAD_BYTES and its document as staged; field transforms, masked paths and
    merges add the values and nested maps they copy, each before they copy them (gamesync_transform,
    masked_entries, merge_entries). A commit holds its WriteResults until it is over and applies
    its writes without yielding, so this bounds the memory it takes and how long other calls wait
    for it. Past it the commit fails with RESOURCE_EXHAUSTED and changes nothing."""

    def __init__(self) -> None:
        self.left = MAX_GAMESYNC_COMMIT_BYTES

    def spend(self, size: int) -> None:
        self.left -= size
        if self.left < 0:
            raise GrpcError(RESOURCE_EXHAUSTED, "the gamesync writes copy too much data")


class GamesyncReadWork:
    """Bounds copied data and nested mask work across one Gamesync read response."""

    def __init__(self) -> None:
        self.left = MAX_GAMESYNC_READ_BYTES

    def spend(self, size: int) -> None:
        self.left -= size
        if self.left < 0:
            raise GrpcError(RESOURCE_EXHAUSTED, "the gamesync read copies too much data")


def gamesync_size(docs: dict[str, dict | None], globals_: dict[str, bytes],
                  deferments: dict[str, tuple[str, Aliases, bytes]],
                  queued: Iterable[QueuedDeferment | QueuedDeparture] = ()) -> tuple[int, int]:
    """(bytes, records) of a game session's Gamesync documents, global values and deferred writes,
    stored or `queued` to be applied (GamesyncSpace.queue), names and per-record overhead included;
    documents staged as deleted (None) do not count. A deferment counts its encoded Deferment
    message, field keys and lengths included, so an empty write still costs what it holds, and the
    aliases it keeps."""
    held = [(name, aliases, deferment) for name, (_, aliases, deferment) in deferments.items()]
    held += [(entry.name, entry.aliases, entry.deferment) for entry in queued if isinstance(entry, QueuedDeferment)]
    size = sum(len(name) + len(doc["fields"]) + STATE_OVERHEAD_BYTES for name, doc in docs.items() if doc is not None)
    size += sum(len(key) + len(value) + STATE_OVERHEAD_BYTES for key, value in globals_.items())
    size += sum(len(name) + len(deferment) + sum(map(len, aliases)) + STATE_OVERHEAD_BYTES
                for name, aliases, deferment in held)
    return size, sum(1 for doc in docs.values() if doc is not None) + len(globals_) + len(held)


class LiveError(Exception):
    """A refused /campaign/live request (CampaignLive): its HTTP status, an error code the client
    acts on, a message for people and, where it matters, the bounds of the journal."""

    def __init__(self, status: int, code: str, message: str,
                 journal: LiveJournal | ProposalJournal | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.bounds = {"first": journal.first, "last": journal.last} if journal is not None else {}


@dataclass(frozen=True)
class ProposalChange:
    """One guest's natural quest change, before the host accepts or rejects it."""

    kind: str
    id: int
    old: int
    new: int
    field: str | None = None
    site: int | None = None

    def payload(self) -> dict:
        result = {"kind": self.kind, "id": self.id, "old": self.old, "new": self.new}
        if self.kind == "unique":
            result.update(field=self.field, site=self.site)
        return result


class ProposalJournal:
    """Bounded, session-local guest proposals. Per-producer sequence numbers make retries idempotent;
    the host consumes a separate global sequence. A producer belongs to its authenticated account."""

    def __init__(self) -> None:
        self.events: deque[tuple[str, int, ProposalChange]] = deque()
        self.retained: dict[tuple[str, int], ProposalChange] = {}
        self.producers: dict[str, tuple[str, int]] = {}
        self.last = 0

    @property
    def first(self) -> int:
        return self.last - len(self.events) + 1

    def since(self, after: int) -> list[dict]:
        if after > self.last:
            raise LiveError(409, "cursor_ahead", f"proposal {after} has not been posted", self)
        if after < self.first - 1:
            raise LiveError(409, "cursor_expired", f"proposals after {after} are no longer kept", self)
        start = after - self.first + 1
        return [{"seq": after + offset, "producer": producer, "number": number, "event": change.payload()}
                for offset, (producer, number, change)
                in enumerate(itertools.islice(self.events, start, start + MAX_LIVE_BATCH), 1)]

    def append(self, account: str, producer: str, first: int, changes: list[ProposalChange]) -> int:
        known = self.producers.get(producer)
        if known is not None and known[0] != account:
            raise LiveError(403, "producer_owned", "that producer belongs to another account")
        if known is None and len(self.producers) >= MAX_LIVE_PRODUCERS:
            raise LiveError(429, "too_many_producers", "the session has too many proposal producers")
        last = known[1] if known is not None else 0
        if first > last + 1:
            raise LiveError(409, "sequence_gap", f"proposal {first} would follow producer event {last}", self)
        overlap = min(len(changes), last - first + 1)
        for number, change in enumerate(changes[:overlap], first):
            kept = self.retained.get((producer, number))
            if kept is None:
                raise LiveError(409, "sequence_expired", f"producer event {number} is no longer kept", self)
            if kept != change:
                raise LiveError(409, "sequence_conflict", f"producer event {number} has other content", self)
        additions = changes[overlap:]
        if self.last + len(additions) > MAX_LIVE_SEQUENCE:
            raise LiveError(409, "sequence_exhausted", "the proposal journal must start a new epoch", self)
        for number, change in enumerate(additions, first + overlap):
            if len(self.events) == MAX_LIVE_EVENTS:
                old_producer, old_number, _ = self.events.popleft()
                del self.retained[old_producer, old_number]
            self.events.append((producer, number, change))
            self.retained[producer, number] = change
        self.last += len(additions)
        self.producers[producer] = (account, max(last, first + len(changes) - 1))
        return len(additions)


class LiveJournal:
    """The live quest events of one game session: (quest id, old state, new state) transitions its
    creator's game posted, numbered from 1 in posting order. It keeps the newest MAX_LIVE_EVENTS, and
    a cursor or resend that reaches past them fails instead of skipping what was discarded. It lives
    and ends with its game session, in memory only. Its epoch names it: when the creator plays in the
    game session under another user session, its game started over and a new journal, with a new
    epoch, replaces this one (CampaignLive.journal)."""

    def __init__(self, host: str):
        self.epoch = random_id()
        self.host = host  # the creator's user session when the journal started; "" if it was away
        self.events: deque[tuple[int, int, int]] = deque(maxlen=MAX_LIVE_EVENTS)
        self.last = 0  # the sequence number of the newest event; 0 before the first
        self.proposals = ProposalJournal()

    @property
    def first(self) -> int:
        """The sequence number of the oldest event kept; last + 1 while there is none."""
        return self.last - len(self.events) + 1

    def since(self, after: int) -> list[dict[str, int]]:
        """The events after sequence number `after`, in order, at most MAX_LIVE_BATCH of them."""
        if after > self.last:
            raise LiveError(409, "cursor_ahead", f"event {after} has not been posted", self)
        if after < self.first - 1:
            raise LiveError(409, "cursor_expired", f"the events after {after} are no longer kept", self)
        start = after - self.first + 1
        return [{"seq": after + offset, "id": quest, "old": old, "new": new}
                for offset, (quest, old, new)
                in enumerate(itertools.islice(self.events, start, start + MAX_LIVE_BATCH), 1)]

    def append(self, first: int, events: list[tuple[int, int, int]]) -> None:
        """Takes `events` as sequence numbers first, first + 1, ... (first >= 1). A resend of events
        already taken must match them, and then only what follows them is added; a refused batch
        adds nothing."""
        if first > self.last + 1:
            raise LiveError(409, "sequence_gap", f"event {first} would follow event {self.last}", self)
        overlap = min(len(events), self.last - first + 1)  # events already taken
        if overlap > 0:
            if first < self.first:
                raise LiveError(409, "sequence_expired",
                                f"event {first} is no longer kept, so its resend cannot be checked", self)
            start = first - self.first
            taken = itertools.islice(self.events, start, start + overlap)
            for seq, (kept, sent) in enumerate(zip(taken, events), first):
                if kept != sent:
                    raise LiveError(409, "sequence_conflict", f"event {seq} was posted with other content", self)
        self.events.extend(events[overlap:])
        self.last += len(events) - overlap


@dataclass
class GameSession:
    name: str
    max_participants: int
    create_time: int
    host: str  # Gamesync endpoint
    port: int
    password: str = ""
    properties_raw: bytes | None = None  # encoded MapValue, passed through as the client sent it
    creator: str = ""  # the user who created it
    # The user whose Cloud Island it hosts (Backend.hosted_island), which a visitor may host while
    # the owner is away; "" if none is known, and then the creator is taken to be the island's owner.
    island: str = ""
    user_sessions: dict[str, UserSession] = field(default_factory=dict)  # by user name
    gamesync: GamesyncSpace = field(default_factory=GamesyncSpace, repr=False, compare=False)
    live: LiveJournal | None = field(default=None, repr=False, compare=False)  # CampaignLive.journal

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


@dataclass(frozen=True)
class TurnServer:
    """A TURN server that shares a secret with this one (--turn, --turn-secret-file; coturn
    use-auth-secret with the same static-auth-secret). AllocateIceServerSet hands it out with
    credentials of the TURN REST API scheme coturn checks: username "<expiry>:<user>", where
    <expiry> is a Unix time TURN_CREDENTIAL_SECONDS ahead, and password
    base64(HMAC-SHA1(secret, username))."""

    host: str
    port: int
    secret: bytes = field(repr=False)

    def credentials(self, user: str, now: int) -> tuple[str, str]:
        """Username and password for `user` at Unix time `now`."""
        username = f"{now + TURN_CREDENTIAL_SECONDS}:{user}"
        digest = hmac.new(self.secret, username.encode(), hashlib.sha1).digest()
        return username, base64.b64encode(digest).decode()


def _only_field(data: bytes, number: int) -> list[bytes] | None:
    """The occurrences of length-delimited field `number` in a message that holds nothing else, or
    None for one that does not parse or holds anything else."""
    try:
        msg = Msg(data)
    except ValueError:
        return None
    if msg.fields.keys() - {number} or any(wire != 2 for wire, _ in msg.fields.get(number, ())):
        return None
    return [item for _, item in msg.fields.get(number, ())]


def _map_items(data: bytes) -> list[tuple[bytes, bytes]] | None:
    """The (key, encoded Value) entries of a MapValue in wire order, or None unless every entry
    holds at most one key and one value and no key is repeated: a peer's parser would merge or
    pick among those, so what it sees could differ from what was looked at."""
    entries = _only_field(data, 1)
    if entries is None:
        return None
    items: list[tuple[bytes, bytes]] = []
    keys: set[bytes] = set()
    for entry in entries:
        try:
            msg = Msg(entry)
        except ValueError:
            return None
        if msg.fields.keys() - {1, 2} or any(len(values) != 1 or values[0][0] != 2
                                             for values in msg.fields.values()):
            return None
        key = msg.get_bytes(1) or b""
        if key in keys:
            return None
        keys.add(key)
        items.append((key, msg.get_bytes(2) or b""))
    return items


@dataclass(frozen=True)
class RelayOnly:
    """Relay-only delivery (--relay-only): what of a gamesync document reaches a player, so that
    the session descriptions players exchange offer only candidates on the TURN server's relay
    (`address`, the --turn IPv4 address, and `ports`, --turn-relay-ports) and no address of a
    player's own. Every gamesync read, watch and change notification, and every field transform
    result, passes through it; what is stored is not changed.

    A session description (a string or bytes value starting with a version line, SDP_START) is
    rebuilt line by line (sdp). A value that may be signaling otherwise is dropped: a string or
    bytes value whose text holds SIGNALING_TEXT, a value nested deeper than MAX_SIGNALING_DEPTH,
    and a value holding signaling that is not exactly one field, an array or a map a peer's parser
    would read the same way (_only_field, _map_items). A dropped value becomes null, so maps keep
    their keys and arrays their indexes. Values without SIGNALING_BYTES are passed on as stored.
    Parsing counts against the request budgets (Msg)."""

    address: str  # dotted IPv4, as str(ipaddress.IPv4Address) writes it
    ports: tuple[int, int]  # lowest and highest relay port

    def fields(self, data: bytes) -> bytes:
        """The encoded fields (MapValue entries) of a document as delivered."""
        if not SIGNALING_BYTES.search(data):
            return data
        entries = _map_items(data)
        if entries is None:
            return b""  # stored fields are always well formed (encode_map); deliver none, not unchecked ones
        kept = self._entries(entries, 0)
        return data if kept is None else kept

    def value(self, raw: bytes, depth: int = 0) -> bytes:
        """An encoded common.Value as delivered: `raw` itself when nothing in it changes."""
        if not SIGNALING_BYTES.search(raw):
            return raw
        if depth >= MAX_SIGNALING_DEPTH:
            return NULL_VALUE
        try:
            fields = [(number, wire, item) for number, items in Msg(raw).fields.items() for wire, item in items]
        except ValueError:
            return NULL_VALUE
        if len(fields) != 1:
            return NULL_VALUE
        number, wire, data = fields[0]
        if wire != 2:
            return raw  # a number or a boolean
        if number in (7, 8):  # string_value, bytes_value
            if SDP_START.match(data):
                sdp = self.sdp(data)
                return NULL_VALUE if sdp is None else encode((number, sdp))
            return NULL_VALUE if SIGNALING_TEXT.search(data) else raw
        if number == 9:  # array_value (ArrayValue.values 1)
            items = _only_field(data, 1)
            if items is None:
                return NULL_VALUE
            kept = [self.value(item, depth + 1) for item in items]
            if all(new is old for new, old in zip(kept, items)):
                return raw
            return encode((9, encode(*[(1, item) for item in kept])))
        if number == 10:  # map_value
            entries = _map_items(data)
            if entries is None:
                return NULL_VALUE
            kept_entries = self._entries(entries, depth + 1)
            return raw if kept_entries is None else encode((10, kept_entries))
        return NULL_VALUE if SIGNALING_BYTES.search(data) else raw  # a timestamp, or unknown

    def _entries(self, entries: list[tuple[bytes, bytes]], depth: int) -> bytes | None:
        """MapValue entries as delivered, encoded, or None when every value is passed on as is."""
        kept = [(key, self.value(item, depth)) for key, item in entries]
        if all(new is old for (_, new), (_, old) in zip(kept, entries)):
            return None
        return encode(*[(1, encode((1, key), (2, item))) for key, item in kept])

    def sdp(self, data: bytes) -> bytes | None:
        """A session description as delivered, or None when it is dropped whole: over MAX_SDP_BYTES
        or MAX_SDP_LINES, a line that is not printable ASCII "<letter>=<value>" (empty lines pass),
        a second v= line, or an o= or m= line that does not parse. Of the rest, v=, t= and b= pass
        as they are, s= becomes "-", o= keeps its session id and version with address 0.0.0.0, c=
        becomes 0.0.0.0, m= keeps its media, protocol and formats with port 9 (0 stays 0), candidates
        pass as `candidate` rebuilds them, and attributes only when SDP_KEPT_ATTRIBUTES lists them.
        Every other line (i=, u=, e=, p=, z=, k=, r=, a=rtcp, a=remote-candidates and attributes not
        listed) may carry an address and is left out. Lines end as the first one does."""
        if len(data) > MAX_SDP_BYTES or not SDP_START.match(data):
            return None
        newline = b"\r\n" if data.split(b"\n", 1)[0].endswith(b"\r") else b"\n"
        lines = data.split(b"\n")
        ended = not lines[-1]  # the last line ends with a newline
        if ended:
            lines.pop()
        if len(lines) > MAX_SDP_LINES:
            return None
        out: list[bytes] = []
        for index, line in enumerate(lines):
            if line.endswith(b"\r"):
                line = line[:-1]
            if not line:
                out.append(line)
                continue
            match = SDP_LINE.fullmatch(line)
            if match is None:
                return None
            kind, value = match.groups()
            if kind == b"v":
                if index:
                    return None
                out.append(line)
            elif kind == b"o":
                if (origin := SDP_ORIGIN.fullmatch(value)) is None:
                    return None
                out.append(b"o=- %s %s IN IP4 0.0.0.0" % origin.groups())
            elif kind == b"s":
                out.append(b"s=-")
            elif kind == b"c":
                out.append(b"c=IN IP4 0.0.0.0")
            elif kind == b"m":
                if (media := SDP_MEDIA.fullmatch(value)) is None:
                    return None
                out.append(b"m=%s %s %s" % (media[1], b"0" if int(media[2]) == 0 else b"9", media[3]))
            elif kind in (b"t", b"b"):
                if (SDP_TIMING if kind == b"t" else SDP_BANDWIDTH).fullmatch(value):
                    out.append(line)
            elif kind == b"a":
                if value.startswith(b"candidate:"):
                    if (candidate := self.candidate(value)) is not None:
                        out.append(b"a=" + candidate)
                elif SDP_KEPT_ATTRIBUTES.fullmatch(value):
                    out.append(line)
        return newline.join(out) + (newline if ended else b"")

    def candidate(self, value: bytes) -> bytes | None:
        """An a=candidate value (RFC 8839) as delivered, or None when it is left out: anything but a
        UDP relay candidate at `address` on a port in `ports`, and anything that does not parse. Its
        raddr and rport, the player's own address the TURN server saw, become 0.0.0.0 and 0; of its
        other extensions only SDP_CANDIDATE_EXTENSIONS pass, each once."""
        match = SDP_CANDIDATE.fullmatch(value)
        if match is None:
            return None
        foundation, component, transport, priority, address, port, kind, rest = match.groups()
        if (transport.lower() != b"udp" or kind != b"relay" or address != self.address.encode()
                or not 1 <= int(component) <= 256 or int(priority) > 0xFFFFFFFF
                or not self.ports[0] <= int(port) <= self.ports[1]):
            return None
        words = rest.split()
        related = False
        extensions: dict[bytes, bytes] = {}
        for name, item in zip(words[::2], words[1::2]):
            if name in (b"raddr", b"rport"):
                related = True
            elif name not in extensions and (pattern := SDP_CANDIDATE_EXTENSIONS.get(name)) and pattern.fullmatch(item):
                extensions[name] = item
        out = b"candidate:%s %d %s %d %s %d typ relay" % (foundation, int(component), transport, int(priority),
                                                          address, int(port))
        if related:
            out += b" raddr 0.0.0.0 rport 0"
        return out + b"".join(b" %s %s" % pair for pair in extensions.items())


def log_gamesync_sdp(changes: dict[str, dict | None], writer: str, relay: RelayOnly | None = None) -> None:
    """Logs the session descriptions in committed gamesync documents: their candidate lines at
    INFO, every byte at DEBUG (-v). ICE credentials (a=ice-pwd) stay out of the INFO line. In
    relay-only mode (RelayOnly) the INFO line counts the candidates written and lists the ones
    delivered instead, so it names no address of a player; DEBUG still has every byte. Looking for
    them parses each document within the writing call's request budgets (Msg); a document that does
    not fit them is logged without its session descriptions, because its write is already committed
    and must still be answered."""
    for name, doc in changes.items():
        if doc is None:
            continue
        try:
            found = sdp_values(doc_entries(doc))
        except GrpcError as exc:
            if exc.code != RESOURCE_EXHAUSTED:
                raise
            log.info("gamesync %s written by %s: SDP not looked for (%s)", name, writer or "-", exc.message)
            continue
        for path, data in found:
            lines = data.decode("utf-8", "backslashreplace").splitlines(keepends=True)
            candidates = [line.rstrip() for line in lines if line.startswith("a=candidate")]
            if relay is None:
                log.info("gamesync %s %s written by %s: SDP (%s); candidates: %s", name, path, writer or "-",
                         describe_sdp(data), "; ".join(candidates) or "none")
            else:
                delivered = relay.sdp(data)
                kept = [] if delivered is None else [
                    line for line in delivered.decode().splitlines() if line.startswith("a=candidate")]
                log.info("gamesync %s %s written by %s: SDP (%s) with %d candidate(s); relay-only delivers %s",
                         name, path, writer or "-", describe_sdp(data), len(candidates),
                         "nothing (dropped whole)" if delivered is None else
                         f"SDP ({describe_sdp(delivered)}); candidates: {'; '.join(kept) or 'none'}")
            if log.isEnabledFor(logging.DEBUG):
                log.debug("SDP %s %s, hex %s:\n%s", name, path, data.hex(),
                          "\n".join(f"  {line!r}" for line in lines))


def log_description(describe: Callable[..., str]) -> Callable[..., str]:
    """Makes `describe`, which summarizes request or gamesync data for an INFO line, leave its
    summary out when what it parses does not fit the request budgets (Msg, RESOURCE_EXHAUSTED) it
    shares with the call it describes, because logging must not change how a call is answered.
    Only that is left out: data that does not decode still fails."""

    @functools.wraps(describe)
    def described(*args: object) -> str:
        try:
            return describe(*args)
        except GrpcError as exc:
            if exc.code != RESOURCE_EXHAUSTED:
                raise
            return f"<not described: {exc.message}>"

    return described


@log_description
def describe_user_session_document(entries: dict[str, bytes]) -> str:
    """Summarizes the ids in a user session's docs/__us document for the log."""
    try:
        return (f"uid={Msg(entries['uid']).get_str(7) or '-'} ussid={Msg(entries['ussid']).get_int(3)} "
                f"ucsid={Msg(entries['ucsid']).get_int(3)}")
    except ValueError:
        return "<not described: malformed stored user session>"


def describe_target(target: Msg) -> str:
    """Summarizes a gamesync Target for the log."""
    documents = (target.get_msg(2) or Msg()).get_strs(1)
    collection = (target.get_msg(3) or Msg()).get_str(1)
    watched = f"documents {documents}" if documents else f"collection {collection!r}"
    return f"{target.get_str(1)!r} on {watched}"


@log_description
def describe_keep_user_session_request(req: Msg) -> str:
    """Summarizes a KeepUserSessionRequest for the log."""
    if req.has(2):
        return f"echo {req.get_str(2)!r}"
    if (update := req.get_msg(3)) is not None:
        return f"update_target {describe_target(update.get_msg(1) or Msg())}"
    if (delete := req.get_msg(4)) is not None:
        return f"delete_target {delete.get_str(1)!r}"
    return "no request"


@log_description
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
    def __init__(self, store: Store, storage: Storage, max_players: int, stun: str, gamesync_port: int,
                 turn: TurnServer | None = None, relay: RelayOnly | None = None):
        self.store = store
        self.storage = storage
        self.signer = TokenSigner(store.secret)
        self.max_players = max_players
        self.stun = stun
        self.gamesync_port = gamesync_port
        self.turn = turn  # handed out by AllocateIceServerSet with credentials (--turn)
        self.relay = relay  # relay-only delivery of gamesync documents (--relay-only)
        self.sessions: dict[str, GameSession] = {}
        self.tickets: dict[str, CreationTicket] = {}
        # Client-certificate mode: (account, island owner) -> (monotonic expiry, password_version) of
        # what a right island password allows (finding the owner's game session, reading its
        # StageData), and the counts of wrong passwords.
        self.password_grants: dict[tuple[str, str], tuple[float, str]] = {}
        self.storage.stage_download_allowed = self.stage_attachment_allowed
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
        """Expands the aliases in `name` (Aliases), verifying only the tokens they need."""
        return self.aliases(call, name).expand(name)

    def aliases(self, call: Call, name: str | None = None) -> Aliases:
        """What the aliases in `call`'s names stand for now: those in `name`, so only the tokens they
        need are verified, or all of them. A deferred write keeps them (gamesync_commit), so its
        names resolve as they did when it was stored, even after the tokens of that call expire."""
        user_session = user_id = ""
        gamesync: dict | None = None
        if name is None or name == "userSessions/current" or name.startswith("userSessions/current/"):
            gamesync = self.caller(call, "gamesync") or {}
            user_session = gamesync.get("user_session") or ""
        if name is None or "users/current" in name:
            # A Gamesync call carries a gamesync token instead of an access token; its user is the
            # one that token was issued to (and gamesync_route checked).
            caller = self.caller(call) or (self.caller(call, "gamesync") if gamesync is None else gamesync) or {}
            user_id = caller["sub"].rpartition("/users/")[2] if "sub" in caller else ""
        return Aliases(call.metadata.get("npln-tenant-id", ""), user_session, user_id)

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
        "password" (as when joining a Cloud Island) and private/StageData for PASSWORD_GRANT_SECONDS
        after that or while it is in that island's game session (island_member). Writes, other
        attachment URIs and all other documents are the owner's alone. The account comes from the
        connection, so this does not depend on a
        bearer token."""
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
            if document == "StageData" and (self.has_grant(call, owner) or self.island_member(call, owner)):
                return
        raise GrpcError(PERMISSION_DENIED, f"no access to {name}")

    def island_string(self, owner: str, document: str, key: str) -> str:
        """The string field `key` of `owner`'s private/`document`, or "" if there is none."""
        tenant, _, user_id = owner.partition("/users/")
        doc = self.store.documents.get(f"{tenant}/documents/users/{user_id}/private/{document}")
        return Msg(doc_entries(doc).get(key) or b"").get_str(7)

    def island_password(self, owner: str) -> str:
        """The password in `owner`'s private/PasswordData, or "" if there is none."""
        return self.island_string(owner, "PasswordData", "password")

    def island_password_version(self, owner: str) -> str:
        return password_version(self.island_password(owner))

    def hosted_island(self, call: Call, properties_raw: bytes | None) -> str:
        """Client-certificate mode: the user whose Cloud Island a new game session hosts, or "". The
        game finds an island's session by its property string1, ":" + the island's sessionID (the
        owner's private/SessionIDData), and whoever opens the island, its owner or a visitor while
        the owner is away, creates the session with it. Only islands of the caller's own users, and
        those it holds a current password grant for, count, so nobody hosts an island they could
        not open."""
        if call.principal is None:
            return ""
        string1 = Msg(map_entries(properties_raw).get("string1") or b"").get_str(7)
        if len(string1) < 2 or not string1.startswith(":"):
            return ""
        account = call.principal.account
        own = [name for name, user in self.store.users.items() if user.get("owner") == account]
        granted = [owner for holder, owner in self.password_grants
                   if holder == account and self.has_grant(call, owner)]
        return next((owner for owner in [*own, *granted]
                     if self.island_string(owner, "SessionIDData", "sessionID") == string1[1:]), "")

    def has_grant(self, call: Call, owner: str) -> bool:
        """Whether the caller's account gave `owner`'s current island password within
        PASSWORD_GRANT_SECONDS. A new or removed password ends every grant for the old one."""
        grant = self.password_grants.get((call.principal.account, owner))
        return (grant is not None and grant[0] > time.monotonic() and bool(self.island_password(owner))
                and grant[1] == self.island_password_version(owner))

    def island_member(self, call: Call, owner: str) -> bool:
        """Whether a user of the caller's account is in a game session that hosts `owner`'s Cloud
        Island (GameSession.island, or else its creator), its game is still there
        (user_session_gone), and it joined under `owner`'s current island password. Membership
        permits reading the island for as long as the game is present. A new or removed password
        ends this, as it ends grants."""
        if not self.island_password(owner):
            return False
        version = self.island_password_version(owner)
        now = time.time_ns()
        return any((session.island or session.creator) == owner
                   and user_session.island_password_version == version
                   and self.owns(call, user) and not self.user_session_gone(session, user_session, now)
                   for session in self.sessions.values()
                   for user, user_session in session.user_sessions.items())

    def stage_attachment_allowed(self, principal: Principal, name: str) -> bool:
        """Whether another account may download `name`'s attachment: only private/StageData's, with
        a current password grant or while in that island's game session (island_member)."""
        match = USER_DOCUMENT.fullmatch(name)
        if not match or match.group(3, 4) != ("private", "StageData"):
            return False
        call, owner = Call("", {}, principal), document_owner(name)
        return self.has_grant(call, owner) or self.island_member(call, owner)


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
        user in it, or own the island the session hosts (GameSession.island, or else its creator), or
        have given that island's current password within PASSWORD_GRANT_SECONDS; a grant for another
        member's island does not count. So an island's visitors and its owner find the session a
        visitor opened it in while the owner was away. The host's properties carry the island's
        session id, which only the password-protected private/SessionIDData otherwise reveals."""
        if call.principal is None or any(self.owns(call, user) for user in session.user_sessions):
            return True
        island = session.island or session.creator
        return bool(island) and (self.owns(call, island) or self.has_grant(call, island))

    def check_commit_room(self, call: Call, staging: Staging) -> None:
        """Refuses a Ugcstore commit that would break a document or storage limit (Storage.room_for,
        MAX_DOCUMENTS_PER_USER). Each imported upload leaves the committing account's storage and
        counts against the document owner's account. Each upload a commit imports
        counts once, as apply_write refuses importing one twice. Shrinking always passes."""
        account = call.principal.account if call.principal is not None else None
        growth: dict[str | None, list[int]] = {}  # account -> [state bytes, blob bytes]
        for name, doc in staging.changes.items():
            old = self.store.documents.get(name)
            user = self.store.users.get(document_owner(name) or "") if account is not None else None
            counts = growth.setdefault((user or {}).get("owner") or account, [0, 0])
            counts[0] += document_state_bytes(name, doc) - document_state_bytes(name, old)
            counts[1] += (doc.get("attachment") or {}).get("size", 0) if doc else 0
            counts[1] -= (old.get("attachment") or {}).get("size", 0) if old else 0
        for upload_id in staging.imported_uploads:
            counts = growth.setdefault(account, [0, 0])
            counts[0] -= STATE_OVERHEAD_BYTES
            counts[1] -= self.store.uploads[upload_id]["received"]
        checks = [(holder, state, blobs) for holder, (state, blobs) in growth.items()]
        if len(checks) > 1:  # each account's own growth, then the server's
            checks.append((None, sum(state for _, state, _ in checks), sum(blobs for _, _, blobs in checks)))
        for holder, state, blobs in checks:
            problem = self.storage.room_for(holder, state, blobs)
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
                    result = apply_transform(entries, split_field_path(path), "request_time", None, now)
                else:
                    kinds = {3: "increment", 4: "maximum", 5: "minimum", 6: "increment"}
                    number = next((n for n in kinds if field_transform.has(n)), None)
                    if number is None:
                        raise GrpcError(INVALID_ARGUMENT, f"empty transform for {path}")
                    result = apply_transform(entries, split_field_path(path), kinds[number],
                                             field_transform.get_bytes(number), now)
                results.append(result)
            for buffered in transform.get_msgs(3):
                apply_transform(entries, split_field_path(buffered.get_str(1)), "increment",
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
        if call.principal is None or not self.stage_attachment_allowed(call.principal, name):
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
                                           definition, now, now,
                                           self.island_password_version(session.island or session.creator))
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
        """Removes a user from a game session. Its KeepUserSession calls end first, so nothing it
        opened reads the game session anymore, whatever happens next. While others remain in it, the
        user session's deferred gamesync writes are then queued to be applied, and after them the
        deletion of the gamesync documents named after it (docs/__us/<id>, docs/__pgn/All/__pus/<id>,
        ...), which happens even if they fail (gamesync_fire_deferments). A game session left empty
        is dropped with its creation tickets and all of its gamesync state, deferred writes still
        queued included, and its remaining KeepUserSession calls end."""
        user_session = session.user_sessions.pop(user, None)
        if user_session is None:
            return
        space = session.gamesync
        log.info("dropped %s", user_session.name)
        if session.user_sessions:
            ending = [watcher for watcher in space.watchers if watcher.member is user_session]
        else:
            self.sessions.pop(session.name, None)
            self.tickets = {name: ticket for name, ticket in self.tickets.items() if ticket.session is not session}
            ending = list(space.watchers)
            space.globals.clear()
            space.transactions.clear()
            space.deferments.clear()
            space.queue.clear()  # its applier, if any, finds nothing left to do
            log.info("dropped %s", session.name)
        for watcher in ending:
            space.watchers.discard(watcher)
            watcher.end(GrpcError(NOT_FOUND, f"{watcher.member.name} has left its game session"))
        if session.user_sessions:
            self.gamesync_fire_deferments(session, user_session.name, left=True)
        else:
            self.gamesync_delete(space, list(space.docs))

    def gamesync_delete(self, space: GamesyncSpace, names: list[str]) -> None:
        """Deletes gamesync documents outside any commit and tells the watchers."""
        for name in names:
            del space.docs[name]
        if names:
            self.gamesync_notify(space, dict.fromkeys(names), set())
            log.info("gamesync deleted %s", ", ".join(names))

    @staticmethod
    def user_session_gone(session: GameSession, user_session: UserSession, now: int) -> bool:
        """Whether the game of `user_session` is gone: it has had no KeepUserSession call open in
        `session` for USER_SESSION_GRACE_SECONDS."""
        return (user_session.last_seen < now - USER_SESSION_GRACE_SECONDS * 1_000_000_000
                and all(watcher.member.name != user_session.name for watcher in session.gamesync.watchers))

    def prune_sessions(self) -> None:
        """Drops the user sessions whose game is gone (user_session_gone)."""
        now = time.time_ns()
        for session in list(self.sessions.values()):
            for user, user_session in list(session.user_sessions.items()):
                if self.user_session_gone(session, user_session, now):
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
                              creator=Msg(definitions[0]).get_str(1) if definitions else "",
                              island=self.hosted_island(call, req_session.get_bytes(11)))
        matched = self.join(call, session, definitions, now)
        self.sessions[session.name] = session
        ticket = CreationTicket(f"{parent}/gameSessionCreationTickets/{random_id()}",
                                ticket_request.get_str(2), definitions, session, matched,
                                TICKET_PENDING)
        self.tickets[ticket.name] = ticket
        log.info("created %s for %s (island %s)", session.name, ", ".join(session.user_sessions) or "-",
                 session.island or "-")
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
        """An IceServerSet: the STUN server (field 2) and, with --turn, the TURN server (field 3:
        host 1, port 2, protocol 3, username 4, password 5) with credentials of its own. Its
        password is never logged, -v included (Server.handle_grpc)."""
        tenant = self.resolve(call, req.get_str(1))
        now = time.time_ns()
        stun = turn = None
        if self.stun:
            host, _, port = self.stun.rpartition(":")
            stun = encode((1, host), (2, int(port)), (3, STUN_PROTOCOL_UDP))
        if self.turn is not None:
            # Client-certificate mode: the TURN server's log names the account by an id derived
            # from it, the same for each allocation; local mode authenticates nobody.
            user = derived_id("turn", call.principal.account) if call.principal is not None else random_id()
            username, password = self.turn.credentials(user, now // 1_000_000_000)
            turn = encode((1, self.turn.host), (2, self.turn.port), (3, STUN_PROTOCOL_UDP),
                          (4, username), (5, password))
            log.info("AllocateIceServerSet: TURN %s:%d for %s", self.turn.host, self.turn.port, username)
        return encode(
            (1, f"{tenant}/iceServerSets/{random_id()}"),
            (2, stun),
            (3, turn),
            (4, duration(ICE_SERVER_TTL_SECONDS)),
            (5, timestamp(now)),
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
        check_name(name)
        doc = self.gamesync_read(space, name, req.get_bytes(3))
        if doc is None:
            raise GrpcError(NOT_FOUND, f"{name} not found")
        return encode_document(name, doc, read_mask_paths(req.get_msg(2)), GamesyncReadWork(), self.relay)

    def gamesync_read_documents(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        paths, transaction = read_mask_paths(req.get_msg(2)), req.get_bytes(3)
        work = GamesyncReadWork()
        results = []
        for raw_name in req.get_strs(1):
            name = self.resolve(call, raw_name)
            check_name(name)
            doc = self.gamesync_read(space, name, transaction)
            if doc:
                results.append(encode((1, encode_document(name, doc, paths, work, self.relay))))
            else:
                work.spend(len(name) + STATE_OVERHEAD_BYTES)
                results.append(encode((2, name)))
        return encode(*[(1, result) for result in results], (2, timestamp(time.time_ns())))

    def gamesync_list_documents(self, call: Call, req: Msg) -> bytes:
        space = self.gamesync_route(call)[0].gamesync
        prefix = self.resolve(call, req.get_str(1)).rstrip("/") + "/"
        check_name(prefix)
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
        paths = read_mask_paths(req.get_msg(4))
        work = GamesyncReadWork()
        documents = []
        for name in page:
            if found[name]:
                documents.append(encode_document(name, found[name], paths, work, self.relay))
            else:
                work.spend(len(name) + STATE_OVERHEAD_BYTES)
                documents.append(encode((1, name)))
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
        results, now = self.gamesync_commit(session.gamesync, member.name, self.aliases(call), req.get_msgs(1),
                                            req.get_msgs(2))
        return encode(*[(1, result) for result in results], (2, timestamp(now)))

    def gamesync_lazy_write_documents(self, call: Call, req: Msg) -> bytes:
        session, member = self.gamesync_route(call)
        # LazyWriteOperation numbers merge_document 1 and transform_document 2; WriteOperation
        # numbers them 2 and 3.
        writes = [Msg(encode((2, op.get_bytes(1)), (3, op.get_bytes(2)))) for op in req.get_msgs(1)]
        _, now = self.gamesync_commit(session.gamesync, member.name, self.aliases(call), writes, [])
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
        results, now = self.gamesync_commit(space, member.name, self.aliases(call), req.get_msgs(1),
                                            req.get_msgs(2))
        return encode(*[(1, result) for result in results], (2, timestamp(now)))

    def gamesync_rollback_transaction(self, call: Call, req: Msg) -> bytes:
        self.gamesync_route(call)[0].gamesync.transactions.pop(req.get_bytes(1) or b"", None)
        return b""

    def gamesync_create_round(self, call: Call, req: Msg) -> bytes:
        # Round's fields are undocumented; the created round is the requested one.
        return req.get_bytes(1) or b""

    def gamesync_commit(self, space: GamesyncSpace, owner: str, aliases: Aliases, writes: Iterable[Msg],
                        deferments: list[Msg]) -> tuple[list[bytes], int]:
        """Applies WriteOperations and DefermentOperations atomically to one game session's gamesync
        state and notifies its watchers. Names resolve with `aliases` (Backend.aliases), which the
        deferments stored keep; they belong to user session `owner`. `writes` are applied in order as
        they are taken, so they may be parsed one at a time, and together cost one GamesyncWork.
        Deferments queued to be applied still count against the Gamesync limit (GamesyncSpace.queue)."""
        now = time.time_ns()
        work = GamesyncWork()
        staging = Staging(space.docs)
        staged_globals = dict(space.globals)
        results = [self.gamesync_apply_write(aliases, op, staging, staged_globals, now, work) for op in writes]
        staged_deferments = dict(space.deferments)
        for op in deferments:
            if (update := op.get_msg(1)) is not None:
                name = aliases.expand((update.get_msg(1) or Msg()).get_str(1))
                staged_deferments[name] = (owner, aliases, update.get_bytes(1) or b"")
            elif (delete := op.get_msg(2)) is not None:
                staged_deferments.pop(aliases.expand(delete.get_str(1)), None)
            else:
                raise GrpcError(INVALID_ARGUMENT, "empty deferment operation")

        # Gamesync state lives in memory, so one game session may only hold so much of it:
        # documents, global values and deferred writes, names included.
        for name in [*staging.changes, *staged_globals.keys() - space.globals.keys(),
                     *staged_deferments.keys() - space.deferments.keys()]:
            check_name(name)
        size, records = gamesync_size({**space.docs, **staging.changes}, staged_globals, staged_deferments,
                                      space.queue)
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
            log_gamesync_sdp(staging.changes, owner, self.relay)
        return results, now

    def gamesync_apply_write(self, aliases: Aliases, op: Msg, staging: Staging, globals_: dict[str, bytes],
                             now: int, work: GamesyncWork) -> bytes:
        """Stages one gamesync WriteOperation and returns its WriteResult. It costs `work`, each
        before it is copied, STATE_OVERHEAD_BYTES, its document as decoded (doc_entries) and as
        staged, and what its field transforms, masked paths and merges copy (GamesyncWork)."""
        if (update := op.get_msg(1)) is not None:
            document = update.get_msg(1) or Msg()
            name = aliases.expand(document.get_str(1))
            doc = staging.get(name)
            check_precondition(name, doc, update.get_msg(3))
            entries = masked_entries(doc, map_entries(document.get_bytes(2)), update.get_msg(2), work)
            result = encode((1, b""))  # UpdateResult
        elif (merge := op.get_msg(2)) is not None:
            document = merge.get_msg(1) or Msg()
            name = aliases.expand(document.get_str(1))
            doc = staging.get(name)
            entries = merge_entries(doc_entries(doc, work), map_entries(document.get_bytes(2)), work)
            result = encode((1, b""))  # UpdateResult
        elif (transform := op.get_msg(3)) is not None:
            name = aliases.expand(transform.get_str(1))
            doc = staging.get(name)
            entries = doc_entries(doc, work)
            # Each FieldTransform is parsed as it is applied and let go after it, so the request
            # budgets (request_budget) hold one at a time, not all of them at once.
            values = [gamesync_transform(entries, Msg(field_transform), globals_, now, work)
                      for field_transform in transform.get_raws(2)]
            if self.relay is not None:  # a result may copy what another player wrote (load_global_value)
                values = [self.relay.value(value) for value in values]
            result = encode((2, encode(*[(1, value) for value in values])))  # TransformResult
        elif (delete := op.get_msg(4)) is not None:
            name = aliases.expand(delete.get_str(1))
            check_precondition(name, staging.get(name), delete.get_msg(2))
            work.spend(STATE_OVERHEAD_BYTES)
            staging.put(name, None)
            return encode((3, b""))  # DeleteResult
        else:
            raise GrpcError(INVALID_ARGUMENT, "empty write operation")
        work.spend(STATE_OVERHEAD_BYTES + stored_fields_size(entries))
        staged = updated_document(doc, now, entries)
        staging.put(name, staged)
        return result

    def gamesync_notify(self, space: GamesyncSpace, changes: dict[str, dict | None], created: set[str]) -> None:
        """Sends the changes to the watchers whose targets cover them, each document encoded once.
        In relay-only mode one that cannot be filtered (RelayOnly) within the request budgets is sent
        to nobody: the commit is already applied, so the calls of the watchers it was for end
        (RESOURCE_EXHAUSTED) instead."""
        documents: dict[str, bytes | GrpcError] = {}
        for watcher in space.watchers:
            for name, doc in changes.items():
                for target_id in watcher.targets:
                    if not watcher.covers(target_id, name):
                        continue
                    if doc is None:
                        change = encode((1, wire_target_id(target_id)), (2, DOCUMENT_CHANGE_DELETED),
                                        (3, encode((1, name))))
                    else:
                        if name not in documents:
                            try:
                                documents[name] = encode_document(name, doc, relay=self.relay)
                            except GrpcError as exc:
                                log.warning("gamesync %s not delivered: %s", name, exc.message)
                                documents[name] = exc
                        document = documents[name]
                        if isinstance(document, GrpcError):
                            watcher.end(GrpcError(document.code, document.message))
                            continue
                        kind = DOCUMENT_CHANGE_EXIST if name in created else DOCUMENT_CHANGE_UPDATED
                        change = encode((1, wire_target_id(target_id)), (2, kind), (3, document))
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
            document = encode_document(name, docs[name], relay=self.relay)
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
        log.info("gamesync %s %s for %s: %s", "refreshed" if doc else "created", name, session.name,
                 describe_user_session_document(entries))

    def gamesync_fire_deferments(self, session: GameSession, user_session: str, left: bool = False) -> None:
        """Queues the deferred writes of user session `user_session`, whose KeepUserSession call
        ended or that `left` the game session, to be applied in the order their names were first
        stored, and after them, when it left, the deletion of the gamesync documents named after it
        (GamesyncSpace.queue), which happens even if they fail. The deferments are taken out of the
        game session's deferments now, so later DefermentOperations no longer reach them, but they
        count against its Gamesync limit until they are applied.

        In the event loop, a task of the game session works through the queue one entry per turn
        of the loop (gamesync_apply_queue), so other calls wait for at most one deferment at a time,
        and each deferment is a commit of its own, with its own GamesyncWork and ParseBudget: what
        one copies or parses never costs another. Without a running event loop (tests, tools),
        nothing else runs meanwhile, so the queue is worked through at once."""
        space = session.gamesync
        for name, (owner, aliases, deferment) in list(space.deferments.items()):
            if owner == user_session:
                del space.deferments[name]
                space.queue.append(QueuedDeferment(name, owner, aliases, deferment))
        if left:
            space.queue.append(QueuedDeparture(user_session))
        if not space.queue:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # no event loop runs in this thread
            while space.queue:
                self.gamesync_apply_queued(session)
            return
        if space.applier is None or space.applier.done():  # done: cancelled before it ever ran
            space.applier = loop.create_task(self.gamesync_apply_queue(session))

    async def gamesync_apply_queue(self, session: GameSession) -> None:
        """Works through a game session's queue (GamesyncSpace.queue), one entry per turn of the
        event loop, until it is empty."""
        space = session.gamesync
        request_budget.set(None)  # inherited from the call that started this task, which is not its own
        try:
            while space.queue:
                try:
                    self.gamesync_apply_queued(session)
                except Exception:  # no caller to report it to; the entries after it still apply
                    log.exception("the gamesync queue of %s failed", session.name)
                await asyncio.sleep(0)
        finally:
            space.applier = None

    def gamesync_apply_queued(self, session: GameSession) -> None:
        """Takes the first entry of a game session's queue (GamesyncSpace.queue) and does it:
        deletes the gamesync documents named after a user session that left, or applies a
        deferment as a commit of its own. A deferment's names resolve with the aliases kept when it
        was stored (gamesync_commit), so the tokens of the call that stored it may have expired
        since. Nothing is done to a game session that has been dropped (drop_user_session).

        Deferments were admitted against the game session's Gamesync limit when they were stored,
        so request data that other calls hold, or that the call that queued them holds, must not
        cost the game session writes it already accepted: a deferment is parsed within a
        ParseBudget of its own (MAX_DEFERMENT_PARSE_BYTES), not a request budget (request_budget).
        One that fails in any way (malformed or empty, a failed precondition, the Gamesync limit,
        its GamesyncWork or ParseBudget spent) is logged and dropped with none of its writes
        applied: its user session may be gone, so nothing would try it again."""
        space = session.gamesync
        entry = space.queue.popleft()
        if self.sessions.get(session.name) is not session:
            space.queue.clear()
            return
        token = request_budget.set(ParseBudget(MAX_DEFERMENT_PARSE_BYTES))
        try:
            if isinstance(entry, QueuedDeparture):
                session_id = entry.user_session.rpartition("/")[2]
                self.gamesync_delete(space, [name for name in space.docs if name.rpartition("/")[2] == session_id])
                return
            try:
                deferred = Msg(entry.deferment)  # held while its writes are applied, so it counts meanwhile
                writes = (Msg(write) for write in deferred.get_raws(2))
                self.gamesync_commit(space, entry.owner, entry.aliases, writes, [])
            except Exception as exc:  # stored client data: whatever it raises, the rest still apply
                log.warning("deferment %s of %s failed: %s", entry.name, entry.owner, exc)
            else:
                log.info("applied deferment %s of %s", entry.name, entry.owner)
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
                    if session.user_sessions.get(member.user) is not member:
                        raise GrpcError(NOT_FOUND, f"{member.name} has left its game session")
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
            self.gamesync_fire_deferments(session, member.name)
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


# --- Live campaign events (HTTP) --------------------------------------------------------------


def is_campaign_live(target: str) -> bool:
    """Whether an HTTP request target names a live campaign endpoint instead of storage."""
    try:
        return urlsplit(target).path in (CAMPAIGN_LIVE_PATH, CAMPAIGN_PROPOSALS_PATH)
    except ValueError:  # left to Storage.handle, as before
        return False


def live_response(status: int, payload: dict, headers: list[tuple[str, str]] | None = None) -> Response:
    return response(status, json.dumps(payload, separators=(",", ":")).encode(), "application/json",
                    [("cache-control", "no-store"), *(headers or [])])


def unique_json_keys(pairs: list[tuple[str, object]]) -> dict:
    """json.loads object_pairs_hook: an object that names a key twice is refused, not trimmed."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("an object names a key twice")
    return result


def no_json_constant(name: str) -> object:
    """json.loads parse_constant: NaN and the infinities are refused."""
    raise ValueError(f"{name} is not a number")


def check_live_session(session: object) -> str:
    if not (isinstance(session, str) and 0 < len(session) <= MAX_NAME_BYTES
            and session.isascii() and session.isprintable()):
        raise LiveError(400, "bad_request", "session is the name of a game session")
    return session


def check_live_epoch(epoch: object) -> str:
    if not (isinstance(epoch, str) and ID_PATTERN.fullmatch(epoch)):
        raise LiveError(400, "bad_request", "epoch is the epoch a GET answered with")
    return epoch


def parse_live_query(query: str) -> tuple[str, str, int]:
    """The session, epoch and cursor (`after`) of a poll, each given once and nothing else."""
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, errors="strict",
                          max_num_fields=3)
    except ValueError:
        pairs = []
    fields = dict(pairs)
    if len(fields) != len(pairs) or fields.keys() != {"session", "epoch", "after"}:
        raise LiveError(400, "bad_request", "a poll's query holds session, epoch and after, once each")
    if not re.fullmatch(r"0|[1-9][0-9]{0,17}", fields["after"]):
        raise LiveError(400, "bad_request", "after is a sequence number, 0 before the first event")
    return check_live_session(fields["session"]), check_live_epoch(fields["epoch"]), int(fields["after"])


def parse_live_event(event: object) -> tuple[int, int, int]:
    """(quest id, old state, new state) of one posted event."""
    if not isinstance(event, dict) or event.keys() != {"id", "old", "new"}:
        raise LiveError(400, "bad_request", "an event is an object of id, old and new")
    quest, old, new = event["id"], event["old"], event["new"]
    if not (type(quest) is int and 1 <= quest <= MAX_QUEST_ID):
        raise LiveError(400, "bad_request", f"an event's id is a quest id from 1 to {MAX_QUEST_ID}")
    if not all(type(state) is int and 1 <= state <= MAX_QUEST_STATE for state in (old, new)) or old == new:
        raise LiveError(400, "bad_request",
                        f"an event's old and new are two different states from 1 to {MAX_QUEST_STATE}")
    return quest, old, new


def parse_live_post(body: bytes) -> tuple[str, str, int, list[tuple[int, int, int]]]:
    """The session, epoch, first sequence number and events of a POST's JSON body. Integers are
    JSON integers: booleans and fractions are refused, as are keys beyond the contract's."""
    if len(body) > MAX_LIVE_REQUEST_BYTES:
        raise LiveError(413, "too_large", f"a POST's body has at most {MAX_LIVE_REQUEST_BYTES} bytes")
    try:
        value = json.loads(body.decode(), object_pairs_hook=unique_json_keys, parse_constant=no_json_constant)
    except (ValueError, RecursionError) as exc:
        raise LiveError(400, "bad_request", f"the body is not JSON: {exc}") from None
    if not isinstance(value, dict) or value.keys() != {"session", "epoch", "first", "events"}:
        raise LiveError(400, "bad_request", "the body is an object of session, epoch, first and events")
    first, events = value["first"], value["events"]
    if type(first) is not int or first < 1:
        raise LiveError(400, "bad_request", "first is the sequence number of the first event, from 1")
    if not isinstance(events, list) or not events:
        raise LiveError(400, "bad_request", "events is a list of at least one event")
    if len(events) > MAX_LIVE_BATCH:
        raise LiveError(413, "too_large", f"a POST carries at most {MAX_LIVE_BATCH} events")
    return (check_live_session(value["session"]), check_live_epoch(value["epoch"]), first,
            [parse_live_event(event) for event in events])


def parse_proposal_event(value: object) -> ProposalChange:
    if not isinstance(value, dict):
        raise LiveError(400, "bad_request", "a proposal event is an object")
    if value.get("kind") == "story" and value.keys() == {"kind", "id", "old", "new"}:
        quest, old, new = parse_live_event({key: value[key] for key in ("id", "old", "new")})
        return ProposalChange("story", quest, old, new)
    if value.get("kind") != "unique" or value.keys() != {"kind", "id", "old", "new", "field", "site"}:
        raise LiveError(400, "bad_request", "a proposal event must be a story or unique quest change")
    quest, old, new, field, site = (value[key] for key in ("id", "old", "new", "field", "site"))
    if type(quest) is not int or not 1 <= quest <= 200:
        raise LiveError(400, "bad_request", "a unique quest id must be from 1 to 200")
    if (type(old) is not int or type(new) is not int or not 0 <= old <= 255
            or not 0 <= new <= 255 or old == new):
        raise LiveError(400, "bad_request", "unique quest bytes must be different values from 0 to 255")
    if type(site) is not int or not 0 <= site <= 13:
        raise LiveError(400, "bad_request", "a unique quest writer site must be from 0 to 13")
    if site < 4:
        if field != "state" or old > 5 or new != (2, 4, 3, 5)[site]:
            raise LiveError(400, "bad_request", "the unique quest state does not match its writer site")
    elif field != "counter":
        raise LiveError(400, "bad_request", "the unique quest counter does not match its writer site")
    return ProposalChange("unique", quest, old, new, field, site)


def parse_proposal_post(body: bytes) -> tuple[str, str, str, int, list[ProposalChange]]:
    if len(body) > MAX_LIVE_REQUEST_BYTES:
        raise LiveError(413, "too_large", f"a POST's body has at most {MAX_LIVE_REQUEST_BYTES} bytes")
    try:
        value = json.loads(body.decode(), object_pairs_hook=unique_json_keys, parse_constant=no_json_constant)
    except (ValueError, RecursionError) as exc:
        raise LiveError(400, "bad_request", f"the body is not JSON: {exc}") from None
    if not isinstance(value, dict) or value.keys() != {"session", "epoch", "producer", "first", "events"}:
        raise LiveError(400, "bad_request", "a proposal has session, epoch, producer, first and events")
    producer, first, events = value["producer"], value["first"], value["events"]
    if not isinstance(producer, str) or re.fullmatch(r"[0-9a-f]{32}", producer) is None:
        raise LiveError(400, "bad_request", "producer is a random 128-bit lowercase hexadecimal id")
    if type(first) is not int or not 1 <= first <= MAX_LIVE_SEQUENCE:
        raise LiveError(400, "bad_request", "first is a positive producer sequence number")
    if not isinstance(events, list) or not events:
        raise LiveError(400, "bad_request", "events is a list of at least one proposal")
    if len(events) > MAX_LIVE_BATCH:
        raise LiveError(413, "too_large", f"a POST carries at most {MAX_LIVE_BATCH} proposals")
    if first + len(events) - 1 > MAX_LIVE_SEQUENCE:
        raise LiveError(400, "bad_request", "producer sequence numbers are exhausted")
    return (check_live_session(value["session"]), check_live_epoch(value["epoch"]), producer, first,
            [parse_proposal_event(event) for event in events])


class CampaignLive:
    """/campaign/live over HTTP/1.1 or HTTP/2: the live quest events of story co-op game sessions
    (LiveJournal). Every request is authorized by the account behind its connection, so only
    client-certificate mode serves them; local mode, which authenticates nobody, refuses them all.

    GET without a query finds the one live game session with an active user of the caller's account
    in it (none or several fail) and answers its name, its journal's epoch and bounds, and the
    caller's role: "host" if the session's creator is in it and belongs to the caller's account,
    else "guest". GET ?session=&epoch=&after= also answers the events after sequence number `after`.
    POST {session, epoch, first, events} adds host events. /campaign/live/proposals takes guest
    quest changes and lets only the host poll them; they are proposals, not authoritative changes.
    Both journals end with the session epoch. Starting quest state and durable checkpoints are not
    served here."""

    def __init__(self, backend: Backend):
        self.backend = backend

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes,
               principal: Principal | None) -> Response:
        try:
            result, outcome = self.serve(method, target, headers, body, principal), "ok"
        except LiveError as exc:
            allow = [("allow", "GET, POST")] if exc.status == 405 else []
            result = live_response(exc.status, {"error": exc.code, "message": exc.message, **exc.bounds}, allow)
            outcome = exc.code
        log.info("campaign live %s from account %s -> %d %s", method,
                 principal.account if principal is not None else "-", result.status, outcome)
        return result

    def serve(self, method: str, target: str, headers: dict[str, str], body: bytes,
              principal: Principal | None) -> Response:
        if principal is None:
            raise LiveError(401, "unauthenticated", "live campaign events need a device certificate")
        parts = urlsplit(target)
        path, query = parts.path, parts.query
        if method not in ("GET", "POST"):
            raise LiveError(405, "method_not_allowed", f"{path} takes GET and POST")
        call = Call(path, {}, principal)
        self.backend.prune_sessions()
        if path == CAMPAIGN_PROPOSALS_PATH:
            return self.proposals(call, method, query, headers, body)
        if method == "GET":
            if body:
                raise LiveError(400, "bad_request", "a GET has no body")
            if not query:
                session = self.discover(call)
                return self.state(call, session, self.journal(session), [])
            name, epoch, after = parse_live_query(query)
            session = self.member_session(call, name)
            journal = self.current(session, epoch)
            return self.state(call, session, journal, journal.since(after))
        if query:
            raise LiveError(400, "bad_request", "a POST has no query")
        if headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
            raise LiveError(415, "unsupported_media_type", "a POST's body is application/json")
        name, epoch, first, events = parse_live_post(body)
        session = self.member_session(call, name)
        if not self.hosts(call, session):
            raise LiveError(403, "not_host", "only the game session's creator posts quest events, while in it")
        journal = self.current(session, epoch)
        journal.append(first, events)
        log.info("live quest events %d-%d posted to %s, whose journal ends at %d", first,
                 first + len(events) - 1, session.name, journal.last)
        return self.state(call, session, journal)

    def proposals(self, call: Call, method: str, query: str, headers: dict[str, str], body: bytes) -> Response:
        if method == "GET":
            if body:
                raise LiveError(400, "bad_request", "a GET has no body")
            name, epoch, after = parse_live_query(query)
            session = self.member_session(call, name)
            if not self.hosts(call, session):
                raise LiveError(403, "not_host", "only the session creator polls guest proposals")
            journal = self.current(session, epoch).proposals
            return live_response(200, {"session": session.name, "epoch": epoch, "first": journal.first,
                                       "last": journal.last, "proposals": journal.since(after)})
        if query:
            raise LiveError(400, "bad_request", "a POST has no query")
        if headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
            raise LiveError(415, "unsupported_media_type", "a POST's body is application/json")
        name, epoch, producer, first, changes = parse_proposal_post(body)
        session = self.member_session(call, name)
        if self.hosts(call, session):
            raise LiveError(403, "not_guest", "the creator posts authoritative events, not guest proposals")
        if session.creator not in session.user_sessions:
            raise LiveError(409, "host_absent", "guest proposals need the session creator present")
        journal = self.current(session, epoch).proposals
        added = journal.append(call.principal.account, producer, first, changes)
        return live_response(200, {"session": session.name, "epoch": epoch, "first": journal.first,
                                   "last": journal.last, "added": added})

    def member(self, call: Call, session: GameSession) -> bool:
        """Whether an active user of the caller's account is in `session` (after prune_sessions)."""
        return any(self.backend.owns(call, user) for user in session.user_sessions)

    def hosts(self, call: Call, session: GameSession) -> bool:
        """Whether the session's creator is in it and belongs to the caller's account."""
        return session.creator in session.user_sessions and self.backend.owns(call, session.creator)

    def discover(self, call: Call) -> GameSession:
        found = [session for session in self.backend.sessions.values() if self.member(call, session)]
        if not found:
            raise LiveError(404, "no_session", "no user of this account is in a live game session")
        if len(found) > 1:
            raise LiveError(404, "ambiguous_session", f"users of this account are in {len(found)} game sessions")
        return found[0]

    def member_session(self, call: Call, name: str) -> GameSession:
        session = self.backend.sessions.get(name)
        if session is None or not self.member(call, session):
            raise LiveError(404, "session_gone", "no user of this account is in that live game session")
        return session

    @staticmethod
    def journal(session: GameSession) -> LiveJournal:
        """The session's journal; a new one, with a new epoch, once its creator plays in it under
        another user session than the journal started with."""
        creator = session.user_sessions.get(session.creator)
        host = creator.name if creator is not None else ""
        if session.live is None or (host and host != session.live.host):
            session.live = LiveJournal(host)
            log.info("live quest events of %s start epoch %s", session.name, session.live.epoch)
        return session.live

    def current(self, session: GameSession, epoch: str) -> LiveJournal:
        journal = self.journal(session)
        if epoch != journal.epoch:
            raise LiveError(409, "stale_epoch", "the session's quest events started over in another epoch")
        return journal

    def state(self, call: Call, session: GameSession, journal: LiveJournal,
              events: list[dict[str, int]] | None = None) -> Response:
        payload = {"session": session.name, "epoch": journal.epoch,
                   "role": "host" if self.hosts(call, session) else "guest",
                   "first": journal.first, "last": journal.last}
        if events is not None:
            payload["events"] = events
        return live_response(200, payload)


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
            target = headers.get(":path", "")
            if is_campaign_live(target):
                result = self.server.campaign.handle(method, target, headers, body, self.principal)
            elif method in ("GET", "HEAD") and (self.downloads >= MAX_DOWNLOADS_PER_CONNECTION
                                                or self.server.downloads >= MAX_DOWNLOADS):
                result = response(503, b"too many downloads at once\n")
            else:
                result = self.server.storage.handle(method, target, headers, body, self.principal)
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


# --- HTTP/1.1 (island storage and live campaign events only) ----------------------------------


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
            target = request.target.decode("latin-1")
            if is_campaign_live(target):
                result = server.campaign.handle(method, target, headers, data, principal)
            elif method in ("GET", "HEAD") and server.downloads >= MAX_DOWNLOADS:
                result = response(503, b"too many downloads at once\n")
            else:
                result = server.storage.handle(method, target, headers, data, principal)
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
SNAPSHOT_CAMPAIGN_PROTOCOL = b"pokopia-snapshot 2"
SNAPSHOT_CHUNK_SIZE = 256 * 1024
# A snapshot client that takes no data for this long is dropped, closing the blobs held open for it.
# It is generous because the client may be streaming into a slow upload.
SNAPSHOT_STALL_SECONDS = 300


class SnapshotService:
    """Serves backup snapshots of the store over a Unix socket (--snapshot-socket, Linux only).

    A client gets "pokopia-snapshot 1" or, with campaigns, "pokopia-snapshot 2", followed by
    "ok", "busy" or "denied". After "ok" comes a tar stream: data/state.json,
    data/blobs/<id> for each blob that state refers to, and last snapshot.json with the size and
    SHA-256 of each file and "damaged_blobs": every referenced blob whose file is missing or not the
    size the state records. Store.snapshot captures those files at one moment. If a campaign registry
    is provided, its files and independent inventory are captured separately; the two stores are not
    one atomic snapshot. Other requests continue while the snapshot streams. Only root and the
    server's own user are served, one at a time. Failure leaves the stream unfinished.
    """

    def __init__(self, store: Store, campaigns: campaign_store.CampaignRegistry | None = None):
        self.store = store
        self.campaigns = campaigns
        self.protocol = SNAPSHOT_CAMPAIGN_PROTOCOL if campaigns is not None else SNAPSHOT_PROTOCOL
        self.busy = False

    async def on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            credentials = writer.get_extra_info("socket").getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", credentials)
            if uid not in (0, os.geteuid()):
                log.warning("snapshot refused to uid %d", uid)
                writer.write(self.protocol + b" denied\n")
            elif self.busy:
                writer.write(self.protocol + b" busy\n")
            else:
                self.busy = True
                try:
                    await self.send(writer)
                finally:
                    self.busy = False
        except (OSError, asyncio.TimeoutError, campaign_store.CampaignError) as exc:
            log.warning("snapshot not sent: %r", exc)
        finally:
            writer.close()

    async def send(self, writer: asyncio.StreamWriter) -> None:
        created = time.time()
        state, blobs, damaged = self.store.snapshot()
        campaign_backup = None
        try:
            if self.campaigns is not None:
                capture = asyncio.create_task(asyncio.to_thread(self.campaigns.capture_backup))
                try:
                    campaign_backup = await asyncio.shield(capture)
                except BaseException:
                    # Cancellation cannot stop a thread. Close its result when capture completes.
                    def discard(task: asyncio.Task) -> None:
                        try:
                            task.result().close()
                        except BaseException:
                            log.exception("failed to discard cancelled campaign backup")
                    capture.add_done_callback(discard)
                    raise
            sent = 0
            files: dict[str, dict] = {}

            async def put(data: bytes) -> None:
                nonlocal sent
                sent += len(data)
                writer.write(data)
                await asyncio.wait_for(writer.drain(), SNAPSHOT_STALL_SECONDS)

            async def add(name: str, size: int, read: Callable[[int, int], bytes], *, threaded: bool = False) -> None:
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = size, int(created), 0o600
                await put(info.tobuf(tarfile.PAX_FORMAT))
                digest = hashlib.sha256()
                offset = 0
                while offset < size:
                    count = min(SNAPSHOT_CHUNK_SIZE, size - offset)
                    chunk = await asyncio.to_thread(read, offset, count) if threaded else read(offset, count)
                    if not chunk:
                        raise OSError(f"{name} ended after {offset} of {size} bytes")
                    digest.update(chunk)
                    offset += len(chunk)
                    await put(chunk)
                await put(bytes(-size % tarfile.BLOCKSIZE))
                files[name] = {"size": size, "sha256": digest.hexdigest()}

            writer.write(self.protocol + b" ok\n")
            await add("data/state.json", len(state), lambda offset, n: state[offset : offset + n])
            for blob_id, fd, size in blobs:
                await add(f"data/blobs/{blob_id}", size, lambda offset, n, fd=fd: os.pread(fd, n, offset))
            inventory = None
            if campaign_backup is not None:
                inventory = {f"data/campaigns/{file.path}": {"size": file.size, "sha256": file.sha256}
                             for file in campaign_backup.files}
                for file in campaign_backup.files:
                    await add(f"data/campaigns/{file.path}", file.size, file.read, threaded=True)
            if damaged:
                log.warning("snapshot: damaged blobs: %s", "; ".join(damaged))
            metadata = {"format": 1, "created": created, "files": files, "damaged_blobs": damaged}
            if inventory is not None:
                metadata["campaign_inventory"] = inventory
            manifest = json.dumps(metadata, indent=1).encode()
            await add("snapshot.json", len(manifest), lambda offset, n: manifest[offset : offset + n])
            end = bytes(2 * tarfile.BLOCKSIZE)
            await put(end + bytes(-(sent + len(end)) % tarfile.RECORDSIZE))
            log.info("snapshot sent: state, %d blob(s), %d bytes", len(blobs), sent)
        finally:
            for _, fd, _ in blobs:
                os.close(fd)
            if campaign_backup is not None:
                # A cancelled read may still hold the backup lock in its worker.
                await asyncio.to_thread(campaign_backup.close)


def raise_open_file_limit() -> None:
    """A snapshot holds every blob open, so lift the soft open-file limit (often 1024) to the hard one."""
    import resource  # Unix only

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


# --- Server -----------------------------------------------------------------------------------


class Server:
    def __init__(self, args: argparse.Namespace, turn: TurnServer | None = None, relay: RelayOnly | None = None):
        self.store = Store(args.data_dir)
        self.campaigns = campaign_store.CampaignRegistry(campaign_store.CampaignStore(args.data_dir / "campaigns"))
        self.storage = Storage(self.store, args.storage_url.rstrip("/"))
        self.storage.max_bytes = args.max_storage_mb * 1024 * 1024
        self.backend = Backend(self.store, self.storage, args.max_players, advertised_stun(args),
                               args.gamesync_port or (args.port or DEFAULT_TLS_PORTS)[0], turn, relay)
        self.campaign = CampaignLive(self.backend)  # /campaign/live
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
                    if path == GAME_SESSIONS + "AllocateIceServerSet":  # may hold a TURN password
                        log.debug("response: <%d bytes, ICE server set not dumped>", len(response_payload))
                    else:
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

    async def purge_deleted_accounts_once(self) -> None:
        """Purge deleted accounts from game data and campaigns; incomplete campaign work retries."""
        deleted = self.auth.deleted_accounts()
        if not deleted:
            return
        owners = {user.get("owner") for user in self.store.users.values()}
        owners.update(upload.get("owner") for upload in self.store.uploads.values())
        for account in deleted & owners:
            self.backend.purge_account(account)
        try:
            campaign_accounts = await asyncio.to_thread(self.campaigns.accounts)
        except campaign_store.CampaignError:
            log.exception("could not enumerate campaign accounts for deletion; will retry")
            return
        for account in deleted & campaign_accounts:
            try:
                result = await asyncio.to_thread(self.campaigns.purge_account, account)
                if result.unfinished:
                    log.warning("campaign purge for %s is incomplete; will retry", account)
            except campaign_store.CampaignError:
                log.exception("campaign purge for %s failed; will retry", account)

    async def purge_deleted_accounts(self) -> None:
        """Purge deleted portal accounts at startup and then every minute."""
        while True:
            await self.purge_deleted_accounts_once()
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


async def serve(args: argparse.Namespace, turn: TurnServer | None = None, relay: RelayOnly | None = None) -> None:
    server = Server(args, turn, relay)
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
        snapshots = SnapshotService(server.store, server.campaigns)
        listeners.append(await asyncio.start_unix_server(snapshots.on_connection, args.snapshot_socket))
        os.chmod(args.snapshot_socket, 0o600)
        log.info("backup snapshots on %s", args.snapshot_socket)
    log.info("AllocateIceServerSet hands out STUN server %s", server.backend.stun or "(none)")
    if turn is not None:
        log.info("AllocateIceServerSet hands out TURN server %s:%d (UDP) with credentials for %d s",
                 turn.host, turn.port, TURN_CREDENTIAL_SECONDS)
    if relay is not None:
        log.info("relay-only: gamesync session descriptions are delivered with only relay candidates at "
                 "%s ports %d-%d", relay.address, *relay.ports)
    log.info("upload/download URIs use %s; data in %s", server.storage.base_url, args.data_dir)
    # Short sleeps keep Ctrl+C responsive on Windows.
    while True:
        await asyncio.sleep(1)


def turn_settings(args: argparse.Namespace) -> tuple[TurnServer | None, RelayOnly | None]:
    """The TURN server (--turn, --turn-secret-file) and relay-only delivery (--relay-only,
    --turn-relay-ports) the options ask for; ValueError says what is wrong with them."""
    if (args.turn is None) != (args.turn_secret_file is None):
        raise ValueError("--turn and --turn-secret-file go together")
    if args.relay_only != (args.turn_relay_ports is not None):
        raise ValueError("--relay-only and --turn-relay-ports go together")
    if args.turn is None:
        if args.relay_only:
            raise ValueError("--relay-only needs --turn")
        return None, None
    host, _, port = args.turn.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("--turn must be host:port")
    try:
        secret = args.turn_secret_file.read_bytes().strip()
    except OSError as exc:
        raise ValueError(f"--turn-secret-file: {exc}") from None
    # The secret is coturn's static-auth-secret, written as one word in turnserver.conf.
    if len(secret) < MIN_TURN_SECRET_BYTES or not re.fullmatch(rb"[\x21-\x7e]+", secret):
        raise ValueError(f"--turn-secret-file must hold one line of at least {MIN_TURN_SECRET_BYTES} "
                         "printable ASCII characters without spaces, e.g. from openssl rand -hex 32")
    if not args.relay_only:
        return TurnServer(host, int(port), secret), None
    try:
        address = str(ipaddress.IPv4Address(host))
    except ValueError:
        raise ValueError("--relay-only needs --turn as IPv4-address:port: relay candidates must name "
                         "that address") from None
    low, _, high = args.turn_relay_ports.partition(":")
    if not (low.isdigit() and high.isdigit() and 0 < int(low) <= int(high) < 65536):
        raise ValueError("--turn-relay-ports must be MIN:MAX, the TURN server's relay port range")
    return TurnServer(address, int(port), secret), RelayOnly(address, (int(low), int(high)))


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
    parser.add_argument("--turn", metavar="HOST:PORT",
                        help="TURN server (UDP) handed out by AllocateIceServerSet with credentials "
                             "that expire with the ICE server set (coturn use-auth-secret); needs "
                             "--turn-secret-file")
    parser.add_argument("--turn-secret-file", type=Path,
                        help="file holding the TURN server's static-auth-secret, kept off the command "
                             "line so the process list does not show it")
    parser.add_argument("--relay-only", action="store_true",
                        help="deliver gamesync session descriptions with only relay candidates on the "
                             "--turn server and no player's own address; needs --turn as an IPv4 "
                             "address and --turn-relay-ports")
    parser.add_argument("--turn-relay-ports", metavar="MIN:MAX",
                        help="the TURN server's relay port range (coturn min-port:max-port), the only "
                             "ports --relay-only lets relay candidates name")
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
    try:
        turn, relay = turn_settings(args)
    except ValueError as exc:
        parser.error(str(exc))
    if os.name == "posix":
        os.umask(0o077)  # state.json, blobs and temporary files are secret (see Store)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    for noisy in ("asyncio", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    try:
        asyncio.run(serve(args, turn, relay))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
