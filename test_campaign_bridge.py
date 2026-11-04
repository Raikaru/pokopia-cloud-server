"""Tests of campaign_bridge, the live quest event transport: event order, loss, retries and fail-closed stops.

The relays run against a simulated patched game: the patch bytes, the capability mask, and a mailbox whose
game side behaves like caves J (reserve, entry, commit, loss count) and D and the unique-quest journal, with
the drain's thread told apart from other game threads. This simulates the patch's specified behavior; it does
not test the patch. The relays talk over real TLS with client certificates to a test double of /campaign/live
and /campaign/live/proposals, which is written from the shared contract and not taken from server.py;
ServerContractTest puts server.py's own CampaignLive behind the same transport when server.py's dependencies
are installed. On Windows, GameProcess also attaches to a child process laid out like the game.

    .\\.venv\\Scripts\\python.exe -m unittest test_campaign_bridge
"""
from __future__ import annotations

import datetime
import functools
import http.server
import json
import logging
import os
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import campaign_bridge as cb

logging.getLogger("campaign_bridge").addHandler(logging.NullHandler())  # expected warnings stay out of the output

SCRATCH = Path(__file__).resolve().parent.parent / "_scratch" / "quest_sync_trace"
MAIN = 0x80004000
MANAGER = 0x90000000
SPECTATOR_CAPS = 0x0387800000  # 00 00 80 87 03
SESSION = "sessions/coop one"
EPOCH = "abcdefghijklmnopqrst"
SERVER_NAME = "campaign.test"
GAME_THREAD, OTHER_THREAD = 0x7F0000100000, 0x7F0000200000  # TPIDRRO_EL0 of the story update thread and another


# --- The game ------------------------------------------------------------------------------------------------

class FakeGame:
    """The patched game as a relay sees it. Its mailbox side follows the caves: set_quest journals like cave J
    around the quest state setter, frame() drains like cave D and apply_one. `thread` is the TPIDRRO_EL0 of the
    game thread that runs: GAME_THREAD, which also runs the drain, unless a change names another."""

    def __init__(self, host: bool, caps: int | None = None) -> None:
        if caps is None:
            caps = cb.HOST_CAPS if host else cb.GUEST_CAPS
        self.main = MAIN
        self.memory: dict[int, bytearray] = {
            MAIN + cb.CAVE: bytearray(cb.CAVE_BYTES),
            MAIN + cb.G_GM: bytearray(struct.pack("<Q", MANAGER)),
            MANAGER + 0x8C: bytearray(caps.to_bytes(5, "little")),
            MAIN + cb.MAILBOX: bytearray(cb.MAILBOX_SIZE),
        }
        for offset, data in cb.HOOKS.items():
            self.memory[MAIN + offset] = bytearray(data)
        self.states: dict[int, int] = {}
        self.taken: list[tuple[int, int, int]] = []  # (id, target, op) of every inbox entry the drain took
        self.writes: list[tuple[int, bytes]] = []  # (mailbox offset, data) the relay wrote
        self.exited = False
        self.thread = GAME_THREAD
        self.on_journal_read: Callable[[], None] | None = None
        # (story quest, new state) -> the unique changes (id, old, new, field, site) its writer makes as well
        self.unique_effects: dict[tuple[int, int], list[tuple[int, int, int, str, int]]] = {}

    @property
    def mb(self) -> bytearray:
        return self.memory[MAIN + cb.MAILBOX]

    def alive(self) -> bool:
        return not self.exited

    def read(self, address: int, size: int) -> bytes:
        if self.exited:
            raise cb.ProcessLost("the fake game exited")
        if address == MAIN + cb.MAILBOX + cb.MB_JOURNAL and self.on_journal_read:
            hook, self.on_journal_read = self.on_journal_read, None
            hook()
        for start, region in self.memory.items():
            if start <= address and address + size <= start + len(region):
                return bytes(region[address - start:address - start + size])
        raise cb.ProcessLost(f"unmapped read {address:#x}+{size:#x}")

    def write(self, address: int, data: bytes) -> None:
        if self.exited:
            raise cb.ProcessLost("the fake game exited")
        offset = address - (MAIN + cb.MAILBOX)
        if offset < 0 or offset + len(data) > cb.MAILBOX_SIZE:
            raise AssertionError(f"the relay wrote outside the mailbox: {address:#x}+{len(data):#x}")
        self.mb[offset:offset + len(data)] = data
        self.writes.append((offset, bytes(data)))

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.mb, offset)[0]

    def set_u32(self, offset: int, value: int) -> None:
        struct.pack_into("<I", self.mb, offset, value & 0xFFFFFFFF)

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.mb, offset)[0]

    def set_u64(self, offset: int, value: int) -> None:
        struct.pack_into("<Q", self.mb, offset, value)

    def on_drain_thread(self) -> bool:
        """What the patch's journals test: the drain is applying and this thread entered it."""
        return self.u32(cb.MB_APPLYING) != 0 and self.thread == self.u64(cb.MB_DRAIN_TLS)

    def set_caps(self, caps: int) -> None:
        self.memory[MANAGER + 0x8C][:] = caps.to_bytes(5, "little")

    def armed(self, flag: int) -> bool:
        return self.u32(cb.MB_MAGIC) == cb.MAGIC and bool(self.u32(cb.MB_FLAGS) & flag)

    def set_quest(self, qid: int, new: int) -> None:
        """The game's quest state setter with cave J around it, and the unique changes it makes with it."""
        old = self.states.get(qid, 1)
        self.states[qid] = new
        if old != new and 1 <= new <= 4 and 1 <= qid <= 1000:
            seq = self.reserve_story(qid, old, new)
            if seq is not None:
                self.commit_story(seq)
        if old != new:
            for effect in self.unique_effects.get((qid, new), ()):
                self.unique_change(*effect)

    def reserve_story(self, qid: int, old: int, new: int, origin: int | None = None) -> int | None:
        """Cave J after the setter: origin 1 on the drain's thread while it applies, else 0, unless given. A
        sequence is reserved only while the journal has room and below 0xffffffff, then the entry is stored;
        returns the sequence for commit_story. Otherwise nothing is reserved or overwritten, and the loss count
        goes up (saturating)."""
        if not self.armed(cb.FLAG_JOURNAL):
            return None
        if origin is None:
            origin = int(self.on_drain_thread())
        w = self.u32(cb.MB_OUT_W)
        if (w - self.u32(cb.MB_STORY_R)) & 0xFFFFFFFF >= cb.JOURNAL_SLOTS or w == 0xFFFFFFFF:
            self.set_u32(cb.MB_STORY_LOST, min(self.u32(cb.MB_STORY_LOST) + 1, 0xFFFFFFFF))
            return None
        self.set_u32(cb.MB_OUT_W, w + 1)
        self.set_u32(cb.MB_JOURNAL + 4 * (w % cb.JOURNAL_SLOTS), qid | (old & 0xF) << 16 | new << 20 | origin << 24)
        return w

    def commit_story(self, seq: int) -> None:
        """Cave J's release store that publishes the entry of sequence seq."""
        self.set_u32(cb.MB_STORY_COMMITS + 4 * (seq % cb.JOURNAL_SLOTS), seq + 1)

    def forge_story(self, word: int) -> None:
        """A committed story journal entry that cave J would never write, from someone else."""
        w = self.u32(cb.MB_OUT_W)
        self.set_u32(cb.MB_JOURNAL + 4 * (w % cb.JOURNAL_SLOTS), word)
        self.set_u32(cb.MB_OUT_W, w + 1)
        self.commit_story(w)

    def fast_forward(self, seq: int) -> None:
        """A story journal that has already carried seq changes, all of them read."""
        for done in range(max(seq - cb.JOURNAL_SLOTS, 0), seq):
            self.commit_story(done)
        self.set_u32(cb.MB_OUT_W, seq)
        self.set_u32(cb.MB_STORY_R, seq)

    def unique_change(self, qid: int, old: int, new: int, field: str, site: int, origin: int | None = None) -> None:
        """A unique-quest byte write with the patch's unique journal around its writer: origin 2 (a side effect
        on the drain thread) while the drain applies an entry on this thread, else 0, unless given. A
        reservation is counted before its entry is committed; a full ring drops the change and counts it as
        lost."""
        if not self.armed(cb.FLAG_UNIQUE_JOURNAL):
            return
        if origin is None:
            origin = 2 if self.on_drain_thread() else 0
        w = self.u32(cb.MB_UJ_W)
        if w - self.u32(cb.MB_UJ_R) >= cb.UNIQUE_JOURNAL_SLOTS:
            self.set_u32(cb.MB_UJ_LOST, self.u32(cb.MB_UJ_LOST) + 1)
            return
        slot = cb.MB_UNIQUE_JOURNAL + 8 * (w % cb.UNIQUE_JOURNAL_SLOTS)
        self.set_u32(cb.MB_UJ_W, w + 1)
        self.set_u32(slot, qid | old << 8 | new << 16 | (field == "counter") << 24 | origin << 25 | site << 27)
        self.set_u32(slot + 4, w + 1)

    def change(self, qid: int, old: int, new: int, thread: int | None = None) -> None:
        """A quest change the game makes itself, on GAME_THREAD unless another thread is given."""
        running, self.thread = self.thread, self.thread if thread is None else thread
        try:
            self.states[qid] = old
            self.set_quest(qid, new)
        finally:
            self.thread = running

    def frame(self, budget: int = 8, during: Callable[[], None] | None = None) -> None:
        """Cave D: records its thread, then takes up to 8 inbox entries before the story quest update. during
        runs while the drain is still applying, as another thread's work would."""
        if not self.armed(cb.FLAG_DRAIN):
            return
        self.set_u64(cb.MB_DRAIN_TLS, self.thread)
        self.set_u32(cb.MB_APPLYING, 1)
        for _ in range(budget):
            r = self.u32(cb.MB_IN_R)
            if r == self.u32(cb.MB_IN_W):
                break
            word = self.u32(cb.MB_INBOX + 4 * (r % cb.INBOX_SLOTS))
            self.set_u32(cb.MB_IN_R, r + 1)
            self.apply_one(word)
            self.set_u32(cb.MB_APPLIED, self.u32(cb.MB_APPLIED) + 1)
        if during:
            during()
        self.set_u32(cb.MB_APPLYING, 0)

    def apply_one(self, word: int) -> None:
        qid, target, op = word & 0xFFFF, word >> 16 & 0xFF, word >> 24
        self.taken.append((qid, target, op))
        if not (1 <= qid <= 1000 and 2 <= target <= 4) or self.states.get(qid, 1) >= target:
            return
        current = self.states.get(qid, 1)
        if op == cb.OP_FORCE4:
            if target == 4:
                self.set_quest(qid, 4)
        elif op == cb.OP_GAME:
            if target == 2:
                self.set_quest(qid, 2)
                return
            if current < 3:
                self.set_quest(qid, 3)
            if target == 4:
                self.set_quest(qid, 4)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# --- The server ----------------------------------------------------------------------------------------------

def error(status: int, code: str, **extra: object) -> tuple[int, dict]:
    return status, {"error": code, "message": code.replace("_", " "), **extra}


class Contract:
    """/campaign/live from the shared contract: a bounded journal per session and epoch, 409 for stale epochs,
    for cursors outside the retained history, and for sequence gaps, conflicts or expiry. POST
    /campaign/live/proposals takes guest proposals into a bounded journal of its own, numbered per producer,
    with the same 409s, 409 host_absent while the creator is away and 429 past the producer limit."""

    RETAIN, PAGE, PRODUCERS = 1024, 64, 64

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.session, self.epoch, self.role = SESSION, EPOCH, "host"
        self.base = 0  # seqs 1..base were discarded
        self.events: list[tuple[int, int, int]] = []
        self.posts: list[dict] = []
        self.host_present = True
        self.proposal_base = 0  # proposals 1..proposal_base were discarded
        self.proposals: list[tuple[str, int, dict]] = []  # (producer, number, event), in the shared order
        self.producers: dict[str, int] = {}  # producer -> its newest number
        self.proposal_posts: list[dict] = []
        self.requests: list[tuple[str, str, str | None]] = []  # method, target, Host header
        # (method or "*", kind or a function that rewrites the answer), each used by one request
        self.faults: list[tuple[str, str | Callable[[dict], object]]] = []

    @property
    def last(self) -> int:
        return self.base + len(self.events)

    @property
    def proposal_last(self) -> int:
        return self.proposal_base + len(self.proposals)

    def view(self, events: list[dict] | None = None) -> dict:
        result = {"session": self.session, "epoch": self.epoch, "role": self.role, "first": self.base + 1,
                  "last": self.last}
        if events is not None:
            result["events"] = events
        return result

    def fault(self, method: str) -> str | Callable[[dict], object] | None:
        for index, (wanted, kind) in enumerate(self.faults):
            if wanted in (method, "*"):
                del self.faults[index]
                return kind
        return None

    def handle(self, method: str, target: str, body: bytes, content_type: str | None = None) -> tuple[int, dict]:
        url = urlsplit(target)
        if url.path == cb.PROPOSALS_PATH and method == "POST":
            return self.propose(body, content_type)
        if url.path != cb.LIVE_PATH:
            return error(404, "not_found")
        if method == "GET":
            if not url.query:
                return 200, self.view([])
            query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            if set(query) != {"session", "epoch", "after"} or any(len(v) != 1 for v in query.values()):
                return error(400, "bad_request")
            if query["session"][0] != self.session:
                return error(404, "session_gone")
            if query["epoch"][0] != self.epoch:
                return error(409, "stale_epoch")
            after = int(query["after"][0])
            if after < self.base:
                return error(409, "cursor_expired", first=self.base + 1, last=self.last)
            if after > self.last:
                return error(409, "cursor_ahead", first=self.base + 1, last=self.last)
            page = self.events[after - self.base:after - self.base + self.PAGE]
            return 200, self.view([{"seq": seq, "id": i, "old": o, "new": n}
                                   for seq, (i, o, n) in enumerate(page, after + 1)])
        request = json.loads(body)
        self.posts.append(request)
        if self.role != "host":
            return error(403, "not_host")
        if request["session"] != self.session:
            return error(404, "session_gone")
        if request["epoch"] != self.epoch:
            return error(409, "stale_epoch")
        first = request["first"]
        events = [(e["id"], e["old"], e["new"]) for e in request["events"]]
        if first <= self.base:
            return error(409, "sequence_expired", first=self.base + 1, last=self.last)
        if first > self.last + 1:
            return error(409, "sequence_gap", first=self.base + 1, last=self.last)
        for seq, event in enumerate(events, first):
            if seq <= self.last and self.events[seq - self.base - 1] != event:
                return error(409, "sequence_conflict", first=self.base + 1, last=self.last)
        self.events.extend(events[self.last - first + 1:])
        if len(self.events) > self.RETAIN:
            dropped = len(self.events) - self.RETAIN
            self.base += dropped
            del self.events[:dropped]
        return 200, self.view()

    def propose(self, body: bytes, content_type: str | None) -> tuple[int, dict]:
        if content_type != "application/json":
            return error(415, "unsupported_media_type")
        request = json.loads(body)
        self.proposal_posts.append(request)
        bounds = {"first": self.proposal_base + 1, "last": self.proposal_last}
        if request["session"] != self.session:
            return error(404, "session_gone")
        if self.role == "host":
            return error(403, "not_guest")
        if not self.host_present:
            return error(409, "host_absent")
        if request["epoch"] != self.epoch:
            return error(409, "stale_epoch")
        producer, first, events = request["producer"], request["first"], request["events"]
        if producer not in self.producers and len(self.producers) >= self.PRODUCERS:
            return error(429, "too_many_producers")
        last = self.producers.get(producer, 0)
        if first > last + 1:
            return error(409, "sequence_gap", **bounds)
        kept = {(owner, number): event for owner, number, event in self.proposals}
        overlap = min(len(events), last - first + 1)
        for number, event in enumerate(events[:overlap], first):
            if (producer, number) not in kept:
                return error(409, "sequence_expired", **bounds)
            if kept[producer, number] != event:
                return error(409, "sequence_conflict", **bounds)
        additions = events[overlap:]
        self.proposals += [(producer, number, event) for number, event in enumerate(additions, first + overlap)]
        if len(self.proposals) > self.RETAIN:
            dropped = len(self.proposals) - self.RETAIN
            self.proposal_base += dropped
            del self.proposals[:dropped]
        self.producers[producer] = max(last, first + len(events) - 1)
        return 200, {"session": self.session, "epoch": self.epoch, "first": self.proposal_base + 1,
                     "last": self.proposal_last, "added": len(additions)}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.serve("GET")

    def do_POST(self) -> None:
        self.serve("POST")

    def serve(self, method: str) -> None:
        contract: Contract = self.server.contract
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with contract.lock:
            contract.requests.append((method, self.path, self.headers.get("Host")))
            kind = contract.fault(method)
            if kind == "drop_before":
                self.close_connection = True
                return
            if kind == "unavailable":
                status, answer = error(503, "unavailable")
            else:
                status, answer = contract.handle(method, self.path, body, self.headers.get("Content-Type"))
            if kind == "drop_after":
                self.close_connection = True
                return
            if kind == "reorder":
                answer["events"].reverse()
            if kind == "gap":
                del answer["events"][0]
            if callable(kind):
                answer = kind(answer)
        payload = b'{"session": "a", "session": "b"}' if kind == "garbage" else json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class LiveServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.contract = Contract()
        self.socket = context.wrap_socket(self.socket, server_side=True)


class SessionBackend:
    """What server.CampaignLive asks of its Backend: the game sessions, and the account that owns each user."""

    def __init__(self, sessions: dict[str, object], owners: dict[str, str]) -> None:
        self.sessions, self.owners = sessions, owners

    def prune_sessions(self) -> None:
        pass

    def owns(self, call: object, user: str) -> bool:
        return self.owners.get(user) == call.principal.account


class ServerContract(Contract):
    """server.py's own CampaignLive behind the TLS double, serving one game session that the host account's
    user created and the guest account's user joined. Requests over TLS come from the guest account; call()
    makes them as either account."""

    def __init__(self, server: types.ModuleType) -> None:
        super().__init__()
        self.users = {"users/host": types.SimpleNamespace(name="userSessions/host"),
                      "users/guest": types.SimpleNamespace(name="userSessions/guest")}
        self.game_session = types.SimpleNamespace(name=SESSION, creator="users/host", user_sessions=self.users,
                                                  live=None)
        backend = SessionBackend({SESSION: self.game_session}, {"users/host": "acct-host", "users/guest": "acct-guest"})
        self.live = server.CampaignLive(backend)
        self.host = server.Principal("acct-host", "dev-host")
        self.guest = server.Principal("acct-guest", "dev-guest")

    def handle(self, method: str, target: str, body: bytes, content_type: str | None = None) -> tuple[int, dict]:
        return self.call(self.guest, method, target, body, content_type)

    def call(self, principal: object, method: str, target: str, body: bytes = b"",
             content_type: str | None = None) -> tuple[int, dict]:
        headers = {"content-type": content_type} if content_type is not None else {}
        result = self.live.handle(method, target, headers, body, principal)
        return result.status, json.loads(result.body)


def issue(name: str, key: ec.EllipticCurvePrivateKey, issuer: x509.Name, issuer_key: ec.EllipticCurvePrivateKey,
          *, usage: x509.ObjectIdentifier | None = None, dns: str | None = None) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = usage is None
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                              critical=False)
               .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False, key_agreement=False,
                                            key_cert_sign=ca, crl_sign=ca, encipher_only=False,
                                            decipher_only=False), critical=True))
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if dns is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def write_pair(directory: Path, name: str, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> None:
    (directory / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                              serialization.PrivateFormat.PKCS8,
                                                              serialization.NoEncryption()))


class LiveFixture(unittest.TestCase):
    """A TLS /campaign/live double that requires client certificates, and a client context built the way
    launcher.upstream_context builds it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        path = Path(cls.directory.name)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ingress CA")])
        ca = issue("test ingress CA", ca_key, ca_name, ca_key)
        cls.ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
        for name, usage, dns in (("server", ExtendedKeyUsageOID.SERVER_AUTH, SERVER_NAME),
                                 ("client", ExtendedKeyUsageOID.CLIENT_AUTH, None)):
            key = ec.generate_private_key(ec.SECP256R1())
            write_pair(path, name, issue(name, key, ca_name, ca_key, usage=usage, dns=dns), key)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(path / "server.pem", path / "server.key")
        server_context.load_verify_locations(cadata=cls.ca_pem)
        server_context.verify_mode = ssl.CERT_REQUIRED
        server_context.set_alpn_protocols(["http/1.1"])
        cls.server = LiveServer(server_context)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.ingress = {"host": "127.0.0.1", "port": cls.server.server_address[1], "server_name": SERVER_NAME}
        cls.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=cls.ca_pem)
        cls.context.minimum_version = ssl.TLSVersion.TLSv1_2
        cls.context.load_cert_chain(path / "client.pem", path / "client.key")
        cls.context.set_alpn_protocols(["http/1.1"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.directory.cleanup()

    def setUp(self) -> None:
        self.contract = Contract()
        self.server.contract = self.contract
        self.client = self.new_client()
        self.clock = Clock()

    def new_client(self) -> cb.LiveClient:
        client = cb.LiveClient(self.context, self.ingress, timeout=5)
        self.addCleanup(client.close)
        return client

    def host_relay(self, game: FakeGame, **options: object) -> cb.HostRelay:
        options.setdefault("heartbeat", 0)
        return cb.HostRelay(self.client, game, retry_delay=0, clock=self.clock, **options)

    def guest_relay(self, game: FakeGame, client: cb.LiveClient | None = None, **options: object) -> cb.GuestRelay:
        return cb.GuestRelay(client or self.client, game, poll_interval=0, retry_delay=0, clock=self.clock,
                             **options)

    def assert_stopped(self, game: FakeGame) -> None:
        self.assertEqual(game.u32(cb.MB_FLAGS), 0, "the relay left the mailbox armed")


def pump(relay: cb.GuestRelay, game: FakeGame, done: Callable[[], bool], limit: int = 300) -> None:
    for _ in range(limit):
        relay.step()
        game.frame()
        if done():
            return
    raise AssertionError("the guest relay did not finish")


def story(qid: int, old: int, new: int) -> dict:
    """A story proposal as the contract carries it."""
    return {"kind": "story", "id": qid, "old": old, "new": new}


def unique(qid: int, old: int, new: int, field: str, site: int) -> dict:
    """A unique-quest proposal as the contract carries it."""
    return {"kind": "unique", "id": qid, "old": old, "new": new, "field": field, "site": site}


# --- Tests -----------------------------------------------------------------------------------------------------

class PatchTest(unittest.TestCase):
    def test_every_patch_byte_is_checked(self) -> None:
        game = FakeGame(host=True)
        cb.verify_patch(game.read, MAIN)
        cells = [(MAIN + cb.CAVE, i) for i in range(len(cb.CAVE_BYTES))]
        cells += [(MAIN + offset, i) for offset, data in cb.HOOKS.items() for i in range(len(data))]
        for start, index in cells:
            game.memory[start][index] ^= 0x01
            with self.assertRaises(cb.PatchMismatch, msg=f"byte at {start + index:#x} not checked"):
                cb.verify_patch(game.read, MAIN)
            game.memory[start][index] ^= 0x01




class QuestEventTest(unittest.TestCase):
    def test_contract_limits(self) -> None:
        for fields in ((0, 1, 2), (1001, 1, 2), (5, 0, 2), (5, 2, 5), (5, 3, 3), (True, 1, 2), (5, 1.0, 2)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                cb.QuestEvent(*fields)

    def test_replay_entries_and_decreases(self) -> None:
        self.assertEqual(cb.QuestEvent(7, 1, 2).inbox_word(), 7 | 2 << 16)
        self.assertEqual(cb.QuestEvent(7, 2, 4).inbox_word(), 7 | 4 << 16)
        self.assertEqual(cb.QuestEvent(7, 1, 4).inbox_word(), 7 | 4 << 16 | cb.OP_FORCE4 << 24)
        for old, new in ((2, 1), (4, 1), (4, 3), (3, 2)):
            with self.subTest(old=old, new=new), self.assertRaises(cb.ResyncRequired):
                cb.QuestEvent(7, old, new).inbox_word()


class ProposalTest(unittest.TestCase):
    def test_contract_limits(self) -> None:
        for fields in (("story", 1000, 4, 1), ("unique", 11, 0, 2, "state", 0), ("unique", 11, 3, 4, "state", 1),
                       ("unique", 11, 5, 3, "state", 2), ("unique", 11, 4, 5, "state", 3),
                       ("unique", 200, 255, 0, "counter", 13), ("unique", 1, 0, 1, "counter", 4)):
            with self.subTest(fields=fields):
                expected = story(*fields[1:]) if fields[0] == "story" else unique(*fields[1:])
                self.assertEqual(cb.Proposal(*fields).payload(), expected)
        for fields in (("story", 3, 1, 2, "state", 0), ("story", 3, 2, 2), ("story", 1001, 1, 2), ("other", 3, 1, 2),
                       ("unique", 201, 0, 1, "counter", 4), ("unique", 0, 0, 1, "counter", 4),
                       ("unique", 11, 1, 1, "counter", 4), ("unique", 11, 0, 256, "counter", 4),
                       ("unique", 11, 6, 2, "state", 0), ("unique", 11, 1, 3, "state", 0),
                       ("unique", 11, 1, 2, "counter", 0), ("unique", 11, 1, 2, "state", 4),
                       ("unique", 11, 1, 2, "counter", 14), ("unique", 11, 1, 2, "state", 15),
                       ("unique", 11, True, 2, "counter", 4), ("unique", 11, 1, 2, "counter", 4.0),
                       ("unique", 11, 1, 2, None, None)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                cb.Proposal(*fields)

    def test_journal_entries_keep_their_kind(self) -> None:
        self.assertEqual(cb.Proposal.of(cb.JournalEntry(3, 1, 2, 0)), cb.Proposal("story", 3, 1, 2))
        entry = cb.UniqueJournalEntry(0, 11, "counter", 0, 3, 0, 10)
        self.assertEqual(cb.Proposal.of(entry), cb.Proposal("unique", 11, 0, 3, "counter", 10))


class MailboxTest(unittest.TestCase):
    def test_a_used_mailbox_is_refused_without_writing(self) -> None:
        self.assertEqual(cb.MB_STORY_COMMITS + 4 * cb.JOURNAL_SLOTS, cb.MAILBOX_SIZE)
        for offset in (cb.MB_OUT_W, cb.MB_STORY_R, cb.MB_STORY_LOST, cb.MAILBOX_SIZE - 4):
            with self.subTest(offset=hex(offset)):
                game = FakeGame(host=True)
                game.set_u32(offset, 1)
                with self.assertRaises(cb.MailboxError):
                    cb.Mailbox(game, drain=False, journal=True).attach()
                self.assertEqual(game.writes, [])

    def test_a_full_journal_drops_changes_without_overwriting_and_stops(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True)
        mailbox.attach()
        for qid in range(1, 129):
            game.change(qid, 1, 2)
        self.assertEqual([e.id for e in mailbox.read_journal()], list(range(1, 129)))
        self.assertEqual(game.u32(cb.MB_STORY_R), 128)
        for qid in range(1, 130):
            game.change(qid, 2, 3)
        self.assertEqual((game.u32(cb.MB_OUT_W), game.u32(cb.MB_STORY_LOST)), (256, 1))
        ring = [cb.JournalEntry.decode(game.u32(cb.MB_JOURNAL + 4 * slot)) for slot in range(cb.JOURNAL_SLOTS)]
        self.assertEqual(ring, [cb.JournalEntry(qid, 2, 3, 0) for qid in range(1, 129)])  # quest 129 was dropped
        for read in (mailbox.read_journal, mailbox.check):
            with self.assertRaisesRegex(cb.MailboxError, "1 quest changes were lost"):
                read()
        self.assertEqual(game.u32(cb.MB_STORY_R), 128)

    def test_loss_or_damage_around_a_read_acknowledges_nothing(self) -> None:
        damages = {"loss": lambda g: [g.change(qid, 1, 2) for qid in range(3, 131)],  # 127 fit, 1 is dropped
                   "cursor moved back": lambda g: g.set_u32(cb.MB_STORY_R, 0),
                   "cursor moved ahead": lambda g: g.set_u32(cb.MB_STORY_R, 2),
                   "reservations behind the cursor": lambda g: g.set_u32(cb.MB_OUT_W, 0),
                   "reservations past capacity": lambda g: g.set_u32(cb.MB_OUT_W, 2 + cb.JOURNAL_SLOTS),
                   "restart": lambda g: g.mb.__setitem__(slice(None), bytes(cb.MAILBOX_SIZE))}
        for when in ("before", "during"):
            for name, damage in damages.items():
                with self.subTest(when=when, damage=name):
                    game = FakeGame(host=True)
                    mailbox = cb.Mailbox(game, drain=False, journal=True)
                    mailbox.attach()
                    game.change(1, 1, 2)
                    self.assertEqual(len(mailbox.read_journal()), 1)
                    game.change(2, 1, 2)
                    writes = len(game.writes)
                    if when == "before":
                        damage(game)
                    else:
                        game.on_journal_read = functools.partial(damage, game)
                    with self.assertRaises(cb.MailboxError):
                        mailbox.read_journal()
                    self.assertEqual((len(game.writes), mailbox.story_r), (writes, 1))

    def test_entries_committed_out_of_order_wait_for_the_ones_reserved_before_them(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True)
        mailbox.attach()
        first, second = game.reserve_story(5, 1, 2), game.reserve_story(6, 1, 3)
        game.commit_story(second)
        self.assertEqual(mailbox.read_journal(), [])
        self.assertEqual((game.u32(cb.MB_STORY_R), mailbox.check()), (0, 0))
        game.on_journal_read = lambda: game.commit_story(first)  # after the commits were read: taken next time
        self.assertEqual(mailbox.read_journal(), [])
        third = game.reserve_story(7, 2, 4)
        self.assertEqual(mailbox.read_journal(), [cb.JournalEntry(5, 1, 2, 0), cb.JournalEntry(6, 1, 3, 0)])
        self.assertEqual(game.u32(cb.MB_STORY_R), 2)
        game.commit_story(third)
        self.assertEqual(mailbox.read_journal(), [cb.JournalEntry(7, 2, 4, 0)])
        self.assertEqual(game.u32(cb.MB_STORY_R), 3)

    def test_slots_are_reused_only_after_their_entries_were_read(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True)
        mailbox.attach()
        for _ in range(3):
            for qid in range(1, 101):
                game.change(qid, 1, 2)
            self.assertEqual([e.id for e in mailbox.read_journal()], list(range(1, 101)))
        first, second = game.reserve_story(1, 2, 3), game.reserve_story(2, 2, 3)  # slots of sequences 172 and 173
        game.commit_story(second)
        self.assertEqual(mailbox.read_journal(), [])
        game.commit_story(first)
        self.assertEqual(mailbox.read_journal(), [cb.JournalEntry(1, 2, 3, 0), cb.JournalEntry(2, 2, 3, 0)])
        self.assertEqual(game.u32(cb.MB_STORY_R), 302)

    def test_invalid_entries_or_commits_stop_it_with_nothing_acknowledged(self) -> None:
        words = {"quest 0": 1 << 16 | 2 << 20, "quest 1001": 1001 | 1 << 16 | 2 << 20, "new state 0": 5 | 1 << 16,
                 "new state 5": 5 | 1 << 16 | 5 << 20, "origin 2": 5 | 1 << 16 | 2 << 20 | 2 << 24,
                 "top bit": 5 | 1 << 16 | 2 << 20 | 1 << 31}
        for name, word in words.items():
            with self.subTest(name):
                game = FakeGame(host=True)
                mailbox = cb.Mailbox(game, drain=False, journal=True)
                mailbox.attach()
                game.change(4, 1, 2)  # valid, but it is not acknowledged either
                game.forge_story(word)
                with self.assertRaisesRegex(cb.MailboxError, "invalid story quest journal entry"):
                    mailbox.read_journal()
                self.assertEqual((game.u32(cb.MB_STORY_R), mailbox.story_r), (0, 0))
        for name, commit in (("garbage", 0x1234), ("a later lap", 2 + cb.JOURNAL_SLOTS)):
            with self.subTest(name):
                game = FakeGame(host=True)
                mailbox = cb.Mailbox(game, drain=False, journal=True)
                mailbox.attach()
                game.change(4, 1, 2)
                seq = game.reserve_story(5, 1, 2)
                game.set_u32(cb.MB_STORY_COMMITS + 4 * seq, commit)
                with self.assertRaisesRegex(cb.MailboxError, "commit"):
                    mailbox.read_journal()
                self.assertEqual((game.u32(cb.MB_STORY_R), mailbox.story_r), (0, 0))

    def test_the_story_sequence_never_wraps(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True)
        mailbox.attach()
        start = cb.U32 - cb.JOURNAL_SLOTS - 2
        game.fast_forward(start)
        mailbox.story_r = start  # as if this relay had read all of them
        game.change(1, 1, 2)
        self.assertEqual(mailbox.read_journal(), [cb.JournalEntry(1, 1, 2, 0)])
        game.change(2, 1, 2)
        with self.assertRaisesRegex(cb.MailboxError, "exhausted"):
            mailbox.read_journal()
        self.assertEqual(game.u32(cb.MB_STORY_R), start + 1)

    def test_journals_refuse_an_incompatible_patch_before_writing(self) -> None:
        for journal, unique_journal in ((True, False), (False, True)):
            with self.subTest(journal=journal, unique_journal=unique_journal):
                game = FakeGame(host=True)
                game.memory[MAIN + 0x6149F8][0] ^= 1
                mailbox = cb.Mailbox(game, drain=False, journal=journal, unique_journal=unique_journal)
                with self.assertRaises(cb.PatchMismatch):
                    mailbox.attach()
                self.assertEqual(game.writes, [])

    def test_unique_journal_waits_for_reserved_entries_in_order(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True, unique_journal=True)
        mailbox.attach()
        game.set_u32(cb.MB_UJ_W, 2)
        slot = cb.MB_UNIQUE_JOURNAL
        game.set_u32(slot, 11 | 2 << 8 | 3 << 16 | 2 << 27)
        game.set_u32(slot + 8, 11 | 3 << 16 | 1 << 24 | 10 << 27)
        game.set_u32(slot + 12, 2)
        self.assertEqual(mailbox.read_unique_journal(), [])
        self.assertEqual(game.u32(cb.MB_UJ_R), 0)
        game.set_u32(slot + 4, 1)
        events = mailbox.read_unique_journal()
        self.assertEqual([(e.sequence, e.id, e.field, e.old, e.new) for e in events],
                         [(0, 11, "state", 2, 3), (1, 11, "counter", 0, 3)])
        self.assertEqual(game.u32(cb.MB_UJ_R), 2)
        self.assertEqual(mailbox.check(), 0)

    def test_unique_journal_loss_during_read_is_not_acknowledged(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=False, unique_journal=True)
        mailbox.attach()
        game.set_u32(cb.MB_UJ_W, 1)
        game.set_u32(cb.MB_UNIQUE_JOURNAL, 11 | 2 << 8 | 3 << 16 | 2 << 27)
        game.set_u32(cb.MB_UNIQUE_JOURNAL + 4, 1)
        original_read = game.read

        def lose_during_read(address: int, size: int) -> bytes:
            data = original_read(address, size)
            if address == mailbox.base + cb.MB_UNIQUE_JOURNAL:
                game.set_u32(cb.MB_UJ_LOST, 1)
            return data

        game.read = lose_during_read
        with self.assertRaisesRegex(cb.MailboxError, "lost changes"):
            mailbox.read_unique_journal()
        self.assertEqual(game.u32(cb.MB_UJ_R), 0)

    def test_unique_journal_rejects_invalid_records_and_foreign_readers(self) -> None:
        for damage in ("invalid_record", "foreign_reader"):
            with self.subTest(damage=damage):
                game = FakeGame(host=True)
                mailbox = cb.Mailbox(game, drain=False, journal=False, unique_journal=True)
                mailbox.attach()
                if damage == "invalid_record":
                    game.set_u32(cb.MB_UJ_W, 1)
                    game.set_u32(cb.MB_UNIQUE_JOURNAL, 2 << 8 | 3 << 16 | 2 << 27)  # id zero
                    game.set_u32(cb.MB_UNIQUE_JOURNAL + 4, 1)
                else:
                    game.set_u32(cb.MB_UJ_R, 1)
                with self.assertRaises(cb.MailboxError):
                    mailbox.read_unique_journal()

    def test_reading_unique_journal_preserves_inbox_acknowledgement(self) -> None:
        game = FakeGame(host=False)
        mailbox = cb.Mailbox(game, drain=True, journal=True, unique_journal=True)
        mailbox.attach()
        mailbox.push([cb.QuestEvent(7, 1, 2).inbox_word()])
        game.frame()
        self.assertEqual(mailbox.read_unique_journal(), [])
        self.assertEqual(mailbox.check(), 1)

    def test_inbox_room_and_consumption(self) -> None:
        game = FakeGame(host=False)
        mailbox = cb.Mailbox(game, drain=True, journal=True)
        mailbox.attach()
        words = [cb.QuestEvent(qid, 1, 2).inbox_word() for qid in range(1, 71)]
        self.assertEqual(mailbox.push(words), 64)
        self.assertEqual(mailbox.push(words[64:]), 0)
        game.frame()
        self.assertEqual(mailbox.check(), 8)
        self.assertEqual(mailbox.push(words[64:]), 6)
        while game.u32(cb.MB_IN_R) != game.u32(cb.MB_IN_W):
            game.frame()
        self.assertEqual([qid for qid, _, _ in game.taken], list(range(1, 71)))

    def test_only_the_drain_thread_makes_replays_and_its_marker_is_not_foreign(self) -> None:
        game = FakeGame(host=False)
        mailbox = cb.Mailbox(game, drain=True, journal=True)
        mailbox.attach()
        mailbox.push([cb.QuestEvent(7, 1, 2).inbox_word()])
        game.frame(during=lambda: game.change(8, 1, 3, thread=OTHER_THREAD))
        game.change(9, 1, 2)  # on the drain's thread, after the drain returned
        self.assertEqual(game.u64(cb.MB_DRAIN_TLS), GAME_THREAD)
        self.assertEqual(mailbox.check(), 1)
        self.assertEqual(game.states[7], 2)
        self.assertEqual(mailbox.read_journal(), [cb.JournalEntry(7, 1, 2, 1), cb.JournalEntry(8, 1, 3, 0),
                                                  cb.JournalEntry(9, 1, 2, 0)])

    def test_a_lost_or_foreign_mailbox_is_detected(self) -> None:
        for name, damage in (("restart", lambda g: g.mb.__setitem__(slice(None), bytes(cb.MAILBOX_SIZE))),
                             ("in_w", lambda g: g.set_u32(cb.MB_IN_W, 3)),
                             ("flags", lambda g: g.set_u32(cb.MB_FLAGS, cb.FLAG_JOURNAL)),
                             ("in_r", lambda g: g.set_u32(cb.MB_IN_R, 1)),
                             ("spare", lambda g: g.set_u32(0x40, 1)),
                             ("story cursor", lambda g: g.set_u32(cb.MB_STORY_R, 1)),
                             ("story loss", lambda g: g.set_u32(cb.MB_STORY_LOST, 1)),
                             ("story reservations", lambda g: g.set_u32(cb.MB_OUT_W, cb.JOURNAL_SLOTS + 1)),
                             ("spare after the story words", lambda g: g.set_u32(cb.MB_STORY_LOST + 4, 1))):
            with self.subTest(name):
                game = FakeGame(host=False)
                mailbox = cb.Mailbox(game, drain=True, journal=True)
                mailbox.attach()
                mailbox.check()
                damage(game)
                with self.assertRaises(cb.MailboxError):
                    mailbox.check()
        for offset in (cb.MB_OUT_W, cb.MB_STORY_R, cb.MB_STORY_LOST):
            with self.subTest(disabled_story_word=hex(offset)):
                game = FakeGame(host=False)
                mailbox = cb.Mailbox(game, drain=True, journal=False)
                mailbox.attach()
                game.set_u32(offset, 1)
                with self.assertRaisesRegex(cb.MailboxError, "disabled story"):
                    mailbox.check()


class LiveClientTest(LiveFixture):
    def test_needs_a_context_that_verifies_the_server(self) -> None:
        unverified = ssl._create_unverified_context()
        with self.assertRaises(ValueError):
            cb.LiveClient(unverified, self.ingress)
        no_name = ssl.create_default_context(cadata=self.ca_pem)
        no_name.check_hostname = False
        with self.assertRaises(ValueError):
            cb.LiveClient(no_name, self.ingress)

    def test_a_certificate_for_another_name_is_refused(self) -> None:
        client = cb.LiveClient(self.context, {**self.ingress, "server_name": "other.test"}, timeout=5)
        self.addCleanup(client.close)
        with self.assertRaises(cb.LiveRefused) as caught:
            client.discover()
        self.assertEqual(caught.exception.code, "certificate")
        self.assertEqual(self.contract.requests, [])

    def test_requests_name_the_ingress_and_encode_the_query(self) -> None:
        view = self.client.discover()
        self.assertEqual(view, cb.LiveView(SESSION, EPOCH, "host", 1, 0))
        self.client.poll(SESSION, EPOCH, 0)
        port = self.ingress["port"]
        self.assertEqual(self.contract.requests, [
            ("GET", "/campaign/live", f"{SERVER_NAME}:{port}"),
            ("GET", f"/campaign/live?session=sessions%2Fcoop%20one&epoch={EPOCH}&after=0", f"{SERVER_NAME}:{port}")])

    def test_errors_keep_their_status_and_code(self) -> None:
        self.contract.role = "guest"
        with self.assertRaises(cb.LiveRefused) as caught:
            self.client.post(SESSION, EPOCH, 1, [cb.QuestEvent(1, 1, 2)])
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "not_host"))
        with self.assertRaises(cb.LiveRefused) as caught:
            self.client.poll("sessions/other", EPOCH, 0)
        self.assertEqual((caught.exception.status, caught.exception.code), (404, "session_gone"))
        with self.assertRaises(cb.LiveConflict) as caught:
            self.client.poll(SESSION, EPOCH, 3)
        self.assertEqual(caught.exception.code, "cursor_ahead")
        self.assertIsInstance(caught.exception, cb.ResyncRequired)
        self.contract.faults.append(("GET", "unavailable"))
        with self.assertRaises(cb.LiveUnavailable):
            self.client.discover()

    def test_malformed_answers_are_protocol_errors(self) -> None:
        self.contract.faults.append(("GET", "garbage"))
        with self.assertRaisesRegex(cb.ProtocolError, "duplicate key"):
            self.client.discover()

    def test_a_closed_kept_alive_connection_is_reopened_once(self) -> None:
        self.client.discover()
        self.contract.faults.append(("GET", "drop_before"))
        self.assertEqual(self.client.discover().last, 0)
        self.assertEqual(len(self.contract.requests), 3)
        self.contract.faults += [("GET", "drop_before"), ("GET", "drop_before")]
        with self.assertRaises(cb.LiveUnavailable):
            self.client.discover()

    def test_proposals_are_posted_as_one_batch_of_one_producer(self) -> None:
        self.contract.role = "guest"
        producer = "0123456789abcdef" * 2
        batch = [cb.Proposal("story", 3, 1, 2), cb.Proposal("unique", 11, 0, 3, "counter", 10)]
        self.assertEqual(self.client.propose(SESSION, EPOCH, producer, 1, batch), cb.ProposalReceipt(1, 2, 2))
        self.assertEqual(self.client.propose(SESSION, EPOCH, producer, 1, batch), cb.ProposalReceipt(1, 2, 0))
        self.assertEqual([request[:2] for request in self.contract.requests], [("POST", cb.PROPOSALS_PATH)] * 2)
        self.assertEqual(self.contract.proposal_posts[0], {"session": SESSION, "epoch": EPOCH, "producer": producer,
                                                           "first": 1, "events": [story(3, 1, 2),
                                                                                  unique(11, 0, 3, "counter", 10)]})
        for first, proposals, code in ((2, [cb.Proposal("story", 3, 1, 4)], "sequence_conflict"),
                                       (4, batch, "sequence_gap")):
            with self.subTest(code), self.assertRaises(cb.LiveConflict) as caught:
                self.client.propose(SESSION, EPOCH, producer, first, proposals)
            self.assertEqual(caught.exception.code, code)
        self.contract.role = "host"
        with self.assertRaises(cb.LiveRefused) as caught:
            self.client.propose(SESSION, EPOCH, producer, 3, batch)
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "not_guest"))
        self.assertEqual(self.contract.producers, {producer: 2})

    def test_proposal_posts_outside_the_contract_are_never_sent(self) -> None:
        producer, batch = "a" * 32, [cb.Proposal("story", 3, 1, 2)]
        for name, args in (("uppercase producer", (SESSION, EPOCH, "A" * 32, 1, batch)),
                           ("short producer", (SESSION, EPOCH, "a" * 31, 1, batch)),
                           ("no producer", (SESSION, EPOCH, None, 1, batch)),
                           ("first 0", (SESSION, EPOCH, producer, 0, batch)),
                           ("boolean first", (SESSION, EPOCH, producer, True, batch)),
                           ("exhausted", (SESSION, EPOCH, producer, cb.MAX_SEQ, batch * 2)),
                           ("empty", (SESSION, EPOCH, producer, 1, [])),
                           ("too many", (SESSION, EPOCH, producer, 1, batch * 65)),
                           ("not proposals", (SESSION, EPOCH, producer, 1, [cb.QuestEvent(3, 1, 2)])),
                           ("bad epoch", (SESSION, "bad epoch", producer, 1, batch))):
            with self.subTest(name), self.assertRaises(ValueError):
                self.client.propose(*args)
        self.assertEqual(self.contract.requests, [])


class HostRelayTest(LiveFixture):
    def test_sends_the_host_changes_in_game_order_after_the_server_journal(self) -> None:
        self.contract.events = [(900, 1, 2), (900, 2, 3)]
        game = FakeGame(host=True)
        relay = self.host_relay(game, batch=2)
        relay.start()
        self.assertEqual(relay.acked, 2)
        changes = [(10, 1, 2), (10, 2, 3), (11, 1, 4), (10, 3, 4), (12, 3, 1)]  # 12 is reset: allowed to send
        for change in changes:
            game.change(*change)
        for _ in range(3):
            relay.step()
        self.assertEqual(self.contract.events[2:], changes)
        self.assertEqual([post["first"] for post in self.contract.posts], [3, 5, 7])
        self.assertEqual((relay.acked, relay.pending), (7, 0))

    def test_a_replayed_change_on_the_host_stops_it_unsent(self) -> None:
        game = FakeGame(host=True)
        relay = self.host_relay(game)
        relay.start()
        game.change(5, 1, 2)
        game.set_u64(cb.MB_DRAIN_TLS, GAME_THREAD)  # someone else poses as the host's drain, which is off
        game.set_u32(cb.MB_APPLYING, 1)
        game.change(6, 1, 2)
        game.set_u32(cb.MB_APPLYING, 0)
        with self.assertRaisesRegex(cb.MailboxError, "replayed change"):
            relay.step()
        self.assertEqual(self.contract.posts, [])
        self.assert_stopped(game)
        with self.assertRaises(cb.BridgeError):
            relay.step()

    def test_a_change_committed_out_of_order_is_sent_after_the_one_reserved_before_it(self) -> None:
        game = FakeGame(host=True)
        relay = self.host_relay(game)
        relay.start()
        first = game.reserve_story(5, 1, 2)
        game.change(6, 1, 3, thread=OTHER_THREAD)  # reserved and committed while quest 5's entry is not committed
        relay.step()
        self.assertEqual((self.contract.events, relay.pending), ([], 0))
        game.commit_story(first)
        relay.step()
        self.assertEqual(self.contract.events, [(5, 1, 2), (6, 1, 3)])
        self.assertEqual((relay.acked, relay.pending), (2, 0))

    def test_journal_overflow_stops_before_anything_is_sent(self) -> None:
        game = FakeGame(host=True)
        relay = self.host_relay(game)
        relay.start()
        for qid in range(1, 130):
            game.change(qid, 1, 2)
        with self.assertRaises(cb.MailboxError):
            relay.step()
        self.assertEqual(self.contract.posts, [])
        self.assert_stopped(game)

    def test_lost_answers_are_resent_unchanged_and_stored_once(self) -> None:
        game = FakeGame(host=True)
        relay = self.host_relay(game)
        relay.start()
        self.contract.faults = [("POST", "drop_after"), ("POST", "drop_after"), ("POST", "drop_before"),
                                ("POST", "unavailable")]
        changes = [(1, 1, 2), (2, 1, 2), (1, 2, 3)]
        for change in changes:
            game.change(*change)
        relay.step()
        self.assertEqual((relay.acked, relay.pending), (0, 3))
        later = [(2, 2, 3), (1, 3, 4)]
        for change in later:
            game.change(*change)
        for _ in range(8):
            relay.step()
        self.assertEqual(self.contract.events, changes + later)
        self.assertEqual((relay.acked, relay.pending, self.contract.faults), (5, 0, []))
        sent: dict[int, list] = {}
        for post in self.contract.posts:
            self.assertEqual(sent.setdefault(post["first"], post["events"]), post["events"])
        self.assertEqual(sorted(sent), [1, 4])
        self.assertGreater(len(self.contract.posts), 3)

    def test_a_conflicting_journal_needs_resync(self) -> None:
        game = FakeGame(host=True)
        relay = self.host_relay(game)
        relay.start()
        self.contract.events.append((99, 1, 2))  # another writer took seq 1
        game.change(5, 1, 2)
        with self.assertRaises(cb.LiveConflict) as caught:
            relay.step()
        self.assertEqual(caught.exception.code, "sequence_conflict")
        self.assertIsInstance(caught.exception, cb.ResyncRequired)
        self.assert_stopped(game)

    def test_an_idle_host_notices_other_writers_and_new_epochs(self) -> None:
        for name, change, error_type in (("writer", lambda c: c.events.append((99, 1, 2)), cb.ResyncRequired),
                                         ("epoch", lambda c: setattr(c, "epoch", "z" * 20), cb.LiveConflict),
                                         ("gone", lambda c: setattr(c, "session", "sessions/next"), cb.LiveRefused),
                                         ("role", lambda c: setattr(c, "role", "guest"), cb.SessionChanged)):
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=True)
                relay = self.host_relay(game)
                relay.start()
                relay.step()
                change(self.contract)
                with self.assertRaises(error_type):
                    relay.step()
                self.assert_stopped(game)
                self.assertEqual(self.contract.posts, [])

    def test_an_unreachable_server_stops_it_after_the_offline_timeout(self) -> None:
        game = FakeGame(host=True)
        relay = self.host_relay(game, offline_timeout=30)
        relay.start()
        self.contract.faults = [("*", "drop_before")] * 20
        game.change(1, 1, 2)
        relay.step()
        self.clock.now = 29
        relay.step()
        self.assertEqual(relay.pending, 1)
        self.clock.now = 31
        with self.assertRaisesRegex(cb.BridgeError, "unreachable"):
            relay.step()
        self.assert_stopped(game)

    def test_needs_the_server_host_role_and_the_host_mask(self) -> None:
        self.contract.role = "guest"
        game = FakeGame(host=True)
        with self.assertRaises(cb.LiveRefused):
            self.host_relay(game).start()
        self.contract.role = "host"
        for caps in (cb.GUEST_CAPS, SPECTATOR_CAPS, 0x007FFFFFFF):
            with self.subTest(caps=hex(caps)):
                game = FakeGame(host=True, caps=caps)
                with self.assertRaises(cb.GameNotReady):
                    self.host_relay(game).start()
                self.assertEqual(game.writes, [])

    def test_a_game_that_changes_or_exits_stops_it(self) -> None:
        for name, damage, error_type in (("caps", lambda g: g.set_caps(SPECTATOR_CAPS), cb.SessionChanged),
                                         ("manager", lambda g: g.memory[MAIN + cb.G_GM].__setitem__(
                                             slice(None), bytes(8)), cb.SessionChanged),
                                         ("exit", lambda g: setattr(g, "exited", True), cb.ProcessLost),
                                         ("patch", lambda g: g.memory[MAIN + 0x5D865C].__setitem__(1, 0x04),
                                          cb.PatchMismatch)):
            with self.subTest(name):
                game = FakeGame(host=True)
                relay = self.host_relay(game)
                relay.start()
                game.change(1, 1, 2)
                damage(game)
                with self.assertRaises(error_type):
                    relay.step()
                self.assertEqual(self.contract.posts, [])
                if not game.exited:
                    self.assert_stopped(game)
                self.setUp()


class GuestRelayTest(LiveFixture):
    def test_replays_every_event_in_order_through_the_inbox(self) -> None:
        events = ([(q, 1, 2) for q in range(1, 51)] + [(q, 2, 3) for q in range(1, 51)]
                  + [(q, 3, 4) for q in range(1, 51)] + [(60, 1, 4)])
        self.contract.events = list(events)
        game = FakeGame(host=False)
        relay = self.guest_relay(game)
        relay.start()
        pump(relay, game, lambda: relay.consumed == len(events))
        self.assertEqual(game.taken, [(i, new, cb.OP_FORCE4 if (old, new) == (1, 4) else cb.OP_GAME)
                                      for i, old, new in events])
        self.assertEqual(game.states, {**{q: 4 for q in range(1, 51)}, 60: 4})
        self.assertEqual((relay.received, relay.replayed, relay.local_changes), (151, 151, 0))
        self.assertEqual(self.contract.posts, [])

    def test_guest_changes_and_replays_are_never_sent(self) -> None:
        self.contract.events = [(1, 1, 2)]
        game = FakeGame(host=False)
        relay = self.guest_relay(game)
        relay.start()
        self.assertEqual(game.u32(cb.MB_FLAGS), cb.FLAG_DRAIN | cb.FLAG_JOURNAL)  # no unique journal by default
        self.assertIsNone(relay.producer)
        pump(relay, game, lambda: relay.consumed == 1)
        game.change(3, 1, 2)
        relay.step()
        self.assertEqual((relay.replayed, relay.local_changes), (1, 1))
        self.assertEqual((relay.proposed, relay.proposals_pending), (0, 0))
        self.assertEqual(self.contract.events, [(1, 1, 2)])
        self.assertEqual({method for method, _, _ in self.contract.requests}, {"GET"})

    def test_a_decrease_needs_resync_before_its_batch_is_queued(self) -> None:
        for decrease in ((5, 2, 1), (5, 4, 2)):
            with self.subTest(decrease=decrease):
                self.setUp()
                self.contract.events = [(5, 1, 2), (6, 1, 2), decrease]
                game = FakeGame(host=False)
                relay = self.guest_relay(game)
                relay.start()
                with self.assertRaises(cb.ResyncRequired):
                    relay.step()
                self.assertEqual(game.u32(cb.MB_IN_W), 0)
                self.assert_stopped(game)
                game.frame()
                self.assertEqual(game.taken, [])

    def test_discarded_history_needs_resync(self) -> None:
        self.contract.base, self.contract.events = 10, [(1, 1, 2)]
        game = FakeGame(host=False)
        relay = self.guest_relay(game)
        relay.start()
        with self.assertRaises(cb.LiveConflict) as caught:
            relay.step()
        self.assertEqual(caught.exception.code, "cursor_expired")
        self.assert_stopped(game)

    def test_resumes_only_in_the_same_session_and_epoch(self) -> None:
        self.contract.events = [(q, 1, 2) for q in range(1, 11)]
        game = FakeGame(host=False)
        with self.assertRaises(cb.SessionChanged):
            self.guest_relay(game, session=SESSION, epoch="b" * 20, after=6).start()
        self.assertEqual(game.writes, [])
        with self.assertRaises(ValueError):
            self.guest_relay(game, after=6)
        relay = self.guest_relay(game, session=SESSION, epoch=EPOCH, after=6)
        relay.start()
        pump(relay, game, lambda: relay.consumed == 10)
        self.assertEqual([qid for qid, _, _ in game.taken], [7, 8, 9, 10])

    def test_events_out_of_order_or_missing_are_refused(self) -> None:
        for fault in ("reorder", "gap"):
            with self.subTest(fault):
                self.setUp()
                self.contract.events = [(1, 1, 2), (2, 1, 2), (3, 1, 2)]
                game = FakeGame(host=False)
                relay = self.guest_relay(game)
                relay.start()
                self.contract.faults.append(("GET", fault))  # after discovery, so the first poll gets it
                with self.assertRaises(cb.ProtocolError):
                    relay.step()
                self.assertEqual(game.u32(cb.MB_IN_W), 0)
                self.assert_stopped(game)

    def test_a_lost_poll_is_retried_from_the_same_cursor(self) -> None:
        self.contract.events = [(1, 1, 2), (2, 1, 2)]
        game = FakeGame(host=False)
        relay = self.guest_relay(game)
        relay.start()
        self.contract.faults = [("GET", "drop_after")] * 2
        relay.step()
        self.assertEqual(relay.received, 0)
        pump(relay, game, lambda: relay.consumed == 2)
        self.assertEqual([qid for qid, _, _ in game.taken], [1, 2])
        polls = [target for method, target, _ in self.contract.requests if "after=" in target]
        self.assertTrue(all(target.endswith("after=0") for target in polls[:3]), polls)

    def test_new_epochs_restarts_and_wrong_masks_stop_it(self) -> None:
        cases = (("epoch", lambda c, g: setattr(c, "epoch", "z" * 20), cb.LiveConflict),
                 ("restart", lambda c, g: g.mb.__setitem__(slice(None), bytes(cb.MAILBOX_SIZE)), cb.MailboxError),
                 ("caps", lambda c, g: g.set_caps(cb.HOST_CAPS), cb.SessionChanged))
        for name, damage, error_type in cases:
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=False)
                relay = self.guest_relay(game)
                relay.start()
                relay.step()
                damage(self.contract, game)
                with self.assertRaises(error_type):
                    relay.step()
        with self.assertRaises(cb.GameNotReady):
            self.guest_relay(FakeGame(host=True)).start()

    def test_a_story_journal_loss_or_damage_stops_even_a_replaying_guest(self) -> None:
        for name, damage in (("loss", lambda g: [g.change(qid, 1, 2) for qid in range(1, 130)]),
                             ("invalid entry", lambda g: g.forge_story(3 | 1 << 16 | 2 << 20 | 2 << 24)),
                             ("foreign cursor", lambda g: g.set_u32(cb.MB_STORY_R, 1))):
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=False)
                relay = self.guest_relay(game)
                relay.start()
                relay.step()
                damage(game)
                with self.assertRaises(cb.MailboxError):
                    relay.step()
                self.assert_stopped(game)


class ProposingGuestRelayTest(LiveFixture):
    """GuestRelay(propose=True) under the server role "guest"."""

    def setUp(self) -> None:
        super().setUp()
        self.contract.role = "guest"

    def proposer(self, game: FakeGame, **options: object) -> cb.GuestRelay:
        return self.guest_relay(game, propose=True, **options)

    def held(self) -> list[dict]:
        """The proposals the server holds, in its shared order."""
        return [event for _, _, event in self.contract.proposals]

    def test_sends_the_guest_games_own_story_and_unique_changes(self) -> None:
        game = FakeGame(host=False)
        relay = self.proposer(game, proposal_batch=2)
        relay.start()
        self.assertEqual(game.u32(cb.MB_FLAGS), cb.FLAG_DRAIN | cb.FLAG_JOURNAL | cb.FLAG_UNIQUE_JOURNAL)
        game.change(3, 1, 2)
        game.unique_change(11, 1, 2, "state", 0)
        game.change(3, 2, 4)
        game.unique_change(11, 0, 3, "counter", 10)
        game.unique_change(12, 3, 4, "state", 1)
        for _ in range(3):
            relay.step()
        # each ring in its own order, story first: the numbers give no order between the two rings
        self.assertEqual(self.held(), [story(3, 1, 2), story(3, 2, 4), unique(11, 1, 2, "state", 0),
                                       unique(11, 0, 3, "counter", 10), unique(12, 3, 4, "state", 1)])
        self.assertEqual([(producer, number) for producer, number, _ in self.contract.proposals],
                         [(relay.producer, number) for number in range(1, 6)])
        self.assertEqual([(post["first"], len(post["events"])) for post in self.contract.proposal_posts],
                         [(1, 2), (3, 2), (5, 1)])
        self.assertTrue(all(post.keys() == {"session", "epoch", "producer", "first", "events"}
                            for post in self.contract.proposal_posts))
        self.assertEqual((relay.proposed, relay.proposals_pending, relay.local_changes), (5, 0, 2))
        self.assertEqual(self.contract.posts, [])  # never an authoritative event

    def test_replays_and_drain_side_effects_are_never_proposed(self) -> None:
        self.contract.events = [(1, 1, 2), (2, 1, 4)]
        game = FakeGame(host=False)
        game.unique_effects[1, 2] = [(11, 1, 2, "state", 0)]
        game.unique_effects[2, 4] = [(12, 0, 1, "counter", 7)]
        game.unique_effects[5, 2] = [(14, 1, 2, "state", 0)]
        relay = self.proposer(game)
        relay.start()
        pump(relay, game, lambda: relay.consumed == 2)
        relay.step()
        game.unique_change(13, 4, 5, "state", 15, origin=1)  # a uniqueCas replay
        game.change(5, 1, 2)  # the guest's own change, and the unique change its writer makes with it
        relay.step()
        self.assertEqual(game.states, {1: 2, 2: 4, 5: 2})
        self.assertEqual(self.held(), [story(5, 1, 2), unique(14, 1, 2, "state", 0)])
        self.assertEqual((relay.replayed, relay.unique_replayed, relay.local_changes, relay.proposed), (2, 3, 1, 2))
        self.assertEqual(self.contract.posts, [])

    def test_another_threads_change_during_a_replay_is_proposed(self) -> None:
        self.contract.events = [(1, 1, 2)]
        game = FakeGame(host=False)
        game.unique_effects[8, 3] = [(14, 1, 2, "state", 0)]
        relay = self.proposer(game)
        relay.start()
        relay.step()
        game.frame(during=lambda: game.change(8, 1, 3, thread=OTHER_THREAD))
        relay.step()
        self.assertEqual(game.states, {1: 2, 8: 3})
        self.assertEqual(self.held(), [story(8, 1, 3), unique(14, 1, 2, "state", 0)])
        self.assertEqual((relay.consumed, relay.replayed, relay.local_changes, relay.proposed), (1, 1, 1, 2))

    def test_lost_answers_are_resent_with_the_same_numbers_and_content(self) -> None:
        game = FakeGame(host=False)
        relay = self.proposer(game, proposal_batch=2)
        relay.start()
        self.contract.faults = [("POST", "drop_after"), ("POST", "drop_after"), ("POST", "drop_before"),
                                ("POST", "unavailable")]
        game.change(1, 1, 2)
        game.change(2, 1, 2)
        game.unique_change(11, 1, 2, "state", 0)
        relay.step()
        self.assertEqual((relay.proposed, relay.proposals_pending), (0, 3))
        game.change(1, 2, 3)
        for _ in range(8):
            relay.step()
        self.assertEqual(self.held(), [story(1, 1, 2), story(2, 1, 2), unique(11, 1, 2, "state", 0), story(1, 2, 3)])
        self.assertEqual((relay.proposed, relay.proposals_pending, self.contract.faults), (4, 0, []))
        self.assertEqual(self.contract.producers, {relay.producer: 4})
        sent: dict[int, tuple[str, list]] = {}
        for post in self.contract.proposal_posts:
            self.assertEqual(sent.setdefault(post["first"], (post["producer"], post["events"])),
                             (post["producer"], post["events"]))
        self.assertEqual(sorted(sent), [1, 3])
        self.assertEqual([target for method, target, _ in self.contract.requests if method == "POST"],
                         [cb.PROPOSALS_PATH] * 6)

    def test_numbers_belong_to_the_producer_not_to_the_shared_journal(self) -> None:
        other = "f" * 32
        self.contract.proposals = [(other, number, story(9, 1, 2)) for number in range(1, 6)]
        self.contract.producers = {other: 5}
        game = FakeGame(host=False)
        relay = self.proposer(game)
        relay.start()
        game.change(3, 1, 2)
        relay.step()
        self.contract.proposals.append((other, 6, story(9, 2, 3)))
        self.contract.producers[other] = 6
        game.change(3, 2, 3)
        relay.step()
        self.assertEqual([(post["producer"], post["first"]) for post in self.contract.proposal_posts],
                         [(relay.producer, 1), (relay.producer, 2)])
        self.assertEqual(self.contract.proposals[5:], [(relay.producer, 1, story(3, 1, 2)), (other, 6, story(9, 2, 3)),
                                                       (relay.producer, 2, story(3, 2, 3))])
        self.assertEqual(relay.proposed, 2)
        second = self.proposer(FakeGame(host=False))
        self.assertNotEqual(second.producer, relay.producer)
        for producer in (relay.producer, second.producer):
            self.assertRegex(producer, r"\A[0-9a-f]{32}\Z")

    def test_answers_outside_the_contract_stop_it(self) -> None:
        tampers = {"garbage": "garbage",
                   "not an object": lambda answer: [answer],
                   "extra field": lambda answer: {**answer, "role": "guest"},
                   "missing added": lambda answer: {k: v for k, v in answer.items() if k != "added"},
                   "other session": lambda answer: {**answer, "session": "sessions/other"},
                   "other epoch": lambda answer: {**answer, "epoch": "z" * 20},
                   "part of the batch": lambda answer: {**answer, "added": 1},
                   "more than the batch": lambda answer: {**answer, "added": 3},
                   "boolean added": lambda answer: {**answer, "added": True},
                   "first past last": lambda answer: {**answer, "first": answer["last"] + 2},
                   "additions not kept": lambda answer: {**answer, "first": answer["last"]},
                   "journal went back": lambda answer: {**answer, "last": answer["last"] - answer["added"]}}
        for name, tamper in tampers.items():
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=False)
                relay = self.proposer(game, proposal_batch=2)
                relay.start()
                game.change(1, 1, 2)
                game.change(2, 1, 2)
                relay.step()
                self.assertEqual(relay.proposed, 2)
                game.change(1, 2, 3)
                game.change(2, 2, 3)
                self.contract.faults.append(("POST", tamper))
                with self.assertRaises(cb.ProtocolError):
                    relay.step()
                self.assert_stopped(game)
                self.assertEqual(relay.proposed, 2)

    def test_refusals_stop_it(self) -> None:
        def limit(contract: Contract) -> None:  # every producer slot taken by others
            contract.producers.update((f"{n:032x}", 1) for n in range(contract.PRODUCERS))

        for name, damage, acknowledged, error_type, code in (
                ("new epoch", lambda c: setattr(c, "epoch", "z" * 20), 1, cb.LiveConflict, "stale_epoch"),
                ("host left", lambda c: setattr(c, "host_present", False), 1, cb.LiveConflict, "host_absent"),
                ("producer forgotten", lambda c: c.producers.clear(), 1, cb.LiveConflict, "sequence_gap"),
                ("producer limit", limit, 0, cb.LiveRefused, "too_many_producers"),
                ("creator's account", lambda c: setattr(c, "role", "host"), 0, cb.LiveRefused, "not_guest")):
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=False)
                relay = self.proposer(game)
                relay.start()
                if acknowledged:
                    game.change(1, 1, 2)
                    relay.step()
                damage(self.contract)
                game.change(2, 1, 2)
                with self.assertRaises(error_type) as caught:
                    relay.step()
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(relay.proposed, acknowledged)
                self.assert_stopped(game)

    def test_a_resend_the_server_no_longer_keeps_stops_it(self) -> None:
        game = FakeGame(host=False)
        relay = self.proposer(game)
        relay.start()
        self.contract.faults = [("POST", "drop_after")] * 2
        game.change(1, 1, 2)
        relay.step()
        self.assertEqual((self.held(), relay.proposed), ([story(1, 1, 2)], 0))
        self.contract.proposal_base, self.contract.proposals = 1, []  # discarded after it arrived
        with self.assertRaises(cb.LiveConflict) as caught:
            relay.step()
        self.assertEqual(caught.exception.code, "sequence_expired")
        self.assertEqual(relay.proposed, 0)
        self.assert_stopped(game)

    def test_overflow_loss_and_changes_the_contract_cannot_carry_stop_it_unsent(self) -> None:
        cases = (("story journal overflow", lambda g: [g.change(qid, 1, 2) for qid in range(1, 130)], cb.MailboxError),
                 ("unique journal loss", lambda g: [g.unique_change(11, n % 2, 1 - n % 2, "counter", 4)
                                                    for n in range(cb.UNIQUE_JOURNAL_SLOTS + 1)], cb.MailboxError),
                 ("invalid story entry", lambda g: g.forge_story(3 | 1 << 16 | 2 << 20 | 2 << 24), cb.MailboxError),
                 ("story state 0", lambda g: g.change(3, 0, 2), cb.ResyncRequired),
                 ("state at a counter site", lambda g: g.unique_change(11, 1, 2, "state", 4), cb.ResyncRequired),
                 ("state its site does not write", lambda g: g.unique_change(11, 1, 3, "state", 0), cb.ResyncRequired))
        for name, damage, error_type in cases:
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=False)
                relay = self.proposer(game)
                relay.start()
                damage(game)
                with self.assertRaises(error_type):
                    relay.step()
                self.assert_stopped(game)
                self.assertEqual(self.contract.proposal_posts, [])

    def test_buffering_is_bounded_while_the_server_is_unreachable(self) -> None:
        game = FakeGame(host=False)
        relay = self.proposer(game, proposal_batch=2, max_proposals=4)
        relay.start()
        self.contract.faults = [("*", "unavailable")] * 10
        for qid in range(1, 4):
            game.change(qid, 1, 2)
        relay.step()
        relay.step()
        self.assertEqual((relay.proposed, relay.proposals_pending), (0, 3))
        game.change(4, 1, 2)
        game.change(5, 1, 2)
        with self.assertRaisesRegex(cb.BridgeError, "refusing to buffer"):
            relay.step()
        self.assert_stopped(game)
        self.assertEqual(self.contract.proposals, [])

    def test_an_outage_keeps_every_proposal_until_the_offline_timeout(self) -> None:
        game = FakeGame(host=False)
        relay = self.proposer(game, offline_timeout=30)
        relay.start()
        self.contract.faults = [("*", "drop_before")] * 20
        game.change(1, 1, 2)
        relay.step()
        self.clock.now = 29
        relay.step()
        self.assertEqual((relay.proposed, relay.proposals_pending), (0, 1))
        self.contract.faults.clear()
        relay.step()
        self.assertEqual((self.held(), relay.proposed), ([story(1, 1, 2)], 1))
        self.contract.faults = [("*", "drop_before")] * 20
        game.change(1, 2, 3)
        relay.step()
        self.clock.now = 60
        with self.assertRaisesRegex(cb.BridgeError, "unreachable"):
            relay.step()
        self.assert_stopped(game)
        self.assertEqual(self.held(), [story(1, 1, 2)])

    def test_needs_the_guest_role_and_an_explicit_opt_in(self) -> None:
        self.contract.role = "host"
        game = FakeGame(host=False)
        with self.assertRaises(cb.LiveRefused) as caught:
            self.proposer(game).start()
        self.assertEqual(caught.exception.code, "not_guest")
        self.assertEqual(game.writes, [])
        for options in ({"propose": 1}, {"propose": True, "proposal_batch": 0},
                        {"propose": True, "proposal_batch": cb.MAX_EVENTS_PER_POST + 1},
                        {"propose": True, "proposal_batch": 20, "max_proposals": 10},
                        {"propose": True, "proposal_batch": 1.5},
                        {"propose": True, "max_proposals": True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.guest_relay(FakeGame(host=False), **options)


class EndToEndTest(LiveFixture):
    def test_host_changes_reach_the_guest_game_once_and_in_order(self) -> None:
        host_game, guest_game = FakeGame(host=True), FakeGame(host=False)
        host = self.host_relay(host_game)
        guest = self.guest_relay(guest_game, client=self.new_client())
        host.start()
        guest.start()
        changes = [(1, 1, 2), (1, 2, 3), (2, 1, 4), (1, 3, 4), (3, 1, 2)]
        for change in changes:
            host_game.change(*change)
        for _ in range(20):
            host.step()
            guest.step()
            guest_game.frame()
            if guest.consumed == len(changes):
                break
        guest.step()
        self.assertEqual(guest_game.states, {1: 4, 2: 4, 3: 2})
        self.assertEqual(self.contract.events, changes)
        self.assertEqual(guest.replayed, 5)
        guest_game.change(9, 1, 3)  # the guest's own change stays local
        guest.step()
        host.step()
        self.assertEqual(self.contract.events, changes)


class ServerContractTest(LiveFixture):
    """A proposing guest relay against server.py's own CampaignLive: /campaign/live and
    /campaign/live/proposals as the server parses, stores and answers them."""

    def setUp(self) -> None:
        try:
            import server
        except ImportError as exc:
            self.skipTest(f"server.py's dependencies are missing: {exc}")
        super().setUp()
        self.srv = server
        self.contract = ServerContract(server)
        self.server.contract = self.contract

    def test_a_proposing_guest_relay_posts_what_the_server_takes(self) -> None:
        game = FakeGame(host=False)
        relay = self.guest_relay(game, propose=True, proposal_batch=2)
        view = relay.start()
        self.assertEqual(view.role, "guest")
        body = json.dumps({"session": SESSION, "epoch": view.epoch, "first": 1,
                           "events": [{"id": 1, "old": 1, "new": 2}]}).encode()
        status, answer = self.contract.call(self.contract.host, "POST", cb.LIVE_PATH, body, "application/json")
        self.assertEqual(status, 200, answer)
        game.unique_effects[1, 2] = [(11, 1, 2, "state", 0)]
        pump(relay, game, lambda: relay.consumed == 1)
        game.change(5, 1, 2)
        game.unique_change(11, 2, 3, "state", 2)
        game.unique_change(12, 0, 9, "counter", 13)
        self.contract.faults.append(("POST", "drop_after"))  # the first batch arrives, its answer is lost
        for _ in range(3):
            relay.step()
        query = urlencode({"session": SESSION, "epoch": view.epoch, "after": 0})
        status, state = self.contract.call(self.contract.host, "GET", f"{cb.PROPOSALS_PATH}?{query}")
        self.assertEqual(status, 200, state)
        events = [story(5, 1, 2), unique(11, 2, 3, "state", 2), unique(12, 0, 9, "counter", 13)]
        self.assertEqual(state["proposals"], [{"seq": number, "producer": relay.producer, "number": number,
                                               "event": event} for number, event in enumerate(events, 1)])
        self.assertEqual((relay.replayed, relay.unique_replayed, relay.proposed, relay.proposals_pending),
                         (1, 1, 3, 0))
        self.assertEqual([target for method, target, _ in self.contract.requests if method == "POST"],
                         [cb.PROPOSALS_PATH] * 3)
        with self.assertRaises(cb.LiveRefused) as denied:
            self.client.poll_proposals(SESSION, view.epoch, 0)
        self.assertEqual((denied.exception.status, denied.exception.code), (403, "not_host"))
        self.contract.guest = self.contract.host  # the host's authenticated connection
        page = self.client.poll_proposals(SESSION, view.epoch, 0)
        self.assertEqual((page.first, page.last), (1, 3))
        self.assertEqual([(p.seq, p.producer, p.number, p.change.payload()) for p in page.proposals],
                         [(i, relay.producer, i, event) for i, event in enumerate(events, 1)])
        self.assertEqual([p.seq for p in self.client.poll_proposals(SESSION, view.epoch, 2).proposals], [3])

    def test_host_rejects_malformed_proposal_pages(self) -> None:
        view = self.client.discover()
        producer = "f" * 32
        self.client.propose(SESSION, view.epoch, producer, 1,
                            [cb.Proposal("story", 10, 1, 2), cb.Proposal("story", 10, 2, 3)])
        self.contract.guest = self.contract.host
        mutations = (
            lambda answer: {**answer, "session": "sessions/other"},
            lambda answer: {**answer, "proposals": []},
            lambda answer: {**answer, "proposals": [{**answer["proposals"][0], "seq": 2}]},
            lambda answer: {**answer, "proposals": [{**answer["proposals"][0], "number": True}]},
            lambda answer: {**answer, "proposals": [{**answer["proposals"][0], "producer": "BAD"}]},
            lambda answer: {**answer, "proposals": [answer["proposals"][0],
                                                      {**answer["proposals"][1], "number": 1}]},
            lambda answer: {**answer, "proposals": [{**answer["proposals"][0],
                                                      "event": {"kind": "story", "id": 10, "old": 1, "new": 1}}]},
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.contract.faults.append(("GET", mutate))
                with self.assertRaises(cb.ProtocolError):
                    self.client.poll_proposals(SESSION, view.epoch, 0)

    def test_client_accepts_overlap_with_new_suffix_from_real_server(self) -> None:
        view = self.client.discover()
        producer = "e" * 32
        first = cb.Proposal("story", 10, 1, 2)
        second = cb.Proposal("unique", 11, 2, 3, "state", 2)
        third = cb.Proposal("unique", 11, 0, 3, "counter", 9)
        self.assertEqual(self.client.propose(SESSION, view.epoch, producer, 1, [first, second]).added, 2)
        receipt = self.client.propose(SESSION, view.epoch, producer, 2, [second, third])
        self.assertEqual((receipt.first, receipt.last, receipt.added), (1, 3, 1))
        query = urlencode({"session": SESSION, "epoch": view.epoch, "after": 0})
        status, state = self.contract.call(self.contract.host, "GET", f"{cb.PROPOSALS_PATH}?{query}")
        self.assertEqual((status, [p["event"] for p in state["proposals"]]),
                         (200, [first.payload(), second.payload(), third.payload()]))

    def test_the_servers_refusals_stop_it(self) -> None:
        returned = types.SimpleNamespace(name="userSessions/host-again")
        for name, damage, code in (("host left", lambda c: c.users.pop("users/host"), "host_absent"),
                                   ("host returned", lambda c: c.users.__setitem__("users/host", returned),
                                    "stale_epoch")):
            with self.subTest(name):
                self.setUp()
                game = FakeGame(host=False)
                relay = self.guest_relay(game, propose=True)
                relay.start()
                game.change(1, 1, 2)
                relay.step()
                self.assertEqual(relay.proposed, 1)
                damage(self.contract)
                game.change(1, 2, 3)
                with self.assertRaises(cb.LiveConflict) as caught:
                    relay.step()
                self.assertEqual(caught.exception.code, code)
                self.assert_stopped(game)


@unittest.skipUnless(os.name == "nt", "attaching to a process needs Windows")
class GameProcessTest(unittest.TestCase):
    """GameProcess against a child process that maps a game-shaped region with VirtualAlloc. sys.executable
    may be a venv launcher that runs the interpreter as a process of its own, so the child reports its pid."""

    CHILD = (
        "import ctypes, json, os, sys\n"
        "k = ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "k.VirtualAlloc.restype = ctypes.c_void_p\n"
        "k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]\n"
        "k.VirtualProtect.restype = ctypes.c_int\n"
        "k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]\n"
        "spec = json.loads(sys.stdin.readline())\n"
        "bases = []\n"
        "for _ in range(spec['copies']):\n"
        "    padding = spec['main'] & 0xffff\n"
        "    allocation = k.VirtualAlloc(None, spec['size'] + padding, 0x3000, 0x04)\n"
        "    if not allocation:\n"
        "        raise ctypes.WinError(ctypes.get_last_error())\n"
        "    if padding:\n"
        "        old = ctypes.c_uint32()\n"
        "        if not k.VirtualProtect(allocation, padding, 0x01, ctypes.byref(old)):\n"
        "            raise ctypes.WinError(ctypes.get_last_error())\n"
        "    base = allocation + padding\n"
        "    for offset, data in spec['writes']:\n"
        "        ctypes.memmove(base + offset, bytes.fromhex(data), len(data) // 2)\n"
        "    bases.append(base)\n"
        "print(json.dumps({'pid': os.getpid(), 'bases': bases}), flush=True)\n"
        "sys.stdin.readline()\n")
    MANAGER_OFFSET = cb.MAILBOX + 0x1000

    def spawn(self, copies: int = 1, damage: int | None = None) -> int:
        """Starts the child and returns the pid of the interpreter that holds the mapping."""
        cave = bytearray(cb.CAVE_BYTES)
        if damage is not None:
            cave[damage] ^= 0xFF
        writes = [(cb.SIGNATURE_OFFSET, cb.SIGNATURE.hex()), (cb.CAVE, cave.hex()),
                  (cb.G_GM, struct.pack("<Q", MAIN + self.MANAGER_OFFSET).hex()),
                  (self.MANAGER_OFFSET + 0x8C, cb.HOST_CAPS.to_bytes(5, "little").hex())]
        writes += [(offset, data.hex()) for offset, data in cb.HOOKS.items()]
        child = subprocess.Popen([sys.executable, "-c", self.CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 text=True)
        for cleanup in (child.stdout.close, child.stdin.close, child.wait, child.kill):
            self.addCleanup(cleanup)  # run in reverse: kill, wait, then close the pipes
        child.stdin.write(json.dumps({"copies": copies, "size": cb.MAILBOX + 0x8000, "main": MAIN, "writes": writes}) + "\n")
        child.stdin.flush()
        ready = json.loads(child.stdout.readline())
        self.addCleanup(self.terminate, ready["pid"])  # first: the interpreter, which a launcher would outlive
        self.assertEqual(len(ready["bases"]), copies)
        return ready["pid"]

    @staticmethod
    def terminate(pid: int) -> None:
        try:
            os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
        except OSError:
            pass

    def test_attaches_and_writes_only_the_mailbox(self) -> None:
        pid = self.spawn()
        with cb.GameProcess(pid, MAIN) as game:
            self.assertTrue(game.alive())
            self.assertEqual(cb.read_session(game), cb.GameSession(MAIN + self.MANAGER_OFFSET, cb.HOST_CAPS))
            self.assertEqual(game.read(MAIN + cb.MAILBOX, cb.MAILBOX_SIZE), bytes(cb.MAILBOX_SIZE))
            cb.Mailbox(game, drain=False, journal=True).attach()
            self.assertEqual(game.read(MAIN + cb.MAILBOX, 4), struct.pack("<I", cb.MAGIC))
            for address, size in ((MAIN + cb.CAVE, 1), (MAIN + cb.MAILBOX - 1, 2),
                                  (MAIN + cb.MAILBOX + cb.MAILBOX_SIZE - 1, 2), (MAIN + cb.G_GM, 8)):
                with self.assertRaises(ValueError):
                    game.write(address, bytes(size))
            cb.verify_patch(game.read, MAIN)
            self.terminate(pid)
            deadline = time.monotonic() + 10
            while game.alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertFalse(game.alive())
            with self.assertRaises(cb.ProcessLost):
                game.read(MAIN + cb.MAILBOX, 4)

    def test_refuses_a_changed_patch_or_an_ambiguous_mapping(self) -> None:
        with self.assertRaises(cb.PatchMismatch):
            cb.GameProcess(self.spawn(damage=len(cb.CAVE_CODE) - 1), MAIN)
        with self.assertRaises(cb.PatchMismatch):
            cb.GameProcess(self.spawn(damage=len(cb.CAVE_CODE)), MAIN)
        with self.assertRaisesRegex(cb.PatchMismatch, "found 2"):
            cb.GameProcess(self.spawn(copies=2), MAIN)
        with self.assertRaisesRegex(cb.PatchMismatch, "found 0"):
            cb.GameProcess(self.spawn(copies=0), MAIN)

    def test_refuses_a_stale_main_address(self) -> None:
        pid = self.spawn()
        with self.assertRaisesRegex(cb.PatchMismatch, "main address"):
            cb.GameProcess(pid, MAIN + 0x1000)

    def test_refuses_bad_arguments(self) -> None:
        for pid, main in ((0, MAIN), (1, MAIN + 4), (1, 0)):
            with self.subTest(pid=pid, main=main), self.assertRaises(ValueError):
                cb.GameProcess(pid, main)


if __name__ == "__main__":
    unittest.main()
