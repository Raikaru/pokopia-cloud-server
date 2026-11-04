"""Tests of campaign_bridge, the live quest event transport: event order, loss, retries and fail-closed stops.

The relays run against a simulated patched game: the patch bytes, the capability mask, and a mailbox whose
game side behaves like caves J and D. They talk over real TLS with client certificates to a test double of
/campaign/live, which is written from the shared contract and not taken from server.py. On Windows,
GameProcess also attaches to a child process laid out like the game.

    .\\.venv\\Scripts\\python.exe -m unittest test_campaign_bridge
"""
from __future__ import annotations

import datetime
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
import unittest
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

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


# --- The game ------------------------------------------------------------------------------------------------

class FakeGame:
    """The patched game as a relay sees it. Its mailbox side follows the caves: set_quest journals like cave J
    around the quest state setter, frame() drains like cave D and apply_one."""

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
        self.on_journal_read: Callable[[], None] | None = None

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

    def set_caps(self, caps: int) -> None:
        self.memory[MANAGER + 0x8C][:] = caps.to_bytes(5, "little")

    def armed(self, flag: int) -> bool:
        return self.u32(cb.MB_MAGIC) == cb.MAGIC and bool(self.u32(cb.MB_FLAGS) & flag)

    def set_quest(self, qid: int, new: int) -> None:
        """The game's quest state setter with cave J around it."""
        old = self.states.get(qid, 1)
        self.states[qid] = new
        if self.armed(cb.FLAG_JOURNAL) and old != new and 1 <= new <= 4 and 1 <= qid <= 1000:
            w = self.u32(cb.MB_OUT_W)
            word = qid | (old & 0xF) << 16 | new << 20 | (self.u32(cb.MB_APPLYING) & 1) << 24
            self.set_u32(cb.MB_JOURNAL + 4 * (w % cb.JOURNAL_SLOTS), word)
            self.set_u32(cb.MB_OUT_W, w + 1)

    def change(self, qid: int, old: int, new: int) -> None:
        """A quest change the game makes itself."""
        self.states[qid] = old
        self.set_quest(qid, new)

    def frame(self, budget: int = 8) -> None:
        """Cave D: takes up to 8 inbox entries before the story quest update."""
        if not self.armed(cb.FLAG_DRAIN):
            return
        self.set_u32(cb.MB_APPLYING, 1)
        for _ in range(budget):
            r = self.u32(cb.MB_IN_R)
            if r == self.u32(cb.MB_IN_W):
                break
            word = self.u32(cb.MB_INBOX + 4 * (r % cb.INBOX_SLOTS))
            self.set_u32(cb.MB_IN_R, r + 1)
            self.apply_one(word)
            self.set_u32(cb.MB_APPLIED, self.u32(cb.MB_APPLIED) + 1)
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
    for cursors outside the retained history, and for sequence gaps, conflicts or expiry."""

    RETAIN, PAGE = 1024, 64

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.session, self.epoch, self.role = SESSION, EPOCH, "host"
        self.base = 0  # seqs 1..base were discarded
        self.events: list[tuple[int, int, int]] = []
        self.posts: list[dict] = []
        self.requests: list[tuple[str, str, str | None]] = []  # method, target, Host header
        self.faults: list[tuple[str, str]] = []  # (method or "*", kind), each used by one request

    @property
    def last(self) -> int:
        return self.base + len(self.events)

    def view(self, events: list[dict] | None = None) -> dict:
        result = {"session": self.session, "epoch": self.epoch, "role": self.role, "first": self.base + 1,
                  "last": self.last}
        if events is not None:
            result["events"] = events
        return result

    def fault(self, method: str) -> str | None:
        for index, (wanted, kind) in enumerate(self.faults):
            if wanted in (method, "*"):
                del self.faults[index]
                return kind
        return None

    def handle(self, method: str, target: str, body: bytes) -> tuple[int, dict]:
        url = urlsplit(target)
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
                status, answer = contract.handle(method, self.path, body)
            if kind == "drop_after":
                self.close_connection = True
                return
            if kind == "reorder":
                answer["events"].reverse()
            if kind == "gap":
                del answer["events"][0]
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


class MailboxTest(unittest.TestCase):
    def test_a_used_mailbox_is_refused_without_writing(self) -> None:
        game = FakeGame(host=True)
        game.set_u32(cb.MB_OUT_W, 1)
        with self.assertRaises(cb.MailboxError):
            cb.Mailbox(game, drain=False, journal=True).attach()
        self.assertEqual(game.writes, [])


    def test_journal_overflow_is_never_silent(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True)
        mailbox.attach()
        for qid in range(1, 129):
            game.change(qid, 1, 2)
        self.assertEqual([e.id for e in mailbox.read_journal()], list(range(1, 129)))
        for qid in range(1, 130):
            game.change(qid, 2, 3)
        with self.assertRaisesRegex(cb.MailboxError, "1 quest changes were lost"):
            mailbox.read_journal()

    def test_journal_wrapping_while_it_is_read_is_loss(self) -> None:
        game = FakeGame(host=True)
        mailbox = cb.Mailbox(game, drain=False, journal=True)
        mailbox.attach()
        game.change(1, 1, 2)
        game.on_journal_read = lambda: [game.change(qid, 1, 2) for qid in range(2, 130)]
        with self.assertRaisesRegex(cb.MailboxError, "while it was read"):
            mailbox.read_journal()

    def test_unique_journal_refuses_an_incompatible_patch_before_writing(self) -> None:
        game = FakeGame(host=True)
        game.memory[MAIN + 0x6149F8][0] ^= 1
        mailbox = cb.Mailbox(game, drain=False, journal=False, unique_journal=True)
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

    def test_game_drain_thread_marker_does_not_stop_quest_replay(self) -> None:
        game = FakeGame(host=False)
        mailbox = cb.Mailbox(game, drain=True, journal=True)
        mailbox.attach()
        game.mb[0x60:0x68] = (0x123456789ABCDEF0).to_bytes(8, "little")
        mailbox.push([cb.QuestEvent(7, 1, 2).inbox_word()])
        game.frame()
        self.assertEqual(mailbox.check(), 1)
        self.assertEqual(game.states[7], 2)

    def test_a_lost_or_foreign_mailbox_is_detected(self) -> None:
        for name, damage in (("restart", lambda g: g.mb.__setitem__(slice(None), bytes(cb.MAILBOX_SIZE))),
                             ("in_w", lambda g: g.set_u32(cb.MB_IN_W, 3)),
                             ("flags", lambda g: g.set_u32(cb.MB_FLAGS, cb.FLAG_JOURNAL)),
                             ("in_r", lambda g: g.set_u32(cb.MB_IN_R, 1)),
                             ("spare", lambda g: g.set_u32(0x40, 1))):
            with self.subTest(name):
                game = FakeGame(host=False)
                mailbox = cb.Mailbox(game, drain=True, journal=True)
                mailbox.attach()
                mailbox.check()
                damage(game)
                with self.assertRaises(cb.MailboxError):
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
        game.set_u32(cb.MB_APPLYING, 1)
        game.change(6, 1, 2)
        game.set_u32(cb.MB_APPLYING, 0)
        with self.assertRaisesRegex(cb.MailboxError, "replayed change"):
            relay.step()
        self.assertEqual(self.contract.posts, [])
        self.assert_stopped(game)
        with self.assertRaises(cb.BridgeError):
            relay.step()

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
        pump(relay, game, lambda: relay.consumed == 1)
        game.change(3, 1, 2)
        relay.step()
        self.assertEqual((relay.replayed, relay.local_changes), (1, 1))
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
