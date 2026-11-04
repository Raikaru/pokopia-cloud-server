#!/usr/bin/env python3
"""Live quest event transport for the EXPERIMENTAL Pokopia 2.0.1 story co-op patch.

The patch (made by _scratch/quest_sync_trace/quest_sync_patch.py) gives the game a mailbox in its bss: a
128-slot journal of quest state changes that game threads reserve and commit (cave J) and a 64-slot inbox
that the game drains through its own quest writers (cave D). This module moves those changes between players
over /campaign/live on the game backend, an HTTP/1.1 endpoint behind client certificates:

- HostRelay runs on the PC of the session creator's account. It sends story changes marked as local
  (journal origin 0), with sequence numbers so a resend after a lost answer does no harm.
- GuestRelay runs on every other player's PC. It polls the events and queues them into the guest
  game's inbox. By default nothing a guest game does is sent. Only with propose=True, which the
  launcher does not set, does it post changes marked as local to /campaign/live/proposals for the
  host to judge. This is not a complete or reliable account of local changes: the journal holds changes in
  the order game threads reserved them, which need not be the order of concurrent writers' stores; a full
  journal drops changes (the relay then stops); deferred replay effects can appear local (see GuestRelay).

Deliberately not solved here: applying unique-quest changes or guest proposals anywhere (no code here reads
/campaign/live/proposals), a guest's initial quest state and durable stage checkpoints. A guest starts
at cursor 0 and replays what the server still holds. Quest changes the host made before its relay attached
were never journaled. The relay stops with ResyncRequired, and nothing performs that resync, when:
- an event lowers a quest state, including a reset to 1 (the patch can only raise states to 2..4);
- the server has discarded history the relay still needs;
- the epoch or the session changes.
If a guest's quest is already at or past an event's target, the patch skips the event without a word, so
diverged saves go unnoticed as well. This transport alone does not make story co-op work. In one real
two-client test, a guest accepted quest 11 only with an additional test-only NOP at main+0x114384
(visitor eligibility); this patch neither applies nor checks that NOP.

Who relays what is decided by the authenticated server role, never by the game's session bytes, which
read zero on a live online host. HostRelay requires the role "host" (this account created the session) and
the game showing the patched host capability mask. A GuestRelay that only replays never writes, so it runs
under any member's role, another device of the creator's account included; a proposing one needs the role
"guest". Either way its game must show the patched guest mask.

Anything else unexpected also stops a relay (BridgeError) and turns the game's mailbox off: the process
exits; a patch byte differs; the mailbox was not pristine or loses its contents; a journal loses changes or
holds an invalid entry; the game's GameManager or capability mask changes; the server role, session or epoch
changes; the server answers outside the contract. Only network trouble (LiveUnavailable) is retried, and only
until offline_timeout runs out. A game whose relay stopped needs a restart before any relay will attach to it
again.

GameProcess, which attaches to the emulator, works only on Windows. The protocol classes accept any object
with main, read, write and alive (see Game).
"""
from __future__ import annotations

import collections
import ctypes
import hashlib
import http.client
import itertools
import json
import logging
import re
import secrets
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import quote, urlencode

log = logging.getLogger("campaign_bridge")

# --- The patch (quest_sync_patch.json), all addresses relative to main -------------------------------------------

BUILD_ID = "76A489F3BD3642FA5E18BD83D32C98BACC5F7D0E"  # Pokopia 2.0.1 main
# 32 bytes of main's text. The host mapping that starts exactly at main holds them at this offset.
SIGNATURE_OFFSET = 0x207B0
SIGNATURE = bytes.fromhex("08aa01b008411c91080140f9880000b40841423900010012c0035fd6e0031f2a")
# Caves A, apply_one, D, J, E, U and W in the zero padding at the end of main's text.
CAVE, CAVE_END = 0x2749480, 0x274A000
CAVE_CODE = bytes.fromhex(
    "6032029156000036169f6517210080528202001287ba659794000036683242390801003268320239749f6517fd7bbda9fd030091"
    "f35301a9f55b02a9f30300aa343c0012355c1053367c1853880600511f9d0f71c8080054a80a00511f09007168080054c8700090"
    "089944f909d484524909a0720001098be103142a313c7a97081c00121f01156b22070054df0a0071e0040054df060071c0030054"
    "96060035bf0a0071a1000054e00313aae103142acc4967972e0000141f0d0071c2000054e00313aae103142afd496797bf0e0071"
    "e0040054e00313aae103142a22008052d14a6797e00313aae103142a820080528b4a6797e00313aae103142a294b6797e00313aa"
    "e103142a864b679718000014bf120071c1020054e00313aae103142a820080527e4a679711000014c8700090089944f909d48452"
    "4909a0720001098be103142ae203152a253c7a97c8700090089944f909d484524909a0720001098be103142a02008052633c7a97"
    "f55b42a9f35341a9fd7bc3a8c0035fd6fd7bbca9fd030091f35301a9f55b02a9e01b00f9e03b00bdf30300aa74ae00f094020091"
    "880240b9296a8a524928a6721f01096ba1050054880640b968050036c8700090088943f9080500b4094d40f9490100b4c9700090"
    "299544f9e90000b4201940f9a00000b4090040f929a540f920013fd6a003003737bc779760030037c8700090089944f9080300b4"
    "680000142800805228fd9f88891640b98a4200914afddf883f010a6be00100542b1500128c02049196596bb8290500118a520091"
    "49fd9f8862000014e103162a79ffff97880e40b908050011880e00b9b5060071c1fdff549f0a00b9e01b40f9e03b40bdf55b42a9"
    "f35341a9fd7bc4a8dac3651769ae00f0290100912a0140b92b6a8a524b28a6725f010b6b610500542a0540b92a050836fd7bbda9"
    "fd030091e00701a9e24f02a9a43b7a97131c0012e00741a9e21340f928040051c73b7a97e00741a9e21340f9421c0012213c0012"
    "5f00136bc0020054480400511f0d007168020054280400511f9d0f710802005469ae00f029010091730e00122b40132a6b51022a"
    "2a2100914afddf88ca0000346ad03bd52c3140f95f010ceb410000546b0108322da101912c010014f31740f9fd7bc3a8c0035fd6"
    "28040051a73b7a1769ae00f0290100912a0140b92b6a8a524b28a6725f010b6b010200542a2100914afddf88aa0100346ad03bd5"
    "2b3140f95f010beb21010054080040392a1140f94a25c89aaa0000362a2940b94a0500112a2900b9c0035fd6080040397d466717"
    "89f2009129fddf88a9f5ff3569d03bd5893200f9150180528922009192ffff17c87e1c53082100511f05007169000054e00313aa"
    "9affff17c92e00122a0500515f1d0371c8030054cb6e14532a7b9552ea0da0727600e0364a090011040000146c0500519f110071"
    "a8020054c8700090089944f90809098b0c696a38cd4e0c539f010d6b2101005400010a8be1030b2ae201805217000094883240b9"
    "08050011883200b980ffff17883640b908050011883600b92d00805206000014883a40b908050011883a00b90c0080124d008052"
    "964200b98c4600b9881640b908050051884a00b988f200910dfd9f8873ffff17e313bda9e51b01a903423bd5e70f02a903004039"
    "01000039211c00127f00016be008005464ae00f084000091850040b9266a8a524628a672bf00066b01080054850440b9c5071036"
    "c5700090a59844f9050005cb267b9552e60da072a50006cbbf0040f2c1060054a6fc42d3c70400d1ff1c03f148060054a5040153"
    "c620032ac640012ac660052ac66c022a5f3c007161000054c60007320900001485200091a5fcdf88c500003465d03bd5873040f9"
    "bf0007eb41000054c600063285500191a7fcdf8885400191a3fc5f886100074b3f0004712202005461040011a1fc028842ffff35"
    "85700191a2fc5f88bffc0188c1ffff35c67c022a611c001285001091a50c018ba60000b961040011a5100091a1fc9f880a000014"
    "5f3f03d585600191a1fc5f8821040011a1fc0288a2ffff352100805285700191a1fc9f88e70f42a903421bd5e51b41a9e313c3a8"
    "c0035fd6e007bea9e27b01a90001098be1030a2a02008052a7ffff97e27b41a9e007c2a873267b17e007bea9e27b01a900010a8b"
    "e103092a220080529effff97e27b41a9e007c2a81e2b7b17e007bea9e27b01a90001098be1030a2a4200805295ffff97e27b41a9"
    "e007c2a8cb2b7b17e007bea9e27b01a900010a8be103092a620080528cffff97e27b41a9e007c2a8993a7b17e007bea9e27b01a9"
    "0001098be1031f2a8200805283ffff97e27b41a9e007c2a88b407b17e007bea9e27b01a90001098be1030a2aa20080527affff97"
    "e27b41a9e007c2a806417b17e007bea9e27b01a90001098be1030a2ac200805271ffff97e27b41a9e007c2a8fd417b17e007bea9"
    "e27b01a90001098be1031f2ae200805268ffff97e27b41a9e007c2a841427b17e007bea9e27b01a90001098be1030a2a02018052"
    "5fffff97e27b41a9e007c2a8e7427b17e007bea9e27b01a90001098be1030a2a2201805256ffff97e27b41a9e007c2a801457b17"
    "e007bea9e27b01a900010a8be103092a420180524dffff97e27b41a9e007c2a8dc457b17e007bea9e27b01a900010a8be103092a"
    "6201805244ffff97e27b41a9e007c2a874467b17e007bea9e27b01a900011c8be103092a820180523bffff97e27b41a9e007c2a8"
    "dc487b17e007bea9e27b01a90001098be1030a2aa201805232ffff97e27b41a9e007c2a80f4c7b172e610091aafddf88ccfd5f88"
    "8f010a4bff010271820100548f05003142010054cffd0a880affff358a1900122d010891ab592ab82d013091ad492a8baffd9f88"
    "c5feff175f3f03d52db10191aafd5f885f0500314a058a1aaafd0c888cffff35bdfeff17"
)
CAVE_CODE_SHA256 = "4697bccc7d79b379c0293985de88f96493aecf39827824f5ea73184ee56ab7a6"
CAVE_BYTES = CAVE_CODE + bytes(CAVE_END - CAVE - len(CAVE_CODE))
HOOKS = {
    0x0B1014: bytes.fromhex("1b619a14"),
    0x0B8B68: bytes.fromhex("a5429a94"),
    0x5D865C: bytes.fromhex("28c48514"),
    0x11B214: bytes.fromhex("6db99814"),
    # Natural unique-quest journal writers.
    0x613450: bytes.fromhex("86d98414"),
    0x6149F8: bytes.fromhex("2ed48414"),
    0x614720: bytes.fromhex("dbd48414"),
    0x618554: bytes.fromhex("60c58414"),
    0x619D40: bytes.fromhex("6ebf8414"),
    0x619F50: bytes.fromhex("f3be8414"),
    0x61A350: bytes.fromhex("fcbd8414"),
    0x61A484: bytes.fromhex("b8bd8414"),
    0x61A740: bytes.fromhex("12bd8414"),
    0x61AFCC: bytes.fromhex("f8ba8414"),
    0x61B35C: bytes.fromhex("1dba8414"),
    0x61B5E0: bytes.fromhex("85b98414"),
    0x61BFA4: bytes.fromhex("1db78414"),
    0x61CC94: bytes.fromhex("eab38414"),
}
if hashlib.sha256(CAVE_CODE).hexdigest() != CAVE_CODE_SHA256:
    raise ImportError("campaign_bridge: the embedded cave code is corrupt")

MAILBOX, MAILBOX_SIZE = 0x3D18000, 0xE00
MAGIC = 0x31425351  # "QSB1"; the caves stay inert until it is written
MB_MAGIC, MB_FLAGS, MB_APPLYING, MB_APPLIED = 0x00, 0x04, 0x08, 0x0C
MB_IN_W, MB_IN_R = 0x10, 0x14
MB_OUT_W = 0x18  # story journal reservations: game threads take seq = out_w with an exclusive increment
MB_SKIP_MASK, MB_SKIPPED = 0x20, 0x28
MB_UJ_W, MB_UJ_R, MB_UJ_LOST, MB_UJ_GAP = 0x50, 0x54, 0x58, 0x5C
MB_DRAIN_TLS = 0x60  # u64 TPIDRRO_EL0 of the thread that last entered the drain; game-written
MB_STORY_R = 0x68  # story journal read cursor, written only by this relay; a writer reserves while out_w - r < 128
MB_STORY_LOST = 0x6C  # story changes dropped because the journal was full; game-written, never decreases
MB_INBOX, INBOX_SLOTS = 0x100, 64  # u32 id | target << 16 | op << 24; written here, drained by cave D
MB_JOURNAL, JOURNAL_SLOTS = 0x200, 128  # u32 id | old << 16 | new << 20 | origin << 24 for seq at slot seq % 128
MB_UNIQUE_JOURNAL, UNIQUE_JOURNAL_SLOTS = 0x400, 256  # u32 event, u32 commit sequence
MB_STORY_COMMITS = 0xC00  # u32 seq + 1 per story journal slot, release-stored by cave J after the entry
HEADER_SIZE = MB_INBOX
FLAG_DRAIN, FLAG_JOURNAL, FLAG_UNIQUE_JOURNAL = 1, 2, 4
OP_GAME, OP_FORCE4 = 0, 1  # the patch's op 2 (raw state write) is never sent
# Quest effect types the guest skips while replaying: 22 and 24 edit world blocks (see quest_bridge.py).
DEFAULT_SKIP_MASK = (1 << 22) | (1 << 24)
G_GM = 0x3561710  # GameManager*: capability mask (5 bytes) at +0x8c, written by 0xb0f60 and cave A
# The patched masks of an online type-1 (story) stage (test_quest_sync.test_caps, confirmed on two live copies).
# Spectator (00 00 80 87 03) and offline (ff ff ff 7f 00) masks match neither. The session bytes at +0x3c..0x40
# read zero on a live online host, so they are not used at all.
HOST_CAPS = 0x035FFFFFFF  # ff ff ff 5f 03: co-op mask plus bit 0 (story pipeline)
GUEST_CAPS = 0x055FFFFFFE  # fe ff ff 5f 05: co-op mask, bit 0 clear
U32 = 0xFFFFFFFF

# --- The /campaign/live contract ----------------------------------------------------------------------------

LIVE_PATH = "/campaign/live"
QUEST_IDS = range(1, 1001)
QUEST_STATES = range(1, 5)
MAX_SEQ = 2**53 - 1
MAX_EVENTS_PER_POST = 64
MAX_POST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 1 << 20
EPOCH = re.compile(r"[A-Za-z0-9._~-]{1,128}")
# Guest proposals (/campaign/live/proposals): a producer is a random 128-bit id that numbers its own proposals
# 1, 2, ...; posts and their limits are those of the host events. A unique-quest change names the patch's
# natural writer site 0..13 (14 is unused, 15 marks a uniqueCas replay); sites 0..3 write these states.
PROPOSALS_PATH = "/campaign/live/proposals"
PRODUCER = re.compile(r"[0-9a-f]{32}")
UNIQUE_QUEST_IDS = range(1, 201)
UNIQUE_BYTES = range(256)
UNIQUE_SITES = range(14)
UNIQUE_SITE_STATES = (2, 4, 3, 5)


class BridgeError(Exception):
    """A relay has to stop. Raised from step() after the game's mailbox was turned off, or from start()
    before anything was written to the game."""


class ResyncRequired(BridgeError):
    """The event stream cannot go on from here. Quests need a resynchronization, which this module does not
    provide."""


class SessionChanged(ResyncRequired):
    """The live session, its epoch, or this player's role in the session or in the game changed."""


class GameNotReady(BridgeError):
    """The game is not in the session role the relay needs. Nothing was written; start() may be retried."""


class PatchMismatch(BridgeError):
    """The process does not run the exact 2.0.1 main with this quest patch, mapped exactly once."""


class ProcessLost(BridgeError):
    """The game process exited, or its memory can no longer be read or written."""


class MailboxError(BridgeError):
    """The mailbox was not pristine, lost its contents, was written by someone else, a journal lost changes, or
    a journal holds an entry the patch cannot write."""


class ProtocolError(BridgeError):
    """The server answered outside the /campaign/live contract."""


class LiveRefused(BridgeError):
    """The server, or TLS, refused a request. status is None when TLS refused the connection, or when the
    server's answer rules the request out (HostRelay.start under a role other than "host")."""

    def __init__(self, status: int | None, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}" if status else f"{code}: {message}")
        self.status, self.code, self.message = status, code, message


class LiveConflict(LiveRefused, ResyncRequired):
    """409: stale epoch, a cursor before the retained history or past its end, or a sequence gap, conflict
    or expiry."""


class LiveUnavailable(Exception):
    """The server could not be reached or answered 502/503/504. This is temporary: relays retry until
    offline_timeout."""


class Game(Protocol):
    """A patched game addressed with guest addresses (GameProcess, or a test double)."""

    main: int

    def read(self, address: int, size: int) -> bytes: ...

    def write(self, address: int, data: bytes) -> None: ...

    def alive(self) -> bool: ...


@dataclass(frozen=True)
class QuestEvent:
    """A quest state change as the contract carries it: id 1..1000, states 1..4, old != new."""

    id: int
    old: int
    new: int

    def __post_init__(self) -> None:
        if not all(type(value) is int for value in (self.id, self.old, self.new)):
            raise ValueError(f"quest event fields must be integers: {self!r}")
        if self.id not in QUEST_IDS:
            raise ValueError(f"quest id {self.id} is outside 1..1000")
        if self.old not in QUEST_STATES or self.new not in QUEST_STATES or self.old == self.new:
            raise ValueError(f"quest {self.id}: {self.old} -> {self.new} is not a change between states 1..4")

    def inbox_word(self) -> int:
        """The inbox entry with which cave D replays this change through the same game writer the host
        used: 0x11bc60 for state 2, 0x11bd3c for 3, completion for 4, and the force path (op 1) for 1 -> 4.
        apply_one cannot lower a state, so a decrease raises ResyncRequired instead of being acknowledged."""
        if self.new < self.old:
            raise ResyncRequired(f"quest {self.id} goes from state {self.old} back to {self.new}; the patch only "
                                 f"raises quest states, so this needs a resynchronization")
        op = OP_FORCE4 if (self.old, self.new) == (1, 4) else OP_GAME
        return self.id | self.new << 16 | op << 24


@dataclass(frozen=True)
class LiveEvent:
    seq: int
    quest: QuestEvent


@dataclass(frozen=True)
class LiveView:
    """A /campaign/live answer. events is empty for discovery and POST answers."""

    session: str
    epoch: str
    role: str
    first: int
    last: int
    events: tuple[LiveEvent, ...] = ()


@dataclass(frozen=True)
class JournalEntry:
    """A story quest change from the journal, which holds them in reservation order (see Mailbox.read_journal)."""

    id: int
    old: int  # the low 4 bits of the state cave J read before the setter ran
    new: int
    origin: int  # 1: written on the drain's thread while it applied inbox entries, 0: otherwise

    @classmethod
    def decode(cls, word: int) -> JournalEntry:
        """Raises MailboxError for a word cave J never writes: a quest id outside 1..1000, a new state outside
        1..4 or an origin other than 0 and 1."""
        entry = cls(word & 0xFFFF, word >> 16 & 0xF, word >> 20 & 0xF, word >> 24 & 0xFF)
        if entry.id not in QUEST_IDS or entry.new not in QUEST_STATES or entry.origin > 1:
            raise MailboxError(f"invalid story quest journal entry {word:#010x}")
        return entry


@dataclass(frozen=True)
class UniqueJournalEntry:
    """A unique-quest byte change, in reservation order (not necessarily completion order)."""

    sequence: int
    id: int
    field: str  # state or counter
    old: int
    new: int
    origin: int  # 0 game, 1 CAS replay, 2 side effect on the drain thread
    site: int

    @classmethod
    def decode(cls, sequence: int, word: int) -> UniqueJournalEntry:
        quest_id, old, new = word & 0xFF, word >> 8 & 0xFF, word >> 16 & 0xFF
        field = "counter" if word >> 24 & 1 else "state"
        origin, site = word >> 25 & 3, word >> 27 & 15
        if (word >> 31 or quest_id not in range(1, 201) or old == new or origin > 2 or site == 14
                or (site == 15) != (origin == 1)
                or (field == "state" and (old > 5 or new not in range(1, 6)))):
            raise MailboxError(f"invalid or gap-marked unique quest journal entry {word:#010x}")
        return cls(sequence, quest_id, field, old, new, origin, site)


@dataclass(frozen=True)
class Proposal:
    """A guest game's own quest change as /campaign/live/proposals carries it, for the host to judge: a story
    change (kind "story", within the QuestEvent limits) or a unique-quest byte change (kind "unique": quest
    1..200, two different bytes 0..255 and the natural writer site 0..13; sites 0..3 set the unique state
    2, 4, 3 and 5 from at most 5, the others write the counter)."""

    kind: str
    id: int
    old: int
    new: int
    field: str | None = None  # unique only: state or counter
    site: int | None = None  # unique only

    def __post_init__(self) -> None:
        if self.kind == "story":
            if self.field is not None or self.site is not None:
                raise ValueError(f"a story proposal has no field or site: {self!r}")
            QuestEvent(self.id, self.old, self.new)
            return
        if self.kind != "unique":
            raise ValueError(f"a proposal is a story or a unique quest change, not {self.kind!r}")
        if not all(type(value) is int for value in (self.id, self.old, self.new, self.site)):
            raise ValueError(f"unique proposal fields must be integers: {self!r}")
        if self.id not in UNIQUE_QUEST_IDS:
            raise ValueError(f"unique quest id {self.id} is outside 1..200")
        if self.old not in UNIQUE_BYTES or self.new not in UNIQUE_BYTES or self.old == self.new:
            raise ValueError(f"unique quest {self.id}: {self.old} -> {self.new} is not a change between bytes 0..255")
        if self.site not in UNIQUE_SITES:
            raise ValueError(f"unique quest {self.id}: writer site {self.site} is not a natural one (0..13)")
        if self.site < len(UNIQUE_SITE_STATES):
            if self.field != "state" or self.old > 5 or self.new != UNIQUE_SITE_STATES[self.site]:
                raise ValueError(f"unique quest {self.id}: {self.field} {self.old} -> {self.new} is not what writer "
                                 f"site {self.site} writes (the state, {UNIQUE_SITE_STATES[self.site]})")
        elif self.field != "counter":
            raise ValueError(f"unique quest {self.id}: writer site {self.site} writes the counter, not {self.field!r}")

    @classmethod
    def of(cls, entry: JournalEntry | UniqueJournalEntry) -> Proposal:
        """The proposal of a journal entry; ValueError if the contract cannot carry it."""
        if isinstance(entry, UniqueJournalEntry):
            return cls("unique", entry.id, entry.old, entry.new, entry.field, entry.site)
        return cls("story", entry.id, entry.old, entry.new)

    def payload(self) -> dict[str, object]:
        result: dict[str, object] = {"kind": self.kind, "id": self.id, "old": self.old, "new": self.new}
        if self.kind == "unique":
            result.update(field=self.field, site=self.site)
        return result


@dataclass(frozen=True)
class ProposalReceipt:
    """The answer to a /campaign/live/proposals POST. The 200 acknowledges the complete batch; `added`
    counts only its previously unseen suffix. first..last bound the session's proposal journal, which
    every guest shares, so they say nothing about any one producer's numbers."""

    first: int
    last: int
    added: int


@dataclass(frozen=True)
class GameSession:
    """The GameManager and its capability mask. A relay requires the exact patched mask of its side and stops
    when either changes."""

    manager: int
    caps: int


def verify_patch(read: Callable[[int, int], bytes], main: int) -> None:
    """Raises PatchMismatch unless every patch byte is in place: all hooks and the whole cave, the code
    followed by its zero padding."""
    if read(main + CAVE, len(CAVE_BYTES)) != CAVE_BYTES:
        raise PatchMismatch("the quest patch caves are missing or differ")
    for offset, expected in HOOKS.items():
        if read(main + offset, len(expected)) != expected:
            raise PatchMismatch(f"the quest patch hook at main+{offset:#x} is missing or differs")


def read_session(game: Game) -> GameSession | None:
    """The game's GameManager and capability mask, or None before the GameManager exists."""
    manager = struct.unpack("<Q", game.read(game.main + G_GM, 8))[0]
    if not manager:
        return None
    return GameSession(manager, int.from_bytes(game.read(manager + 0x8C, 5), "little"))


# --- Attaching to the emulator (Windows) -------------------------------------------------------------------

PROCESS_ACCESS = 0x0400 | 0x0008 | 0x0010 | 0x0020 | 0x00100000  # QUERY_INFORMATION, VM_OPERATION/READ/WRITE, SYNCHRONIZE
MEM_COMMIT = 0x1000
PAGE_NOACCESS, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_GUARD = 0x01, 0x04, 0x40, 0x100
WAIT_OBJECT_0, WAIT_TIMEOUT = 0, 0x102
USER_SPACE_END = 0x7FFFFFFFFFFF


class _MemoryInfo(ctypes.Structure):  # MEMORY_BASIC_INFORMATION (64-bit)
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_uint32), ("PartitionId", ctypes.c_uint16),
                ("RegionSize", ctypes.c_size_t), ("State", ctypes.c_uint32), ("Protect", ctypes.c_uint32),
                ("Type", ctypes.c_uint32)]


_kernel32_dll = None


def _kernel32():
    global _kernel32_dll
    if _kernel32_dll is None:
        if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise OSError("attaching to the game needs 64-bit Python on Windows")
        k = ctypes.WinDLL("kernel32", use_last_error=True)  # a private instance: its prototypes are ours
        handle, size = ctypes.c_void_p, ctypes.c_size_t
        k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k.OpenProcess.restype = handle
        k.CloseHandle.argtypes = [handle]
        k.CloseHandle.restype = ctypes.c_int
        k.ReadProcessMemory.argtypes = [handle, ctypes.c_void_p, ctypes.c_void_p, size, ctypes.POINTER(size)]
        k.ReadProcessMemory.restype = ctypes.c_int
        k.WriteProcessMemory.argtypes = [handle, ctypes.c_void_p, ctypes.c_void_p, size, ctypes.POINTER(size)]
        k.WriteProcessMemory.restype = ctypes.c_int
        k.VirtualQueryEx.argtypes = [handle, ctypes.c_void_p, ctypes.POINTER(_MemoryInfo), size]
        k.VirtualQueryEx.restype = size
        k.WaitForSingleObject.argtypes = [handle, ctypes.c_uint32]
        k.WaitForSingleObject.restype = ctypes.c_uint32
        _kernel32_dll = k
    return _kernel32_dll


class GameProcess:
    """An emulator process running the patched game, addressed with guest addresses.

    pid: the disposable emulator's process; main: its current "Module main loaded at ..." log address.
    The constructor writes nothing. It checks the 2.0.1 main signature, the patched bytes, mailbox
    permissions and 64 KiB arena alignment. Alignment catches some stale main addresses, not all:
    the address MUST come from this process's current log. Reads may go anywhere in the game; writes
    are refused outside the mailbox. The open handle pins the process object against PID reuse."""

    def __init__(self, pid: int, main: int) -> None:
        if type(pid) is not int or pid <= 0:
            raise ValueError(f"bad process id {pid!r}")
        if type(main) is not int or main <= 0 or main % 0x1000 or main + MAILBOX + MAILBOX_SIZE > 1 << 48:
            raise ValueError(f"bad main load address {main!r}")
        self._k = _kernel32()
        self.pid, self.main = pid, main
        self._handle = self._k.OpenProcess(PROCESS_ACCESS, False, pid)
        if not self._handle:
            raise ProcessLost(f"cannot open process {pid}: {ctypes.WinError(ctypes.get_last_error())}")
        try:
            self._arena = self._find_main() - main
            if self._arena <= 0 or self._arena & 0xFFFF:
                raise PatchMismatch(f"process {pid}: main address {main:#x} does not map to an aligned "
                                    "guest arena; use this process's current module-load log")
            verify_patch(self.read, main)
            self._check_mailbox_memory()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> GameProcess:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._handle:
            self._k.CloseHandle(self._handle)
            self._handle = None

    def _query(self, address: int) -> _MemoryInfo | None:
        info = _MemoryInfo()
        if not self._k.VirtualQueryEx(self._handle, ctypes.c_void_p(address), ctypes.byref(info),
                                      ctypes.sizeof(info)):
            return None
        return info

    def _find_main(self) -> int:
        candidates = []
        address = 0
        while address < USER_SPACE_END:
            info = self._query(address)
            if info is None or not info.RegionSize:
                break
            base = info.BaseAddress or 0
            if (info.State == MEM_COMMIT and info.Protect and not info.Protect & (PAGE_NOACCESS | PAGE_GUARD)
                    and info.RegionSize >= SIGNATURE_OFFSET + len(SIGNATURE)):
                try:
                    if self._read_host(base + SIGNATURE_OFFSET, len(SIGNATURE)) == SIGNATURE:
                        candidates.append(base)
                except OSError:
                    pass
            address = base + info.RegionSize
        if len(candidates) != 1:
            raise PatchMismatch(f"process {self.pid}: expected exactly one mapping of Pokopia 2.0.1 main, "
                                f"found {len(candidates)}")
        return candidates[0]

    def _check_mailbox_memory(self) -> None:
        address = self._arena + self.main + MAILBOX
        end = address + MAILBOX_SIZE
        while address < end:
            info = self._query(address)
            if (info is None or info.State != MEM_COMMIT or info.Protect & PAGE_GUARD
                    or info.Protect & 0xFF not in (PAGE_READWRITE, PAGE_EXECUTE_READWRITE)):
                raise MailboxError(f"process {self.pid}: the quest mailbox is not committed read-write memory")
            address = (info.BaseAddress or 0) + info.RegionSize

    def _read_host(self, address: int, size: int) -> bytes:
        if not self._handle:
            raise ProcessLost(f"process {self.pid} is closed")
        buffer = ctypes.create_string_buffer(size)
        done = ctypes.c_size_t()
        if (not self._k.ReadProcessMemory(self._handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(done))
                or done.value != size):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw

    def read(self, address: int, size: int) -> bytes:
        try:
            return self._read_host(self._arena + address, size)
        except OSError as exc:
            raise ProcessLost(f"process {self.pid}: cannot read {size:#x} bytes at {address:#x} ({exc})") from exc

    def write(self, address: int, data: bytes) -> None:
        low = self.main + MAILBOX
        if not data or address < low or address + len(data) > low + MAILBOX_SIZE:
            raise ValueError(f"refusing to write outside the quest mailbox: {address:#x}+{len(data):#x}")
        if not self._handle:
            raise ProcessLost(f"process {self.pid} is closed")
        done = ctypes.c_size_t()
        if (not self._k.WriteProcessMemory(self._handle, ctypes.c_void_p(self._arena + address), data, len(data),
                                           ctypes.byref(done)) or done.value != len(data)):
            raise ProcessLost(f"process {self.pid}: cannot write the mailbox at {address:#x} "
                              f"({ctypes.WinError(ctypes.get_last_error())})")

    def alive(self) -> bool:
        if not self._handle:
            return False
        result = self._k.WaitForSingleObject(self._handle, 0)
        if result == WAIT_TIMEOUT:
            return True
        if result == WAIT_OBJECT_0:
            return False
        raise ProcessLost(f"process {self.pid}: cannot query it ({ctypes.WinError(ctypes.get_last_error())})")


# --- The mailbox ------------------------------------------------------------------------------------------

class Mailbox:
    """The relay's side of the patch mailbox in one game. The game writes the inbox read index, counters,
    journal reservations, entries, commits and loss counts; this object owns the inbox write index and both
    journal read cursors. check() detects a restarted game, a foreign writer and journal loss."""

    def __init__(self, game: Game, *, drain: bool, journal: bool, unique_journal: bool = False,
                 skip_mask: int = DEFAULT_SKIP_MASK) -> None:
        if type(skip_mask) is not int or not 0 <= skip_mask < 1 << 64:
            raise ValueError(f"bad effect skip mask {skip_mask!r}")
        self.game = game
        self.base = game.main + MAILBOX
        self.flags = ((FLAG_DRAIN if drain else 0) | (FLAG_JOURNAL if journal else 0)
                      | (FLAG_UNIQUE_JOURNAL if unique_journal else 0))
        self.skip_mask = skip_mask
        self.attached = False
        self.in_w = self.in_r = self.story_r = self.unique_r = 0
        self.applied = self.skipped = 0

    def attach(self) -> None:
        """Arms the caves of a mailbox nobody has used. A mailbox that is not all zero belongs to an earlier
        attachment or to a game that is not fresh, and is refused before anything is written; so both journal
        read cursors start at zero."""
        if self.attached:
            raise RuntimeError("the mailbox is already attached")
        if self.flags & (FLAG_JOURNAL | FLAG_UNIQUE_JOURNAL):
            verify_patch(self.game.read, self.game.main)
        if self.game.read(self.base, MAILBOX_SIZE) != bytes(MAILBOX_SIZE):
            raise MailboxError("the quest mailbox is not pristine; start a fresh game before attaching")
        self.game.write(self.base + MB_SKIP_MASK, struct.pack("<Q", self.skip_mask))
        self.game.write(self.base + MB_FLAGS, struct.pack("<I", self.flags))
        self.game.write(self.base + MB_MAGIC, struct.pack("<I", MAGIC))  # last: the caves stay inert until then
        self.attached = True

    def detach(self) -> None:
        """Turns the drain and the journal off (flags 0). The magic stays, so the mailbox never counts as
        pristine again: no relay attaches twice to one run of the game."""
        if self.attached:
            self.attached = False
            self.game.write(self.base + MB_FLAGS, bytes(4))

    def _u32(self, offset: int) -> int:
        return struct.unpack("<I", self.game.read(self.base + offset, 4))[0]

    def _header(self) -> bytes:
        """The mailbox header, which must still hold the magic and this relay's flags."""
        header = self.game.read(self.base, HEADER_SIZE)
        if struct.unpack_from("<I", header, MB_MAGIC)[0] != MAGIC:
            raise MailboxError("the quest mailbox lost its contents")
        if struct.unpack_from("<I", header, MB_FLAGS)[0] != self.flags:
            raise MailboxError("the quest mailbox flags changed")
        return header

    def _story_end(self, header: bytes) -> int:
        """Validates the story journal's header words and returns out_w, the sequence after the last reserved
        entry."""
        written = struct.unpack_from("<I", header, MB_OUT_W)[0]
        read, lost = struct.unpack_from("<2I", header, MB_STORY_R)
        if not self.flags & FLAG_JOURNAL:
            if written or read or lost:
                raise MailboxError("the disabled story quest journal was changed")
            return 0
        if read != self.story_r:
            raise MailboxError("the story quest journal read cursor was changed by someone other than this relay")
        if lost:
            raise MailboxError(f"the story quest journal was full: {lost} quest changes were lost; "
                               f"resynchronization is required")
        if written < read or written >= U32 - JOURNAL_SLOTS:
            raise MailboxError("the story quest journal sequence is invalid or exhausted")
        if written - read > JOURNAL_SLOTS:
            raise MailboxError("the story quest journal exceeds its capacity")
        return written

    def _unique_end(self, header: bytes) -> int:
        written, read, lost, gap = struct.unpack_from("<4I", header, MB_UJ_W)
        if not self.flags & FLAG_UNIQUE_JOURNAL:
            if written or read or lost or gap:
                raise MailboxError("the disabled unique quest journal was changed")
            return 0
        if read != self.unique_r:
            raise MailboxError("the unique quest journal read index was changed")
        if lost or gap:
            raise MailboxError("the unique quest journal lost changes; resynchronization is required")
        if written < read or written >= U32 - UNIQUE_JOURNAL_SLOTS:
            raise MailboxError("the unique quest journal sequence is invalid or exhausted")
        if written - read > UNIQUE_JOURNAL_SLOTS:
            raise MailboxError("the unique quest journal exceeds its capacity")
        return written

    def check(self) -> int:
        """Validates the header and returns how many inbox entries the game took since the last check."""
        if not self.attached:
            raise RuntimeError("the mailbox is not attached")
        header = self.game.read(self.base, HEADER_SIZE)
        magic, flags, applying, applied, in_w, in_r = struct.unpack_from("<6I", header)
        skip_mask, skipped = struct.unpack_from("<QI", header, MB_SKIP_MASK)
        if magic != MAGIC:
            raise MailboxError("the quest mailbox lost its contents (the game restarted or its memory was reset)")
        if (flags != self.flags or skip_mask != self.skip_mask or applying > 1 or in_w != self.in_w
                or header[0x1C:MB_SKIP_MASK] != bytes(4) or header[0x2C:MB_UJ_W] != bytes(0x24)
                or header[MB_STORY_LOST + 4:] != bytes(HEADER_SIZE - MB_STORY_LOST - 4)):
            raise MailboxError("the quest mailbox was changed by someone other than this relay and the game")
        self._unique_end(header)
        self._story_end(header)
        taken = (in_r - self.in_r) & U32
        if taken > (self.in_w - self.in_r) & U32:
            raise MailboxError("the game's inbox read index is past the entries this relay queued")
        self.in_r, self.applied, self.skipped = in_r, applied, skipped
        return taken

    def read_journal(self) -> list[JournalEntry]:
        """Reads the committed story quest changes after the read cursor, in reservation order, and acknowledges
        them by moving the cursor past them, which frees their slots. Reading stops at the first reserved entry
        that is not committed yet; it and everything after it wait for a later call.

        Game threads reserve after their quest store, so the entries of concurrent writers need not be in the
        order of their stores, and an entry's old state need not be what the previous entry for that quest set:
        the journal is neither a causal order nor an atomic snapshot of quest states. A loss, a cursor written
        by someone else, a sequence out of bounds, a commit cave J cannot have written or an invalid entry stops
        the relay with nothing acknowledged; the header is checked before and after the copy."""
        if not self.attached or not self.flags & FLAG_JOURNAL:
            raise RuntimeError("the story quest journal is not attached")
        start = self.story_r
        end = self._story_end(self._header())
        if end == start:
            return []
        # Commits before entries: an entry is complete once its commit, stored after it, reads seq + 1, and the
        # game does not reuse its slot before this relay moves the cursor past it.
        commits = struct.unpack(f"<{JOURNAL_SLOTS}I", self.game.read(self.base + MB_STORY_COMMITS, 4 * JOURNAL_SLOTS))
        ring = struct.unpack(f"<{JOURNAL_SLOTS}I", self.game.read(self.base + MB_JOURNAL, 4 * JOURNAL_SLOTS))
        self._story_end(self._header())  # a loss, a restart or a foreign cursor during the copy acknowledges nothing
        committed = start
        while committed < end and commits[committed % JOURNAL_SLOTS] == committed + 1:
            committed += 1
        for sequence in range(committed, end):  # reserved: committed out of order, or still the previous lap's
            commit = commits[sequence % JOURNAL_SLOTS]
            if commit not in (sequence + 1, max(sequence + 1 - JOURNAL_SLOTS, 0)):
                raise MailboxError(f"the story quest journal commit of sequence {sequence} reads {commit:#x}, "
                                   f"which cave J never writes there")
        entries = [JournalEntry.decode(ring[sequence % JOURNAL_SLOTS]) for sequence in range(start, committed)]
        if entries:
            self.game.write(self.base + MB_STORY_R, struct.pack("<I", committed))
            self.story_r = committed
        return entries

    def read_unique_journal(self) -> list[UniqueJournalEntry]:
        """Read committed unique-quest changes in reservation order. A loss or a changed read index
        stops the relay; an uncommitted reservation is left for the next call."""
        if not self.attached or not self.flags & FLAG_UNIQUE_JOURNAL:
            raise RuntimeError("the unique quest journal is not attached")
        end = self._unique_end(self._header())
        sequence = self.unique_r
        events = []
        while sequence < end:
            slot = MB_UNIQUE_JOURNAL + 8 * (sequence % UNIQUE_JOURNAL_SLOTS)
            if self._u32(slot + 4) != sequence + 1:
                break
            events.append(UniqueJournalEntry.decode(sequence, self._u32(slot)))
            sequence += 1
        self._unique_end(self._header())
        if events:
            self.game.write(self.base + MB_UJ_R, struct.pack("<I", sequence))
            self.unique_r = sequence
        return events

    def push(self, words: Sequence[int]) -> int:
        """Queues as many of words, in order, as the 64-slot inbox has room for (as of the last check) and
        returns how many."""
        count = min(INBOX_SLOTS - ((self.in_w - self.in_r) & U32), len(words))
        if count <= 0:
            return 0
        data = struct.pack(f"<{count}I", *words[:count])
        slot = self.in_w % INBOX_SLOTS
        head = min(count, INBOX_SLOTS - slot)
        self.game.write(self.base + MB_INBOX + 4 * slot, data[:4 * head])
        if count > head:
            self.game.write(self.base + MB_INBOX, data[4 * head:])
        self.in_w = (self.in_w + count) & U32
        self.game.write(self.base + MB_IN_W, struct.pack("<I", self.in_w))  # after the entries: cave D uses ldar
        return count


# --- HTTP client --------------------------------------------------------------------------------------------

class _TLSConnection(http.client.HTTPConnection):
    """HTTP/1.1 over TLS to host:port, verifying the certificate for server_name (the ingress name), which
    http.client.HTTPSConnection cannot do when the two differ."""

    default_port = 443

    def __init__(self, host: str, port: int, *, context: ssl.SSLContext, server_name: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._tls_context, self._server_name = context, server_name

    def connect(self) -> None:
        super().connect()
        self.sock = self._tls_context.wrap_socket(self.sock, server_hostname=self._server_name)
        protocol = self.sock.selected_alpn_protocol()
        if protocol not in (None, "http/1.1"):
            self.close()
            raise ProtocolError(f"the server chose {protocol} for the HTTP/1.1 live transport; "
                                f"use an http/1.1 SSLContext")


def _json_object(data: bytes) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    def no_constant(name: str) -> object:
        raise ValueError(f"{name} is not JSON")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError(f"the server sent malformed JSON ({exc})") from exc
    if not isinstance(value, dict):
        raise ProtocolError("the server's answer is not a JSON object")
    return value


def _valid_session(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 512 and all(" " <= c <= "~" for c in value)


def _valid_epoch(value: object) -> bool:
    return isinstance(value, str) and EPOCH.fullmatch(value) is not None


def _seq(obj: dict, key: str, low: int) -> int:
    value = obj.get(key)
    if type(value) is not int or not low <= value <= MAX_SEQ:
        raise ProtocolError(f"the server sent a bad {key!r}: {value!r}")
    return value


def parse_view(obj: dict, after: int | None) -> LiveView:
    """Validates a /campaign/live answer. after=None for discovery and POST answers, whose events are
    ignored. Otherwise the events must continue the cursor after one by one; a cursor the server no longer
    covers raises ResyncRequired."""
    session, epoch, role = obj.get("session"), obj.get("epoch"), obj.get("role")
    if not _valid_session(session) or not _valid_epoch(epoch) or role not in ("host", "guest"):
        raise ProtocolError(f"the server sent a bad session, epoch or role: {session!r} {epoch!r} {role!r}")
    first, last = _seq(obj, "first", 1), _seq(obj, "last", 0)
    if first > last + 1:
        raise ProtocolError(f"the server's journal starts at {first} after its end {last}")
    raw = obj.get("events")
    if after is None:
        if raw is not None and not isinstance(raw, list):
            raise ProtocolError("the server sent events that are not a list")
        return LiveView(session, epoch, role, first, last)
    if after > last:
        raise ResyncRequired(f"the server's journal ends at {last}, before this relay's cursor {after}")
    if after < first - 1:
        raise ResyncRequired(f"the server discarded events {after + 1}..{first - 1} that this relay has not seen")
    if not isinstance(raw, list):
        raise ProtocolError("the server sent no event list")
    events = []
    for seq, item in enumerate(raw, after + 1):
        if not isinstance(item, dict) or set(item) != {"seq", "id", "old", "new"}:
            raise ProtocolError(f"the server sent a malformed event: {item!r}")
        if type(item["seq"]) is not int or item["seq"] != seq or seq > last:
            raise ProtocolError(f"the server's events are not in order: expected seq {seq} (journal end {last}), "
                                f"got {item['seq']!r}")
        try:
            events.append(LiveEvent(seq, QuestEvent(item["id"], item["old"], item["new"])))
        except ValueError as exc:
            raise ProtocolError(f"the server sent an invalid event {seq}: {exc}") from exc
    if not events and last > after:
        raise ProtocolError(f"the server holds events up to {last} after cursor {after} but sent none")
    return LiveView(session, epoch, role, first, last, tuple(events))


def parse_receipt(obj: dict, session: str, epoch: str, count: int) -> ProposalReceipt:
    """Validates the answer to a /campaign/live/proposals POST of `count` proposals."""
    if obj.keys() != {"session", "epoch", "first", "last", "added"}:
        raise ProtocolError(f"the server's proposal answer holds {sorted(obj)}, not session, epoch, first, last "
                            f"and added")
    if (obj["session"], obj["epoch"]) != (session, epoch):
        raise ProtocolError(f"proposed to {session} epoch {epoch}, the server answered for {obj['session']!r} epoch "
                            f"{obj['epoch']!r}")
    first, last, added = _seq(obj, "first", 1), _seq(obj, "last", 0), obj["added"]
    if first > last + 1:
        raise ProtocolError(f"the server's proposal journal starts at {first} after its end {last}")
    if type(added) is not int or not 0 <= added <= count:
        raise ProtocolError(f"the server added {added!r} of {count} proposals")
    if added > last - first + 1:
        raise ProtocolError(f"the server added {added} proposals but its journal holds only {first}..{last}")
    return ProposalReceipt(first, last, added)


class LiveClient:
    """HTTP/1.1 client of /campaign/live over the mutually authenticated connection to the game backend.

    context: the launcher's upstream SSLContext with this PC's client certificate and the ingress CA, i.e.
    launcher.upstream_context(home, "http/1.1"). ingress: launcher.json's {"host", "port", "server_name"}.
    It keeps one connection alive and reopens it after any error. Not thread-safe: give each relay its own."""

    def __init__(self, context: ssl.SSLContext, ingress: Mapping[str, object], *, timeout: float = 10.0) -> None:
        if (not isinstance(context, ssl.SSLContext) or context.verify_mode != ssl.CERT_REQUIRED
                or not context.check_hostname):
            raise ValueError("the live transport needs an SSLContext that verifies the server's certificate and name")
        host, port, server_name = ingress.get("host"), ingress.get("port"), ingress.get("server_name")
        if (not isinstance(host, str) or not host or not isinstance(server_name, str) or not server_name
                or type(port) is not int or not 0 < port < 65536):
            raise ValueError(f"bad ingress configuration {dict(ingress)!r}")
        if not timeout > 0:
            raise ValueError(f"bad timeout {timeout!r}")
        self._context, self._host, self._port, self._server_name = context, host, port, server_name
        self._timeout = timeout
        self._host_header = server_name if port == 443 else f"{server_name}:{port}"
        self._connection: _TLSConnection | None = None

    def __enter__(self) -> LiveClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _request(self, method: str, target: str, body: bytes | None = None) -> dict:
        headers = {"Host": self._host_header, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(2):
            reused = self._connection is not None
            if self._connection is None:
                self._connection = _TLSConnection(self._host, self._port, context=self._context,
                                                  server_name=self._server_name, timeout=self._timeout)
            try:
                self._connection.request(method, target, body=body, headers=headers)
                response = self._connection.getresponse()
                data = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
                if len(data) > MAX_RESPONSE_BYTES or response.will_close or not response.isclosed():
                    self.close()
                break
            except (OSError, http.client.HTTPException) as exc:
                self.close()
                if isinstance(exc, ssl.SSLCertVerificationError):
                    raise LiveRefused(None, "certificate", f"the server's certificate was refused: "
                                                           f"{exc.verify_message}") from exc
                if isinstance(exc, ssl.SSLError) and not isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
                    raise LiveRefused(None, "tls", f"TLS with the server failed: {exc.reason or exc}") from exc
                if reused and not attempt and isinstance(exc, (http.client.RemoteDisconnected, ConnectionError,
                                                               ssl.SSLEOFError)):
                    continue  # the server had closed the kept-alive connection; a resend is harmless
                raise LiveUnavailable(f"{type(exc).__name__}: {exc}") from exc
        if len(data) > MAX_RESPONSE_BYTES:
            raise ProtocolError(f"the server's answer is larger than {MAX_RESPONSE_BYTES} bytes")
        if status == 200:
            return _json_object(data)
        try:
            error = _json_object(data)
            code, message = str(error.get("error", "")), str(error.get("message", ""))
            message += "".join(f" {key}={error[key]}" for key in ("first", "last") if key in error)
        except ProtocolError:
            code, message = "", data[:200].decode("utf-8", "replace")
        if status == 409:
            raise LiveConflict(status, code, message)
        if status in (502, 503, 504):
            raise LiveUnavailable(f"{status} {code}: {message}")
        raise LiveRefused(status, code, message)

    def discover(self) -> LiveView:
        """The only live session with an active user of this account (404 if there is none or more)."""
        return parse_view(self._request("GET", LIVE_PATH), None)

    def poll(self, session: str, epoch: str, after: int) -> LiveView:
        """The events after seq `after`, contiguous and in order (the server may return only a page)."""
        if not _valid_session(session) or not _valid_epoch(epoch) or type(after) is not int or not 0 <= after <= MAX_SEQ:
            raise ValueError(f"bad poll {session!r} {epoch!r} {after!r}")
        query = urlencode({"session": session, "epoch": epoch, "after": after}, quote_via=quote, safe="")
        view = parse_view(self._request("GET", f"{LIVE_PATH}?{query}"), after)
        if (view.session, view.epoch) != (session, epoch):
            raise ProtocolError(f"asked for {session} epoch {epoch}, the server answered for {view.session} epoch "
                                f"{view.epoch}")
        return view

    def post(self, session: str, epoch: str, first: int, events: Sequence[QuestEvent]) -> int:
        """Appends events as seqs first.. (session creator only). Resending the same events at the same seqs
        succeeds; anything conflicting raises LiveConflict. Returns the server's journal end."""
        if not _valid_session(session) or not _valid_epoch(epoch) or type(first) is not int or not 1 <= first:
            raise ValueError(f"bad post {session!r} {epoch!r} {first!r}")
        if not 1 <= len(events) <= MAX_EVENTS_PER_POST or first + len(events) - 1 > MAX_SEQ:
            raise ValueError(f"a post carries 1..{MAX_EVENTS_PER_POST} events, not {len(events)}")
        body = json.dumps({"session": session, "epoch": epoch, "first": first,
                           "events": [{"id": e.id, "old": e.old, "new": e.new} for e in events]},
                          separators=(",", ":")).encode()
        if len(body) > MAX_POST_BYTES:
            raise ValueError(f"the post body is larger than {MAX_POST_BYTES} bytes")
        view = parse_view(self._request("POST", LIVE_PATH, body), None)
        end = first + len(events) - 1
        if (view.session, view.epoch, view.role) != (session, epoch, "host") or view.last < end:
            raise ProtocolError(f"the server confirmed events {first}..{end} with {view.session} epoch {view.epoch} "
                                f"role {view.role}, journal end {view.last}")
        return view.last

    def propose(self, session: str, epoch: str, producer: str, first: int,
                proposals: Sequence[Proposal]) -> ProposalReceipt:
        """Posts proposals as the numbers first.. of producer (guests only, while the session creator is in
        the session). Resending the same proposals at the same numbers succeeds, with added 0 if they had
        arrived; other proposals at a taken number, a gap or a number the server no longer keeps raise
        LiveConflict. The receipt's first and last are the shared journal's, not this producer's."""
        if (not _valid_session(session) or not _valid_epoch(epoch) or not isinstance(producer, str)
                or PRODUCER.fullmatch(producer) is None or type(first) is not int or not 1 <= first <= MAX_SEQ):
            raise ValueError(f"bad proposal post {session!r} {epoch!r} {producer!r} {first!r}")
        if not 1 <= len(proposals) <= MAX_EVENTS_PER_POST or first + len(proposals) - 1 > MAX_SEQ:
            raise ValueError(f"a proposal post carries 1..{MAX_EVENTS_PER_POST} proposals, not {len(proposals)}")
        if not all(isinstance(proposal, Proposal) for proposal in proposals):
            raise ValueError("a proposal post carries Proposal objects only")
        body = json.dumps({"session": session, "epoch": epoch, "producer": producer, "first": first,
                           "events": [proposal.payload() for proposal in proposals]},
                          separators=(",", ":")).encode()
        if len(body) > MAX_POST_BYTES:
            raise ValueError(f"the proposal post body is larger than {MAX_POST_BYTES} bytes")
        return parse_receipt(self._request("POST", PROPOSALS_PATH, body), session, epoch, len(proposals))


# --- Relays -------------------------------------------------------------------------------------------------

class _Relay:
    _host_side: bool

    def __init__(self, client: LiveClient, game: Game, *, drain: bool, skip_mask: int, offline_timeout: float,
                 retry_delay: float, clock: Callable[[], float], unique_journal: bool = False) -> None:
        if not offline_timeout > 0 or not retry_delay >= 0:
            raise ValueError("offline_timeout must be positive and retry_delay non-negative")
        self.client, self.game = client, game
        self.mailbox = Mailbox(game, drain=drain, journal=True, unique_journal=unique_journal, skip_mask=skip_mask)
        self.session: str | None = None
        self.epoch: str | None = None
        self.server_role: str | None = None
        self._game_session: GameSession | None = None
        self._offline_timeout, self._retry_delay, self._clock = offline_timeout, retry_delay, clock
        self._last_contact = self._retry_at = 0.0
        self._started = False

    def _begin(self) -> LiveView:
        if self._started:
            raise RuntimeError("a relay starts only once")
        self._started = True
        return self.client.discover()

    def _attach(self, view: LiveView) -> None:
        state = read_session(self.game)
        side, expected = ("host", HOST_CAPS) if self._host_side else ("guest", GUEST_CAPS)
        if state is None:
            raise GameNotReady("the game has no GameManager yet")
        if state.caps != expected:
            raise GameNotReady(f"the game's capability mask is {state.caps.to_bytes(5, 'little').hex(' ')}, not the "
                               f"patched {side} mask of an online story stage "
                               f"({expected.to_bytes(5, 'little').hex(' ')})")
        self.mailbox.attach()
        self._game_session = state
        self.session, self.epoch, self.server_role = view.session, view.epoch, view.role
        self._last_contact = self._clock()

    def _check_game(self) -> int:
        if not self.game.alive():
            raise ProcessLost("the game process exited")
        verify_patch(self.game.read, self.game.main)
        if read_session(self.game) != self._game_session:
            raise SessionChanged("the game's GameManager or capability mask changed (session or stage left)")
        return self.mailbox.check()

    def _check_view(self, view: LiveView) -> None:
        if view.role != self.server_role:
            raise SessionChanged(f"this account's role in the live session changed to {view.role}")

    def _unavailable(self, exc: LiveUnavailable) -> None:
        now = self._clock()
        if now - self._last_contact > self._offline_timeout:
            raise BridgeError(f"the server was unreachable for over {self._offline_timeout:g} s ({exc})") from exc
        log.warning("live server unavailable, retrying: %s", exc)
        self._retry_at = now + self._retry_delay

    def step(self) -> None:
        """One relay cycle; call it every ~0.1 s. Network trouble is retried within it. Any other failure
        turns the mailbox off and raises, BridgeError for every expected one."""
        if not self.mailbox.attached:
            raise BridgeError("the relay is not running: start() it first, or it already stopped")
        try:
            self._step()
        except BaseException:
            self.close()
            raise

    def _step(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        """Turns the game's mailbox off. Neither the client nor the game is closed: they are the caller's."""
        try:
            self.mailbox.detach()
        except (BridgeError, OSError) as exc:
            log.warning("could not turn the quest mailbox off: %s", exc)

    def run(self, stop: threading.Event, interval: float = 0.1) -> None:
        """Starts the relay if needed and steps it until stop is set. Always turns the mailbox off on the way
        out. Errors from start() (LiveUnavailable included) and every BridgeError reach the caller."""
        try:
            if not self._started:
                self.start()
            while not stop.wait(interval):
                self.step()
        finally:
            self.close()

    def start(self) -> LiveView:
        raise NotImplementedError


class HostRelay(_Relay):
    """Runs on the session creator's PC: sends the host game's own quest changes (journal origin 0), in journal
    (reservation) order, as the seqs after the server's journal end. For changes made concurrently on different
    threads that order need not be the order of their stores (see Mailbox.read_journal).

    The drain stays off on the host, so its journal can never hold a replay; an origin 1 entry means
    someone else touched the mailbox, and stops the relay. Changes wait in `pending` while the server is
    unreachable, up to max_pending. A batch whose answer was lost is resent unchanged with the same seqs,
    and the server accepts an identical resend. Every `heartbeat` seconds without changes it polls the
    server, so an ended session, a new epoch or another writer is noticed while the host is idle."""

    _host_side = True

    def __init__(self, client: LiveClient, game: Game, *, batch: int = MAX_EVENTS_PER_POST, max_pending: int = 4096,
                 heartbeat: float = 5.0, offline_timeout: float = 60.0, retry_delay: float = 1.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__(client, game, drain=False, skip_mask=DEFAULT_SKIP_MASK, offline_timeout=offline_timeout,
                         retry_delay=retry_delay, clock=clock)
        if not 1 <= batch <= MAX_EVENTS_PER_POST or max_pending < batch or not heartbeat >= 0:
            raise ValueError("bad batch, max_pending or heartbeat")
        self._batch, self._max_pending, self._heartbeat = batch, max_pending, heartbeat
        self.acked = 0  # the server's journal end, everything up to it confirmed
        self._pending: collections.deque[QuestEvent] = collections.deque()
        self._inflight: tuple[QuestEvent, ...] = ()
        self._next_heartbeat = 0.0

    @property
    def pending(self) -> int:
        return len(self._pending) + len(self._inflight)

    def start(self) -> LiveView:
        """Finds the live session, which this account must have created (server role "host"). Then arms the
        journal of a game showing the patched host mask whose mailbox is pristine."""
        view = self._begin()
        if view.role != "host":
            raise LiveRefused(None, "not_host", "this account did not create the live session; only the creator's "
                                                "PC relays host quest changes")
        self._attach(view)
        self.acked = view.last
        self._next_heartbeat = self._last_contact + self._heartbeat
        log.info("host relay attached to %s epoch %s at seq %d", view.session, view.epoch, view.last)
        return view

    def _step(self) -> None:
        self._check_game()
        for entry in self.mailbox.read_journal():
            if entry.origin != 0:
                raise MailboxError(f"the host journal holds a replayed change {entry}; the host's drain is off, "
                                   f"so someone else wrote the mailbox")
            try:
                self._pending.append(QuestEvent(entry.id, entry.old, entry.new))
            except ValueError as exc:
                raise ResyncRequired(f"the host made a quest change the contract cannot carry: {entry}") from exc
        if self.pending > self._max_pending:
            raise BridgeError(f"{self.pending} host quest changes are waiting for the server; refusing to buffer more")
        now = self._clock()
        if now < self._retry_at:
            return
        try:
            if self.pending:
                self._send(now)
            elif now >= self._next_heartbeat:
                view = self.client.poll(self.session, self.epoch, self.acked)
                self._check_view(view)
                if view.last != self.acked:
                    raise ResyncRequired(f"the server's journal moved from {self.acked} to {view.last} without this host")
                self._last_contact, self._next_heartbeat = now, now + self._heartbeat
        except LiveUnavailable as exc:
            self._unavailable(exc)

    def _send(self, now: float) -> None:
        if not self._inflight:
            self._inflight = tuple(self._pending.popleft() for _ in range(min(self._batch, len(self._pending))))
        first = self.acked + 1
        last = self.client.post(self.session, self.epoch, first, self._inflight)
        end = first + len(self._inflight) - 1
        if last != end:
            raise ResyncRequired(f"the server's journal ends at {last} after this host's events {first}..{end}: "
                                 f"another writer")
        for seq, event in enumerate(self._inflight, first):
            log.info("host quest %d: %d -> %d sent as seq %d", event.id, event.old, event.new, seq)
        self.acked, self._inflight = end, ()
        self._last_contact, self._next_heartbeat = now, now + self._heartbeat


class GuestRelay(_Relay):
    """Runs on a guest's PC: replays the live session's events, in order, through the guest game's inbox.

    It starts after seq `after`, 0 by default, which replays the whole retained history. A nonzero cursor
    is only meaningful within its session and epoch, so it needs both, and start() raises SessionChanged if
    the live session is a different one. `consumed` is the last seq the game's drain has taken from the inbox;
    persist (session, epoch, consumed) to resume. `received` is the last seq fetched. The guest's journal is
    only observed: `replayed` counts the changes its drain made (origin 1), `local_changes` the changes the
    guest game made on its own (origin 0). Unless propose is set, none of them is ever sent.

    propose=True, an explicit opt-in that the launcher does not use, needs the server role "guest". It also
    arms the game's unique-quest journal and posts the guest game's own changes to /campaign/live/proposals:
    story changes of journal origin 0 and unique-quest changes of unique origin 0. Replayed story changes
    (origin 1), uniqueCas replays (unique origin 1) and side effects on the drain thread (unique origin 2)
    are only counted, in `replayed` and `unique_replayed`. Proposals are untrusted input for the host to
    judge against its own game, which may have made the same change on its own (the host's inventory alone
    can advance quest 11); nothing here applies them, on the host or anywhere else. They go out in
    batches of up to proposal_batch, as the numbers 1, 2, ... of `producer`, a random 128-bit id of this
    relay alone; `proposed` is how many the server has acknowledged. A batch whose answer was lost is resent
    unchanged, at the same numbers, until offline_timeout. The shared journal bounds in the server's answers
    are only checked never to go back, never taken as an acknowledgement. The relay stops, giving up the
    proposals the server has not acknowledged (close() logs how many), when more than max_proposals wait,
    the guest game makes a change the contract cannot carry, a journal loses an entry, the server refuses a
    batch (a conflict, a gap, a number it no longer keeps, a new epoch, a host that left) or answers outside
    the contract. A new relay is a new producer, and the server takes at most 64 producers per epoch.

    The numbers order each journal on its own, in reservation order, which for concurrent writers need not be
    the order of their stores. The rings are separate, so between a story and a unique proposal the numbers
    only say which ring a step read first (story), not which change came first. A story change counts as a
    replay only when the drain's own thread made it while applying inbox entries, so another thread's change
    during a replay stays local; conversely, a deferred replay effect, made after the drain returned, appears
    local. A full story journal drops changes and stops the relay. This sender is not a reliable basis for
    campaign synchronization."""

    _host_side = False

    def __init__(self, client: LiveClient, game: Game, *, session: str | None = None, epoch: str | None = None,
                 after: int = 0, poll_interval: float = 0.5, skip_mask: int = DEFAULT_SKIP_MASK,
                 propose: bool = False, proposal_batch: int = MAX_EVENTS_PER_POST, max_proposals: int = 1024,
                 offline_timeout: float = 60.0, retry_delay: float = 1.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if type(propose) is not bool:
            raise ValueError(f"propose is True or False, not {propose!r}")
        super().__init__(client, game, drain=True, skip_mask=skip_mask, offline_timeout=offline_timeout,
                         retry_delay=retry_delay, clock=clock, unique_journal=propose)
        if type(after) is not int or not 0 <= after <= MAX_SEQ or not poll_interval >= 0:
            raise ValueError("bad cursor or poll interval")
        if (session is None) != (epoch is None) or (after and session is None):
            raise ValueError("a cursor belongs to one session and epoch: pass both with it")
        if (type(proposal_batch) is not int or type(max_proposals) is not int
                or not 1 <= proposal_batch <= MAX_EVENTS_PER_POST or max_proposals < proposal_batch):
            raise ValueError("bad proposal batch or max_proposals")
        self._resume = (session, epoch) if session is not None else None
        self._poll_interval = poll_interval
        self.received = self.consumed = after
        self.replayed = self.local_changes = 0
        self._queue: collections.deque[tuple[int, int]] = collections.deque()  # (seq, inbox word) not yet queued
        self._inbox: collections.deque[int] = collections.deque()  # seqs in the inbox, not yet taken
        self._next_poll = 0.0
        self._propose, self._proposal_batch, self._max_proposals = propose, proposal_batch, max_proposals
        self.producer = secrets.token_hex(16) if propose else None
        self.proposed = self.unique_replayed = 0
        self._proposals: collections.deque[Proposal] = collections.deque()  # read, not yet posted
        self._posting: tuple[Proposal, ...] = ()  # posted as numbers proposed + 1.., not yet acknowledged
        self._proposal_bounds = (1, 0)  # the shared proposal journal's first and last in the newest answer

    @property
    def proposals_pending(self) -> int:
        return len(self._proposals) + len(self._posting)

    def start(self) -> LiveView:
        """Finds the live session (the one to resume, if given). Then arms the drain of a game showing the
        patched guest mask whose mailbox is pristine."""
        view = self._begin()
        if self._resume is not None and (view.session, view.epoch) != self._resume:
            raise SessionChanged(f"the cursor belongs to {self._resume[0]} epoch {self._resume[1]}, the live session "
                                 f"is {view.session} epoch {view.epoch}")
        if self._propose and view.role != "guest":
            raise LiveRefused(None, "not_guest", "this account created the live session; only other accounts' PCs "
                                                 "propose guest quest changes")
        self._attach(view)
        log.info("guest relay attached to %s epoch %s after seq %d", view.session, view.epoch, self.received)
        if self._propose:
            log.info("guest relay proposes this game's own quest changes as producer %s", self.producer)
        return view

    def close(self) -> None:
        if self.mailbox.attached and self.proposals_pending:
            log.warning("guest relay stopped with %d quest proposals the server has not acknowledged",
                        self.proposals_pending)
        super().close()

    def _step(self) -> None:
        for _ in range(self._check_game()):
            self.consumed = self._inbox.popleft()
        for entry in self.mailbox.read_journal():
            if entry.origin:
                self.replayed += 1
                log.debug("guest replayed quest %d: %d -> %d", entry.id, entry.old, entry.new)
            else:
                self.local_changes += 1
                if self._propose:
                    self._take(entry)
                else:
                    log.info("guest game changed quest %d itself: %d -> %d (not sent)", entry.id, entry.old,
                             entry.new)
        if self._propose:
            for unique in self.mailbox.read_unique_journal():
                if unique.origin:
                    self.unique_replayed += 1
                    log.debug("guest unique quest %d %s %d -> %d by %s (not sent)", unique.id, unique.field,
                              unique.old, unique.new, "a uniqueCas replay" if unique.origin == 1 else "the drain")
                else:
                    self._take(unique)
            if self.proposals_pending > self._max_proposals:
                raise BridgeError(f"{self.proposals_pending} guest quest proposals are waiting for the server; "
                                  f"refusing to buffer more")
        self._fill()
        now = self._clock()
        if now < self._retry_at:
            return
        if self.proposals_pending:
            try:
                self._send_proposals(now)
            except LiveUnavailable as exc:
                self._unavailable(exc)
                return
        if self._queue or now < self._next_poll:
            return
        try:
            view = self.client.poll(self.session, self.epoch, self.received)
        except LiveUnavailable as exc:
            self._unavailable(exc)
            return
        self._check_view(view)
        words = [(event.seq, event.quest.inbox_word()) for event in view.events]  # all checked before any is queued
        self._queue.extend(words)
        if view.events:
            self.received = view.events[-1].seq
        self._last_contact = now
        self._next_poll = now if self.received < view.last else now + self._poll_interval
        self._fill()

    def _fill(self) -> None:
        if self._queue:
            taken = self.mailbox.push([word for _, word in itertools.islice(self._queue, INBOX_SLOTS)])
            for _ in range(taken):
                self._inbox.append(self._queue.popleft()[0])

    def _take(self, entry: JournalEntry | UniqueJournalEntry) -> None:
        try:
            proposal = Proposal.of(entry)
        except ValueError as exc:
            raise ResyncRequired(f"the guest game made a quest change the proposal contract cannot carry: "
                                 f"{entry}") from exc
        self._proposals.append(proposal)
        log.info("guest game changed %s itself (proposed)", proposal.payload())

    def _send_proposals(self, now: float) -> None:
        if not self._posting:
            self._posting = tuple(self._proposals.popleft()
                                  for _ in range(min(self._proposal_batch, len(self._proposals))))
        first = self.proposed + 1
        receipt = self.client.propose(self.session, self.epoch, self.producer, first, self._posting)
        if receipt.added not in (0, len(self._posting)):
            raise ProtocolError(f"the server added {receipt.added} of this relay's {len(self._posting)} "
                                "proposals; its batch must be new or an exact retry")
        low, high = self._proposal_bounds
        if receipt.first < low or receipt.last < high + receipt.added:
            raise ProtocolError(f"the server's proposal journal went from {low}..{high} to "
                                f"{receipt.first}..{receipt.last} while adding {receipt.added} proposals")
        for number, proposal in enumerate(self._posting, first):
            log.info("guest proposal %d of producer %s acknowledged: %s", number, self.producer, proposal.payload())
        self.proposed += len(self._posting)
        self._posting, self._proposal_bounds = (), (receipt.first, receipt.last)
        self._last_contact = now
