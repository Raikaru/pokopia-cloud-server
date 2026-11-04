#!/usr/bin/env python3
"""Live quest event transport for the EXPERIMENTAL Pokopia 2.0.1 story co-op patch.

The patch (made by _scratch/quest_sync_trace/quest_sync_patch.py) gives the game a mailbox in its bss: a
128-slot journal of quest state changes (cave J) and a 64-slot inbox that the game drains through its own
quest writers (cave D). This module moves those changes between players over /campaign/live on the game
backend, an HTTP/1.1 endpoint behind client certificates:

- HostRelay runs on the PC of the session creator's account. It sends every quest change the host game
  makes itself (journal origin 0), in game order. Each change gets a sequence number, so a resend after a
  lost answer does no harm.
- GuestRelay runs on every other player's PC. It polls the events and queues them, in order, into the
  guest game's inbox. Nothing a guest game does is ever sent, its own replays (origin 1) included.

Deliberately not solved here: unique-quest changes, a guest's initial quest state and durable stage checkpoints. A guest starts
at cursor 0 and replays what the server still holds. Quest changes the host made before its relay attached
were never journaled. The relay stops with ResyncRequired, and nothing performs that resync, when:
- an event lowers a quest state, including a reset to 1 (the patch can only raise states to 2..4);
- the server has discarded history the relay still needs;
- the epoch or the session changes.
If a guest's quest is already at or past an event's target, the patch skips the event without a word, so
diverged saves go unnoticed as well. This transport alone does not make story co-op work.

Who relays what is decided by the authenticated server role, never by the game's session bytes, which
read zero on a live online host. HostRelay requires the role "host" (this account created the session) and
the game showing the patched host capability mask. GuestRelay never writes, so it runs under any member's
role, another device of the creator's account included, but its game must show the patched guest mask.

Anything else unexpected also stops a relay (BridgeError) and turns the game's mailbox off: the process
exits; a patch byte differs; the mailbox was not pristine or loses its contents; the journal overflows; the
game's GameManager or capability mask changes; the server role, session or epoch changes; the server
answers outside the contract. Only network trouble (LiveUnavailable) is retried, and only until
offline_timeout runs out. A game whose relay stopped needs a restart before any relay will attach to it
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
    "6300001428008052880a00b9891640b98a4200914afddf883f010a6be00100542b1500128c02049196596bb8290500118a520091"
    "49fd9f885c000014e103162a79ffff97880e40b908050011880e00b9b5060071c1fdff549f0a00b9e01b40f9e03b40bdf55b42a9"
    "f35341a9fd7bc4a8dac3651769ae00f0290100912a0140b92b6a8a524b28a6725f010b6b610500542a0540b92a050836fd7bbda9"
    "fd030091e00701a9e24f02a9a43b7a97131c0012e00741a9e21340f928040051c73b7a97e00741a9e21340f9421c0012213c0012"
    "5f00136bc0020054480400511f0d007168020054280400511f9d0f710802005469ae00f0290100912a0940b94a010012730e0012"
    "2b40132a6b51022a6b610a2a2c1940b98d1900122e010891cb592db88c0500112e610091ccfd9f88f31740f9fd7bc3a8c0035fd6"
    "28040051a73b7a1769ae00f0290100912a0140b92b6a8a524b28a6725f010b6b610100542a0940b92a010034080040392a1140f9"
    "4a25c89aaa0000362a2940b94a0500112a2900b9c0035fd6080040398246671789f2009129fddf8849f6ff3569d03bd5893200f9"
    "1501805298ffff17c87e1c53082100511f05007169000054e00313aaa0ffff17c92e00122a0500515f1d0371c8030054cb6e1453"
    "2a7b9552ea0da0727600e0364a090011040000146c0500519f110071a8020054c8700090089944f90809098b0c696a38cd4e0c53"
    "9f010d6b2101005400010a8be1030b2ae201805217000094883240b908050011883200b986ffff17883640b908050011883600b9"
    "2d00805206000014883a40b908050011883a00b90c0080124d008052964200b98c4600b9881640b908050051884a00b988f20091"
    "0dfd9f8879ffff17e313bda9e51b01a903423bd5e70f02a90300403901000039211c00127f00016bc008005464ae00f084000091"
    "850040b9266a8a524628a672bf00066be1070054850440b9a5071036c5700090a59844f9050005cb267b9552e60da072a50006cb"
    "bf0040f2a1060054a6fc42d3c70400d1ff1c03f128060054a5040153c620032ac640012ac660052ac66c022a5f3c007161000054"
    "c600073208000014850840b9c500003465d03bd5873040f9bf0007eb41000054c600063285500191a7fcdf8885400191a3fc5f88"
    "6100074b3f0004712202005461040011a1fc028842ffff3585700191a2fc5f88bffc0188c1ffff35c67c022a611c001285001091"
    "a50c018ba60000b961040011a5100091a1fc9f880a0000145f3f03d585600191a1fc5f8821040011a1fc0288a2ffff3521008052"
    "85700191a1fc9f88e70f42a903421bd5e51b41a9e313c3a8c0035fd6e007bea9e27b01a90001098be1030a2a02008052a8ffff97"
    "e27b41a9e007c2a87a267b17e007bea9e27b01a900010a8be103092a220080529fffff97e27b41a9e007c2a8252b7b17e007bea9"
    "e27b01a90001098be1030a2a4200805296ffff97e27b41a9e007c2a8d22b7b17e007bea9e27b01a900010a8be103092a62008052"
    "8dffff97e27b41a9e007c2a8a03a7b17e007bea9e27b01a90001098be1031f2a8200805284ffff97e27b41a9e007c2a892407b17"
    "e007bea9e27b01a90001098be1030a2aa20080527bffff97e27b41a9e007c2a80d417b17e007bea9e27b01a90001098be1030a2a"
    "c200805272ffff97e27b41a9e007c2a804427b17e007bea9e27b01a90001098be1031f2ae200805269ffff97e27b41a9e007c2a8"
    "48427b17e007bea9e27b01a90001098be1030a2a0201805260ffff97e27b41a9e007c2a8ee427b17e007bea9e27b01a90001098b"
    "e1030a2a2201805257ffff97e27b41a9e007c2a808457b17e007bea9e27b01a900010a8be103092a420180524effff97e27b41a9"
    "e007c2a8e3457b17e007bea9e27b01a900010a8be103092a6201805245ffff97e27b41a9e007c2a87b467b17e007bea9e27b01a9"
    "00011c8be103092a820180523cffff97e27b41a9e007c2a8e3487b17e007bea9e27b01a90001098be1030a2aa201805233ffff97"
    "e27b41a9e007c2a8164c7b17"
)
CAVE_CODE_SHA256 = "29321aad73934b4e8d60009f1be3fd66cace56592bcb2faba6f7311f6767fa8c"
CAVE_BYTES = CAVE_CODE + bytes(CAVE_END - CAVE - len(CAVE_CODE))
HOOKS = {
    0x0B1014: bytes.fromhex("1b619a14"),
    0x0B8B68: bytes.fromhex("a5429a94"),
    0x5D865C: bytes.fromhex("28c48514"),
    0x11B214: bytes.fromhex("6db99814"),
    # Unique-quest journal sites; this relay does not enable or relay that journal yet.
    0x613450: bytes.fromhex("7fd98414"),
    0x6149F8: bytes.fromhex("27d48414"),
    0x614720: bytes.fromhex("d4d48414"),
    0x618554: bytes.fromhex("59c58414"),
    0x619D40: bytes.fromhex("67bf8414"),
    0x619F50: bytes.fromhex("ecbe8414"),
    0x61A350: bytes.fromhex("f5bd8414"),
    0x61A484: bytes.fromhex("b1bd8414"),
    0x61A740: bytes.fromhex("0bbd8414"),
    0x61AFCC: bytes.fromhex("f1ba8414"),
    0x61B35C: bytes.fromhex("16ba8414"),
    0x61B5E0: bytes.fromhex("7eb98414"),
    0x61BFA4: bytes.fromhex("16b78414"),
    0x61CC94: bytes.fromhex("e3b38414"),
}
if hashlib.sha256(CAVE_CODE).hexdigest() != CAVE_CODE_SHA256:
    raise ImportError("campaign_bridge: the embedded cave code is corrupt")

MAILBOX, MAILBOX_SIZE = 0x3D18000, 0xC00  # includes the inactive unique-quest journal
MAGIC = 0x31425351  # "QSB1"; the caves stay inert until it is written
MB_MAGIC, MB_FLAGS, MB_APPLYING, MB_APPLIED = 0x00, 0x04, 0x08, 0x0C
MB_IN_W, MB_IN_R, MB_OUT_W = 0x10, 0x14, 0x18
MB_SKIP_MASK, MB_SKIPPED = 0x20, 0x28
MB_INBOX, INBOX_SLOTS = 0x100, 64  # u32 id | target << 16 | op << 24; written here, drained by cave D
MB_JOURNAL, JOURNAL_SLOTS = 0x200, 128  # u32 id | old << 16 | new << 20 | origin << 24; written by cave J
HEADER_SIZE = MB_INBOX
FLAG_DRAIN, FLAG_JOURNAL = 1, 2
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
    """The mailbox was not pristine, lost its contents, was written by someone else, or a ring overflowed."""


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
    id: int
    old: int
    new: int
    origin: int  # 0: the game changed the quest itself, 1: the inbox drain did

    @classmethod
    def decode(cls, word: int) -> JournalEntry:
        return cls(word & 0xFFFF, word >> 16 & 0xF, word >> 20 & 0xF, word >> 24 & 0xFF)


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

    pid: the disposable emulator's process; main: the load address it logs as "Module main loaded at ...".
    The constructor writes nothing. It checks that exactly one host mapping starts at main with the 2.0.1
    main signature, that every patch byte is in place, and that the mailbox is committed read-write memory.
    Reads may go anywhere in the game; writes are refused outside the mailbox. The open handle pins the
    process object, so a reused PID can never be mistaken for the game."""

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
    """The relay's side of the patch mailbox in one game, the same protocol as quest_bridge.Mailbox. The game
    writes in_r, applied, applying, skipped, out_w and the journal; this object writes the rest, and nothing
    else does. check() makes sure the mailbox still holds what was written to it and that the game's indices
    make sense, which catches a game that restarted, memory that was reused, or another writer."""

    def __init__(self, game: Game, *, drain: bool, journal: bool, skip_mask: int = DEFAULT_SKIP_MASK) -> None:
        if type(skip_mask) is not int or not 0 <= skip_mask < 1 << 64:
            raise ValueError(f"bad effect skip mask {skip_mask!r}")
        self.game = game
        self.base = game.main + MAILBOX
        self.flags = (FLAG_DRAIN if drain else 0) | (FLAG_JOURNAL if journal else 0)
        self.skip_mask = skip_mask
        self.attached = False
        self.in_w = self.in_r = self.out_r = 0
        self.applied = self.skipped = 0

    def attach(self) -> None:
        """Arms the caves of a mailbox nobody has used. A mailbox that is not all zero belongs to an earlier
        attachment or to a game that is not fresh, and is refused before anything is written."""
        if self.attached:
            raise RuntimeError("the mailbox is already attached")
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

    def check(self) -> int:
        """Validates the header and returns how many inbox entries the game took since the last check."""
        if not self.attached:
            raise RuntimeError("the mailbox is not attached")
        header = self.game.read(self.base, HEADER_SIZE)
        magic, flags, applying, applied, in_w, in_r, out_w = struct.unpack_from("<7I", header)
        skip_mask, skipped = struct.unpack_from("<QI", header, MB_SKIP_MASK)
        if magic != MAGIC:
            raise MailboxError("the quest mailbox lost its contents (the game restarted or its memory was reset)")
        if (flags != self.flags or skip_mask != self.skip_mask or applying > 1 or in_w != self.in_w
                or header[0x1C:MB_SKIP_MASK] != bytes(4) or header[0x2C:0x60] != bytes(0x34)
                or header[0x68:] != bytes(HEADER_SIZE - 0x68)):
            raise MailboxError("the quest mailbox was changed by someone other than this relay and the game")
        taken = (in_r - self.in_r) & U32
        if taken > (self.in_w - self.in_r) & U32:
            raise MailboxError("the game's inbox read index is past the entries this relay queued")
        if (out_w - self.out_r) & U32 > JOURNAL_SLOTS:
            raise MailboxError(f"the quest journal overflowed: {((out_w - self.out_r) & U32) - JOURNAL_SLOTS} "
                               f"quest changes were lost")
        self.in_r, self.applied, self.skipped = in_r, applied, skipped
        return taken

    def read_journal(self) -> list[JournalEntry]:
        """The journal entries written since the last call, in game order. Raises MailboxError if the
        128-slot ring wrapped past an entry before it was read: those quest changes are lost."""
        start = self.out_r
        end = self._u32(MB_OUT_W)
        count = (end - start) & U32
        if count > JOURNAL_SLOTS:
            raise MailboxError(f"the quest journal overflowed: {count - JOURNAL_SLOTS} quest changes were lost")
        if not count:
            return []
        ring = struct.unpack(f"<{JOURNAL_SLOTS}I", self.game.read(self.base + MB_JOURNAL, 4 * JOURNAL_SLOTS))
        if (self._u32(MB_OUT_W) - start) & U32 > JOURNAL_SLOTS:
            raise MailboxError("the quest journal overflowed while it was read; quest changes were lost")
        self.out_r = end
        return [JournalEntry.decode(ring[(start + i) % JOURNAL_SLOTS]) for i in range(count)]

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


# --- Relays -------------------------------------------------------------------------------------------------

class _Relay:
    _host_side: bool

    def __init__(self, client: LiveClient, game: Game, *, drain: bool, skip_mask: int, offline_timeout: float,
                 retry_delay: float, clock: Callable[[], float]) -> None:
        if not offline_timeout > 0 or not retry_delay >= 0:
            raise ValueError("offline_timeout must be positive and retry_delay non-negative")
        self.client, self.game = client, game
        self.mailbox = Mailbox(game, drain=drain, journal=True, skip_mask=skip_mask)
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
    """Runs on the session creator's PC: sends the host game's own quest changes (journal origin 0), in game
    order, as the seqs after the server's journal end.

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
    guest game made on its own (origin 0). None of them is ever sent."""

    _host_side = False

    def __init__(self, client: LiveClient, game: Game, *, session: str | None = None, epoch: str | None = None,
                 after: int = 0, poll_interval: float = 0.5, skip_mask: int = DEFAULT_SKIP_MASK,
                 offline_timeout: float = 60.0, retry_delay: float = 1.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__(client, game, drain=True, skip_mask=skip_mask, offline_timeout=offline_timeout,
                         retry_delay=retry_delay, clock=clock)
        if type(after) is not int or not 0 <= after <= MAX_SEQ or not poll_interval >= 0:
            raise ValueError("bad cursor or poll interval")
        if (session is None) != (epoch is None) or (after and session is None):
            raise ValueError("a cursor belongs to one session and epoch: pass both with it")
        self._resume = (session, epoch) if session is not None else None
        self._poll_interval = poll_interval
        self.received = self.consumed = after
        self.replayed = self.local_changes = 0
        self._queue: collections.deque[tuple[int, int]] = collections.deque()  # (seq, inbox word) not yet queued
        self._inbox: collections.deque[int] = collections.deque()  # seqs in the inbox, not yet taken
        self._next_poll = 0.0

    def start(self) -> LiveView:
        """Finds the live session (the one to resume, if given). Then arms the drain of a game showing the
        patched guest mask whose mailbox is pristine."""
        view = self._begin()
        if self._resume is not None and (view.session, view.epoch) != self._resume:
            raise SessionChanged(f"the cursor belongs to {self._resume[0]} epoch {self._resume[1]}, the live session "
                                 f"is {view.session} epoch {view.epoch}")
        self._attach(view)
        log.info("guest relay attached to %s epoch %s after seq %d", view.session, view.epoch, self.received)
        return view

    def _step(self) -> None:
        for _ in range(self._check_game()):
            self.consumed = self._inbox.popleft()
        for entry in self.mailbox.read_journal():
            if entry.origin:
                self.replayed += 1
                log.debug("guest replayed quest %d: %d -> %d", entry.id, entry.old, entry.new)
            else:
                self.local_changes += 1
                log.info("guest game changed quest %d itself: %d -> %d (not sent)", entry.id, entry.old, entry.new)
        self._fill()
        now = self._clock()
        if self._queue or now < self._retry_at or now < self._next_poll:
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
