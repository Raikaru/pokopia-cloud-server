"""Durable checkpoints of shared Pokopia 2.0.1 story campaigns, kept apart from personal saves, and
the registry of who may use them.

A campaign is the story progress and the stage terrain that the players of one shared story map
have reached together. CampaignStore keeps its checkpoints on the server's disk; CampaignRegistry
records beside them the account that owns each campaign and the accounts it is shared with, and is
the way in that checks them. Neither has a network API, and nothing in server.py uses them yet.

What a checkpoint holds, and the only representations accepted:
  * The story block of a 2.0.1 common save (CMNDAT.BIN, save version 0x0200017D): the
    STORY_BLOCK_SIZE (0x2365) bytes at STORY_OFFSET (0x220F04) of its decompressed stream. Whether
    this region contains player-identifying data is not fully established. It is stored as given:
    nothing here interprets quest states or assumes they only go up.
  * The unique quest history of the same common save (m_uniqueQuestHistoryVer2): the UNIQUE_SIZE
    (0x400) bytes at UNIQUE_OFFSET (0x427764) of its decompressed stream, 256 records of
    UNIQUE_RECORD (4) bytes. It is the payload that story_checkpoint.py (_scratch/story_state_trace)
    captures as unique_quest_history_ver2.bin, UNIQUE_FORMAT version UNIQUE_PAYLOAD_VERSION (1),
    and it is stored as given, byte for byte: nothing here interprets its records (the meaning of
    byte 3 and the record-to-quest mapping are unknown), and applying it to a save is the
    installer's job (story_checkpoint.merge_unique_history). Whether the game honours replayed
    unique-history bytes is not established. Story block and unique quest history come from one
    common save, so a commit sends both or neither, and every checkpoint has both.
  * Zero or more stage files, by stage number nn (0-99, the nn of STGDATnn.BIN): the bytes of a
    local STGDATnn.BIN exactly as the game writes it (2.4 and 3.4 MB for the STGDAT01 files seen).
    Its 0x124-byte header must carry the save magic, save version 0x0300018B and the compressed
    flag, and name the end of one zlib stream (+0x10) that inflates completely, to at most
    MAX_STAGE_RAW_BYTES (STGDAT01 inflates to 0x83FFDB8, about 138 MB; the check streams it and
    holds 1 MiB at a time).
    Bytes after that end are kept as they are, as the game leaves them. A Cloud Island StageData
    blob (the whole file zlib-compressed again) is refused, and so is a file whose stream does not
    finish, which a save copied while the emulator rewrites it in place can be. The stage ID inside
    the stream is not compared with nn.

Limits (constructor arguments, defaults below): a stage file may have MAX_STAGE_BYTES (16 MiB), a
checkpoint MAX_STAGES (16) stage files and MAX_CHECKPOINT_BYTES (32 MiB) of story block, unique quest
history and stage files together, so any single payload fits the server's 32 MiB request bodies. A
campaign, with the checkpoints it retains, may take DEFAULT_MAX_CAMPAIGN_BYTES (128 MiB; 3 x 32 MiB
with the default retention). A commit that would go past any of them, or leave less than
MIN_FREE_DISK_BYTES free on the disk, fails with PayloadTooLarge or QuotaExceeded before anything is
written; nothing over a limit is ever stored.

Layout under the store's root directory (owner-only on POSIX: directories 0700, files 0600):
  <campaign>/campaign.json                            the registry's metadata: owner and members
  <campaign>/checkpoints/<revision, 20 digits>.json   manifests, written once, never changed
  <campaign>/objects/<sha256>                         payloads by content, written once
  <campaign>/staging/                                 temporary files of an unfinished commit or change
  .locks/<campaign>.lock                              one lock file per campaign ID, kept forever
  .locks/_registry.lock                               the registry's lock for creations and purges
  .deleted/<campaign>                                 one tombstone per deleted campaign, kept forever
  .purged/<SHA-256 of the account ID>                 one marker per purged account, kept forever
  .trash/                                             deleted campaigns until their files are gone

Guarantees, as far as the platform promises them (the same flushes as server.py: fsync or
F_FULLFSYNC, then a rename made durable, MoveFileExW with MOVEFILE_WRITE_THROUGH on Windows):
  * Every call takes the campaign's lock, an OS file lock (flock, or a Windows byte-range lock)
    that other threads and processes respect and that a crashed process releases. One commit or
    read of a campaign runs at a time; another waits up to lock_timeout seconds (CampaignBusy).
    The registry's creations, purge_account while it marks an account, and capture_backup also
    hold .locks/_registry.lock, always taken before any campaign's lock.
  * Lost writes are refused: commit names the etag of the checkpoint it was based on (None for a
    campaign without one) and fails with RevisionConflict unless that is still the newest. The
    etag is the SHA-256 of the manifest, which includes its parent's etag and the commit time, so
    it never repeats, even for a revision number that a power loss took back. Merging is the
    caller's job (for the story block, _scratch/story_state_trace/story_block.py merge3; nothing
    merges two unique quest histories yet).
  * A commit is one rename: payloads are written to staging, flushed and renamed into objects/,
    then the manifest likewise into checkpoints/. Until that rename the previous checkpoint is the
    newest, complete and untouched; a crash leaves only staging files and unreferenced objects,
    which the next commit removes. If the platform cannot promise the payloads are on disk the
    commit fails (DurabilityError) rather than publish a manifest that refers to them.
  * Readback checks everything: the manifest's format version (MANIFEST_FORMAT, 2), structure,
    campaign and revision, the kind and version of each payload, and each payload's size and SHA-256
    (IntegrityError). A manifest of any other format, such as format 1 (story block and stages only,
    from before the unique quest history was kept), or a payload kind or version this module does
    not read, is refused (UnsupportedFormat, an IntegrityError): no unique quest history is ever made
    up for a checkpoint that lacks one. Reads and commits of a campaign whose newest checkpoint is
    refused fail; delete() without if_match removes it. Objects are checked when a commit writes or
    keeps them too.
  * A payload file is never rewritten in place, and is deleted only once no retained manifest
    refers to it and the newer manifest is known to be on disk. An OpenCheckpoint holds every
    payload of one revision open, so it reads the same bytes after a later commit deletes them on
    POSIX; on Windows the deletion fails while they are open and is retried by later commits.
  * A deleted campaign's ID is never used again. delete() first publishes a tombstone
    (.deleted/<campaign>), which is the deletion, then moves the directory into the trash. Every
    call refuses an ID with a tombstone, commit included, so a stale commit cannot create the
    campaign afresh. A crash or failure between the two steps (Windows: files still open) leaves the
    directory, which nothing serves or lists; opening the store, or a later delete, removes it.

The registry (CampaignRegistry) is what a server route calls, with the account its caller
authenticated as (server.py: Principal.account; local mode, which authenticates nobody, must not
use it). Account IDs are opaque here: 1 to MAX_ACCOUNT_BYTES printable ASCII characters without
spaces, compared exactly.
  * create() makes a campaign under an ID the server draws: ID_LENGTH (26) characters of
    ID_ALPHABET from `secrets`, 130 bits, so no caller chooses or guesses one. The creator owns it,
    and may own at most max_owned (DEFAULT_MAX_OWNED) campaigns at a time.
  * The owner shares the campaign with up to max_members (DEFAULT_MAX_MEMBERS) other accounts
    (add_member), takes it back from any of them (remove_member, which a member may also call on
    itself to leave), and deletes it with every checkpoint (delete). Owner and members read and
    commit checkpoints (head, history, open, read, commit; commit records the account as the
    author). Ownership cannot be passed on.
  * Every check is made under the campaign's lock, together with the read or change it allows: a
    call that gets the lock after a member was removed or the campaign deleted is refused, and one
    that got it before finishes first. An account that is neither owner nor member is told
    CampaignNotFound, exactly as for an ID that does not exist or was deleted; a member asking for
    what only the owner may do gets AccessDenied. Revocation does not reach back: an OpenCheckpoint
    opened before it keeps reading.
  * add_member takes the etag of the metadata it was decided on (if_match) and fails with
    MetadataConflict unless that is still current, so a stale or replayed invitation cannot bring
    back a member removed since. remove_member and delete accept if_match but do not need it:
    taking access away never waits. The etag is the SHA-256 of the metadata file, which includes
    its parent's etag and the time, so it never repeats.
  * Metadata is published like a manifest: written to staging, flushed, renamed over
    <campaign>/campaign.json and read back; a failure leaves the previous metadata whole (see
    StorageError.committed). create() makes the directory, then publishes the first metadata; a
    crash in between leaves a directory without metadata, which is not a campaign to the registry,
    and whose ID nobody was given.
  * purge_account() is for accounts an operator deleted (server.py: AuthRegistry.deleted_accounts,
    Backend.purge_account). It first marks the account purged, for good: from then on it has no
    access, no campaign it owns is served to anyone, and none can be created by or shared with it.
    Then it deletes every campaign the account owns, checkpoints and all, and removes it from every
    other one. What it cannot finish now (a campaign busy, damaged, or failing I/O) it reports in
    PurgeResult.unfinished, and calling it again finishes. accounts() names every account that
    still appears in some campaign's metadata.

Not integrated, for the caller to wire up:
  * Routes: no server route calls the registry. Routes must go through CampaignRegistry, never
    CampaignStore, whose methods check no account.
  * Account deletion: server.py's purge_deleted_accounts does not call purge_account; it would,
    for each deleted account that accounts() names, as it calls Backend.purge_account.
  * Backups: server.py's Store.snapshot and SnapshotService capture only state.json and blobs.
    CampaignRegistry.capture_backup() captures the whole registry (see it): every campaign's
    metadata, every retained checkpoint's manifest and payload files, the deleted campaigns'
    tombstones and the purged accounts' markers, as a RegistryBackup of files, each with its path
    under the root, size, SHA-256 and a reader of its pinned contents, and a summary for
    snapshot.json. A snapshot would add them as data/campaigns/<path>, the names snapshot.py
    admits. Restored under an empty root, they form a working store and registry that give each
    account the access it had when the backup was taken. A restored backup also brings back
    checkpoints, campaigns and members changed or removed after it was taken, and an account
    purged since is not purged in it until purge_account is called for it again.
  * Quotas: campaign bytes are not counted by server.py's room_for (--max-storage-mb, the per-account
    128 MiB of blobs, MIN_FREE_DISK_BYTES). usage() gives what a campaign takes; the store applies
    only its own max_campaign_bytes and min_free_bytes, and the registry its max_owned.

The methods block on disk I/O (a commit hashes, inflates and flushes up to 32 MiB); run them off an
event loop (asyncio.to_thread). CampaignStore and CampaignRegistry hold no state of their own
between calls beyond their settings.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import json
import logging
import math
import os
import re
import secrets
import shutil
import stat
import struct
import sys
import threading
import time
import types
import weakref
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping

try:
    import fcntl  # POSIX: flock, and F_FULLFSYNC on macOS
except ImportError:
    fcntl = None
try:
    import msvcrt  # Windows: byte-range locks
except ImportError:
    msvcrt = None

log = logging.getLogger("npln.campaign")

MANIFEST_FORMAT = 2  # format 1 (story block and stages, no unique quest history) is refused
# Container of 2.0.1 saves: magic at +0, save version at +4 (top byte: 2 common, 3 stage), flags at
# +0xA (bit 2: compressed), end of the zlib stream at +0x10.
SAVE_MAGIC = 0x31227687
SAVE_FLAGS_OFFSET = 0x0A
SAVE_COMPRESSED_FLAG = 0x04
SAVE_END_OFFSET = 0x10
COMMON_VERSION = 0x0200017D
STORY_FORMAT = "pokopia-2.0.1-common-story"
STORY_OFFSET = 0x220F04  # in the decompressed stream of the common save
STORY_BLOCK_SIZE = 0x2365
# The unique quest history payload as story_checkpoint.py defines it (m_uniqueQuestHistoryVer2).
UNIQUE_FORMAT = "pokopia-2.0.1-unique-quest-history-ver2"
UNIQUE_PAYLOAD_VERSION = 1
UNIQUE_OFFSET = 0x427764  # in the decompressed stream of the common save
UNIQUE_SIZE = 0x400  # 256 records
UNIQUE_RECORD = 4
STAGE_FORMAT = "pokopia-2.0.1-stgdat"
STAGE_VERSION = 0x0300018B
STAGE_HEADER_SIZE = 0x124
MAX_STAGE_NUMBER = 99

MAX_STAGE_BYTES = 16 * 1024 * 1024
MAX_STAGE_RAW_BYTES = 192 * 1024 * 1024  # STGDAT01 inflates to 0x83FFDB8 (138,411,448) bytes
MAX_STAGES = 16
MAX_CHECKPOINT_BYTES = 32 * 1024 * 1024  # story block, unique quest history and stage files of one checkpoint
DEFAULT_RETAIN = 2  # previous checkpoints kept besides the newest
DEFAULT_MAX_CAMPAIGN_BYTES = 128 * 1024 * 1024  # retained manifests and the payloads they refer to
MIN_FREE_DISK_BYTES = 1024 ** 3  # as server.py: storage stops growing when less is free
LOCK_TIMEOUT_SECONDS = 10.0
MAX_MANIFEST_BYTES = 64 * 1024
MAX_AUTHOR_BYTES = 512

# The registry (CampaignRegistry).
METADATA_FORMAT = 1
METADATA_NAME = "campaign.json"
MAX_METADATA_BYTES = 64 * 1024
METADATA_KEYS = frozenset({"format", "campaign", "revision", "parent", "created", "updated", "owner", "members"})
# The campaign IDs the registry draws: server.py's random_id alphabet, 26 characters (130 bits).
ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
ID_LENGTH = 26
# Account IDs are opaque (portal.py's are "acct-" and 24 base32 characters). Commits record them as
# the checkpoint's author, so they fit MAX_AUTHOR_BYTES.
MAX_ACCOUNT_BYTES = MAX_AUTHOR_BYTES
ACCOUNT_ID = re.compile(rf"[!-~]{{1,{MAX_ACCOUNT_BYTES}}}")  # printable ASCII, no spaces
DEFAULT_MAX_OWNED = 4  # campaigns one account owns at a time, each up to max_campaign_bytes
DEFAULT_MAX_MEMBERS = 16  # accounts one campaign is shared with besides its owner
MAX_MEMBERS_LIMIT = 32  # the most max_members may be, so that metadata stays under MAX_METADATA_BYTES
REGISTRY_LOCK = "_registry"  # .locks/_registry.lock: no campaign ID starts with "_"
# Backups (CampaignRegistry.capture_backup).
BACKUP_FORMAT = 1  # of RegistryBackup.summary
MAX_MARKER_BYTES = 4 * 1024  # a tombstone or purge marker: one small JSON object

# Lower case only, so that two IDs never name one directory on a case-insensitive filesystem.
CAMPAIGN_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
# Names Windows reserves for devices in every directory.
RESERVED_NAMES = frozenset({"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)),
                            *(f"lpt{i}" for i in range(10))})
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
MANIFEST_NAME = re.compile(r"[0-9]{20}\.json")
STAGE_KEY = re.compile(r"[0-9]{2}")
MAX_REVISION = 10 ** 20 - 1
MANIFEST_KEYS = frozenset({"format", "campaign", "revision", "parent", "created", "author", "story",
                           "unique_quest_history", "stages"})
STORY_KEYS = frozenset({"format", "common_version", "offset", "size", "sha256"})
UNIQUE_KEYS = frozenset({"format", "payload_version", "common_version", "offset", "record_size", "size", "sha256"})
STAGE_KEYS = frozenset({"format", "save_version", "size", "raw_size", "sha256"})
READ_CHUNK = 1024 * 1024
INFLATE_INPUT_CHUNK = 64 * 1024
INFLATE_OUTPUT_CHUNK = 1024 * 1024
_O_BINARY = getattr(os, "O_BINARY", 0)
_LOCKED_ERRNOS = frozenset(getattr(errno, name) for name in ("EACCES", "EDEADLK", "EDEADLOCK", "EAGAIN")
                           if hasattr(errno, name))
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)  # no effect on reading a regular file; a FIFO does not block the open
_LINK_ERRNOS = frozenset(getattr(errno, name) for name in ("ELOOP", "EMLINK") if hasattr(errno, name))


# --- Errors ------------------------------------------------------------------------------------


class CampaignError(Exception):
    """Base class of every error this module raises on purpose."""


class InvalidCampaignId(CampaignError, ValueError):
    """The campaign ID is not one this store accepts, or its directory leads out of the store."""


class PayloadError(CampaignError, ValueError):
    """A story block, unique quest history, stage file or other argument of a commit is not in the
    accepted form."""


class PayloadTooLarge(PayloadError):
    """A payload, or the checkpoint it would make, is over a size or count limit. Nothing was stored."""

    def __init__(self, message: str, size: int, limit: int):
        super().__init__(message)
        self.size = size
        self.limit = limit


class QuotaExceeded(CampaignError):
    """The commit would take the campaign over max_campaign_bytes, or the disk under min_free_bytes.
    Nothing was stored."""


class CampaignNotFound(CampaignError, LookupError):
    """No such campaign, retained revision, or stage in a checkpoint. A deleted campaign is no
    campaign; to the registry, neither is one the account is not owner or member of."""


class RevisionConflict(CampaignError):
    """The campaign's newest checkpoint is not the one the call expected. `current` is the newest
    checkpoint (None: there is none). Nothing was changed."""

    def __init__(self, campaign: str, expected: str | None, current: Checkpoint | None):
        have = f"revision {current.revision} ({current.etag})" if current else "no checkpoint"
        super().__init__(f"campaign {campaign}: expected {expected or 'no checkpoint'}, but it has {have}")
        self.current = current


class CampaignBusy(CampaignError):
    """The campaign's lock, or the registry's, was not free within lock_timeout seconds. Nothing was
    changed."""


class IntegrityError(CampaignError):
    """Stored data is damaged: a manifest that does not parse, names another campaign or revision,
    or assigns conflicting sizes to the same payload hash; a payload missing or differing in size
    or SHA-256 from its manifest; or campaign metadata that does not parse or names another campaign."""


class UnsupportedFormat(IntegrityError):
    """A stored checkpoint or campaign metadata has a format or payload kind this module does not
    read."""


class StorageError(CampaignError):
    """The filesystem failed. `committed` tells, for commit, delete and the registry's changes,
    whether the change took effect: False no, True yes, None unknown (read the newest checkpoint, or
    the campaign's metadata, to find out)."""

    def __init__(self, message: str, committed: bool | None = None):
        super().__init__(message)
        self.committed = committed


class DurabilityError(StorageError):
    """The platform did not promise that written data is on disk (a filesystem without directory
    or full syncs). See `committed`."""


class InvalidAccount(CampaignError, ValueError):
    """An account ID is not 1 to MAX_ACCOUNT_BYTES printable ASCII characters without spaces."""


class AccessDenied(CampaignError):
    """The account is a member of the campaign, but only its owner may make this call. Nothing was
    changed."""


class AccountPurged(CampaignError):
    """The account was purged (CampaignRegistry.purge_account): no campaign is created by or shared
    with it any more. Nothing was changed."""


class MetadataConflict(CampaignError):
    """The campaign's metadata is not the one the call expected (if_match); `current` is what it is.
    Nothing was changed."""

    def __init__(self, campaign: str, expected: object, current: CampaignInfo):
        super().__init__(f"campaign {campaign}: expected metadata {expected!r:.80}, but it has revision "
                         f"{current.revision} ({current.etag})")
        self.current = current


# --- Checkpoints -------------------------------------------------------------------------------


@dataclass(frozen=True)
class StoryInfo:
    sha256: str
    size: int


@dataclass(frozen=True)
class UniqueInfo:
    """The unique quest history payload: UNIQUE_FORMAT version UNIQUE_PAYLOAD_VERSION."""

    sha256: str
    size: int


@dataclass(frozen=True)
class StageInfo:
    sha256: str
    size: int  # of the STGDATnn.BIN file
    raw_size: int  # of its inflated stream


@dataclass(frozen=True)
class Checkpoint:
    """One committed revision of a campaign, as its manifest describes it."""

    campaign: str
    revision: int  # 1 for the first checkpoint, then one more for each commit
    etag: str  # SHA-256 of the manifest: the precondition for the next commit
    parent: str | None  # etag of the checkpoint this one replaced
    created: float  # time.time() of the commit
    author: str | None  # what the committing caller recorded, for example an account ID
    story: StoryInfo
    unique: UniqueInfo  # every checkpoint has one; none is made up for a manifest without it
    stages: Mapping[int, StageInfo]  # read-only

    def objects(self) -> dict[str, int]:
        """The size of each payload this checkpoint refers to, by SHA-256."""
        sizes = {self.story.sha256: self.story.size, self.unique.sha256: self.unique.size}
        sizes.update((stage.sha256, stage.size) for stage in self.stages.values())
        return sizes


@dataclass(frozen=True)
class CheckpointData:
    """A checkpoint with its payloads, all checked against the manifest."""

    checkpoint: Checkpoint
    story: bytes
    unique: bytes  # UNIQUE_SIZE bytes, exactly as committed
    stages: Mapping[int, bytes]


@dataclass(frozen=True)
class CapturedObject:
    """A payload file held open by an OpenCheckpoint. `path` is relative to the store's root."""

    path: str
    fd: int
    size: int
    sha256: str


class OpenCheckpoint:
    """One revision of a campaign with every payload file it refers to held open, captured together
    under the campaign's lock. The files are immutable, so reads keep returning the captured bytes
    after the lock is released, even once later commits delete the files (POSIX). Closing releases
    the files; use it as a context manager.

    `manifest_path` and `manifest` are the manifest's path under the root and its exact bytes, and
    `objects` the payload files, each with its path, descriptor, size and SHA-256; verify() checks
    every file's hash. Backups use CampaignRegistry.capture_backup, which captures every retained
    checkpoint with what the registry needs."""

    def __init__(self, checkpoint: Checkpoint, manifest_path: str, manifest: bytes,
                 objects: dict[str, CapturedObject]):
        self.checkpoint = checkpoint
        self.manifest_path = manifest_path
        self.manifest = manifest
        self._objects = objects
        self._lock = threading.Lock()  # lseek and read go together where os.pread is missing
        self._closed = False

    @property
    def objects(self) -> list[CapturedObject]:
        return sorted(self._objects.values(), key=lambda captured: captured.path)

    def read_story(self) -> bytes:
        return self._read(self.checkpoint.story.sha256)

    def read_unique(self) -> bytes:
        return self._read(self.checkpoint.unique.sha256)

    def read_stage(self, number: int) -> bytes:
        stage = self.checkpoint.stages.get(number)
        if stage is None:
            raise CampaignNotFound(f"campaign {self.checkpoint.campaign} revision {self.checkpoint.revision} "
                                   f"has no stage {number!r}")
        return self._read(stage.sha256)

    def read_all(self) -> CheckpointData:
        """Every payload, read and checked against the manifest (IntegrityError)."""
        stages = {number: self.read_stage(number) for number in self.checkpoint.stages}
        return CheckpointData(self.checkpoint, self.read_story(), self.read_unique(), types.MappingProxyType(stages))

    def verify(self) -> None:
        """Checks the SHA-256 of every captured payload file (IntegrityError)."""
        for captured in self.objects:
            self._scan(captured, None)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            for captured in self._objects.values():
                os.close(captured.fd)

    def __enter__(self) -> OpenCheckpoint:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _read(self, sha256: str) -> bytes:
        chunks: list[bytes] = []
        self._scan(self._objects[sha256], chunks)
        return b"".join(chunks)

    def _scan(self, captured: CapturedObject, chunks: list[bytes] | None) -> None:
        if self._closed:
            raise ValueError("the checkpoint is closed")
        digest = hashlib.sha256()
        offset = 0
        with _io(f"campaign {self.checkpoint.campaign}: reading {captured.path}"):
            while offset < captured.size:
                chunk = self._read_at(captured.fd, offset, min(READ_CHUNK, captured.size - offset))
                if not chunk:
                    break
                digest.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
                offset += len(chunk)
        if offset != captured.size or digest.hexdigest() != captured.sha256:
            raise IntegrityError(f"campaign {self.checkpoint.campaign} revision {self.checkpoint.revision}: "
                                 f"{captured.path} does not match its manifest")

    def _read_at(self, fd: int, offset: int, size: int) -> bytes:
        if hasattr(os, "pread"):
            return os.pread(fd, size, offset)
        with self._lock:
            os.lseek(fd, offset, os.SEEK_SET)
            return os.read(fd, size)


# --- Payload checks ----------------------------------------------------------------------------


def check_story_block(block: bytes | bytearray | memoryview) -> bytes:
    """The story block as bytes, if it is one: exactly STORY_BLOCK_SIZE bytes. Its contents are not
    interpreted. Raises PayloadError."""
    view = _byte_view(block, "the story block")
    if view.nbytes != STORY_BLOCK_SIZE:
        raise PayloadError(f"a 2.0.1 story block is {STORY_BLOCK_SIZE:#x} bytes, not {view.nbytes:#x}")
    return view.tobytes() if not isinstance(block, bytes) else block


def check_unique_history(history: bytes | bytearray | memoryview) -> bytes:
    """The unique quest history as bytes, if it is one: exactly UNIQUE_SIZE bytes, the
    m_uniqueQuestHistoryVer2 region of the same common save as the story block (UNIQUE_FORMAT
    version UNIQUE_PAYLOAD_VERSION). Its records are not interpreted. Raises PayloadError."""
    view = _byte_view(history, "the unique quest history")
    if view.nbytes != UNIQUE_SIZE:
        raise PayloadError(f"a {UNIQUE_FORMAT} version {UNIQUE_PAYLOAD_VERSION} unique quest history is "
                           f"{UNIQUE_SIZE:#x} bytes, not {view.nbytes:#x}")
    return view.tobytes() if not isinstance(history, bytes) else history


def check_stage_number(number: int) -> int:
    if type(number) is not int or not 0 <= number <= MAX_STAGE_NUMBER:
        raise PayloadError(f"a stage number is the nn of STGDATnn.BIN, 0 to {MAX_STAGE_NUMBER}, not {number!r}")
    return number


def check_stage_file(data: bytes | bytearray | memoryview, *, max_bytes: int = MAX_STAGE_BYTES,
                     max_raw_bytes: int = MAX_STAGE_RAW_BYTES) -> int:
    """Checks that `data` is a whole local 2.0.1 STGDATnn.BIN (see the module's description) and
    returns the size its stream inflates to. Raises PayloadError, or PayloadTooLarge past a limit."""
    view = _byte_view(data, "a stage file")
    if len(view) > max_bytes:
        raise PayloadTooLarge(f"the stage file has {len(view)} bytes, more than the {max_bytes} allowed",
                              len(view), max_bytes)
    if len(view) < STAGE_HEADER_SIZE:
        raise PayloadError(f"the stage file is shorter than the {STAGE_HEADER_SIZE:#x}-byte header")
    magic, version = struct.unpack_from("<II", view, 0)
    if magic != SAVE_MAGIC:
        hint = (": it looks like a Cloud Island StageData blob, which is the file compressed again; "
                "send the local STGDATnn.BIN") if view[0] == 0x78 else ""
        raise PayloadError(f"not a stage save file (magic {magic:#x}){hint}")
    if version != STAGE_VERSION:
        raise PayloadError(f"not a 2.0.1 stage file (save version {version:#x}, expected {STAGE_VERSION:#x})")
    if not view[SAVE_FLAGS_OFFSET] & SAVE_COMPRESSED_FLAG:
        raise PayloadError("the stage file is not marked compressed")
    end = struct.unpack_from("<i", view, SAVE_END_OFFSET)[0]
    if not STAGE_HEADER_SIZE < end <= len(view):
        raise PayloadError(f"the stage file's stream ends at {end:#x}, outside its {len(view):#x} bytes")
    return _inflated_size(view[STAGE_HEADER_SIZE:end], max_raw_bytes)


def _inflated_size(stream: memoryview, limit: int) -> int:
    """The size `stream` inflates to, if it is exactly one complete zlib stream; it is inflated a
    piece at a time and the output dropped, so memory stays bounded."""
    inflater = zlib.decompressobj()
    size = 0
    offset = 0
    pending: bytes | memoryview = b""
    while True:
        if not pending and offset < len(stream):
            pending = stream[offset:offset + INFLATE_INPUT_CHUNK]
            offset += len(pending)
        try:
            out = inflater.decompress(pending, INFLATE_OUTPUT_CHUNK)
        except zlib.error as exc:
            raise PayloadError(f"the stage file's stream does not inflate: {exc}") from None
        size += len(out)
        if size > limit:
            raise PayloadTooLarge(f"the stage file inflates to more than the {limit} bytes allowed", size, limit)
        pending = inflater.unconsumed_tail
        if inflater.eof:
            break
        if not out and not pending and offset >= len(stream):
            raise PayloadError("the stage file's stream is truncated (a save caught while being written?)")
    if inflater.unused_data or pending or offset < len(stream):
        raise PayloadError("the stage file has data between its stream's end and the end its header records")
    return size


def _byte_view(value: object, what: str) -> memoryview:
    """`value` as a flat view of unsigned bytes, without copying bytes, bytearrays and plain views."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PayloadError(f"{what} must be bytes, not {type(value).__name__}")
    view = memoryview(value)
    return view if view.format == "B" and view.ndim == 1 and view.c_contiguous else memoryview(view.tobytes())


def _check_author(author: str | None) -> str | None:
    if author is not None and not (isinstance(author, str) and len(author.encode("utf-8")) <= MAX_AUTHOR_BYTES):
        raise PayloadError(f"the author must be a string of at most {MAX_AUTHOR_BYTES} UTF-8 bytes")
    return author


# --- Manifests ---------------------------------------------------------------------------------


def _manifest_name(revision: int) -> str:
    return f"{revision:020d}.json"


# What a manifest's unique_quest_history entry records besides "size" and "sha256": the payload's
# kind and version, as story_checkpoint.py captures it. Any other value is refused, not converted.
_UNIQUE_KIND = types.MappingProxyType({"format": UNIQUE_FORMAT, "payload_version": UNIQUE_PAYLOAD_VERSION,
                                       "common_version": COMMON_VERSION, "offset": UNIQUE_OFFSET,
                                       "record_size": UNIQUE_RECORD})
assert set(_UNIQUE_KIND) | {"size", "sha256"} == UNIQUE_KEYS


def _encode_manifest(campaign: str, revision: int, parent: str | None, created: float, author: str | None,
                     story: StoryInfo, unique: UniqueInfo, stages: Mapping[int, StageInfo]) -> bytes:
    doc = {
        "format": MANIFEST_FORMAT,
        "campaign": campaign,
        "revision": revision,
        "parent": parent,
        "created": created,
        "author": author,
        "story": {"format": STORY_FORMAT, "common_version": COMMON_VERSION, "offset": STORY_OFFSET,
                  "size": story.size, "sha256": story.sha256},
        "unique_quest_history": {**_UNIQUE_KIND, "size": unique.size, "sha256": unique.sha256},
        "stages": {f"{number:02d}": {"format": STAGE_FORMAT, "save_version": STAGE_VERSION, "size": stage.size,
                                     "raw_size": stage.raw_size, "sha256": stage.sha256}
                   for number, stage in sorted(stages.items())},
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")


def _parse_manifest(data: bytes, campaign: str, revision: int) -> Checkpoint:
    where = f"campaign {campaign} revision {revision}"
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise IntegrityError(f"{where}: the manifest is not JSON ({exc})") from None
    if not isinstance(doc, dict):
        raise IntegrityError(f"{where}: the manifest is not an object")
    if not _exactly(doc.get("format"), MANIFEST_FORMAT):
        note = " (format 1 has no unique quest history, and none is made up)" if _exactly(doc.get("format"), 1) else ""
        raise UnsupportedFormat(f"{where}: manifest format {doc.get('format')!r}; this module reads "
                                f"{MANIFEST_FORMAT}{note}")
    if set(doc) != MANIFEST_KEYS:
        raise IntegrityError(f"{where}: the manifest has the fields {sorted(doc)}")
    if doc["campaign"] != campaign or type(doc["revision"]) is not int or doc["revision"] != revision:
        raise IntegrityError(f"{where}: the manifest is for campaign {doc['campaign']!r} revision {doc['revision']!r}")
    parent, created, author = doc["parent"], doc["created"], doc["author"]
    if parent is not None and not _is_sha256(parent):
        raise IntegrityError(f"{where}: the manifest's parent is {parent!r}")
    if type(created) not in (int, float) or not math.isfinite(created):
        raise IntegrityError(f"{where}: the manifest's time is {created!r}")
    if author is not None and not (isinstance(author, str) and len(author.encode("utf-8")) <= MAX_AUTHOR_BYTES):
        raise IntegrityError(f"{where}: the manifest's author is not a short string")
    story = _parse_story(doc["story"], where)
    unique = _parse_unique(doc["unique_quest_history"], where)
    if not isinstance(doc["stages"], dict):
        raise IntegrityError(f"{where}: the manifest's stages are not an object")
    stages = {}
    for key, value in doc["stages"].items():
        if not STAGE_KEY.fullmatch(key):
            raise IntegrityError(f"{where}: the manifest names stage {key!r}")
        stages[int(key)] = _parse_stage(value, f"{where} stage {key}")
    sizes: dict[str, int] = {}
    for payload in (story, unique, *stages.values()):
        if sizes.setdefault(payload.sha256, payload.size) != payload.size:
            raise IntegrityError(f"{where}: payload {payload.sha256} has conflicting sizes in the manifest")
    return Checkpoint(campaign, revision, hashlib.sha256(data).hexdigest(), parent, float(created), author,
                      story, unique, types.MappingProxyType(stages))


def _parse_story(value: object, where: str) -> StoryInfo:
    if not isinstance(value, dict) or set(value) != STORY_KEYS:
        raise IntegrityError(f"{where}: the manifest's story entry is malformed")
    if (value["format"], value["common_version"], value["offset"]) != (STORY_FORMAT, COMMON_VERSION, STORY_OFFSET):
        raise UnsupportedFormat(f"{where}: story block {value['format']!r}, save version {value['common_version']!r}, "
                                f"offset {value['offset']!r}; this module reads {STORY_FORMAT}")
    if type(value["size"]) is not int or value["size"] != STORY_BLOCK_SIZE or not _is_sha256(value["sha256"]):
        raise IntegrityError(f"{where}: the manifest's story entry is malformed")
    return StoryInfo(value["sha256"], value["size"])


def _parse_unique(value: object, where: str) -> UniqueInfo:
    if not isinstance(value, dict) or set(value) != UNIQUE_KEYS:
        raise IntegrityError(f"{where}: the manifest's unique quest history entry is malformed")
    if not all(_exactly(value[key], expected) for key, expected in _UNIQUE_KIND.items()):
        raise UnsupportedFormat(f"{where}: unique quest history {value['format']!r} version "
                                f"{value['payload_version']!r}, save version {value['common_version']!r}, offset "
                                f"{value['offset']!r}, record size {value['record_size']!r}; this module reads "
                                f"{UNIQUE_FORMAT} version {UNIQUE_PAYLOAD_VERSION}")
    if not _exactly(value["size"], UNIQUE_SIZE) or not _is_sha256(value["sha256"]):
        raise IntegrityError(f"{where}: the manifest's unique quest history entry is malformed")
    return UniqueInfo(value["sha256"], value["size"])


def _parse_stage(value: object, where: str) -> StageInfo:
    if not isinstance(value, dict) or set(value) != STAGE_KEYS:
        raise IntegrityError(f"{where}: the manifest's entry is malformed")
    if (value["format"], value["save_version"]) != (STAGE_FORMAT, STAGE_VERSION):
        raise UnsupportedFormat(f"{where}: stage file {value['format']!r}, save version {value['save_version']!r}; "
                                f"this module reads {STAGE_FORMAT}")
    size, raw_size = value["size"], value["raw_size"]
    if (type(size) is not int or size <= STAGE_HEADER_SIZE or type(raw_size) is not int or raw_size < 0
            or not _is_sha256(value["sha256"])):
        raise IntegrityError(f"{where}: the manifest's entry is malformed")
    return StageInfo(value["sha256"], size, raw_size)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_HEX.fullmatch(value) is not None


def _exactly(value: object, expected: object) -> bool:
    """Equal and of the same JSON type, so that true is not 1 and 2.0 is not 2."""
    return type(value) is type(expected) and value == expected


# --- Durable files (the same flushes as server.py's sync_fd, sync_directory and publish) --------

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


def _warn_once(key: str, message: str, *args: object) -> None:
    if key not in _sync_warnings:
        _sync_warnings.add(key)
        log.warning(message, *args)


def _sync_fd(fd: int) -> bool:
    """Flushes a file to stable storage and returns whether the platform promises it is there:
    fsync on POSIX, FlushFileBuffers (os.fsync) on Windows, F_FULLFSYNC on macOS. A failed flush is
    raised."""
    if sys.platform == "darwin" and fcntl is not None and hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return True
        except OSError as exc:
            if exc.errno not in UNSUPPORTED_SYNC_ERRNOS:
                raise
            _warn_once("F_FULLFSYNC", "this filesystem has no F_FULLFSYNC (%s); campaign writes are not crash-safe", exc)
        os.fsync(fd)
        return False
    os.fsync(fd)
    return True


def _sync_directory(path: Path) -> bool:
    """Flushes the entries created, renamed or removed in a directory and returns whether that is
    durable (POSIX). Windows cannot open a directory to flush it: there renames are MoveFileExW with
    MOVEFILE_WRITE_THROUGH (_publish, _move_directory), and this returns True."""
    if os.name == "nt":
        return True
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        return _sync_fd(fd)
    except OSError as exc:
        if exc.errno not in UNSUPPORTED_SYNC_ERRNOS:
            raise
        _warn_once(f"directory {path}", "%s cannot be synced (%s); campaign renames there are not crash-safe", path, exc)
        return False
    finally:
        os.close(fd)


def _publish(temp: Path, path: Path) -> bool:
    """Renames `temp` over `path` atomically and returns whether the rename is durable."""
    if os.name == "nt":
        if not _move_file_ex(str(temp), str(path), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH):
            raise ctypes.WinError(ctypes.get_last_error())
        return True
    os.replace(temp, path)
    return _sync_directory(path.parent)


def _move_directory(source: Path, target: Path) -> bool:
    """Renames the directory `source` to `target`, which must not exist, and returns whether the
    rename is durable."""
    if os.name == "nt":
        if not _move_file_ex(str(source), str(target), MOVEFILE_WRITE_THROUGH):
            raise ctypes.WinError(ctypes.get_last_error())
        return True
    os.rename(source, target)
    synced_source = _sync_directory(source.parent)
    return _sync_directory(target.parent) and synced_source


def _make_directory(path: Path) -> None:
    with contextlib.suppress(FileExistsError):
        path.mkdir(mode=0o700)
    if not path.is_dir() or path.is_symlink():
        raise StorageError(f"{path} is not a directory", committed=False)


def _read_bounded(path: Path, limit: int) -> bytes:
    with open(path, "rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise IntegrityError(f"{path.name} is larger than {limit} bytes")
    return data


def _open_regular(path: Path) -> int:
    """A read-only descriptor of the regular file at `path`, which is not followed if it is a link:
    IntegrityError for a link, a directory or any other kind of file, so that nothing outside the
    store, and no FIFO that would block, is read in its place. FileNotFoundError if it is absent."""
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise IntegrityError(f"{path} is not a regular file")
    try:
        fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:  # made a link since the lstat
            raise IntegrityError(f"{path} is not a regular file") from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise IntegrityError(f"{path} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_regular(path: Path, limit: int) -> bytes:
    """The bytes of the regular file at `path` (see _open_regular); IntegrityError if it has more
    than `limit`."""
    fd = _open_regular(path)
    try:
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0 and (chunk := os.read(fd, remaining)):
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > limit:
        raise IntegrityError(f"{path} is larger than {limit} bytes")
    return data


def _close_all(fds: list[int]) -> None:
    """Closes every descriptor in `fds` and empties it."""
    while fds:
        with contextlib.suppress(OSError):
            os.close(fds.pop())


def _file_matches(path: Path, size: int, sha256: str) -> bool:
    """Whether the file at `path` exists with exactly this size and SHA-256."""
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as file:
            if os.fstat(file.fileno()).st_size != size:
                return False
            while chunk := file.read(READ_CHUNK):
                digest.update(chunk)
                total += len(chunk)
    except FileNotFoundError:
        return False
    return total == size and digest.hexdigest() == sha256


def _exists(path: Path) -> bool:
    """Whether `path` exists. Any error other than its absence is raised (os.path.lexists would
    take it for absence), so that a failing tombstone check never lets a call through."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _remove(path: Path, what: str) -> None:
    """Deletes a file nothing needs any more; a failure (Windows: still open) leaves an orphan."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("could not delete %s %s: %s", what, path, exc)


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        log.warning("could not delete all of %s; the rest is deleted later", path)


@contextlib.contextmanager
def _io(what: str, committed: bool | None = None) -> Iterator[None]:
    try:
        yield
    except OSError as exc:
        raise StorageError(f"{what}: {exc}", committed) from exc


def _try_lock(fd: int) -> bool:
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return True
    except OSError as exc:
        if exc.errno in _LOCKED_ERRNOS:
            return False
        raise


def _unlock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@dataclass(frozen=True)
class _Plan:
    """A commit worked out under the lock, before anything is written."""

    campaign: str
    directory: Path
    checkpoint: Checkpoint
    manifest: bytes
    payloads: dict[str, bytes]  # new payloads by SHA-256


@dataclass(frozen=True)
class _Change:
    """A commit's arguments, checked before the lock is taken."""

    expected: str | None
    common: tuple[bytes, bytes] | None  # a new story block and unique quest history, or None to keep both
    updates: dict[int, tuple[bytes, int] | None]  # stage number: (file, inflated size), or None to drop it
    author: str | None


# --- The store ---------------------------------------------------------------------------------


class CampaignStore:
    """Campaign checkpoints under `root`, a directory used for nothing else (for example
    data/campaigns). See the module's description for the guarantees and limits. Its methods check
    no account: what serves accounts goes through CampaignRegistry."""

    def __init__(self, root: Path | str, *, retain: int = DEFAULT_RETAIN, max_stage_bytes: int = MAX_STAGE_BYTES,
                 max_stage_raw_bytes: int = MAX_STAGE_RAW_BYTES, max_stages: int = MAX_STAGES,
                 max_checkpoint_bytes: int = MAX_CHECKPOINT_BYTES,
                 max_campaign_bytes: int = DEFAULT_MAX_CAMPAIGN_BYTES, min_free_bytes: int = MIN_FREE_DISK_BYTES,
                 lock_timeout: float = LOCK_TIMEOUT_SECONDS):
        for name, value in (("retain", retain), ("max_stages", max_stages), ("min_free_bytes", min_free_bytes)):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be an integer of at least 0")
        for name, value in (("max_stage_bytes", max_stage_bytes), ("max_stage_raw_bytes", max_stage_raw_bytes),
                            ("max_checkpoint_bytes", max_checkpoint_bytes), ("max_campaign_bytes", max_campaign_bytes)):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not (isinstance(lock_timeout, (int, float)) and math.isfinite(lock_timeout) and lock_timeout >= 0):
            raise ValueError("lock_timeout must be a number of seconds")
        self.retain = retain
        self.max_stage_bytes = max_stage_bytes
        self.max_stage_raw_bytes = max_stage_raw_bytes
        self.max_stages = max_stages
        self.max_checkpoint_bytes = max_checkpoint_bytes
        self.max_campaign_bytes = max_campaign_bytes
        self.min_free_bytes = min_free_bytes
        self.lock_timeout = float(lock_timeout)
        with _io("opening the campaign store"):
            Path(root).mkdir(mode=0o700, parents=True, exist_ok=True)
            self.root = Path(os.path.realpath(root))
            if os.name == "posix":
                try:
                    self.root.chmod(0o700)  # the campaigns are the players' data: owner-only
                except PermissionError as exc:
                    raise StorageError(f"cannot make {self.root} private ({exc}); it must belong to this user") from None
            self.lock_dir = self.root / ".locks"
            self.trash_dir = self.root / ".trash"
            self.deleted_dir = self.root / ".deleted"
            for directory in (self.lock_dir, self.trash_dir, self.deleted_dir):
                _make_directory(directory)
            self._finish_deletions()
            self._purge_trash()

    # --- Reading ---

    def campaigns(self) -> list[str]:
        """The IDs of the campaigns that have a directory in the store, sorted. Deleted campaigns are
        not listed, even while their directory waits to be moved out."""
        with _io("listing campaigns"):
            return sorted(name for name in os.listdir(self.root)
                          if _valid_id(name) and (self.root / name).is_dir() and not (self.root / name).is_symlink()
                          and not self._gone(name))

    def head(self, campaign: str) -> Checkpoint | None:
        """The newest checkpoint's manifest, checked but without reading its payloads; None if the
        campaign has no checkpoint. Raises IntegrityError if that manifest is damaged."""
        directory = self._directory(campaign)
        with self._locked(campaign), _io(f"campaign {campaign}: reading"):
            return self._head_locked(directory, campaign)

    def history(self, campaign: str) -> list[Checkpoint]:
        """The retained checkpoints' manifests, newest first (empty if there are none)."""
        directory = self._directory(campaign)
        with self._locked(campaign), _io(f"campaign {campaign}: reading"):
            return self._history_locked(directory, campaign)

    def open(self, campaign: str, revision: int | None = None) -> OpenCheckpoint:
        """The newest checkpoint, or a retained `revision`, with its payload files held open (see
        OpenCheckpoint); the caller closes it. Raises CampaignNotFound if there is no such
        checkpoint, IntegrityError if its manifest is damaged or a payload file is missing or has
        the wrong size. Payload hashes are checked when read (read_story, read_unique, read_stage,
        verify)."""
        directory = self._directory(campaign)
        with self._locked(campaign), _io(f"campaign {campaign}: opening"):
            return self._open_locked(directory, campaign, revision)

    def read(self, campaign: str, revision: int | None = None) -> CheckpointData:
        """The newest checkpoint, or a retained `revision`, with every payload read and checked
        against its manifest (IntegrityError). Raises CampaignNotFound if there is none."""
        with self.open(campaign, revision) as opened:
            return opened.read_all()

    def usage(self, campaign: str) -> int:
        """The bytes the campaign takes: its retained manifests and the payloads they refer to,
        each payload once. Orphans of interrupted commits are not counted (server.py does not count
        orphaned blobs either). 0 for a campaign without a directory, or deleted."""
        directory = self._directory(campaign)
        with self._locked(campaign), _io(f"campaign {campaign}: reading"):
            if self._gone(campaign):
                return 0
            return self._footprint(directory, campaign, self._revisions(directory), {})

    # --- Changing ---

    def commit(self, campaign: str, expected: str | None, *, story: bytes | None = None,
               unique: bytes | None = None, stages: Mapping[int, bytes | None] | None = None,
               author: str | None = None) -> Checkpoint:
        """Makes a new checkpoint from the newest one, which must have the etag `expected` (None: the
        campaign must have no checkpoint yet), and returns it.

        `story` and `unique` replace the story block and the unique quest history (UNIQUE_SIZE bytes,
        UNIQUE_FORMAT version UNIQUE_PAYLOAD_VERSION, kept byte for byte). They come from one common
        save, so they go together: the first checkpoint needs both, a later commit sends both or
        neither (None for both keeps both); one without the other is a PayloadError.
        `stages` maps stage numbers to the new STGDATnn.BIN bytes, or to None to drop the stage;
        stages it does not name are kept. A commit that changes nothing returns the newest
        checkpoint as it is, unless a payload it sends is stored damaged: then a new revision with
        the same content rewrites that file. `author` (at most 512 bytes) is recorded in the manifest.

        Nothing is changed when it raises RevisionConflict, PayloadError (PayloadTooLarge),
        QuotaExceeded, CampaignBusy, CampaignNotFound (the campaign was deleted: its ID is never used
        again) or IntegrityError (the newest manifest, or a payload the commit keeps, is damaged;
        UnsupportedFormat if the newest checkpoint has a manifest format or payload version this
        module does not read, such as format 1 without a unique quest history). For StorageError and
        DurabilityError see their `committed`."""
        directory = self._directory(campaign)
        change = self._check_change(expected, story, unique, stages, author)
        with self._locked(campaign):
            return self._commit_locked(directory, campaign, change)

    def delete(self, campaign: str, *, if_match: str | None = None) -> bool:
        """Deletes the campaign with every checkpoint, for good: its ID is never used again. With
        `if_match` only if that is still the newest checkpoint's etag (RevisionConflict). Returns
        whether there was a campaign. Publishing a tombstone (.deleted/<campaign>) is the deletion;
        then the directory is renamed into the trash and removed. What cannot be moved or removed
        yet (Windows: files still open) stays, served by nothing, until a later delete or store
        opening removes it. For StorageError see `committed`."""
        directory = self._directory(campaign)
        with self._locked(campaign):
            deleted = self._delete_locked(directory, campaign, if_match)
        if deleted:
            self._sweep()
        return deleted

    # --- Internals ---

    def _directory(self, campaign: str) -> Path:
        if not isinstance(campaign, str) or not _valid_id(campaign):
            raise InvalidCampaignId(f"campaign IDs are 1-64 of a-z, 0-9, _ and -, starting with a letter or "
                                    f"digit, and not a Windows device name: {campaign!r}")
        directory = self.root / campaign
        if os.path.normcase(os.path.realpath(directory)) != os.path.normcase(str(directory)):
            raise InvalidCampaignId(f"campaign {campaign}: its directory is a link out of the store")
        return directory

    @contextlib.contextmanager
    def _locked(self, campaign: str, timeout: float | None = None) -> Iterator[None]:
        """Holds the campaign's lock, waiting up to `timeout` (default lock_timeout) seconds."""
        with self._hold(f"{campaign}.lock", f"campaign {campaign}", timeout):
            yield

    @contextlib.contextmanager
    def _hold(self, name: str, what: str, timeout: float | None = None) -> Iterator[None]:
        """Holds the lock file .locks/<name>, an OS lock that other threads and processes respect,
        waiting up to `timeout` (default lock_timeout) seconds for it (CampaignBusy)."""
        wait = self.lock_timeout if timeout is None else timeout
        with _io(f"{what}: locking"):
            fd = os.open(self.lock_dir / name, os.O_RDWR | os.O_CREAT | _O_BINARY, 0o600)
        try:
            deadline = time.monotonic() + wait
            delay = 0.002
            while True:
                with _io(f"{what}: locking"):
                    if _try_lock(fd):
                        break
                if time.monotonic() >= deadline:
                    raise CampaignBusy(f"{what} stayed locked for {wait:g} s")
                time.sleep(delay)
                delay = min(delay * 2, 0.05)
            try:
                yield
            finally:
                _unlock(fd)
        finally:
            os.close(fd)

    def _gone(self, campaign: str) -> bool:
        """Whether the campaign was deleted: it has a tombstone."""
        return _exists(self.deleted_dir / campaign)

    def _head_locked(self, directory: Path, campaign: str) -> Checkpoint | None:
        newest = None if self._gone(campaign) else self._newest(directory, campaign)
        return newest[0] if newest else None

    def _history_locked(self, directory: Path, campaign: str) -> list[Checkpoint]:
        if self._gone(campaign):
            return []
        return [self._load(directory, campaign, revision)[0] for revision in reversed(self._revisions(directory))]

    def _open_locked(self, directory: Path, campaign: str, revision: int | None) -> OpenCheckpoint:
        if self._gone(campaign):
            raise CampaignNotFound(f"campaign {campaign} was deleted")
        if revision is None:
            newest = self._newest(directory, campaign)
            if newest is None:
                raise CampaignNotFound(f"campaign {campaign} has no checkpoint")
            checkpoint, manifest = newest
        else:
            if type(revision) is not int or not 1 <= revision <= MAX_REVISION:
                raise CampaignNotFound(f"campaign {campaign} has no revision {revision!r}")
            checkpoint, manifest = self._load(directory, campaign, revision)
        objects: dict[str, CapturedObject] = {}
        try:
            for sha256, size in checkpoint.objects().items():
                try:
                    fd = os.open(directory / "objects" / sha256, os.O_RDONLY | _O_BINARY)
                except FileNotFoundError:
                    raise IntegrityError(f"campaign {campaign} revision {checkpoint.revision}: "
                                         f"payload {sha256} is missing") from None
                objects[sha256] = CapturedObject(f"{campaign}/objects/{sha256}", fd, size, sha256)
                if os.fstat(fd).st_size != size:
                    raise IntegrityError(f"campaign {campaign} revision {checkpoint.revision}: payload "
                                         f"{sha256} has {os.fstat(fd).st_size} bytes, not {size}")
        except BaseException:
            for captured in objects.values():
                os.close(captured.fd)
            raise
        return OpenCheckpoint(checkpoint, f"{campaign}/checkpoints/{_manifest_name(checkpoint.revision)}",
                              manifest, objects)

    def _check_change(self, expected: str | None, story: bytes | None, unique: bytes | None,
                      stages: Mapping[int, bytes | None] | None, author: str | None) -> _Change:
        """A commit's arguments, checked (PayloadError) without the lock: stage files are inflated here."""
        if expected is not None and not isinstance(expected, str):
            raise PayloadError("expected must be an etag string or None")
        author = _check_author(author)
        new_story = None if story is None else check_story_block(story)
        new_unique = None if unique is None else check_unique_history(unique)
        if (new_story is None) != (new_unique is None):
            raise PayloadError("the story block and the unique quest history come from one common save: send both, "
                               "or neither to keep both")
        new_common = None if new_story is None else (new_story, new_unique)
        if stages is not None and not isinstance(stages, Mapping):
            raise PayloadError("stages must map stage numbers to stage files or None")
        updates: dict[int, tuple[bytes, int] | None] = {}
        for number, data in (stages or {}).items():
            check_stage_number(number)
            if data is None:
                updates[number] = None
            else:
                try:
                    raw_size = check_stage_file(data, max_bytes=self.max_stage_bytes,
                                                max_raw_bytes=self.max_stage_raw_bytes)
                except PayloadTooLarge as exc:
                    raise PayloadTooLarge(f"stage {number:02d}: {exc}", exc.size, exc.limit) from None
                except PayloadError as exc:
                    raise PayloadError(f"stage {number:02d}: {exc}") from None
                updates[number] = bytes(data), raw_size  # no copy of bytes, which callers pass
        return _Change(expected, new_common, updates, author)

    def _commit_locked(self, directory: Path, campaign: str, change: _Change) -> Checkpoint:
        with _io(f"campaign {campaign}: commit failed", committed=False):
            if self._gone(campaign):
                raise CampaignNotFound(f"campaign {campaign} was deleted; its ID is not used again")
            plan = self._plan(campaign, directory, change.expected, change.common, change.updates, change.author)
        if isinstance(plan, Checkpoint):
            return plan
        return self._apply(plan)

    def _delete_locked(self, directory: Path, campaign: str, if_match: str | None) -> bool:
        """Publishes the campaign's tombstone, then moves its directory into the trash, which the
        caller empties after releasing the lock (_sweep). Returns whether there was a campaign."""
        with _io(f"campaign {campaign}: delete failed", committed=False):
            if self._gone(campaign) or not os.path.lexists(directory):
                return False
            if if_match is not None:
                newest = self._newest(directory, campaign)
                if (newest[0].etag if newest else None) != if_match:
                    raise RevisionConflict(campaign, if_match, newest[0] if newest else None)
            staging = directory / "staging"
            _make_directory(staging)
            temp = self._stage(staging, json.dumps({"campaign": campaign, "deleted": time.time()},
                                                   sort_keys=True).encode("ascii"))
        with _io(f"campaign {campaign}: delete failed", committed=None):
            durable = _publish(temp, self.deleted_dir / campaign)
        if not durable:
            _warn_once("tombstones", "campaign deletions in %s cannot be made durable here; a power loss may "
                       "undo them", self.deleted_dir)
        self._discard(directory, campaign)
        return True

    def _discard(self, directory: Path, campaign: str) -> None:
        """Moves a deleted campaign's directory into the trash. A failure (Windows: files still open)
        leaves it for _finish_deletions."""
        try:
            _move_directory(directory, self.trash_dir / f"{campaign}.{secrets.token_hex(8)}")
        except OSError as exc:
            log.warning("campaign %s is deleted, but its files stay until later: %s", campaign, exc)

    def _finish_deletions(self) -> None:
        """Moves into the trash the directories that deleted campaigns left in place (a crash or a
        failed move after the tombstone), skipping any whose lock is held. Never raises."""
        try:
            names = [name for name in os.listdir(self.deleted_dir)
                     if _valid_id(name) and os.path.lexists(self.root / name)]
        except OSError as exc:
            log.warning("could not list %s: %s", self.deleted_dir, exc)
            return
        for name in names:
            try:
                with self._locked(name, timeout=0):
                    if os.path.lexists(self.root / name):
                        self._discard(self.root / name, name)
            except (CampaignBusy, StorageError) as exc:
                log.warning("campaign %s is deleted, but its files stay until later: %s", name, exc)

    def _sweep(self) -> None:
        """After a deletion: finishes earlier ones and empties the trash. Never raises."""
        self._finish_deletions()
        try:
            self._purge_trash()
        except OSError as exc:
            log.warning("could not empty %s: %s", self.trash_dir, exc)

    def _revisions(self, directory: Path) -> list[int]:
        """The revisions with a manifest file, oldest first."""
        try:
            names = os.listdir(directory / "checkpoints")
        except FileNotFoundError:
            return []
        return sorted(int(name[:-5]) for name in names if MANIFEST_NAME.fullmatch(name))

    def _load(self, directory: Path, campaign: str, revision: int) -> tuple[Checkpoint, bytes]:
        try:
            data = _read_bounded(directory / "checkpoints" / _manifest_name(revision), MAX_MANIFEST_BYTES)
        except FileNotFoundError:
            raise CampaignNotFound(f"campaign {campaign} has no revision {revision}") from None
        return _parse_manifest(data, campaign, revision), data

    def _newest(self, directory: Path, campaign: str) -> tuple[Checkpoint, bytes] | None:
        revisions = self._revisions(directory)
        return self._load(directory, campaign, revisions[-1]) if revisions else None

    def _footprint(self, directory: Path, campaign: str, revisions: list[int], sizes: dict[str, int]) -> int:
        """The bytes of the manifests of `revisions` and of the payloads they and `sizes` refer to."""
        sizes = dict(sizes)
        total = 0
        for revision in revisions:
            path = directory / "checkpoints" / _manifest_name(revision)
            try:
                total += path.stat().st_size
                sizes.update(self._load(directory, campaign, revision)[0].objects())
            except (FileNotFoundError, CampaignNotFound):
                continue
            except IntegrityError:
                continue  # a damaged manifest counts as its file only
        return total + sum(sizes.values())

    def _plan(self, campaign: str, directory: Path, expected: str | None, new_common: tuple[bytes, bytes] | None,
              updates: dict[int, tuple[bytes, int] | None], author: str | None) -> _Plan | Checkpoint:
        """`new_common` is a new story block and unique quest history, or None to keep both."""
        newest = self._newest(directory, campaign)
        current = newest[0] if newest else None
        if expected != (current.etag if current else None):
            raise RevisionConflict(campaign, expected, current)
        if current is None and new_common is None:
            raise PayloadError(f"campaign {campaign}: the first checkpoint needs a story block and a unique quest "
                               "history")
        payloads: dict[str, bytes] = {}
        if new_common is None:
            story, unique = current.story, current.unique
        else:
            new_story, new_unique = new_common
            story = StoryInfo(hashlib.sha256(new_story).hexdigest(), len(new_story))
            unique = UniqueInfo(hashlib.sha256(new_unique).hexdigest(), len(new_unique))
            payloads[story.sha256] = new_story
            payloads[unique.sha256] = new_unique
        stages = dict(current.stages) if current else {}
        for number, update in sorted(updates.items()):
            if update is None:
                stages.pop(number, None)
                continue
            data, raw_size = update
            stage = StageInfo(hashlib.sha256(data).hexdigest(), len(data), raw_size)
            stages[number] = stage
            payloads[stage.sha256] = data
        if len(stages) > self.max_stages:
            raise PayloadTooLarge(f"campaign {campaign}: a checkpoint may have {self.max_stages} stages, not "
                                  f"{len(stages)}", len(stages), self.max_stages)
        size = story.size + unique.size + sum(stage.size for stage in stages.values())
        if size > self.max_checkpoint_bytes:
            raise PayloadTooLarge(f"campaign {campaign}: the checkpoint would have {size} bytes of story block, "
                                  f"unique quest history and stages, more than the {self.max_checkpoint_bytes} "
                                  "allowed", size, self.max_checkpoint_bytes)
        objects = directory / "objects"
        sizes = {story.sha256: story.size, unique.sha256: unique.size,
                 **{stage.sha256: stage.size for stage in stages.values()}}
        for sha256, object_size in sizes.items():
            if sha256 not in payloads and not _file_matches(objects / sha256, object_size, sha256):
                raise IntegrityError(f"campaign {campaign} revision {current.revision}: payload {sha256}, which "
                                     "the commit keeps, is missing or damaged; send it again")
        # A commit that changes nothing makes no revision, unless it brings a payload whose stored
        # file is damaged: then a new revision rewrites that file (_store_object).
        if (current is not None and story == current.story and unique == current.unique
                and stages == dict(current.stages)
                and all(_file_matches(objects / sha256, len(data), sha256) for sha256, data in payloads.items())):
            return current
        revision = current.revision + 1 if current else 1
        if revision > MAX_REVISION:
            raise StorageError(f"campaign {campaign} has no revision numbers left", committed=False)
        manifest = _encode_manifest(campaign, revision, current.etag if current else None, time.time(), author,
                                    story, unique, stages)
        if len(manifest) > MAX_MANIFEST_BYTES:
            raise PayloadTooLarge(f"campaign {campaign}: the manifest would have {len(manifest)} bytes",
                                  len(manifest), MAX_MANIFEST_BYTES)
        checkpoint = _parse_manifest(manifest, campaign, revision)
        kept = self._revisions(directory)[-self.retain:] if self.retain else []
        footprint = len(manifest) + self._footprint(directory, campaign, kept, sizes)
        if footprint > self.max_campaign_bytes:
            raise QuotaExceeded(f"campaign {campaign} would take {footprint} bytes with its retained checkpoints, "
                                f"more than the {self.max_campaign_bytes} allowed")
        growth = len(manifest) + sum(len(data) for sha256, data in payloads.items() if not (objects / sha256).exists())
        if shutil.disk_usage(self.root).free - growth < self.min_free_bytes:
            raise QuotaExceeded("the disk is nearly full")
        return _Plan(campaign, directory, checkpoint, manifest, payloads)

    def _apply(self, plan: _Plan) -> Checkpoint:
        """Writes the payloads, then publishes the manifest: the commit's one atomic step."""
        campaign, directory = plan.campaign, plan.directory
        staging, objects, checkpoints = directory / "staging", directory / "objects", directory / "checkpoints"
        committed: bool | None = False
        try:
            _make_directory(directory)
            for path in (staging, objects, checkpoints):
                _make_directory(path)
            for name in os.listdir(staging):  # left by an interrupted commit: this one holds the lock
                _remove(staging / name, "staging file")
            if not (_sync_directory(self.root) and _sync_directory(directory)):
                raise DurabilityError(f"campaign {campaign}: its directories cannot be made durable", committed)
            for sha256, data in plan.payloads.items():
                self._store_object(staging, objects / sha256, data, sha256)
            if not _sync_directory(objects):
                raise DurabilityError(f"campaign {campaign}: its payloads cannot be made durable", committed)
            target = checkpoints / _manifest_name(plan.checkpoint.revision)
            if os.path.lexists(target):
                raise IntegrityError(f"campaign {campaign}: {target.name} exists but is not the newest checkpoint")
            temp = self._stage(staging, plan.manifest)
            committed = None
            durable = _publish(temp, target)
            committed = True
            if not durable:
                raise DurabilityError(f"campaign {campaign}: revision {plan.checkpoint.revision} is committed, but "
                                      "the platform did not promise it is on disk", committed)
            if _read_bounded(target, MAX_MANIFEST_BYTES) != plan.manifest:
                raise StorageError(f"campaign {campaign}: revision {plan.checkpoint.revision} is committed, but its "
                                   "manifest reads back differently", committed)
        except OSError as exc:
            raise StorageError(f"campaign {campaign}: commit failed: {exc}", committed) from exc
        self._collect(directory, campaign)
        return plan.checkpoint

    def _stage(self, staging: Path, data: bytes) -> Path:
        """A new file in `staging` holding `data`, flushed to disk (DurabilityError if the platform does
        not promise that)."""
        temp = staging / f"{secrets.token_hex(16)}.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            synced = _sync_fd(file.fileno())
        if not synced:
            raise DurabilityError(f"{temp} cannot be flushed to disk here", committed=False)
        return temp

    def _store_object(self, staging: Path, path: Path, data: bytes, sha256: str) -> None:
        """Makes `path` a durable payload file holding `data`. A file already there with that content
        (from an earlier commit, or one interrupted before its manifest) is flushed and kept; a
        damaged one is replaced by a rename, never rewritten in place."""
        if _file_matches(path, len(data), sha256):
            # Windows flushes only handles open for writing; POSIX flushes any.
            fd = os.open(path, (os.O_RDWR if os.name == "nt" else os.O_RDONLY) | _O_BINARY)
            try:
                if not _sync_fd(fd):
                    raise DurabilityError(f"{path} cannot be flushed to disk here", committed=False)
            finally:
                os.close(fd)
            return
        if os.path.lexists(path):
            log.warning("campaign payload %s is damaged; writing it again", path)
        if not _publish(self._stage(staging, data), path):
            raise DurabilityError(f"{path} cannot be made durable here", committed=False)
        if not _file_matches(path, len(data), sha256):
            raise IntegrityError(f"{path} reads back differently from what was written")

    def _collect(self, directory: Path, campaign: str) -> None:
        """After a durable commit: deletes the manifests past the retention, then the payload files no
        remaining manifest refers to. Never raises; what it cannot delete is left for a later commit."""
        try:
            checkpoints = directory / "checkpoints"
            revisions = self._revisions(directory)
            for revision in revisions[:-(self.retain + 1)]:
                _remove(checkpoints / _manifest_name(revision), "old campaign checkpoint")
            # Payloads go only once their manifests are gone for good, so a power loss cannot bring
            # back a manifest whose payloads were deleted.
            if not _sync_directory(checkpoints):
                return
            referenced: set[str] = set()
            for revision in self._revisions(directory):
                try:
                    referenced.update(self._load(directory, campaign, revision)[0].objects())
                except (IntegrityError, CampaignNotFound) as exc:
                    log.warning("campaign %s: keeping every payload file: revision %d is unreadable (%s)",
                                campaign, revision, exc)
                    return
            for name in os.listdir(directory / "objects"):
                if SHA256_HEX.fullmatch(name) and name not in referenced:
                    _remove(directory / "objects" / name, "unreferenced campaign payload")
        except OSError as exc:
            log.warning("campaign %s: could not delete old checkpoints and payloads: %s", campaign, exc)

    def _purge_trash(self) -> None:
        """Removes deleted campaigns, once their move into the trash is known to be durable."""
        if not (_sync_directory(self.root) and _sync_directory(self.trash_dir)):
            _warn_once("keep trash", "keeping deleted campaigns in %s: the deletion cannot be made durable here",
                       self.trash_dir)
            return
        for name in os.listdir(self.trash_dir):
            _remove_tree(self.trash_dir / name)


def _valid_id(name: str) -> bool:
    return CAMPAIGN_ID.fullmatch(name) is not None and name not in RESERVED_NAMES


# --- The registry ------------------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignInfo:
    """A campaign's metadata: who owns it and who it is shared with."""

    campaign: str
    revision: int  # 1 when created, then one more for each change
    etag: str  # SHA-256 of the metadata file: the if_match of the next change
    parent: str | None  # etag of the metadata this one replaced
    created: float  # time.time() of the creation
    updated: float  # time.time() of the latest change
    owner: str  # the account that created the campaign
    members: tuple[str, ...]  # the other accounts it is shared with, sorted

    def role(self, account: str) -> str | None:
        """The account's role: "owner", "member", or None if this metadata gives it no access."""
        if account == self.owner:
            return "owner"
        return "member" if account in self.members else None


@dataclass(frozen=True)
class PurgeResult:
    """What purge_account did. Calling it again finishes what is unfinished."""

    deleted: tuple[str, ...]  # campaigns the account owned, deleted with their checkpoints
    left: tuple[str, ...]  # campaigns the account was removed from
    unfinished: tuple[str, ...]  # campaigns that could not be read or changed now (busy, damaged, I/O)


class BackupFile:
    """One file of a RegistryBackup, to restore at `path` (relative to the store's root, "/" between
    names) under an empty root: `size` bytes that hash to `sha256`. Its contents were captured with
    the backup and do not change: a payload file is held open, any other file in memory."""

    __slots__ = ("path", "size", "sha256", "_backup", "_data", "_fd", "_digest", "_offset")

    def __init__(self, backup: RegistryBackup, path: str, size: int, sha256: str, data: bytes | None,
                 fd: int | None):
        self.path = path
        self.size = size
        self.sha256 = sha256
        self._backup = backup
        self._data = data  # the contents, or None for a payload file read through `_fd`
        self._fd = fd
        self._digest = None  # SHA-256 of what was read in order from offset 0 so far
        self._offset = 0  # where that reading has got to

    def read(self, offset: int, size: int) -> bytes:
        """Up to `size` bytes from `offset`, fewer only at the end. Read the file in order from offset
        0, as a stream does: each read starts where the one before it ended, or at 0 again (anything
        else is a ValueError). The read that reaches the end raises IntegrityError instead of
        returning if the file does not have `size` bytes that hash to `sha256`, so a damaged payload
        never ends a stream complete; after an IntegrityError or StorageError, it is read from 0
        again. ValueError once the backup is closed."""
        return self._backup._read(self, offset, size)

    def __repr__(self) -> str:
        return f"BackupFile({self.path!r}, size={self.size}, sha256={self.sha256!r})"


class RegistryBackup:
    """What CampaignRegistry.capture_backup captured: `files`, the BackupFiles sorted by path, and
    `summary`, its manifest metadata for snapshot.json, a JSON object that names no account:
    "format" (BACKUP_FORMAT), "created" (time.time() of the capture), "campaigns" (by campaign ID:
    "metadata", {"revision", "etag"} of its metadata or None for a campaign the registry did not
    create, and "checkpoints", [{"revision", "etag"}] of its retained checkpoints, oldest first),
    "deleted" and "purged" (how many tombstones and purge markers), "files" and "bytes".

    Its payload files stay open until close(); use it as a context manager. Closing waits for a read
    in progress, reads after it raise ValueError, and a backup dropped unclosed is closed when it is
    garbage-collected. While it is open on Windows, the payload files it holds cannot be deleted,
    and later commits and deletions leave them for later, as with OpenCheckpoint."""

    def __init__(self, created: float):
        self.created = created
        self.files: tuple[BackupFile, ...] = ()
        self.summary: dict[str, object] = {}
        self._entries: list[BackupFile] = []
        self._fds: list[int] = []
        # One read or close at a time, so that no descriptor is read once closed (and maybe reused),
        # and lseek and read go together where os.pread is missing.
        self._lock = threading.Lock()
        self._closed = False
        self._finalizer = weakref.finalize(self, _close_all, self._fds)

    def close(self) -> None:
        """Releases every payload file. Calling it again does nothing."""
        with self._lock:
            self._closed = True
            self._finalizer()

    def __enter__(self) -> RegistryBackup:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _pin(self, fd: int) -> int:
        """Takes `fd`, which closing the backup closes."""
        self._fds.append(fd)
        return fd

    def _add(self, path: str, size: int, sha256: str, *, data: bytes | None = None, fd: int | None = None) -> None:
        self._entries.append(BackupFile(self, path, size, sha256, data, fd))

    def _seal(self, campaigns: dict[str, dict[str, object]], deleted: int, purged: int) -> None:
        self.files = tuple(sorted(self._entries, key=lambda file: file.path))
        self.summary = {"format": BACKUP_FORMAT, "created": self.created, "campaigns": campaigns,
                        "deleted": deleted, "purged": purged, "files": len(self.files),
                        "bytes": sum(file.size for file in self.files)}

    def _read(self, file: BackupFile, offset: int, size: int) -> bytes:
        if type(offset) is not int or type(size) is not int or offset < 0 or size < 0:
            raise ValueError("offset and size must be integers of at least 0")
        with self._lock:
            if self._closed:
                raise ValueError("the backup is closed")
            if offset == 0:
                file._digest, file._offset = hashlib.sha256(), 0
            elif file._digest is None or offset != file._offset:
                raise ValueError(f"{file.path} is read in order from offset 0, not from {offset}")
            count = min(size, file.size - offset)
            if count == 0:
                return b""
            try:
                chunk = file._data[offset:offset + count] if file._data is not None else self._read_at(file, offset, count)
                file._digest.update(chunk)
                file._offset += count
                if file._offset == file.size and file._digest.hexdigest() != file.sha256:
                    raise IntegrityError(f"{file.path} does not match its SHA-256 {file.sha256}: it is damaged")
            except BaseException:
                file._digest = None
                raise
            return chunk

    @staticmethod
    def _read_at(file: BackupFile, offset: int, count: int) -> bytes:
        """`count` bytes of a payload file from `offset`, under the backup's lock."""
        chunks: list[bytes] = []
        with _io(f"reading {file.path} for a backup"):
            while count:
                if hasattr(os, "pread"):
                    chunk = os.pread(file._fd, count, offset)
                else:
                    os.lseek(file._fd, offset, os.SEEK_SET)
                    chunk = os.read(file._fd, count)
                if not chunk:
                    raise IntegrityError(f"{file.path} ends before its {file.size} bytes: it is damaged")
                chunks.append(chunk)
                offset += len(chunk)
                count -= len(chunk)
        return b"".join(chunks)


def _new_campaign_id() -> str:
    return "".join(secrets.choice(ID_ALPHABET) for _ in range(ID_LENGTH))


def _is_account(value: object) -> bool:
    return isinstance(value, str) and ACCOUNT_ID.fullmatch(value) is not None


def _check_account(account: object, what: str = "account") -> str:
    if not _is_account(account):
        raise InvalidAccount(f"{what} IDs are 1 to {MAX_ACCOUNT_BYTES} printable ASCII characters without spaces")
    return account


def _account_key(account: str) -> str:
    """The name of an account's purge marker: its ID's SHA-256, so that no account ID is kept there."""
    return hashlib.sha256(account.encode("ascii")).hexdigest()


def _encode_metadata(campaign: str, revision: int, parent: str | None, created: float, updated: float,
                     owner: str, members: list[str]) -> bytes:
    doc = {"format": METADATA_FORMAT, "campaign": campaign, "revision": revision, "parent": parent,
           "created": created, "updated": updated, "owner": owner, "members": sorted(members)}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")


def _parse_metadata(data: bytes, campaign: str) -> CampaignInfo:
    where = f"campaign {campaign} metadata"
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise IntegrityError(f"{where}: not JSON ({exc})") from None
    if not isinstance(doc, dict):
        raise IntegrityError(f"{where}: not an object")
    if not _exactly(doc.get("format"), METADATA_FORMAT):
        raise UnsupportedFormat(f"{where}: format {doc.get('format')!r}; this module reads {METADATA_FORMAT}")
    if set(doc) != METADATA_KEYS:
        raise IntegrityError(f"{where}: it has the fields {sorted(doc)}")
    revision, parent, created, updated = doc["revision"], doc["parent"], doc["created"], doc["updated"]
    owner, members = doc["owner"], doc["members"]
    if doc["campaign"] != campaign:
        raise IntegrityError(f"{where}: it is for campaign {doc['campaign']!r}")
    if type(revision) is not int or not 1 <= revision <= MAX_REVISION:
        raise IntegrityError(f"{where}: revision {revision!r}")
    if (parent is None) != (revision == 1) or (parent is not None and not _is_sha256(parent)):
        raise IntegrityError(f"{where}: parent {parent!r} at revision {revision}")
    if not all(type(moment) in (int, float) and math.isfinite(moment) for moment in (created, updated)):
        raise IntegrityError(f"{where}: times {created!r} and {updated!r}")
    if not _is_account(owner):
        raise IntegrityError(f"{where}: the owner is not an account ID")
    if (not isinstance(members, list) or not all(_is_account(member) for member in members)
            or members != sorted(set(members)) or owner in members):
        raise IntegrityError(f"{where}: the members are not distinct account IDs, sorted, without the owner")
    return CampaignInfo(campaign, revision, hashlib.sha256(data).hexdigest(), parent, float(created),
                        float(updated), owner, tuple(members))


class CampaignRegistry:
    """Who owns and may use each campaign of `store`, and the calls that check it. Every method takes
    the account the caller authenticated as; see the module's description for the rules."""

    def __init__(self, store: CampaignStore, *, max_owned: int = DEFAULT_MAX_OWNED,
                 max_members: int = DEFAULT_MAX_MEMBERS):
        if type(max_owned) is not int or max_owned < 1:
            raise ValueError("max_owned must be a positive integer")
        if type(max_members) is not int or not 0 <= max_members <= MAX_MEMBERS_LIMIT:
            raise ValueError(f"max_members must be an integer from 0 to {MAX_MEMBERS_LIMIT}")
        self.store = store
        self.max_owned = max_owned
        self.max_members = max_members
        self.purged_dir = store.root / ".purged"
        with _io("opening the campaign registry"):
            _make_directory(self.purged_dir)

    # --- Reading ---

    def get(self, campaign: str, account: str) -> CampaignInfo:
        """The campaign's metadata, for its owner or a member. Anyone else is told CampaignNotFound,
        as for a campaign that does not exist or was deleted."""
        account = _check_account(account)
        directory = self.store._directory(campaign)
        with self.store._locked(campaign), _io(f"campaign {campaign}: reading"):
            return self._authorize(directory, campaign, account)

    def campaigns_of(self, account: str) -> list[CampaignInfo]:
        """The campaigns the account owns or is a member of, by ID."""
        account = _check_account(account)
        with _io("listing campaigns"):
            if self._purged(account):
                return []
            return [info for info in self._all() if info.role(account) is not None and not self._purged(info.owner)]

    def accounts(self) -> set[str]:
        """Every account that owns or is a member of a campaign, purged ones included until
        purge_account has finished with them: for finding deleted accounts that still have campaigns."""
        found: set[str] = set()
        for info in self._all():
            found.add(info.owner)
            found.update(info.members)
        return found

    def purged(self, account: str) -> bool:
        """Whether purge_account was called for the account."""
        account = _check_account(account)
        with _io("reading the purged accounts"):
            return self._purged(account)

    def head(self, campaign: str, account: str) -> Checkpoint | None:
        """CampaignStore.head, for the campaign's owner or a member (CampaignNotFound for anyone else)."""
        account = _check_account(account)
        directory = self.store._directory(campaign)
        with self.store._locked(campaign), _io(f"campaign {campaign}: reading"):
            self._authorize(directory, campaign, account)
            return self.store._head_locked(directory, campaign)

    def history(self, campaign: str, account: str) -> list[Checkpoint]:
        """CampaignStore.history, for the campaign's owner or a member (CampaignNotFound for anyone else)."""
        account = _check_account(account)
        directory = self.store._directory(campaign)
        with self.store._locked(campaign), _io(f"campaign {campaign}: reading"):
            self._authorize(directory, campaign, account)
            return self.store._history_locked(directory, campaign)

    def open(self, campaign: str, account: str, revision: int | None = None) -> OpenCheckpoint:
        """CampaignStore.open, for the campaign's owner or a member (CampaignNotFound for anyone else).
        The OpenCheckpoint keeps reading after the account loses access."""
        account = _check_account(account)
        directory = self.store._directory(campaign)
        with self.store._locked(campaign), _io(f"campaign {campaign}: opening"):
            self._authorize(directory, campaign, account)
            return self.store._open_locked(directory, campaign, revision)

    def read(self, campaign: str, account: str, revision: int | None = None) -> CheckpointData:
        """CampaignStore.read, for the campaign's owner or a member (CampaignNotFound for anyone else)."""
        with self.open(campaign, account, revision) as opened:
            return opened.read_all()

    def capture_backup(self) -> RegistryBackup:
        """The whole registry, captured for a backup snapshot: every campaign's metadata (its owner
        and members) and every retained checkpoint, manifests and payload files, with the deleted
        campaigns' tombstones and the purged accounts' markers. Restored under an empty root, the
        files form a working store and registry that give each account the access it had, and no
        more. The caller closes the RegistryBackup (see it). Nothing is written.

        It holds the registry's lock throughout, so that no campaign is created and no account is
        marked purged meanwhile, and each campaign's lock while it captures that campaign, so that
        the campaign's metadata and checkpoints come from one moment. Campaigns are captured one
        after another, and the tombstones last, so that a campaign deleted while the capture runs is
        restored deleted. Metadata, manifests and markers are read into memory and checked as reads
        check them; payload files are held open, not read: BackupFile.read checks each as it is
        streamed. Creations and purges wait for the capture, up to lock_timeout seconds.

        Damage is refused, never skipped, so nothing is left out: IntegrityError (UnsupportedFormat)
        if a campaign's metadata, a retained manifest or a marker is damaged, or a payload file is
        missing, has another size than its manifests record, or is not a regular file;
        InvalidCampaignId if a campaign's directory is a link out of the store; CampaignBusy if the
        registry or a campaign stays locked for lock_timeout seconds; StorageError if the filesystem
        fails. Then nothing is left open. A directory with neither metadata nor checkpoint (an
        interrupted creation) has nothing to capture; staging files, payloads no manifest refers to,
        the locks and the trash are never captured."""
        backup = RegistryBackup(time.time())
        try:
            with self.store._hold(f"{REGISTRY_LOCK}.lock", "the campaign registry"):
                with _io("backing up the purged accounts"):
                    purged = self._capture_markers(backup, self.purged_dir, SHA256_HEX.fullmatch)
                campaigns: dict[str, dict[str, object]] = {}
                for campaign in self.store.campaigns():
                    directory = self.store._directory(campaign)
                    with self.store._locked(campaign), _io(f"campaign {campaign}: backing up"):
                        captured = self._capture_campaign(backup, directory, campaign)
                    if captured is not None:
                        campaigns[campaign] = captured
                with _io("backing up the deleted campaigns"):
                    deleted = self._capture_markers(backup, self.store.deleted_dir, _valid_id)
            backup._seal(campaigns, deleted, purged)
        except BaseException:
            backup.close()
            raise
        log.info("campaign backup captured: %d campaigns, %d deleted, %d purged accounts, %d files, %d bytes",
                 len(campaigns), deleted, purged, len(backup.files), backup.summary["bytes"])
        return backup

    # --- Changing ---

    def create(self, account: str) -> CampaignInfo:
        """A new campaign owned by the account, under an ID the server draws, without a checkpoint.
        Raises AccountPurged, or QuotaExceeded if the account owns max_owned campaigns already. For
        StorageError see `committed`: after False nothing is left, after None or True the campaign
        may exist, and campaigns_of() shows it."""
        account = _check_account(account)
        with self.store._hold(f"{REGISTRY_LOCK}.lock", "the campaign registry"):
            with _io("creating a campaign failed", committed=False):
                if self._purged(account):
                    raise AccountPurged(f"account {account} was purged")
            owned = sum(1 for info in self._all() if info.owner == account)
            if owned >= self.max_owned:
                raise QuotaExceeded(f"account {account} owns {owned} campaigns, the most it may")
            for _ in range(8):  # 130-bit IDs: a second draw is already never needed
                campaign = _new_campaign_id()
                directory = self.store.root / campaign
                with self.store._locked(campaign):
                    with _io("creating a campaign failed", committed=False):
                        if self.store._gone(campaign) or os.path.lexists(directory):
                            continue
                    info = self._create_locked(directory, campaign, account)
                log.info("campaign %s: created by account %s", campaign, account)
                return info
        raise StorageError("creating a campaign failed: every ID drawn was taken", committed=False)

    def add_member(self, campaign: str, account: str, member: str, *, if_match: str) -> CampaignInfo:
        """Shares the campaign with `member`. Only its owner may (AccessDenied), and only while
        `if_match` is the metadata's etag (MetadataConflict), so a stale or replayed call cannot undo
        a removal made since. Returns the new metadata, or the current one if `member` is the owner
        or a member already. Raises AccountPurged if `member` was purged, QuotaExceeded if the
        campaign has max_members members. For StorageError see `committed`."""
        account = _check_account(account)
        member = _check_account(member, "member")
        directory = self.store._directory(campaign)
        with self.store._locked(campaign):
            with _io(f"campaign {campaign}: adding a member failed", committed=False):
                info = self._authorize(directory, campaign, account, owner=True)
                if info.etag != if_match:
                    raise MetadataConflict(campaign, if_match, info)
                if info.role(member) is not None:
                    return info
                if self._purged(member):
                    raise AccountPurged(f"account {member} was purged")
                if len(info.members) >= self.max_members:
                    raise QuotaExceeded(f"campaign {campaign} is shared with {len(info.members)} accounts, the most "
                                        "it may be")
            info = self._change(directory, campaign, info, [*info.members, member])
        log.info("campaign %s: account %s added member %s", campaign, account, member)
        return info

    def remove_member(self, campaign: str, account: str, member: str, *, if_match: str | None = None) -> CampaignInfo:
        """Takes the campaign back from `member`: its owner may remove any member, a member only
        itself (AccessDenied), and the owner cannot leave (AccessDenied; delete the campaign
        instead). Once it returns, every call of `member` is refused. With `if_match` only while
        that is the metadata's etag (MetadataConflict). Returns the new metadata, or the current one
        if `member` is not a member. For StorageError see `committed`."""
        account = _check_account(account)
        member = _check_account(member, "member")
        directory = self.store._directory(campaign)
        with self.store._locked(campaign):
            with _io(f"campaign {campaign}: removing a member failed", committed=False):
                info = self._authorize(directory, campaign, account)
                if account != info.owner and member != account:
                    raise AccessDenied(f"campaign {campaign}: only its owner may remove another member")
                if member == info.owner:
                    raise AccessDenied(f"campaign {campaign}: its owner cannot leave it, only delete it")
                if if_match is not None and info.etag != if_match:
                    raise MetadataConflict(campaign, if_match, info)
                if member not in info.members:
                    return info
            info = self._change(directory, campaign, info, [name for name in info.members if name != member])
        log.info("campaign %s: account %s removed member %s", campaign, account, member)
        return info

    def delete(self, campaign: str, account: str, *, if_match: str | None = None) -> None:
        """Deletes the campaign with every checkpoint, for good (CampaignStore.delete): its ID is
        never used again. Only its owner may (AccessDenied); with `if_match` only while that is the
        metadata's etag (MetadataConflict). For StorageError see `committed`."""
        account = _check_account(account)
        directory = self.store._directory(campaign)
        with self.store._locked(campaign):
            with _io(f"campaign {campaign}: delete failed", committed=False):
                info = self._authorize(directory, campaign, account, owner=True)
                if if_match is not None and info.etag != if_match:
                    raise MetadataConflict(campaign, if_match, info)
            self.store._delete_locked(directory, campaign, None)
        self.store._sweep()
        log.info("campaign %s: deleted by its owner %s", campaign, account)

    def commit(self, campaign: str, account: str, expected: str | None, *, story: bytes | None = None,
               unique: bytes | None = None, stages: Mapping[int, bytes | None] | None = None) -> Checkpoint:
        """CampaignStore.commit, for the campaign's owner or a member (CampaignNotFound for anyone
        else), recording the account as the checkpoint's author. Access is checked before the
        payloads are, so that nothing is inflated for an account without it, and again under the
        lock that the commit holds, so that a removal or deletion made in between is respected."""
        account = _check_account(account)
        directory = self.store._directory(campaign)
        with self.store._locked(campaign), _io(f"campaign {campaign}: commit failed", committed=False):
            self._authorize(directory, campaign, account)
        change = self.store._check_change(expected, story, unique, stages, account)
        with self.store._locked(campaign):
            with _io(f"campaign {campaign}: commit failed", committed=False):
                self._authorize(directory, campaign, account)
            return self.store._commit_locked(directory, campaign, change)

    def purge_account(self, account: str) -> PurgeResult:
        """Removes an account an operator deleted from every campaign, for good. It first marks the
        account purged (.purged/), which takes effect at once: the account has no access any more,
        no campaign it owns is served to anyone, and none is created by or shared with it again.
        Then it deletes every campaign the account owns, checkpoints and all, and removes it from
        the members of the others. Campaigns it could not finish are in `unfinished`; calling it
        again finishes them. Raises (StorageError, CampaignBusy) only if the account could not be
        marked, or the campaigns not listed."""
        account = _check_account(account)
        with self.store._hold(f"{REGISTRY_LOCK}.lock", "the campaign registry"):
            self._mark_purged(account)
        deleted: list[str] = []
        left: list[str] = []
        unfinished: list[str] = []
        for campaign in self.store.campaigns():
            try:
                directory = self.store._directory(campaign)
                with self.store._locked(campaign):
                    with _io(f"campaign {campaign}: purging account {account} failed", committed=False):
                        info = self._metadata(directory, campaign)
                    if info is None:
                        continue
                    if info.owner == account:
                        self.store._delete_locked(directory, campaign, None)
                        deleted.append(campaign)
                    elif account in info.members:
                        self._change(directory, campaign, info, [name for name in info.members if name != account])
                        left.append(campaign)
            except (CampaignBusy, IntegrityError, StorageError, InvalidCampaignId) as exc:
                log.warning("campaign %s: account %s is purged, but not from it yet: %s", campaign, account, exc)
                unfinished.append(campaign)
        if deleted:
            self.store._sweep()
        log.info("purged account %s from the campaigns: %d deleted, %d left, %d unfinished", account,
                 len(deleted), len(left), len(unfinished))
        return PurgeResult(tuple(deleted), tuple(left), tuple(unfinished))

    # --- Internals ---

    def _purged(self, account: str) -> bool:
        return _exists(self.purged_dir / _account_key(account))

    def _metadata(self, directory: Path, campaign: str) -> CampaignInfo | None:
        """The campaign's metadata, read under its lock; None if it has none: the registry did not
        create it, its creation was interrupted, or it was deleted. IntegrityError if damaged."""
        if self.store._gone(campaign):
            return None
        try:
            data = _read_bounded(directory / METADATA_NAME, MAX_METADATA_BYTES)
        except FileNotFoundError:
            return None
        return _parse_metadata(data, campaign)

    def _authorize(self, directory: Path, campaign: str, account: str, *, owner: bool = False) -> CampaignInfo:
        """The campaign's metadata if the account may use it (as its owner, if `owner`), under its lock."""
        info = self._metadata(directory, campaign)
        if info is None or info.role(account) is None or self._purged(account) or self._purged(info.owner):
            raise CampaignNotFound(f"campaign {campaign} does not exist or is not shared with account {account}")
        if owner and info.owner != account:
            raise AccessDenied(f"campaign {campaign}: only its owner may do this")
        return info

    def _all(self) -> list[CampaignInfo]:
        """The metadata of every campaign, each read under its lock. Campaigns without metadata are
        skipped, and so are damaged ones, with a warning; CampaignBusy and StorageError are raised."""
        infos: list[CampaignInfo] = []
        for campaign in self.store.campaigns():
            directory = self.store._directory(campaign)
            with self.store._locked(campaign), _io(f"campaign {campaign}: reading"):
                try:
                    info = self._metadata(directory, campaign)
                except IntegrityError as exc:
                    log.warning("campaign %s: skipped, its metadata is unreadable: %s", campaign, exc)
                    continue
            if info is not None:
                infos.append(info)
        return infos

    def _capture_markers(self, backup: RegistryBackup, directory: Path, valid: Callable[[str], object]) -> int:
        """Adds to `backup` every marker in `directory` (.purged/ or .deleted/), the files with a name
        `valid` accepts, and returns how many there are. No other name means anything to the store
        (.purged/ keeps the .tmp file of an interrupted purge until the next purge)."""
        names = sorted(name for name in os.listdir(directory) if valid(name))
        for name in names:
            data = _read_regular(directory / name, MAX_MARKER_BYTES)
            backup._add(f"{directory.name}/{name}", len(data), hashlib.sha256(data).hexdigest(), data=data)
        return len(names)

    def _capture_campaign(self, backup: RegistryBackup, directory: Path, campaign: str) -> dict[str, object] | None:
        """Adds to `backup` the campaign's metadata, retained manifests and the payload files they
        refer to, under its lock, and returns its entry of the summary. None if there is nothing to
        capture: it was deleted (its tombstone is captured with the others), or it has neither
        metadata nor checkpoint."""
        if self.store._gone(campaign):
            return None
        try:
            metadata = _read_regular(directory / METADATA_NAME, MAX_METADATA_BYTES)
        except FileNotFoundError:
            metadata = None
        info = None if metadata is None else _parse_metadata(metadata, campaign)
        manifests: list[tuple[Checkpoint, bytes]] = []
        sizes: dict[str, int] = {}
        for revision in self.store._revisions(directory):
            data = _read_regular(directory / "checkpoints" / _manifest_name(revision), MAX_MANIFEST_BYTES)
            checkpoint = _parse_manifest(data, campaign, revision)
            for sha256, size in checkpoint.objects().items():
                if sizes.setdefault(sha256, size) != size:
                    raise IntegrityError(f"campaign {campaign} revision {revision}: payload {sha256} has another "
                                         "size in another manifest")
            manifests.append((checkpoint, data))
        if info is None and not manifests:
            return None
        if info is not None:
            backup._add(f"{campaign}/{METADATA_NAME}", len(metadata), info.etag, data=metadata)
        for checkpoint, data in manifests:
            backup._add(f"{campaign}/checkpoints/{_manifest_name(checkpoint.revision)}", len(data), checkpoint.etag,
                        data=data)
        for sha256, size in sorted(sizes.items()):
            try:
                fd = backup._pin(_open_regular(directory / "objects" / sha256))
            except FileNotFoundError:
                raise IntegrityError(f"campaign {campaign}: payload {sha256} is missing") from None
            actual = os.fstat(fd).st_size
            if actual != size:
                raise IntegrityError(f"campaign {campaign}: payload {sha256} has {actual} bytes, not {size}")
            backup._add(f"{campaign}/objects/{sha256}", size, sha256, fd=fd)
        return {"metadata": None if info is None else {"revision": info.revision, "etag": info.etag},
                "checkpoints": [{"revision": checkpoint.revision, "etag": checkpoint.etag}
                                for checkpoint, _ in manifests]}

    def _create_locked(self, directory: Path, campaign: str, account: str) -> CampaignInfo:
        """Makes the campaign's directory, then publishes its first metadata; under its lock."""
        now = time.time()
        data = _encode_metadata(campaign, 1, None, now, now, account, [])
        made = False
        try:
            with _io(f"creating campaign {campaign} failed", committed=False):
                directory.mkdir(mode=0o700)
                made = True
                (directory / "staging").mkdir(mode=0o700)
                if not (_sync_directory(self.store.root) and _sync_directory(directory)):
                    raise DurabilityError(f"campaign {campaign}: its directory cannot be made durable", committed=False)
            self._publish_metadata(directory, campaign, data)
        except StorageError as exc:
            if made and exc.committed is False:
                _remove_tree(directory)  # nobody was given its ID
            raise
        return _parse_metadata(data, campaign)

    def _change(self, directory: Path, campaign: str, current: CampaignInfo, members: list[str]) -> CampaignInfo:
        """Publishes the next revision of the campaign's metadata, with `members`; under its lock."""
        data = _encode_metadata(campaign, current.revision + 1, current.etag, current.created, time.time(),
                                current.owner, members)
        self._publish_metadata(directory, campaign, data)
        return _parse_metadata(data, campaign)

    def _publish_metadata(self, directory: Path, campaign: str, data: bytes) -> None:
        """Writes `data` to staging, flushes it, renames it over campaign.json and reads it back."""
        path = directory / METADATA_NAME
        committed: bool | None = False
        try:
            staging = directory / "staging"
            _make_directory(staging)
            temp = self.store._stage(staging, data)
            committed = None
            durable = _publish(temp, path)
            committed = True
            if not durable:
                raise DurabilityError(f"campaign {campaign}: its metadata is published, but the platform did not "
                                      "promise it is on disk", committed)
            if _read_bounded(path, MAX_METADATA_BYTES) != data:
                raise StorageError(f"campaign {campaign}: its metadata is published, but reads back differently",
                                   committed)
        except OSError as exc:
            raise StorageError(f"campaign {campaign}: publishing its metadata failed: {exc}", committed) from exc

    def _mark_purged(self, account: str) -> None:
        """Publishes the account's purge marker, under the registry's lock."""
        path = self.purged_dir / _account_key(account)
        with _io(f"marking account {account} purged failed", committed=False):
            if _exists(path):
                return
            for name in os.listdir(self.purged_dir):
                if name.endswith(".tmp"):  # left by an interrupted purge; every writer holds the registry's lock
                    _remove(self.purged_dir / name, "staging file")
            temp = self.store._stage(self.purged_dir, json.dumps({"purged": time.time()}).encode("ascii"))
        with _io(f"marking account {account} purged failed", committed=None):
            durable = _publish(temp, path)
        if not durable:
            _warn_once("purge markers", "account purges in %s cannot be made durable here; a power loss may undo "
                       "them", self.purged_dir)
        log.info("account %s is purged from the campaigns", account)
