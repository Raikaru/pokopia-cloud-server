#!/usr/bin/env python3
"""Writes a verified backup snapshot of a running server.py to stdout as a .tar.gz, or checks one.

Run it as root on the server host, for example over SSH from the machine that keeps the backups:

    ssh host python3 /opt/pokopia-server/snapshot.py --socket /run/pokopia-cloud/snapshot.sock > backup.tar.gz

The server, started with --snapshot-socket, captures data/state.json and the data/blobs/<id> files
it refers to at one moment and streams them. The names under data/campaigns/ are those of the
campaign registry's backup files (campaign_store.py, CampaignRegistry.capture_backup), for a server
that sends them. Every file is checked against the server's manifest on the way through, and a
snapshot fails if the state refers to a blob that is missing or not the size the state records, or
if the campaign files do not hold together (CampaignFiles): a retained checkpoint whose manifest is
damaged, names another campaign or revision, or refers to a payload that is missing, of another
size, or does not hash to its name. A server that sends campaign files must include
`campaign_inventory` in its manifest: a map from each captured `data/campaigns/...` path to its
size and SHA-256, collected from the registry capture before streaming. The archive preserves and
checks it independently of the stream's file list, so whole omitted files are detected too.
Protocol 2 requires the inventory even when no campaign files arrive; protocol 1 remains readable
for older servers. The archive records protocol 2, but cannot authenticate its own manifest: if
both that marker and the inventory are deliberately removed, it is indistinguishable from legacy.
Checking campaign files needs campaign_store.py beside snapshot.py; a snapshot without them does not.
--file adds a file, --dir adds the files of a directory, and --sqlite adds an SQLite database,
copied with SQLite's backup API in one read transaction, so the copy is
consistent while its owner keeps writing. --require names a file the archive must hold, such as a
key that --dir would otherwise silently do without. The archive ends with snapshot.json, which
lists the size and SHA-256 of every file.

Nothing is written to disk. Any failure, or running past --deadline, exits non-zero and leaves the
archive unfinished; discard the output then. --sqlite needs Python 3.11 or newer.

--check ARCHIVE checks a snapshot before it is restored: every file must match snapshot.json, which
must come last, every name must be a safe relative path, the campaign files must hold together as
for a snapshot, whatever snapshot.json says of them, and every --require file must be there. It
prints one sha256sum line per file, for checking the files once they are unpacked.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import signal
import socket
import sqlite3
import sys
import tarfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import campaign_store  # imported when needed (CampaignFiles.parsers): a snapshot may go without it

PROTOCOL = b"pokopia-snapshot 1"
CAMPAIGN_PROTOCOL = b"pokopia-snapshot 2"
# A campaign ID as campaign_store.py accepts it: 1-64 of a-z, 0-9, _ and -, starting with a letter or
# digit, and not a Windows device name.
CAMPAIGN_ID = r"(?!(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?![a-z0-9_-]))[a-z0-9][a-z0-9_-]{0,63}"
# The campaign registry's files under data/campaigns/: each campaign's metadata, retained manifests
# and payloads, and the deleted campaigns' tombstones and purged accounts' markers. None leads out of
# data/campaigns/ or into its locks, trash or staging files, and none is longer than 152 characters.
# Its groups name the campaign and the kind of file; a tombstone or purge marker sets none of them.
CAMPAIGN_FILE = (rf"data/campaigns/(?:(?P<campaign>{CAMPAIGN_ID})/(?:(?P<metadata>campaign\.json)"
                 rf"|checkpoints/(?P<revision>[0-9]{{20}})\.json|objects/(?P<object>[0-9a-f]{{64}}))"
                 rf"|\.deleted/{CAMPAIGN_ID}|\.purged/[0-9a-f]{{64}})")
CAMPAIGN_PATH = re.compile(CAMPAIGN_FILE)
SERVER_FILE = re.compile(rf"data/state\.json|data/blobs/[a-z2-7]{{20}}|{CAMPAIGN_FILE}")
SEGMENT = r"[A-Za-z0-9_-][A-Za-z0-9._-]*"
# Names given to --file, --sqlite and --dir; data/ and snapshot.json belong to the server's snapshot.
EXTRA_NAME = re.compile(rf"(?!data/|data$|snapshot\.json$){SEGMENT}(?:/{SEGMENT})*")
STALL_SECONDS = 120  # longest wait for data from the server, which reads only local files


class Hashing:
    """A file object that hashes what is read from it."""

    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        self.digest.update(data)
        return data


class CampaignFiles:
    """The campaign registry's files of one snapshot (CAMPAIGN_FILE), checked as the campaign store
    reads them, with campaign_store.py's own parsers. That module is imported for the first campaign
    file, so a snapshot without one does not need it. Every file of the snapshot goes through read()
    and add(), then finish() checks them together; every failure is a RuntimeError.

      * <campaign>/campaign.json must be metadata of the campaign it is filed under (_parse_metadata).
      * <campaign>/checkpoints/<revision>.json must be a manifest of that campaign and revision, 1 or
        more (_parse_manifest), with a parent exactly when the revision is above 1. Where the snapshot
        also holds the revision before, the parent must be that manifest's etag.
      * Every payload a retained manifest refers to must be in the campaign's objects/, with the size
        the manifest records; every payload there must hash to its name and be referred to.
      * Tombstones and purge markers must be no bigger than the store reads them (MAX_MARKER_BYTES).

    Metadata and manifests are read whole once their size is known to be within the store's limits;
    payloads and markers stream, and only the parsed manifests and each payload's size are kept. A
    campaign may lack metadata, as capture_backup allows for campaigns the registry did not create.
    The independently captured campaign_inventory detects whole omitted files, provided the server
    sent that inventory. A legacy snapshot with neither campaign files nor inventory remains valid."""

    def __init__(self) -> None:
        self.module = None  # campaign_store, once a campaign file needs it
        self.checkpoints: dict[str, dict[int, campaign_store.Checkpoint]] = {}  # by campaign, then revision
        self.objects: dict[str, dict[str, int]] = {}  # payload sizes by campaign, then SHA-256

    def parsers(self):
        if self.module is None:
            try:
                import campaign_store
            except ImportError as exc:
                raise RuntimeError(f"the snapshot has campaign files, and checking them needs campaign_store.py "
                                   f"beside snapshot.py ({exc})") from None
            self.module = campaign_store
        return self.module

    def read(self, name: str, size: int, source) -> bytes | None:
        """The contents of the file `name`, `size` bytes from `source`, if it is campaign metadata or a
        manifest, which are parsed whole; None for any other file, which is left to stream."""
        match = CAMPAIGN_PATH.fullmatch(name)
        if match is None or not (match["metadata"] or match["revision"]):
            return None
        store = self.parsers()
        limit = store.MAX_METADATA_BYTES if match["metadata"] else store.MAX_MANIFEST_BYTES
        if size > limit:
            raise RuntimeError(f"{name} has {size} bytes, more than the {limit} the campaign store reads")
        data = source.read(size)
        if len(data) != size:
            raise RuntimeError(f"{name} ends after {len(data)} of its {size} bytes")
        return data

    def add(self, name: str, size: int, sha256: str, data: bytes | None) -> None:
        """Checks the file `name`, `size` bytes that hash to `sha256`; `data` is what read() returned."""
        match = CAMPAIGN_PATH.fullmatch(name)
        if match is None:
            return
        store, campaign = self.parsers(), match["campaign"]
        try:
            if match["metadata"]:
                store._parse_metadata(data, campaign)
            elif match["revision"]:
                revision = int(match["revision"])
                checkpoint = store._parse_manifest(data, campaign, revision)
                if revision < 1 or (checkpoint.parent is None) != (revision == 1):
                    raise RuntimeError(f"{name} is damaged: revision {revision} with the parent {checkpoint.parent!r}")
                self.checkpoints.setdefault(campaign, {})[revision] = checkpoint
            elif match["object"]:
                if sha256 != match["object"]:
                    raise RuntimeError(f"{name} is damaged: its SHA-256 is {sha256}")
                self.objects.setdefault(campaign, {})[sha256] = size
            elif size > store.MAX_MARKER_BYTES:
                raise RuntimeError(f"{name} has {size} bytes, more than the {store.MAX_MARKER_BYTES} of a marker")
        except store.CampaignError as exc:
            raise RuntimeError(f"{name} is damaged: {exc}") from None

    def finish(self) -> None:
        """Checks that each campaign's retained manifests and payloads go together (see the class)."""
        for campaign in sorted(self.checkpoints.keys() | self.objects.keys()):
            present = self.objects.get(campaign, {})
            referenced: set[str] = set()
            previous = None
            for revision, checkpoint in sorted(self.checkpoints.get(campaign, {}).items()):
                where = f"campaign {campaign} revision {revision}"
                if previous is not None and previous.revision == revision - 1 and checkpoint.parent != previous.etag:
                    raise RuntimeError(f"{where} follows {checkpoint.parent}, not revision {previous.revision} "
                                       f"({previous.etag})")
                for sha256, size in sorted(checkpoint.objects().items()):
                    if sha256 not in present:
                        raise RuntimeError(f"{where}: payload {sha256} is missing")
                    if present[sha256] != size:
                        raise RuntimeError(f"{where}: payload {sha256} has {present[sha256]} bytes, not {size}")
                    referenced.add(sha256)
                previous = checkpoint
            unreferenced = sorted(present.keys() - referenced)
            if unreferenced:
                raise RuntimeError(f"campaign {campaign}: payload {unreferenced[0]} belongs to no retained checkpoint")


def named_path(value: str) -> tuple[str, Path]:
    name, sep, path = value.partition("=")
    if not sep or not path or not EXTRA_NAME.fullmatch(name):
        raise argparse.ArgumentTypeError(f"expected NAME=PATH with a relative archive NAME outside data/: {value}")
    return name, Path(path)


def archive_name(value: str) -> str:
    if not (SERVER_FILE.fullmatch(value) or EXTRA_NAME.fullmatch(value)):
        raise argparse.ArgumentTypeError(f"not a file name in a snapshot: {value}")
    return value


def check_required(files: dict[str, dict], required: list[str]) -> None:
    absent = sorted(set(required) - set(files))
    if absent:
        raise RuntimeError(f"required files are absent: {', '.join(absent)}")


def add(archive: tarfile.TarFile, files: dict[str, dict], name: str, data: bytes, mtime: float) -> None:
    if name in files:
        raise RuntimeError(f"{name} is in the archive twice")
    archive.addfile(entry(name, len(data), mtime), io.BytesIO(data))
    files[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def entry(name: str, size: int, mtime: float) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = size, int(mtime), 0o600
    return info


def sqlite_copy(path: Path) -> bytes:
    """The database at `path`, read in one transaction with SQLite's backup API."""
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as source, \
            contextlib.closing(sqlite3.connect(":memory:")) as copy:
        source.backup(copy)
        if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError(f"{path} fails PRAGMA integrity_check")
        return copy.serialize()


def check_manifest(manifest: dict | None, files: dict[str, dict]) -> None:
    if manifest is None:
        raise RuntimeError("the snapshot ends before its manifest")
    if manifest.get("format") != 1 or manifest.get("files") != files or "data/state.json" not in files:
        raise RuntimeError("the snapshot does not match its manifest")
    if manifest.get("damaged_blobs") != []:
        raise RuntimeError(f"the server's data is damaged: {'; '.join(manifest.get('damaged_blobs') or ['?'])}")


def check_campaign_inventory(manifest: dict, files: dict[str, dict], *, required: bool = False) -> None:
    """Compare streamed campaign files with the independently captured server inventory."""
    actual = {name: info for name, info in files.items() if CAMPAIGN_PATH.fullmatch(name)}
    inventory = manifest.get("campaign_inventory")
    if inventory is None:
        if required or actual:
            raise RuntimeError("campaign files lack the server's captured inventory")
    elif not isinstance(inventory, dict) or inventory != actual:
        raise RuntimeError("campaign files do not match the server's captured inventory")


def snapshot(args: argparse.Namespace, output) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(STALL_SECONDS)
        connection.connect(str(args.socket))
        stream = connection.makefile("rb")
        status = stream.readline(100).rstrip(b"\n")
        if status not in (PROTOCOL + b" ok", CAMPAIGN_PROTOCOL + b" ok"):
            raise RuntimeError(f"the server answered {status.decode('ascii', 'replace')!r}")
        campaign_protocol = status == CAMPAIGN_PROTOCOL + b" ok"

        archive = tarfile.open(fileobj=output, mode="w|gz", format=tarfile.PAX_FORMAT)
        files: dict[str, dict] = {}
        campaigns = CampaignFiles()
        manifest = None
        with tarfile.open(fileobj=stream, mode="r|") as server:
            for member in server:
                if manifest is not None:
                    raise RuntimeError(f"{member.name} follows snapshot.json")
                if not member.isfile():
                    raise RuntimeError(f"{member.name} is not a regular file")
                if member.name == "snapshot.json":
                    manifest = json.loads(server.extractfile(member).read())
                elif SERVER_FILE.fullmatch(member.name) and member.name not in files:
                    source = server.extractfile(member)
                    document = campaigns.read(member.name, member.size, source)
                    data = Hashing(source if document is None else io.BytesIO(document))
                    archive.addfile(entry(member.name, member.size, member.mtime), data)
                    files[member.name] = {"size": member.size, "sha256": data.digest.hexdigest()}
                    campaigns.add(member.name, member.size, files[member.name]["sha256"], document)
                else:
                    raise RuntimeError(f"unexpected file {member.name}")
        # Read the end-of-archive padding too, so the server finishes its last write before we close.
        while stream.read(1 << 16):
            pass
    check_manifest(manifest, files)
    campaigns.finish()
    check_campaign_inventory(manifest, files, required=campaign_protocol)

    extras_time = time.time()
    for name, path in args.file:
        add(archive, files, name, path.read_bytes(), extras_time)
    for name, path in args.sqlite:
        add(archive, files, name, sqlite_copy(path), extras_time)
    for name, path in args.dir:
        for item in sorted(os.scandir(path), key=lambda item: item.name):
            if not item.is_file(follow_symlinks=False) or not re.fullmatch(SEGMENT, item.name):
                raise RuntimeError(f"{item.path} is not a plain file with a simple name")
            add(archive, files, f"{name}/{item.name}", Path(item.path).read_bytes(), extras_time)
    check_required(files, args.require)

    summary = {"format": 1, "server_time": manifest["created"], "extras_time": extras_time,
               "files": files, "damaged_blobs": []}
    if campaign_protocol:
        summary["server_snapshot_protocol"] = 2
    if "campaign_inventory" in manifest:
        summary["campaign_inventory"] = manifest["campaign_inventory"]
    add(archive, {}, "snapshot.json", json.dumps(summary, indent=1).encode(), time.time())
    archive.close()
    output.flush()


def check(path: Path, required: list[str]) -> None:
    """Checks a snapshot archive and prints a sha256sum line for each of its files."""
    files: dict[str, dict] = {}
    campaigns = CampaignFiles()
    manifest = None
    with tarfile.open(path, mode="r|gz") as archive:
        for member in archive:
            if manifest is not None:
                raise RuntimeError(f"{member.name} follows snapshot.json")
            if not member.isfile():
                raise RuntimeError(f"{member.name} is not a regular file")
            data = archive.extractfile(member)
            if member.name == "snapshot.json":
                manifest = json.loads(data.read())
                continue
            if member.name in files or not (SERVER_FILE.fullmatch(member.name) or EXTRA_NAME.fullmatch(member.name)):
                raise RuntimeError(f"unexpected file {member.name}")
            document = campaigns.read(member.name, member.size, data)
            content = Hashing(data if document is None else io.BytesIO(document))
            while content.read(1 << 20):
                pass
            files[member.name] = {"size": member.size, "sha256": content.digest.hexdigest()}
            campaigns.add(member.name, member.size, files[member.name]["sha256"], document)
    check_manifest(manifest, files)
    campaigns.finish()
    protocol = manifest.get("server_snapshot_protocol")
    if protocol is not None and (type(protocol) is not int or protocol != 2):
        raise RuntimeError(f"unsupported server snapshot protocol {protocol!r}")
    check_campaign_inventory(manifest, files, required=protocol == 2)
    check_required(files, required)
    for name, info in sorted(files.items()):
        print(f"{info['sha256']}  {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Write a verified .tar.gz backup snapshot of server.py "
                                                 "to stdout, or check one.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", type=Path, help="the server's --snapshot-socket")
    source.add_argument("--check", type=Path, metavar="ARCHIVE",
                        help="check a snapshot archive and print sha256sum lines for its files")
    parser.add_argument("--file", type=named_path, action="append", default=[], metavar="NAME=PATH",
                        help="also add the file PATH as NAME; repeatable")
    parser.add_argument("--sqlite", type=named_path, action="append", default=[], metavar="NAME=PATH",
                        help="also add the SQLite database at PATH as NAME; repeatable")
    parser.add_argument("--dir", type=named_path, action="append", default=[], metavar="NAME=PATH",
                        help="also add every file in the directory PATH as NAME/<file>; repeatable")
    parser.add_argument("--require", type=archive_name, action="append", default=[], metavar="NAME",
                        help="fail unless the archive holds the file NAME; repeatable")
    parser.add_argument("--deadline", type=int, default=1800,
                        help="seconds after which the snapshot is abandoned (default 1800)")
    args = parser.parse_args()
    if args.check:
        if args.file or args.sqlite or args.dir:
            parser.error("--file, --sqlite and --dir only go with --socket")
        try:
            check(args.check, args.require)
        except (OSError, EOFError, ValueError, RuntimeError, tarfile.TarError) as exc:
            sys.exit(f"{args.check} is not a complete snapshot: {exc!r}")
        return
    if args.sqlite and not hasattr(sqlite3.Connection, "serialize"):
        parser.error("--sqlite needs Python 3.11 or newer")
    if sys.stdout.isatty():
        parser.error("stdout is a terminal; redirect it to a file or pipe")

    # SIGALRM's default action ends the process at once, wherever it is blocked.
    signal.alarm(args.deadline)
    try:
        snapshot(args, sys.stdout.buffer)
    except BaseException as exc:
        print(f"snapshot failed: {exc!r}", file=sys.stderr, flush=True)
        # os._exit skips the finalizer that would close the gzip stream, so a failed archive
        # never ends like a complete one.
        os._exit(1)


if __name__ == "__main__":
    main()
