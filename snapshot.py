#!/usr/bin/env python3
"""Writes a verified backup snapshot of a running server.py to stdout as a .tar.gz, or checks one.

Run it as root on the server host, for example over SSH from the machine that keeps the backups:

    ssh host python3 /opt/pokopia-server/snapshot.py --socket /run/pokopia-cloud/snapshot.sock > backup.tar.gz

The server, started with --snapshot-socket, captures data/state.json and the data/blobs/<id> files
it refers to at one moment and streams them. Every file is checked against the server's manifest
on the way through, and a snapshot fails if the state refers to a blob that is missing or not the
size the state records. --file adds a file, --dir adds the files of a directory, and --sqlite adds
an SQLite database, copied with SQLite's backup API in one read transaction, so the copy is
consistent while its owner keeps writing. --require names a file the archive must hold, such as a
key that --dir would otherwise silently do without. The archive ends with snapshot.json, which
lists the size and SHA-256 of every file.

Nothing is written to disk. Any failure, or running past --deadline, exits non-zero and leaves the
archive unfinished; discard the output then. --sqlite needs Python 3.11 or newer.

--check ARCHIVE checks a snapshot before it is restored: every file must match snapshot.json, which
must come last, every name must be a safe relative path, and every --require file must be there. It
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

PROTOCOL = b"pokopia-snapshot 1"
SERVER_FILE = re.compile(r"data/state\.json|data/blobs/[a-z2-7]{20}")
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


def snapshot(args: argparse.Namespace, output) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(STALL_SECONDS)
        connection.connect(str(args.socket))
        stream = connection.makefile("rb")
        status = stream.readline(100).rstrip(b"\n")
        if status != PROTOCOL + b" ok":
            raise RuntimeError(f"the server answered {status.decode('ascii', 'replace')!r}")

        archive = tarfile.open(fileobj=output, mode="w|gz", format=tarfile.PAX_FORMAT)
        files: dict[str, dict] = {}
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
                    data = Hashing(server.extractfile(member))
                    archive.addfile(entry(member.name, member.size, member.mtime), data)
                    files[member.name] = {"size": member.size, "sha256": data.digest.hexdigest()}
                else:
                    raise RuntimeError(f"unexpected file {member.name}")
        # Read the end-of-archive padding too, so the server finishes its last write before we close.
        while stream.read(1 << 16):
            pass
    check_manifest(manifest, files)

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
    add(archive, {}, "snapshot.json", json.dumps(summary, indent=1).encode(), time.time())
    archive.close()
    output.flush()


def check(path: Path, required: list[str]) -> None:
    """Checks a snapshot archive and prints a sha256sum line for each of its files."""
    files: dict[str, dict] = {}
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
            digest = hashlib.sha256()
            while chunk := data.read(1 << 20):
                digest.update(chunk)
            files[member.name] = {"size": member.size, "sha256": digest.hexdigest()}
    check_manifest(manifest, files)
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
