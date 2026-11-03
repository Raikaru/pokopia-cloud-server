"""Regression test: backup snapshots show one moment while the server keeps changing its data.

Snapshots need Linux (Unix sockets, SO_PEERCRED); elsewhere the tests are skipped. Run it from this
directory with the dependencies installed:

    python3 -m unittest test_snapshot
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import server

HERE = Path(__file__).resolve().parent
BLOB = "a" * 20
# Bigger than the socket buffers, so the server is still sending when the test changes the data.
BIG = 4 * 1024 * 1024


def manifest_entry(content: bytes) -> dict:
    return {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "snapshots need Linux")
class SnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        logger = logging.getLogger("npln")
        self.addCleanup(logger.setLevel, logger.level)
        logger.setLevel(logging.CRITICAL)
        self.store = server.Store(self.root / "data")
        self.storage = server.Storage(self.store, "https://storage.invalid")
        self.service = server.SnapshotService(self.store)
        self.socket = self.root / "snapshot.sock"
        # A document with a big attachment and an upload that has received half its data.
        self.attachment = os.urandom(BIG)
        self.store.write_blob(BLOB, self.attachment)
        self.store.documents["docs/island"] = {"fields": "", "create_time": 1, "update_time": 1,
                                               "attachment": {"blob": BLOB, "mime_type": "", "size": BIG}}
        self.upload = self.storage.new_upload()
        self.storage.upload(self.upload, {"content-range": "bytes 0-9/20"}, b"0123456789")
        self.store.save()

    @contextlib.asynccontextmanager
    async def serving(self):
        listener = await asyncio.start_unix_server(self.service.on_connection, self.socket)
        try:
            yield
        finally:
            listener.close()
            await listener.wait_closed()

    def change_everything(self) -> None:
        """Replaces and deletes the attachment and finishes the upload."""
        self.store.write_blob(BLOB, b"replaced")
        del self.store.documents["docs/island"]
        self.store.release_blob(BLOB)
        self.storage.upload(self.upload, {"content-range": "bytes 10-19/20"}, b"abcdefghij")
        self.store.save()

    def test_snapshot_ignores_later_changes(self) -> None:
        asyncio.run(self.snapshot_ignores_later_changes())

    async def snapshot_ignores_later_changes(self) -> None:
        state = self.store.state_json().encode()
        async with self.serving():
            reader, writer = await asyncio.open_unix_connection(self.socket)
            self.assertEqual(await reader.readline(), b"pokopia-snapshot 1 ok\n")
            busy_reader, busy_writer = await asyncio.open_unix_connection(self.socket)
            self.assertEqual(await busy_reader.readline(), b"pokopia-snapshot 1 busy\n")
            busy_writer.close()
            self.change_everything()
            data = await reader.read()
            writer.close()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            names = archive.getnames()
            files = {member.name: archive.extractfile(member).read() for member in archive}
        manifest = json.loads(files.pop("snapshot.json"))
        self.assertEqual(names[-1], "snapshot.json")
        self.assertEqual(files, {"data/state.json": state, f"data/blobs/{BLOB}": self.attachment,
                                 f"data/blobs/{self.upload}": b"0123456789"})
        self.assertEqual(manifest["files"], {name: manifest_entry(content) for name, content in files.items()})
        self.assertEqual(manifest["damaged_blobs"], [])
        self.assertFalse(self.service.busy)

    def test_stalled_client_is_dropped(self) -> None:
        asyncio.run(self.stalled_client_is_dropped())

    async def stalled_client_is_dropped(self) -> None:
        self.addCleanup(setattr, server, "SNAPSHOT_STALL_SECONDS", server.SNAPSHOT_STALL_SECONDS)
        server.SNAPSHOT_STALL_SECONDS = 0.2
        async with self.serving():
            reader, writer = await asyncio.open_unix_connection(self.socket)
            self.assertEqual(await reader.readline(), b"pokopia-snapshot 1 ok\n")
            for _ in range(100):
                await asyncio.sleep(0.05)
                if not self.service.busy:
                    break
            self.assertFalse(self.service.busy)
            writer.close()

    async def run_client(self, *args: str) -> tuple[int, bytes, bytes]:
        async with self.serving():
            client = await asyncio.create_subprocess_exec(
                sys.executable, str(HERE / "snapshot.py"), "--socket", str(self.socket), *args,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            output, errors = await client.communicate()
        return client.returncode, output, errors

    def check(self, archive: bytes, *args: str) -> subprocess.CompletedProcess:
        path = self.root / "backup.tar.gz"
        path.write_bytes(archive)
        return subprocess.run([sys.executable, str(HERE / "snapshot.py"), "--check", str(path), *args],
                              capture_output=True, text=True)

    def archive_files(self, output: bytes) -> dict[str, bytes]:
        with tarfile.open(fileobj=io.BytesIO(output), mode="r:gz") as archive:
            return {member.name: archive.extractfile(member).read() for member in archive}

    @unittest.skipUnless(hasattr(sqlite3.Connection, "serialize"), "snapshot.py --sqlite needs Python 3.11")
    def test_snapshot_client(self) -> None:
        asyncio.run(self.snapshot_client())

    async def snapshot_client(self) -> None:
        database = self.root / "auth.db"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("CREATE TABLE accounts (name TEXT)")
            connection.execute("INSERT INTO accounts VALUES ('somebody')")
        pki = self.root / "pki"
        pki.mkdir()
        (pki / "device-ca.crt").write_bytes(b"certificate")
        (pki / "device-ca.key").write_bytes(b"key")
        (self.root / "server.key").write_bytes(b"server key")
        state = self.store.state_json().encode()
        returncode, output, errors = await self.run_client(
            "--sqlite", f"portal/auth.db={database}", "--dir", f"portal/pki={pki}",
            "--file", f"tls/server.key={self.root / 'server.key'}",
            "--require", "portal/pki/device-ca.key", "--require", "tls/server.key")
        self.assertEqual(returncode, 0, errors)
        with tarfile.open(fileobj=io.BytesIO(output), mode="r:gz") as archive:
            names = archive.getnames()
            files = {member.name: archive.extractfile(member).read() for member in archive}
        manifest = json.loads(files.pop("snapshot.json"))
        self.assertEqual(names[-1], "snapshot.json")
        self.assertEqual(manifest["files"], {name: manifest_entry(content) for name, content in files.items()})
        self.assertEqual(manifest["damaged_blobs"], [])
        self.assertEqual(files.pop("data/state.json"), state)
        self.assertEqual(files.pop(f"data/blobs/{BLOB}"), self.attachment)
        self.assertEqual(files.pop(f"data/blobs/{self.upload}"), b"0123456789")
        self.assertEqual(files.pop("portal/pki/device-ca.crt"), b"certificate")
        self.assertEqual(files.pop("portal/pki/device-ca.key"), b"key")
        self.assertEqual(files.pop("tls/server.key"), b"server key")
        copy = sqlite3.connect(":memory:")
        copy.deserialize(files.pop("portal/auth.db"))
        self.assertEqual(copy.execute("SELECT name FROM accounts").fetchall(), [("somebody",)])
        self.assertEqual(files, {})

        # --check accepts the archive and prints a sha256sum line per file; a truncated copy fails,
        # and so does a required file the archive lacks.
        checked = self.check(output, "--require", "portal/pki/device-ca.key")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(checked.stdout.splitlines(),
                         [f"{entry['sha256']}  {name}" for name, entry in sorted(manifest["files"].items())])
        self.assertNotEqual(self.check(output[:len(output) // 2]).returncode, 0)
        self.assertNotEqual(self.check(output, "--require", "portal/pki/ingress.key").returncode, 0)

    def test_snapshot_client_fails_without_required_file(self) -> None:
        asyncio.run(self.snapshot_client_fails_without_required_file())

    async def snapshot_client_fails_without_required_file(self) -> None:
        pki = self.root / "pki"
        pki.mkdir()
        (pki / "device-ca.crt").write_bytes(b"certificate")
        returncode, output, errors = await self.run_client(
            "--dir", f"portal/pki={pki}", "--require", "portal/pki/device-ca.key")
        self.assertNotEqual(returncode, 0)
        self.assertIn(b"portal/pki/device-ca.key", errors)
        self.assertNotEqual(self.check(output).returncode, 0)

    def test_snapshot_client_fails_on_missing_database(self) -> None:
        asyncio.run(self.snapshot_client_fails_on_missing_database())

    async def snapshot_client_fails_on_missing_database(self) -> None:
        returncode, output, errors = await self.run_client("--sqlite", f"portal/auth.db={self.root / 'absent.db'}")
        self.assertNotEqual(returncode, 0)
        self.assertIn(b"snapshot failed", errors)
        # The archive is left unfinished, so nothing mistakes it for a complete one.
        with self.assertRaises((tarfile.TarError, EOFError, OSError)):
            with tarfile.open(fileobj=io.BytesIO(output), mode="r:gz") as archive:
                archive.getmembers()
        self.assertNotEqual(self.check(output).returncode, 0)

    def test_snapshot_client_fails_on_missing_blob(self) -> None:
        asyncio.run(self.snapshot_client_fails_on_missing_blob())

    async def snapshot_client_fails_on_missing_blob(self) -> None:
        self.store.blob_path(BLOB).unlink()
        returncode, output, errors = await self.run_client()
        self.assertNotEqual(returncode, 0)
        self.assertIn(f"{BLOB} is missing".encode(), errors)
        self.assertNotEqual(self.check(output).returncode, 0)

    def test_snapshot_client_fails_on_short_blobs(self) -> None:
        for blob_id, size in ((BLOB, BIG - 1), (self.upload, 5)):
            with self.subTest(blob=blob_id):
                with self.store.blob_path(blob_id).open("r+b") as blob:
                    original = blob.read()
                    blob.truncate(size)
                returncode, output, errors = asyncio.run(self.run_client())
                self.assertNotEqual(returncode, 0)
                self.assertIn(f"{blob_id} has {size} bytes".encode(), errors)
                self.assertNotEqual(self.check(output).returncode, 0)
                self.store.write_blob(blob_id, original)

    def test_upload_past_received_is_captured_up_to_received(self) -> None:
        # The server stopped after appending to the upload but before saving that it received it.
        with self.store.blob_path(self.upload).open("ab") as blob:
            blob.write(b"unsaved")
        returncode, output, errors = asyncio.run(self.run_client())
        self.assertEqual(returncode, 0, errors)
        self.assertEqual(self.archive_files(output)[f"data/blobs/{self.upload}"], b"0123456789")


if __name__ == "__main__":
    unittest.main()
