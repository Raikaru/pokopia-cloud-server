"""Regression test: backup snapshots show one moment while the server keeps changing its data, and
neither a snapshot nor --check accepts campaign files that do not hold together.

Snapshots need Linux (Unix sockets, SO_PEERCRED); elsewhere the tests are skipped, except those of
--check. Run it from this directory with the dependencies installed:

    python3 -m unittest test_snapshot
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import gzip
import io
import json
import logging
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path

import campaign_store as cs
import server
from test_campaign_backup import contents
from test_campaign_store import common, encode, stage_file

HERE = Path(__file__).resolve().parent
BLOB = "a" * 20
# Bigger than the socket buffers, so the server is still sending when the test changes the data.
BIG = 4 * 1024 * 1024
OWNER = "acct-owner"
FRIEND = "acct-friend"
PURGED = "acct-purged"


def manifest_entry(content: bytes) -> dict:
    return {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def tar(files: dict[str, bytes], manifest: dict, mode: str) -> bytes:
    """`files`, then snapshot.json: `manifest` with the size and SHA-256 of each of them."""
    manifest = {**manifest, "files": {name: manifest_entry(data) for name, data in files.items()}}
    if any(name.startswith("data/campaigns/") for name in files) and "campaign_inventory" not in manifest:
        manifest["campaign_inventory"] = {name: info for name, info in manifest["files"].items()
                                          if name.startswith("data/campaigns/")}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode, format=tarfile.PAX_FORMAT) as archive:
        for name, data in [*files.items(), ("snapshot.json", json.dumps(manifest).encode())]:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def check_archive(archive: bytes, root: Path, script: Path = HERE / "snapshot.py") -> subprocess.CompletedProcess:
    """snapshot.py --check of `archive`, run as `script`, with no PYTHONPATH to find other modules by."""
    path = root / "backup.tar.gz"
    path.write_bytes(archive)
    environment = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
    return subprocess.run([sys.executable, str(script), "--check", str(path)], capture_output=True, text=True,
                          env=environment)


def campaign_files(root: Path) -> tuple[dict[str, bytes], str, str]:
    """A server's snapshot files with the campaign registry made under `root`, as capture_backup takes
    it: a shared campaign whose revisions 2 to 4 are retained, all keeping stage 1's payload, another
    campaign with metadata only, a deleted campaign's tombstone and a purged account's marker.
    Returns the files, the shared campaign's ID and the other's."""
    registry = cs.CampaignRegistry(cs.CampaignStore(root, min_free_bytes=0))
    info = registry.create(OWNER)
    info = registry.add_member(info.campaign, OWNER, FRIEND, if_match=info.etag)
    head = registry.commit(info.campaign, OWNER, None, **common(0), stages={1: stage_file(1), 2: stage_file(2)})
    for seed in range(1, 4):
        head = registry.commit(info.campaign, FRIEND, head.etag, **common(seed), stages={2: stage_file(seed + 10)})
    other = registry.create(FRIEND).campaign
    registry.delete(registry.create(OWNER).campaign, OWNER)
    registry.purge_account(PURGED)
    with registry.capture_backup() as backup:
        captured = contents(backup)
    files = {"data/state.json": b"{}", **{f"data/campaigns/{path}": data for path, data in captured.items()}}
    return files, info.campaign, other


class SnapshotCancellationTest(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_during_capture_releases_the_late_backup(self) -> None:
        started, proceed, closed = threading.Event(), threading.Event(), threading.Event()

        class Store:
            def snapshot(self):
                return b"{}", [], []

        class Backup:
            def close(self):
                closed.set()

        class Registry:
            def capture_backup(self):
                started.set()
                proceed.wait()
                return Backup()

        task = asyncio.create_task(server.SnapshotService(Store(), Registry()).send(None))
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            proceed.set()
        self.assertTrue(await asyncio.to_thread(closed.wait, 5))


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

    def test_campaign_snapshot_captures_acl_and_retained_checkpoints(self) -> None:
        asyncio.run(self.campaign_snapshot_captures_acl_and_retained_checkpoints())

    async def campaign_snapshot_captures_acl_and_retained_checkpoints(self) -> None:
        registry = cs.CampaignRegistry(cs.CampaignStore(self.root / "campaigns", min_free_bytes=0))
        info = registry.create(OWNER)
        info = registry.add_member(info.campaign, OWNER, FRIEND, if_match=info.etag)
        first = registry.commit(info.campaign, OWNER, None, **common(0), stages={1: stage_file(1)})
        second = registry.commit(info.campaign, FRIEND, first.etag, **common(1))
        with registry.capture_backup() as backup:
            expected = {f"data/campaigns/{path}": data for path, data in contents(backup).items()}
        self.service = server.SnapshotService(self.store, registry)
        async with self.serving():
            reader, writer = await asyncio.open_unix_connection(self.socket)
            self.assertEqual(await reader.readline(), b"pokopia-snapshot 1 ok\n")
            registry.commit(info.campaign, OWNER, second.etag, **common(2))
            data = await reader.read()
            writer.close()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            files = {member.name: archive.extractfile(member).read() for member in archive}
        manifest = json.loads(files["snapshot.json"])
        captured = {name: value for name, value in files.items() if name.startswith("data/campaigns/")}
        self.assertEqual(captured, expected)
        self.assertEqual(manifest["campaign_inventory"],
                         {name: manifest_entry(value) for name, value in expected.items()})
        checked = check_archive(gzip.compress(data), self.root)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        restored = self.root / "restored"
        for name, value in captured.items():
            path = restored / name.removeprefix("data/campaigns/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        copy = cs.CampaignRegistry(cs.CampaignStore(restored, min_free_bytes=0))
        self.assertEqual(copy.get(info.campaign, FRIEND).role(FRIEND), "member")
        self.assertEqual(copy.read(info.campaign, FRIEND).checkpoint, second)
        returncode, output, errors = await self.run_client()
        self.assertEqual(returncode, 0, errors)
        self.assertEqual(self.check(output).returncode, 0)
        streamed = self.archive_files(output)
        with registry.capture_backup() as backup:
            latest = {f"data/campaigns/{path}": data for path, data in contents(backup).items()}
        self.assertEqual({name: value for name, value in streamed.items() if name.startswith("data/campaigns/")},
                         latest)

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


class CampaignCheckTest(unittest.TestCase):
    """--check of snapshots with campaign files. Every archive's snapshot.json matches its files, so
    only the checks of the campaign files themselves can refuse one."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.files, self.campaign, self.other = campaign_files(self.root / "campaigns")

    def check(self, files: dict[str, bytes], script: Path = HERE / "snapshot.py") -> subprocess.CompletedProcess:
        """--check of an archive of `files` as snapshot.py writes one."""
        archive = tar(files, {"format": 1, "server_time": 0, "extras_time": 0, "damaged_blobs": []}, "w:gz")
        return check_archive(archive, self.root, script)

    def manifest(self, revision: int, campaign: str | None = None) -> str:
        return f"data/campaigns/{campaign or self.campaign}/checkpoints/{revision:020d}.json"

    def payload(self, sha256: str) -> str:
        return f"data/campaigns/{self.campaign}/objects/{sha256}"

    def edited(self, revision: int, **fields: object) -> dict[str, bytes]:
        """The files with these fields of the manifest of `revision` changed, written as the store would."""
        doc = json.loads(self.files[self.manifest(revision)])
        return {**self.files, self.manifest(revision): encode({**doc, **fields})}

    def without(self, name: str) -> dict[str, bytes]:
        return {other: data for other, data in self.files.items() if other != name}

    def test_a_whole_campaign_registry_passes(self) -> None:
        purged = f"data/campaigns/.purged/{hashlib.sha256(PURGED.encode()).hexdigest()}"
        for name in (f"data/campaigns/{self.campaign}/campaign.json", f"data/campaigns/{self.other}/campaign.json",
                     *(self.manifest(revision) for revision in (2, 3, 4)), purged):
            self.assertIn(name, self.files)
        self.assertNotIn(self.manifest(1), self.files)
        self.assertEqual(len([name for name in self.files if name.startswith("data/campaigns/.deleted/")]), 1)
        checked = self.check(self.files)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(checked.stdout.splitlines(),
                         [f"{manifest_entry(data)['sha256']}  {name}" for name, data in sorted(self.files.items())])

    def test_campaign_files_that_do_not_hold_together_fail(self) -> None:
        newest = json.loads(self.files[self.manifest(4)])
        story, stage1, stage2 = (newest["story"]["sha256"], newest["stages"]["01"]["sha256"],
                                 newest["stages"]["02"]["sha256"])
        size = newest["stages"]["02"]["size"]
        metadata, other_metadata = (f"data/campaigns/{campaign}/campaign.json" for campaign in (self.campaign, self.other))
        tombstone = next(name for name in self.files if name.startswith("data/campaigns/.deleted/"))
        orphan = b"a payload that no manifest refers to"
        cases = [
            ("a payload is missing", self.without(self.payload(stage1)), f"revision 2: payload {stage1} is missing"),
            ("a payload holds other bytes", {**self.files, self.payload(story): bytes(cs.STORY_BLOCK_SIZE)},
             f"{self.payload(story)} is damaged"),
            ("a payload is cut short", {**self.files, self.payload(stage2): self.files[self.payload(stage2)][:-1]},
             f"{self.payload(stage2)} is damaged"),
            ("a manifest records another size",
             self.edited(4, stages={**newest["stages"], "02": {**newest["stages"]["02"], "size": size + 1}}),
             f"payload {stage2} has {size} bytes, not {size + 1}"),
            ("a payload belongs to no checkpoint", {**self.files, self.payload(hashlib.sha256(orphan).hexdigest()): orphan},
             "belongs to no retained checkpoint"),
            ("a manifest is cut short", {**self.files, self.manifest(4): self.files[self.manifest(4)][:-1]},
             f"{self.manifest(4)} is damaged"),
            ("a manifest is filed under another revision",
             {**self.without(self.manifest(4)), self.manifest(5): self.files[self.manifest(4)]},
             f"{self.manifest(5)} is damaged"),
            ("a manifest is filed under another campaign",
             {**self.files, self.manifest(4, self.other): self.files[self.manifest(4)]},
             f"{self.manifest(4, self.other)} is damaged"),
            ("metadata is filed under another campaign", {**self.files, other_metadata: self.files[metadata]},
             f"{other_metadata} is damaged"),
            ("metadata is not the registry's", {**self.files, metadata: b"{}"}, f"{metadata} is damaged"),
            ("a manifest follows another parent", self.edited(3, parent="0" * 64), f"revision 3 follows {'0' * 64}"),
            ("a later revision has no parent", self.edited(2, parent=None), f"{self.manifest(2)} is damaged"),
            ("a manifest has an older format", self.edited(4, format=1), f"{self.manifest(4)} is damaged"),
            ("a manifest is too big to be one",
             {**self.files, self.manifest(4): self.files[self.manifest(4)] + b" " * cs.MAX_MANIFEST_BYTES},
             f"{self.manifest(4)} has"),
            ("a tombstone is too big to be one", {**self.files, tombstone: bytes(cs.MAX_MARKER_BYTES + 1)},
             f"{tombstone} has"),
        ]
        for case, files, message in cases:
            with self.subTest(case):
                checked = self.check(files)
                self.assertNotEqual(checked.returncode, 0, checked.stdout)
                self.assertIn(message, checked.stderr)

    def test_inventory_detects_omitted_complete_files(self) -> None:
        inventory = {name: manifest_entry(data) for name, data in self.files.items()
                     if name.startswith("data/campaigns/")}
        tombstone = next(name for name in inventory if name.startswith("data/campaigns/.deleted/"))
        purged = next(name for name in inventory if name.startswith("data/campaigns/.purged/"))
        metadata = f"data/campaigns/{self.other}/campaign.json"
        for omitted in (metadata, self.manifest(4), tombstone, purged):
            with self.subTest(omitted=omitted):
                files = self.without(omitted)
                if omitted == self.manifest(4):
                    # Keep the other retained manifests and their shared payloads; remove only payloads
                    # used exclusively by the omitted checkpoint.
                    remaining = set()
                    for revision in (2, 3):
                        checkpoint = json.loads(files[self.manifest(revision)])
                        remaining.update((checkpoint["story"]["sha256"],
                                          checkpoint["unique_quest_history"]["sha256"]))
                        remaining.update(stage["sha256"] for stage in checkpoint["stages"].values())
                    files = {name: data for name, data in files.items()
                             if "/objects/" not in name or name.rsplit("/", 1)[-1] in remaining}
                archive = tar(files, {"format": 1, "damaged_blobs": [], "campaign_inventory": inventory}, "w:gz")
                checked = check_archive(archive, self.root)
                self.assertNotEqual(checked.returncode, 0)
                self.assertIn("server's captured inventory", checked.stderr)
        for prefix in (f"data/campaigns/{self.campaign}/", "data/campaigns/"):
            with self.subTest(omitted_tree=prefix):
                files = {name: data for name, data in self.files.items() if not name.startswith(prefix)}
                archive = tar(files, {"format": 1, "damaged_blobs": [], "campaign_inventory": inventory}, "w:gz")
                checked = check_archive(archive, self.root)
                self.assertNotEqual(checked.returncode, 0)
                self.assertIn("server's captured inventory", checked.stderr)

    def test_campaign_files_without_inventory_are_refused(self) -> None:
        manifest = {"format": 1, "damaged_blobs": [], "campaign_inventory": None}
        checked = check_archive(tar(self.files, manifest, "w:gz"), self.root)
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("lack the server's captured inventory", checked.stderr)

    def test_only_campaign_files_need_campaign_store(self) -> None:
        standalone = self.root / "standalone"
        standalone.mkdir()
        shutil.copy(HERE / "snapshot.py", standalone)
        checked = self.check({"data/state.json": b"{}", f"data/blobs/{BLOB}": b"blob"}, standalone / "snapshot.py")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        checked = self.check(self.files, standalone / "snapshot.py")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("checking them needs campaign_store.py beside snapshot.py", checked.stderr)


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and hasattr(signal, "alarm"), "snapshot.py --socket needs Unix")
class CampaignSnapshotTest(unittest.TestCase):
    """snapshot.py checks the campaign files a server sends before it finishes an archive of them."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.files, self.campaign, _ = campaign_files(self.root / "campaigns")

    async def run_client(self, files: dict[str, bytes], inventory: dict | None = None) -> tuple[int, bytes, bytes]:
        """snapshot.py --socket from a server that sends `files` and a manifest that matches them."""
        manifest = {"format": 1, "created": 0, "damaged_blobs": []}
        if inventory is not None:
            manifest["campaign_inventory"] = inventory
        stream = b"pokopia-snapshot 1 ok\n" + tar(files, manifest, "w")

        async def send(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            with contextlib.suppress(OSError):  # a client that fails stops reading
                writer.write(stream)
                await writer.drain()
            writer.close()

        path = self.root / "snapshot.sock"
        listener = await asyncio.start_unix_server(send, path)
        try:
            client = await asyncio.create_subprocess_exec(
                sys.executable, str(HERE / "snapshot.py"), "--socket", str(path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            output, errors = await client.communicate()
        finally:
            listener.close()
            await listener.wait_closed()
        return client.returncode, output, errors

    def test_a_whole_campaign_registry_is_archived(self) -> None:
        returncode, output, errors = asyncio.run(self.run_client(self.files))
        self.assertEqual(returncode, 0, errors)
        with tarfile.open(fileobj=io.BytesIO(output), mode="r:gz") as archive:
            archived = {member.name: archive.extractfile(member).read() for member in archive}
        manifest = json.loads(archived.pop("snapshot.json"))
        self.assertEqual(archived, self.files)
        self.assertEqual(manifest["files"], {name: manifest_entry(data) for name, data in self.files.items()})
        self.assertEqual(manifest["campaign_inventory"],
                         {name: manifest_entry(data) for name, data in self.files.items()
                          if name.startswith("data/campaigns/")})
        checked = check_archive(output, self.root)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_snapshot_refuses_missing_captured_metadata(self) -> None:
        inventory = {name: manifest_entry(data) for name, data in self.files.items()
                     if name.startswith("data/campaigns/")}
        missing = f"data/campaigns/{self.campaign}/campaign.json"
        files = {name: data for name, data in self.files.items() if name != missing}
        returncode, output, errors = asyncio.run(self.run_client(files, inventory))
        self.assertNotEqual(returncode, 0)
        self.assertIn(b"server's captured inventory", errors)
        self.assertNotEqual(check_archive(output, self.root).returncode, 0)

    def test_campaign_files_that_do_not_hold_together_fail_the_snapshot(self) -> None:
        checkpoints = f"data/campaigns/{self.campaign}/checkpoints"
        story = json.loads(self.files[f"{checkpoints}/{4:020d}.json"])["story"]["sha256"]
        manifest = f"{checkpoints}/{3:020d}.json"
        cases = [
            ("a payload is missing",
             {name: data for name, data in self.files.items() if name != f"data/campaigns/{self.campaign}/objects/{story}"},
             f"payload {story} is missing"),
            ("a manifest is damaged", {**self.files, manifest: self.files[manifest][:-1]}, f"{manifest} is damaged"),
        ]
        for case, files, message in cases:
            with self.subTest(case):
                returncode, output, errors = asyncio.run(self.run_client(files))
                self.assertNotEqual(returncode, 0)
                self.assertIn(message.encode(), errors)
                # The archive is left unfinished, so nothing mistakes it for a complete one.
                self.assertNotEqual(check_archive(output, self.root).returncode, 0)


if __name__ == "__main__":
    unittest.main()
