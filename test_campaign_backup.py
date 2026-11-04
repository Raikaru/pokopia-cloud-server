"""Tests for CampaignRegistry.capture_backup and the snapshot names of its files: a backup holds the
whole registry, each campaign as it was at one moment, refuses damage rather than leave anything
out, keeps its payloads pinned, and restores no more access than there was.

Run it from this directory:

    python -m unittest test_campaign_backup
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Iterator
from unittest import mock

import campaign_store as cs
import snapshot
from test_campaign_store import common, stage_file

OWNER = "acct-owner"
FRIEND = "acct-friend"
PURGED = "acct-purged"
STRANGER = "acct-stranger"
CHUNK = 1000  # smaller than any payload, so that each is read in several steps


def contents(backup: cs.RegistryBackup) -> dict[str, bytes]:
    """Every file of the backup, read as a snapshot streams it."""
    files = {}
    for file in backup.files:
        chunks: list[bytes] = []
        offset = 0
        while offset < file.size:
            chunks.append(file.read(offset, CHUNK))
            offset += len(chunks[-1])
        files[file.path] = b"".join(chunks)
    return files


def restore(files: dict[str, bytes], root: Path) -> cs.CampaignRegistry:
    """A registry over `files`, written under the empty directory `root`."""
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return cs.CampaignRegistry(cs.CampaignStore(root, min_free_bytes=0))


@contextlib.contextmanager
def opened_files() -> Iterator[list[int]]:
    """Records every descriptor os.open returns meanwhile."""
    fds: list[int] = []
    real_open = os.open

    def recording(*args: object, **kwargs: object) -> int:
        fd = real_open(*args, **kwargs)
        fds.append(fd)
        return fd

    with mock.patch.object(cs.os, "open", recording):
        yield fds


class CampaignBackupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "campaigns"
        self.store = cs.CampaignStore(self.root, min_free_bytes=0)
        self.registry = cs.CampaignRegistry(self.store)

    def capture(self, registry: cs.CampaignRegistry | None = None) -> cs.RegistryBackup:
        backup = (registry or self.registry).capture_backup()
        self.addCleanup(backup.close)  # before the directory goes: Windows deletes no open file
        return backup

    def shared(self, owner: str, *members: str) -> cs.CampaignInfo:
        info = self.registry.create(owner)
        for member in members:
            info = self.registry.add_member(info.campaign, owner, member, if_match=info.etag)
        return info

    def restored(self, files: dict[str, bytes]) -> cs.CampaignRegistry:
        return restore(files, Path(self.directory.name) / "restored")

    def assertAllClosed(self, fds: list[int]) -> None:
        self.assertTrue(fds)
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def archive(self, files: dict[str, bytes]) -> Path:
        """A snapshot archive of `files`, as snapshot.py writes it."""
        manifest = {"format": 1, "server_time": 0, "extras_time": 0, "damaged_blobs": [],
                    "files": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                              for name, data in files.items()}}
        manifest["campaign_inventory"] = {name: info for name, info in manifest["files"].items()
                                          if name.startswith("data/campaigns/")}
        path = Path(self.directory.name) / "backup.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name, data in [*files.items(), ("snapshot.json", json.dumps(manifest).encode())]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def test_a_restored_backup_gives_the_access_there_was_and_no_more(self) -> None:
        info = self.shared(OWNER, FRIEND, PURGED)
        campaign = info.campaign
        head = None
        for seed in range(4):  # with the default retention, revisions 2 to 4 are kept
            head = self.registry.commit(campaign, FRIEND, head.etag if head else None, **common(seed),
                                        stages={1: stage_file(seed), seed + 2: stage_file(seed + 10)})
        gone = self.shared(OWNER, FRIEND)
        self.registry.delete(gone.campaign, OWNER)
        theirs = self.shared(PURGED, OWNER)
        self.registry.commit(theirs.campaign, OWNER, None, **common(7))
        self.assertEqual(self.registry.purge_account(PURGED), cs.PurgeResult((theirs.campaign,), (campaign,), ()))
        # What interrupted work leaves behind, which no backup holds.
        (self.root / campaign / "staging" / "leftover.tmp").write_bytes(b"part of a commit")
        (self.root / campaign / "objects" / ("0" * 64)).write_bytes(b"an orphan")
        (self.root / "abandoned").mkdir()  # a creation interrupted before its metadata
        (self.root / ".purged" / f"{'1' * 32}.tmp").write_bytes(b"{}")  # an interrupted purge
        live = self.registry.get(campaign, OWNER)
        history = self.registry.history(campaign, FRIEND)
        self.assertEqual([checkpoint.revision for checkpoint in history], [4, 3, 2])

        backup = self.capture()
        files = contents(backup)
        self.assertEqual(set(files), {
            f"{campaign}/campaign.json",
            *(f"{campaign}/checkpoints/{checkpoint.revision:020d}.json" for checkpoint in history),
            *(f"{campaign}/objects/{sha256}" for checkpoint in history for sha256 in checkpoint.objects()),
            f".deleted/{gone.campaign}", f".deleted/{theirs.campaign}",
            f".purged/{hashlib.sha256(PURGED.encode()).hexdigest()}"})
        self.assertEqual([file.path for file in backup.files], sorted(files))
        for file in backup.files:
            data = files[file.path]
            self.assertEqual((file.size, file.sha256), (len(data), hashlib.sha256(data).hexdigest()))
            self.assertTrue(snapshot.SERVER_FILE.fullmatch(f"data/campaigns/{file.path}"), file.path)
        self.assertEqual(backup.summary, {
            "format": cs.BACKUP_FORMAT, "created": backup.created,
            "campaigns": {campaign: {"metadata": {"revision": live.revision, "etag": live.etag},
                                     "checkpoints": [{"revision": checkpoint.revision, "etag": checkpoint.etag}
                                                     for checkpoint in reversed(history)]}},
            "deleted": 2, "purged": 1, "files": len(files), "bytes": sum(map(len, files.values()))})
        summary = json.dumps(backup.summary)
        for account in (OWNER, FRIEND, PURGED):
            self.assertNotIn(account, summary)

        restored = self.restored(files)
        self.assertEqual(restored.get(campaign, FRIEND), live)
        self.assertEqual(restored.history(campaign, OWNER), history)
        for checkpoint in history:
            self.assertEqual(restored.read(campaign, FRIEND, checkpoint.revision),
                             self.registry.read(campaign, FRIEND, checkpoint.revision))
        self.assertEqual(restored.accounts(), {OWNER, FRIEND})
        for account in (PURGED, STRANGER):
            with self.assertRaises(cs.CampaignNotFound):
                restored.get(campaign, account)
        for deleted in (gone.campaign, theirs.campaign):
            for account in (OWNER, FRIEND, PURGED):
                with self.assertRaises(cs.CampaignNotFound):
                    restored.get(deleted, account)
            with self.assertRaises(cs.CampaignNotFound):  # nor revived below the registry
                restored.store.commit(deleted, None, **common(9))
        with self.assertRaises(cs.AccountPurged):
            restored.create(PURGED)
        with self.assertRaises(cs.AccountPurged):
            restored.add_member(campaign, OWNER, PURGED, if_match=live.etag)
        self.assertEqual(restored.commit(campaign, OWNER, head.etag, **common(9)).revision, 5)

    def test_a_capture_sees_each_campaign_at_one_moment(self) -> None:
        first, second = sorted((self.shared(OWNER, FRIEND) for _ in range(2)), key=lambda info: info.campaign)
        heads = {info.campaign: self.registry.commit(info.campaign, OWNER, None, **common(1)) for info in (first, second)}
        impatient = cs.CampaignRegistry(cs.CampaignStore(self.root, min_free_bytes=0, lock_timeout=0.1))
        capture = cs.CampaignRegistry._capture_campaign
        meanwhile: list[str] = []

        def capturing(registry: cs.CampaignRegistry, backup: cs.RegistryBackup, directory: Path,
                      campaign: str) -> object:
            if campaign == second.campaign:
                # The campaign being captured waits, and so do creations and purges...
                for call in (lambda: impatient.remove_member(campaign, OWNER, FRIEND),
                             lambda: impatient.commit(campaign, OWNER, heads[campaign].etag, **common(2)),
                             lambda: impatient.create(OWNER), lambda: impatient.purge_account(FRIEND)):
                    with self.assertRaises(cs.CampaignBusy):
                        call()
                # ...but a campaign captured already may change: deleted now, it is restored deleted.
                impatient.delete(first.campaign, OWNER)
                meanwhile.append(campaign)
            return capture(registry, backup, directory, campaign)

        with mock.patch.object(cs.CampaignRegistry, "_capture_campaign", capturing):
            backup = self.capture()
        self.assertEqual(meanwhile, [second.campaign])
        self.assertFalse(self.registry.purged(FRIEND))
        self.assertEqual((self.registry.get(second.campaign, FRIEND), self.registry.head(second.campaign, FRIEND)),
                         (second, heads[second.campaign]))
        files = contents(backup)
        self.assertIn(f"{first.campaign}/campaign.json", files)  # captured before its deletion,
        self.assertIn(f".deleted/{first.campaign}", files)  # and its tombstone after
        restored = self.restored(files)
        for account in (OWNER, FRIEND):
            with self.assertRaises(cs.CampaignNotFound):
                restored.get(first.campaign, account)
        self.assertFalse((restored.store.root / first.campaign).exists())  # opening the store finished the deletion
        self.assertEqual((restored.get(second.campaign, FRIEND), restored.head(second.campaign, FRIEND)),
                         (second, heads[second.campaign]))

    def test_damage_is_refused_and_leaves_nothing_open(self) -> None:
        # The damaged campaign is captured last, when the good one's payloads are already held open.
        with mock.patch.object(cs, "_new_campaign_id", side_effect=["a" * 26, "b" * 26]):
            good, bad = self.shared(OWNER, FRIEND), self.shared(OWNER, FRIEND)
        self.registry.commit(good.campaign, OWNER, None, **common(1), stages={1: stage_file(1)})
        first = self.registry.commit(bad.campaign, OWNER, None, **common(2), stages={1: stage_file(2)})
        self.registry.commit(bad.campaign, OWNER, first.etag, **common(3))
        directory = self.root / bad.campaign
        metadata = directory / cs.METADATA_NAME
        older = directory / "checkpoints" / f"{1:020d}.json"
        payload = directory / "objects" / first.stages[1].sha256  # in the newest checkpoint too
        outside = Path(self.directory.name) / "outside"

        def replace(path: Path, data: bytes):
            original = path.read_bytes()
            path.write_bytes(data)
            return lambda: path.write_bytes(original)

        def remove(path: Path):
            original = path.read_bytes()
            path.unlink()
            return lambda: path.write_bytes(original)

        def make_directory(path: Path):
            path.mkdir()
            return path.rmdir

        def link(path: Path):  # to the very bytes its manifest records, outside the store
            outside.write_bytes(path.read_bytes())
            undo = remove(path)
            path.symlink_to(outside)
            return lambda: (path.unlink(), undo())

        cases = [
            ("metadata that is not JSON", cs.IntegrityError, lambda: replace(metadata, b"{")),
            ("metadata of a later format", cs.UnsupportedFormat,
             lambda: replace(metadata, metadata.read_bytes().replace(b'"format":1', b'"format":2'))),
            ("metadata over its limit", cs.IntegrityError, lambda: replace(metadata, b" " * (cs.MAX_METADATA_BYTES + 1))),
            ("an older manifest", cs.IntegrityError,
             lambda: replace(older, older.read_bytes().replace(b'"revision":1', b'"revision":2'))),
            ("a missing payload", cs.IntegrityError, lambda: remove(payload)),
            ("a short payload", cs.IntegrityError, lambda: replace(payload, payload.read_bytes()[:-1])),
            ("a tombstone that is no file", cs.IntegrityError, lambda: make_directory(self.root / ".deleted" / ("c" * 26))),
            ("a purge marker that is no file", cs.IntegrityError,
             lambda: make_directory(self.root / ".purged" / hashlib.sha256(STRANGER.encode()).hexdigest())),
        ]
        if os.name == "posix":  # links to files need privileges on Windows
            cases.append(("a payload that is a link", cs.IntegrityError, lambda: link(payload)))
        for name, error, damage in cases:
            with self.subTest(name):
                undo = damage()
                try:
                    with opened_files() as fds, self.assertRaises(error):
                        self.registry.capture_backup()
                    self.assertAllClosed(fds)
                finally:
                    undo()
        impatient = cs.CampaignRegistry(cs.CampaignStore(self.root, min_free_bytes=0, lock_timeout=0.1))
        for lock in (f"{cs.REGISTRY_LOCK}.lock", f"{bad.campaign}.lock"):
            with self.subTest(locked=lock), self.store._hold(lock, "the test"):
                with opened_files() as fds, self.assertRaises(cs.CampaignBusy):
                    impatient.capture_backup()
                self.assertAllClosed(fds)
        with self.capture() as backup:
            self.assertEqual(set(backup.summary["campaigns"]), {good.campaign, bad.campaign})

    def test_pinned_payloads_outlive_later_changes(self) -> None:
        registry = cs.CampaignRegistry(cs.CampaignStore(self.root, min_free_bytes=0, retain=0))
        info = registry.create(OWNER)
        first = registry.commit(info.campaign, OWNER, None, **common(1), stages={1: stage_file(1)})
        backup = self.capture(registry)
        # Later commits delete the captured payloads (Windows: once the backup is closed), and the
        # deletion the whole campaign.
        second = registry.commit(info.campaign, OWNER, first.etag, **common(2), stages={1: stage_file(2)})
        registry.commit(info.campaign, OWNER, second.etag, **common(3), stages={1: stage_file(3)})
        registry.delete(info.campaign, OWNER)
        copy = self.restored(contents(backup)).read(info.campaign, OWNER)
        self.assertEqual((copy.checkpoint, copy.story, copy.unique, dict(copy.stages)),
                         (first, common(1)["story"], common(1)["unique"], {1: stage_file(1)}))

    def test_a_damaged_payload_never_streams_complete(self) -> None:
        info = self.registry.create(OWNER)
        checkpoint = self.registry.commit(info.campaign, OWNER, None, **common(1), stages={1: stage_file(1)})
        path = self.root / info.campaign / "objects" / checkpoint.stages[1].sha256
        damaged = bytearray(path.read_bytes())
        damaged[-1] ^= 1  # the same size: the capture checks sizes, the stream hashes
        path.write_bytes(damaged)
        backup = self.capture()
        files = {file.path: file for file in backup.files}
        stage = files[f"{info.campaign}/objects/{checkpoint.stages[1].sha256}"]
        self.assertEqual(stage.read(0, stage.size - 1), bytes(damaged[:-1]))
        with self.assertRaises(cs.IntegrityError):  # the last byte does not go out
            stage.read(stage.size - 1, 1)
        with self.assertRaises(ValueError):  # and nothing more but from the start again
            stage.read(stage.size - 1, 1)
        story = files[f"{info.campaign}/objects/{checkpoint.story.sha256}"]
        with self.assertRaises(ValueError):  # no skipping ahead, so nothing goes out unchecked
            story.read(10, 10)
        self.assertEqual(story.read(0, 10), common(1)["story"][:10])
        with self.assertRaises(ValueError):
            story.read(20, 10)
        self.assertEqual(story.read(10, story.size), common(1)["story"][10:])
        self.assertEqual(story.read(story.size, 10), b"")
        backup.close()
        backup.close()
        with self.assertRaises(ValueError):
            story.read(0, 10)

    def test_snapshot_names_admit_the_backup_files_and_nothing_else(self) -> None:
        campaign, sha256 = "a" * 26, "0" * 64
        admitted = [f"data/campaigns/{campaign}/campaign.json", f"data/campaigns/{campaign}/checkpoints/{7:020d}.json",
                    f"data/campaigns/{campaign}/objects/{sha256}", f"data/campaigns/.deleted/{campaign}",
                    f"data/campaigns/.purged/{sha256}", f"data/campaigns/{'x' * 64}/campaign.json",
                    "data/campaigns/console/campaign.json", "data/campaigns/com10/campaign.json"]
        refused = ["data/campaigns", "data/campaigns/", f"data/campaigns/{campaign}", "data/campaigns/../state.json",
                   f"data/campaigns/{campaign}/../../state.json", f"data/campaigns/./{campaign}/campaign.json",
                   f"/data/campaigns/{campaign}/campaign.json", f"data\\campaigns\\{campaign}\\campaign.json",
                   f"data/campaigns/{campaign}//campaign.json", f"data/campaigns/{campaign}/campaign.json/",
                   f"data/campaigns/{campaign}/campaign.json\n", f"data/campaigns/{campaign}/staging/x.tmp",
                   "data/campaigns/.locks/_registry.lock", f"data/campaigns/.locks/{campaign}.lock",
                   f"data/campaigns/.trash/{campaign}.0123456789abcdef/campaign.json",
                   f"data/campaigns/{campaign}/checkpoints/7.json", f"data/campaigns/{campaign}/objects/{'A' * 64}",
                   f"data/campaigns/{campaign}/objects/{sha256[:-1]}", f"data/campaigns/.purged/{sha256}.tmp",
                   f"data/campaigns/.deleted/{campaign}/campaign.json", "data/campaigns/.deleted/lpt1"]
        for name in admitted:
            self.assertEqual(snapshot.archive_name(name), name)
        for name in refused:
            with self.subTest(name=name), self.assertRaises(argparse.ArgumentTypeError):
                snapshot.archive_name(name)
        # Exactly the campaign IDs of the store.
        for campaign in ("a", "0", "a" * 64, "a" * 65, "aux_", "a-b_c", "con", "nul", "com1", "lpt9", "-a",
                         "_registry", "A", "a.b", "a b", "\u00e9", ""):
            with self.subTest(campaign=campaign):
                for name in (f"data/campaigns/{campaign}/campaign.json", f"data/campaigns/.deleted/{campaign}"):
                    self.assertEqual(snapshot.SERVER_FILE.fullmatch(name) is not None, cs._valid_id(campaign))

        # --check admits an archive with the backup's files, and refuses one with anything else.
        info = self.registry.create(OWNER)
        self.registry.commit(info.campaign, OWNER, None, **common(1))
        files = {"data/state.json": b"{}",
                 **{f"data/campaigns/{path}": data for path, data in contents(self.capture()).items()}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            snapshot.check(self.archive(files), [f"data/campaigns/{info.campaign}/campaign.json"])
        self.assertEqual(output.getvalue().splitlines(),
                         [f"{hashlib.sha256(data).hexdigest()}  {name}" for name, data in sorted(files.items())])
        for name in ("data/campaigns/../state.json", f"data/campaigns/{info.campaign}/staging/x.tmp"):
            with self.subTest(name), self.assertRaisesRegex(RuntimeError, "unexpected file"):
                snapshot.check(self.archive({**files, name: b"x"}), [])


if __name__ == "__main__":
    unittest.main()
