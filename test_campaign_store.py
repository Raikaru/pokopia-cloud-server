"""Tests for campaign_store: durable, versioned checkpoints of shared story campaigns.

Run it from this directory:

    python -m unittest test_campaign_store
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import struct
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from unittest import mock

import campaign_store as cs


def story(seed: int) -> bytes:
    return bytes((seed * 7 + i) % 256 for i in range(cs.STORY_BLOCK_SIZE))


def unique(seed: int) -> bytes:
    """An m_uniqueQuestHistoryVer2 region: 256 records of 4 bytes."""
    return bytes((seed * 11 + i * 5) % 256 for i in range(cs.UNIQUE_SIZE))


def common(seed: int) -> dict[str, bytes]:
    """The story block and unique quest history of one common save, as commit takes them."""
    return {"story": story(seed), "unique": unique(seed)}


def stage_file(seed: int, raw_size: int = 4096, trailing: bytes = b"") -> bytes:
    """A local STGDATnn.BIN as the game writes it: header, one zlib stream, maybe leftovers."""
    raw = bytes((seed + i * 13) % 251 for i in range(raw_size))
    stream = zlib.compress(raw, 9)
    header = bytearray(cs.STAGE_HEADER_SIZE)
    struct.pack_into("<II", header, 0, cs.SAVE_MAGIC, cs.STAGE_VERSION)
    header[cs.SAVE_FLAGS_OFFSET] = cs.SAVE_COMPRESSED_FLAG
    struct.pack_into("<i", header, cs.SAVE_END_OFFSET, cs.STAGE_HEADER_SIZE + len(stream))
    return bytes(header) + stream + trailing


def encode(doc: dict) -> bytes:
    """A manifest document as campaign_store writes it."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")


class CampaignStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "campaigns"
        self.store = cs.CampaignStore(self.root, min_free_bytes=0)

    def store_with(self, **limits) -> cs.CampaignStore:
        return cs.CampaignStore(self.root, min_free_bytes=0, **limits)

    def objects(self, campaign: str) -> set[str]:
        return set(os.listdir(self.root / campaign / "objects"))

    def manifest(self, campaign: str, revision: int) -> Path:
        return self.root / campaign / "checkpoints" / f"{revision:020d}.json"

    def test_commit_reads_back_exactly(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1, trailing=b"old")},
                                  author="account-a")
        self.assertEqual((first.revision, first.parent, first.author), (1, None, "account-a"))
        self.assertEqual(first.unique, cs.UniqueInfo(hashlib.sha256(unique(1)).hexdigest(), cs.UNIQUE_SIZE))
        data = self.store.read("map1")
        self.assertEqual(data.checkpoint, first)
        self.assertEqual((data.story, data.unique), (story(1), unique(1)))
        self.assertEqual(dict(data.stages), {1: stage_file(1, trailing=b"old")})
        self.assertEqual(self.store.head("map1"), first)
        self.assertEqual(self.store.campaigns(), ["map1"])

    def test_a_new_store_recovers_story_unique_history_and_stages(self) -> None:
        # Every byte value in every record position, so that any lossy round trip would show.
        history = bytes(range(256)) * (cs.UNIQUE_SIZE // 256)
        first = self.store.commit("map1", None, story=story(1), unique=history, stages={1: stage_file(1)})
        manifest = json.loads(self.manifest("map1", 1).read_bytes())
        self.assertEqual(manifest["format"], 2)
        self.assertEqual(manifest["unique_quest_history"], {
            "format": "pokopia-2.0.1-unique-quest-history-ver2", "payload_version": 1,
            "common_version": 0x0200017D, "offset": 0x427764, "record_size": 4, "size": 0x400,
            "sha256": hashlib.sha256(history).hexdigest()})
        self.assertEqual((self.root / "map1" / "objects" / first.unique.sha256).read_bytes(), history)
        reopened = cs.CampaignStore(self.root, min_free_bytes=0)
        data = reopened.read("map1")
        self.assertEqual((data.checkpoint, data.story, data.unique, dict(data.stages)),
                         (first, story(1), history, {1: stage_file(1)}))
        with reopened.open("map1") as opened:
            self.assertEqual(opened.read_unique(), history)

    def test_stale_etag_cannot_overwrite(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        second = self.store.commit("map1", first.etag, **common(2))
        self.assertEqual((second.revision, second.parent), (2, first.etag))
        with self.assertRaises(cs.RevisionConflict) as caught:
            self.store.commit("map1", first.etag, **common(3))
        self.assertEqual(caught.exception.current, second)
        with self.assertRaises(cs.RevisionConflict):
            self.store.commit("map1", first.etag, story=story(2), unique=unique(3))
        with self.assertRaises(cs.RevisionConflict):
            self.store.commit("map1", None, **common(3))
        data = self.store.read("map1")
        self.assertEqual((data.story, data.unique), (story(2), unique(2)))

    def test_quest_states_may_go_back(self) -> None:
        # The store does not interpret the payloads: a later checkpoint may hold "lower" quest states.
        high = {"story": bytes([4]) * cs.STORY_BLOCK_SIZE, "unique": bytes([4]) * cs.UNIQUE_SIZE}
        low = {"story": bytes([1]) * cs.STORY_BLOCK_SIZE, "unique": bytes([1]) * cs.UNIQUE_SIZE}
        first = self.store.commit("map1", None, **high)
        self.store.commit("map1", first.etag, **low)
        data = self.store.read("map1")
        self.assertEqual({"story": data.story, "unique": data.unique}, low)

    def test_partial_updates_keep_and_drop_stages(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1), 2: stage_file(2)})
        second = self.store.commit("map1", first.etag, stages={2: stage_file(3), 3: stage_file(4)})
        self.assertEqual((second.story, second.unique), (first.story, first.unique))
        data = self.store.read("map1")
        self.assertEqual((data.story, data.unique), (story(1), unique(1)))
        self.assertEqual(dict(data.stages), {1: stage_file(1), 2: stage_file(3), 3: stage_file(4)})
        self.store.commit("map1", second.etag, stages={1: None, 9: None})
        self.assertEqual(sorted(self.store.read("map1").stages), [2, 3])

    def test_unchanged_commit_makes_no_revision(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        again = self.store.commit("map1", first.etag, **common(1), stages={1: stage_file(1)})
        self.assertEqual(again, first)
        self.assertEqual([c.revision for c in self.store.history("map1")], [1])
        # A unique quest history that changes alone is a change.
        second = self.store.commit("map1", first.etag, story=story(1), unique=unique(2))
        self.assertEqual((second.revision, second.story), (2, first.story))
        self.assertEqual(self.store.read("map1").unique, unique(2))

    def test_first_checkpoint_needs_story_and_unique_history(self) -> None:
        for payloads in ({"stages": {1: stage_file(1)}}, {"story": story(1)}, {"unique": unique(1)},
                         {"story": story(1), "stages": {1: stage_file(1)}}):
            with self.subTest(sorted(payloads)):
                with self.assertRaises(cs.PayloadError):
                    self.store.commit("map1", None, **payloads)
        self.assertIsNone(self.store.head("map1"))
        self.assertEqual(self.store.campaigns(), [])

    def test_story_and_unique_history_are_committed_together(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        for payloads in ({"story": story(2)}, {"unique": unique(2)}, {"unique": unique(2), "stages": {1: None}}):
            with self.subTest(sorted(payloads)):
                with self.assertRaises(cs.PayloadError):
                    self.store.commit("map1", first.etag, **payloads)
        self.assertEqual(self.store.head("map1"), first)
        self.assertEqual(self.objects("map1"), set(first.objects()))

    def test_unique_history_must_be_whole(self) -> None:
        self.assertEqual(cs.check_unique_history(bytearray(unique(1))), unique(1))
        self.assertEqual(cs.check_unique_history(memoryview(unique(1))), unique(1))
        for name, bad in (("empty", b""), ("short", unique(1)[:-1]), ("long", unique(1) + b"\0"),
                          ("story block", story(1)), ("text", "x" * cs.UNIQUE_SIZE), ("list", list(unique(1)))):
            with self.subTest(name):
                with self.assertRaises(cs.PayloadError):
                    cs.check_unique_history(bad)
                with self.assertRaises(cs.PayloadError):
                    self.store.commit("map1", None, story=story(1), unique=bad)
        self.assertIsNone(self.store.head("map1"))

    def test_campaign_ids_cannot_leave_the_store(self) -> None:
        for bad in ("", "../x", "..", "a/b", "a\\b", "Map1", ".locks", "con", "lpt1", "x" * 65, "-x", "a.b", None):
            with self.subTest(campaign=bad):
                with self.assertRaises(cs.InvalidCampaignId):
                    self.store.commit(bad, None, **common(1))
        self.assertEqual(self.store.campaigns(), [])

    def test_only_local_stage_files_are_accepted(self) -> None:
        good = stage_file(1)
        cloud = zlib.compress(good, 9)  # a Cloud Island StageData blob
        truncated = good[:-10]  # the header's end lies past the file
        cut_stream = bytearray(good[:-10])  # the stream stops early, where the header says it ends
        struct.pack_into("<i", cut_stream, cs.SAVE_END_OFFSET, len(cut_stream))
        end = struct.unpack_from("<i", good, cs.SAVE_END_OFFSET)[0]
        short_end = bytearray(good)
        struct.pack_into("<i", short_end, cs.SAVE_END_OFFSET, end + 4)  # end past the stream
        wrong_version = bytearray(good)
        struct.pack_into("<I", wrong_version, 4, cs.COMMON_VERSION)
        uncompressed = bytearray(good)
        uncompressed[cs.SAVE_FLAGS_OFFSET] = 0
        self.assertEqual(cs.check_stage_file(good), 4096)
        self.assertEqual(cs.check_stage_file(stage_file(1, trailing=b"leftover")), 4096)
        for name, data in (("cloud", cloud), ("truncated", truncated), ("cut stream", bytes(cut_stream)),
                           ("end past stream", bytes(short_end) + b"pad!"),
                           ("version", bytes(wrong_version)), ("uncompressed", bytes(uncompressed)),
                           ("header", good[:0x100]), ("text", "STGDAT")):
            with self.subTest(name):
                with self.assertRaises(cs.PayloadError):
                    self.store.commit("map1", None, **common(1), stages={1: data})
        with self.assertRaisesRegex(cs.PayloadError, "Cloud Island"):
            cs.check_stage_file(cloud)
        for number in (-1, 100, "01", True):
            with self.subTest(number=number):
                with self.assertRaises(cs.PayloadError):
                    self.store.commit("map1", None, **common(1), stages={number: good})
        with self.assertRaises(cs.PayloadError):
            self.store.commit("map1", None, story=story(1)[:-1], unique=unique(1))
        self.assertIsNone(self.store.head("map1"))

    def test_limits_fail_before_anything_is_stored(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        small = self.store_with(max_stage_bytes=1000)
        with self.assertRaises(cs.PayloadTooLarge) as caught:
            small.commit("map1", first.etag, stages={1: stage_file(1, raw_size=100_000) + bytes(2000)})
        self.assertEqual(caught.exception.limit, 1000)
        with self.assertRaises(cs.PayloadTooLarge):
            self.store_with(max_stage_raw_bytes=1000).commit("map1", first.etag, stages={1: stage_file(1)})
        with self.assertRaises(cs.PayloadTooLarge):
            self.store_with(max_stages=1).commit("map1", first.etag, stages={1: stage_file(1), 2: stage_file(2)})
        size = cs.STORY_BLOCK_SIZE + cs.UNIQUE_SIZE + len(stage_file(1))
        with self.assertRaises(cs.PayloadTooLarge) as caught:
            self.store_with(max_checkpoint_bytes=size - 1).commit("map1", first.etag, stages={1: stage_file(1)})
        self.assertEqual((caught.exception.size, caught.exception.limit), (size, size - 1))
        with self.assertRaises(cs.QuotaExceeded):
            self.store_with(max_campaign_bytes=size).commit("map1", first.etag, stages={1: stage_file(1)})
        with self.assertRaises(cs.QuotaExceeded):
            cs.CampaignStore(self.root, min_free_bytes=1 << 62).commit("map1", first.etag, stages={1: stage_file(1)})
        self.assertEqual(self.store.head("map1"), first)
        self.assertEqual(self.objects("map1"), {first.story.sha256, first.unique.sha256})
        # The unique quest history counts towards the checkpoint limit, exactly once.
        second = self.store_with(max_checkpoint_bytes=size).commit("map1", first.etag, stages={1: stage_file(1)})
        self.assertEqual((second.revision, sorted(second.stages)), (2, [1]))

    def test_usage_counts_each_payload_once(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        self.assertEqual(self.store.usage("map1"),
                         self.manifest("map1", 1).stat().st_size + cs.STORY_BLOCK_SIZE + cs.UNIQUE_SIZE)
        second = self.store.commit("map1", first.etag, story=story(2), unique=unique(1))
        self.assertEqual(second.unique, first.unique)
        self.assertEqual(self.store.usage("map1"),
                         self.manifest("map1", 1).stat().st_size + self.manifest("map1", 2).stat().st_size
                         + 2 * cs.STORY_BLOCK_SIZE + cs.UNIQUE_SIZE)

    def test_interrupted_manifest_rename_keeps_previous_checkpoint(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        publish = cs._publish

        def crash_on_manifest(temp: Path, path: Path) -> bool:
            if path.parent.name == "checkpoints":
                raise OSError(errno.EIO, "simulated crash")
            return publish(temp, path)

        with mock.patch.object(cs, "_publish", crash_on_manifest):
            with self.assertRaises(cs.StorageError) as caught:
                self.store.commit("map1", first.etag, **common(2), stages={1: stage_file(2)})
        self.assertIsNone(caught.exception.committed)
        data = self.store.read("map1")
        self.assertEqual((data.checkpoint, data.story, data.unique, dict(data.stages)),
                         (first, story(1), unique(1), {1: stage_file(1)}))
        self.assertTrue(os.listdir(self.root / "map1" / "staging"))
        second = self.store.commit("map1", first.etag, **common(3))
        self.assertEqual(os.listdir(self.root / "map1" / "staging"), [])
        data = self.store.read("map1")
        self.assertEqual((data.story, data.unique), (story(3), unique(3)))
        # The payloads the interrupted commit left behind are collected.
        self.assertEqual(self.objects("map1"), set(first.objects()) | set(second.objects()))

    def test_failed_flush_keeps_previous_checkpoint(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        with mock.patch.object(cs, "_sync_fd", side_effect=OSError(errno.EIO, "simulated I/O error")):
            with self.assertRaises(cs.StorageError) as caught:
                self.store.commit("map1", first.etag, **common(2))
        self.assertIs(caught.exception.committed, False)
        data = self.store.read("map1")
        self.assertEqual((data.story, data.unique), (story(1), unique(1)))

    def test_unpromised_flush_publishes_nothing(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        with mock.patch.object(cs, "_sync_fd", return_value=False):
            with self.assertRaises(cs.DurabilityError) as caught:
                self.store.commit("map1", first.etag, **common(2))
        self.assertIs(caught.exception.committed, False)
        self.assertEqual(self.store.head("map1"), first)

    def test_a_fence_decides_with_the_payloads_written_and_nothing_published(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        before = self.store.usage("map1")
        seen: list[object] = []

        def fence(intent: cs.CommitIntent) -> cs.Settle:
            seen.append((intent, os.listdir(self.root / "map1" / "checkpoints"), self.objects("map1")))
            return seen.append

        second = self.store.commit("map1", first.etag, **common(2), stages={2: stage_file(2)}, author="host",
                                   fence=fence)
        (intent, manifests, objects), measured = seen
        self.assertEqual(intent, cs.CommitIntent("map1", None, second, before, self.store.usage("map1")))
        self.assertEqual(manifests, [self.manifest("map1", 1).name])  # the fence came before the rename
        self.assertLessEqual(set(second.objects()), objects)  # and after every payload was written
        self.assertEqual(measured, self.store.usage("map1"))
        self.assertEqual(self.store.head("map1"), second)
        # A commit that changes nothing publishes nothing, so its fence is not asked.
        self.assertEqual(self.store.commit("map1", second.etag, **common(2), fence=fence), second)
        self.assertEqual(len(seen), 2)

    def test_a_refusing_fence_publishes_nothing_and_takes_back_its_payloads(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        kept = self.objects("map1")

        class Refused(Exception):
            pass

        def refuse(intent: cs.CommitIntent) -> None:
            self.assertLess(set(first.objects()), self.objects("map1"))  # the new payloads are written
            raise Refused()

        with self.assertRaises(Refused):  # stage 1 is sent again, unchanged: it stays
            self.store.commit("map1", first.etag, **common(2), stages={1: stage_file(1), 2: stage_file(2)},
                              fence=refuse)
        self.assertEqual(self.store.head("map1"), first)
        self.assertEqual(self.objects("map1"), kept)
        second = self.store.commit("map1", first.etag, **common(2), fence=lambda intent: None)
        self.assertEqual((second.revision, second.parent), (2, first.etag))

    def test_a_settle_learns_what_a_failed_publication_left(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        settled: list[int | None] = []
        publish = cs._publish

        def crash_on_manifest(temp: Path, path: Path) -> bool:
            if path.parent.name == "checkpoints":
                raise OSError(errno.EIO, "simulated crash")
            return publish(temp, path)

        with mock.patch.object(cs, "_publish", crash_on_manifest):
            with self.assertRaises(cs.StorageError) as caught:
                self.store.commit("map1", first.etag, **common(2), fence=lambda intent: settled.append)
        self.assertIsNone(caught.exception.committed)
        self.assertEqual(settled, [self.store.usage("map1")])
        self.assertEqual(self.store.head("map1"), first)

        def broken(measured: int | None) -> None:
            raise RuntimeError("the settle failed")

        with self.assertLogs("npln.campaign", "ERROR"):  # logged, not passed on: the commit landed
            second = self.store.commit("map1", first.etag, **common(3), fence=lambda intent: broken)
        self.assertEqual(self.store.head("map1"), second)

    def test_damaged_payload_is_detected_and_can_be_replaced(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        path = self.root / "map1" / "objects" / first.stages[1].sha256
        damaged = bytearray(path.read_bytes())
        damaged[-1] ^= 0xFF
        path.write_bytes(bytes(damaged))
        with self.assertRaises(cs.IntegrityError):
            self.store.read("map1")
        with self.assertRaises(cs.IntegrityError):
            self.store.commit("map1", first.etag, **common(2))  # would keep the damaged stage
        self.assertEqual(self.store.head("map1"), first)
        second = self.store.commit("map1", first.etag, stages={1: stage_file(1)})
        self.assertEqual((second.revision, second.parent), (2, first.etag))  # same content, file rewritten
        self.assertEqual(dict(self.store.read("map1").stages), {1: stage_file(1)})
        self.assertEqual(self.store.commit("map1", second.etag, stages={1: stage_file(1)}), second)

    def test_damaged_unique_history_fails_closed(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        path = self.root / "map1" / "objects" / first.unique.sha256
        damaged = bytearray(unique(1))
        damaged[3] ^= 0x01  # byte 3 of record 0, whose meaning is unknown
        path.write_bytes(bytes(damaged))
        with self.assertRaises(cs.IntegrityError):
            self.store.read("map1")
        with self.store.open("map1") as opened:
            self.assertEqual(opened.read_story(), story(1))
            with self.assertRaises(cs.IntegrityError):
                opened.read_unique()
            with self.assertRaises(cs.IntegrityError):
                opened.verify()
        with self.assertRaises(cs.IntegrityError):
            self.store.commit("map1", first.etag, stages={1: stage_file(2)})  # would keep the damaged history
        self.assertEqual(self.store.head("map1"), first)
        path.write_bytes(unique(1)[:-1])
        with self.assertRaises(cs.IntegrityError):
            self.store.open("map1")
        # Sending the same history again rewrites the file, in a new revision.
        second = self.store.commit("map1", first.etag, **common(1))
        self.assertEqual((second.revision, second.unique), (2, first.unique))
        self.assertEqual(self.store.read("map1").unique, unique(1))

    def test_missing_payload_is_detected(self) -> None:
        for campaign, kind in (("map1", "story"), ("map2", "unique")):
            with self.subTest(kind):
                checkpoint = self.store.commit(campaign, None, **common(1))
                (self.root / campaign / "objects" / getattr(checkpoint, kind).sha256).unlink()
                with self.assertRaises(cs.IntegrityError):
                    self.store.read(campaign)

    def test_damaged_manifest_is_detected(self) -> None:
        self.store.commit("map1", None, **common(1))
        path = self.manifest("map1", 1)
        path.write_bytes(path.read_bytes().replace(b'"revision":1', b'"revision":2'))
        with self.assertRaises(cs.IntegrityError):
            self.store.head("map1")
        path.write_bytes(b"{not json")
        with self.assertRaises(cs.IntegrityError):
            self.store.read("map1")

    def test_manifest_cannot_reuse_one_hash_for_different_sizes(self) -> None:
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        path = self.manifest("map1", 1)
        doc = json.loads(path.read_bytes())
        doc["story"]["sha256"] = doc["unique_quest_history"]["sha256"]
        path.write_bytes(encode(doc))
        for call in (lambda: self.store.head("map1"), lambda: self.store.open("map1"),
                     lambda: self.store.read("map1"), lambda: self.store.commit("map1", first.etag, **common(2))):
            with self.assertRaisesRegex(cs.IntegrityError, "conflicting sizes"):
                call()

    def test_incompatible_or_damaged_unique_entries_are_refused(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        path = self.manifest("map1", 1)
        original = json.loads(path.read_bytes())

        def entry(**changes: object):
            return lambda doc: doc["unique_quest_history"].update(changes)

        unsupported = {
            "payload version 2": entry(payload_version=2),
            "payload version true": entry(payload_version=True),
            "payload version 1.0": entry(payload_version=1.0),
            "another format": entry(format="pokopia-2.0.1-unique-quest-history-ver3"),
            "another save version": entry(common_version=cs.COMMON_VERSION + 1),
            "another offset": entry(offset=cs.UNIQUE_OFFSET + cs.UNIQUE_RECORD),
            "another record size": entry(record_size=8),
            "manifest format 2.0": lambda doc: doc.update(format=2.0),
            "manifest format 3": lambda doc: doc.update(format=3),
        }
        damaged = {
            "no unique entry": lambda doc: doc.pop("unique_quest_history"),
            "unique entry null": lambda doc: doc.update(unique_quest_history=None),
            "no sha256": lambda doc: doc["unique_quest_history"].pop("sha256"),
            "extra field": entry(records=256),
            "another size": entry(size=cs.UNIQUE_SIZE + 1),
            "size as text": entry(size=str(cs.UNIQUE_SIZE)),
            "malformed sha256": entry(sha256="0" * 63),
        }
        for expected, cases in ((cs.UnsupportedFormat, unsupported), (cs.IntegrityError, damaged)):
            for name, change in cases.items():
                with self.subTest(name):
                    doc = json.loads(encode(original))
                    change(doc)
                    path.write_bytes(encode(doc))
                    for call in (lambda: self.store.head("map1"), lambda: self.store.read("map1"),
                                 lambda: self.store.commit("map1", first.etag, **common(2))):
                        with self.assertRaises(expected) as caught:
                            call()
                        if expected is cs.IntegrityError:
                            self.assertNotIsInstance(caught.exception, cs.UnsupportedFormat)
        path.write_bytes(encode(original))
        self.assertEqual(self.store.head("map1"), first)
        self.assertEqual(os.listdir(self.root / "map1" / "checkpoints"), [f"{1:020d}.json"])
        self.assertEqual(self.objects("map1"), set(first.objects()))

    def test_format_1_checkpoints_are_refused_not_upgraded(self) -> None:
        # A checkpoint from before the unique quest history was kept: story block and stages only.
        first = self.store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        path = self.manifest("map1", 1)
        doc = json.loads(path.read_bytes())
        del doc["unique_quest_history"]
        doc["format"] = 1
        path.write_bytes(encode(doc))
        legacy = hashlib.sha256(path.read_bytes()).hexdigest()
        for call in (lambda: self.store.head("map1"), lambda: self.store.history("map1"),
                     lambda: self.store.open("map1"), lambda: self.store.read("map1"),
                     lambda: self.store.commit("map1", legacy, **common(2)),
                     lambda: self.store.commit("map1", legacy, stages={2: stage_file(2)})):
            with self.assertRaisesRegex(cs.UnsupportedFormat, "format 1 has no unique quest history"):
                call()
        with self.assertRaisesRegex(cs.UnsupportedFormat, "format 1 has no unique quest history"):
            cs.CampaignRegistry(self.store).capture_backup()  # refused, not left out of the backup
        self.assertEqual(os.listdir(self.root / "map1" / "checkpoints"), [f"{1:020d}.json"])
        self.assertEqual(self.objects("map1"), set(first.objects()))
        self.assertTrue(self.store.delete("map1"))  # what is left to do with it; a new campaign takes a new ID
        self.assertEqual(self.store.campaigns(), [])

    def test_retention_collects_unreferenced_payloads(self) -> None:
        store = self.store_with(retain=1)
        head = store.commit("map1", None, **common(0), stages={1: stage_file(0)})
        for seed in range(1, 4):
            head = store.commit("map1", head.etag, **common(seed), stages={1: stage_file(seed)})
        history = store.history("map1")
        self.assertEqual([c.revision for c in history], [4, 3])
        self.assertEqual(self.objects("map1"), {sha for c in history for sha in c.objects()})
        self.assertEqual(len(self.objects("map1")), 6)  # story block, unique quest history and stage, twice
        data = store.read("map1", 3)
        self.assertEqual((data.story, data.unique), (story(2), unique(2)))
        with self.assertRaises(cs.CampaignNotFound):
            store.read("map1", 2)
        self.assertEqual(store.usage("map1"), sum(
            self.manifest("map1", c.revision).stat().st_size for c in history)
            + sum(size for c in history for size in c.objects().values()))

    def test_retention_keeps_a_unique_history_still_referenced(self) -> None:
        store = self.store_with(retain=0)
        first = store.commit("map1", None, **common(1))
        second = store.commit("map1", first.etag, story=story(2), unique=unique(1))
        self.assertEqual(self.objects("map1"), {second.story.sha256, first.unique.sha256})
        self.assertEqual(store.read("map1").unique, unique(1))

    def test_open_checkpoint_outlives_later_commits(self) -> None:
        store = self.store_with(retain=0)
        first = store.commit("map1", None, **common(1), stages={1: stage_file(1)})
        with store.open("map1") as opened:
            self.assertEqual(opened.manifest_path, f"map1/checkpoints/{1:020d}.json")
            self.assertEqual({o.path for o in opened.objects}, {f"map1/objects/{sha}" for sha in first.objects()})
            second = store.commit("map1", first.etag, **common(2), stages={1: stage_file(2)})
            self.assertEqual(opened.read_story(), story(1))
            self.assertEqual(opened.read_unique(), unique(1))
            self.assertEqual(opened.read_stage(1), stage_file(1))
            opened.verify()
        # Windows cannot delete files while they are open; the next commit collects them.
        third = store.commit("map1", second.etag, stages={2: stage_file(9)})
        self.assertEqual(self.objects("map1"), set(third.objects()))

    def test_lock_excludes_other_callers(self) -> None:
        self.store.commit("map1", None, **common(1))
        impatient = cs.CampaignStore(self.root, min_free_bytes=0, lock_timeout=0.1)
        with self.store._locked("map1"):
            with self.assertRaises(cs.CampaignBusy):
                impatient.head("map1")
            self.assertIsNone(impatient.head("map2"))  # other campaigns are not held up
        self.assertIsNotNone(impatient.head("map1"))

    def test_concurrent_writers_lose_no_updates(self) -> None:
        def counter(block: bytes) -> int:
            return int.from_bytes(block[:4], "little")

        def with_counter(value: int) -> dict[str, bytes]:
            mark = value.to_bytes(4, "little")
            return {"story": mark + bytes(cs.STORY_BLOCK_SIZE - 4), "unique": mark + bytes(cs.UNIQUE_SIZE - 4)}

        self.store.commit("map1", None, **with_counter(0))
        errors: list[BaseException] = []

        def worker() -> None:
            store = cs.CampaignStore(self.root, min_free_bytes=0, lock_timeout=30)
            try:
                for _ in range(5):
                    while True:
                        data = store.read("map1")
                        if counter(data.story) != counter(data.unique):
                            raise AssertionError("story block and unique quest history were committed apart")
                        try:
                            store.commit("map1", data.checkpoint.etag, **with_counter(counter(data.story) + 1))
                            break
                        except cs.RevisionConflict:
                            continue
            except BaseException as exc:  # reported by the main thread
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        data = self.store.read("map1")
        self.assertEqual((counter(data.story), counter(data.unique), data.checkpoint.revision), (20, 20, 21))

    def test_delete(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        with self.assertRaises(cs.RevisionConflict):
            self.store.delete("map1", if_match="0" * 64)
        self.assertTrue(self.store.delete("map1", if_match=first.etag))
        self.assertFalse(self.store.delete("map1"))
        self.assertIsNone(self.store.head("map1"))
        with self.assertRaises(cs.CampaignNotFound):
            self.store.read("map1")
        self.assertEqual(self.store.campaigns(), [])
        self.assertEqual(os.listdir(self.root / ".trash"), [])
        # A deleted ID is never used again, not even by a commit that expects no checkpoint.
        with self.assertRaises(cs.CampaignNotFound):
            self.store.commit("map1", None, **common(2))
        self.assertFalse((self.root / "map1").exists())
        self.assertEqual(os.listdir(self.root / ".deleted"), ["map1"])

    def test_deletion_interrupted_after_its_tombstone_is_finished_later(self) -> None:
        self.store.commit("map1", None, **common(1))
        with mock.patch.object(cs, "_move_directory", side_effect=OSError(errno.EACCES, "simulated: files open")):
            self.assertTrue(self.store.delete("map1"))
        self.assertTrue((self.root / "map1").is_dir())  # left in place, but served by nothing
        self.assertEqual(self.store.campaigns(), [])
        with cs.CampaignRegistry(self.store).capture_backup() as backup:  # its tombstone, nothing of its directory
            self.assertEqual([file.path for file in backup.files], [".deleted/map1"])
        self.assertIsNone(self.store.head("map1"))
        self.assertEqual(self.store.usage("map1"), 0)
        with self.assertRaises(cs.CampaignNotFound):
            self.store.open("map1")
        with self.assertRaises(cs.CampaignNotFound):
            self.store.commit("map1", None, **common(2))
        self.assertFalse(self.store.delete("map1"))
        cs.CampaignStore(self.root, min_free_bytes=0)  # opening the store finishes the deletion
        self.assertFalse((self.root / "map1").exists())
        self.assertEqual(os.listdir(self.root / ".trash"), [])

    @unittest.skipUnless(os.name == "posix", "file modes are POSIX")
    def test_files_are_private(self) -> None:
        first = self.store.commit("map1", None, **common(1))
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        for sha256 in (first.story.sha256, first.unique.sha256):
            self.assertEqual((self.root / "map1" / "objects" / sha256).stat().st_mode & 0o077, 0)
        self.assertEqual(self.manifest("map1", 1).stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
