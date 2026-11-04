"""Tests for campaign_store.CampaignRegistry: who owns and may use a shared story campaign, and that
access taken away stays away.

Run it from this directory:

    python -m unittest test_campaign_registry
"""
from __future__ import annotations

import errno
import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import campaign_store as cs
from test_campaign_store import common

OWNER = "acct-owner"
FRIEND = "acct-friend"
OTHER = "acct-other"
STRANGER = "acct-stranger"


class CampaignRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "campaigns"
        self.store = cs.CampaignStore(self.root, min_free_bytes=0)
        self.registry = cs.CampaignRegistry(self.store)

    def reopened(self, lock_timeout: float = cs.LOCK_TIMEOUT_SECONDS, **settings) -> cs.CampaignRegistry:
        """A registry over a new store on the same root, as another server process would have."""
        return cs.CampaignRegistry(cs.CampaignStore(self.root, min_free_bytes=0, lock_timeout=lock_timeout),
                                   **settings)

    def shared(self) -> cs.CampaignInfo:
        """A new campaign of OWNER, shared with FRIEND."""
        created = self.registry.create(OWNER)
        return self.registry.add_member(created.campaign, OWNER, FRIEND, if_match=created.etag)

    def assertNoAccess(self, registry: cs.CampaignRegistry, campaign: str, account: str) -> list[str]:
        """Every call of `account` is refused with CampaignNotFound; returns the messages."""
        messages = []
        for call in (lambda: registry.get(campaign, account), lambda: registry.head(campaign, account),
                     lambda: registry.history(campaign, account), lambda: registry.read(campaign, account),
                     lambda: registry.commit(campaign, account, None, **common(9)),
                     lambda: registry.remove_member(campaign, account, account),
                     lambda: registry.delete(campaign, account)):
            with self.assertRaises(cs.CampaignNotFound) as caught:
                call()
            messages.append(str(caught.exception).replace(campaign, "<campaign>"))
        return messages

    def test_create_draws_the_id_and_records_the_owner(self) -> None:
        first, second = self.registry.create(OWNER), self.registry.create(OWNER)
        for info in (first, second):
            self.assertRegex(info.campaign, r"\A[a-z2-7]{26}\Z")
            self.assertEqual((info.revision, info.parent, info.owner, info.members), (1, None, OWNER, ()))
            self.assertEqual(info.role(OWNER), "owner")
            self.assertIsNone(self.registry.head(info.campaign, OWNER))
        self.assertNotEqual(first.campaign, second.campaign)
        self.assertEqual(self.reopened().get(first.campaign, OWNER), first)
        self.assertEqual(self.registry.campaigns_of(OWNER), sorted([first, second], key=lambda info: info.campaign))
        self.assertEqual(self.registry.campaigns_of(STRANGER), [])

    def test_strangers_cannot_tell_a_campaign_from_none(self) -> None:
        info = self.shared()
        self.registry.commit(info.campaign, OWNER, None, **common(1))
        self.assertEqual(self.assertNoAccess(self.registry, info.campaign, STRANGER),
                         self.assertNoAccess(self.registry, cs._new_campaign_id(), STRANGER))
        with mock.patch.object(cs, "check_stage_file") as check:
            with self.assertRaises(cs.CampaignNotFound):
                self.registry.commit(info.campaign, STRANGER, None, stages={1: b"not inflated"})
        check.assert_not_called()

    def test_members_use_the_campaign_and_only_the_owner_manages_it(self) -> None:
        info = self.shared()
        campaign = info.campaign
        self.assertEqual((info.revision, info.members, info.role(FRIEND)), (2, (FRIEND,), "member"))
        first = self.registry.commit(campaign, FRIEND, None, **common(1))
        self.assertEqual(first.author, FRIEND)
        self.registry.commit(campaign, OWNER, first.etag, **common(2))
        self.assertEqual(self.registry.read(campaign, FRIEND).story, common(2)["story"])
        self.assertEqual([checkpoint.revision for checkpoint in self.registry.history(campaign, FRIEND)], [2, 1])
        self.assertEqual(self.registry.campaigns_of(FRIEND), [info])
        with self.assertRaises(cs.AccessDenied):
            self.registry.add_member(campaign, FRIEND, OTHER, if_match=info.etag)
        with self.assertRaises(cs.AccessDenied):
            self.registry.delete(campaign, FRIEND)
        with self.assertRaises(cs.AccessDenied):
            self.registry.remove_member(campaign, OWNER, OWNER)
        three = self.registry.add_member(campaign, OWNER, OTHER, if_match=info.etag)
        with self.assertRaises(cs.AccessDenied):
            self.registry.remove_member(campaign, FRIEND, OTHER)
        self.assertEqual(self.registry.get(campaign, OWNER), three)
        left = self.registry.remove_member(campaign, FRIEND, FRIEND)  # a member may leave
        self.assertEqual(left.members, (OTHER,))
        self.assertNoAccess(self.registry, campaign, FRIEND)

    def test_a_removed_member_stays_removed(self) -> None:
        created = self.registry.create(OWNER)
        campaign = created.campaign
        shared = self.registry.add_member(campaign, OWNER, FRIEND, if_match=created.etag)
        head = self.registry.commit(campaign, FRIEND, None, **common(1))
        removed = self.registry.remove_member(campaign, OWNER, FRIEND)
        other = self.reopened()  # another process sees the removal at once
        self.assertNoAccess(other, campaign, FRIEND)
        # The invitation replayed, or one decided on metadata from before the removal, is refused.
        for stale in (created.etag, shared.etag):
            with self.assertRaises(cs.MetadataConflict) as caught:
                other.add_member(campaign, OWNER, FRIEND, if_match=stale)
            self.assertEqual(caught.exception.current, removed)
        self.assertEqual((other.get(campaign, OWNER), other.head(campaign, OWNER)), (removed, head))
        again = other.add_member(campaign, OWNER, FRIEND, if_match=removed.etag)
        self.assertEqual(again.members, (FRIEND,))
        self.assertEqual(len({created.etag, shared.etag, removed.etag, again.etag}), 4)

    def test_a_commit_in_flight_when_its_member_is_removed_is_refused(self) -> None:
        campaign = self.shared().campaign
        check = cs.CampaignStore._check_change

        def removed_meanwhile(store: cs.CampaignStore, *args: object) -> object:
            change = check(store, *args)  # the payloads are checked without the lock
            self.registry.remove_member(campaign, OWNER, FRIEND)
            return change

        with mock.patch.object(cs.CampaignStore, "_check_change", removed_meanwhile):
            with self.assertRaises(cs.CampaignNotFound):
                self.registry.commit(campaign, FRIEND, None, **common(1))
        self.assertIsNone(self.registry.head(campaign, OWNER))

    def test_a_deleted_campaign_is_never_revived(self) -> None:
        campaign = self.shared().campaign
        first = self.registry.commit(campaign, FRIEND, None, **common(1))
        check = cs.CampaignStore._check_change

        def deleted_meanwhile(store: cs.CampaignStore, *args: object) -> object:
            change = check(store, *args)
            self.registry.delete(campaign, OWNER)
            return change

        with mock.patch.object(cs.CampaignStore, "_check_change", deleted_meanwhile):
            with self.assertRaises(cs.CampaignNotFound):
                self.registry.commit(campaign, FRIEND, first.etag, **common(2))
        self.assertFalse((self.root / campaign).exists())
        self.assertEqual(os.listdir(self.root / ".trash"), [])
        for account in (OWNER, FRIEND):
            self.assertNoAccess(self.registry, campaign, account)
        self.assertEqual(self.registry.campaigns_of(OWNER), [])
        with self.assertRaises(cs.CampaignNotFound):  # nor below the registry, even as a first checkpoint
            self.store.commit(campaign, None, **common(3))
        self.assertFalse((self.root / campaign).exists())
        fresh = cs._new_campaign_id()
        with mock.patch.object(cs, "_new_campaign_id", side_effect=[campaign, fresh]):
            self.assertEqual(self.registry.create(OWNER).campaign, fresh)

    def test_an_interrupted_change_keeps_the_previous_metadata(self) -> None:
        shared = self.shared()
        with mock.patch.object(cs, "_publish", side_effect=OSError(errno.EIO, "simulated I/O error")):
            with self.assertRaises(cs.StorageError) as caught:
                self.registry.remove_member(shared.campaign, OWNER, FRIEND)
        self.assertIsNone(caught.exception.committed)
        self.assertEqual(self.reopened().get(shared.campaign, FRIEND), shared)
        with mock.patch.object(cs, "_sync_fd", return_value=False):
            with self.assertRaises(cs.DurabilityError) as caught:
                self.registry.remove_member(shared.campaign, OWNER, FRIEND)
        self.assertIs(caught.exception.committed, False)
        self.assertEqual(self.registry.get(shared.campaign, FRIEND), shared)

    def test_an_interrupted_creation_leaves_no_campaign(self) -> None:
        with mock.patch.object(cs, "_sync_fd", return_value=False):
            with self.assertRaises(cs.DurabilityError) as caught:
                self.registry.create(OWNER)
        self.assertIs(caught.exception.committed, False)
        self.assertEqual(self.store.campaigns(), [])
        with mock.patch.object(cs, "_publish", side_effect=OSError(errno.EIO, "simulated I/O error")):
            with self.assertRaises(cs.StorageError) as caught:
                self.registry.create(OWNER)
        self.assertIsNone(caught.exception.committed)
        self.assertEqual(len(self.store.campaigns()), 1)  # a directory without metadata, whose ID nobody got,
        self.assertEqual(self.registry.campaigns_of(OWNER), [])  # is no campaign

    def test_purge_takes_an_account_out_of_every_campaign_for_good(self) -> None:
        owned = self.shared()
        self.registry.commit(owned.campaign, FRIEND, None, **common(1))
        theirs = self.registry.create(FRIEND)
        theirs = self.registry.add_member(theirs.campaign, FRIEND, OWNER, if_match=theirs.etag)
        self.assertEqual(self.registry.accounts(), {OWNER, FRIEND})
        self.assertEqual(self.registry.purge_account(OWNER), cs.PurgeResult((owned.campaign,), (theirs.campaign,), ()))
        self.assertTrue(self.registry.purged(OWNER))
        self.assertFalse((self.root / owned.campaign).exists())
        self.assertNoAccess(self.registry, owned.campaign, FRIEND)  # deleted for its members too
        current = self.registry.get(theirs.campaign, FRIEND)
        self.assertEqual(current.members, ())
        self.assertEqual(self.registry.accounts(), {FRIEND})
        # Calls still carrying the purged account change nothing.
        with self.assertRaises(cs.AccountPurged):
            self.registry.create(OWNER)
        with self.assertRaises(cs.AccountPurged):
            self.registry.add_member(theirs.campaign, FRIEND, OWNER, if_match=current.etag)
        self.assertEqual(self.registry.campaigns_of(OWNER), [])
        self.assertEqual(self.reopened().purge_account(OWNER), cs.PurgeResult((), (), ()))
        self.assertEqual(os.listdir(self.root / ".purged"), [hashlib.sha256(OWNER.encode()).hexdigest()])

    def test_a_purge_takes_effect_before_it_finishes(self) -> None:
        owned = self.shared()
        with mock.patch.object(cs.CampaignStore, "_delete_locked",
                               side_effect=cs.StorageError("simulated failure", committed=False)):
            self.assertEqual(self.registry.purge_account(OWNER).unfinished, (owned.campaign,))
        self.assertNoAccess(self.registry, owned.campaign, FRIEND)  # its owner is purged: served to nobody
        self.assertIn(OWNER, self.registry.accounts())
        self.assertEqual(self.registry.purge_account(OWNER).deleted, (owned.campaign,))
        self.assertEqual(self.registry.accounts(), set())

    def test_limits(self) -> None:
        registry = cs.CampaignRegistry(self.store, max_owned=2, max_members=1)
        first = registry.create(OWNER)
        registry.create(OWNER)
        with self.assertRaises(cs.QuotaExceeded):
            registry.create(OWNER)
        registry.delete(first.campaign, OWNER)
        third = registry.create(OWNER)  # a deletion frees a place
        third = registry.add_member(third.campaign, OWNER, FRIEND, if_match=third.etag)
        with self.assertRaises(cs.QuotaExceeded):
            registry.add_member(third.campaign, OWNER, OTHER, if_match=third.etag)
        self.assertEqual(registry.create("x" * cs.MAX_ACCOUNT_BYTES).owner, "x" * cs.MAX_ACCOUNT_BYTES)
        for bad in ("", "a b", "x" * (cs.MAX_ACCOUNT_BYTES + 1), "caf\u00e9", "line\nbreak", None, 7):
            with self.subTest(account=bad), self.assertRaises(cs.InvalidAccount):
                registry.create(bad)

    def test_concurrent_creations_respect_the_limit(self) -> None:
        outcomes: list[object] = []

        def worker() -> None:
            try:
                outcomes.append(self.reopened(max_owned=3).create(OWNER))
            except BaseException as exc:  # reported by the main thread
                outcomes.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(type(outcome).__name__ for outcome in outcomes), ["CampaignInfo"] * 3 + ["QuotaExceeded"] * 3)
        self.assertEqual(len(self.registry.campaigns_of(OWNER)), 3)

    def test_calls_wait_for_the_locks(self) -> None:
        info = self.shared()
        impatient = self.reopened(lock_timeout=0.1)
        with self.store._locked(info.campaign):
            for call in (lambda: impatient.get(info.campaign, FRIEND),
                         lambda: impatient.remove_member(info.campaign, OWNER, FRIEND),
                         lambda: impatient.delete(info.campaign, OWNER),
                         lambda: impatient.create(OTHER)):  # counts owned campaigns under each one's lock
                with self.assertRaises(cs.CampaignBusy):
                    call()
        with self.store._hold(f"{cs.REGISTRY_LOCK}.lock", "the campaign registry"):
            for call in (lambda: impatient.create(OTHER), lambda: impatient.purge_account(OTHER)):
                with self.assertRaises(cs.CampaignBusy):
                    call()
            self.assertEqual(impatient.get(info.campaign, FRIEND), info)  # other calls do not wait for it
        self.assertEqual(impatient.campaigns_of(OTHER), [])
        self.assertFalse(impatient.purged(OTHER))

    def test_damaged_metadata_fails_closed(self) -> None:
        info = self.shared()
        path = self.root / info.campaign / cs.METADATA_NAME
        original = path.read_bytes()
        for name, damaged in (("not JSON", b"{"),
                              ("another campaign", original.replace(info.campaign.encode(), b"a" * 26)),
                              ("owner among members", original.replace(b'"members":["acct-friend"]',
                                                                       b'"members":["acct-owner"]')),
                              ("format 2", original.replace(b'"format":1', b'"format":2'))):
            with self.subTest(name):
                path.write_bytes(damaged)
                with self.assertRaises(cs.IntegrityError):
                    self.registry.get(info.campaign, FRIEND)
                with self.assertRaises(cs.IntegrityError):
                    self.registry.commit(info.campaign, OWNER, None, **common(1))
                self.assertEqual(self.registry.campaigns_of(OWNER), [])
        path.write_bytes(original)
        self.assertEqual(self.registry.get(info.campaign, FRIEND), info)


if __name__ == "__main__":
    unittest.main()
