"""Tests for campaign_api: the HTTP routes of durable shared story campaigns, over a real
CampaignRegistry in a temporary directory, with a stand-in for server.py's game sessions as the host
check. Nothing here starts a server, opens a socket or touches live data.

Run them from this directory:

    python -m unittest test_campaign_api

CampaignApiScenarioTest is the isolated end-to-end scenario: one shared campaign through its whole
life, every request through CampaignApi.handle on an event loop with a dedicated worker thread:

    python -m unittest test_campaign_api.CampaignApiScenarioTest
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import logging
import tempfile
import threading
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock
from urllib.parse import quote

import campaign_api as api
import campaign_store as cs
from test_campaign_store import common, stage_file, story, unique

logging.getLogger("npln.campaign.api").addHandler(logging.NullHandler())  # expected warnings stay out of the output

OWNER = "acct-owner"
FRIEND = "acct-friend"
STRANGER = "acct-stranger"
SESSION = "game-session-1"
NO_ETAG = '"' + "0" * 64 + '"'


@dataclass(frozen=True)
class Principal:
    """What server.Principal carries: the account behind a device certificate."""

    account: str
    device: str = "device-test"


class Sessions:
    """host_session for the tests, standing in for server.py's live game sessions: by name, the
    account whose user created (hosts) each one and the campaign it was bound to."""

    def __init__(self) -> None:
        self.live: dict[str, tuple[str, str]] = {}
        self.calls: list[tuple[str, str, int]] = []  # (account, session, thread)

    def host(self, session: str, account: str, campaign: str) -> None:
        self.live[session] = (account, campaign)

    def __call__(self, principal: Principal, session: str) -> api.HostSession | None:
        self.calls.append((principal.account, session, threading.get_ident()))
        found = self.live.get(session)
        if found is None or found[0] != principal.account:
            return None
        return api.HostSession(found[0], session, found[1])


def etag(value: str) -> str:
    return f'"{value}"'


def frame(header: bytes, payloads: bytes = b"") -> bytes:
    """A commit body with any header bytes."""
    return len(header).to_bytes(api.COMMIT_LENGTH_BYTES, "big") + header + payloads


def head(**changes: object) -> bytes:
    """A commit header, an empty commit's with `changes`."""
    doc = {"session": SESSION, "story": None, "unique": None, "stages": {}}
    doc.update(changes)
    return json.dumps(doc).encode()


def read_stream(result: api.ApiResponse) -> bytes:
    file, offset, length = result.stream
    file.seek(offset)
    return file.read(length)


class ApiTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "campaigns"
        self.store = cs.CampaignStore(self.root, min_free_bytes=0)
        self.registry = cs.CampaignRegistry(self.store)
        self.sessions = Sessions()
        self.api = api.CampaignApi(self.registry, self.sessions)

    def call(self, account: str | None, method: str, target: str, body: bytes = b"", **headers: str) -> api.ApiResponse:
        """One request through CampaignApi.serve; header names are keyword names with - for _."""
        principal = None if account is None else Principal(account)
        result = self.api.serve(method, target, {name.replace("_", "-"): value for name, value in headers.items()},
                                body, principal)
        self.addCleanup(result.close)  # before the directory goes: Windows deletes no open file
        return result

    @staticmethod
    def doc(result: api.ApiResponse) -> dict:
        return json.loads(result.body)

    @staticmethod
    def header(result: api.ApiResponse, name: str) -> str | None:
        return dict(result.headers).get(name)

    def assertRefused(self, result: api.ApiResponse, status: int, code: str) -> dict:
        self.assertEqual((result.status, self.doc(result)["error"]), (status, code), result.body)
        return self.doc(result)

    @staticmethod
    def path(campaign: str, *rest: object) -> str:
        return "/".join([api.PREFIX, campaign, *map(str, rest)])

    def member_path(self, campaign: str, member: str) -> str:
        return self.path(campaign, "members", quote(member, safe=""))

    def create(self, account: str = OWNER) -> dict:
        result = self.call(account, "POST", api.PREFIX)
        self.assertEqual(result.status, 201, result.body)
        return self.doc(result)

    def shared(self) -> dict:
        """A new campaign of OWNER, shared with FRIEND: its Campaign document."""
        created = self.create()
        result = self.call(OWNER, "PUT", self.member_path(created["campaign"], FRIEND), if_match=etag(created["etag"]))
        self.assertEqual(result.status, 200, result.body)
        return self.doc(result)

    def commit(self, account: str, campaign: str, body: bytes, **preconditions: str) -> api.ApiResponse:
        return self.call(account, "POST", self.path(campaign, "checkpoint"), body, content_type=api.COMMIT_MEDIA_TYPE,
                         **preconditions)


class AuthenticationTest(ApiTestCase):
    def test_every_route_needs_an_authenticated_account(self) -> None:
        campaign = cs._new_campaign_id()
        routes = [("GET", api.PREFIX), ("POST", api.PREFIX), ("GET", self.path(campaign)),
                  ("DELETE", self.path(campaign)), ("PUT", self.member_path(campaign, FRIEND)),
                  ("DELETE", self.member_path(campaign, FRIEND)), ("GET", self.path(campaign, "checkpoint")),
                  ("POST", self.path(campaign, "checkpoint")), ("GET", self.path(campaign, "checkpoints")),
                  ("GET", self.path(campaign, "checkpoints", 1, "story")),
                  ("GET", self.path(campaign, "checkpoints", 1, "stages", 1)), ("GET", api.PREFIX + "/no/such/route")]
        for method, target in routes:
            for account in (None, "", "two words"):
                with self.subTest(method=method, target=target, account=account):
                    self.assertRefused(self.call(account, method, target, if_match="*"), 401, "unauthenticated")
        no_account = self.api.serve("GET", api.PREFIX, {}, b"", object())
        self.assertRefused(no_account, 401, "unauthenticated")
        self.assertEqual(self.sessions.calls, [])
        self.assertEqual(self.store.campaigns(), [])


class LifecycleTest(ApiTestCase):
    def test_create_share_revoke_and_delete(self) -> None:
        created_result = self.call(OWNER, "POST", api.PREFIX)
        self.assertEqual(created_result.status, 201)
        created = self.doc(created_result)
        campaign = created["campaign"]
        self.assertRegex(campaign, rf"\A[{cs.ID_ALPHABET}]{{{cs.ID_LENGTH}}}\Z")
        self.assertEqual((created["role"], created["owner"], created["members"], created["revision"]),
                         ("owner", OWNER, [], 1))
        self.assertEqual(self.header(created_result, "location"), self.path(campaign))
        self.assertEqual(self.header(created_result, "etag"), etag(created["etag"]))
        got = self.call(OWNER, "GET", self.path(campaign))
        self.assertEqual((got.status, self.doc(got), self.header(got, "etag")), (200, created, etag(created["etag"])))

        # Sharing: owner only, and only with the metadata's current etag.
        target = self.member_path(campaign, FRIEND)
        self.assertRefused(self.call(OWNER, "PUT", target), 428, "precondition_required")
        self.assertRefused(self.call(OWNER, "PUT", target, if_match="*"), 400, "bad_request")
        self.assertRefused(self.call(OWNER, "PUT", target, if_match="W/" + etag(created["etag"])), 400, "bad_request")
        self.assertEqual(self.assertRefused(self.call(OWNER, "PUT", target, if_match=NO_ETAG), 412,
                                            "precondition_failed")["etag"], created["etag"])
        added = self.call(OWNER, "PUT", target, if_match=etag(created["etag"]))
        self.assertEqual((added.status, self.doc(added)["members"], self.doc(added)["revision"]), (200, [FRIEND], 2))
        shared_etag = self.doc(added)["etag"]
        self.assertEqual(self.header(added, "etag"), etag(shared_etag))
        self.assertRefused(self.call(OWNER, "PUT", target, if_match=etag(created["etag"])), 412,
                           "precondition_failed")  # a replayed invitation

        listed = self.doc(self.call(FRIEND, "GET", api.PREFIX))["campaigns"]
        self.assertEqual([(entry["campaign"], entry["role"], entry["owner"]) for entry in listed],
                         [(campaign, "member", OWNER)])
        self.assertRefused(self.call(FRIEND, "PUT", self.member_path(campaign, STRANGER), if_match=etag(shared_etag)),
                           403, "forbidden")
        self.assertRefused(self.call(FRIEND, "DELETE", self.path(campaign), if_match="*"), 403, "forbidden")
        self.assertRefused(self.call(FRIEND, "DELETE", self.member_path(campaign, OWNER), if_match="*"), 403,
                           "forbidden")
        self.assertEqual(self.registry.get(campaign, OWNER).members, (FRIEND,))

        # Revoking: explicit, and If-Match: * takes access away whatever changed.
        self.assertRefused(self.call(OWNER, "DELETE", target), 428, "precondition_required")
        self.assertRefused(self.call(OWNER, "DELETE", target, if_match=etag(created["etag"])), 412,
                           "precondition_failed")
        removed = self.call(OWNER, "DELETE", target, if_match="*")
        self.assertEqual((removed.status, self.doc(removed)["members"]), (200, []))
        self.assertRefused(self.call(FRIEND, "GET", self.path(campaign)), 404, "not_found")
        self.assertEqual(self.doc(self.call(FRIEND, "GET", api.PREFIX)), {"campaigns": []})

        # Deleting: owner only, explicit, for good.
        self.assertRefused(self.call(OWNER, "DELETE", self.path(campaign)), 428, "precondition_required")
        self.assertRefused(self.call(OWNER, "DELETE", self.path(campaign), if_match=etag(shared_etag)), 412,
                           "precondition_failed")
        deleted = self.call(OWNER, "DELETE", self.path(campaign), if_match=etag(self.doc(removed)["etag"]))
        self.assertEqual((deleted.status, deleted.body), (204, b""))
        self.assertRefused(self.call(OWNER, "GET", self.path(campaign)), 404, "not_found")
        self.assertRefused(self.call(OWNER, "DELETE", self.path(campaign), if_match="*"), 404, "not_found")
        self.assertEqual(self.doc(self.call(OWNER, "GET", api.PREFIX)), {"campaigns": []})

    def test_a_member_may_leave_but_the_owner_may_not(self) -> None:
        info = self.shared()
        campaign = info["campaign"]
        self.assertRefused(self.call(OWNER, "DELETE", self.member_path(campaign, OWNER), if_match="*"), 403,
                           "forbidden")
        left = self.call(FRIEND, "DELETE", self.member_path(campaign, FRIEND), if_match=etag(info["etag"]))
        self.assertEqual((left.status, left.body), (204, b""))
        self.assertRefused(self.call(FRIEND, "GET", self.path(campaign)), 404, "not_found")
        self.assertRefused(self.call(FRIEND, "DELETE", self.member_path(campaign, FRIEND), if_match="*"), 404,
                           "not_found")
        self.assertEqual(self.registry.get(campaign, OWNER).members, ())

    def test_owned_campaigns_and_members_are_bounded(self) -> None:
        for _ in range(cs.DEFAULT_MAX_OWNED):
            self.create(FRIEND)
        self.assertRefused(self.call(FRIEND, "POST", api.PREFIX), 409, "too_many_campaigns")
        self.assertEqual(len(self.registry.campaigns_of(FRIEND)), cs.DEFAULT_MAX_OWNED)
        self.api = api.CampaignApi(cs.CampaignRegistry(self.store, max_members=1), self.sessions)
        info = self.shared()
        target = self.member_path(info["campaign"], STRANGER)
        self.assertRefused(self.call(OWNER, "PUT", target, if_match=etag(info["etag"])), 409, "too_many_members")
        self.registry.purge_account(STRANGER)
        self.assertRefused(self.call(OWNER, "PUT", target, if_match=etag(info["etag"])), 409, "member_unavailable")
        self.assertEqual(self.registry.get(info["campaign"], OWNER).members, (FRIEND,))

    def test_member_ids_are_one_percent_encoded_segment(self) -> None:
        created = self.create()
        campaign = created["campaign"]
        odd = "acct/odd?%#"
        added = self.call(OWNER, "PUT", self.member_path(campaign, odd), if_match=etag(created["etag"]))
        self.assertEqual((added.status, self.doc(added)["members"]), (200, [odd]))
        for segment in ("%zz", "%C3%A9", "%FF", "a%20b", "a b", ""):  # not encoding, not ASCII, a space, empty
            with self.subTest(segment=segment):
                self.assertRefused(self.call(OWNER, "PUT", self.path(campaign, "members", segment),
                                             if_match=etag(self.doc(added)["etag"])), 400, "bad_request")
        removed = self.call(OWNER, "DELETE", self.member_path(campaign, odd), if_match="*")
        self.assertEqual((removed.status, self.doc(removed)["members"]), (200, []))

    def test_requests_are_parsed_strictly(self) -> None:
        campaign = self.create()["campaign"]
        self.assertRefused(self.call(OWNER, "GET", self.path(campaign) + "?x=1"), 400, "bad_request")
        self.assertRefused(self.call(OWNER, "GET", self.path(campaign) + "?"), 400, "bad_request")
        self.assertRefused(self.call(OWNER, "GET", self.path(campaign), b"x"), 400, "bad_request")
        self.assertRefused(self.call(OWNER, "POST", api.PREFIX, b"{}"), 400, "bad_request")
        self.assertRefused(self.call(OWNER, "GET", api.PREFIX + "/" + "a" * api.MAX_TARGET_CHARS), 400, "bad_request")
        refused = self.call(OWNER, "HEAD", self.path(campaign))
        self.assertRefused(refused, 405, "method_not_allowed")
        self.assertEqual(self.header(refused, "allow"), "GET, DELETE")
        self.assertEqual(self.header(self.call(OWNER, "PUT", self.path(campaign, "checkpoint")), "allow"), "GET, POST")
        for target in (api.PREFIX + "/", self.path(campaign) + "/", self.path(campaign, "nothing"),
                       self.path(campaign, "checkpoints", 1), self.path(campaign, "checkpoints", "01", "story"),
                       self.path(campaign, "checkpoints", 0, "story"),
                       self.path(campaign, "checkpoints", 1, "stages", "01"),
                       self.path(campaign, "checkpoints", 1, "stages", 100), self.path(campaign.upper()),
                       self.path(campaign[:-1]), self.path(campaign + "a")):
            with self.subTest(target=target):
                self.assertRefused(self.call(OWNER, "GET", target), 404, "not_found")
        self.assertEqual(self.sessions.calls, [])


class DisclosureTest(ApiTestCase):
    def stranger_requests(self, campaign: str, metadata_etag: str) -> list[tuple[int, list, bytes]]:
        results = [self.call(STRANGER, "GET", self.path(campaign)),
                   self.call(STRANGER, "DELETE", self.path(campaign), if_match="*"),
                   self.call(STRANGER, "DELETE", self.path(campaign), if_match=etag(metadata_etag)),
                   self.call(STRANGER, "PUT", self.member_path(campaign, STRANGER), if_match=etag(metadata_etag)),
                   self.call(STRANGER, "DELETE", self.member_path(campaign, STRANGER), if_match="*"),
                   self.call(STRANGER, "DELETE", self.member_path(campaign, FRIEND), if_match="*"),
                   self.call(STRANGER, "GET", self.path(campaign, "checkpoint")),
                   self.call(STRANGER, "GET", self.path(campaign, "checkpoints")),
                   self.call(STRANGER, "GET", self.path(campaign, "checkpoints", 1, "story")),
                   self.call(STRANGER, "GET", self.path(campaign, "checkpoints", 1, "stages", 1)),
                   self.commit(STRANGER, campaign, api.encode_commit("stranger-session", **common(2)),
                               if_none_match="*")]
        return [(result.status, result.headers, result.body) for result in results]

    def test_strangers_cannot_tell_a_campaign_from_none(self) -> None:
        info = self.shared()
        campaign = info["campaign"]
        self.sessions.host(SESSION, FRIEND, campaign)
        first = self.commit(FRIEND, campaign, api.encode_commit(SESSION, **common(1), stages={1: stage_file(1)}),
                            if_none_match="*")
        self.assertEqual(first.status, 201)
        answers = []
        for target in (campaign, cs._new_campaign_id(), "not-a-campaign"):
            self.sessions.host("stranger-session", STRANGER, target)  # even a host bound to it gets nowhere
            answers.append(self.stranger_requests(target, info["etag"]))
        self.assertEqual(answers[0], answers[1])
        self.assertEqual(answers[1], answers[2])
        self.assertEqual({status for status, _, _ in answers[0]}, {404})
        self.assertEqual(self.registry.get(campaign, OWNER).etag, info["etag"])
        self.assertEqual(self.registry.head(campaign, OWNER).etag, self.doc(first)["checkpoint"]["etag"])

    def test_damaged_metadata_looks_like_no_campaign_to_everyone(self) -> None:
        campaign = self.shared()["campaign"]
        (self.root / campaign / cs.METADATA_NAME).write_bytes(b"{not json")
        expected = self.call(STRANGER, "GET", self.path(cs._new_campaign_id()))
        for account in (OWNER, FRIEND, STRANGER):
            for method, target in (("GET", self.path(campaign)), ("GET", self.path(campaign, "checkpoint")),
                                   ("DELETE", self.path(campaign)), ("DELETE", self.member_path(campaign, FRIEND))):
                with self.subTest(account=account, method=method, target=target):
                    result = self.call(account, method, target, if_match="*")
                    self.assertEqual((result.status, result.body), (expected.status, expected.body))
        self.assertTrue((self.root / campaign).is_dir())

    def test_damaged_checkpoints_are_told_only_to_those_who_may_see_them(self) -> None:
        campaign = self.shared()["campaign"]
        self.sessions.host(SESSION, OWNER, campaign)
        committed = self.commit(OWNER, campaign, api.encode_commit(SESSION, **common(1)), if_none_match="*")
        manifest = self.doc(committed)["checkpoint"]
        path = self.root / campaign / "objects" / manifest["story"]["sha256"]
        damaged = bytearray(path.read_bytes())
        damaged[0] ^= 0xFF
        path.write_bytes(bytes(damaged))
        target = self.path(campaign, "checkpoints", 1, "story")
        for account in (OWNER, FRIEND):
            self.assertRefused(self.call(account, "GET", target), 500, "damaged")
        self.assertRefused(self.call(STRANGER, "GET", target), 404, "not_found")
        self.assertEqual(self.call(FRIEND, "GET", self.path(campaign, "checkpoints", 1, "unique")).status, 200)


class CommitTest(ApiTestCase):
    def test_commits_need_the_current_host_of_a_session_bound_to_the_campaign(self) -> None:
        campaign = self.shared()["campaign"]
        other = self.create()["campaign"]
        body = api.encode_commit(SESSION, **common(1), stages={1: stage_file(1)})
        self.assertRefused(self.commit(FRIEND, campaign, body, if_none_match="*"), 403, "not_host")  # no session
        self.sessions.host(SESSION, FRIEND, other)
        self.assertRefused(self.commit(FRIEND, campaign, body, if_none_match="*"), 403, "not_host")  # bound elsewhere
        self.sessions.host(SESSION, OWNER, campaign)
        self.assertRefused(self.commit(FRIEND, campaign, body, if_none_match="*"), 403, "not_host")  # not its host
        # Whatever else the check answers refuses the commit.
        for answer in (True, {"campaign": campaign}, api.HostSession(OWNER, SESSION, campaign),
                       api.HostSession(FRIEND, "another-session", campaign), api.HostSession(FRIEND, SESSION, other)):
            with self.subTest(answer=answer), mock.patch.object(self.api, "host_session",
                                                                lambda principal, session, answer=answer: answer):
                self.assertRefused(self.commit(FRIEND, campaign, body, if_none_match="*"), 403, "not_host")

        def broken(principal: Principal, session: str) -> api.HostSession:
            raise RuntimeError("the backend failed")

        with mock.patch.object(self.api, "host_session", broken):
            self.assertRefused(self.commit(FRIEND, campaign, body, if_none_match="*"), 503, "unavailable")
        self.assertIsNone(self.registry.head(campaign, OWNER))

        self.sessions.host(SESSION, FRIEND, campaign)
        committed = self.commit(FRIEND, campaign, body, if_none_match="*")
        self.assertEqual(committed.status, 201, committed.body)
        checkpoint = self.doc(committed)["checkpoint"]
        self.assertEqual((checkpoint["campaign"], checkpoint["revision"], checkpoint["parent"], checkpoint["author"]),
                         (campaign, 1, None, FRIEND))
        self.assertEqual(self.header(committed, "etag"), etag(checkpoint["etag"]))
        self.assertEqual(self.registry.head(campaign, OWNER).etag, checkpoint["etag"])
        self.assertEqual(self.sessions.calls[-1][:2], (FRIEND, SESSION))
        with self.assertRaises(TypeError):
            api.CampaignApi(self.registry, None)

    def test_commits_compare_and_swap_the_newest_checkpoint(self) -> None:
        campaign = self.create()["campaign"]
        self.sessions.host(SESSION, OWNER, campaign)
        first_body = api.encode_commit(SESSION, **common(1), stages={1: stage_file(1)})
        self.assertRefused(self.commit(OWNER, campaign, first_body), 428, "precondition_required")
        for preconditions in ({"if_match": "*"}, {"if_none_match": NO_ETAG}, {"if_match": "W/" + NO_ETAG},
                              {"if_match": NO_ETAG, "if_none_match": "*"}, {"if_match": NO_ETAG + ", " + NO_ETAG}):
            with self.subTest(preconditions=preconditions):
                self.assertRefused(self.commit(OWNER, campaign, first_body, **preconditions), 400, "bad_request")
        self.assertEqual(self.assertRefused(self.commit(OWNER, campaign, first_body, if_match=NO_ETAG), 412,
                                            "precondition_failed") | {"message": ""},
                         {"error": "precondition_failed", "message": "", "etag": None, "revision": None})
        self.assertIsNone(self.registry.head(campaign, OWNER))

        first = self.commit(OWNER, campaign, first_body, if_none_match="*")
        self.assertEqual(first.status, 201)
        first_etag = self.doc(first)["checkpoint"]["etag"]
        again = self.assertRefused(self.commit(OWNER, campaign, first_body, if_none_match="*"), 412,
                                   "precondition_failed")
        self.assertEqual((again["etag"], again["revision"]), (first_etag, 1))

        second_body = api.encode_commit(SESSION, stages={1: None, 2: stage_file(2)})
        second = self.commit(OWNER, campaign, second_body, if_match=etag(first_etag))
        self.assertEqual(second.status, 201)
        checkpoint = self.doc(second)["checkpoint"]
        self.assertEqual((checkpoint["revision"], checkpoint["parent"], sorted(checkpoint["stages"])),
                         (2, first_etag, ["2"]))
        self.assertEqual(checkpoint["story"]["sha256"], hashlib.sha256(story(1)).hexdigest())  # kept
        stale = self.assertRefused(self.commit(OWNER, campaign, api.encode_commit(SESSION, **common(3)),
                                               if_match=etag(first_etag)), 412, "precondition_failed")
        self.assertEqual((stale["etag"], stale["revision"]), (checkpoint["etag"], 2))
        unchanged = self.commit(OWNER, campaign, second_body, if_match=etag(checkpoint["etag"]))
        self.assertEqual((unchanged.status, self.doc(unchanged)["checkpoint"]), (200, checkpoint))
        history = self.doc(self.call(OWNER, "GET", self.path(campaign, "checkpoints")))["checkpoints"]
        self.assertEqual([entry["revision"] for entry in history], [2, 1])
        self.assertEqual(history[0], checkpoint)

    def test_commit_bodies_are_bounded_and_exact(self) -> None:
        campaign = self.create()["campaign"]
        self.sessions.host(SESSION, OWNER, campaign)
        good = api.encode_commit(SESSION, **common(1), stages={1: stage_file(1)})

        def refused(body: bytes, status: int, code: str, content_type: str = api.COMMIT_MEDIA_TYPE) -> None:
            result = self.call(OWNER, "POST", self.path(campaign, "checkpoint"), body, content_type=content_type,
                               if_none_match="*")
            self.assertRefused(result, status, code)

        refused(good, 415, "unsupported_media_type", "application/octet-stream")
        refused(good, 415, "unsupported_media_type", "")
        refused(good[:-1], 400, "bad_request")  # a payload cut short
        refused(good + b"\0", 400, "bad_request")  # a byte after the last payload
        refused(b"", 400, "bad_request")
        refused(b"\0\0\0", 400, "bad_request")
        refused(frame(b""), 400, "bad_request")
        refused(frame(head())[:-1], 400, "bad_request")  # the header cut short
        refused((api.MAX_COMMIT_HEADER_BYTES + 1).to_bytes(api.COMMIT_LENGTH_BYTES, "big"), 413, "too_large")
        refused(frame(b"[]"), 400, "bad_request")
        refused(frame(b"\xff"), 400, "bad_request")
        refused(frame(b'{"session":"s","session":"s","story":null,"unique":null,"stages":{}}'), 400, "bad_request")
        refused(frame(b'{"session":"s","story":NaN,"unique":null,"stages":{}}'), 400, "bad_request")
        refused(frame(head(extra=1)), 400, "bad_request")
        refused(frame(head(session="")), 400, "bad_request")
        refused(frame(head(session="x" * (api.MAX_SESSION_NAME_BYTES + 1))), 400, "bad_request")
        refused(frame(head(session="caf\u00e9")), 400, "bad_request")
        refused(frame(head(story=cs.STORY_BLOCK_SIZE), story(1)), 400, "bad_payload")  # without its unique history
        refused(frame(head(story=True, unique=cs.UNIQUE_SIZE), b"\0" + unique(1)), 400, "bad_payload")
        refused(frame(head(story=cs.STORY_BLOCK_SIZE + 1, unique=cs.UNIQUE_SIZE), story(1) + b"\0" + unique(1)), 400,
                "bad_payload")
        refused(frame(head(stages=[1])), 400, "bad_request")
        refused(frame(head(stages={"01": None})), 400, "bad_request")
        refused(frame(head(stages={"100": None})), 400, "bad_request")
        refused(frame(head(stages={"1": True}), b"\0"), 400, "bad_request")
        refused(frame(head(stages={"1": 0})), 400, "bad_request")
        refused(frame(head(stages={"1": 1.0}), b"\0"), 400, "bad_request")
        refused(frame(head(stages={"1": self.store.max_stage_bytes + 1})), 413, "too_large")
        with mock.patch.object(api, "MAX_COMMIT_REQUEST_BYTES", len(good) - 1):
            refused(good, 413, "too_large")
        self.assertEqual(self.sessions.calls, [])  # none of them got as far as the host check
        self.assertIsNone(self.registry.head(campaign, OWNER))

        # The store checks the payloads themselves.
        refused(api.encode_commit(SESSION, **common(1), stages={1: b"not a stage file"}), 400, "bad_payload")
        self.assertIsNone(self.registry.head(campaign, OWNER))
        committed = self.call(OWNER, "POST", self.path(campaign, "checkpoint"), good,
                              content_type=api.COMMIT_MEDIA_TYPE + "; charset=binary", if_none_match="*")
        self.assertEqual(committed.status, 201, committed.body)

    def test_parse_commit_reads_back_encode_commit_without_copying(self) -> None:
        stages = {7: stage_file(7), 1: stage_file(1), 3: None}
        body = api.encode_commit(SESSION, **common(4), stages=stages)
        parsed = api.parse_commit(body)
        self.assertEqual(parsed.session, SESSION)
        self.assertEqual((bytes(parsed.story), bytes(parsed.unique)), (story(4), unique(4)))
        self.assertEqual({number: None if view is None else bytes(view) for number, view in parsed.stages.items()},
                         stages)
        self.assertTrue(parsed.story.readonly)
        self.assertIs(parsed.story.obj, body)
        with self.assertRaises(TypeError):
            parsed.stages[2] = None
        empty = api.parse_commit(api.encode_commit(SESSION))
        self.assertEqual((empty.story, empty.unique, dict(empty.stages)), (None, None, {}))


class PayloadTest(ApiTestCase):
    def test_payloads_stream_checked_and_match_the_manifest(self) -> None:
        campaign = self.shared()["campaign"]
        self.sessions.host(SESSION, FRIEND, campaign)
        files = {1: stage_file(1, trailing=b"kept as the game leaves it"), 7: stage_file(7)}
        committed = self.commit(FRIEND, campaign, api.encode_commit(SESSION, **common(1), stages=files),
                                if_none_match="*")
        self.assertEqual(committed.status, 201, committed.body)
        current = self.call(OWNER, "GET", self.path(campaign, "checkpoint"))
        manifest = self.doc(current)["checkpoint"]
        self.assertEqual(manifest, self.doc(committed)["checkpoint"])
        self.assertEqual(self.header(current, "etag"), etag(manifest["etag"]))
        self.assertEqual(sorted(manifest["stages"]), ["1", "7"])
        expected = {("story",): story(1), ("unique",): unique(1), ("stages", 1): files[1], ("stages", 7): files[7]}
        for part, data in expected.items():
            with self.subTest(part=part):
                result = self.call(OWNER, "GET", self.path(campaign, "checkpoints", manifest["revision"], *part))
                self.assertEqual((result.status, result.body), (200, b""))
                self.assertEqual(read_stream(result), data)
                result.close()
                digest = hashlib.sha256(data).hexdigest()
                entry = manifest[part[0]] if len(part) == 1 else manifest["stages"][str(part[1])]
                self.assertEqual((entry["sha256"], entry["size"]), (digest, len(data)))
                self.assertEqual(self.header(result, "etag"), etag(digest))
                self.assertEqual(self.header(result, "x-checkpoint-etag"), etag(manifest["etag"]))
                self.assertEqual(self.header(result, "content-length"), str(len(data)))
                self.assertEqual(self.header(result, "content-type"), "application/octet-stream")
        for missing in (self.path(campaign, "checkpoints", 1, "stages", 2), self.path(campaign, "checkpoints", 2, "story")):
            with self.subTest(missing=missing):
                self.assertRefused(self.call(FRIEND, "GET", missing), 404, "not_found")

    def test_a_download_outlives_revocation_and_later_commits(self) -> None:
        campaign = self.shared()["campaign"]
        self.sessions.host(SESSION, OWNER, campaign)
        first = self.doc(self.commit(OWNER, campaign, api.encode_commit(SESSION, **common(1)), if_none_match="*"))
        download = self.call(FRIEND, "GET", self.path(campaign, "checkpoints", 1, "story"))
        self.assertEqual(download.status, 200)
        self.assertEqual(self.call(OWNER, "DELETE", self.member_path(campaign, FRIEND), if_match="*").status, 200)
        self.commit(OWNER, campaign, api.encode_commit(SESSION, **common(2)), if_match=etag(first["checkpoint"]["etag"]))
        self.assertEqual(read_stream(download), story(1))
        self.assertRefused(self.call(FRIEND, "GET", self.path(campaign, "checkpoints", 1, "story")), 404, "not_found")


class WorkerTest(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.executor = concurrent.futures.ThreadPoolExecutor(1, thread_name_prefix="campaign-test")
        self.addCleanup(self.executor.shutdown, wait=True)
        self.api = api.CampaignApi(self.registry, self.sessions, executor=self.executor)

    def test_disk_work_runs_in_the_executor_and_the_host_check_on_the_loop(self) -> None:
        campaign = self.create()["campaign"]
        self.sessions.host(SESSION, OWNER, campaign)
        threads: dict[str, int] = {}
        commit = self.registry.commit

        def recorded(*args: object, **kwargs: object) -> cs.Checkpoint:
            threads["commit"] = threading.get_ident()
            return commit(*args, **kwargs)

        async def run() -> tuple[api.ApiResponse, api.ApiResponse]:
            threads["loop"] = threading.get_ident()
            with mock.patch.object(self.registry, "commit", recorded):
                committed = await self.api.handle("POST", self.path(campaign, "checkpoint"),
                                                  {"content-type": api.COMMIT_MEDIA_TYPE, "if-none-match": "*"},
                                                  api.encode_commit(SESSION, **common(1)), Principal(OWNER))
            with mock.patch.object(self.executor, "submit", side_effect=AssertionError("no work for a refusal")):
                refused = await self.api.handle("GET", self.path(campaign), {}, b"", None)
            return committed, refused

        committed, refused = asyncio.run(run())
        self.assertEqual((committed.status, refused.status), (201, 401))
        self.assertEqual(self.sessions.calls[-1][2], threads["loop"])
        self.assertNotEqual(threads["commit"], threads["loop"])

    def test_a_cancelled_download_closes_its_file(self) -> None:
        campaign = self.create()["campaign"]
        self.sessions.host(SESSION, OWNER, campaign)
        self.assertEqual(self.commit(OWNER, campaign, api.encode_commit(SESSION, **common(1)),
                                     if_none_match="*").status, 201)
        started, release = threading.Event(), threading.Event()
        opened: list = []
        open_payload = api.open_payload

        def slow_open(captured: cs.CapturedObject, checkpoint: cs.Checkpoint):
            file = open_payload(captured, checkpoint)
            opened.append(file)
            started.set()
            release.wait(10)
            return file

        async def run() -> None:
            task = asyncio.create_task(self.api.handle("GET", self.path(campaign, "checkpoints", 1, "story"), {}, b"",
                                                       Principal(OWNER)))
            while not started.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with mock.patch.object(api, "open_payload", slow_open):
            asyncio.run(run())
            release.set()
            self.executor.shutdown(wait=True)
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].closed)


class LoggingTest(ApiTestCase):
    def test_logs_name_route_and_outcome_but_no_content(self) -> None:
        campaign = self.shared()["campaign"]
        session = "session-name-kept-out-of-logs"
        self.sessions.host(session, FRIEND, campaign)
        with self.assertLogs("npln.campaign.api", "INFO") as logs:
            committed = self.commit(FRIEND, campaign, api.encode_commit(session, **common(1)), if_none_match="*")
            self.commit(FRIEND, campaign, frame(head(session=session, extra="secret-value")), if_none_match="*")
            self.call(FRIEND, "GET", self.path(campaign, "checkpoint"))
        self.assertEqual(committed.status, 201)
        text = "\n".join(logs.output)
        self.assertIn(f"POST commit from account {FRIEND} -> 201 ok", text)
        self.assertIn("-> 400 bad_request", text)
        self.assertIn(f"GET head from account {FRIEND} -> 200 ok", text)
        for content in (session, "secret-value", campaign):
            self.assertNotIn(content, text)


class ServerContractTest(unittest.TestCase):
    def test_dispatch_predicate_and_body_limits(self) -> None:
        campaign = cs._new_campaign_id()
        for target in (api.PREFIX, api.PREFIX + "/", f"{api.PREFIX}/{campaign}", f"{api.PREFIX}/{campaign}/checkpoint?x"):
            self.assertTrue(api.is_campaign_api(target), target)
        for target in ("/campaign/live", "/campaignsx", "/upload/" + "a" * 20, "/", "", "//campaigns", "/x/campaigns"):
            self.assertFalse(api.is_campaign_api(target), target)
        commit = f"{api.PREFIX}/{campaign}/checkpoint"
        self.assertEqual(api.body_limit("POST", commit), api.MAX_COMMIT_REQUEST_BYTES)
        self.assertEqual(api.body_limit("POST", commit + "?x"), api.MAX_COMMIT_REQUEST_BYTES)  # refused later, unread
        for method, target in (("GET", commit), ("PUT", commit), ("POST", api.PREFIX), ("PUT", f"{commit}s"),
                               ("DELETE", f"{api.PREFIX}/{campaign}")):
            self.assertEqual(api.body_limit(method, target), 0, (method, target))

    def test_budgets_match_server_py(self) -> None:
        try:
            import server
        except ImportError as exc:
            self.skipTest(f"server.py's dependencies are missing: {exc}")
        self.assertEqual(api.MAX_COMMIT_REQUEST_BYTES, server.MAX_STORAGE_REQUEST_BYTES)
        self.assertEqual(api.MAX_COMMIT_HEADER_BYTES, server.MAX_LIVE_REQUEST_BYTES)
        self.assertEqual(api.MAX_SESSION_NAME_BYTES, server.MAX_NAME_BYTES)
        self.assertLessEqual(cs.MAX_STAGE_BYTES + api.MAX_COMMIT_HEADER_BYTES, api.MAX_COMMIT_REQUEST_BYTES)
        self.assertFalse(server.is_campaign_live(api.PREFIX))
        self.assertFalse(api.is_campaign_api(server.CAMPAIGN_LIVE_PATH))
        response = api.json_response(200, {})
        self.assertEqual(server.Response(response.status, response.headers, response.body, response.stream),
                         server.Response(200, response.headers, response.body))


class CampaignApiScenarioTest(unittest.TestCase):
    """The isolated scenario: one shared campaign through its whole life, as server.py would serve
    it, every request through CampaignApi.handle on an event loop with a dedicated worker, over a
    temporary directory and stand-in game sessions."""

    def test_shared_campaign_end_to_end(self) -> None:
        asyncio.run(self.scenario())

    async def scenario(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="campaign") as executor:
            registry = cs.CampaignRegistry(cs.CampaignStore(Path(directory) / "campaigns", min_free_bytes=0))
            sessions = Sessions()
            app = api.CampaignApi(registry, sessions, executor=executor)

            async def request(account: str, method: str, target: str, body: bytes = b"",
                              **headers: str) -> tuple[int, dict, object]:
                result = await app.handle(method, target, {name.replace("_", "-"): value
                                                           for name, value in headers.items()}, body,
                                          Principal(account))
                if result.stream is not None:
                    try:
                        payload: object = read_stream(result)
                    finally:
                        result.close()
                else:
                    payload = json.loads(result.body) if result.body else None
                return result.status, dict(result.headers), payload

            def commit_headers(**precondition: str) -> dict[str, str]:
                return {"content_type": api.COMMIT_MEDIA_TYPE, **precondition}

            # The owner creates a campaign and shares it with a friend.
            status, headers, created = await request(OWNER, "POST", api.PREFIX)
            self.assertEqual(status, 201)
            campaign = created["campaign"]
            members = f"{api.PREFIX}/{campaign}/members/{quote(FRIEND, safe='')}"
            status, _, shared = await request(OWNER, "PUT", members, if_match=headers["etag"])
            self.assertEqual((status, shared["members"]), (200, [FRIEND]))

            # The friend hosts tonight's session, bound to the campaign, and commits the first checkpoint.
            sessions.host("night-1", FRIEND, campaign)
            checkpoint_path = f"{api.PREFIX}/{campaign}/checkpoint"
            first_files = {1: stage_file(1)}
            status, headers, body = await request(
                FRIEND, "POST", checkpoint_path, api.encode_commit("night-1", **common(1), stages=first_files),
                **commit_headers(if_none_match="*"))
            self.assertEqual((status, body["checkpoint"]["revision"], body["checkpoint"]["author"]), (201, 1, FRIEND))
            first_etag = headers["etag"]

            # The owner reads it back, every payload checked against the manifest.
            status, headers, body = await request(OWNER, "GET", checkpoint_path)
            self.assertEqual((status, headers["etag"]), (200, first_etag))
            manifest = body["checkpoint"]
            base = f"{api.PREFIX}/{campaign}/checkpoints/{manifest['revision']}"
            for suffix, entry, data in (("story", manifest["story"], story(1)),
                                        ("unique", manifest["unique"], unique(1)),
                                        ("stages/1", manifest["stages"]["1"], first_files[1])):
                status, headers, payload = await request(OWNER, "GET", f"{base}/{suffix}")
                self.assertEqual((status, payload), (200, data))
                self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"])
                self.assertEqual(headers["x-checkpoint-etag"], first_etag)

            # The next night the owner hosts and commits on top of it; the friend's session is over.
            del sessions.live["night-1"]
            sessions.host("night-2", OWNER, campaign)
            status, headers, body = await request(
                OWNER, "POST", checkpoint_path, api.encode_commit("night-2", **common(2), stages={2: stage_file(2)}),
                **commit_headers(if_match=first_etag))
            self.assertEqual((status, body["checkpoint"]["revision"], sorted(body["checkpoint"]["stages"])),
                             (201, 2, ["1", "2"]))
            second_etag = headers["etag"]

            # The friend's old session no longer hosts anything; a new one with a stale etag loses.
            status, _, body = await request(FRIEND, "POST", checkpoint_path,
                                            api.encode_commit("night-1", **common(3)),
                                            **commit_headers(if_match=first_etag))
            self.assertEqual((status, body["error"]), (403, "not_host"))
            sessions.host("night-3", FRIEND, campaign)
            status, _, body = await request(FRIEND, "POST", checkpoint_path,
                                            api.encode_commit("night-3", **common(3)),
                                            **commit_headers(if_match=first_etag))
            self.assertEqual((status, body["error"], f'"{body["etag"]}"', body["revision"]),
                             (412, "precondition_failed", second_etag, 2))
            status, _, body = await request(FRIEND, "GET", f"{api.PREFIX}/{campaign}/checkpoints")
            self.assertEqual([entry["revision"] for entry in body["checkpoints"]], [2, 1])

            # The owner takes the campaign back from the friend, whose host binding no longer helps.
            status, _, body = await request(OWNER, "DELETE", members, if_match="*")
            self.assertEqual((status, body["members"]), (200, []))
            status, _, body = await request(FRIEND, "POST", checkpoint_path,
                                            api.encode_commit("night-3", **common(3)),
                                            **commit_headers(if_match=second_etag))
            self.assertEqual((status, body["error"]), (404, "not_found"))
            status, _, body = await request(FRIEND, "GET", f"{api.PREFIX}/{campaign}")
            self.assertEqual((status, body["error"]), (404, "not_found"))

            # The owner deletes it, for good.
            status, _, body = await request(OWNER, "DELETE", f"{api.PREFIX}/{campaign}", if_match="*")
            self.assertEqual((status, body), (204, None))
            status, _, body = await request(OWNER, "GET", checkpoint_path)
            self.assertEqual((status, body["error"]), (404, "not_found"))
            status, _, body = await request(OWNER, "GET", api.PREFIX)
            self.assertEqual((status, body), (200, {"campaigns": []}))


if __name__ == "__main__":
    unittest.main()
