"""Contract tests for /campaign/live: the live quest events of a story co-op game session, as the
bridge of each member sees them over the server's own HTTP/1.1 and HTTP/2 handling.

Every test runs over both transports, with the account (Principal) a device certificate would give
the connection. Run them from this directory with the dependencies installed:

    python -m unittest test_campaign_live
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

import h11
import h2.config
import h2.connection
import h2.events

import campaign_store as cs
import server
from server import Msg, encode
from test_campaign_store import common

TENANT = "tenants/t-test"
SESSION_ID = ":K5Y67P9D4Q8V"  # Synthetic host session identifier.
PASSWORD = "H4N7Q2"
LIVE = server.CAMPAIGN_LIVE_PATH
PROPOSALS = server.CAMPAIGN_PROPOSALS_PATH


def text(value: str) -> bytes:
    return encode((7, value))  # common.Value string_value


def id_token(subject: str) -> str:
    """The emulator's unsigned id token: only its subject matters."""
    payload = base64.urlsafe_b64encode(json.dumps({"sub": subject}).encode()).rstrip(b"=").decode()
    return f"e30.{payload}."


def update(name: str, fields: dict[str, bytes]) -> bytes:
    """A Ugcstore WriteOperation that replaces a document."""
    return encode((1, encode((1, encode((1, name), (2, server.encode_map(fields)))))))


def changes(*events: tuple[int, int, int]) -> list[dict[str, int]]:
    return [{"id": quest, "old": old, "new": new} for quest, old, new in events]


def numbered(first: int, *events: tuple[int, int, int]) -> list[dict[str, int]]:
    """The events as a poll answers them, numbered from `first`."""
    return [{"seq": seq, **event} for seq, event in enumerate(changes(*events), first)]


class Account:
    """One portal account with one emulator profile and its NPLN user."""

    def __init__(self, backend: server.Backend, account: str, network: str, profile: str = "profile"):
        self.backend = backend
        self.principal = server.Principal(account, f"dev-{account}")
        self.network = network
        request = encode((1, "tenants/current"), (2, 1), (3, encode((1, id_token(profile)))))
        response = Msg(backend.issue_prearranged_user_token(self.call(), Msg(request)))
        self.user = response.get_msg(1).get_str(1)
        self.token = response.get_msg(2).get_str(2)
        self.documents = f"{TENANT}/documents/users/{self.user.rpartition('/users/')[2]}"

    def call(self) -> server.Call:
        metadata = {"npln-tenant-id": "t-test"}
        if getattr(self, "token", ""):
            metadata["authorization"] = f"Bearer {self.token}"
        return server.Call("", metadata, self.principal, self.network)

    def commit(self, *operations: bytes) -> bytes:
        return self.backend.commit_documents(self.call(), Msg(encode(*[(2, op) for op in operations])))

    def get(self, name: str, password: str) -> Msg:
        context = server.encode_map({"password": text(password)})
        return Msg(self.backend.get_document(self.call(), Msg(encode((1, name), (3, context)))))

    def host(self, password: str = PASSWORD) -> server.GameSession:
        properties = server.encode_map({"string1": text(SESSION_ID)})
        ticket_request = encode((2, "tenants/current/matchmakingConfigs/MatchmakingConfigsDefault"),
                                (3, encode((1, "tenants/current/users/current"))),
                                (6, encode((6, password), (11, properties))))
        response = self.backend.create_game_session_creation_ticket(
            self.call(), Msg(encode((1, "tenants/current"), (2, ticket_request))))
        return self.backend.tickets[Msg(response).get_str(1)].session

    def join(self, session: server.GameSession, password: str = PASSWORD) -> Msg:
        request = encode((1, session.name), (2, password), (3, encode((1, "tenants/current/users/current"))))
        return Msg(self.backend.join_game_session(self.call(), Msg(request)))


class FakeWriter:
    def __init__(self) -> None:
        self.sent = bytearray()  # what the server wrote, for a client to read

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


class Bridge:
    """What a member's bridge sees of the server: one connection per request, through serve_http1
    or H2Session, from the account behind `principal` (None: a connection without a device
    certificate, as in local mode)."""

    def __init__(self, srv: server.Server, principal: server.Principal | None, transport: str):
        self.server = srv
        self.principal = principal
        self.transport = transport

    async def discover(self) -> tuple[int, dict]:
        return await self.exchange("GET", LIVE)

    async def poll(self, session: str, epoch: str, after: int) -> tuple[int, dict]:
        return await self.exchange("GET", f"{LIVE}?{urlencode({'session': session, 'epoch': epoch, 'after': after})}")

    async def post(self, session: str, epoch: str, first: int, *events: tuple[int, int, int]) -> tuple[int, dict]:
        body = {"session": session, "epoch": epoch, "first": first, "events": changes(*events)}
        return await self.exchange("POST", LIVE, json.dumps(body).encode(), "application/json")

    async def propose(self, session: str, epoch: str, producer: str, first: int,
                      *events: dict) -> tuple[int, dict]:
        body = {"session": session, "epoch": epoch, "producer": producer, "first": first, "events": events}
        return await self.exchange("POST", PROPOSALS, json.dumps(body).encode(), "application/json")

    async def proposals(self, session: str, epoch: str, after: int) -> tuple[int, dict]:
        query = urlencode({"session": session, "epoch": epoch, "after": after})
        return await self.exchange("GET", f"{PROPOSALS}?{query}")

    async def exchange(self, method: str, target: str, body: bytes = b"",
                       content_type: str | None = None) -> tuple[int, dict]:
        status, headers, payload = await self.request(method, target, body, content_type)
        if target.startswith(LIVE):
            assert headers["content-type"] == "application/json", headers
            assert headers["cache-control"] == "no-store", headers
        return status, json.loads(payload)

    async def request(self, method: str, target: str, body: bytes = b"",
                      content_type: str | None = None) -> tuple[int, dict[str, str], bytes]:
        headers = [("content-type", content_type)] if content_type is not None else []
        if self.transport == "http1":
            return await self.http1(method, target, body, headers)
        return await self.http2(method, target, body, headers)

    async def http1(self, method: str, target: str, body: bytes,
                    headers: list[tuple[str, str]]) -> tuple[int, dict[str, str], bytes]:
        client = h11.Connection(h11.CLIENT)
        data = client.send(h11.Request(method=method, target=target,
                                       headers=[("host", "test"), ("content-length", str(len(body))), *headers]))
        if body:
            data += client.send(h11.Data(data=body))
        data += client.send(h11.EndOfMessage())
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        writer = FakeWriter()
        await server.serve_http1(self.server, reader, writer, principal=self.principal)
        client.receive_data(bytes(writer.sent))
        status, response_headers, payload = 0, {}, bytearray()
        while not isinstance(event := client.next_event(), h11.EndOfMessage):
            if isinstance(event, h11.Response):
                status = event.status_code
                response_headers = {name.decode(): value.decode() for name, value in event.headers}
            elif isinstance(event, h11.Data):
                payload += event.data
            else:
                raise AssertionError(f"unexpected {event!r}")
        return status, response_headers, bytes(payload)

    async def http2(self, method: str, target: str, body: bytes,
                    headers: list[tuple[str, str]]) -> tuple[int, dict[str, str], bytes]:
        writer = FakeWriter()
        session = server.H2Session(self.server, None, writer, self.principal)
        session.conn.initiate_connection()
        client = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        client.initiate_connection()
        client.send_headers(1, [(":method", method), (":scheme", "https"), (":authority", "test"),
                                (":path", target), *headers], end_stream=not body)
        frame = client.max_outbound_frame_size
        for offset in range(0, len(body), frame):
            client.send_data(1, body[offset:offset + frame], end_stream=offset + frame >= len(body))
        for event in session.conn.receive_data(client.data_to_send()):
            session.on_event(event)
        await session.tasks[1]
        status, response_headers, payload, ended = 0, {}, bytearray(), False
        for event in client.receive_data(bytes(writer.sent)):
            if isinstance(event, h2.events.ResponseReceived):
                response_headers = {name.decode(): value.decode() for name, value in event.headers}
                status = int(response_headers[":status"])
            elif isinstance(event, h2.events.DataReceived):
                payload += event.data
            ended = ended or (isinstance(event, h2.events.StreamEnded) and event.stream_id == 1)
        if not ended:
            raise AssertionError("the response did not end")
        return status, response_headers, bytes(payload)


class CampaignAccountPurgeTest(unittest.IsolatedAsyncioTestCase):
    async def test_deleted_members_and_owners_are_purged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = server.Server(argparse.Namespace(
                data_dir=Path(directory), storage_url="https://storage.invalid", max_storage_mb=1024,
                max_players=4, stun="", stun_port=0, gamesync_port=443, port=None, client_ca=None, auth_db=None))
            registry = instance.campaigns
            campaign = registry.create("owner")
            registry.add_member(campaign.campaign, "owner", "guest", if_match=campaign.etag)
            saved = registry.commit(campaign.campaign, "owner", None, **common(1))
            instance.auth = mock.Mock()
            instance.auth.deleted_accounts.return_value = {"guest"}
            await instance.purge_deleted_accounts_once()
            with self.assertRaises(cs.CampaignNotFound):
                registry.get(campaign.campaign, "guest")
            self.assertEqual(registry.read(campaign.campaign, "owner").checkpoint, saved)
            instance.auth.deleted_accounts.return_value = {"owner"}
            await instance.purge_deleted_accounts_once()
            with self.assertRaises(cs.CampaignNotFound):
                registry.get(campaign.campaign, "owner")
            self.assertTrue(registry.purged("owner"))


class CampaignLiveTest(unittest.IsolatedAsyncioTestCase):
    """The host (the game session's creator) and the guest are in one game session; the stranger's
    account has no user in it."""

    transport = "http1"

    async def asyncSetUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.server = server.Server(argparse.Namespace(
            data_dir=Path(directory.name), storage_url="https://storage.invalid", max_storage_mb=1024,
            max_players=4, stun="", stun_port=0, gamesync_port=443, port=None, client_ca=None, auth_db=None))
        self.backend = self.server.backend
        self.host = Account(self.backend, "acct-host", "198.51.100.1")
        self.guest = Account(self.backend, "acct-guest", "203.0.113.1")
        self.stranger = Account(self.backend, "acct-stranger", "192.0.2.7")
        self.host.commit(
            update(f"{self.host.documents}/private/PasswordData", {"password": text(PASSWORD)}),
            update(f"{self.host.documents}/private/SessionIDData", {"sessionID": text(SESSION_ID[1:])}),
        )
        self.session = self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.guest.join(self.session)

    def bridge(self, account: Account | None) -> Bridge:
        return Bridge(self.server, account.principal if account is not None else None, self.transport)

    async def epoch(self) -> str:
        status, state = await self.bridge(self.host).discover()
        self.assertEqual(status, 200, state)
        return state["epoch"]

    async def events(self, after: int = 0) -> dict:
        """What the guest polls after sequence number `after`, which must succeed."""
        status, state = await self.bridge(self.guest).poll(self.session.name, await self.epoch(), after)
        self.assertEqual(status, 200, state)
        return state

    def assert_error(self, reply: tuple[int, dict], status: int, code: str, **bounds: int) -> None:
        self.assertEqual(reply[0], status, reply[1])
        self.assertEqual(reply[1]["error"], code, reply[1])
        self.assertIsInstance(reply[1]["message"], str)
        for name, value in bounds.items():
            self.assertEqual(reply[1][name], value, reply[1])

    # Access

    async def test_members_discover_their_session_and_role(self) -> None:
        status, guest = await self.bridge(self.guest).discover()  # the first to ask starts the journal
        self.assertEqual(status, 200, guest)
        status, host = await self.bridge(self.host).discover()
        self.assertEqual(status, 200, host)
        self.assertEqual(host, {"session": self.session.name, "epoch": guest["epoch"], "role": "host",
                                "first": 1, "last": 0, "events": []})
        self.assertEqual(guest, {**host, "role": "guest"})
        self.assertRegex(host["epoch"], r"^[a-z2-7]{20}$")

    async def test_others_see_no_session(self) -> None:
        epoch = await self.epoch()
        stranger = self.bridge(self.stranger)
        self.assert_error(await stranger.discover(), 404, "no_session")
        self.assert_error(await stranger.poll(self.session.name, epoch, 0), 404, "session_gone")
        self.assert_error(await stranger.post(self.session.name, epoch, 1, (1, 1, 2)), 404, "session_gone")
        self.assertEqual((await self.events())["last"], 0)

    async def test_connections_without_an_account_are_refused(self) -> None:
        epoch = await self.epoch()
        anonymous = self.bridge(None)
        self.assert_error(await anonymous.discover(), 401, "unauthenticated")
        self.assert_error(await anonymous.poll(self.session.name, epoch, 0), 401, "unauthenticated")
        self.assert_error(await anonymous.post(self.session.name, epoch, 1, (1, 1, 2)), 401, "unauthenticated")
        self.assert_error(await anonymous.exchange("PUT", LIVE), 401, "unauthenticated")
        self.assertEqual((await self.events())["last"], 0)

    async def test_only_the_creators_account_posts(self) -> None:
        epoch = await self.epoch()
        self.assert_error(await self.bridge(self.guest).post(self.session.name, epoch, 1, (1, 1, 2)),
                          403, "not_host")
        self.assertEqual((await self.events())["last"], 0)
        # The creator's account, while the creator is in the session, posts.
        status, posted = await self.bridge(self.host).post(self.session.name, epoch, 1, (1, 1, 2))
        self.assertEqual(status, 200, posted)

    async def test_an_account_in_several_sessions_must_name_one(self) -> None:
        epoch = await self.epoch()
        second = Account(self.backend, self.host.principal.account, self.host.network, profile="second")
        self.assertNotEqual(second.user, self.host.user)
        second.host(password="")
        self.assert_error(await self.bridge(self.host).discover(), 404, "ambiguous_session")
        status, state = await self.bridge(self.host).poll(self.session.name, epoch, 0)
        self.assertEqual((status, state["role"]), (200, "host"), state)

    async def test_guest_proposals_are_ordered_idempotent_and_visible_only_to_host(self) -> None:
        epoch, producer = await self.epoch(), "1" * 32
        host, guest, stranger = self.bridge(self.host), self.bridge(self.guest), self.bridge(self.stranger)
        accepted = {"kind": "unique", "id": 11, "field": "state", "old": 2, "new": 3, "site": 2}
        counter = {"kind": "unique", "id": 11, "field": "counter", "old": 0, "new": 3, "site": 9}
        story = {"kind": "story", "id": 10, "old": 1, "new": 2}
        self.assert_error(await stranger.propose(self.session.name, epoch, producer, 1, accepted),
                          404, "session_gone")
        self.assert_error(await self.bridge(None).propose(self.session.name, epoch, producer, 1, accepted),
                          401, "unauthenticated")
        self.assert_error(await host.propose(self.session.name, epoch, producer, 1, accepted), 403, "not_guest")
        self.assert_error(await guest.proposals(self.session.name, epoch, 0), 403, "not_host")
        status, result = await guest.propose(self.session.name, epoch, producer, 1, accepted, counter)
        self.assertEqual((status, result["added"], result["last"]), (200, 2, 2))
        status, retry = await guest.propose(self.session.name, epoch, producer, 1, accepted, counter)
        self.assertEqual((status, retry["added"], retry["last"]), (200, 0, 2))
        status, overlap = await guest.propose(self.session.name, epoch, producer, 2, counter, story)
        self.assertEqual((status, overlap["added"], overlap["last"]), (200, 1, 3))
        self.assert_error(await guest.propose(self.session.name, epoch, producer, 3, accepted, story),
                          409, "sequence_conflict", first=1, last=3)
        self.assert_error(await guest.propose(self.session.name, epoch, producer, 5, story),
                          409, "sequence_gap", first=1, last=3)
        status, result = await host.proposals(self.session.name, epoch, 0)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["proposals"],
                         [{"seq": i, "producer": producer, "number": i, "event": event}
                          for i, event in enumerate((accepted, counter, story), 1)])
        self.assertEqual((await self.events())["events"], [])  # proposals are not authoritative events

    async def test_guest_proposal_producer_cannot_be_claimed_by_another_account(self) -> None:
        epoch, producer = await self.epoch(), "a" * 32
        event = {"kind": "unique", "id": 11, "field": "state", "old": 2, "new": 3, "site": 2}
        self.assertEqual((await self.bridge(self.guest).propose(self.session.name, epoch, producer, 1, event))[0], 200)
        self.stranger.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.stranger.join(self.session)
        self.assert_error(await self.bridge(self.stranger).propose(self.session.name, epoch, producer, 2, event),
                          403, "producer_owned")
        other = "d" * 32
        self.assertEqual((await self.bridge(self.stranger).propose(self.session.name, epoch, other, 1, event))[0], 200)
        status, state = await self.bridge(self.host).proposals(self.session.name, epoch, 0)
        self.assertEqual((status, [(p["seq"], p["producer"], p["number"]) for p in state["proposals"]]),
                         (200, [(1, producer, 1), (2, other, 1)]))

    async def test_guest_proposal_eviction_and_epoch_changes_fail_closed(self) -> None:
        with mock.patch.object(server, "MAX_LIVE_EVENTS", 3):
            epoch, producer = await self.epoch(), "b" * 32
            host, guest = self.bridge(self.host), self.bridge(self.guest)
            events = [{"kind": "story", "id": i, "old": 1, "new": 2} for i in range(1, 5)]
            self.assertEqual((await guest.propose(self.session.name, epoch, producer, 1, *events))[0], 200)
            self.assert_error(await host.proposals(self.session.name, epoch, 0), 409, "cursor_expired",
                              first=2, last=4)
            self.assert_error(await guest.propose(self.session.name, epoch, producer, 1, events[0]),
                              409, "sequence_expired", first=2, last=4)
            status, state = await host.proposals(self.session.name, epoch, 1)
            self.assertEqual((status, [p["event"] for p in state["proposals"]]), (200, events[1:]))
            self.backend.drop_user_session(self.session, self.host.user)
            self.assert_error(await guest.propose(self.session.name, epoch, producer, 5, events[0]),
                              409, "host_absent")
            self.host.join(self.session)
            new_epoch = await self.epoch()
            self.assertNotEqual(new_epoch, epoch)
            self.assert_error(await host.proposals(self.session.name, epoch, 0), 409, "stale_epoch")
            status, state = await host.proposals(self.session.name, new_epoch, 0)
            self.assertEqual((status, state["first"], state["last"], state["proposals"]), (200, 1, 0, []))

    async def test_producer_limit_preserves_existing_retry_history(self) -> None:
        with mock.patch.object(server, "MAX_LIVE_PRODUCERS", 1):
            epoch = await self.epoch()
            guest, host = self.bridge(self.guest), self.bridge(self.host)
            event = {"kind": "story", "id": 11, "old": 1, "new": 2}
            self.assertEqual((await guest.propose(self.session.name, epoch, "1" * 32, 1, event))[0], 200)
            self.assert_error(await guest.propose(self.session.name, epoch, "2" * 32, 1, event),
                              429, "too_many_producers")
            status, retry = await guest.propose(self.session.name, epoch, "1" * 32, 1, event)
            self.assertEqual((status, retry["added"]), (200, 0))
            status, state = await host.proposals(self.session.name, epoch, 0)
            self.assertEqual((status, state["last"]), (200, 1))

    async def test_guest_proposals_reject_invalid_writer_and_batch_atomically(self) -> None:
        epoch, producer = await self.epoch(), "c" * 32
        host, guest = self.bridge(self.host), self.bridge(self.guest)
        valid = {"kind": "unique", "id": 11, "field": "state", "old": 2, "new": 3, "site": 2}
        for bad in ({**valid, "site": 1}, {**valid, "id": 201}, {**valid, "new": True},
                    {**valid, "field": "counter"}, {**valid, "extra": 1}):
            with self.subTest(bad=bad):
                self.assert_error(await guest.propose(self.session.name, epoch, producer, 1, valid, bad),
                                  400, "bad_request")
        self.assert_error(await guest.propose(self.session.name, epoch, "not-a-producer", 1, valid),
                          400, "bad_request")
        status, state = await host.proposals(self.session.name, epoch, 0)
        self.assertEqual((status, state["last"], state["proposals"]), (200, 0, []))
        self.assertEqual((await guest.propose(self.session.name, epoch, producer, 1, valid))[0], 200)

    # Ordering

    async def test_guests_poll_the_hosts_events_in_order(self) -> None:
        epoch = await self.epoch()
        host, guest = self.bridge(self.host), self.bridge(self.guest)
        status, posted = await host.post(self.session.name, epoch, 1, (10, 1, 2), (11, 2, 3), (10, 2, 3))
        self.assertEqual(status, 200, posted)
        self.assertEqual(posted, {"session": self.session.name, "epoch": epoch, "role": "host", "first": 1, "last": 3})
        status, polled = await guest.poll(self.session.name, epoch, 0)
        self.assertEqual(status, 200, polled)
        self.assertEqual(polled, {"session": self.session.name, "epoch": epoch, "role": "guest", "first": 1,
                                  "last": 3, "events": numbered(1, (10, 1, 2), (11, 2, 3), (10, 2, 3))})
        self.assertEqual([list(event) for event in polled["events"]], [["seq", "id", "old", "new"]] * 3)
        self.assertEqual((await guest.poll(self.session.name, epoch, 2))[1]["events"], numbered(3, (10, 2, 3)))
        self.assertEqual((await guest.poll(self.session.name, epoch, 3))[1]["events"], [])
        status, posted = await host.post(self.session.name, epoch, 4, (12, 1, 4), (1000, 4, 1))
        self.assertEqual((status, posted["last"]), (200, 5), posted)
        self.assertEqual((await guest.poll(self.session.name, epoch, 3))[1]["events"],
                         numbered(4, (12, 1, 4), (1000, 4, 1)))
        status, own = await host.poll(self.session.name, epoch, 4)  # the host reads them too
        self.assertEqual((status, own["role"], own["events"]), (200, "host", numbered(5, (1000, 4, 1))))

    async def test_a_poll_answers_at_most_one_batch(self) -> None:
        epoch = await self.epoch()
        host = self.bridge(self.host)
        batch = server.MAX_LIVE_BATCH
        for first in (1, batch + 1):
            events = [(quest, 1, 2) for quest in range(first, first + batch)]
            self.assertEqual((await host.post(self.session.name, epoch, first, *events))[0], 200)
        state = await self.events(0)
        self.assertEqual((state["first"], state["last"]), (1, 2 * batch))
        self.assertEqual([event["seq"] for event in state["events"]], list(range(1, batch + 1)))
        state = await self.events(batch)
        self.assertEqual([event["seq"] for event in state["events"]], list(range(batch + 1, 2 * batch + 1)))

    async def test_a_resend_succeeds_and_a_conflict_or_gap_fails(self) -> None:
        epoch = await self.epoch()
        host = self.bridge(self.host)
        self.assertEqual((await host.post(self.session.name, epoch, 1, (1, 1, 2), (2, 1, 2)))[1]["last"], 2)
        # A retry after a lost answer, and one that overlaps with what follows, add nothing twice.
        status, posted = await host.post(self.session.name, epoch, 1, (1, 1, 2), (2, 1, 2))
        self.assertEqual((status, posted["last"]), (200, 2), posted)
        status, posted = await host.post(self.session.name, epoch, 2, (2, 1, 2), (3, 1, 2))
        self.assertEqual((status, posted["last"]), (200, 3), posted)
        # The same numbers with other content, or a later batch that overlaps wrongly, add nothing.
        self.assert_error(await host.post(self.session.name, epoch, 2, (2, 1, 3)), 409, "sequence_conflict",
                          first=1, last=3)
        self.assert_error(await host.post(self.session.name, epoch, 3, (9, 1, 2), (4, 1, 2)), 409,
                          "sequence_conflict", first=1, last=3)
        self.assert_error(await host.post(self.session.name, epoch, 5, (5, 1, 2)), 409, "sequence_gap",
                          first=1, last=3)
        self.assertEqual((await self.events())["events"], numbered(1, (1, 1, 2), (2, 1, 2), (3, 1, 2)))

    async def test_a_cursor_past_the_kept_events_fails(self) -> None:
        with mock.patch.object(server, "MAX_LIVE_EVENTS", 4):
            epoch = await self.epoch()  # the journal starts, keeping 4 events
        host, guest = self.bridge(self.host), self.bridge(self.guest)
        events = [(quest, 1, 2) for quest in range(1, 7)]
        status, posted = await host.post(self.session.name, epoch, 1, *events)
        self.assertEqual((status, posted["first"], posted["last"]), (200, 3, 6), posted)
        for after in (0, 1):
            self.assert_error(await guest.poll(self.session.name, epoch, after), 409, "cursor_expired",
                              first=3, last=6)
        status, polled = await guest.poll(self.session.name, epoch, 2)
        self.assertEqual((status, polled["events"]), (200, numbered(3, *events[2:])), polled)
        self.assert_error(await guest.poll(self.session.name, epoch, 7), 409, "cursor_ahead", first=3, last=6)
        # A resend reaching back past the kept events cannot be checked.
        self.assert_error(await host.post(self.session.name, epoch, 2, *events[1:]), 409, "sequence_expired")
        self.assertEqual((await host.post(self.session.name, epoch, 3, *events[2:]))[0], 200)

    # Epochs and session lifetime

    async def test_the_journal_starts_over_when_the_creator_returns(self) -> None:
        old = await self.epoch()
        host, guest = self.bridge(self.host), self.bridge(self.guest)
        self.assertEqual((await host.post(self.session.name, old, 1, (1, 1, 2)))[0], 200)
        self.backend.drop_user_session(self.session, self.host.user)  # the creator's game is gone
        status, polled = await guest.poll(self.session.name, old, 0)  # what it posted stays readable
        self.assertEqual((status, polled["role"], polled["events"]), (200, "guest", numbered(1, (1, 1, 2))))
        self.assert_error(await host.discover(), 404, "no_session")
        self.assert_error(await host.post(self.session.name, old, 2, (2, 1, 2)), 404, "session_gone")
        self.host.join(self.session)  # under a new user session
        status, state = await host.discover()
        self.assertEqual((status, state["role"], state["first"], state["last"]), (200, "host", 1, 0), state)
        self.assertNotEqual(state["epoch"], old)
        self.assert_error(await guest.poll(self.session.name, old, 1), 409, "stale_epoch")
        self.assert_error(await host.post(self.session.name, old, 2, (2, 1, 2)), 409, "stale_epoch")
        self.assert_error(await guest.poll(self.session.name, "a" * 20, 0), 409, "stale_epoch")

    async def test_expired_sessions_fail(self) -> None:
        epoch = await self.epoch()
        host, guest = self.bridge(self.host), self.bridge(self.guest)
        # The guest's game has had no KeepUserSession call open for longer than the grace period.
        self.session.user_sessions[self.guest.user].last_seen -= (server.USER_SESSION_GRACE_SECONDS + 1) * 10 ** 9
        self.assert_error(await guest.poll(self.session.name, epoch, 0), 404, "session_gone")
        self.assert_error(await guest.discover(), 404, "no_session")
        self.assertNotIn(self.guest.user, self.session.user_sessions)
        self.backend.drop_user_session(self.session, self.host.user)  # the last member leaves
        self.assertNotIn(self.session.name, self.backend.sessions)
        self.assert_error(await host.post(self.session.name, epoch, 1, (1, 1, 2)), 404, "session_gone")
        self.assert_error(await host.poll(self.session.name, epoch, 0), 404, "session_gone")
        self.assert_error(await host.discover(), 404, "no_session")

    # Malformed requests

    async def test_malformed_posts_are_refused(self) -> None:
        epoch = await self.epoch()
        host = self.bridge(self.host)
        base = {"session": self.session.name, "epoch": epoch, "first": 1, "events": changes((1, 1, 2))}
        valid = json.dumps(base)

        def body(**fields: object) -> bytes:
            return json.dumps({**base, **fields}).encode()

        def event(**fields: object) -> bytes:
            return body(events=[{"id": 1, "old": 1, "new": 2, **fields}])

        without_events = {key: value for key, value in base.items() if key != "events"}
        cases = [
            ("not JSON", b"{", 400, "bad_request"),
            ("not UTF-8", b'{"session": "\xff"}', 400, "bad_request"),
            ("not an object", b"[]", 400, "bad_request"),
            ("missing events", json.dumps(without_events).encode(), 400, "bad_request"),
            ("extra key", body(extra=1), 400, "bad_request"),
            ("key twice", (valid[:-1] + ', "first": 1}').encode(), 400, "bad_request"),
            ("NaN", valid.replace('"first": 1', '"first": NaN').encode(), 400, "bad_request"),
            ("first 0", body(first=0), 400, "bad_request"),
            ("first boolean", body(first=True), 400, "bad_request"),
            ("first fraction", body(first=1.0), 400, "bad_request"),
            ("first string", body(first="1"), 400, "bad_request"),
            ("no events", body(events=[]), 400, "bad_request"),
            ("events object", body(events={}), 400, "bad_request"),
            ("event list", body(events=[[1, 1, 2]]), 400, "bad_request"),
            ("event without new", body(events=[{"id": 1, "old": 1}]), 400, "bad_request"),
            ("event extra key", event(seq=1), 400, "bad_request"),
            ("id 0", event(id=0), 400, "bad_request"),
            ("id 1001", event(id=server.MAX_QUEST_ID + 1), 400, "bad_request"),
            ("id boolean", event(id=True), 400, "bad_request"),
            ("state 0", event(old=0), 400, "bad_request"),
            ("state 5", event(new=server.MAX_QUEST_STATE + 1), 400, "bad_request"),
            ("state fraction", event(new=2.0), 400, "bad_request"),
            ("unchanged state", event(new=1), 400, "bad_request"),
            ("malformed epoch", body(epoch="x"), 400, "bad_request"),
            ("numeric epoch", body(epoch=1), 400, "bad_request"),
            ("empty session", body(session=""), 400, "bad_request"),
            ("numeric session", body(session=1), 400, "bad_request"),
            ("too many events", body(events=changes(*[(1, 1, 2)] * (server.MAX_LIVE_BATCH + 1))), 413, "too_large"),
            ("oversized body", valid.encode() + b" " * server.MAX_LIVE_REQUEST_BYTES, 413, "too_large"),
        ]
        for name, payload, status, code in cases:
            with self.subTest(name):
                self.assert_error(await host.exchange("POST", LIVE, payload, "application/json"), status, code)
        for content_type in ("text/plain", None):
            with self.subTest(content_type=content_type):
                self.assert_error(await host.exchange("POST", LIVE, valid.encode(), content_type),
                                  415, "unsupported_media_type")
        self.assert_error(await host.exchange("POST", f"{LIVE}?after=0", valid.encode(), "application/json"),
                          400, "bad_request")
        self.assertEqual((await self.events())["last"], 0)
        status, posted = await host.exchange("POST", LIVE, valid.encode(), "application/json; charset=utf-8")
        self.assertEqual((status, posted["last"]), (200, 1), posted)

    async def test_malformed_polls_are_refused(self) -> None:
        epoch = await self.epoch()
        guest = self.bridge(self.guest)
        query = {"session": self.session.name, "epoch": epoch, "after": "0"}
        cases = [
            ("no after", urlencode({"session": self.session.name, "epoch": epoch})),
            ("extra key", urlencode({**query, "extra": "1"})),
            ("after twice", urlencode(query) + "&after=0"),
            ("field without value", urlencode(query) + "&after"),
            ("negative after", urlencode({**query, "after": "-1"})),
            ("signed after", urlencode({**query, "after": "+1"})),
            ("zero-padded after", urlencode({**query, "after": "01"})),
            ("fractional after", urlencode({**query, "after": "1.0"})),
            ("empty after", urlencode({**query, "after": ""})),
            ("malformed epoch", urlencode({**query, "epoch": "x"})),
            ("empty session", urlencode({**query, "session": ""})),
            ("session not UTF-8", urlencode({**query, "session": "x"}).replace("session=x", "session=%FF")),
        ]
        for name, target in cases:
            with self.subTest(name):
                self.assert_error(await guest.exchange("GET", f"{LIVE}?{target}"), 400, "bad_request")
        self.assert_error(await guest.exchange("GET", f"{LIVE}?{urlencode(query)}", b"{}", "application/json"),
                          400, "bad_request")
        for method in ("PUT", "DELETE"):
            with self.subTest(method):
                status, headers, payload = await guest.request(method, LIVE)
                self.assertEqual((status, headers["allow"], json.loads(payload)["error"]),
                                 (405, "GET, POST", "method_not_allowed"))

    # Storage, beside it

    async def test_storage_is_served_as_before(self) -> None:
        host = self.bridge(self.host)
        for path in (f"{LIVE}/", f"{LIVE}x", "/campaign"):
            with self.subTest(path):
                status, headers, payload = await host.request("GET", path)
                self.assertEqual((status, headers["content-type"], payload), (404, "text/plain", b"not found\n"))
        upload_id = self.server.storage.new_upload(self.host.principal.account)
        status, _, payload = await host.request("PUT", f"/upload/{upload_id}", b"island")
        self.assertEqual((status, json.loads(payload)["name"]), (200, upload_id))
        self.assertEqual((await host.request("GET", f"/download/{upload_id}"))[::2], (200, b"island"))
        # Live events are no download: they are answered while downloads are at their limit.
        self.server.downloads = server.MAX_DOWNLOADS
        self.assertEqual((await host.request("GET", f"/download/{upload_id}"))[0], 503)
        self.assertEqual((await host.discover())[0], 200)


class CampaignLiveHttp2Test(CampaignLiveTest):
    transport = "http2"


if __name__ == "__main__":
    unittest.main()
