"""Regression tests: game sessions open at the same time keep their Gamesync state apart, even when
deferred writes fail. Deferred writes stay within the Gamesync limit and are applied under request
memory pressure and after their tokens expire, one at a time, each as a commit of its own within a
parsing budget of its own, and commits copy no more than they may. With --turn the ICE server set
carries TURN credentials coturn accepts, and with --relay-only every Gamesync delivery offers only
relay candidates on that TURN server.

Run them from this directory with the dependencies installed:

    python -m unittest test_gamesync_isolation
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import gc
import hashlib
import hmac
import logging
import secrets
import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

import server
from server import Msg, encode

TENANT = "tenants/t-test"


def call(token: str = "") -> server.Call:
    metadata = {"npln-tenant-id": "t-test"}
    if token:
        metadata["authorization"] = f"Bearer {token}"
    return server.Call("", metadata)


def definition(user: str) -> bytes:
    return encode((1, f"{TENANT}/users/{user}"))  # UserDefinition


def text(value: str) -> bytes:
    return encode((7, value))  # common.Value string_value


def update(name: str, fields: dict[str, bytes]) -> bytes:
    """A WriteOperation that replaces a document."""
    return encode((1, encode((1, encode((1, name), (2, server.encode_map(fields)))))))


def masked_update(name: str, fields: dict[str, bytes], *paths: str) -> bytes:
    """A WriteOperation that replaces only the field `paths` of a document; those `fields` lack are
    deleted."""
    document = encode((1, name), (2, server.encode_map(fields)))
    return encode((1, encode((1, document), (2, encode(*[(1, path) for path in paths])))))


def merge(name: str, fields: dict[str, bytes]) -> bytes:
    """A WriteOperation that merges `fields` into a document."""
    return encode((2, encode((1, encode((1, name), (2, server.encode_map(fields)))))))


def transform(name: str, *field_transforms: bytes) -> bytes:
    """A WriteOperation that applies FieldTransforms to a document."""
    return encode((3, encode((1, name), *[(2, field_transform) for field_transform in field_transforms])))


def defer(deferment: bytes) -> bytes:
    """A WriteDocumentsRequest that stores a Deferment."""
    return encode((2, encode((1, encode((1, deferment))))))


class Budget:
    """Stands in for a connection's request budgets (server.request_budget): parsed messages may
    hold `room` bytes."""

    def __init__(self) -> None:
        self.room = 1 << 30
        self.held = 0

    def request_room(self) -> int:
        return self.room - self.held

    def count(self, size: int) -> None:
        self.held += size

    def uncount(self, size: int) -> None:
        self.held -= size


def gamesync_token(backend: server.Backend, session_id: str, matchmaking_token: str) -> str:
    request = encode((1, f"userSessions/{session_id}"), (2, matchmaking_token))
    return Msg(backend.gamesync_issue_token(call(), Msg(request))).get_msg(1).get_str(2)


class Player:
    """A user session and the gamesync token the game gets for it."""

    def __init__(self, backend: server.Backend, matched: Msg):
        self.user_session = matched.get_str(2)
        self.id = self.user_session.rpartition("/")[2]
        self.matchmaking_token = matched.get_str(3)
        self.call = call(gamesync_token(backend, self.id, self.matchmaking_token))


def host(backend: server.Backend, user: str) -> tuple[server.GameSession, Player]:
    request = encode((1, TENANT), (2, encode((3, definition(user)))))
    ticket_name = Msg(backend.create_game_session_creation_ticket(call(), Msg(request))).get_str(1)
    ticket = backend.tickets[ticket_name]
    return ticket.session, Player(backend, Msg(ticket.matched[0]))


def join(backend: server.Backend, session: server.GameSession, user: str) -> Player:
    request = encode((1, session.name), (3, definition(user)))
    return Player(backend, Msg(backend.join_game_session(call(), Msg(request))).get_msgs(1)[0])


def read_text(backend: server.Backend, player: Player, name: str) -> str:
    document = Msg(backend.gamesync_get_document(player.call, Msg(encode((1, name)))))
    return Msg(server.map_entries(document.get_bytes(2))["pl"]).get_str(7)


def read_fields(backend: server.Backend, player: Player, name: str) -> dict[str, bytes]:
    document = Msg(backend.gamesync_get_document(player.call, Msg(encode((1, name)))))
    return server.map_entries(document.get_bytes(2))


async def settle() -> None:
    for _ in range(50):
        await asyncio.sleep(0)


class Watch:
    """A KeepUserSession call that names its user session and watches `documents`."""

    def __init__(self, backend: server.Backend, gamesync_call: server.Call, *documents: str):
        self.requests: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.received: list[Msg] = []
        self.error: server.GrpcError | None = None
        target = encode((1, "userSessions/current/targets/1"), (2, encode(*[(1, name) for name in documents])))
        self.requests.put_nowait(encode((1, "userSessions/current"), (3, encode((1, target)))))
        self.task = asyncio.create_task(self.run(backend.keep_user_session(gamesync_call, self.incoming())))

    async def incoming(self):
        while (request := await self.requests.get()) is not None:
            yield Msg(request)

    async def run(self, responses) -> None:
        try:
            async for message in responses:
                self.received.append(Msg(message))
        except server.GrpcError as exc:
            self.error = exc

    async def close(self) -> None:
        self.requests.put_nowait(None)
        await settle()

    def changes(self) -> list[tuple[int, str, dict[str, bytes]]]:
        """Kind, document name and fields of every DocumentChange received."""
        found = []
        for message in self.received:
            if (change := message.get_msg(2)) is not None:
                document = change.get_msg(3) or Msg()
                found.append((change.get_int(2), document.get_str(1), server.map_entries(document.get_bytes(2))))
        return found

    def texts(self, name: str) -> list[str]:
        return [Msg(fields["pl"]).get_str(7) for kind, document, fields in self.changes()
                if document == name and kind != server.DOCUMENT_CHANGE_DELETED]

    def gsid(self) -> str:
        return next(Msg(fields["gsid"]).get_str(7) for _, name, fields in self.changes()
                    if name == server.GAMESYNC_GAME_SESSION_FIXED_DOC)


class GamesyncIsolationTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        logger = logging.getLogger("npln")
        self.addCleanup(logger.setLevel, logger.level)
        logger.setLevel(logging.CRITICAL)
        store = server.Store(Path(directory.name))
        self.backend = server.Backend(store, server.Storage(store, "https://storage.invalid"), 4, "", 443)

    def assert_status(self, code: int, method, gamesync_call: server.Call, request: bytes) -> None:
        with self.assertRaises(server.GrpcError) as raised:
            method(gamesync_call, Msg(request))
        self.assertEqual(raised.exception.code, code)

    def test_simultaneous_islands(self) -> None:
        asyncio.run(self.simultaneous_islands())

    async def simultaneous_islands(self) -> None:
        backend = self.backend
        island_a, host_a = host(backend, "u-host-a")
        guest_a = join(backend, island_a, "u-guest-a")
        island_b, host_b = host(backend, "u-host-b")
        watch_a = Watch(backend, host_a.call, server.GAMESYNC_GAME_SESSION_FIXED_DOC, "docs/__stg/All")
        watch_guest = Watch(backend, guest_a.call, "docs/__stg/All")
        watch_b = Watch(backend, host_b.call, server.GAMESYNC_GAME_SESSION_FIXED_DOC, "docs/__stg/All")
        anonymous = Watch(backend, call(), server.GAMESYNC_GAME_SESSION_FIXED_DOC)
        await settle()

        # Each island gets its own docs/__gs/f; a call without a gamesync token gets nothing.
        self.assertEqual(watch_a.gsid(), island_a.name.rpartition("/")[2])
        self.assertEqual(watch_b.gsid(), island_b.name.rpartition("/")[2])
        self.assertEqual(anonymous.error.code, server.UNAUTHENTICATED)
        self.assertEqual(anonymous.received, [])
        self.assert_status(server.UNAUTHENTICATED, backend.gamesync_get_document, call(),
                           encode((1, server.GAMESYNC_GAME_SESSION_FIXED_DOC)))

        # Documents with the same name stay apart and are only announced within their island.
        backend.gamesync_write_documents(host_a.call, Msg(encode((1, update("docs/__stg/All", {"pl": text("A")})))))
        backend.gamesync_write_documents(host_b.call, Msg(encode((1, update("docs/__stg/All", {"pl": text("B")})))))
        await settle()
        self.assertEqual(read_text(backend, guest_a, "docs/__stg/All"), "A")
        self.assertEqual(read_text(backend, host_b, "docs/__stg/All"), "B")
        self.assertEqual(watch_a.texts("docs/__stg/All"), ["A"])
        self.assertEqual(watch_guest.texts("docs/__stg/All"), ["A"])
        self.assertEqual(watch_b.texts("docs/__stg/All"), ["B"])

        def listed(player: Player) -> list[str]:
            response = Msg(backend.gamesync_list_documents(player.call, Msg(encode((1, "docs/__us")))))
            return sorted(document.get_str(1) for document in response.get_msgs(1))

        self.assertEqual(listed(host_a), sorted([f"docs/__us/{host_a.id}", f"docs/__us/{guest_a.id}"]))
        self.assertEqual(listed(host_b), [f"docs/__us/{host_b.id}"])

        # Global values are shared within an island only.
        global_name = "__upcsidn"
        store = encode((3, encode((1, "docs/g"), (2, encode((1, "n"), (7, global_name))))))
        backend.gamesync_write_documents(host_a.call, Msg(encode((1, update("docs/g", {"n": encode((3, 7))})),
                                                                 (1, store))))
        load = encode((1, encode((3, encode((1, "docs/h"), (2, encode((1, "n"), (6, global_name))))))))

        def loaded(player: Player) -> bytes:
            response = Msg(backend.gamesync_write_documents(player.call, Msg(load)))
            return response.get_msgs(1)[0].get_msg(2).get_raws(1)[0]  # TransformResult value

        self.assertEqual(loaded(host_b), server.NULL_VALUE)
        self.assertEqual(loaded(guest_a), encode((3, 7)))

        # A transaction belongs to the island it was begun in.
        transaction = Msg(backend.gamesync_begin_transaction(host_a.call, Msg())).get_bytes(1)
        self.assert_status(server.INVALID_ARGUMENT, backend.gamesync_get_document, host_b.call,
                           encode((1, "docs/__stg/All"), (3, transaction)))
        self.assert_status(server.INVALID_ARGUMENT, backend.gamesync_commit_transaction, host_b.call,
                           encode((3, transaction)))
        backend.gamesync_get_document(guest_a.call, Msg(encode((1, "docs/__stg/All"), (3, transaction))))
        backend.gamesync_commit_transaction(host_a.call, Msg(encode(
            (1, update("docs/__stg/All", {"pl": text("A2")})), (3, transaction))))
        await settle()
        self.assertEqual(watch_a.texts("docs/__stg/All"), ["A", "A2"])
        self.assertEqual(watch_b.texts("docs/__stg/All"), ["B"])

        # A gamesync token naming another user's user session reaches no island.
        impostor = call(gamesync_token(backend, host_b.id, guest_a.matchmaking_token))
        self.assert_status(server.NOT_FOUND, backend.gamesync_get_document, impostor, encode((1, "docs/__stg/All")))

        # Deferred writes apply to their own island when the KeepUserSession call ends.
        deferment = encode((1, "userSessions/current/deferments/leave"),
                           (2, encode((4, encode((1, "docs/__stg/All"))))))
        backend.gamesync_write_documents(host_b.call, Msg(encode((2, encode((1, encode((1, deferment))))))))
        await watch_b.close()
        self.assertIsNone(watch_b.error)
        result = Msg(backend.gamesync_read_documents(host_b.call, Msg(encode((1, "docs/__stg/All"))))).get_msgs(1)[0]
        self.assertEqual(result.get_str(2), "docs/__stg/All")  # missing
        self.assertEqual(read_text(backend, host_a, "docs/__stg/All"), "A2")

        # Dropping island B deletes its gamesync state, leaves island A alone and shuts B's player out.
        next(iter(island_b.user_sessions.values())).last_seen = 0
        backend.prune_sessions()
        self.assertNotIn(island_b.name, backend.sessions)
        self.assertEqual(island_b.gamesync.docs, {})
        self.assertEqual(island_b.gamesync.globals, {})
        self.assertEqual(island_b.gamesync.deferments, {})
        self.assertEqual(island_b.gamesync.watchers, set())
        self.assert_status(server.NOT_FOUND, backend.gamesync_get_document, host_b.call,
                           encode((1, server.GAMESYNC_GAME_SESSION_FIXED_DOC)))
        self.assertIn(island_a.name, backend.sessions)
        self.assertEqual(read_text(backend, guest_a, "docs/__stg/All"), "A2")
        await settle()
        self.assertEqual([change for change in watch_a.changes() if change[0] == server.DOCUMENT_CHANGE_DELETED], [])

        # A player who leaves island A for an island of its own loses its call and its documents in A.
        host(backend, "u-guest-a")
        await settle()
        self.assertEqual(watch_guest.error.code, server.NOT_FOUND)
        self.assertNotIn(f"docs/__us/{guest_a.id}", island_a.gamesync.docs)
        self.assertEqual(read_text(backend, host_a, "docs/__stg/All"), "A2")
        self.assert_status(server.NOT_FOUND, backend.gamesync_get_document, guest_a.call, encode((1, "docs/__stg/All")))

        await watch_a.close()
        self.assertIsNone(watch_a.error)
        self.assertTrue(all(watch.task.done() for watch in (watch_a, watch_guest, watch_b, anonymous)))

    def test_deferments_hold_what_they_count(self) -> None:
        # Deferments stay within the game session's Gamesync limit however they are made up: empty
        # writes cost the bytes they take, and the headers of the calls that stored them are let go.
        limit = 128 * 1024
        session, player = host(self.backend, "u-host")
        refused = 0
        with mock.patch.object(server, "MAX_GAMESYNC_BYTES", limit):
            gc.collect()
            tracemalloc.start()
            try:
                for i in range(32):
                    padded = server.Call("", {**player.call.metadata, "x-padding": secrets.token_hex(8192)})
                    deferment = encode((1, f"userSessions/current/deferments/d{i}"), *[(2, b"")] * 4000)
                    try:
                        self.backend.gamesync_write_documents(padded, Msg(defer(deferment)))
                    except server.GrpcError as exc:
                        self.assertEqual(exc.code, server.RESOURCE_EXHAUSTED)
                        refused += 1
                    del padded
                gc.collect()
                held = tracemalloc.get_traced_memory()[0]
            finally:
                tracemalloc.stop()
        self.assertGreater(refused, 0)
        self.assertEqual(len(session.gamesync.deferments), 32 - refused)
        self.assertLess(held, 2 * limit)

    def test_deferred_writes_survive_request_pressure(self) -> None:
        asyncio.run(self.deferred_writes_survive_request_pressure())

    async def deferred_writes_survive_request_pressure(self) -> None:
        # Request data that other calls hold does not cost a player the deferred writes the game
        # session already accepted from it.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        watch_host = Watch(backend, host_player.call, "docs/__stg/All")
        budget = Budget()
        token = server.request_budget.set(budget)
        try:
            watch_guest = Watch(backend, guest.call, "docs/__stg/All")  # handled under `budget`
        finally:
            server.request_budget.reset(token)
        await settle()
        deferment = encode((1, "userSessions/current/deferments/leave"),
                           (2, update("docs/__stg/All", {"pl": text("left")})))
        backend.gamesync_write_documents(guest.call, Msg(defer(deferment)))
        self.assertEqual(len(island.gamesync.deferments), 1)

        budget.room = 0  # by the time the guest's call ends, other calls hold all request memory
        await watch_guest.close()
        self.assertIsNone(watch_guest.error)
        self.assertEqual(island.gamesync.deferments, {})
        self.assertEqual(read_text(backend, host_player, "docs/__stg/All"), "left")
        self.assertEqual(watch_host.texts("docs/__stg/All"), ["left"])
        await watch_host.close()
        self.assertIsNone(watch_host.error)

    def test_failed_deferments_keep_islands_apart(self) -> None:
        asyncio.run(self.failed_deferments_keep_islands_apart())

    async def failed_deferments_keep_islands_apart(self) -> None:
        # A deferred write that fails, however it fails, neither keeps the player who stored it
        # watching the island it left nor costs that player its other deferments.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        watch_guest = Watch(backend, guest.call, "docs/__stg/All")
        await settle()
        deep = ".".join(["x"] * (2 * sys.getrecursionlimit()))
        load_deep = transform("docs/deep", encode((1, deep), (6, "g")))  # load_global_value
        self.assert_status(server.INVALID_ARGUMENT, backend.gamesync_write_documents, guest.call,
                           encode((1, load_deep)))
        # Deferred, the write is only stored. With the path limit lifted, applying it fails past
        # Python's recursion limit when the guest leaves for an island of its own.
        backend.gamesync_write_documents(guest.call, Msg(defer(encode(
            (1, "userSessions/current/deferments/deep"), (2, load_deep)))))
        backend.gamesync_write_documents(guest.call, Msg(defer(encode(
            (1, "userSessions/current/deferments/leave"), (2, update("docs/__stg/All", {"pl": text("left")}))))))
        with mock.patch.object(server, "MAX_FIELD_DEPTH", 1 << 30):
            host(backend, "u-guest")
            await settle()  # its deferments are applied meanwhile, one per turn of the event loop
        self.assertEqual(watch_guest.error.code, server.NOT_FOUND)
        self.assertTrue(watch_guest.task.done())
        self.assertEqual(island.gamesync.watchers, set())
        self.assertEqual(island.gamesync.deferments, {})
        self.assertNotIn(f"docs/__us/{guest.id}", island.gamesync.docs)
        self.assertNotIn("docs/deep", island.gamesync.docs)
        self.assertEqual(read_text(backend, host_player, "docs/__stg/All"), "left")

        # However a player stops being in the island, its call answers no further request.
        other = join(backend, island, "u-other")
        watch_other = Watch(backend, other.call, "docs/__stg/All")
        await settle()
        received = len(watch_other.received)
        del island.user_sessions[f"{TENANT}/users/u-other"]
        target = encode((1, "userSessions/current/targets/2"), (2, encode((1, "docs/__stg/All"))))
        watch_other.requests.put_nowait(encode((3, encode((1, target)))))
        await settle()
        self.assertEqual(watch_other.error.code, server.NOT_FOUND)
        self.assertEqual(len(watch_other.received), received)

    def test_commits_copy_within_their_limit(self) -> None:
        # Writes that copy a large global value again and again fail once they copy more than one
        # commit may, before the copies take the server's memory, whether they are sent or
        # deferred. The player's other deferments still apply.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        limit = 1024 * 1024
        backend.gamesync_write_documents(guest.call, Msg(encode(
            (1, update("docs/g", {"n": encode((8, bytes(limit // 4)))})),  # common.Value bytes_value
            (1, transform("docs/g", encode((1, "n"), (7, "big")))))))  # store_global_value
        loads = [transform("docs/h", encode((1, "n"), (6, "big")))] * 400  # load_global_value
        with mock.patch.object(server, "MAX_GAMESYNC_COMMIT_BYTES", limit):
            gc.collect()
            tracemalloc.start()
            try:
                self.assert_status(server.RESOURCE_EXHAUSTED, backend.gamesync_write_documents, guest.call,
                                   encode(*[(1, load) for load in loads]))
                backend.gamesync_write_documents(guest.call, Msg(defer(encode(
                    (1, "userSessions/current/deferments/leave"),
                    (2, update("docs/__stg/All", {"pl": text("left")}))))))
                backend.gamesync_write_documents(guest.call, Msg(defer(encode(
                    (1, "userSessions/current/deferments/copies"), *[(2, load) for load in loads]))))
                host(backend, "u-guest")  # the guest leaves, so its deferments are applied
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        self.assertLess(peak, 8 * limit)  # the 400 copies alone would take 100 MiB
        self.assertEqual(island.gamesync.deferments, {})
        self.assertNotIn("docs/h", island.gamesync.docs)
        self.assertEqual(read_text(backend, host_player, "docs/__stg/All"), "left")

    def test_failed_deferment_leaves_the_others_applied(self) -> None:
        asyncio.run(self.failed_deferment_leaves_the_others_applied())

    async def failed_deferment_leaves_the_others_applied(self) -> None:
        # A deferment that copies more than a commit may fails alone when the player's
        # KeepUserSession call ends, changing nothing: the small one stored after it still applies.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        watch_guest = Watch(backend, guest.call, "docs/__stg/All")
        await settle()
        limit = 1024 * 1024
        deferments = [("huge", update("docs/huge", {"n": encode((8, bytes(limit)))})),  # common.Value bytes_value
                      ("leave", update("docs/__stg/All", {"pl": text("left")}))]
        with mock.patch.object(server, "MAX_GAMESYNC_COMMIT_BYTES", limit):
            for name, write in deferments:
                backend.gamesync_write_documents(guest.call, Msg(defer(encode(
                    (1, f"userSessions/current/deferments/{name}"), (2, write)))))
            await watch_guest.close()
        self.assertIsNone(watch_guest.error)
        self.assertEqual(island.gamesync.deferments, {})
        self.assertNotIn("docs/huge", island.gamesync.docs)
        self.assertEqual(read_text(backend, host_player, "docs/__stg/All"), "left")

    def test_valid_deferments_apply_one_at_a_time(self) -> None:
        asyncio.run(self.valid_deferments_apply_one_at_a_time())

    async def valid_deferments_apply_one_at_a_time(self) -> None:
        # Each deferment a player leaves behind may copy as much as one commit, however many there
        # are, so deferments that each fit a commit all apply, even when together they copy more.
        # They are applied one per turn of the event loop and count against the Gamesync limit
        # until then, and the documents named after the player's user session are deleted after
        # them.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        limit = 1024 * 1024
        heavy = {f"docs/h{k}": update(f"docs/h{k}", {"n": encode((8, bytes(limit * 3 // 10)))}) for k in range(4)}
        own = f"docs/__us/{guest.id}"
        with mock.patch.object(server, "MAX_GAMESYNC_COMMIT_BYTES", limit):
            backend.gamesync_write_documents(guest.call, Msg(encode((1, heavy["docs/h0"]))))  # fits one commit
            writes = [heavy["docs/h1"], heavy["docs/h2"], heavy["docs/h3"],  # more than one commit together
                      update(own, {"pl": text("gone")}), update("docs/__stg/All", {"pl": text("left")})]
            for index, write in enumerate(writes):
                backend.gamesync_write_documents(guest.call, Msg(defer(encode(
                    (1, f"userSessions/current/deferments/d{index}"), (2, write)))))
            size, _ = server.gamesync_size(island.gamesync.docs, island.gamesync.globals, island.gamesync.deferments)
            host(backend, "u-guest")  # the guest leaves, so its deferments are queued to be applied
            with mock.patch.object(server, "MAX_GAMESYNC_BYTES", size + 1024):
                self.assert_status(server.RESOURCE_EXHAUSTED, backend.gamesync_write_documents, host_player.call,
                                   encode((1, update("docs/extra", {"pl": text("x" * 2048)}))))
            await asyncio.sleep(0)
            self.assertLess(sum(name in island.gamesync.docs for name in ("docs/h1", "docs/h2", "docs/h3")), 3)
            await settle()
        docs = island.gamesync.docs
        self.assertTrue(all(name in docs for name in heavy))
        self.assertNotIn(own, docs)
        self.assertEqual(read_text(backend, host_player, "docs/__stg/All"), "left")
        self.assertEqual(len(island.gamesync.queue), 0)

    def test_queued_deferments_go_with_their_game_session(self) -> None:
        asyncio.run(self.queued_deferments_go_with_their_game_session())

    async def queued_deferments_go_with_their_game_session(self) -> None:
        # Deferments still queued when the last player leaves are dropped with the rest of the game
        # session's Gamesync state: nothing is applied to it afterwards.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        backend.gamesync_write_documents(guest.call, Msg(defer(encode(
            (1, "userSessions/current/deferments/leave"), (2, update("docs/__stg/All", {"pl": text("left")}))))))
        host(backend, "u-guest")  # its deferment is queued
        host(backend, "u-host")  # the last player leaves before it is applied
        self.assertNotIn(island.name, backend.sessions)
        await settle()
        self.assertEqual(island.gamesync.docs, {})
        self.assertEqual(len(island.gamesync.queue), 0)
        self.assertIsNone(island.gamesync.applier)

    def test_deferred_parsing_has_a_budget_of_its_own(self) -> None:
        asyncio.run(self.deferred_parsing_has_a_budget_of_its_own())

    async def deferred_parsing_has_a_budget_of_its_own(self) -> None:
        # Deferred writes are parsed within a budget of their own, however much request memory other
        # calls hold: field transforms one at a time, so a write of many that each fit applies,
        # while one that would hold more than the budget fails alone before it is all decoded.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        budget = Budget()
        token = server.request_budget.set(budget)
        try:
            watch_guest = Watch(backend, guest.call, "docs/__stg/All")  # handled under `budget`
        finally:
            server.request_budget.reset(token)
        await settle()
        limit = 1024 * 1024

        def stamp(padding: int) -> bytes:
            """A FieldTransform that sets field t to the request time, padded with `padding` unknown
            fields of distinct numbers, each of which its parsed message counts MSG_FIELD_BYTES for."""
            return encode((1, "t"), (2, 1), *[(1000 + i, 1) for i in range(padding)])

        deferments = [
            # A third of the budget each, four times the budget together.
            ("stamps", transform("docs/t", *[stamp(limit // 3 // server.MSG_FIELD_BYTES)] * 12)),
            ("bloated", transform("docs/b", stamp(2 * limit // server.MSG_FIELD_BYTES))),  # twice it alone
            ("leave", update("docs/__stg/All", {"pl": text("left")})),
        ]
        for name, write in deferments:
            backend.gamesync_write_documents(guest.call, Msg(defer(encode(
                (1, f"userSessions/current/deferments/{name}"), (2, write)))))
        budget.room = 0  # by the time the guest's call ends, other calls hold all request memory
        with mock.patch.object(server, "MAX_DEFERMENT_PARSE_BYTES", limit):
            gc.collect()
            tracemalloc.start()
            try:
                await watch_guest.close()
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        self.assertIsNone(watch_guest.error)
        self.assertLess(peak, 4 * limit)
        self.assertEqual(island.gamesync.deferments, {})
        self.assertIn("docs/t", island.gamesync.docs)
        self.assertNotIn("docs/b", island.gamesync.docs)
        self.assertEqual(read_text(backend, host_player, "docs/__stg/All"), "left")

    def test_deferred_writes_outlive_their_tokens(self) -> None:
        asyncio.run(self.deferred_writes_outlive_their_tokens())

    async def deferred_writes_outlive_their_tokens(self) -> None:
        # A deferred write changes the documents its aliases named when it was stored, even after
        # the tokens of the call that stored it have expired.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        own = f"userSessions/{guest.id}/state"
        backend.gamesync_write_documents(guest.call, Msg(encode(
            (1, update("userSessions/current/state", {"pl": text("kept")})))))
        self.assertEqual(read_text(backend, host_player, own), "kept")
        backend.gamesync_write_documents(guest.call, Msg(defer(encode(
            (1, "userSessions/current/deferments/leave"),
            (2, update("userSessions/current/state", {"pl": text("left")}))))))
        watch_guest = Watch(backend, guest.call, own)
        await settle()
        expired = time.time() + server.TOKEN_TTL_SECONDS + 60
        with mock.patch.object(server.time, "time", return_value=expired):
            self.assert_status(server.UNAUTHENTICATED, backend.gamesync_get_document, guest.call,
                               encode((1, own)))
            await watch_guest.close()
        self.assertIsNone(watch_guest.error)
        self.assertEqual(island.gamesync.deferments, {})
        self.assertEqual(read_text(backend, host_player, own), "left")
        self.assertNotIn("userSessions/current/state", island.gamesync.docs)

    def test_read_work_is_bounded_across_masks_and_documents(self) -> None:
        _, player = host(self.backend, "u-host")
        name = "docs/__stg/All"
        nested = encode((10, server.encode_map({"leaf": text("x" * 1000)})))
        self.backend.gamesync_write_documents(player.call, Msg(encode((1, update(name, {"big": nested})))))
        one_path = encode((1, name), (2, encode((1, "big.leaf"))))
        repeated = encode((1, name), (2, encode(*[(1, "big.leaf")] * 8)))
        many_documents = encode(*[(1, name)] * 8)
        with mock.patch.object(server, "MAX_GAMESYNC_READ_BYTES", 5000, create=True):
            self.backend.gamesync_get_document(player.call, Msg(one_path))
            self.assert_status(server.RESOURCE_EXHAUSTED, self.backend.gamesync_get_document,
                               player.call, repeated)
            self.assert_status(server.RESOURCE_EXHAUSTED, self.backend.gamesync_read_documents,
                               player.call, many_documents)

    def test_read_rejects_oversized_resolved_alias(self) -> None:
        _, player = host(self.backend, "u-host")
        long_tenant = server.Call("", {**player.call.metadata, "npln-tenant-id": "x" * 600})
        request = encode(*[(1, "tenants/current/state")] * 10)
        self.assert_status(server.INVALID_ARGUMENT, self.backend.gamesync_read_documents,
                           long_tenant, request)

    def test_masked_deletions_change_only_the_named_fields(self) -> None:
        # A masked path the update leaves out is deleted where it is; a field above it that is
        # missing or holds no map stays as it is. Setting a nested field still makes the fields
        # above it maps.
        _, player = host(self.backend, "u-host")
        name = "docs/__stg/All"
        pair = encode((10, server.encode_map({"b": text("gone"), "c": text("kept")})))
        self.backend.gamesync_write_documents(player.call, Msg(encode(
            (1, update(name, {"a": text("important"), "m": pair})))))
        self.backend.gamesync_write_documents(player.call, Msg(encode(
            (1, masked_update(name, {}, "a.b", "m.b", "n.b")))))
        fields = read_fields(self.backend, player, name)
        self.assertEqual(fields["a"], text("important"))
        self.assertEqual(server.map_entries(Msg(fields["m"]).get_bytes(10)), {"c": text("kept")})
        self.assertNotIn("n", fields)
        nested = encode((10, server.encode_map({"b": text("set")})))
        self.backend.gamesync_write_documents(player.call, Msg(encode(
            (1, masked_update(name, {"a": nested}, "a.b")))))
        fields = read_fields(self.backend, player, name)
        self.assertEqual(server.map_entries(Msg(fields["a"]).get_bytes(10)), {"b": text("set")})
        self.assertEqual(server.map_entries(Msg(fields["m"]).get_bytes(10)), {"c": text("kept")})

    def test_users_current_is_the_callers_user(self) -> None:
        asyncio.run(self.users_current_is_the_callers_user())

    async def users_current_is_the_callers_user(self) -> None:
        # In a Gamesync name "users/current" stands for the user of the caller's gamesync token, so
        # the players of an island each write their own documents, and a deferred write keeps that
        # user after the token has expired.
        backend = self.backend
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        for player, value in ((host_player, "host"), (guest, "guest")):
            backend.gamesync_write_documents(player.call, Msg(encode(
                (1, update("docs/users/current/state", {"pl": text(value)})))))
        self.assertEqual(read_text(backend, host_player, "docs/users/u-host/state"), "host")
        self.assertEqual(read_text(backend, host_player, "docs/users/u-guest/state"), "guest")
        self.assertEqual(read_text(backend, guest, "docs/users/current/state"), "guest")
        self.assertNotIn("docs/users/current/state", island.gamesync.docs)
        backend.gamesync_write_documents(guest.call, Msg(defer(encode(
            (1, "userSessions/current/deferments/leave"),
            (2, update("docs/users/current/state", {"pl": text("left")}))))))
        watch_guest = Watch(backend, guest.call, "docs/users/current/state")
        await settle()
        expired = time.time() + server.TOKEN_TTL_SECONDS + 60
        with mock.patch.object(server.time, "time", return_value=expired):
            await watch_guest.close()
        self.assertIsNone(watch_guest.error)
        self.assertEqual(island.gamesync.deferments, {})
        self.assertEqual(read_text(backend, host_player, "docs/users/u-guest/state"), "left")
        self.assertEqual(read_text(backend, host_player, "docs/users/u-host/state"), "host")
        self.assertNotIn("docs/users/current/state", island.gamesync.docs)

    def test_nested_fields_cost_every_map_they_copy(self) -> None:
        # A masked path, field transform or merge into a field ten maps deep decodes and encodes
        # every map above it again. A commit pays for each before it copies it, so one such write
        # beside a 16 KiB value fits a 1 MiB commit, but eight do not, and change nothing.
        backend = self.backend
        island, player = host(backend, "u-host")
        name = "docs/deep"
        keys = [f"k{i}" for i in range(10)]
        value = text("x" * 16 * 1024)
        for key in reversed(keys[1:]):
            value = encode((10, server.encode_map({key: value})))
        deep = {keys[0]: value}  # k0.k1. ... .k9 holds the 16 KiB value
        backend.gamesync_write_documents(player.call, Msg(encode((1, update(name, deep)))))
        branch = {"t": text("y")}
        for key in reversed(keys[:-1]):
            branch = {key: encode((10, server.encode_map(branch)))}  # k0. ... .k8.t, beside k9
        writes = {
            "masked path": masked_update(name, deep, ".".join(keys)),
            "transform": transform(name, encode((1, ".".join([*keys[:-1], "n"])), (3, encode((3, 1))))),
            "merge": merge(name, branch),
        }
        with mock.patch.object(server, "MAX_GAMESYNC_COMMIT_BYTES", 1024 * 1024):
            for kind, write in writes.items():
                with self.subTest(kind):
                    before = island.gamesync.docs[name]["fields"]
                    self.assert_status(server.RESOURCE_EXHAUSTED, backend.gamesync_write_documents,
                                       player.call, encode(*[(1, write)] * 8))
                    self.assertEqual(island.gamesync.docs[name]["fields"], before)
                    backend.gamesync_write_documents(player.call, Msg(encode((1, write))))


TURN_IP = "203.0.113.10"
TURN_SECRET = b"0123456789abcdef0123456789abcdef"
RELAY_PORTS = (49160, 49200)
# What a player wrote: its own addresses in candidates, raddr, o=, s=, c= and other lines, and relay
# candidates naming another address, a port outside the relay range, IPv6 and TCP.
WRITTEN_SDP = "\r\n".join([
    "v=1",
    "o=alice 5C5tScTtfCgcey8C 2 IN IP4 192.168.1.43",
    "s=192.168.1.43",
    "t=0 0",
    "c=IN IP4 192.168.1.43",
    "",
    "a=candidate:1 1 udp 2113929727 192.168.1.43 56371 typ host",
    "a=candidate:2 1 udp 1677722111 198.51.100.7 54515 typ srflx raddr 192.168.1.43 rport 54515",
    "a=candidate:3 1 udp 33562623 203.0.113.10 49170 typ relay raddr 198.51.100.7 rport 54515 "
    "generation 0 network-id 1 x-addr 192.168.1.43",
    "a=candidate:4 1 udp 33562623 198.51.100.66 49170 typ relay raddr 0.0.0.0 rport 0",
    "a=candidate:5 1 udp 33562623 203.0.113.10 3478 typ relay",
    "a=candidate:6 1 udp 33562623 2001:db8::1 49171 typ relay",
    "a=candidate:7 1 tcp 33562623 203.0.113.10 49172 typ relay tcptype passive",
    "a=candidate:8 1 udp 2113929727 abcd.local 56371 typ host",
    "a=rtcp:9 IN IP4 192.168.1.43",
    "a=remote-candidates:1 192.168.1.43 56371",
    "a=x-addr:192.168.1.43",
    "a=setup:actpass",
    "a=ice-pwd:sc8LHT4LjDaBnZwyJbNuMX",
    "a=ice-ufrag:Zput",
]) + "\r\n"
DELIVERED_SDP = "\r\n".join([
    "v=1",
    "o=- 5C5tScTtfCgcey8C 2 IN IP4 0.0.0.0",
    "s=-",
    "t=0 0",
    "c=IN IP4 0.0.0.0",
    "",
    "a=candidate:3 1 udp 33562623 203.0.113.10 49170 typ relay raddr 0.0.0.0 rport 0 generation 0 network-id 1",
    "a=setup:actpass",
    "a=ice-pwd:sc8LHT4LjDaBnZwyJbNuMX",
    "a=ice-ufrag:Zput",
]) + "\r\n"
PLAYER_ADDRESSES = [b"192.168.1.43", b"198.51.100.7", b"198.51.100.66", b"2001:db8::1", b"abcd.local"]


def map_value(entries: dict[str, bytes]) -> bytes:
    return encode((10, server.encode_map(entries)))  # common.Value map_value


def signaling(sdp: str) -> dict[str, bytes]:
    """The fields of a docs/__pgn message as the game writes them, plus other values that look
    like signaling or only nearly do."""
    return {
        "susid": text("u4kxve2ohf5jj6xjflbf"),
        "mp": map_value({"i": encode((3, 2)), "r": encode((2, False)), "sd": text(sdp), "v": encode((3, 1))}),
        "note": text("env=1"),
        "trickle": text("candidate:9 1 udp 2113929727 192.168.1.43 50000 typ host"),
        "blob": encode((8, b"\x01\x02a=candidate:9 1 udp 1 192.168.1.43 50000 typ host")),
        "twice": encode((7, DELIVERED_SDP), (7, WRITTEN_SDP)),
        "nested": encode((9, encode((1, text("ok")), (1, map_value({"sd": text(sdp)}))))),
        "broken": text("v=1\r\nv=0\r\na=candidate:1 1 udp 1 203.0.113.10 49170 typ relay\r\n"),
    }


DELIVERED_FIELDS = {
    **signaling(DELIVERED_SDP),
    "trickle": server.NULL_VALUE,
    "blob": server.NULL_VALUE,
    "twice": server.NULL_VALUE,
    "broken": server.NULL_VALUE,
}


class RelayOnlyTest(unittest.TestCase):
    """--turn and --relay-only, through the calls the game makes."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        logger = logging.getLogger("npln")
        self.addCleanup(logger.setLevel, logger.level)
        logger.setLevel(logging.CRITICAL)

    def backend(self, turn: server.TurnServer | None = None,
                relay: server.RelayOnly | None = None) -> server.Backend:
        store = server.Store(Path(self.directory.name) / secrets.token_hex(4))
        return server.Backend(store, server.Storage(store, "https://storage.invalid"), 4, "", 443, turn, relay)

    def relay_backend(self) -> server.Backend:
        return self.backend(server.TurnServer(TURN_IP, 3478, TURN_SECRET), server.RelayOnly(TURN_IP, RELAY_PORTS))

    def test_ice_server_set_hands_out_turn_credentials(self) -> None:
        backend = self.backend(server.TurnServer(TURN_IP, 3478, TURN_SECRET))
        before = int(time.time())
        response = Msg(backend.allocate_ice_server_set(call(), Msg(encode((1, TENANT)))))
        after = int(time.time())
        turn = response.get_msg(3)
        self.assertEqual((turn.get_str(1), turn.get_int(2), turn.get_int(3)),
                         (TURN_IP, 3478, server.STUN_PROTOCOL_UDP))
        username, password = turn.get_str(4), turn.get_str(5)
        expiry, _, user = username.partition(":")
        ttl = server.ICE_SERVER_TTL_SECONDS
        self.assertTrue(before + ttl <= int(expiry) <= after + ttl)
        self.assertTrue(user)
        # coturn use-auth-secret: base64(HMAC-SHA1(static-auth-secret, username)).
        expected = base64.b64encode(hmac.new(TURN_SECRET, username.encode(), hashlib.sha1).digest()).decode()
        self.assertEqual(password, expected)

    def test_turn_user_is_stable_per_account(self) -> None:
        backend = self.backend(server.TurnServer(TURN_IP, 3478, TURN_SECRET))

        def user(account: str) -> str:
            account_call = server.Call("", {"npln-tenant-id": "t-test"}, server.Principal(account, "device"))
            response = Msg(backend.allocate_ice_server_set(account_call, Msg(encode((1, TENANT)))))
            username = response.get_msg(3).get_str(4)
            self.assertNotIn(account, username)
            return username.partition(":")[2]

        self.assertEqual(user("acct-a"), user("acct-a"))
        self.assertNotEqual(user("acct-a"), user("acct-b"))

    def test_default_setup_is_unchanged(self) -> None:
        asyncio.run(self.default_setup_is_unchanged())

    async def default_setup_is_unchanged(self) -> None:
        backend = self.backend()
        self.assertFalse(Msg(backend.allocate_ice_server_set(call(), Msg(encode((1, TENANT))))).has(3))
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        name = f"docs/__pgn/All/__stu/{guest.id}"
        watch = Watch(backend, guest.call, name)
        await settle()
        backend.gamesync_write_documents(host_player.call, Msg(encode((1, update(name, signaling(WRITTEN_SDP))))))
        await settle()
        self.assertEqual(read_fields(backend, guest, name), signaling(WRITTEN_SDP))
        self.assertEqual([fields for _, document, fields in watch.changes() if document == name],
                         [signaling(WRITTEN_SDP)])
        await watch.close()

    def test_relay_only_delivers_only_relay_candidates(self) -> None:
        asyncio.run(self.relay_only_delivers_only_relay_candidates())

    async def relay_only_delivers_only_relay_candidates(self) -> None:
        backend = self.relay_backend()
        island, host_player = host(backend, "u-host")
        guest = join(backend, island, "u-guest")
        name = f"docs/__pgn/All/__stu/{guest.id}"
        watching = Watch(backend, guest.call, name)
        await settle()
        backend.gamesync_write_documents(host_player.call, Msg(encode((1, update(name, signaling(WRITTEN_SDP))))))
        await settle()
        listing = Watch(backend, host_player.call, name)
        await settle()

        delivered = {
            "change": [fields for _, document, fields in watching.changes() if document == name],
            "listing": [fields for _, document, fields in listing.changes() if document == name],
            "GetDocument": [read_fields(backend, guest, name)],
            "ReadDocuments": [server.map_entries(document.get_bytes(2)) for result in Msg(
                backend.gamesync_read_documents(guest.call, Msg(encode((1, name))))).get_msgs(1)
                for document in [result.get_msg(1)]],
            "ListDocuments": [server.map_entries(document.get_bytes(2)) for document in Msg(
                backend.gamesync_list_documents(guest.call, Msg(encode((1, "docs/__pgn/All/__stu"))))).get_msgs(1)
                if document.get_str(1) == name],
        }
        for how, documents in delivered.items():
            with self.subTest(how):
                self.assertEqual(documents, [DELIVERED_FIELDS])
                for address in PLAYER_ADDRESSES:
                    self.assertNotIn(address, b"".join(documents[0].values()))

        masked = Msg(backend.gamesync_get_document(guest.call, Msg(encode((1, name), (2, encode((1, "mp.sd")))))))
        self.assertEqual(server.map_entries(masked.get_bytes(2)), {"mp": map_value({"sd": text(DELIVERED_SDP)})})

        # Field transforms return what they copy filtered too: here the SDP the host wrote.
        store = encode((3, encode((1, name), (2, encode((1, "mp.sd"), (7, "copied"))))))
        load = encode((3, encode((1, "docs/h"), (2, encode((1, "x"), (6, "copied"))))))
        response = Msg(backend.gamesync_write_documents(guest.call, Msg(encode((1, store), (1, load)))))
        self.assertEqual([result.get_msg(2).get_raws(1)[0] for result in response.get_msgs(1)],
                         [text(DELIVERED_SDP)] * 2)
        self.assertEqual(read_fields(backend, host_player, "docs/h"), {"x": text(DELIVERED_SDP)})
        await watching.close()
        await listing.close()

    def test_turn_settings(self) -> None:
        secret_file = Path(self.directory.name) / "turn-secret"
        secret_file.write_bytes(TURN_SECRET + b"\n")
        short_file = Path(self.directory.name) / "short-secret"
        short_file.write_bytes(b"too short\n")

        def settings(turn: str | None = f"{TURN_IP}:3478", secret: Path | None = secret_file, relay_only: bool = True,
                     ports: str | None = "49160:49200"):
            return server.turn_settings(argparse.Namespace(turn=turn, turn_secret_file=secret, relay_only=relay_only,
                                                           turn_relay_ports=ports))

        self.assertEqual(settings(None, None, False, None), (None, None))
        self.assertEqual(settings(), (server.TurnServer(TURN_IP, 3478, TURN_SECRET),
                                      server.RelayOnly(TURN_IP, RELAY_PORTS)))
        self.assertEqual(settings("turn.example.org:3478", relay_only=False, ports=None),
                         (server.TurnServer("turn.example.org", 3478, TURN_SECRET), None))
        for problem, arguments in {
            "TURN without a secret": dict(secret=None),
            "a short secret": dict(secret=short_file),
            "relay-only without TURN": dict(turn=None, secret=None),
            "relay-only without ports": dict(ports=None),
            "relay-only with a host name": dict(turn="turn.example.org:3478"),
            "relay-only with IPv6": dict(turn="2001:db8::1:3478"),
            "a reversed port range": dict(ports="49200:49160"),
            "ports without relay-only": dict(relay_only=False),
        }.items():
            with self.subTest(problem), self.assertRaises(ValueError):
                settings(**arguments)


if __name__ == "__main__":
    unittest.main()
