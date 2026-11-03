"""Regression test: game sessions open at the same time keep their Gamesync state apart.

Run it from this directory with the dependencies installed:

    python -m unittest test_gamesync_isolation
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
import unittest
from pathlib import Path

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
    ticket = backend.tickets[Msg(backend.create_game_session_creation_ticket(call(), Msg(request))).get_str(1)]
    return ticket.session, Player(backend, Msg(ticket.matched[0]))


def join(backend: server.Backend, session: server.GameSession, user: str) -> Player:
    request = encode((1, session.name), (3, definition(user)))
    return Player(backend, Msg(backend.join_game_session(call(), Msg(request))).get_msgs(1)[0])


def read_text(backend: server.Backend, player: Player, name: str) -> str:
    document = Msg(backend.gamesync_get_document(player.call, Msg(encode((1, name)))))
    return Msg(server.map_entries(document.get_bytes(2))["pl"]).get_str(7)


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


if __name__ == "__main__":
    unittest.main()
