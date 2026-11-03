"""Contract tests for client-certificate mode: what each account may do with the others' data.

These drive server.Backend and server.Storage directly with the account (Principal) a device
certificate would give a connection. Run them from this directory with the dependencies installed:

    python -m unittest test_client_auth
"""

from __future__ import annotations

import asyncio
import base64
import json
import errno
import gc
import os
import struct
import tempfile
import types
import unittest
import zlib
from pathlib import Path
from unittest import mock

import h2.config
import h2.connection

import server
from server import Msg, encode

TENANT = "tenants/t-test"
SESSION_ID = ":K5Y67P9D4Q8V"  # Synthetic host session identifier.
PASSWORD = "H4N7Q2"


def text(value: str) -> bytes:
    return encode((7, value))  # common.Value string_value


def id_token(subject: str) -> str:
    """The emulator's unsigned id token: only its subject matters."""
    payload = base64.urlsafe_b64encode(json.dumps({"sub": subject}).encode()).rstrip(b"=").decode()
    return f"e30.{payload}."


def update(name: str, fields: dict[str, bytes]) -> bytes:
    """A Ugcstore WriteOperation that replaces a document."""
    return encode((1, encode((1, encode((1, name), (2, server.encode_map(fields)))))))


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

    def call(self, token: str | None = None) -> server.Call:
        metadata = {"npln-tenant-id": "t-test"}
        token = getattr(self, "token", "") if token is None else token
        if token:
            metadata["authorization"] = f"Bearer {token}"
        return server.Call("", metadata, self.principal, self.network)

    def commit(self, *operations: bytes) -> bytes:
        return self.backend.commit_documents(self.call(), Msg(encode(*[(2, op) for op in operations])))

    def get(self, name: str, password: str | None = None) -> Msg:
        context = server.encode_map({"password": text(password)}) if password is not None else None
        return Msg(self.backend.get_document(self.call(), Msg(encode((1, name), (3, context)))))

    def host(self, password: str = PASSWORD) -> server.GameSession:
        properties = server.encode_map({"string1": text(SESSION_ID)})
        ticket_request = encode((2, "tenants/current/matchmakingConfigs/MatchmakingConfigsDefault"),
                                (3, encode((1, "tenants/current/users/current"))),
                                (6, encode((6, password), (11, properties))))
        response = self.backend.create_game_session_creation_ticket(
            self.call(), Msg(encode((1, "tenants/current"), (2, ticket_request))))
        return self.backend.tickets[Msg(response).get_str(1)].session

    def query(self, session_id: str = SESSION_ID) -> list[Msg]:
        request = encode((1, "tenants/current"), (6, server.encode_map({"f_string1": text(session_id)})))
        return Msg(self.backend.query_game_sessions(self.call(), Msg(request))).get_msgs(1)

    def join(self, session: server.GameSession, password: str) -> Msg:
        request = encode((1, session.name), (2, password), (3, encode((1, "tenants/current/users/current"))))
        return Msg(self.backend.join_game_session(self.call(), Msg(request)))


class ClientAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = server.Store(Path(directory.name))
        self.storage = server.Storage(self.store, "https://storage.invalid")
        self.backend = server.Backend(self.store, self.storage, 4, "", 443)
        self.host = Account(self.backend, "acct-host", "198.51.100.1")
        self.guest = Account(self.backend, "acct-guest", "203.0.113.1")
        self.host.commit(
            update(f"{self.host.documents}/public/MetaData", {"owner": text("host")}),
            update(f"{self.host.documents}/private/PasswordData", {"password": text(PASSWORD)}),
            update(f"{self.host.documents}/private/SessionIDData", {"sessionID": text(SESSION_ID[1:])}),
            update(f"{self.host.documents}/private/StageData", {}),
        )

    def assert_status(self, code: int, function, *args) -> None:
        with self.assertRaises(server.GrpcError) as raised:
            function(*args)
        self.assertEqual(raised.exception.code, code, raised.exception.message)

    # Identity

    def test_profiles_of_different_accounts_are_different_users(self) -> None:
        other = Account(self.backend, "acct-other", "192.0.2.1", profile="profile")
        self.assertNotEqual(other.user, self.host.user)

    def test_token_only_works_for_its_account(self) -> None:
        self.backend.validate_token(self.host.call(), Msg())
        stolen = self.guest.call(token=self.host.token)
        self.assert_status(server.UNAUTHENTICATED, self.backend.validate_token, stolen, Msg())

    def test_no_token_for_another_accounts_user(self) -> None:
        self.assert_status(server.PERMISSION_DENIED, self.backend.issue_token,
                           self.guest.call(), Msg(encode((1, self.host.user))))

    def test_no_anonymous_users(self) -> None:
        self.assert_status(server.PERMISSION_DENIED, self.backend.issue_anonymous_user_token,
                           self.guest.call(), Msg(encode((1, "tenants/current"))))

    # Ugcstore

    def test_documents_of_other_accounts(self) -> None:
        self.assertEqual(self.guest.get(f"{self.host.documents}/public/MetaData").get_str(1),
                         f"{self.host.documents}/public/MetaData")
        self.assert_status(server.PERMISSION_DENIED, self.guest.get, f"{self.host.documents}/private/PasswordData")
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit,
                           update(f"{self.host.documents}/public/MetaData", {"owner": text("guest")}))
        self.assert_status(server.PERMISSION_DENIED, self.backend.issue_attachment_uri, self.guest.call(),
                           Msg(encode((1, f"{self.host.documents}/private/StageData"))))

    def test_island_password_opens_session_id_then_stage_data(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        self.assert_status(server.PERMISSION_DENIED, self.guest.get, stage)
        self.assert_status(server.PERMISSION_DENIED, self.guest.get,
                           f"{self.host.documents}/private/SessionIDData", "WRONG0")
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assertEqual(self.guest.get(stage).get_str(1), stage)

    def test_wrong_passwords_are_limited_per_account(self) -> None:
        session_id_data = f"{self.host.documents}/private/SessionIDData"
        for _ in range(server.GUESS_LIMITS["account"][0]):
            self.assert_status(server.PERMISSION_DENIED, self.guest.get, session_id_data, "WRONG0")
        self.assert_status(server.RESOURCE_EXHAUSTED, self.guest.get, session_id_data, PASSWORD)
        # Other accounts, even on the same network, keep their own count until the network's.
        other = Account(self.backend, "acct-other", self.guest.network)
        other.get(session_id_data, PASSWORD)

    def test_wrong_passwords_are_limited_per_island_across_accounts(self) -> None:
        session_id_data = f"{self.host.documents}/private/SessionIDData"
        limit = server.GUESS_LIMITS["target"][0]
        for number in range(limit):
            attacker = Account(self.backend, f"acct-attacker-{number}", f"10.0.{number}.1")
            self.assert_status(server.PERMISSION_DENIED, attacker.get, session_id_data, "WRONG0")
        newcomer = Account(self.backend, "acct-newcomer", "192.0.2.7")
        self.assert_status(server.RESOURCE_EXHAUSTED, newcomer.get, session_id_data, PASSWORD)

    def test_upload_belongs_to_its_account(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        target = f"/upload/{upload_id}"
        self.assertEqual(self.storage.handle("PUT", target, {}, b"island", self.guest.principal).status, 404)
        self.assertEqual(self.storage.handle("PUT", target, {}, b"island", self.host.principal).status, 200)
        self.assertFalse(self.storage.may_download(upload_id, self.guest.principal))
        self.assertTrue(self.storage.may_download(upload_id, self.host.principal))

    def test_oversized_upload_is_discarded(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        with mock.patch.object(server, "MAX_UPLOAD_BYTES", 4):
            result = self.storage.handle("PUT", f"/upload/{upload_id}", {}, b"island", self.host.principal)
        self.assertEqual(result.status, 413)
        self.assertNotIn(upload_id, self.store.uploads)

    def test_account_storage_quota(self) -> None:
        with mock.patch.object(server, "ACCOUNT_STATE_BYTES", 64):
            self.assert_status(server.RESOURCE_EXHAUSTED, self.host.commit,
                               update(f"{self.host.documents}/public/Big", {"blob": text("x" * 200)}))
        self.assertNotIn(f"{self.host.documents}/public/Big", self.store.documents)

    def test_names_are_bounded(self) -> None:
        self.assert_status(server.INVALID_ARGUMENT, self.host.commit,
                           update(f"{self.host.documents}/public/" + "x" * server.MAX_NAME_BYTES, {}))

    def complete_upload(self) -> str:
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.storage.handle("PUT", f"/upload/{upload_id}", {}, b"island", self.host.principal)
        return upload_id

    def test_imported_upload_left_unreferenced_is_deleted(self) -> None:
        upload_id = self.complete_upload()
        name = f"{self.host.documents}/private/Extra"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))),
                         encode((2, encode((1, name)))))
        self.assertNotIn(upload_id, self.store.uploads)
        self.assertFalse(self.store.blob_path(upload_id).exists())

    def test_blob_outlives_a_failed_save(self) -> None:
        """Files are deleted only after the state that stops referring to them is saved."""
        upload_id = self.complete_upload()
        name = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))
        with mock.patch.object(self.store, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.host.commit(encode((4, encode((1, name)))))  # unset the attachment
        self.assertTrue(self.store.blob_path(upload_id).exists())

    def test_blob_outlives_a_failed_sync(self) -> None:
        """A save that cannot reach storage fails before the old file goes."""
        upload_id = self.complete_upload()
        name = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))
        with mock.patch.object(server, "sync_fd", side_effect=OSError("I/O error")):
            with self.assertRaises(OSError):
                self.host.commit(encode((4, encode((1, name)))))
        self.assertTrue(self.store.blob_path(upload_id).exists())

    def test_state_is_flushed_before_it_is_published(self) -> None:
        events: list[object] = []
        with mock.patch.object(server, "sync_fd", side_effect=lambda fd: events.append("flush") or True), \
                mock.patch.object(server, "publish", side_effect=lambda temp, path: events.append(("publish", path)) or True):
            self.store.save()
        self.assertEqual(events, ["flush", ("publish", self.store.path)])
        self.assertTrue(self.store.durable)

    @unittest.skipUnless(os.name == "posix", "POSIX renames")
    def test_rename_is_followed_by_a_directory_sync(self) -> None:
        events: list[object] = []
        replace = os.replace
        temp, target = self.store.blob_dir / "x.tmp", self.store.blob_dir / "x"
        temp.write_bytes(b"x")
        with mock.patch.object(server.os, "replace", side_effect=lambda a, b: (events.append("rename"), replace(a, b))), \
                mock.patch.object(server, "sync_directory", side_effect=lambda path: events.append(("sync", path)) or True):
            self.assertTrue(server.publish(temp, target))
        self.assertEqual(events, ["rename", ("sync", self.store.blob_dir)])

    @unittest.skipUnless(os.name == "nt", "Windows renames")
    def test_windows_rename_writes_through(self) -> None:
        with mock.patch.object(server, "_move_file_ex", return_value=1) as move:
            self.assertTrue(server.publish(Path("x.tmp"), Path("x")))
        flags = move.call_args.args[2]
        self.assertEqual(flags & server.MOVEFILE_WRITE_THROUGH, server.MOVEFILE_WRITE_THROUGH)
        self.assertEqual(flags & server.MOVEFILE_REPLACE_EXISTING, server.MOVEFILE_REPLACE_EXISTING)

    def test_failed_full_sync_is_raised_not_downgraded(self) -> None:
        def without_full_sync(error: int) -> types.SimpleNamespace:
            def fcntl(fd: int, command: int) -> None:
                raise OSError(error, os.strerror(error))
            return types.SimpleNamespace(F_FULLFSYNC=51, fcntl=fcntl)

        with mock.patch.object(server.sys, "platform", "darwin"), \
                mock.patch.object(server, "fcntl", without_full_sync(errno.EIO)), \
                mock.patch.object(server.os, "fsync") as fsync:
            with self.assertRaises(OSError):
                server.sync_fd(3)
            fsync.assert_not_called()
        with mock.patch.object(server.sys, "platform", "darwin"), \
                mock.patch.object(server, "fcntl", without_full_sync(errno.EINVAL)), \
                mock.patch.object(server.os, "fsync") as fsync:
            self.assertFalse(server.sync_fd(3))  # only fsync is left: not promised durable
            fsync.assert_called_once_with(3)

    def test_blobs_stay_when_the_state_cannot_be_saved_durably(self) -> None:
        upload_id = self.complete_upload()
        name = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))
        with mock.patch.object(server, "sync_fd", return_value=False):
            self.host.commit(encode((4, encode((1, name)))))
        self.assertFalse(self.store.durable)
        self.assertTrue(self.store.blob_path(upload_id).exists())

    def put(self, upload_id: str, body: bytes, content_range: str | None = None) -> server.Response:
        headers = {"content-range": content_range} if content_range else {}
        return self.storage.handle("PUT", f"/upload/{upload_id}", headers, body, self.host.principal)

    def fail_blob_publish(self, nth: int, after_rename: bool):
        """A publish that fails on the nth blob file it renames, before or after the rename."""
        publish = server.publish
        seen = []

        def fake(temp: Path, path: Path) -> bool:
            if path.parent == self.store.blob_dir:
                seen.append(path)
                if len(seen) == nth:
                    if after_rename:
                        publish(temp, path)
                    raise OSError(errno.EIO, "sync failed")
            return publish(temp, path)

        return mock.patch.object(server, "publish", side_effect=fake)

    def test_whole_upload_failing_after_its_rename_starts_over(self) -> None:
        """The audit's case: a whole-object PUT replaces the file with three bytes, then its
        directory sync fails. The session must not resume at byte 10 of the old upload."""
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.assertEqual(self.put(upload_id, b"a" * 10, "bytes 0-9/20").status, 308)
        with self.fail_blob_publish(2, after_rename=True):  # 1: the new empty file, 2: the body
            with self.assertRaises(OSError):
                self.put(upload_id, b"bbb")
        resumed = self.put(upload_id, b"c" * 10, "bytes 10-19/20")
        self.assertEqual(resumed.status, 308)
        self.assertNotIn("range", dict(resumed.headers))  # start again from byte 0
        self.assertFalse(self.store.uploads[upload_id]["complete"])
        self.assertEqual(self.put(upload_id, b"d" * 20, "bytes 0-19/20").status, 200)
        self.assertEqual(self.store.blob_path(upload_id).read_bytes(), b"d" * 20)

    def test_whole_upload_failing_on_its_empty_file_is_discarded(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.put(upload_id, b"a" * 10, "bytes 0-9/20")
        with self.fail_blob_publish(1, after_rename=True):
            with self.assertRaises(OSError):
                self.put(upload_id, b"bbb")
        # The file is empty, the count still 10: no gap gets filled in.
        self.assertEqual(self.put(upload_id, b"c" * 10, "bytes 10-19/20").status, 410)
        self.assertNotIn(upload_id, self.store.uploads)

    @unittest.skipUnless(os.name == "posix", "snapshots run on Linux; Windows cannot replace an open file")
    def test_whole_upload_never_rewrites_the_file_a_snapshot_reads(self) -> None:
        """A snapshot keeps the old file open and reads it up to the count it captured."""
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.put(upload_id, b"a" * 10, "bytes 0-9/20")
        with self.store.blob_path(upload_id).open("rb") as captured:
            with self.fail_blob_publish(2, after_rename=False):  # the body never lands
                with self.assertRaises(OSError):
                    self.put(upload_id, b"bbb")
            self.assertEqual(self.put(upload_id, b"e" * 20, "bytes 0-19/20").status, 200)
            self.assertEqual(captured.read(), b"a" * 10)
        self.assertEqual(self.store.blob_path(upload_id).read_bytes(), b"e" * 20)

    def test_upload_shorter_than_received_is_discarded(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.put(upload_id, b"a" * 10, "bytes 0-9/20")
        with self.store.blob_path(upload_id).open("r+b") as blob:
            blob.truncate(4)  # the count survived a crash, the bytes did not
        self.assertEqual(self.put(upload_id, b"c" * 10, "bytes 10-19/20").status, 410)
        self.assertNotIn(upload_id, self.store.uploads)

    def test_leftover_bytes_past_the_count_are_dropped(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.put(upload_id, b"a" * 4, "bytes 0-3/8")
        with self.store.blob_path(upload_id).open("ab") as blob:
            blob.write(b"zzzzzz")  # written, but the state counting it was never saved
        self.assertEqual(self.put(upload_id, b"b" * 4, "bytes 4-7/8").status, 200)
        self.assertEqual(self.store.blob_path(upload_id).read_bytes(), b"aaaabbbb")

    def test_damaged_upload_is_not_imported(self) -> None:
        upload_id = self.complete_upload()
        with self.store.blob_path(upload_id).open("r+b") as blob:
            blob.truncate(2)
        name = f"{self.host.documents}/private/StageData"
        self.assert_status(server.FAILED_PRECONDITION, self.host.commit,
                           encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))

    def test_upload_chunk_is_synced_before_its_count_is_saved(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        events: list[str] = []
        save = self.store.save
        with mock.patch.object(server, "sync_fd", side_effect=lambda fd: events.append("sync")), \
                mock.patch.object(self.store, "save", side_effect=lambda: (events.append("save"), save())):
            result = self.storage.handle("PUT", f"/upload/{upload_id}", {"content-range": "bytes 0-2/6"}, b"isl",
                                         self.host.principal)
        self.assertEqual(result.status, 308)
        self.assertEqual(events[:2], ["sync", "save"])

    def test_upload_cannot_be_imported_twice(self) -> None:
        upload_id = self.complete_upload()
        uri = f"https://storage.invalid/upload/{upload_id}"
        self.assert_status(server.INVALID_ARGUMENT, self.host.commit,
                           *[encode((5, encode((1, f"{self.host.documents}/private/Copy{i}"), (2, uri))))
                             for i in range(2)])
        self.assertIn(upload_id, self.store.uploads)

    def test_download_streams_from_an_open_file(self) -> None:
        upload_id = self.complete_upload()
        result = self.storage.handle("GET", f"/download/{upload_id}", {"range": "bytes=1-3"}, b"",
                                     self.host.principal)
        file, offset, length = result.stream
        try:
            file.seek(offset)
            self.assertEqual((result.status, file.read(length)), (206, b"sla"))
        finally:
            file.close()

    def test_deleting_a_user_deletes_its_documents(self) -> None:
        self.backend.delete_user(self.host.call(), Msg(encode((1, self.host.user))))
        self.assertNotIn(self.host.user, self.store.users)
        self.assertFalse([name for name in self.store.documents if name.startswith(self.host.documents)])

    # Matchmaking

    def test_session_needs_island_password_to_be_found_and_joined(self) -> None:
        session = self.host.host()
        self.assertEqual(len(self.host.query()), 1)
        self.assertEqual(self.guest.query(), [])  # no password given yet
        self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        found = self.guest.query()
        self.assertEqual([entry.get_str(1) for entry in found], [session.name])
        self.assertEqual(found[0].get_str(6), "")  # only members see the session password
        self.assertEqual(self.guest.query(":SOMETHINGELSE"), [])
        self.assert_status(server.PERMISSION_DENIED, self.guest.join, session, "WRONG0")
        joined = self.guest.join(session, PASSWORD)
        self.assertEqual(joined.get_msg(2).get_str(6), PASSWORD)
        self.assertIn(self.guest.user, session.user_sessions)

    def test_grant_for_a_visitors_island_does_not_reveal_the_session(self) -> None:
        session = self.host.host()
        visitor = Account(self.backend, "acct-visitor", "192.0.2.9")
        visitor.commit(update(f"{visitor.documents}/private/PasswordData", {"password": text("VISIT1")}))
        visitor.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        visitor.join(session, PASSWORD)
        # The guest knows the visitor's island password, not the host's (the visitor's own
        # SessionIDData does not exist, but the password is checked first).
        self.assert_status(server.NOT_FOUND, self.guest.get, f"{visitor.documents}/private/SessionIDData", "VISIT1")
        self.assertEqual(self.guest.query(), [])
        self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)

    def test_new_island_password_ends_grants(self) -> None:
        self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assertEqual(len(self.guest.query()), 1)
        self.host.commit(update(f"{self.host.documents}/private/PasswordData", {"password": text("NEW123")}))
        self.assertEqual(self.guest.query(), [])
        self.assert_status(server.PERMISSION_DENIED, self.guest.get, f"{self.host.documents}/private/StageData")

    def test_request_may_only_name_own_users(self) -> None:
        session = self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        request = encode((1, session.name), (2, PASSWORD), (3, encode((1, self.host.user))))
        self.assert_status(server.PERMISSION_DENIED, self.backend.join_game_session,
                           self.guest.call(), Msg(request))

    # Account deletion

    def test_purge_removes_the_accounts_game_data(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.host.host()
        self.backend.purge_account(self.host.principal.account)
        self.assertNotIn(self.host.user, self.store.users)
        self.assertFalse([name for name in self.store.documents if name.startswith(self.host.documents)])
        self.assertNotIn(upload_id, self.store.uploads)
        self.assertFalse(self.backend.sessions)
        self.assertIn(self.guest.user, self.store.users)


class LimitsTest(unittest.TestCase):
    def test_decompression_is_bounded(self) -> None:
        bomb = zlib.compress(b"\0" * (server.MAX_GRPC_MESSAGE_BYTES + 1))
        frame = b"\x01" + len(bomb).to_bytes(4, "big") + bomb
        with self.assertRaises(ValueError):
            server.single_grpc_message(frame, "deflate")
        small = zlib.compress(b"hello")
        self.assertEqual(server.single_grpc_message(b"\x01" + len(small).to_bytes(4, "big") + small, "deflate"),
                         b"hello")

    def test_a_request_holds_exactly_one_message(self) -> None:
        frame = b"\x00\x00\x00\x00\x01x"
        self.assertEqual(server.single_grpc_message(frame, "identity"), b"x")
        self.assertEqual(server.single_grpc_message(b"", "identity"), b"")
        for body in (frame * 2, frame[:-1], frame[:3]):
            with self.assertRaises(ValueError):
                server.single_grpc_message(body, "identity")

    def test_many_small_compressed_messages_cannot_add_up(self) -> None:
        compressed = zlib.compress(b"\0" * (1024 * 1024))
        frame = b"\x01" + len(compressed).to_bytes(4, "big") + compressed
        self.assertEqual(len(server.take_grpc_frames(bytearray(frame * 2), "deflate", 2 * 1024 * 1024)), 2)
        with self.assertRaises(ValueError):
            server.take_grpc_frames(bytearray(frame * 3), "deflate", 2 * 1024 * 1024)

    def test_declared_size_is_bounded(self) -> None:
        header = b"\x00" + (server.MAX_GRPC_MESSAGE_BYTES + 1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            server.take_grpc_frames(bytearray(header), "identity")

    def test_messages_have_a_field_limit(self) -> None:
        self.assertEqual(len(Msg(b"\x08\x01" * server.MAX_MESSAGE_FIELDS).fields[1]), server.MAX_MESSAGE_FIELDS)
        with self.assertRaises(ValueError):
            Msg(b"\x08\x01" * (server.MAX_MESSAGE_FIELDS + 1))

    def test_string_filters_pick_the_island(self) -> None:
        def session(string1: str) -> server.GameSession:
            return server.GameSession(f"{TENANT}/gameSessions/{string1}", 4, 0, "", 443,
                                      properties_raw=server.encode_map({"string1": text(string1)}))

        filters = server.map_entries(server.encode_map({
            "f_sys_lock": encode((3, 1)), "f_string1": text(":A"), "f_int1": b""}))
        self.assertTrue(server.session_matches(session(":A"), filters))
        self.assertFalse(server.session_matches(session(":B"), filters))
        self.assertTrue(server.session_matches(session(":B"), {}))

    def test_trust_ends_with_the_password_and_keeps_network_counts(self) -> None:
        limiter = server.GuessLimiter()
        call = server.Call("", {}, server.Principal("acct", "dev"), "192.0.2.1")
        limiter.succeeded(call, "island x", "v1")
        self.assertNotIn(("target", "island x"), limiter.buckets(call, "island x", "v1"))
        self.assertIn(("network", "192.0.2.1"), limiter.buckets(call, "island x", "v1"))
        self.assertIn(("target", "island x"), limiter.buckets(call, "island x", "v2"))

    def test_inbound_queue_is_bounded_and_released(self) -> None:
        budget = types.SimpleNamespace(buffered=0)
        inbound = server.GrpcInbound("identity", budget)
        message = b"\0" * 1024 * 1024
        frame = b"\x00" + len(message).to_bytes(4, "big") + message
        for _ in range(server.MAX_INBOUND_QUEUE_BYTES // len(message)):
            inbound.feed(frame)
        self.assertFalse(inbound.failed)
        self.assertEqual(budget.buffered, inbound.size())
        inbound.feed(frame)
        self.assertTrue(inbound.failed)
        inbound.discard()
        self.assertEqual(budget.buffered, 0)

    def test_stun_descriptions_are_bounded(self) -> None:
        description = server.describe_stun_attributes(struct.pack("!HH", 0x8028, 0) * 5000)
        self.assertLessEqual(len(description), server.STUN_LOG_LINE_CHARS)
        self.assertIn("more attributes", description)

    def test_gamesync_size_counts_globals_and_names(self) -> None:
        size, records = server.gamesync_size({"d": {"fields": "abc"}, "gone": None}, {"g": b"xyz"}, {})
        self.assertEqual(records, 2)
        self.assertEqual(size, 1 + 3 + 1 + 3 + 2 * server.STATE_OVERHEAD_BYTES)


class FakeWriter:
    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def write(self, data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


def request_headers(path: str, method: str = "POST", grpc: bool = False) -> list[tuple[str, str]]:
    headers = [(":method", method), (":scheme", "https"), (":authority", "test"), (":path", path)]
    return headers + [("content-type", "application/grpc")] if grpc else headers


class StreamAccountingTest(unittest.IsolatedAsyncioTestCase):
    """Request bytes stay counted in Server.buffered exactly as long as they are kept."""

    def setUp(self) -> None:
        self.server = types.SimpleNamespace(
            buffered=0, pending=0, downloads=0,
            backend=types.SimpleNamespace(bidi={"/test.Service/Bidi": None}),
            storage=types.SimpleNamespace(handle=lambda *args: server.response(404, b"none\n")))
        self.session = server.H2Session(self.server, None, FakeWriter())
        self.session.conn.initiate_connection()
        self.client = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        self.client.initiate_connection()

    def deliver(self) -> None:
        """Hands the server everything the client sent, as one batch of events."""
        for event in self.session.conn.receive_data(self.client.data_to_send()):
            self.session.on_event(event)

    async def settle(self) -> None:
        for _ in range(5):
            await asyncio.sleep(0)

    async def test_request_body_stays_counted_until_its_response_is_sent(self) -> None:
        self.client.send_headers(1, request_headers("/upload/x", "PUT"))
        self.client.send_data(1, b"y" * 1000, end_stream=True)
        self.deliver()
        task = self.session.tasks[1]
        self.assertEqual((self.server.buffered, self.session.buffered), (1000, 1000))
        await task
        await self.settle()
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

    async def test_reset_after_end_of_stream_releases_queued_messages(self) -> None:
        # Request, data, end of stream and reset arrive together, so the call's task is
        # cancelled before it ever runs.
        message = b"x" * 1000
        self.client.send_headers(1, request_headers("/test.Service/Bidi", grpc=True))
        self.client.send_data(1, b"\0" + len(message).to_bytes(4, "big") + message, end_stream=True)
        self.client.reset_stream(1)
        self.deliver()
        await self.settle()
        self.assertEqual(self.server.buffered, 0)

    async def test_decoded_request_stays_counted_for_a_server_stream(self) -> None:
        release = asyncio.Event()

        async def subscribe(call: server.Call, request: Msg):
            await release.wait()
            return
            yield

        self.server.backend.streams = {"/test.Service/Watch": subscribe}
        self.server.backend.unary = {}
        payload = encode((1, b"x" * 100000))
        compressed = zlib.compress(payload)
        body = b"\x01" + len(compressed).to_bytes(4, "big") + compressed
        self.client.send_headers(1, request_headers("/test.Service/Watch", grpc=True))
        self.deliver()  # opens the stream that the call answers on
        call = asyncio.create_task(server.Server.handle_grpc(
            self.server, server.H2Stream(self.session, 1),
            {":path": "/test.Service/Watch", "grpc-encoding": "deflate"}, body))
        await self.settle()
        cost = server.message_cost(len(payload), 1)
        self.assertEqual((self.server.buffered, self.session.buffered), (cost, cost))
        release.set()
        await call
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

    async def test_invalid_protobuf_returns_invalid_argument(self) -> None:
        self.server.backend.streams = {}
        self.server.backend.unary = {}
        self.client.send_headers(1, request_headers("/test.Service/Watch", grpc=True))
        self.deliver()
        stream = server.H2Stream(self.session, 1)
        with mock.patch.object(stream, "finish") as finish:
            await server.Server.handle_grpc(
                self.server, stream, {":path": "/test.Service/Watch"}, b"\0\0\0\0\1\0")
        self.assertEqual(finish.call_args.args[0], server.INVALID_ARGUMENT)
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

    async def test_request_that_does_not_fit_is_refused(self) -> None:
        self.server.backend.streams = {}
        self.server.backend.unary = {}
        self.session.buffered = server.MAX_CONNECTION_BUFFER_BYTES - 4096
        self.client.send_headers(1, request_headers("/test.Service/Watch", grpc=True))
        self.deliver()
        stream = server.H2Stream(self.session, 1)
        payload = b"\x08\x01" * 1000  # 2000 bytes, but 1000 fields
        with mock.patch.object(stream, "finish") as finish:
            await server.Server.handle_grpc(self.server, stream, {":path": "/test.Service/Watch"},
                                            b"\0" + len(payload).to_bytes(4, "big") + payload)
        self.assertEqual(finish.call_args.args[0], server.RESOURCE_EXHAUSTED)
        self.assertEqual(self.session.buffered, server.MAX_CONNECTION_BUFFER_BYTES - 4096)

    async def test_parsed_messages_count_until_dropped(self) -> None:
        token = server.request_budget.set(self.session)
        try:
            raw = encode(*[(1, encode((2, 1)))] * 1000)
            outer = Msg(raw)
            outer_cost = server.message_cost(len(raw), 1000)
            self.assertEqual((self.server.buffered, self.session.buffered), (outer_cost, outer_cost))
            nested = outer.get_msgs(1)  # what a handler parses from the request counts too
            self.assertEqual(self.server.buffered, outer_cost + 1000 * server.message_cost(2, 1))
            del nested
            self.assertEqual(self.server.buffered, outer_cost)
            del outer
            self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))
        finally:
            server.request_budget.reset(token)

    async def test_parsing_stops_at_the_budget(self) -> None:
        room = server.message_cost(2000, 10)
        self.session.buffered = server.MAX_CONNECTION_BUFFER_BYTES - room
        token = server.request_budget.set(self.session)
        try:
            with self.assertRaises(server.GrpcError) as refused:
                Msg(b"\x08\x01" * 1000)  # 1000 fields; 10 fit
            self.assertEqual(refused.exception.code, server.RESOURCE_EXHAUSTED)
            self.assertEqual(self.session.buffered, server.MAX_CONNECTION_BUFFER_BYTES - room)
        finally:
            server.request_budget.reset(token)

    async def test_bidi_request_counts_until_the_handler_lets_go(self) -> None:
        inbound = server.GrpcInbound("identity", self.server)
        payload = encode((1, b"x" * 50000))
        frame = b"\0" + len(payload).to_bytes(4, "big") + payload
        cost = server.message_cost(len(payload), 1)
        working = asyncio.Event()

        async def handler() -> None:
            server.request_budget.set(self.session)
            async for request in inbound.messages():
                await working.wait()  # holds the request while it works with it, or idles
                working.clear()
                del request

        inbound.feed(frame)
        task = asyncio.create_task(handler())
        await self.settle()
        self.assertEqual((self.server.buffered, self.session.buffered), (cost, cost))
        working.set()  # done with it: the handler waits for the next message
        await self.settle()
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))
        inbound.feed(frame)
        await self.settle()
        self.assertEqual(self.server.buffered, cost)
        task.cancel()  # the call ends while the handler and the paused generator hold a request
        await asyncio.wait([task])
        del task
        await self.settle()
        gc.collect()
        await self.settle()
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))


if __name__ == "__main__":
    unittest.main()
