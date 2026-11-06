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
import h2.events

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


def island_context(password: str) -> bytes:
    """The rule context the game commits a Cloud Island save with: the island's sessionID and password."""
    return server.encode_map({"sessionID": text(SESSION_ID[1:]), "password": text(password)})


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

    def commit(self, *operations: bytes, context: bytes | None = None) -> bytes:
        return self.backend.commit_documents(
            self.call(), Msg(encode(*[(2, op) for op in operations], (3, context))))

    def get(self, name: str, password: str | None = None) -> Msg:
        context = server.encode_map({"password": text(password)}) if password is not None else None
        return Msg(self.backend.get_document(self.call(), Msg(encode((1, name), (3, context)))))

    def host(self, password: str = PASSWORD, session_id: str = SESSION_ID) -> server.GameSession:
        properties = server.encode_map({"string1": text(session_id)})
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

    def assert_status(self, code: int, function, *args, **kwargs) -> None:
        with self.assertRaises(server.GrpcError) as raised:
            function(*args, **kwargs)
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

    def test_masked_deletion_keeps_unrelated_fields(self) -> None:
        # A masked path the update leaves out is deleted where it is; a field above it that is
        # missing or holds no map is kept as it is.
        name = f"{self.host.documents}/public/MetaData"
        pair = encode((10, server.encode_map({"b": text("gone"), "c": text("kept")})))
        self.host.commit(update(name, {"owner": text("host"), "m": pair}))
        mask = encode((1, "owner.b"), (1, "m.b"), (1, "n.b"))
        self.host.commit(encode((1, encode((1, encode((1, name))), (2, mask)))))
        fields = server.map_entries(self.host.get(name).get_bytes(2))
        self.assertEqual(fields["owner"], text("host"))
        self.assertEqual(server.map_entries(Msg(fields["m"]).get_bytes(10)), {"c": text("kept")})
        self.assertNotIn("n", fields)

    def test_island_password_opens_session_id_then_stage_data(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        self.assert_status(server.PERMISSION_DENIED, self.guest.get, stage)
        self.assert_status(server.PERMISSION_DENIED, self.guest.get,
                           f"{self.host.documents}/private/SessionIDData", "WRONG0")
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assertEqual(self.guest.get(stage).get_str(1), stage)

    def test_island_attachment_requires_current_password_grant(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        upload_id = self.complete_upload()
        self.host.commit(encode((5, encode((1, stage), (2, f"https://storage.invalid/upload/{upload_id}")))))
        request = Msg(encode((1, stage)))
        self.assert_status(server.PERMISSION_DENIED, self.backend.issue_attachment_uri, self.guest.call(), request)
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        url = Msg(self.backend.issue_attachment_uri(self.guest.call(), request)).get_str(1)
        path = "/" + url.split("/", 3)[3]
        result = self.storage.handle("GET", path, {}, b"", self.guest.principal)
        self.assertEqual(result.status, 200)
        file, start, length = result.stream
        try:
            file.seek(start)
            self.assertEqual(file.read(length), b"island")
        finally:
            file.close()
        other = Account(self.backend, "acct-other", "192.0.2.1")
        self.assertEqual(self.storage.handle("GET", path, {}, b"", other.principal).status, 404)
        extra = f"{self.host.documents}/private/Extra"
        extra_upload = self.complete_upload()
        self.host.commit(encode((5, encode((1, extra), (2, f"https://storage.invalid/upload/{extra_upload}")))))
        self.assert_status(server.PERMISSION_DENIED, self.backend.issue_attachment_uri, self.guest.call(),
                           Msg(encode((1, extra))))
        extra_url = Msg(self.backend.issue_attachment_uri(self.host.call(), Msg(encode((1, extra))))).get_str(1)
        self.assertEqual(self.storage.handle("GET", "/" + extra_url.split("/", 3)[3], {}, b"",
                                             self.guest.principal).status, 404)
        with mock.patch.object(server.time, "monotonic", return_value=float("inf")):
            self.assert_status(server.PERMISSION_DENIED, self.backend.issue_attachment_uri, self.guest.call(), request)
            self.assertEqual(self.storage.handle("GET", path, {}, b"", self.guest.principal).status, 404)
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit, update(stage, {}))
        self.host.commit(update(f"{self.host.documents}/private/PasswordData", {"password": text("NEW123")}))
        self.assert_status(server.PERMISSION_DENIED, self.backend.issue_attachment_uri, self.guest.call(), request)
        self.assertEqual(self.storage.handle("GET", path, {}, b"", self.guest.principal).status, 404)

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
        blob_id = self.store.uploads[upload_id]["blob"]
        name = f"{self.host.documents}/private/Extra"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))),
                         encode((2, encode((1, name)))))
        self.assertNotIn(upload_id, self.store.uploads)
        self.assertFalse(self.store.blob_path(blob_id).exists())

    def test_blob_outlives_a_failed_save(self) -> None:
        """Files are deleted only after the state that stops referring to them is saved."""
        upload_id = self.complete_upload()
        blob_id = self.store.uploads[upload_id]["blob"]
        name = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))
        with mock.patch.object(self.store, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.host.commit(encode((4, encode((1, name)))))  # unset the attachment
        self.assertTrue(self.store.blob_path(blob_id).exists())

    def test_blob_outlives_a_failed_sync(self) -> None:
        """A save that cannot reach storage fails before the old file goes."""
        upload_id = self.complete_upload()
        blob_id = self.store.uploads[upload_id]["blob"]
        name = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))
        with mock.patch.object(server, "sync_fd", side_effect=OSError("I/O error")):
            with self.assertRaises(OSError):
                self.host.commit(encode((4, encode((1, name)))))
        self.assertTrue(self.store.blob_path(blob_id).exists())

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
        blob_id = self.store.uploads[upload_id]["blob"]
        name = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, name), (2, f"https://storage.invalid/upload/{upload_id}")))))
        with mock.patch.object(server, "sync_fd", return_value=False):
            self.host.commit(encode((4, encode((1, name)))))
        self.assertFalse(self.store.durable)
        self.assertTrue(self.store.blob_path(blob_id).exists())

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

    def test_failed_replacement_preserves_upload_and_backup(self) -> None:
        for after_rename in (False, True):
            with self.subTest(after_rename=after_rename):
                upload_id = self.storage.new_upload(self.host.principal.account)
                self.assertEqual(self.put(upload_id, b"a" * 10, "bytes 0-9/20").status, 308)
                with self.fail_blob_publish(1, after_rename=after_rename):
                    with self.assertRaises(OSError):
                        self.put(upload_id, b"bbb")
                reopened = server.Store(self.store.path.parent)
                _, descriptors, damaged = reopened.snapshot()
                for _, fd, _ in descriptors:
                    os.close(fd)
                self.assertEqual(damaged, [])
                storage = server.Storage(reopened, "https://storage.invalid")
                response = storage.handle("PUT", f"/upload/{upload_id}",
                                          {"content-range": "bytes 10-19/20"},
                                          b"c" * 10, self.host.principal)
                self.assertEqual(response.status, 200)
                self.assertEqual(reopened.blob_path(reopened.uploads[upload_id]["blob"]).read_bytes(),
                                 b"a" * 10 + b"c" * 10)

    def test_replacement_state_save_failure_keeps_both_versions(self) -> None:
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.put(upload_id, b"a" * 10, "bytes 0-9/20")
        old_blob = self.store.uploads[upload_id]["blob"]
        save = self.store.save

        def fail_after_save():
            save()
            raise OSError(errno.EIO, "state sync failed")

        with mock.patch.object(self.store, "save", side_effect=fail_after_save):
            with self.assertRaises(OSError):
                self.put(upload_id, b"bbb")
        self.assertEqual(self.store.uploads[upload_id]["blob"], old_blob)
        self.assertEqual(self.store.blob_path(old_blob).read_bytes(), b"a" * 10)
        reopened = server.Store(self.store.path.parent)
        self.assertEqual(reopened.blob_path(reopened.uploads[upload_id]["blob"]).read_bytes(), b"bbb")
        _, descriptors, damaged = reopened.snapshot()
        for _, fd, _ in descriptors:
            os.close(fd)
        self.assertEqual(damaged, [])

    @unittest.skipUnless(os.name == "posix", "snapshots run on Linux; Windows cannot replace an open file")
    def test_whole_upload_never_rewrites_the_file_a_snapshot_reads(self) -> None:
        """A snapshot keeps the old file open and reads it up to the count it captured."""
        upload_id = self.storage.new_upload(self.host.principal.account)
        self.put(upload_id, b"a" * 10, "bytes 0-9/20")
        with self.store.blob_path(upload_id).open("rb") as captured:
            with self.fail_blob_publish(1, after_rename=False):
                with self.assertRaises(OSError):
                    self.put(upload_id, b"bbb")
            self.assertEqual(self.put(upload_id, b"e" * 20).status, 200)
            self.assertEqual(captured.read(), b"a" * 10)
        self.assertEqual(self.store.blob_path(self.store.uploads[upload_id]["blob"]).read_bytes(), b"e" * 20)

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
        with self.store.blob_path(self.store.uploads[upload_id]["blob"]).open("r+b") as blob:
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

    def test_town_link_code_grants_only_the_searching_account_session_access(self) -> None:
        session = self.host.host(session_id=":ABC123")
        self.assertEqual(session.island, "")
        other = Account(self.backend, "acct-other", "192.0.2.3")
        self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)
        self.assertEqual(self.guest.query(":WRONG1"), [])
        found = self.guest.query(":ABC123")
        self.assertEqual([entry.get_str(1) for entry in found], [session.name])
        self.assertEqual(found[0].get_str(6), "")
        self.assert_status(server.NOT_FOUND, other.join, session, PASSWORD)
        self.assert_status(server.PERMISSION_DENIED, self.guest.get,
                           f"{self.host.documents}/private/StageData")
        self.assert_status(server.PERMISSION_DENIED, self.guest.join, session, "WRONG0")
        self.guest.join(session, PASSWORD)
        self.assertIn(self.guest.user, session.user_sessions)

    def test_town_code_grant_expires_and_ends_when_code_changes(self) -> None:
        session = self.host.host(session_id=":ABC123")
        self.assertEqual(len(self.guest.query(":ABC123")), 1)
        session.properties_raw = server.encode_map({"string1": text(":NEW123")})
        self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)
        self.assertEqual(len(self.guest.query(":NEW123")), 1)
        with mock.patch.object(server.time, "monotonic",
                               return_value=server.time.monotonic() + server.PASSWORD_GRANT_SECONDS + 1):
            self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)

    def test_short_island_session_id_does_not_bypass_island_password(self) -> None:
        self.host.commit(update(f"{self.host.documents}/private/SessionIDData",
                                {"sessionID": text("ABC123")}))
        session = self.host.host(session_id=":ABC123")
        self.assertEqual(session.island, self.host.user)
        self.assertEqual(self.guest.query(":ABC123"), [])
        self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        for _ in range(server.GUESS_LIMITS["account"][0] + 1):
            self.assertEqual([item.get_str(1) for item in self.guest.query(":ABC123")],
                             [session.name])
        self.guest.join(session, PASSWORD)

    def test_late_island_association_revokes_town_code_visibility(self) -> None:
        session = self.host.host(session_id=":ABC123")
        self.assertEqual(len(self.guest.query(":ABC123")), 1)
        self.host.commit(update(f"{self.host.documents}/private/SessionIDData",
                                {"sessionID": text("ABC123")}))
        self.assertEqual(session.island, "")
        self.assertEqual(self.guest.query(":ABC123"), [])
        self.assert_status(server.NOT_FOUND, self.guest.join, session, PASSWORD)

    def test_town_code_guesses_are_rate_limited(self) -> None:
        self.host.host(session_id=":ABC123")
        for _ in range(server.GUESS_LIMITS["account"][0]):
            self.assertEqual(self.guest.query(":WRONG1"), [])
        self.assert_status(server.RESOURCE_EXHAUSTED, self.guest.query, ":ABC123")

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

    def test_rejoining_after_password_change_does_not_restore_read_access(self) -> None:
        session = self.join_island()
        self.host.commit(update(f"{self.host.documents}/private/PasswordData", {"password": text("NEW123")}))
        another_profile = Account(self.backend, "acct-guest", "203.0.113.1", profile="second-profile")
        another_profile.join(session, PASSWORD)
        self.assert_status(server.PERMISSION_DENIED, another_profile.get,
                           f"{self.host.documents}/private/StageData")

    def test_join_proved_with_current_island_password_survives_grant_expiry(self) -> None:
        session = self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.guest.join(session, PASSWORD)
        another_profile = Account(self.backend, "acct-guest", "203.0.113.1", profile="second-profile")
        with mock.patch.object(server.time, "monotonic", return_value=self.grant_expired()):
            another_profile.join(session, PASSWORD)
            self.backend.drop_user_session(session, self.guest.user)
            stage = f"{self.host.documents}/private/StageData"
            self.assertEqual(another_profile.get(stage).get_str(1), stage)

    def test_request_may_only_name_own_users(self) -> None:
        session = self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        request = encode((1, session.name), (2, PASSWORD), (3, encode((1, self.host.user))))
        self.assert_status(server.PERMISSION_DENIED, self.backend.join_game_session,
                           self.guest.call(), Msg(request))

    # Cloud Island hosting by others than the owner

    @staticmethod
    def grant_expired() -> float:
        """A monotonic time at which every password grant given so far has ended."""
        return server.time.monotonic() + server.PASSWORD_GRANT_SECONDS + 1

    def join_island(self) -> server.GameSession:
        """The owner's island session, which the guest joined with the island password."""
        session = self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.guest.join(session, PASSWORD)
        return session

    def guest_upload(self, body: bytes = b"saved by the guest") -> str:
        upload_id = self.storage.new_upload(self.guest.principal.account)
        self.storage.handle("PUT", f"/upload/{upload_id}", {}, body, self.guest.principal)
        return upload_id

    def island_save(self, upload_id: str) -> tuple[bytes, bytes, bytes]:
        """The writes of the game's Cloud Island save, as its host commits them."""
        stage = f"{self.host.documents}/private/StageData"
        return (update(stage, {}),
                encode((5, encode((1, stage), (2, f"https://storage.invalid/upload/{upload_id}")))),
                update(f"{self.host.documents}/public/MetaData", {"ownerPlayerName": text("host")}))

    def download_stage(self, account: Account) -> bytes:
        request = Msg(encode((1, f"{self.host.documents}/private/StageData")))
        url = Msg(self.backend.issue_attachment_uri(account.call(), request)).get_str(1)
        result = self.storage.handle("GET", "/" + url.split("/", 3)[3], {}, b"", account.principal)
        self.assertEqual(result.status, 200)
        file, start, length = result.stream
        try:
            file.seek(start)
            return file.read(length)
        finally:
            file.close()

    def test_sole_guest_takes_over_after_owner_leaves(self) -> None:
        # With the owner gone, the one remaining authorized guest can save the island.
        stage = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((5, encode((1, stage), (2, f"https://storage.invalid/upload/{self.complete_upload()}")))))
        session = self.join_island()
        self.backend.drop_user_session(session, self.host.user)  # the owner has left
        self.assertEqual(list(session.user_sessions), [self.guest.user])
        self.assertIs(self.backend.sessions[session.name], session)
        self.assertEqual(session.island, self.host.user)
        save = self.island_save(self.guest_upload())
        with mock.patch.object(server.time, "monotonic", return_value=self.grant_expired()):
            self.assertEqual(self.guest.get(stage).get_str(1), stage)
            self.assertEqual(self.download_stage(self.guest), b"island")
            self.guest.commit(*save, context=island_context(PASSWORD))
        self.assertEqual(self.download_stage(self.host), b"saved by the guest")

    def test_expired_host_is_pruned_before_the_sole_guest_saves(self) -> None:
        session = self.join_island()
        session.user_sessions[self.host.user].last_seen -= (server.USER_SESSION_GRACE_SECONDS + 1) * 1_000_000_000
        self.guest.commit(*self.island_save(self.guest_upload()), context=island_context(PASSWORD))
        self.assertNotIn(self.host.user, session.user_sessions)
        self.assertEqual(self.download_stage(self.host), b"saved by the guest")

    def test_expired_host_is_pruned_before_sole_guest_publishes_host(self) -> None:
        session = self.join_island()
        calls = []
        for account in (self.host, self.guest):
            member = session.user_sessions[account.user]
            self.backend.gamesync_join(session, member)
            token = Msg(self.backend.encode_gamesync_token(account.call(), account.user, member.name)).get_msg(1).get_str(2)
            calls.append((account.call(token), member))
        doc = "docs/ktglol/sys"
        initial = update(doc, {"h_sid": encode((3, calls[0][1].ussid)), "h_uid": encode((3, 101))})
        self.backend.gamesync_write_documents(calls[0][0], Msg(encode((1, initial))))
        calls[0][1].last_seen -= (server.USER_SESSION_GRACE_SECONDS + 1) * 1_000_000_000
        elected = update(doc, {"h_sid": encode((3, calls[1][1].ussid)), "h_uid": encode((3, 202))})
        self.backend.gamesync_write_documents(calls[1][0], Msg(encode((1, elected))))
        self.assertEqual(session.host_session, calls[1][1].name)

    def test_multiple_guests_cannot_claim_a_departed_hosts_save(self) -> None:
        session = self.join_island()
        other = Account(self.backend, "acct-other", "192.0.2.1")
        other.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        other.join(session, PASSWORD)
        self.backend.drop_user_session(session, self.host.user)
        stage = f"{self.host.documents}/private/StageData"
        for account in (self.guest, other):
            self.assert_status(server.PERMISSION_DENIED, account.commit, update(stage, {}),
                               context=island_context(PASSWORD))

    def test_visitor_hosts_the_island_while_the_owner_is_away(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        self.host.commit(encode((2, encode((1, stage)))))  # the owner left before saving it once
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assertEqual(self.guest.query(), [])
        session = self.guest.host()
        self.assertEqual(session.island, self.host.user)
        # Other visitors with the password, and the owner, find the session the visitor opened.
        other = Account(self.backend, "acct-other", "192.0.2.1")
        self.assertEqual(other.query(), [])
        other.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assertEqual([entry.get_str(1) for entry in other.query()], [session.name])
        other.join(session, PASSWORD)
        self.assertEqual([entry.get_str(1) for entry in self.host.query()], [session.name])
        save = self.island_save(self.guest_upload())
        with mock.patch.object(server.time, "monotonic", return_value=self.grant_expired()):
            # The creator is the real host of this session; another joined visitor is not.
            self.assert_status(server.PERMISSION_DENIED, other.commit, save[0],
                               context=island_context(PASSWORD))
            self.guest.commit(*save, context=island_context(PASSWORD))
            self.assertEqual(self.download_stage(other), b"saved by the guest")
        self.backend.drop_user_session(session, self.guest.user)
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit, save[0],
                           context=island_context(PASSWORD))
        other.commit(save[0], context=island_context(PASSWORD))

    def test_island_owner_cannot_overwrite_a_visiting_hosts_save(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        metadata = f"{self.host.documents}/public/MetaData"
        initial = self.complete_upload()
        self.host.commit(encode((5, encode((1, stage), (2, f"https://storage.invalid/upload/{initial}")))))
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        session = self.guest.host()
        self.host.join(session, PASSWORD)
        original = self.download_stage(self.host)
        owner_upload = self.complete_upload()
        operations = (
            update(stage, {"changed": text("owner")}),
            update(metadata, {"changed": text("owner")}),
            encode((2, encode((1, stage)))),
            encode((6, encode((1, stage), (2, encode((1, "changed"), (2, 1)))))),
            encode((3, encode((1, stage), (2, b"owner"), (4, "application/octet-stream")))),
            encode((4, encode((1, stage)))),
            encode((5, encode((1, stage), (2, f"https://storage.invalid/upload/{owner_upload}")))),
        )
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                self.assert_status(server.PERMISSION_DENIED, self.host.commit, operation)
        self.assertEqual(self.download_stage(self.host), original)
        self.guest.commit(*self.island_save(self.guest_upload()), context=island_context(PASSWORD))
        self.assertEqual(self.download_stage(self.host), b"saved by the guest")
        self.backend.drop_user_session(session, self.host.user)
        self.assert_status(server.PERMISSION_DENIED, self.host.commit, operations[0])
        self.host.commit(update(f"{self.host.documents}/private/SessionIDData", {"sessionID": text("CHANGED")}))
        self.assert_status(server.PERMISSION_DENIED, self.host.commit, operations[0])
        self.backend.drop_user_session(session, self.guest.user)
        self.host.commit(operations[0])

    def test_another_profile_on_the_hosts_account_is_not_the_host(self) -> None:
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.guest.host()
        other = Account(self.backend, "acct-guest", "203.0.113.1", profile="other-profile")
        stage = f"{self.host.documents}/private/StageData"
        self.assert_status(server.PERMISSION_DENIED, other.commit, update(stage, {"changed": text("other")}),
                           context=island_context(PASSWORD))
        self.guest.commit(*self.island_save(self.guest_upload()), context=island_context(PASSWORD))
        self.assertEqual(self.download_stage(self.host), b"saved by the guest")

    def test_host_grant_moves_island_save_authority(self) -> None:
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        session = self.guest.host()
        other = Account(self.backend, "acct-other", "192.0.2.1")
        other.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        other.join(session, PASSWORD)

        def gamesync(account: Account) -> tuple[server.Call, int]:
            member = session.user_sessions[account.user]
            self.backend.gamesync_join(session, member)
            token = Msg(self.backend.encode_gamesync_token(account.call(), account.user, member.name)).get_msg(1).get_str(2)
            name = server.GAMESYNC_USER_SESSION_DOCS + member.name.rpartition("/")[2]
            ussid = Msg(server.doc_entries(session.gamesync.docs[name])["ussid"]).get_int(3)
            return account.call(token), ussid

        host_call, host_sid = gamesync(self.guest)
        other_call, other_sid = gamesync(other)
        doc = "docs/ktglol/sys"
        initial = update(doc, {"h_sid": encode((3, host_sid)), "h_uid": encode((3, 101))})
        transfer = update(doc, {"h_sid": encode((3, other_sid)), "h_uid": encode((3, 202))})
        self.backend.gamesync_write_documents(host_call, Msg(encode((1, initial))))
        self.assert_status(server.PERMISSION_DENIED, self.backend.gamesync_write_documents,
                           other_call, Msg(encode((1, transfer))))
        # Alternate write paths and forged server-issued identity must not bypass host authority.
        self.assert_status(server.PERMISSION_DENIED, self.backend.gamesync_lazy_write_documents,
                           other_call, Msg(encode((1, transfer))))
        tx = Msg(self.backend.gamesync_begin_transaction(other_call, Msg())).get_bytes(1)
        self.assert_status(server.PERMISSION_DENIED, self.backend.gamesync_commit_transaction,
                           other_call, Msg(encode((1, transfer), (3, tx))))
        host_member = session.user_sessions[self.guest.user]
        presence = server.GAMESYNC_USER_SESSION_DOCS + host_member.name.rpartition("/")[2]
        self.assert_status(server.PERMISSION_DENIED, self.backend.gamesync_write_documents,
                           other_call, Msg(encode((1, update(presence, {"ussid": encode((3, other_sid))})))))
        deferred = encode((1, "userSessions/current/deferments/forged"), (2, transfer))
        self.backend.gamesync_write_documents(other_call, Msg(encode((2, encode((1, encode((1, deferred))))))))
        self.backend.gamesync_fire_deferments(session, session.user_sessions[other.user].name)
        self.assertEqual(session.host_session, host_member.name)
        self.backend.gamesync_write_documents(host_call, Msg(encode((1, transfer))))
        self.assert_status(server.PERMISSION_DENIED, self.backend.gamesync_write_documents,
                           host_call, Msg(encode((1, initial))))

        stage = f"{self.host.documents}/private/StageData"
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit, update(stage, {}),
                           context=island_context(PASSWORD))
        upload_id = self.storage.new_upload(other.principal.account)
        self.storage.handle("PUT", f"/upload/{upload_id}", {}, b"new host's island", other.principal)
        other.commit(*self.island_save(upload_id), context=island_context(PASSWORD))
        self.assertEqual(self.download_stage(self.host), b"new host's island")

    def test_visitor_host_save_requires_current_password_and_session(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        password_doc = f"{self.host.documents}/private/PasswordData"
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.guest.host()
        save = self.island_save(self.guest_upload())
        original = self.store.documents[stage]
        wrong_session = server.encode_map({"sessionID": text("NOT-THE-ISLAND"), "password": text(PASSWORD)})
        for context in (None, wrong_session, island_context("WRONG0")):
            with self.subTest(context=context):
                self.assert_status(server.PERMISSION_DENIED, self.guest.commit, *save, context=context)
        # A permitted operation cannot smuggle a different document into the same commit.
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit, save[0],
                           update(password_doc, {"password": text("HIJACK")}),
                           context=island_context(PASSWORD))
        self.assertEqual(self.store.documents[stage], original)
        self.host.commit(update(password_doc, {"password": text("NEW123")}))
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit, *save,
                           context=island_context("NEW123"))

    def test_visitor_host_import_transfers_quota_without_new_global_blob_usage(self) -> None:
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.guest.host()
        save = self.island_save(self.guest_upload(b"x" * 100))
        self.storage.max_bytes = sum(self.storage.usage())
        self.guest.commit(*save, context=island_context(PASSWORD))
        self.assertEqual(self.storage.usage(self.host.principal.account)[1], 100)
        self.assertEqual(self.storage.usage(self.guest.principal.account)[1], 0)

    def test_cannot_create_a_second_session_for_an_active_island(self) -> None:
        session = self.host.host()
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assert_status(server.ALREADY_EXISTS, self.guest.host)
        self.guest.join(session, PASSWORD)

    def test_unrecognized_owner_session_also_blocks_duplicate_host(self) -> None:
        session_doc = f"{self.host.documents}/private/SessionIDData"
        self.host.commit(update(session_doc, {"sessionID": text("OLD-ID")}))
        original = self.host.host()
        self.assertEqual(original.island, "")
        self.host.commit(update(session_doc, {"sessionID": text(SESSION_ID[1:])}))
        self.guest.get(session_doc, PASSWORD)
        self.assert_status(server.ALREADY_EXISTS, self.guest.host)

    def test_strangers_unassociated_session_does_not_block_owner(self) -> None:
        stranger = Account(self.backend, "acct-stranger", "192.0.2.7")
        self.assertEqual(stranger.host().island, "")
        self.assertEqual(self.host.host().island, self.host.user)

    def test_ambiguous_island_ids_cannot_claim_host_authority(self) -> None:
        self.guest.commit(update(f"{self.guest.documents}/private/SessionIDData",
                                 {"sessionID": text(SESSION_ID[1:])}))
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assert_status(server.FAILED_PRECONDITION, self.guest.host)

    def test_rejoined_creator_does_not_recover_host_authority(self) -> None:
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        session = self.guest.host()
        other = Account(self.backend, "acct-other", "192.0.2.1")
        other.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        other.join(session, PASSWORD)
        self.backend.drop_user_session(session, self.guest.user)
        self.guest.join(session, PASSWORD)
        stage = f"{self.host.documents}/private/StageData"
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit, update(stage, {}),
                           context=island_context(PASSWORD))

    def test_changed_island_id_fences_the_old_session(self) -> None:
        session_doc = f"{self.host.documents}/private/SessionIDData"
        self.guest.get(session_doc, PASSWORD)
        self.guest.host()
        self.host.commit(update(session_doc, {"sessionID": text("NEW-ID")}))
        new_context = server.encode_map({"sessionID": text("NEW-ID"), "password": text(PASSWORD)})
        self.assert_status(server.PERMISSION_DENIED, self.guest.commit,
                           update(f"{self.host.documents}/private/StageData", {}), context=new_context)

    def test_a_session_only_hosts_an_island_its_creator_may_open(self) -> None:
        # The stranger names the island's session id without having given the island password.
        stranger = Account(self.backend, "acct-stranger", "192.0.2.7")
        session = stranger.host()
        self.assertEqual(session.island, "")
        self.guest.get(f"{self.host.documents}/private/SessionIDData", PASSWORD)
        self.assertEqual(self.guest.query(), [])
        stage = f"{self.host.documents}/private/StageData"
        self.assert_status(server.PERMISSION_DENIED, stranger.get, stage)
        self.assert_status(server.PERMISSION_DENIED, stranger.commit, update(stage, {}),
                           context=island_context(PASSWORD))

    def test_member_cannot_write_another_accounts_island(self) -> None:
        self.join_island()
        stage = f"{self.host.documents}/private/StageData"
        metadata = f"{self.host.documents}/public/MetaData"
        save = self.island_save(self.guest_upload())
        original_stage = self.store.documents.get(stage)
        original_metadata = self.store.documents.get(metadata)
        # The password and current membership authorize reading, not writing either save document
        # or importing an attachment. Test each operation separately and as one atomic commit.
        for writes in [(save[0],), (save[1],), (save[2],), save]:
            with self.subTest(writes=len(writes)):
                self.assert_status(server.PERMISSION_DENIED, self.guest.commit, *writes,
                                   context=island_context(PASSWORD))
        self.assertEqual(self.store.documents.get(stage), original_stage)
        self.assertEqual(self.store.documents.get(metadata), original_metadata)

    def test_island_membership_ends_with_the_members_game(self) -> None:
        stage = f"{self.host.documents}/private/StageData"
        session = self.join_island()
        gone = server.time.time_ns() + (server.USER_SESSION_GRACE_SECONDS + 1) * 1_000_000_000
        with mock.patch.object(server.time, "monotonic", return_value=self.grant_expired()):
            self.assertEqual(self.guest.get(stage).get_str(1), stage)
            with mock.patch.object(server.time, "time_ns", return_value=gone):
                self.assert_status(server.PERMISSION_DENIED, self.guest.get, stage)
                self.assert_status(server.PERMISSION_DENIED, self.guest.commit, update(stage, {}),
                                   context=island_context(PASSWORD))
            self.backend.drop_user_session(session, self.guest.user)
            self.assert_status(server.PERMISSION_DENIED, self.guest.get, stage)

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
        session = server.H2Session(types.SimpleNamespace(buffered=0), None, FakeWriter())
        inbound = server.GrpcInbound("identity", session)
        message = b"\0" * 1024 * 1024
        frame = b"\x00" + len(message).to_bytes(4, "big") + message
        for _ in range(server.MAX_INBOUND_QUEUE_BYTES // (len(message) + server.INBOUND_MESSAGE_OVERHEAD)):
            inbound.feed(frame)
        self.assertFalse(inbound.failed)
        self.assertEqual((session.server.buffered, session.buffered), (inbound.size(), inbound.size()))
        inbound.feed(frame)
        self.assertTrue(inbound.failed)
        inbound.discard()
        self.assertEqual((session.server.buffered, session.buffered), (0, 0))

    def test_empty_bidi_messages_cannot_bypass_queue_limit(self) -> None:
        session = server.H2Session(types.SimpleNamespace(buffered=0), None, FakeWriter())
        inbound = server.GrpcInbound("identity", session)
        with mock.patch.object(server, "MAX_INBOUND_QUEUE_BYTES", 2 * server.INBOUND_MESSAGE_OVERHEAD):
            inbound.feed(b"\0" * 5)
            inbound.feed(b"\0" * 5)
            self.assertFalse(inbound.failed)
            inbound.feed(b"\0" * 5)
            self.assertTrue(inbound.failed)
        self.assertEqual((session.server.buffered, session.buffered), (0, 0))

    def test_stun_descriptions_are_bounded(self) -> None:
        description = server.describe_stun_attributes(struct.pack("!HH", 0x8028, 0) * 5000)
        self.assertLessEqual(len(description), server.STUN_LOG_LINE_CHARS)
        self.assertIn("more attributes", description)

    def test_gamesync_size_counts_globals_and_names(self) -> None:
        size, records = server.gamesync_size({"d": {"fields": "abc"}, "gone": None}, {"g": b"xyz"}, {})
        self.assertEqual(records, 2)
        self.assertEqual(size, 1 + 3 + 1 + 3 + 2 * server.STATE_OVERHEAD_BYTES)


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


def request_headers(path: str, method: str = "POST", grpc: bool = False) -> list[tuple[str, str]]:
    headers = [(":method", method), (":scheme", "https"), (":authority", "test"), (":path", path)]
    return headers + [("content-type", "application/grpc")] if grpc else headers


BIDI_DEFLATE_HEADERS = request_headers("/test.Service/Bidi", grpc=True) + [("grpc-encoding", "deflate")]


def compressed_frame(payload: bytes) -> bytes:
    compressed = zlib.compress(payload)
    return b"\x01" + len(compressed).to_bytes(4, "big") + compressed


async def consume(call: server.Call, requests):
    """A bidirectional handler that reads every request and answers once the client is done."""
    async for request in requests:
        del request
    yield b""


class StreamAccountingTest(unittest.IsolatedAsyncioTestCase):
    """Request bytes stay counted in Server.buffered exactly as long as they are kept."""

    def setUp(self) -> None:
        self.server = types.SimpleNamespace(
            buffered=0, pending=0, downloads=0,
            backend=types.SimpleNamespace(bidi={"/test.Service/Bidi": None}),
            storage=types.SimpleNamespace(handle=lambda *args: server.response(404, b"none\n")))
        self.writer = FakeWriter()
        self.session = server.H2Session(self.server, None, self.writer)
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

    def statuses(self) -> dict[int, int]:
        """The grpc-status of each call the server answered, as the client reads it."""
        statuses = {}
        for event in self.client.receive_data(bytes(self.writer.sent)):
            if isinstance(event, (h2.events.ResponseReceived, h2.events.TrailersReceived)):
                headers = dict(event.headers)
                if b"grpc-status" in headers:
                    statuses[event.stream_id] = int(headers[b"grpc-status"])
        self.writer.sent.clear()
        return statuses

    def serve_bidi(self, handler) -> None:
        """Answers bidirectional calls with `handler`, through the server's own call handling."""
        self.server.backend.bidi = {"/test.Service/Bidi": handler}
        self.server.handle_grpc = lambda *args: server.Server.handle_grpc(self.server, *args)

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
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

    async def test_decompressed_bidi_messages_count_against_the_connection(self) -> None:
        payload = encode((1, b"x" * 1_000_000))
        self.client.send_headers(1, BIDI_DEFLATE_HEADERS)
        self.client.send_data(1, compressed_frame(payload) * 2)
        self.deliver()  # the call has not read anything yet: both messages wait, decoded
        self.assertEqual((self.server.buffered, self.session.buffered),
                         (2 * (len(payload) + server.INBOUND_MESSAGE_OVERHEAD),) * 2)
        self.client.reset_stream(1)
        self.deliver()
        await self.settle()
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

    async def send_expanding_call(self) -> dict[int, int]:
        """A bidirectional call whose one message decompresses from about 1 KB to 1 MB."""
        self.serve_bidi(consume)
        self.client.send_headers(1, BIDI_DEFLATE_HEADERS)
        self.client.send_data(1, compressed_frame(encode((1, b"x" * 1_000_000))))
        self.deliver()
        await self.settle()
        return self.statuses()

    async def test_decoding_past_the_connection_budget_fails_the_call(self) -> None:
        held = server.MAX_CONNECTION_BUFFER_BYTES - 100_000  # what the connection's other calls hold
        self.session.buffered = held
        self.assertEqual(await self.send_expanding_call(), {1: server.RESOURCE_EXHAUSTED})
        self.assertEqual((self.server.buffered, self.session.buffered), (0, held))
        self.assertFalse(self.session.overloaded)  # the connection and its other calls go on

    async def test_decoding_past_the_global_budget_fails_the_call(self) -> None:
        held = server.MAX_BUFFERED_BYTES - 100_000  # what other connections hold
        self.server.buffered = held
        self.assertEqual(await self.send_expanding_call(), {1: server.RESOURCE_EXHAUSTED})
        self.assertEqual((self.server.buffered, self.session.buffered), (held, 0))

    async def test_compressed_calls_arriving_together_stay_within_the_budget(self) -> None:
        payload = encode((1, b"x" * 400_000))
        self.serve_bidi(consume)
        with mock.patch.object(server, "MAX_CONNECTION_BUFFER_BYTES", 1_000_000):
            for stream_id in (1, 3, 5):
                self.client.send_headers(stream_id, BIDI_DEFLATE_HEADERS)
                self.client.send_data(stream_id, compressed_frame(payload))
            self.deliver()  # one batch, decoded before any of the calls reads a message
            self.assertEqual((self.server.buffered, self.session.buffered),
                             (2 * (len(payload) + server.INBOUND_MESSAGE_OVERHEAD),) * 2)
            await self.settle()
            self.assertEqual(self.statuses(), {5: server.RESOURCE_EXHAUSTED})
            for stream_id in (1, 3):
                self.client.reset_stream(stream_id)
            self.deliver()
            await self.settle()
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

    async def test_queued_messages_are_released_when_the_call_ends(self) -> None:
        async def refuse(call: server.Call, requests):
            raise server.GrpcError(server.PERMISSION_DENIED, "not yours")
            yield

        self.serve_bidi(refuse)
        payload = encode((1, b"x" * 100_000))
        self.client.send_headers(1, BIDI_DEFLATE_HEADERS)
        self.client.send_data(1, compressed_frame(payload))
        self.deliver()
        self.assertEqual((self.server.buffered, self.session.buffered),
                         (len(payload) + server.INBOUND_MESSAGE_OVERHEAD,) * 2)
        await self.settle()  # the call ends without reading its message
        self.assertEqual(self.statuses(), {1: server.PERMISSION_DENIED})
        self.assertEqual((self.server.buffered, self.session.buffered), (0, 0))

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

    async def test_verbose_logging_cannot_leave_a_call_unanswered(self) -> None:
        self.server.backend.streams = {}
        self.server.backend.unary = {
            "/test.Service/Count": lambda call, request: encode((1, len(request.fields[1])))}
        payload = b"\x08\x01" * 1000
        # Room for the request and no more, so logging it cannot parse it a second time.
        held = server.MAX_CONNECTION_BUFFER_BYTES - server.message_cost(len(payload), 1000)
        self.session.buffered = held
        self.client.send_headers(1, request_headers("/test.Service/Count", grpc=True))
        self.deliver()
        with self.assertLogs(server.log, "DEBUG") as logs:
            await server.Server.handle_grpc(self.server, server.H2Stream(self.session, 1),
                                            {":path": "/test.Service/Count"},
                                            b"\0" + len(payload).to_bytes(4, "big") + payload)
        self.assertEqual(self.statuses(), {1: server.OK})
        self.assertIn(f"<{len(payload)} bytes>", "\n".join(logs.output))
        self.assertEqual((self.server.buffered, self.session.buffered), (0, held))

    async def test_logged_payloads_are_rendered_within_the_budget(self) -> None:
        inner = encode((2, 1))  # not printable, so rendered as a nested message
        raw = encode((1, inner))
        # Room for the outer message only: the nested one would count on top of it.
        self.session.buffered = server.MAX_CONNECTION_BUFFER_BYTES - server.message_cost(len(raw), 1)
        token = server.request_budget.set(self.session)
        try:
            self.assertEqual(server.dump(raw), f"1: <{len(inner)} bytes> {inner.hex()}")
            self.session.buffered -= server.message_cost(len(inner), 1)
            self.assertEqual(server.dump(raw), "1 {\n  2: 1\n}")
        finally:
            server.request_budget.reset(token)
        self.assertEqual(self.server.buffered, 0)

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
        inbound = server.GrpcInbound("identity", self.session)
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


def watch_request(user_session: str, document: str) -> bytes:
    """A KeepUserSessionRequest that names `user_session` and watches `document`."""
    target = encode((1, "userSessions/current/targets/1"), (2, encode((1, document))))
    return encode((1, user_session), (3, encode((1, target))))


class KeepUserSession:
    """A KeepUserSession call read as the server's call handling reads it. Its responses are kept as
    bytes and the status it ends with as its code, so the test holds none of its parsed messages."""

    def __init__(self, backend: server.Backend, gamesync_call: server.Call, request: bytes):
        self.requests: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.requests.put_nowait(request)
        self.responses: list[bytes] = []
        self.status: int | None = None
        self.task = asyncio.create_task(self.run(backend.keep_user_session(gamesync_call, self.incoming())))

    async def incoming(self):
        while (request := await self.requests.get()) is not None:
            yield Msg(request)

    async def run(self, responses) -> None:
        try:
            async for message in responses:
                self.responses.append(message)
        except server.GrpcError as exc:
            self.status = exc.code


class GamesyncLoggingTest(unittest.IsolatedAsyncioTestCase):
    """What a Gamesync call parses only to log it counts against the connection's request budget,
    but a description that does not fit is left out of the log: the call is answered as it would
    be without it, with its own errors."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = server.Store(Path(directory.name))
        self.backend = server.Backend(store, server.Storage(store, "https://storage.invalid"), 4, "", 443)
        host = Account(self.backend, "acct-host", "198.51.100.1")
        guest = Account(self.backend, "acct-guest", "203.0.113.1")
        host.commit(update(f"{host.documents}/private/PasswordData", {"password": text(PASSWORD)}),
                    update(f"{host.documents}/private/SessionIDData", {"sessionID": text(SESSION_ID[1:])}))
        self.island = host.host()
        ticket = next(ticket for ticket in self.backend.tickets.values() if ticket.session is self.island)
        guest.get(f"{host.documents}/private/SessionIDData", PASSWORD)
        self.host_call, self.host_session = self.gamesync(host, ticket.matched[0])
        self.guest_call, _ = self.gamesync(guest, guest.join(self.island, PASSWORD).get_raws(1)[0])
        # The connection the Gamesync calls arrive on, whose request budget they count against.
        self.connection = server.H2Session(types.SimpleNamespace(buffered=0), None, FakeWriter())

    def gamesync(self, account: Account, matched: bytes) -> tuple[server.Call, str]:
        """A Gamesync call of the user session in a MatchedUserSession, and that user session."""
        user_session, matchmaking_token = Msg(matched).get_str(2), Msg(matched).get_str(3)
        request = encode((1, f"userSessions/{user_session.rpartition('/')[2]}"), (2, matchmaking_token))
        token = Msg(self.backend.gamesync_issue_token(account.call(), Msg(request))).get_msg(1).get_str(2)
        return account.call(token), user_session

    async def settle(self) -> None:
        for _ in range(50):
            await asyncio.sleep(0)

    async def test_malformed_session_diagnostic_does_not_end_watch(self) -> None:
        member = next(member for member in self.island.user_sessions.values()
                      if member.name == self.host_session)
        self.backend.gamesync_join(self.island, member)
        # An unassociated session does not enforce island-host presence fields.
        self.island.island = ""
        name = server.GAMESYNC_USER_SESSION_DOCS + self.host_session.rpartition('/')[2]
        self.backend.gamesync_write_documents(
            self.host_call, Msg(encode((1, update(name, {'ussid': b'\x0f'})))))
        watch = KeepUserSession(self.backend, self.host_call,
                                watch_request('userSessions/current', 'docs/__stg/All'))
        await self.settle()
        self.assertFalse(watch.task.done())
        self.backend.gamesync_write_documents(
            self.host_call, Msg(encode((1, update('docs/__stg/All', {'pl': text('still connected')})))))
        await self.settle()
        self.assertTrue(any(b'still connected' in response for response in watch.responses))
        watch.requests.put_nowait(None)
        await self.settle()
        self.assertIsNone(watch.status)

    async def test_committed_write_is_answered_when_logging_it_does_not_fit(self) -> None:
        # A valid value the write stores as it is, an array of 50,000 small integers: looking for
        # session descriptions in it parses every element, past the connection's 48 MiB.
        many = encode((9, encode(*[(1, encode((3, 1)))] * 50_000)))  # common.Value array_value
        sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=candidate:1 1 udp 1 192.0.2.7 50000 typ host\r\n"
        token = server.request_budget.set(self.connection)
        try:
            with self.assertLogs(server.log, "INFO") as logs:
                watch = KeepUserSession(self.backend, self.host_call,
                                        watch_request("userSessions/current", "docs/__stg/All"))
                await self.settle()
                self.backend.gamesync_write_documents(
                    self.host_call, Msg(encode((1, update("docs/__stg/All", {"pl": many})))))
                await self.settle()
                self.backend.gamesync_write_documents(
                    self.host_call, Msg(encode((1, update("docs/__stg/Sdp", {"sdp": text(sdp)})))))
                watch.requests.put_nowait(None)
                await self.settle()
        finally:
            server.request_budget.reset(token)
        output = "\n".join(logs.output)
        self.assertIn(f"gamesync docs/__stg/All written by {self.host_session}: SDP not looked for "
                      "(too much request data in flight)", output)
        self.assertIn("-> <not described: too much request data in flight>", output)
        self.assertIn("candidates: a=candidate:1 1 udp 1 192.0.2.7 50000 typ host", output)  # what fits is logged
        self.assertEqual(server.doc_entries(self.island.gamesync.docs["docs/__stg/All"])["pl"], many)
        self.assertTrue(any(many in response for response in watch.responses))  # the watcher was told
        self.assertIsNone(watch.status)  # and its call went on until the client closed it
        gc.collect()
        self.assertEqual(self.connection.buffered, 0)

    async def test_another_users_session_is_refused_when_describing_the_request_does_not_fit(self) -> None:
        request = watch_request(self.host_session, "docs/__stg/All")
        # Room for the request and no more, so describing it for the log cannot parse its target.
        self.connection.buffered = server.MAX_CONNECTION_BUFFER_BYTES - server.message_cost(len(request), 2)
        token = server.request_budget.set(self.connection)
        try:
            with self.assertLogs(server.log, "INFO") as logs:
                watch = KeepUserSession(self.backend, self.guest_call, request)
                await self.settle()
        finally:
            server.request_budget.reset(token)
        self.assertIn("<- <not described: too much request data in flight>", "\n".join(logs.output))
        self.assertEqual(watch.status, server.PERMISSION_DENIED)

    async def test_write_still_fails_on_its_own_errors(self) -> None:
        malformed = encode((1, encode((1, encode((1, "docs/__stg/All"), (2, b"\x0f"))))))  # fields: wire type 7
        request = encode((1, update("docs/__stg/All", {"pl": text("A")})))
        token = server.request_budget.set(self.connection)
        try:
            with self.assertRaises(ValueError):
                self.backend.gamesync_write_documents(self.host_call, Msg(malformed))
            # Room for the request and no more, so the write cannot parse its operation.
            self.connection.buffered = server.MAX_CONNECTION_BUFFER_BYTES - server.message_cost(len(request), 1)
            with self.assertRaises(server.GrpcError) as refused:
                self.backend.gamesync_write_documents(self.host_call, Msg(request))
            self.assertEqual(refused.exception.code, server.RESOURCE_EXHAUSTED)
        finally:
            server.request_budget.reset(token)
        self.assertNotIn("docs/__stg/All", self.island.gamesync.docs)

    async def test_descriptions_that_do_not_fit_are_left_out(self) -> None:
        entries = {"uid": encode((7, "u-1")), "ussid": encode((3, 1)), "ucsid": encode((3, 2))}
        self.assertEqual(server.describe_user_session_document(entries), "uid=u-1 ussid=1 ucsid=2")
        with self.assertRaises(ValueError):  # data that does not decode is not hidden
            server.describe_keep_user_session_response(b"\x0f")
        self.connection.buffered = server.MAX_CONNECTION_BUFFER_BYTES  # other calls hold all of it
        token = server.request_budget.set(self.connection)
        try:
            self.assertEqual(server.describe_user_session_document(entries),
                             "<not described: too much request data in flight>")
        finally:
            server.request_budget.reset(token)
        self.assertEqual(self.connection.buffered, server.MAX_CONNECTION_BUFFER_BYTES)


if __name__ == "__main__":
    unittest.main()
