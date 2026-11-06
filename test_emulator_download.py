"""Tests for the boundaries of the emulator download: what the installer refuses to download, unpack or
install, and that a refusal leaves nothing behind and changes nothing that exists. The network is
replaced by fixed responses."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import emulator_download as download

ASSET = "eglantine-windows-x86_64.zip"
COMPATIBLE = b"MZ compatible build"


def unix_member(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = mode << 16
    return info


def zip_bytes(entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for member, data in entries:
            bundle.writestr(member, data)
    return buffer.getvalue()


def files_under(path: Path) -> dict[str, bytes]:
    return {str(item.relative_to(path)): item.read_bytes() for item in path.rglob("*")
            if item.is_file() and item.name != download.LOCK_NAME}


class Response(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data))}


class MemberPathTest(unittest.TestCase):
    def test_accepts_the_release_layout(self) -> None:
        self.assertEqual(download.member_parts("./eglantine", windows=False), ("eglantine",))
        self.assertEqual(download.member_parts("plugins/", windows=True), ("plugins",))
        self.assertEqual(download.member_parts("plugins/platforms/qwindows.dll", windows=True),
                         ("plugins", "platforms", "qwindows.dll"))

    def test_refuses_paths_that_leave_the_destination(self) -> None:
        for name in ["../evil", "a/../../evil", "/etc/passwd", "a//b", "..\\evil", "a\x01b", ""]:
            for windows in (False, True):
                with self.subTest(name=name, windows=windows), self.assertRaises(download.ArchiveError):
                    download.member_parts(name, windows=windows)

    def test_refuses_names_that_windows_reinterprets(self) -> None:
        for name in ["C:evil", "C:/evil", "eglantine.exe:stream", "nul", "con.txt", "LPT1.dll", "dir./x", "x "]:
            with self.subTest(name=name), self.assertRaises(download.ArchiveError):
                download.member_parts(name, windows=True)
        self.assertEqual(download.member_parts("nul", windows=False), ("nul",))


class UnpackZipTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.destination = self.root / "files"
        self.destination.mkdir()

    def unpack(self, entries: list[tuple[zipfile.ZipInfo | str, bytes]], windows: bool = os.name == "nt") -> None:
        archive = self.root / ASSET
        archive.write_bytes(zip_bytes(entries))
        download.unpack_zip(archive, self.destination, windows)

    def test_unpacks_regular_files_and_directories(self) -> None:
        self.unpack([("plugins/", b""), ("plugins/platforms/qwindows.dll", b"dll"),
                     (unix_member(download.EXE_NAME, stat.S_IFREG | 0o755), COMPATIBLE)])
        self.assertEqual((self.destination / "plugins" / "platforms" / "qwindows.dll").read_bytes(), b"dll")
        self.assertEqual((self.destination / download.EXE_NAME).read_bytes(), COMPATIBLE)
        if os.name == "posix":
            self.assertTrue(os.access(self.destination / download.EXE_NAME, os.X_OK))

    def test_refuses_links_and_paths_outside(self) -> None:
        cases = {"link": [(unix_member("link", stat.S_IFLNK | 0o777), b"../../outside")],
                 "traversal": [("../outside", b"evil")],
                 "absolute": [("/outside", b"evil")],
                 "file over directory": [("a", b"file"), ("a/b", b"evil")]}
        for case, entries in cases.items():
            with self.subTest(case), self.assertRaises(SystemExit) as raised:
                self.unpack(entries)
            self.assertIn("cannot be installed safely", str(raised.exception.code))
            self.assertFalse((self.root / "outside").exists())
            self.assertFalse((self.destination / "link").exists())

    def test_refuses_names_that_collide_on_windows(self) -> None:
        with self.assertRaisesRegex(SystemExit, "listed twice"):
            self.unpack([("Qt6Core.dll", b"one"), ("QT6CORE.DLL", b"two")], windows=True)

    def test_refuses_an_archive_that_expands_too_far(self) -> None:
        with mock.patch.object(download, "MAX_EXPANDED_BYTES", 1000), \
                self.assertRaisesRegex(SystemExit, "expands to more than 1000 bytes"):
            self.unpack([("big.dll", bytes(4096))])

    def test_counts_the_bytes_written_not_the_declared_size(self) -> None:
        with mock.patch.object(download, "MAX_EXPANDED_BYTES", 1000):
            extractor = download.Extractor(self.destination, windows=False)
            with self.assertRaisesRegex(download.ArchiveError, "expands"):
                extractor.file("small.dll", 10, io.BytesIO(bytes(4096)), executable=False)


@unittest.skipIf(os.name == "nt", "the AppImage tree is unpacked on Linux; symbolic links need privileges on Windows")
class ScanTreeTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "squashfs-root"
        (self.root / "usr" / "bin").mkdir(parents=True)
        (self.root / "usr" / "bin" / "eglantine").write_bytes(COMPATIBLE)
        (self.root / "AppRun").symlink_to("usr/bin/eglantine")

    def test_accepts_relative_links_inside(self) -> None:
        download.scan_tree(self.root, final=True)

    def test_refuses_links_that_resolve_outside(self) -> None:
        # The last one stays inside if read as text, but "a" is the root itself, so b is its parent.
        for name, link in [("escape", "../outside"), ("absolute", "/etc"), ("b", "a/..")]:
            with self.subTest(link=link):
                (self.root / "a").symlink_to(".")
                (self.root / name).symlink_to(link)
                with self.assertRaisesRegex(download.ArchiveError, "links outside"):
                    download.scan_tree(self.root, final=True)
                (self.root / name).unlink()
                (self.root / "a").unlink()

    def test_refuses_special_and_set_user_id_files(self) -> None:
        os.mkfifo(self.root / "fifo")
        with self.assertRaisesRegex(download.ArchiveError, "special file"):
            download.scan_tree(self.root, final=True)
        (self.root / "fifo").unlink()
        (self.root / "usr" / "bin" / "eglantine").chmod(0o4755)
        with self.assertRaisesRegex(download.ArchiveError, "set-user-ID"):
            download.scan_tree(self.root, final=True)

    def test_refuses_a_tree_beyond_the_limits(self) -> None:
        with mock.patch.object(download, "MAX_EXPANDED_BYTES", 10), \
                self.assertRaisesRegex(download.ArchiveError, "expands"):
            download.scan_tree(self.root, final=False)
        with mock.patch.object(download, "MAX_MEMBERS", 2), self.assertRaisesRegex(download.ArchiveError, "entries"):
            download.scan_tree(self.root, final=False)


@unittest.skipUnless(sys.platform.startswith("linux"), "AppImages run on Linux")
class ExtractAppImageTest(unittest.TestCase):
    """Stand-ins for the AppImage runtime: shell scripts that unpack into squashfs-root."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.staging = Path(directory.name)

    def extract(self, script: str) -> Path:
        appimage = self.staging / "eglantine-linux-x86_64.AppImage"
        appimage.write_text("#!/bin/sh\n" + script)
        return download.extract_appimage(appimage, self.staging)

    def test_returns_the_unpacked_tree(self) -> None:
        files = self.extract("mkdir -p squashfs-root/usr/bin && printf x > squashfs-root/usr/bin/eglantine && "
                             "chmod 755 squashfs-root/usr/bin/eglantine && ln -s usr/bin/eglantine squashfs-root/AppRun\n")
        self.assertEqual(files, self.staging / "squashfs-root")
        self.assertEqual(download.find_executable(files), files / "usr" / "bin" / "eglantine")

    def test_refuses_a_tree_with_a_link_outside(self) -> None:
        with self.assertRaisesRegex(SystemExit, "links outside"):
            self.extract("mkdir -p squashfs-root && ln -s /etc squashfs-root/escape\n")

    def test_reports_a_failed_extraction(self) -> None:
        with self.assertRaisesRegex(SystemExit, "exit code 3.*squashfs is damaged"):
            self.extract("echo 'squashfs is damaged' >&2; exit 3\n")

    def test_stops_an_extraction_that_grows_too_far(self) -> None:
        started = time.monotonic()
        with mock.patch.object(download, "MAX_EXPANDED_BYTES", 4096), \
                mock.patch.object(download, "EXTRACT_POLL_SECONDS", 0.05), \
                self.assertRaisesRegex(SystemExit, "expands to more than 4096 bytes"):
            self.extract("mkdir -p squashfs-root && head -c 100000 /dev/zero > squashfs-root/big && exec sleep 30\n")
        self.assertLess(time.monotonic() - started, 20)


class DownloadEmulatorTest(unittest.TestCase):
    """The Windows zip on every system: expected_asset is fixed, the network replaced."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name) / "home"
        self.archive = zip_bytes([(unix_member(download.EXE_NAME, stat.S_IFREG | 0o755), COMPATIBLE),
                                  ("plugins/platforms/qwindows.dll", b"dll")])
        self.size = len(self.archive)
        self.digest = "sha256:" + hashlib.sha256(self.archive).hexdigest()
        self.requested: list[str] = []
        patcher = mock.patch.object(download, "expected_asset", return_value=ASSET)
        patcher.start()
        self.addCleanup(patcher.stop)

    def url(self, tag: str) -> str:
        return f"{download.DOWNLOAD_PREFIX}{tag}/{ASSET}"

    def releases(self) -> list[dict]:
        def release(tag: str, published: str, prerelease: bool) -> dict:
            return {"tag_name": tag, "draft": False, "prerelease": prerelease, "published_at": published,
                    "assets": [{"name": ASSET, "state": "uploaded", "size": self.size, "digest": self.digest,
                                "browser_download_url": self.url(tag)}]}
        return [release("build-11", "2026-11-04T10:50:11Z", False), release("build-18", "2026-11-05T21:14:19Z", True)]

    def install(self, check, releases: list[dict] | None = None) -> Path:
        metadata = json.dumps(self.releases() if releases is None else releases).encode()

        def respond(url: str, accept: str) -> Response:
            self.requested.append(url)
            if url == download.RELEASES_API:
                return Response(metadata)
            self.assertEqual(url, self.url("build-18"))
            return Response(self.archive)

        with mock.patch.object(download, "_open", respond):
            return download.download_emulator(self.home, check)

    def assert_no_leftovers(self) -> None:
        root = self.home / download.INSTALL_DIR
        self.assertEqual([path.name for path in root.iterdir() if path.name.startswith(download.STAGING_PREFIX)], [])
        self.assertEqual(list(self.home.rglob(ASSET)), [])


    def test_refuses_an_incompatible_release_without_changing_anything(self) -> None:
        earlier = self.home / download.INSTALL_DIR / "build-11"
        (earlier / "user").mkdir(parents=True)
        (earlier / "user" / "save.bin").write_bytes(b"progress")
        (self.home / "play.json").write_text("{}")
        before = files_under(self.home)

        def incompatible(executable: Path) -> None:
            sys.exit(f"{executable} is not a compatible emulator build: it lacks the private-server integration.")

        with self.assertRaises(SystemExit) as raised:
            self.install(incompatible)
        message = str(raised.exception.code)
        self.assertIn("build-18, is not online-capable", message)
        self.assertIn("lacks the private-server integration", message)
        self.assertIn(download.RELEASES_URL, message)
        self.assertNotIn(download.STAGING_PREFIX, message)
        self.assertFalse((self.home / download.INSTALL_DIR / "build-18").exists())
        self.assertEqual(files_under(self.home), before)
        self.assert_no_leftovers()

    def test_refuses_a_download_that_does_not_match_the_release(self) -> None:
        for field, value in [("digest", "sha256:" + "0" * 64), ("size", self.size + 1)]:
            with self.subTest(field=field):
                releases = self.releases()
                releases[1]["assets"][0][field] = value
                with self.assertRaises(SystemExit):
                    self.install(lambda executable: self.fail("checked an unverified download"), releases)
                self.assertFalse((self.home / download.INSTALL_DIR / "build-18").exists())
                self.assert_no_leftovers()

    def test_keeps_an_existing_install_of_the_release(self) -> None:
        target = self.home / download.INSTALL_DIR / "build-18"
        (target / "user").mkdir(parents=True)
        (target / download.EXE_NAME).write_bytes(b"installed earlier")
        (target / download.EXE_NAME).chmod(0o755)
        executable = self.install(lambda executable: None)
        self.assertEqual(executable, (target / download.EXE_NAME).resolve())
        self.assertEqual(executable.read_bytes(), b"installed earlier")
        self.assertEqual(self.requested, [download.RELEASES_API])


class ExpectedAssetTest(unittest.TestCase):
    def test_official_builds_and_unsupported_systems(self) -> None:
        self.assertEqual(download.expected_asset("win32", "AMD64"), "eglantine-windows-x86_64.zip")
        self.assertEqual(download.expected_asset("linux", "x86_64"), "eglantine-linux-x86_64.AppImage")
        self.assertEqual(download.expected_asset("linux", "arm64"), "eglantine-linux-aarch64.AppImage")
        for system, machine in [("darwin", "arm64"), ("win32", "ARM64"), ("linux", "armv7l"), ("freebsd14", "amd64")]:
            with self.subTest(system=system, machine=machine), self.assertRaises(SystemExit) as raised:
                download.expected_asset(system, machine)
            self.assertIn(download.RELEASES_URL, str(raised.exception.code))


if __name__ == "__main__":
    unittest.main()
