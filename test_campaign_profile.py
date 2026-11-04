"""Regression tests for isolated campaign profiles and save imports."""
from __future__ import annotations

import os
import re
import shutil
import struct
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import campaign_profile as cp

TITLE = "0100000000010000"
CA_NAME = "pokopia-launcher-gateway-ca.der"
HOST = bytes.fromhex("4bcfd8f4942a0f0d6268f17e2403036a")
GUEST = bytes.fromhex("116c9d7aa6d941608833361a4effd431")


def make_pe(imports: list[str], delayed: list[str] = (), machine: int = 0x8664, library: bool = False) -> bytes:
    """A minimal 64-bit Windows program or DLL that imports `imports` and delay-loads `delayed`."""
    section, headers = 0x1000, 0x200
    descriptors = 20 * (len(imports) + 1)
    delay = 32 * (len(delayed) + 1) if delayed else 0
    names = bytearray()
    addresses = []
    for name in (*imports, *delayed):
        addresses.append(section + descriptors + delay + len(names))
        names += name.encode() + b"\0"
    content = bytearray()
    for address in addresses[:len(imports)]:
        content += struct.pack("<IIIII", 0, 0, 0, address, 0x2000)
    content += bytes(20)
    if delayed:
        for address in addresses[len(imports):]:
            content += struct.pack("<II", 1, address) + bytes(24)
        content += bytes(32)
    content += names
    content += bytes(-len(content) % 0x200)
    header = bytearray(headers)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    optional, optional_size = 0x58, 112 + 16 * 8
    struct.pack_into("<HHIIIHH", header, 0x44, machine, 1, 0, 0, 0, optional_size,
                     0x22 | (0x2000 if library else 0))
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<Q", header, optional + 24, 0x140000000)
    struct.pack_into("<I", header, optional + 60, headers)
    struct.pack_into("<I", header, optional + 108, 16)
    struct.pack_into("<II", header, optional + 112 + 8, section, descriptors)
    if delayed:
        struct.pack_into("<II", header, optional + 112 + 13 * 8, section + descriptors, delay)
    struct.pack_into("<8sIIII", header, optional + optional_size, b".idata", len(content), section,
                     len(content), headers)
    return bytes(header) + bytes(content)


def profiles_dat(*users: tuple[bytes, str]) -> bytes:
    data = bytearray(cp.PROFILES_SIZE)
    for slot, (uuid, name) in enumerate(users):
        offset = 0x10 + slot * cp.PROFILE_RECORD
        data[offset:offset + 16] = uuid
        data[offset + 16:offset + 32] = uuid
        data[offset + 0x28:offset + 0x28 + len(name.encode())] = name.encode()
    return bytes(data)


def snapshot(*roots: Path) -> dict[str, tuple[bytes, int] | None]:
    """Every folder, and the content and modification time of every file, below `roots`."""
    state: dict[str, tuple[bytes, int] | None] = {}
    for root in roots:
        for path in sorted(root.rglob("*")):
            state[str(path)] = (path.read_bytes(), path.stat().st_mtime_ns) if path.is_file() else None
    return state


def make_directory_link(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
        return
    raise unittest.SkipTest("cannot create directory links here")


class CampaignFixture(unittest.TestCase):
    """A tester's emulator with its own profile: two users, keys, firmware, a save, a mod and settings
    whose storage paths name that profile."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.top = Path(os.path.realpath(directory.name))
        self.program_dir = self.top / "emulator"
        self.program_dir.mkdir()
        self.exe = self.program_dir / "eglantine.exe"
        self.exe.write_bytes(make_pe(["KERNEL32.dll", "MSVCP140.dll", "api-ms-win-crt-runtime-l1-1-0.dll"]))
        (self.program_dir / "msvcp140.dll").write_bytes(make_pe(["VCRUNTIME140.dll", "KERNEL32.dll"], library=True))
        (self.program_dir / "vcruntime140.dll").write_bytes(make_pe(["KERNEL32.dll"], library=True))
        system = self.top / "windows" / "system32"
        system.mkdir(parents=True)
        (system / "kernel32.dll").write_bytes(b"MZ")
        patcher = mock.patch.object(cp, "_system_directories", return_value=[system])
        patcher.start()
        self.addCleanup(patcher.stop)

        self.user = self.top / "roaming" / "eden"
        self.config_dir = self.user / "config"
        nand = self.user / "nand"
        self.profiles = nand.joinpath(*cp.IDENTITY_PARTS) / "profiles.dat"
        self.profiles.parent.mkdir(parents=True)
        self.profiles.write_bytes(profiles_dat((HOST, "Host"), (GUEST, "Guest")))
        (self.user / "keys").mkdir()
        (self.user / "keys" / "prod.keys").write_text("prod")
        (self.user / "keys" / "title.keys").write_text("title")
        firmware = nand.joinpath(*cp.FIRMWARE_PARTS) / "a.nca"
        firmware.mkdir(parents=True)
        (firmware / "00").write_bytes(b"firmware")
        self.personal_save = nand / "user" / "save" / "0000000000000000" / "6A0303247EF168620D0F2A94F4D8CF4B" / TITLE / "data.bin"
        self.personal_save.parent.mkdir(parents=True)
        self.personal_save.write_bytes(b"personal")
        mod = self.user / "load" / TITLE / "personal-mod" / "exefs"
        mod.mkdir(parents=True)
        (mod / "main.pchtxt").write_text("personal")
        (self.user / "certs").mkdir()
        (self.user / "certs" / CA_NAME).write_bytes(b"ca")
        (self.top / "games").mkdir()
        self.config_dir.mkdir()
        (self.config_dir / "qt-config.ini").write_bytes((
            "[Controls]\r\nplayer_0_type=0\r\n\r\n"
            "[Data%20Storage]\r\n"
            f"nand_directory\\default=false\r\nnand_directory={nand.as_posix()}\r\n"
            f"load_directory\\default=false\r\nload_directory={(self.user / 'load').as_posix()}\r\n"
            "save_directory\\default=true\r\nsave_directory=\r\n\r\n"
            f"[Services]\r\nprivate_server_ca={(self.user / 'certs' / CA_NAME).as_posix()}\r\n\r\n"
            "[System]\r\ncurrent_user\\default=false\r\ncurrent_user=1\r\n\r\n"
            f"[UI]\r\nScreenshots\\screenshot_path={(self.user / 'screenshots').as_posix()}\r\n"
            f"Paths\\gamedirs\\1\\path={(self.top / 'games').as_posix()}\r\n").encode())
        self.base = self.top / "launcher" / "campaigns"

    def source(self) -> cp.SourceProfile:
        return cp.read_source_profile(self.exe, self.user, self.config_dir)

    def create(self) -> cp.PreparedCampaign:
        return cp.create_campaign(self.base, "spring", self.source())


class CreateCampaignTest(CampaignFixture):
    def test_creates_a_separate_copy_and_leaves_the_profile_unchanged(self) -> None:
        before = snapshot(self.user, self.program_dir)
        prepared = self.create()
        self.assertEqual(snapshot(self.user, self.program_dir), before)
        profile = prepared.profile
        self.assertTrue(prepared.created)
        self.assertEqual(profile.root, self.base / "spring")
        self.assertEqual(cp.list_campaigns(self.base), ["spring"])
        self.assertEqual(cp.open_campaign(self.base, "spring"), profile)

        # Local saves and the normal private-server game-user namespace use distinct stable UUIDs.
        self.assertEqual([user.name for user in prepared.identity], ["Host", "Guest"])
        self.assertEqual(prepared.current_user, prepared.identity[1])
        campaign_users = cp.read_identity(profile.nand_dir)
        self.assertEqual([user.name for user in campaign_users], ["Host", "Guest"])
        self.assertEqual([profile.campaign_user(user) for user in prepared.identity], list(campaign_users))
        self.assertTrue({cp._private_account_id(user.uuid) for user in prepared.identity}.isdisjoint(
            cp._private_account_id(user.uuid) for user in campaign_users))

        # Keys, firmware and certificates are copied; saves and mods are not.
        self.assertTrue(prepared.keys)
        self.assertTrue(prepared.firmware)
        self.assertEqual((profile.keys_dir / "title.keys").read_text(), "title")
        self.assertEqual((profile.firmware_dir / "a.nca" / "00").read_bytes(), b"firmware")
        self.assertEqual((profile.certs_dir / CA_NAME).read_bytes(), b"ca")
        self.assertEqual(list(profile.save_dir.iterdir()), [])
        self.assertEqual(list(profile.load_dir.iterdir()), [])

        # The settings are kept, but every place the emulator writes to is the campaign's.
        text = (profile.config_dir / "qt-config.ini").read_bytes().decode()
        for key, path in (("nand_directory", profile.nand_dir), ("sdmc_directory", profile.sdmc_dir),
                          ("load_directory", profile.load_dir), ("dump_directory", profile.dump_dir),
                          ("tas_directory", profile.tas_dir)):
            self.assertEqual(Path(cp._ini_value(text, cp.DATA_STORAGE, key)), path)
        self.assertEqual(cp._ini_value(text, cp.DATA_STORAGE, "save_directory"), "")
        self.assertEqual(Path(cp._ini_value(text, "UI", cp.SCREENSHOT_KEY)), profile.screenshots_dir)
        self.assertEqual(Path(cp._ini_value(text, "Services", "private_server_ca")), profile.certs_dir / CA_NAME)
        self.assertEqual(Path(cp._ini_value(text, "UI", "Paths\\gamedirs\\1\\path")), self.top / "games")
        self.assertIn("[Controls]\r\nplayer_0_type=0\r\n", text)
        self.assertNotIn(self.user.as_posix(), text)

        if os.name == "nt":
            self.assertEqual(profile.executable, profile.root / "eglantine.exe")
            self.assertEqual(profile.executable.read_bytes(), self.exe.read_bytes())
            self.assertEqual(prepared.dependencies, ("msvcp140.dll", "vcruntime140.dll"))
            self.assertEqual(prepared.system_dependencies, ("KERNEL32.dll",))
        else:
            self.assertEqual(profile.executable, self.exe)
        game = self.top / "games" / "game.nsp"
        self.assertEqual(profile.command(game), [str(profile.executable), "-g", str(game)])
        self.assertEqual(profile.working_directory, profile.root)
        cp.verify_isolation(profile)

    def test_campaign_avatar_follows_its_remapped_user(self) -> None:
        original_avatar = self.profiles.parent / f"{uuid.UUID(bytes=HOST)}.jpg"
        original_avatar.write_bytes(b"avatar")
        prepared = self.create()
        campaign_user = prepared.profile.campaign_user(prepared.identity[0])
        avatar = prepared.profile.identity_dir / f"{uuid.UUID(hex=campaign_user.uuid)}.jpg"
        self.assertEqual(avatar.read_bytes(), b"avatar")
        self.assertFalse((prepared.profile.identity_dir / original_avatar.name).exists())

    def test_an_existing_campaign_is_not_created_again(self) -> None:
        self.create()
        with self.assertRaisesRegex(cp.CampaignProfileError, "already exists"):
            self.create()

    def test_refuses_dangerous_locations_and_names(self) -> None:
        source = self.source()
        cases = [(self.user / "campaigns", "spring"),  # inside the tester's profile
                 (self.program_dir, "user"),           # would become the emulator's portable profile
                 (self.top, "emulator"),               # the emulator's own folder
                 (Path("relative"), "spring")]
        if os.name == "nt":
            cases.append((Path("\\\\server\\share\\campaigns"), "spring"))
        for base, name in cases:
            with self.subTest(base=base, name=name), self.assertRaises(cp.UnsafePathError):
                cp.create_campaign(base, name, source)
        self.assertFalse((self.program_dir / "user").exists())
        self.assertFalse((self.user / "campaigns").exists())
        for name in ("", ".hidden", "../up", "a/b", "a b", "CON", "nul", "x" * 49, 7):
            with self.subTest(name=name), self.assertRaises(cp.UnsafePathError):
                cp.create_campaign(self.base, name, source)
        self.assertFalse(self.base.exists())

        occupied = self.base / "taken"
        occupied.mkdir(parents=True)
        (occupied / "notes.txt").write_text("mine")
        with self.assertRaisesRegex(cp.UnsafePathError, "not a campaign"):
            cp.prepare_campaign(self.base, "taken", source)
        self.assertEqual([path.name for path in occupied.iterdir()], ["notes.txt"])

    def test_a_profile_without_a_user_is_refused_before_anything_is_written(self) -> None:
        self.profiles.unlink()
        with self.assertRaisesRegex(cp.IdentityError, "creates its user"):
            self.create()
        self.assertFalse(self.base.exists())

    def test_failed_or_interrupted_creation_leaves_no_usable_campaign(self) -> None:
        with mock.patch.object(cp, "_mirror_tree", side_effect=RuntimeError("disk full")), \
                self.assertRaisesRegex(RuntimeError, "disk full"):
            self.create()
        self.assertFalse((self.base / "spring").exists())

        root = self.base / "spring"
        root.mkdir()
        (root / cp.CREATING_MARKER).write_text("incomplete\n")
        (root / "junk.bin").write_bytes(b"junk")
        self.assertEqual(cp.list_campaigns(self.base), [])
        prepared = cp.prepare_campaign(self.base, "spring", self.source())
        self.assertTrue(prepared.created)
        self.assertFalse((root / "junk.bin").exists())
        self.assertFalse((root / cp.CREATING_MARKER).exists())


class SeedCampaignTest(CampaignFixture):
    def test_import_is_independent_and_never_overwrites_campaign_progress(self) -> None:
        prepared = self.create()
        original = self.personal_save.read_bytes()
        destination = cp.seed_campaign_save(prepared.profile, self.source(), TITLE, prepared.identity[0])
        self.assertEqual(destination, prepared.profile.account_save_dir(
            TITLE, prepared.profile.campaign_user(prepared.identity[0])))
        copy = destination / "data.bin"
        self.assertEqual(copy.read_bytes(), original)
        copy.write_bytes(b"campaign progress")
        self.assertEqual(self.personal_save.read_bytes(), original)
        with self.assertRaisesRegex(cp.CampaignProfileError, "already has a save"):
            cp.seed_campaign_save(prepared.profile, self.source(), TITLE, prepared.identity[0])
        self.assertEqual(copy.read_bytes(), b"campaign progress")

    def test_missing_source_save_is_not_created_as_a_new_game(self) -> None:
        prepared = self.create()
        with self.assertRaisesRegex(cp.CampaignProfileError, "No supported save"):
            cp.seed_campaign_save(prepared.profile, self.source(), TITLE, prepared.identity[1])
        self.assertFalse(prepared.profile.account_save_dir(
            TITLE, prepared.profile.campaign_user(prepared.identity[1])).exists())

    def test_newer_save_layout_takes_precedence_when_both_exist(self) -> None:
        prepared = self.create()
        user = prepared.identity[0]
        future = self.source().save_dir / "user" / "save" / "account" / user.uuid.lower() / TITLE / "0"
        future.mkdir(parents=True)
        (future / "data.bin").write_bytes(b"new layout")
        destination = cp.seed_campaign_save(prepared.profile, self.source(), TITLE, user)
        campaign_user = prepared.profile.campaign_user(user)
        self.assertEqual(destination, prepared.profile.save_dir / "account" / campaign_user.uuid / TITLE / "0")
        self.assertEqual((destination / "data.bin").read_bytes(), b"new layout")
        self.assertFalse(prepared.profile.account_save_dir(TITLE, campaign_user).exists())
        self.assertEqual(self.personal_save.read_bytes(), b"personal")

    @unittest.skipUnless(os.name == "nt", "Windows executable sharing check")
    def test_import_refuses_when_original_process_state_cannot_be_checked(self) -> None:
        prepared = self.create()
        source = self.source()
        original_open = Path.open

        def deny_program(path: Path, *args: object, **kwargs: object):
            if path == self.exe and args and args[0] == "r+b":
                raise PermissionError("access denied")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", deny_program):
            with self.assertRaisesRegex(cp.CampaignProfileError, "Cannot verify"):
                cp.seed_campaign_save(prepared.profile, source, TITLE, prepared.identity[0])
        self.assertFalse(prepared.profile.account_save_dir(
            TITLE, prepared.profile.campaign_user(prepared.identity[0])).exists())
        self.assertEqual(self.personal_save.read_bytes(), b"personal")

    def test_unsupported_process_check_does_not_assume_emulator_is_stopped(self) -> None:
        with mock.patch.object(cp.os, "name", "posix"):
            with self.assertRaisesRegex(cp.CampaignProfileError, "Cannot verify"):
                cp._in_use(self.exe)


class PrepareCampaignTest(CampaignFixture):
    def test_restores_isolation_and_identity_and_keeps_campaign_saves(self) -> None:
        prepared = self.create()
        profile = prepared.profile
        campaign_user = profile.campaign_user(prepared.identity[0])
        save = profile.account_save_dir(TITLE, campaign_user) / "data.bin"
        save.parent.mkdir(parents=True)
        save.write_bytes(b"campaign")
        ini = profile.config_dir / "qt-config.ini"
        ini.write_bytes(ini.read_bytes().replace(profile.nand_dir.as_posix().encode(),
                                                 (self.user / "nand").as_posix().encode()))
        with self.assertRaisesRegex(cp.IsolationError, "nand_directory"):
            cp.verify_isolation(profile)
        identity_before = (profile.identity_dir / "profiles.dat").read_bytes()
        changed = profile.identity_dir / "profiles.dat"
        changed.write_bytes(profiles_dat((GUEST, "Other")))
        os.utime(changed, ns=(1_000_000_000, 1_000_000_000))
        (self.user / "keys" / "prod.keys").write_text("new prod keys")

        before = snapshot(self.user, self.program_dir)
        prepared = cp.prepare_campaign(self.base, "spring", self.source())
        self.assertEqual(snapshot(self.user, self.program_dir), before)
        self.assertFalse(prepared.created)
        self.assertEqual(save.read_bytes(), b"campaign")
        self.assertEqual(changed.read_bytes(), identity_before)
        self.assertEqual(prepared.profile.campaign_user(prepared.identity[0]), campaign_user)
        self.assertEqual((profile.keys_dir / "prod.keys").read_text(), "new prod keys")
        self.assertIn("user/keys/prod.keys", prepared.updated)
        text = ini.read_bytes().decode()
        self.assertEqual(Path(cp._ini_value(text, cp.DATA_STORAGE, "nand_directory")), profile.nand_dir)
        cp.verify_isolation(profile)

    def test_refuses_reused_personal_identity(self) -> None:
        prepared = self.create()
        (prepared.profile.identity_dir / "profiles.dat").write_bytes(self.profiles.read_bytes())
        with self.assertRaisesRegex(cp.IsolationError, "user identities"):
            cp.verify_isolation(prepared.profile)
        with self.assertRaises(cp.IsolationError):
            cp.seed_campaign_save(prepared.profile, self.source(), TITLE, prepared.identity[0])
        self.assertEqual(self.personal_save.read_bytes(), b"personal")

    def test_changed_source_users_cannot_replace_existing_campaign_identities(self) -> None:
        prepared = self.create()
        cp.seed_campaign_save(prepared.profile, self.source(), TITLE, prepared.identity[0])
        before = snapshot(prepared.profile.root)
        self.profiles.write_bytes(profiles_dat((HOST, "Host")))
        with self.assertRaisesRegex(cp.IdentityError, "users changed"):
            cp.prepare_campaign(self.base, "spring", self.source())
        self.assertEqual(snapshot(prepared.profile.root), before)
        cp.verify_isolation(prepared.profile)

    def test_refuses_a_campaign_that_lost_its_profile_or_links_out(self) -> None:
        profile = self.create().profile
        moved = profile.root / "moved"
        profile.user_dir.rename(moved)
        with self.assertRaisesRegex(cp.IsolationError, "missing"):
            cp.verify_isolation(profile)
        moved.rename(profile.user_dir)
        cp.verify_isolation(profile)

        link = profile.save_dir / "0000000000000000"
        make_directory_link(self.personal_save.parents[2], link)
        self.addCleanup(lambda: os.rmdir(link) if os.name == "nt" else os.unlink(link))
        with self.assertRaisesRegex(cp.IsolationError, "is a link"):
            cp.verify_isolation(profile)
        before = snapshot(self.user)
        with self.assertRaisesRegex(cp.IsolationError, "nothing was changed"):
            cp.prepare_campaign(self.base, "spring", self.source())
        self.assertEqual(snapshot(self.user), before)

    def test_refuses_a_hard_link_to_your_save(self) -> None:
        profile = self.create().profile
        linked = profile.save_dir / "linked.bin"
        try:
            os.link(self.personal_save, linked)
        except OSError:
            self.skipTest("hard links are not supported here")
        with self.assertRaisesRegex(cp.IsolationError, "hard link"):
            cp.verify_isolation(profile)

    def test_another_profile_replaces_the_identity_only_when_asked(self) -> None:
        self.create()
        other = self.top / "portable" / "user"
        shutil.copytree(self.user, other)
        source = cp.read_source_profile(self.exe, other, other / "config")
        with self.assertRaisesRegex(cp.IdentityError, "was copied from"):
            cp.prepare_campaign(self.base, "spring", source)
        prepared = cp.prepare_campaign(self.base, "spring", source, rebind_source=True)
        self.assertEqual(prepared.profile.source_user_dir, other)
        self.assertEqual(cp.open_campaign(self.base, "spring").source_user_dir, other)


class InstallModTest(CampaignFixture):
    def test_installs_only_into_the_campaign_mod_tree(self) -> None:
        profile = self.create().profile
        mod = self.top / "quest-sync"
        (mod / "exefs").mkdir(parents=True)
        (mod / "exefs" / "main.pchtxt").write_text("patch 1")
        target = cp.install_mod(profile, TITLE.lower(), "quest-sync", mod)
        self.assertEqual(target, profile.mod_dir(TITLE, "quest-sync"))
        self.assertEqual(target, profile.load_dir / TITLE / "quest-sync")
        self.assertEqual((target / "exefs" / "main.pchtxt").read_text(), "patch 1")
        self.assertFalse((self.user / "load" / TITLE / "quest-sync").exists())

        with self.assertRaisesRegex(cp.CampaignProfileError, "already has"):
            cp.install_mod(profile, TITLE, "quest-sync", mod)
        (mod / "exefs" / "main.pchtxt").write_text("patch 2, longer")
        cp.install_mod(profile, TITLE, "quest-sync", mod, replace=True)
        self.assertEqual((target / "exefs" / "main.pchtxt").read_text(), "patch 2, longer")

        with self.assertRaisesRegex(cp.CampaignProfileError, "update"):
            cp.install_mod(profile, "0100000000010800", "other", mod)
        with self.assertRaises(cp.UnsafePathError):
            cp.install_mod(profile, TITLE, "other", profile.load_dir)
        (mod / "readme.txt").write_text("notes")
        with self.assertRaisesRegex(cp.CampaignProfileError, "readme.txt"):
            cp.install_mod(profile, TITLE, "other", mod)
        self.assertFalse((profile.load_dir / TITLE / "other").exists())


@unittest.skipUnless(os.name == "nt", "only Windows campaigns run their own copy of the program")
class WindowsProgramTest(CampaignFixture):
    def test_a_missing_dll_is_refused_before_anything_is_written(self) -> None:
        self.exe.write_bytes(make_pe(["KERNEL32.dll", "MSVCP140.dll", "missing.dll"]))
        with self.assertRaisesRegex(cp.DependencyError, "missing.dll"):
            self.create()
        self.assertFalse(self.base.exists())

    def test_a_missing_visual_cpp_runtime_names_the_redistributable(self) -> None:
        (self.program_dir / "msvcp140.dll").unlink()
        with self.assertRaisesRegex(cp.DependencyError, re.escape(cp.VC_REDIST_URL)):
            self.create()

    def test_a_dll_for_another_processor_is_refused(self) -> None:
        (self.program_dir / "vcruntime140.dll").write_bytes(make_pe(["KERNEL32.dll"], machine=0x14C, library=True))
        with self.assertRaisesRegex(cp.DependencyError, "x86"):
            self.create()

    def test_refresh_follows_the_dlls_of_a_new_build(self) -> None:
        profile = self.create().profile
        (self.program_dir / "extra.dll").write_bytes(make_pe([], library=True))
        prepared = cp.prepare_campaign(self.base, "spring", self.source())
        self.assertIn("extra.dll", prepared.dependencies)
        self.assertTrue((profile.root / "extra.dll").is_file())
        (self.program_dir / "extra.dll").unlink()
        cp.prepare_campaign(self.base, "spring", self.source())
        self.assertFalse((profile.root / "extra.dll").exists())
        self.assertTrue((profile.root / "msvcp140.dll").is_file())

    def test_a_campaign_without_its_own_program_is_not_used(self) -> None:
        profile = self.create().profile
        profile.executable.unlink()
        with self.assertRaisesRegex(cp.IsolationError, "own emulator"):
            cp.verify_isolation(profile)


class ProgramImageTest(unittest.TestCase):
    def test_reads_imports_and_delay_loaded_dlls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "library.dll"
            path.write_bytes(make_pe(["KERNEL32.dll", "MSVCP140.dll"], delayed=["d3d12.dll"], library=True))
            image = cp.read_program_image(path)
        self.assertEqual(image, cp.ProgramImage(0x8664, True, ("KERNEL32.dll", "MSVCP140.dll", "d3d12.dll")))

    def test_rejects_a_file_that_is_not_a_program(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eglantine.exe"
            path.write_bytes(b"#!/bin/sh\n")
            with self.assertRaises(cp.DependencyError):
                cp.read_program_image(path)


if __name__ == "__main__":
    unittest.main()
