"""Regression tests for how the launcher sets up a tester's emulator: it changes only the settings it
needs, never without consent, and only in the emulator's own profile."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import launcher

SETTINGS = {"custom_dns_redirect_enabled\\default": "false", "custom_dns_redirect_enabled": "true",
            "custom_dns_redirect_domains": '"npln.srv.nintendo.net,npln.nintendo.net"'}
RELAY = "192.0.2.10:3478,49170-49233"


class UpdateIniTest(unittest.TestCase):
    def test_changes_only_the_given_keys_of_the_section(self) -> None:
        text = ("[UI]\r\ncustom_dns_redirect_enabled=false\r\n\r\n[Services]\r\nnetwork_interface=Wi-Fi\r\n"
                "Custom_DNS_Redirect_Enabled = false\r\n\r\n[Core]\r\nuse_multi_core=true\r\n")
        updated, changes = launcher.update_ini(text, "Services", SETTINGS)
        self.assertEqual(updated, (
            "[UI]\r\ncustom_dns_redirect_enabled=false\r\n\r\n[Services]\r\nnetwork_interface=Wi-Fi\r\n"
            "custom_dns_redirect_enabled=true\r\ncustom_dns_redirect_enabled\\default=false\r\n"
            "custom_dns_redirect_domains=\"npln.srv.nintendo.net,npln.nintendo.net\"\r\n\r\n"
            "[Core]\r\nuse_multi_core=true\r\n"))
        self.assertEqual(len(changes), 3)

    def test_values_the_emulator_reads_the_same_are_left_alone(self) -> None:
        text = ("[Services]\ncustom_dns_redirect_enabled\\default=false\ncustom_dns_redirect_enabled=TRUE\n"
                "custom_dns_redirect_domains=npln.srv.nintendo.net,npln.nintendo.net\n")
        self.assertEqual(launcher.update_ini(text, "Services", SETTINGS), (text, []))

    def test_adds_a_missing_section(self) -> None:
        updated, _ = launcher.update_ini("[Core]\nuse_multi_core=true\n", "Services", SETTINGS)
        self.assertEqual(updated, "[Core]\nuse_multi_core=true\n\n[Services]\n"
                                  "custom_dns_redirect_enabled\\default=false\ncustom_dns_redirect_enabled=true\n"
                                  "custom_dns_redirect_domains=\"npln.srv.nintendo.net,npln.nintendo.net\"\n")


class ConfigureUserDirTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name) / "home"
        self.user_dir = Path(directory.name) / "emulator" / "user"
        self.user_dir.mkdir(parents=True)
        self.ini = self.user_dir / "config" / "qt-config.ini"

    def test_new_profile_gets_the_ca_and_the_settings(self) -> None:
        launcher.configure_user_dir(self.home, self.user_dir, RELAY)
        ca = self.user_dir / "certs" / launcher.GATEWAY_CA_NAME
        self.assertEqual(ca.read_bytes(), (self.home / "gateway-ca.der").read_bytes())
        text = self.ini.read_text("utf-8")
        self.assertIn("airplane_mode=false\n", text)
        self.assertIn(f"private_server_ca={launcher.ini_string(str(ca.resolve()))}\n", text)
        self.assertIn(f"private_server_relay={launcher.ini_string(RELAY)}\n", text)
        self.assertEqual(launcher.update_ini(text, "Services", launcher.emulator_settings(ca, RELAY))[1], [])

    def test_existing_settings_change_only_with_consent_and_are_kept(self) -> None:
        self.ini.parent.mkdir()
        original = b"[Services]\r\ncustom_dns_redirect_address=127.0.0.2\r\n[Core]\r\nspeed_limit=100\r\n"
        self.ini.write_bytes(original)
        with mock.patch.object(launcher, "ask", return_value=False), self.assertRaises(SystemExit):
            launcher.configure_user_dir(self.home, self.user_dir, RELAY)
        self.assertEqual(self.ini.read_bytes(), original)
        self.assertEqual(list(self.ini.parent.iterdir()), [self.ini])

        with mock.patch.object(launcher, "ask", return_value=True):
            launcher.configure_user_dir(self.home, self.user_dir, RELAY)
        backups = [path for path in self.ini.parent.iterdir() if path != self.ini]
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        text = self.ini.read_bytes().decode()
        self.assertTrue(text.endswith("[Core]\r\nspeed_limit=100\r\n"))

        with mock.patch.object(launcher, "ask", side_effect=AssertionError("asked again")):
            launcher.configure_user_dir(self.home, self.user_dir, RELAY)


class RelayConfigTest(unittest.TestCase):
    def test_valid_and_invalid_relay_policies(self) -> None:
        self.assertEqual(launcher.choose_relay(RELAY), RELAY)
        for relay in ("example.org:3478", "192.0.2.10:0", "192.0.2.10:500-400",
                      "192.0.2.10:3478,65536", "192.0.2.10:3478,",
                      "192.0.2.10:03478", "224.0.0.1:3478"):
            with self.subTest(relay=relay), self.assertRaises(SystemExit):
                launcher.choose_relay(relay)

    def test_missing_relay_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(launcher.sys, "_MEIPASS", directory, create=True):
            with self.assertRaisesRegex(SystemExit, "No relay configured"):
                launcher.choose_relay(None)


class KeysAndFirmwareTest(unittest.TestCase):
    def test_copies_keys_and_firmware_without_changing_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "appdata" / "eden"
            (source / "keys").mkdir(parents=True)
            (source / "keys" / "prod.keys").write_text("prod")
            (source / "keys" / "title.keys").write_text("title")
            firmware = source / "nand" / "system" / "Contents" / "registered"
            (firmware / "a.nca").mkdir(parents=True)
            (firmware / "a.nca" / "00").write_bytes(b"part")
            (source / "nand" / "user" / "save").mkdir(parents=True)
            user_dir = Path(directory) / "emulator" / "user"
            user_dir.mkdir(parents=True)
            variable = "APPDATA" if os.name == "nt" else "XDG_DATA_HOME"
            with mock.patch.dict(os.environ, {variable: str(source.parent)}), \
                    mock.patch.object(launcher, "ask", return_value=True):
                launcher.import_keys_and_firmware(user_dir)
            self.assertEqual((user_dir / "keys" / "prod.keys").read_text(), "prod")
            self.assertEqual((user_dir / "keys" / "title.keys").read_text(), "title")
            self.assertEqual((user_dir / "nand" / "system" / "Contents" / "registered" / "a.nca" / "00")
                             .read_bytes(), b"part")
            self.assertFalse((user_dir / "nand" / "user").exists())
            self.assertEqual(sorted(path.name for path in (source / "keys").iterdir()), ["prod.keys", "title.keys"])


class ExistingProfileTest(unittest.TestCase):
    def test_prefers_existing_portable_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exe = root / "eglantine"
            (root / "user").mkdir()
            self.assertEqual(launcher.emulator_profile(exe), (root / "user", root / "user" / "config"))

    def test_global_profile_does_not_create_portable_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exe = root / "program" / "eglantine"
            env = ({"APPDATA": str(root / "data")} if os.name == "nt" else
                   {"XDG_DATA_HOME": str(root / "data"), "XDG_CONFIG_HOME": str(root / "config")})
            with mock.patch.dict(os.environ, env):
                data, config = launcher.emulator_profile(exe)
            self.assertEqual(data, root / "data" / "eden")
            self.assertEqual(config, (data / "config" if os.name == "nt" else root / "config" / "eden"))
            self.assertFalse((exe.parent / "user").exists())

    @unittest.skipIf(os.name == "nt", "Windows may not permit creating unprivileged symbolic links")
    def test_replacement_reuses_portable_saves_without_copying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, new = root / "old" / "eglantine", root / "new" / "eglantine"
            (old.parent / "user").mkdir(parents=True)
            new.parent.mkdir()
            (old.parent / "user" / "save.bin").write_bytes(b"progress")
            launcher.reuse_portable_profile(old, new)
            profile, _ = launcher.emulator_profile(new)
            self.assertTrue(profile.samefile(old.parent / "user"))
            self.assertEqual((profile / "save.bin").read_bytes(), b"progress")

    def test_replacement_never_overwrites_another_portable_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, new = root / "old" / "eglantine", root / "new" / "eglantine"
            (old.parent / "user").mkdir(parents=True)
            (new.parent / "user").mkdir(parents=True)
            (new.parent / "user" / "save.bin").write_bytes(b"other profile")
            with self.assertRaisesRegex(SystemExit, "different profile"):
                launcher.reuse_portable_profile(old, new)
            self.assertEqual((new.parent / "user" / "save.bin").read_bytes(), b"other profile")


class MacBundleTest(unittest.TestCase):
    def test_finds_bundle_and_keeps_profile_outside_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            executable = package / "eglantine.app" / "Contents" / "MacOS" / "eglantine"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"test")
            with mock.patch.object(launcher.sys, "platform", "darwin"):
                selected = launcher.find_emulator(package / "eglantine.app", {})
                self.assertEqual(selected, executable.resolve())
                self.assertTrue(launcher.emulator_directory(selected).samefile(package))


class CheckEmulatorTest(unittest.TestCase):
    def check(self, content: bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "eglantine.exe"
            exe.write_bytes(content)
            launcher.check_emulator(exe)

    def test_compatible_build_passes(self) -> None:
        self.check(b"MZ" + b"\0".join(launcher.EMULATOR_FEATURES))

    def test_build_without_a_feature_is_refused(self) -> None:
        markers = list(launcher.EMULATOR_FEATURES)
        with self.assertRaisesRegex(SystemExit, "private-server account token"):
            self.check(b"MZ" + b"\0".join(markers[:-1]))

    def test_local_only_build_is_refused(self) -> None:
        with self.assertRaisesRegex(SystemExit, "local-only"):
            self.check(b"MZ" + b"\0".join(launcher.EMULATOR_FEATURES) + launcher.LOCAL_ONLY_BUILD)


if __name__ == "__main__":
    unittest.main()
