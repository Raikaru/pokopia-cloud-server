#!/usr/bin/env python3
"""Isolated campaign emulator profiles for story-map co-op.

A campaign is a separately named copy of the tester's emulator setup, in its own directory. The game
keeps its campaign saves and loads its campaign mods only there. Each source user is mapped to a
different, stable campaign UUID so normal play uses a different private-server game-user namespace.
The device certificate still belongs to the same server account; it is not an authorization boundary.
Profile preparation and save or mod changes currently require Windows: on other platforms this module
cannot yet verify that the emulator is stopped and refuses those operations.

  <base>/<name>/                    base: default_campaign_base(<launcher home>) or the caller's choice
    campaign.json                   manifest; a directory without one is never used or written
    eglantine.exe, *.dll            Windows: copies of the emulator and of every DLL next to it
    user/                           the emulator's portable profile
      config/qt-config.ini          copy of the tester's settings; every storage path points here
      keys/                         copy of the decryption keys
      certs/                        copy of the CA certificates the emulator trusts
      nand/system/Contents/registered/                copy of the firmware
      nand/system/save/8000000000000010/su/avators/   user profiles with distinct campaign UUIDs
      nand/user/save/               campaign saves
      load/                         campaign mods
      sdmc/ dump/ tas/ screenshots/ (and log/ and cache/, which the emulator creates)

Why the campaign stays apart from the tester's profile:
- On Windows the emulator uses <folder of its .exe>/user if that is a directory and otherwise
  %APPDATA%/eden (Reinitialize in common/fs/path_util.cpp). The campaign therefore runs its own copy
  of the program. Elsewhere it uses ./user, so the campaign runs the tester's program with the
  campaign directory as its working directory.
- The emulator stores absolute NAND, SD card, mod, dump and TAS paths in qt-config.ini and reads them
  back (Config::ReadDataStorageValues). A copied config would send campaign saves to the tester's
  NAND, so these paths, and the screenshot path, are set to the campaign every time it is prepared.
- When its config directory is missing, the emulator offers to move or link another emulator's data
  (UserDataMigrator). A campaign always has a config directory.
- The private-server account token's subject is a hash of the profile UUID in profiles.dat
  (PrivateAccountId in core/hle/service/acc/acc.cpp). A stable, distinct UUID for each source user
  separates their normal campaign game-user namespace. The launcher's device certificate still
  names the same server account and may authorize access to that account's other game users.

Every write made by this module is checked to land inside the campaign directory, and is refused if a
symbolic link, junction or hard link inside the campaign could carry it elsewhere. verify_isolation()
repeats these checks, and those of the configured paths, and must pass before each launch. Functions
raise CampaignProfileError (or a subclass) for anything the tester has to fix, and OSError for I/O
failures.
"""

from __future__ import annotations

import codecs
import contextlib
import datetime
import json
import mmap
import os
import re
import secrets
import shutil
import stat
import struct
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Sequence

__all__ = [
    "CampaignProfile", "CampaignProfileError", "DependencyError", "IdentityError", "IdentityUser",
    "IsolationError", "PreparedCampaign", "ProgramImage", "SourceProfile", "UnsafePathError",
    "campaign_root", "check_campaign_name", "check_title_id", "create_campaign",
    "default_campaign_base", "install_mod", "list_campaigns", "open_campaign", "prepare_campaign",
    "read_identity", "read_program_image", "read_source_profile", "seed_campaign_save", "verify_isolation",
]

FORMAT = 2
MANIFEST_NAME = "campaign.json"
# Present while a campaign is being created; such a directory is rebuilt, never launched.
CREATING_MARKER = "campaign.creating"
PORTABLE_DIR = "user"
CONFIG_NAME = "qt-config.ini"
# Emulators of the same family keep their profiles under these names (launcher.KEY_SOURCE_PROFILES).
FAMILY_PROFILES = ("eden", "yuzu", "citron", "suyu", "sudachi")
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}")
TITLE_ID_PATTERN = re.compile(r"[0-9A-Fa-f]{16}")
RESERVED_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} |
                           {f"COM{number}" for number in range(10)} |
                           {f"LPT{number}" for number in range(10)})
# GetModuleFileNameW, which the emulator uses to find its portable profile, cuts paths at MAX_PATH;
# a cut path would make it use %APPDATA%/eden. The limit also leaves room for the deepest save paths.
WINDOWS_MAX_PATH = 260
MAX_ROOT_CHARS = 140
SAFE_DRIVE_TYPES = (2, 3, 6)  # DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_RAMDISK
# As launcher.INI_SPECIAL_CHARACTERS: the emulator quotes values containing these.
INI_SPECIAL_CHARACTERS = "!#$%^&*|;'\",<>?`~="
DATA_STORAGE = "Data%20Storage"
STORAGE_KEYS = ("nand_directory", "sdmc_directory", "load_directory", "dump_directory", "tas_directory")
SAVE_KEY = "save_directory"
SCREENSHOT_KEY = "Screenshots\\screenshot_path"
IDENTITY_PARTS = ("system", "save", "8000000000000010", "su", "avators")
FIRMWARE_PARTS = ("system", "Contents", "registered")
INSTALLED_PARTS = ("user", "Contents", "registered")       # games, updates and DLC in the NAND
# On the SD card: registered content, and the private file that with the NAND system save
# 8000000000000043 makes the SD seed that dumped SD content is encrypted with (DeriveSDSeed).
SD_CONTENTS_PARTS = ("Nintendo", "Contents")
SD_SEED_PARTS = ("system", "save", "8000000000000043")
ACCOUNT_SAVES = "0000000000000000"
PROFILES_NAME = "profiles.dat"
PROFILES_SIZE = 0x650  # ProfileDataRaw: 0x10 bytes, then 8 records of 0xC8 bytes
PROFILE_RECORD = 0xC8
MAX_USERS = 8
# Mod folders the emulator reads (core/file_sys/patch_manager.cpp).
MOD_PARTS = ("exefs", "romfs", "romfs_ext", "cheats")
# Folders a dynamically linked Qt build loads plugins and translations from at run time.
QT_RUNTIME_DIRS = ("platforms", "styles", "imageformats", "iconengines", "tls", "networkinformation",
                   "generic", "platforminputcontexts", "multimedia", "translations")
QT_CONF = "qt.conf"
API_SET_PREFIXES = ("api-ms-", "ext-ms-")
VC_RUNTIME_PREFIXES = ("msvcp", "vcruntime", "concrt", "vccorlib")
VC_REDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}
PROGRAM_MACHINES = (0x8664, 0xAA64)
MAX_IMPORTS = 4096
COPY_CHUNK = 1 << 20


class CampaignProfileError(Exception):
    """The campaign cannot be created, prepared or used as asked. The tester's profile is unchanged."""


class UnsafePathError(CampaignProfileError):
    """The campaign name or location is invalid or could reach the tester's own data."""


class IsolationError(CampaignProfileError):
    """The campaign directory is not, or would no longer be, separate from the tester's data."""


class DependencyError(CampaignProfileError):
    """The emulator program, or a DLL it needs, cannot be found or copied for the campaign."""


class IdentityError(CampaignProfileError):
    """The tester's online identity cannot be taken over, or would change."""


@dataclass(frozen=True)
class IdentityUser:
    """A user of the emulator's profiles.dat."""
    index: int  # position in the emulator's user list, as [System] current_user counts
    uuid: str   # the 16 bytes of the UUID as stored, in hexadecimal
    name: str

    @property
    def save_folder(self) -> str:
        """The folder of this user's saves in nand/user/save/0000000000000000 (SaveDataFactory)."""
        raw = bytes.fromhex(self.uuid)
        return f"{int.from_bytes(raw[8:], 'little'):016X}{int.from_bytes(raw[:8], 'little'):016X}"


@dataclass(frozen=True)
class SourceProfile:
    """The tester's own emulator profile, which a campaign is copied from and never writes to.
    Create it with read_source_profile()."""
    emulator: Path
    user_dir: Path
    config_dir: Path
    nand_dir: Path
    sdmc_dir: Path
    load_dir: Path
    dump_dir: Path
    tas_dir: Path
    save_dir: Path

    @property
    def keys_dir(self) -> Path:
        return self.user_dir / "keys"

    @property
    def certs_dir(self) -> Path:
        return self.user_dir / "certs"

    @property
    def identity_dir(self) -> Path:
        return self.nand_dir.joinpath(*IDENTITY_PARTS)

    @property
    def firmware_dir(self) -> Path:
        return self.nand_dir.joinpath(*FIRMWARE_PARTS)

    @property
    def installed_dir(self) -> Path:
        return self.nand_dir.joinpath(*INSTALLED_PARTS)

    @property
    def program_dir(self) -> Path:
        return _program_directory(self.emulator)

    def protected(self) -> tuple[Path, ...]:
        """Everything a campaign must stay out of, including the place where a new directory would
        become the emulator's portable profile instead of its current one."""
        return (self.user_dir, self.config_dir, self.nand_dir, self.sdmc_dir, self.load_dir,
                self.dump_dir, self.tas_dir, self.save_dir, self.program_dir / PORTABLE_DIR)


@dataclass(frozen=True)
class CampaignProfile:
    """The paths of a campaign. Get one from prepare_campaign(), create_campaign() or open_campaign()."""
    name: str
    root: Path
    executable: Path
    source_emulator: Path
    source_user_dir: Path
    source_config_dir: Path

    @property
    def working_directory(self) -> Path:
        """Where the emulator must run. On Windows it equals launcher.emulator_directory(executable);
        elsewhere the emulator finds its profile only from its working directory."""
        return self.root

    @property
    def user_dir(self) -> Path:
        return self.root / PORTABLE_DIR

    @property
    def config_dir(self) -> Path:
        return self.user_dir / "config"

    @property
    def keys_dir(self) -> Path:
        return self.user_dir / "keys"

    @property
    def certs_dir(self) -> Path:
        return self.user_dir / "certs"

    @property
    def nand_dir(self) -> Path:
        return self.user_dir / "nand"

    @property
    def save_dir(self) -> Path:
        return self.nand_dir / "user" / "save"

    @property
    def load_dir(self) -> Path:
        return self.user_dir / "load"

    @property
    def sdmc_dir(self) -> Path:
        return self.user_dir / "sdmc"

    @property
    def dump_dir(self) -> Path:
        return self.user_dir / "dump"

    @property
    def tas_dir(self) -> Path:
        return self.user_dir / "tas"

    @property
    def screenshots_dir(self) -> Path:
        return self.user_dir / "screenshots"

    @property
    def log_dir(self) -> Path:
        return self.user_dir / "log"

    @property
    def identity_dir(self) -> Path:
        return self.nand_dir.joinpath(*IDENTITY_PARTS)

    @property
    def firmware_dir(self) -> Path:
        return self.nand_dir.joinpath(*FIRMWARE_PARTS)

    @property
    def installed_dir(self) -> Path:
        return self.nand_dir.joinpath(*INSTALLED_PARTS)

    def command(self, game: Path | None = None) -> list[str]:
        """The emulator's command line, as launcher.play_session builds it; run it in
        working_directory, and only after verify_isolation() passed."""
        return [str(self.executable)] + (["-g", str(game)] if game else [])

    def mod_dir(self, title_id: str, mod_name: str) -> Path:
        """Where install_mod() puts the mod `mod_name` of the base title `title_id`."""
        return self.load_dir / check_title_id(title_id) / _check_name(mod_name, "mod name")

    def account_save_dir(self, title_id: str, user: IdentityUser) -> Path:
        """The campaign save of `title_id` for `user`."""
        return self.save_dir / ACCOUNT_SAVES / user.save_folder / check_title_id(title_id, base_title=False)

    def campaign_user(self, source_user: IdentityUser) -> IdentityUser:
        """Return the campaign identity corresponding to a user of the source profile."""
        manifest = _read_manifest(self.root, self.name)
        mapped = (manifest or {}).get("identities", {}).get(source_user.uuid)
        if mapped is not None:
            for user in read_identity(self.nand_dir):
                if user.uuid == mapped:
                    return user
        raise IdentityError("The selected source user has no matching campaign identity.")


@dataclass(frozen=True)
class PreparedCampaign:
    """What prepare_campaign() or create_campaign() set up. `identity` and `current_user` identify
    source users for save import; profile.campaign_user() resolves their campaign UUIDs."""
    profile: CampaignProfile
    created: bool
    identity: tuple[IdentityUser, ...]
    current_user: IdentityUser | None  # the user the campaign plays as, or None if not in identity
    keys: bool       # the campaign has prod.keys
    firmware: bool   # the campaign has firmware
    dependencies: tuple[str, ...]         # files and folders copied next to the campaign's program
    system_dependencies: tuple[str, ...]  # DLLs the program loads from the Windows system folder
    updated: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class ProgramImage:
    """What the headers of a Windows program or DLL say."""
    machine: int
    library: bool
    imports: tuple[str, ...]  # imported and delay-loaded DLL names, as written in the file


@dataclass(frozen=True)
class _Program:
    executable: Path
    files: tuple[Path, ...]    # DLLs and qt.conf next to the program
    folders: tuple[Path, ...]  # Qt runtime folders next to the program
    system: tuple[str, ...]


# --- Names and locations -------------------------------------------------------------------------


def default_campaign_base(home: Path) -> Path:
    """Where the launcher keeps campaigns: in its own home, which is private to the user."""
    return Path(home) / "campaigns"


def check_campaign_name(name: str) -> str:
    """Returns `name` if it can name a campaign directory everywhere; raises UnsafePathError."""
    return _check_name(name, "campaign name")


def check_title_id(title_id: str, *, base_title: bool = True) -> str:
    """The title id in the emulator's spelling (16 upper-case hexadecimal digits). With
    `base_title`, refuses update title ids, for which the emulator loads no mods."""
    if not isinstance(title_id, str) or not TITLE_ID_PATTERN.fullmatch(title_id):
        raise CampaignProfileError(f"Invalid title id {title_id!r}: use 16 hexadecimal digits.")
    value = int(title_id, 16)
    if value == 0:
        raise CampaignProfileError("Invalid title id 0000000000000000.")
    if base_title and value & 0xFFF == 0x800:
        raise CampaignProfileError(f"{title_id} is the title id of an update; the emulator loads mods "
                                   f"only for the base title id.")
    return f"{value:016X}"


def campaign_root(base: Path, name: str, source: SourceProfile) -> Path:
    """The directory of campaign `name` in `base`, once it is known to be safe for a campaign copied
    from `source`. Raises UnsafePathError otherwise."""
    name = check_campaign_name(name)
    base = Path(base)
    if not base.is_absolute():
        raise UnsafePathError(f"The campaign folder {base} must be an absolute path.")
    base = Path(os.path.abspath(base))  # drops "..", without touching the file system
    _check_path_text(base)
    root = Path(os.path.realpath(base)) / name
    _check_path_text(root)
    if os.name == "nt" and len(str(root)) > MAX_ROOT_CHARS:
        raise UnsafePathError(f"{root} is too long ({len(str(root))} characters, at most {MAX_ROOT_CHARS}): "
                              f"Windows would cut the path of the campaign's emulator, which would then "
                              f"use your own profile. Choose a shorter folder.")
    for path in (*source.protected(), *_family_roots()):
        if _overlaps(root, path):
            raise UnsafePathError(f"{root} cannot hold a campaign: it overlaps {path}, which belongs to "
                                  f"your own emulator profile or to another emulator's.")
    if _within(source.program_dir, root):
        raise UnsafePathError(f"{root} cannot hold a campaign: it contains the emulator's own folder "
                              f"{source.program_dir}.")
    if _within(Path.home(), root):
        raise UnsafePathError(f"{root} cannot hold a campaign: it contains your home folder.")
    for system in _system_roots():
        if _within(root, system):
            raise UnsafePathError(f"{root} cannot hold a campaign: it is in the system folder {system}.")
    if os.path.lexists(root) and _is_link(os.lstat(root)):
        raise UnsafePathError(f"{root} is a link; a campaign needs a real folder.")
    return root


def _check_name(name: object, what: str) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise UnsafePathError(f"Invalid {what} {name!r}: use 1 to 48 letters, digits, '-' or '_', "
                              f"starting with a letter or digit.")
    if name.upper() in RESERVED_NAMES:
        raise UnsafePathError(f"Invalid {what} {name!r}: Windows reserves it for a device.")
    return name


def _check_path_text(path: Path) -> None:
    text = str(path)
    if any(ord(character) < 32 for character in text):
        raise UnsafePathError(f"{text!r} contains control characters.")
    if os.name != "nt":
        return
    if text.startswith(("\\\\", "//")) or not re.fullmatch(r"[A-Za-z]:", path.drive):
        raise UnsafePathError(f"{path} is a network or device path; use a folder on a local drive.")
    for part in path.parts[1:]:
        if any(character in '<>:"|?*' for character in part) or part != part.rstrip(" ."):
            raise UnsafePathError(f"{path} contains the folder name {part!r}, which Windows cannot use "
                                  f"reliably.")
        if part.split(".", 1)[0].rstrip(" ").upper() in RESERVED_NAMES:
            raise UnsafePathError(f"{path} contains {part!r}, which Windows reserves for a device.")
    import ctypes
    if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(path.anchor)) not in SAFE_DRIVE_TYPES:
        raise UnsafePathError(f"{path} is not on a local drive (network, optical and unknown drives are "
                              f"not supported).")


def _program_directory(exe: Path) -> Path:
    """The folder that holds the emulator's portable profile (as launcher.emulator_directory)."""
    if sys.platform == "darwin" and exe.parent.name == "MacOS" and \
            exe.parent.parent.name == "Contents" and exe.parent.parent.parent.suffix == ".app":
        return exe.parent.parent.parent.parent
    return exe.parent


def _family_roots() -> list[Path]:
    """The standard profiles of every emulator of the family, which a campaign never touches."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return [base / name for name in FAMILY_PROFILES]
    bases = (os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share",
             os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config",
             os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return [Path(base) / name for base in bases for name in FAMILY_PROFILES]


def _system_roots() -> list[Path]:
    if os.name == "nt":
        names = ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData")
        return [Path(os.environ[name]) for name in names if os.environ.get(name)]
    return [Path(path) for path in ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin",
                                    "/sys", "/usr", "/System", "/Library")]


def _canonical(path: Path | str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _within(path: Path | str, root: Path | str) -> bool:
    """Whether `path` is `root` or inside it, after following links."""
    inner, outer = _canonical(path), _canonical(root)
    try:
        return os.path.commonpath([inner, outer]) == outer
    except ValueError:  # different drives
        return False


def _overlaps(a: Path, b: Path) -> bool:
    return _within(a, b) or _within(b, a)


def _is_link(info: os.stat_result) -> bool:
    """Symbolic links, and on Windows also junctions and other reparse points."""
    return stat.S_ISLNK(info.st_mode) or \
        bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


# --- The tester's profile --------------------------------------------------------------------------


def read_source_profile(emulator: Path, user_dir: Path, config_dir: Path) -> SourceProfile:
    """The tester's profile as `emulator` uses it; pass the user and config directories that
    launcher.emulator_profile(emulator) returns. Only reads."""
    emulator = Path(os.path.realpath(emulator))
    if not emulator.is_file():
        raise CampaignProfileError(f"{emulator} does not exist.")
    user_dir = Path(os.path.realpath(user_dir))
    if not user_dir.is_dir():
        raise CampaignProfileError(f"The emulator profile {user_dir} does not exist yet: start the "
                                   f"emulator once so that it creates it, then try again.")
    config_dir = Path(os.path.realpath(config_dir))
    loaded = _read_ini(config_dir / CONFIG_NAME)
    text = loaded[1] if loaded else ""

    def configured(key: str, default: Path) -> Path:
        # The emulator uses a configured directory only if it exists (Common::FS::SetEdenPath).
        value = _ini_value(text, DATA_STORAGE, key)
        if value and _absolute_text(value) and os.path.isdir(value):
            return Path(os.path.realpath(value))
        return default

    nand = configured("nand_directory", user_dir / "nand")
    return SourceProfile(emulator=emulator, user_dir=user_dir, config_dir=config_dir, nand_dir=nand,
                         sdmc_dir=configured("sdmc_directory", user_dir / "sdmc"),
                         load_dir=configured("load_directory", user_dir / "load"),
                         dump_dir=configured("dump_directory", user_dir / "dump"),
                         tas_dir=configured("tas_directory", user_dir / "tas"),
                         save_dir=configured(SAVE_KEY, nand))


def read_identity(nand_dir: Path) -> tuple[IdentityUser, ...]:
    """The users of the profiles.dat in `nand_dir`, as the emulator loads them
    (ProfileManager::ParseUserSaveFile). Raises IdentityError if there are none."""
    path = Path(nand_dir).joinpath(*IDENTITY_PARTS, PROFILES_NAME)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise IdentityError(f"{path} does not exist: the emulator profile has no user yet. Start the "
                            f"emulator once with it so that it creates its user, then try again.") from None
    except OSError as exc:
        raise IdentityError(f"Cannot read {path}: {exc}") from exc
    if len(data) < PROFILES_SIZE:
        raise IdentityError(f"{path} is damaged: it has {len(data)} bytes instead of {PROFILES_SIZE}.")
    users: list[IdentityUser] = []
    for slot in range(MAX_USERS):
        offset = 0x10 + slot * PROFILE_RECORD
        uuid = data[offset:offset + 16]
        if any(uuid):
            name = data[offset + 0x28:offset + 0x48].split(b"\0", 1)[0].decode("utf-8", "replace")
            users.append(IdentityUser(len(users), uuid.hex(), name))
    if not users:
        raise IdentityError(f"{path} lists no user: start the emulator once with this profile so that "
                            f"it creates its user, then try again.")
    return tuple(users)


def _private_account_id(value: str) -> int:
    """Match the private-server account ID generated from a profile UUID by the emulator."""
    raw = bytes.fromhex(value)
    low, high = struct.unpack("<QQ", raw)
    return (low ^ ((high << 1 | high >> 63) & 0xffffffffffffffff)) | 0x1000000000000000


def _valid_identities(value: object) -> bool:
    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_USERS:
        return False
    if not all(isinstance(key, str) and re.fullmatch(r"[0-9a-f]{32}", key) and int(key, 16)
               and isinstance(target, str) and re.fullmatch(r"[0-9a-f]{32}", target) and int(target, 16)
               for key, target in value.items()):
        return False
    source = {_private_account_id(key) for key in value}
    targets = [_private_account_id(target) for target in value.values()]
    return len(set(value.values())) == len(value) and len(set(targets)) == len(targets) and source.isdisjoint(targets)


def _new_identities(users: Sequence[IdentityUser]) -> dict[str, str]:
    sources = {user.uuid for user in users}
    if len(sources) != len(users):
        raise IdentityError("The source profile contains duplicate user UUIDs.")
    taken = {_private_account_id(source) for source in sources}
    result: dict[str, str] = {}
    for user in users:
        while True:
            target = secrets.token_hex(16)
            account = _private_account_id(target)
            if int(target, 16) and account not in taken:
                break
        result[user.uuid] = target
        taken.add(account)
    return result


# --- INI files -----------------------------------------------------------------------------------


def _read_ini(path: Path) -> tuple[bytes, str] | None:
    """(BOM, text) of an INI file, or None if it does not exist."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    bom = codecs.BOM_UTF8 if raw.startswith(codecs.BOM_UTF8) else b""
    try:
        return bom, raw[len(bom):].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CampaignProfileError(f"{path} is not UTF-8 text ({exc}); the campaign cannot use it.") from exc


def _unquote(value: str) -> str:
    """A value the way the emulator reads it: it drops double quotes."""
    return value.strip().replace('"', "")


def _ini_value(text: str, section: str, key: str) -> str | None:
    """The last value of `key` in `section`; names match regardless of case, as in SimpleIni."""
    in_section, result = False, None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped[1:-1].strip().lower() == section.lower()
        elif in_section and stripped and stripped[0] not in ";#":
            name, separator, value = line.partition("=")
            if separator and name.strip().lower() == key.lower():
                result = _unquote(value)
    return result


def _set_ini_values(text: str, section: str, values: dict[str, str]) -> str:
    """Sets `values` in `section` and leaves every other line as it was (as launcher.update_ini)."""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    names = {key.lower(): key for key in values}
    found: set[str] = set()
    in_section, insert_at = False, None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped[1:-1].strip().lower() == section.lower()
            if in_section:
                insert_at = index + 1
            continue
        if not in_section or not stripped or stripped[0] in ";#":
            continue
        insert_at = index + 1
        key, separator, _ = line.partition("=")
        name = names.get(key.strip().lower())
        if separator and name is not None:
            found.add(name)
            lines[index] = f"{name}={values[name]}"
    missing = [f"{key}={values[key]}" for key in values if key not in found]
    if missing:
        if insert_at is None:
            if lines and lines[-1].strip():
                lines.append("")
            lines += [f"[{section}]"] + missing
        else:
            lines[insert_at:insert_at] = missing
    return newline.join(lines) + newline


def _ini_path(path: Path) -> str:
    """A path the way the emulator writes it (launcher.ini_string)."""
    value = str(path).replace("\\", "/")
    return f'"{value}"' if any(character in value for character in INI_SPECIAL_CHARACTERS) else value


def _absolute_text(value: str) -> bool:
    if os.name == "nt":
        return re.match(r"[A-Za-z]:[\\/]", value) is not None
    return value.startswith("/")


def _relative_parts(value: str, root: Path) -> tuple[str, ...] | None:
    """The parts of `value` below `root`, or None if it is not inside it."""
    roots = {Path(os.path.abspath(root)).parts, Path(os.path.realpath(root)).parts}
    for candidate in {Path(os.path.abspath(value)).parts, Path(os.path.realpath(value)).parts}:
        for parts in roots:
            if len(candidate) >= len(parts) and all(
                    os.path.normcase(a) == os.path.normcase(b) for a, b in zip(candidate, parts)):
                return candidate[len(parts):]
    return None


def _remap_paths(text: str, mapping: Sequence[tuple[Path, Path]]) -> str:
    """Points every value that names an existing file or folder in the tester's profile at the
    campaign's copy of it, where the campaign has one. Other values, such as game folders, are kept:
    the emulator only reads them."""
    if not text:
        return text
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped[0] in ";#[":
            continue
        key, separator, value = line.partition("=")
        candidate = _unquote(value)
        if not separator or not _absolute_text(candidate) or not os.path.exists(candidate):
            continue
        for source, target in mapping:
            rest = _relative_parts(candidate, source)
            if rest is not None:
                if os.path.exists(target.joinpath(*rest)):
                    lines[index] = f"{key}={_ini_path(target.joinpath(*rest))}"
                break
    return newline.join(lines) + newline


def _current_user(text: str, identity: Sequence[IdentityUser]) -> IdentityUser | None:
    """The user [System] current_user selects (Config::ReadSettingGeneric: its value counts only if
    current_user\\default is false)."""
    flag = _ini_value(text, "System", "current_user\\default")
    value = _ini_value(text, "System", "current_user")
    index = 0
    if flag is not None and flag.lower() in ("false", "0", "no", "off") and value is not None:
        try:
            index = int(value)
        except ValueError:
            return None
    return identity[index] if 0 <= index < len(identity) else None


# --- Writing inside a campaign only --------------------------------------------------------------


def _guard(path: Path, root: Path) -> None:
    if not _within(path, root):
        raise IsolationError(f"Refusing to write {path}: it is outside the campaign directory {root}.")


def _mkdir(path: Path, root: Path) -> None:
    """Creates `path` and its parents below `root`, refusing links and files in the way."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise IsolationError(f"Refusing to create {path}: it is outside the campaign directory {root}.") from None
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            continue
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise IsolationError(f"{current} is not a plain folder; the campaign does not write through links.")


def _unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except PermissionError:
        if os.name != "nt":
            raise
        os.chmod(path, stat.S_IWRITE)  # read-only files cannot be deleted on Windows
        os.unlink(path)


def _remove_tree(path: Path, root: Path) -> None:
    """Deletes `path` below `root`. Refuses links instead of deleting through them."""
    _guard(path, root)
    info = os.lstat(path)
    if _is_link(info):
        raise IsolationError(f"{path} is a link; it was left alone rather than deleted through.")
    if stat.S_ISDIR(info.st_mode):
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
        for child in children:
            _remove_tree(child, root)
        os.rmdir(path)
    else:
        _unlink(path)


def _replace_file(path: Path, root: Path, write: Callable[[BinaryIO], None], private: bool = False,
                  times: tuple[int, int] | None = None) -> None:
    """Atomically replaces `path`, below `root`, with what `write` writes."""
    _guard(path, root)
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        current = None
    if current is not None and (_is_link(current) or not stat.S_ISREG(current.st_mode)):
        raise IsolationError(f"{path} is not a plain file; the campaign does not write through links.")
    temp = path.with_name(f".{path.name}.campaign-tmp")
    if os.path.lexists(temp):
        _remove_tree(temp, root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(temp, flags, 0o600 if private else 0o644)
    try:
        with os.fdopen(fd, "wb") as file:
            write(file)
        if times is not None:
            os.utime(temp, ns=times)
        try:
            os.replace(temp, path)
        except PermissionError as exc:  # Windows: the file is open, for example a running program
            raise CampaignProfileError(f"Cannot replace {path}: {exc.strerror or exc}. Close the campaign "
                                       f"emulator, and anything else using the file, and try again.") from exc
    except BaseException:
        with contextlib.suppress(OSError):
            _unlink(temp)
        raise


def _copy_file(source: Path, target: Path, root: Path, private: bool = False) -> bool:
    """Copies `source` to `target` below `root` unless they already match; returns whether it did.
    A target with other hard links is replaced by a file of its own."""
    wanted = os.stat(source)
    try:
        current = os.lstat(target)
    except FileNotFoundError:
        current = None
    if current is not None and not _is_link(current) and stat.S_ISREG(current.st_mode) and \
            current.st_nlink == 1 and current.st_size == wanted.st_size and \
            current.st_mtime_ns == wanted.st_mtime_ns:
        return False

    def write(file: BinaryIO) -> None:
        with source.open("rb") as original:
            shutil.copyfileobj(original, file, COPY_CHUNK)

    _replace_file(target, root, write, private, (wanted.st_atime_ns, wanted.st_mtime_ns))
    return True


def _copy_files(source_dir: Path, target_dir: Path, root: Path, updated: list[str], *,
                only_missing: bool = False, private: bool = False, suffix: str | None = None,
                exclude: frozenset[str] = frozenset()) -> None:
    """Copies the files directly in `source_dir` (not its folders)."""
    if not source_dir.is_dir():
        return
    with os.scandir(source_dir) as entries:
        files = sorted((Path(entry.path) for entry in entries if entry.is_file()), key=lambda p: p.name)
    for file in files:
        if file.name.lower() in exclude:
            continue
        if suffix is not None and not file.name.lower().endswith(suffix):
            continue
        target = target_dir / file.name
        if only_missing and os.path.lexists(target):
            continue
        _mkdir(target_dir, root)
        if _copy_file(file, target, root, private):
            updated.append(target.relative_to(root).as_posix())


def _source_listing(directory: Path) -> dict[str, tuple[int, int]]:
    """Relative path -> (size, modification time) of each file below `directory`, (-1, 0) for each
    folder. Links are read through; a link back into a folder being listed is refused."""
    listing: dict[str, tuple[int, int]] = {}
    active: set[str] = set()

    def walk(path: Path, prefix: str) -> None:
        key = _canonical(path)
        if key in active:
            raise CampaignProfileError(f"{path} links back into a folder that contains it.")
        active.add(key)
        with os.scandir(path) as entries:
            children = sorted((entry.name, entry.path) for entry in entries)
        for name, child in children:
            info = os.stat(child)
            if stat.S_ISDIR(info.st_mode):
                listing[prefix + name] = (-1, 0)
                walk(Path(child), f"{prefix}{name}/")
            elif stat.S_ISREG(info.st_mode):
                listing[prefix + name] = (info.st_size, info.st_mtime_ns)
        active.discard(key)

    walk(directory, "")
    return listing


def _target_listing(directory: Path) -> dict[str, tuple[int, int]] | None:
    """As _source_listing for a folder of the campaign, refusing links; None if it does not exist."""
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        return None
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise IsolationError(f"{directory} is not a plain folder; the campaign does not write through links.")
    listing: dict[str, tuple[int, int]] = {}
    pending = [(directory, "")]
    while pending:
        path, prefix = pending.pop()
        with os.scandir(path) as entries:
            children = [(entry.name, entry.path) for entry in entries]
        for name, child in children:
            info = os.lstat(child)
            if _is_link(info):
                raise IsolationError(f"{child} is a link; the campaign does not write through links.")
            if stat.S_ISDIR(info.st_mode):
                listing[prefix + name] = (-1, 0)
                pending.append((Path(child), f"{prefix}{name}/"))
            elif info.st_nlink > 1:
                listing[prefix + name] = (-2, 0)  # never equal: replaced by a file of its own
            else:
                listing[prefix + name] = (info.st_size, info.st_mtime_ns)
    return listing


def _mirror_tree(source: Path, target: Path, root: Path) -> bool:
    """Makes `target`, below `root`, an exact copy of `source` unless it already is one: the copy is
    built next to it and then swapped in. Returns whether anything changed."""
    wanted = _source_listing(source)
    if _target_listing(target) == wanted:
        return False
    staging = target.with_name(f".{target.name}.campaign-new")
    retired = target.with_name(f".{target.name}.campaign-old")
    for leftover in (staging, retired):
        if os.path.lexists(leftover):
            _remove_tree(leftover, root)
    _mkdir(staging, root)
    try:
        for relative, (size, _) in sorted(wanted.items()):  # folders sort before their contents
            parts = relative.split("/")
            if size < 0:
                _mkdir(staging.joinpath(*parts), root)
            else:
                _copy_file(source.joinpath(*parts), staging.joinpath(*parts), root)
    except BaseException:
        with contextlib.suppress(OSError, CampaignProfileError):
            _remove_tree(staging, root)
        raise
    if os.path.lexists(target):
        os.rename(target, retired)
    os.rename(staging, target)
    if os.path.lexists(retired):
        _remove_tree(retired, root)
    return True


def _links_below(root: Path, hard_links: bool) -> list[str]:
    """Links below `root` that could carry writes out of it."""
    found: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = [entry.path for entry in entries]
        except OSError as exc:
            found.append(f"{directory} cannot be read ({exc.strerror or exc})")
            continue
        for child in children:
            info = os.lstat(child)
            if _is_link(info):
                found.append(f"{child} is a link")
            elif stat.S_ISDIR(info.st_mode):
                pending.append(Path(child))
            elif hard_links and info.st_nlink > 1:
                found.append(f"{child} shares its data with another file (hard link)")
    return found


def _has_entries(path: Path) -> bool:
    try:
        with os.scandir(path) as entries:
            return any(True for _ in entries)
    except (FileNotFoundError, NotADirectoryError):
        return False


# --- The Windows program and its DLLs -------------------------------------------------------------


def read_program_image(path: Path) -> ProgramImage:
    """The machine, kind and imported DLLs (including delay-loaded ones) of a Windows program or DLL."""
    try:
        with Path(path).open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as image:
            return _parse_program(image)
    except (OSError, ValueError, struct.error) as exc:
        raise DependencyError(f"Cannot read {path} as a Windows program or DLL: {exc}") from exc


def _parse_program(image) -> ProgramImage:
    if image[:2] != b"MZ":
        raise ValueError("no MZ header")
    (header,) = struct.unpack_from("<I", image, 0x3C)
    if image[header:header + 4] != b"PE\0\0":
        raise ValueError("no PE header")
    machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", image, header + 4)
    optional = header + 24
    (magic,) = struct.unpack_from("<H", image, optional)
    if magic == 0x20B:
        directories, (image_base,) = optional + 112, struct.unpack_from("<Q", image, optional + 24)
    elif magic == 0x10B:
        directories, (image_base,) = optional + 96, struct.unpack_from("<I", image, optional + 28)
    else:
        raise ValueError(f"unknown optional header {magic:#x}")
    (headers_size,) = struct.unpack_from("<I", image, optional + 60)
    (directory_count,) = struct.unpack_from("<I", image, directories - 4)
    table = optional + optional_size
    spans = [struct.unpack_from("<IIII", image, table + 40 * index + 8) for index in range(sections)]

    def offset(address: int) -> int:
        if 0 <= address < headers_size:
            return address
        for virtual_size, virtual_address, raw_size, raw_pointer in spans:
            if virtual_address <= address < virtual_address + max(virtual_size, raw_size) and \
                    address - virtual_address < raw_size:
                return raw_pointer + address - virtual_address
        raise ValueError(f"address {address:#x} is outside the file")

    def name_at(address: int) -> str:
        start = offset(address)
        end = image.find(b"\0", start, start + 256)
        if end < 0:
            raise ValueError("unterminated DLL name")
        return image[start:end].decode("ascii")

    def directory(index: int) -> int:
        if directory_count <= index:
            return 0
        return struct.unpack_from("<I", image, directories + 8 * index)[0]

    names: list[str] = []
    address = directory(1)
    if address:
        entry = offset(address)
        for _ in range(MAX_IMPORTS):
            lookup, _, _, name, thunks = struct.unpack_from("<IIIII", image, entry)
            if not (lookup or name or thunks):
                break
            names.append(name_at(name))
            entry += 20
        else:
            raise ValueError("the import table does not end")
    address = directory(13)
    if address:
        entry = offset(address)
        for _ in range(MAX_IMPORTS):
            attributes, name = struct.unpack_from("<II", image, entry)
            if not name:
                break
            # Old delay-load tables hold virtual addresses instead of relative ones.
            names.append(name_at(name if attributes & 1 else name - image_base))
            entry += 32
        else:
            raise ValueError("the delay-load table does not end")
    return ProgramImage(machine, bool(characteristics & 0x2000), tuple(names))


def _system_directories() -> list[Path]:
    """The folders Windows loads a 64-bit program's system DLLs from."""
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer)):
        raise DependencyError("Cannot find the Windows folder.")
    windows = Path(buffer.value)
    native = windows / "Sysnative"  # the real System32 as a 32-bit Python sees it
    if native.is_dir():
        return [native, windows]
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer)):
        raise DependencyError("Cannot find the Windows system folder.")
    return [Path(buffer.value), windows]


def _machine(value: int) -> str:
    return MACHINES.get(value, f"machine {value:#x}")


def _inspect_program(exe: Path, system_dirs: Sequence[Path]) -> _Program:
    """What the campaign needs next to its copy of `exe`. Raises DependencyError if a DLL that `exe`
    loads is neither next to it nor in the system folder, or is built for another processor."""
    image = read_program_image(exe)
    if image.library or image.machine not in PROGRAM_MACHINES:
        raise DependencyError(f"{exe} is not a 64-bit Windows program ({_machine(image.machine)}"
                              f"{', a DLL' if image.library else ''}).")
    if not exe.name.lower().endswith(".exe"):
        raise DependencyError(f"{exe} is not named like a Windows program (.exe).")
    folder = exe.parent
    files: list[Path] = []
    folders: list[Path] = []
    with os.scandir(folder) as entries:
        for entry in entries:
            lower = entry.name.lower()
            if entry.is_file() and (lower.endswith(".dll") or lower == QT_CONF):
                files.append(Path(entry.path))
            elif entry.is_dir() and lower in QT_RUNTIME_DIRS:
                folders.append(Path(entry.path))
    files.sort(key=lambda path: path.name.lower())
    folders.sort(key=lambda path: path.name.lower())
    local = {path.name.lower(): path for path in files if path.name.lower().endswith(".dll")}

    def library(path: Path) -> ProgramImage:
        found = read_program_image(path)
        if found.machine != image.machine:
            raise DependencyError(f"{path} is built for {_machine(found.machine)}, but {exe.name} for "
                                  f"{_machine(image.machine)}; Windows cannot load it.")
        return found

    pending = list(image.imports)
    for runtime in folders:
        for directory, _, names in os.walk(runtime):
            pending += [name for file in sorted(names) if file.lower().endswith(".dll")
                        for name in library(Path(directory) / file).imports]
    seen: set[str] = set()
    system: list[str] = []
    missing: list[str] = []
    while pending:
        name = pending.pop(0)
        lower = name.lower()
        if lower in seen or lower.startswith(API_SET_PREFIXES):
            continue
        seen.add(lower)
        if lower in local:
            pending += library(local[lower]).imports
        elif any((directory / name).is_file() for directory in system_dirs):
            system.append(name)
        else:
            missing.append(name)
    if missing:
        hint = ""
        if any(name.lower().startswith(VC_RUNTIME_PREFIXES) for name in missing):
            hint = (f" Install the Microsoft Visual C++ Redistributable (x64) from {VC_REDIST_URL}, or "
                    f"put the emulator's own copies of these DLLs next to {exe.name}.")
        raise DependencyError(f"{exe.name} needs {', '.join(sorted(missing, key=str.lower))}, which is "
                              f"neither next to it in {folder} nor in the Windows system folder, so the "
                              f"campaign's copy could not start.{hint}")
    return _Program(exe, tuple(files), tuple(folders), tuple(sorted(system, key=str.lower)))


def _install_program(program: _Program, root: Path, previous: Sequence[str], updated: list[str]) -> tuple[str, ...]:
    """Copies the program and everything next to it that it needs into `root`, and deletes what an
    earlier preparation copied but the program no longer has. Returns the names copied besides it."""
    if _copy_file(program.executable, root / program.executable.name, root):
        updated.append(program.executable.name)
    names: list[str] = []
    for file in program.files:
        if _copy_file(file, root / file.name, root):
            updated.append(file.name)
        names.append(file.name)
    for folder in program.folders:
        if _mirror_tree(folder, root / folder.name, root):
            updated.append(folder.name + "/")
        names.append(folder.name)
    keep = {name.lower() for name in names} | {program.executable.name.lower()}
    for stale in previous:
        if stale.lower() not in keep and os.path.lexists(root / stale):
            _remove_tree(root / stale, root)
            updated.append(stale)
    return tuple(names)


def _in_use(program: Path) -> bool:
    """Whether the Windows program is running, as launcher.emulator_running: Windows refuses to open
    a running program for writing; opening it changes nothing."""
    if os.name != "nt":
        raise CampaignProfileError("Cannot verify whether the emulator is closed on this platform; "
                                   "the campaign was not modified.")
    try:
        with program.open("r+b"):
            return False
    except FileNotFoundError:
        return False
    except OSError as exc:
        if getattr(exc, "winerror", None) == 32:
            return True
        raise CampaignProfileError(f"Cannot verify whether the emulator ({program}) is closed: {exc}") from exc


# --- Campaigns ------------------------------------------------------------------------------------


def _read_manifest(root: Path, name: str) -> dict | None:
    path = root / MANIFEST_NAME
    try:
        data = json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise IsolationError(f"{path} is damaged ({exc}); the campaign was not used.") from exc
    if not isinstance(data, dict):
        raise IsolationError(f"{path} is damaged; the campaign was not used.")
    source, owned, program = data.get("source"), data.get("dependencies"), data.get("program")
    valid = (data.get("format") == FORMAT and data.get("name") == name and isinstance(source, dict) and
             all(isinstance(source.get(key), str) and source[key] for key in ("emulator", "user_dir", "config_dir")) and
             isinstance(owned, list) and (program is not None or os.name != "nt") and
             _valid_identities(data.get("identities")) and
             all(_owned_name(item) for item in owned + ([program] if program is not None else [])))
    if not valid:
        raise IsolationError(f"{path} is damaged or belongs to another campaign; the campaign was not used.")
    return data


def _owned_name(item: object) -> bool:
    """Whether `item` can name a file the campaign copied next to its program."""
    return isinstance(item, str) and item not in ("", ".", "..", PORTABLE_DIR, MANIFEST_NAME, CREATING_MARKER) \
        and not any(character in item for character in "/\\:")
    return data


def _profile_from_manifest(root: Path, data: dict) -> CampaignProfile:
    source = data["source"]
    program = data.get("program")
    emulator = Path(source["emulator"])
    return CampaignProfile(name=data["name"], root=root, executable=root / program if program else emulator,
                           source_emulator=emulator, source_user_dir=Path(source["user_dir"]),
                           source_config_dir=Path(source["config_dir"]))


def open_campaign(base: Path, name: str) -> CampaignProfile:
    """The existing campaign `name` in `base`. Call verify_isolation() before launching it."""
    name = check_campaign_name(name)
    base = Path(base)
    if not base.is_absolute():
        raise UnsafePathError(f"The campaign folder {base} must be an absolute path.")
    root = Path(os.path.realpath(base)) / name
    data = _read_manifest(root, name)
    if data is None:
        raise CampaignProfileError(f"There is no campaign {name!r} in {base}.")
    return _profile_from_manifest(root, data)


def list_campaigns(base: Path) -> list[str]:
    """The names of the complete campaigns in `base`."""
    base = Path(os.path.realpath(base))
    try:
        with os.scandir(base) as entries:
            candidates = [entry for entry in entries
                          if NAME_PATTERN.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False)]
    except FileNotFoundError:
        return []
    return sorted((entry.name for entry in candidates
                   if (Path(entry.path) / MANIFEST_NAME).is_file() and
                   not os.path.lexists(Path(entry.path) / CREATING_MARKER)), key=str.lower)


def verify_isolation(profile: CampaignProfile) -> None:
    """Raises IsolationError unless the emulator, started as profile.command() in
    profile.working_directory, keeps everything it writes inside the campaign directory."""
    root = profile.root
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        raise IsolationError(f"The campaign directory {root} does not exist.") from None
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise IsolationError(f"The campaign directory {root} is not a plain folder.")
    problems: list[str] = []
    if os.path.lexists(root / CREATING_MARKER):
        problems.append("it was not completely set up; prepare it again")
    manifest = None
    try:
        manifest = _read_manifest(root, profile.name)
        if manifest is None:
            problems.append(f"{MANIFEST_NAME} is missing")
    except IsolationError as exc:
        problems.append(str(exc))
    if manifest is not None:
        try:
            users = read_identity(profile.nand_dir)
            if {user.uuid for user in users} != set(manifest["identities"].values()):
                problems.append("its user identities do not match the campaign's isolated identities")
        except IdentityError as exc:
            problems.append(str(exc))
    try:
        _check_path_text(root)
    except UnsafePathError as exc:
        problems.append(str(exc))
    protected = [profile.source_user_dir, profile.source_config_dir,
                 _program_directory(profile.source_emulator) / PORTABLE_DIR, *_family_roots()]
    problems += [f"it overlaps {path}" for path in protected if _overlaps(root, path)]
    problems += _links_below(root, hard_links=True)
    # Without its portable profile the emulator would use the tester's.
    for directory in (profile.user_dir, profile.config_dir, profile.nand_dir, profile.save_dir,
                      profile.load_dir, profile.sdmc_dir, profile.dump_dir, profile.tas_dir,
                      profile.screenshots_dir):
        if not directory.is_dir():
            problems.append(f"{directory} is missing")
    if os.name == "nt":
        if profile.executable.parent != root or not profile.executable.is_file():
            problems.append(f"the campaign's own emulator {root / profile.executable.name} is missing")
        elif _canonical(profile.executable) == _canonical(profile.source_emulator):
            problems.append(f"{profile.executable} is your own emulator, not the campaign's copy")
        if len(str(profile.executable)) >= WINDOWS_MAX_PATH:
            problems.append(f"the path of {profile.executable} is too long for Windows")
    try:
        loaded = _read_ini(profile.config_dir / CONFIG_NAME)
    except CampaignProfileError as exc:
        problems.append(str(exc))
        loaded = None
    if loaded is None:
        problems.append(f"{profile.config_dir / CONFIG_NAME} is missing")
    else:
        text = loaded[1]
        configured = [(f"[Data Storage] {key}", _ini_value(text, DATA_STORAGE, key))
                      for key in (*STORAGE_KEYS, SAVE_KEY)]
        configured.append((f"[UI] {SCREENSHOT_KEY}", _ini_value(text, "UI", SCREENSHOT_KEY)))
        for setting, value in configured:
            if value and (not _absolute_text(value) or not _within(value, root)):
                problems.append(f"{setting} points to {value}, outside the campaign")
    if problems:
        raise IsolationError(f"The campaign profile in {root} is not isolated from your own profile, so "
                             f"it was not used: {'; '.join(problems)}.")


def seed_campaign_save(profile: CampaignProfile, source: SourceProfile,
                       title_id: str, user: IdentityUser) -> Path:
    """Copy one existing player save into an empty isolated campaign, without changing its source.

    This is a one-time import: an existing campaign save is never replaced. Both emulators must be
    stopped so the copy is not assembled from different saves. A missing or unsupported save layout
    is an error, not a new-game fallback.
    """
    verify_isolation(profile)
    if _canonical(source.emulator) != _canonical(profile.source_emulator) or \
            _canonical(source.user_dir) != _canonical(profile.source_user_dir) or \
            _canonical(source.config_dir) != _canonical(profile.source_config_dir):
        raise IdentityError("The save source is not the profile this campaign was created from.")
    if _in_use(source.emulator) or _in_use(profile.executable):
        raise CampaignProfileError("Close both the original and campaign emulators before copying a save.")
    if user not in read_identity(source.nand_dir):
        raise IdentityError("The chosen user is not in the source profile.")
    target_user = profile.campaign_user(user)
    title = check_title_id(title_id, base_title=False)
    root = source.save_dir / "user" / "save"
    # SaveDataFactory prefers the newer account/<UUID>/<base-title>/0 layout if both exist.
    future_parts = ("account", user.uuid.lower(), f"{int(title, 16) & ~0xff:016X}", "0")
    legacy_parts = (ACCOUNT_SAVES, user.save_folder, title)
    future, legacy = root.joinpath(*future_parts), root.joinpath(*legacy_parts)
    future_target = ("account", target_user.uuid.lower(), f"{int(title, 16) & ~0xff:016X}", "0")
    legacy_target = (ACCOUNT_SAVES, target_user.save_folder, title)
    original, parts = (future, future_target) if future.is_dir() else (legacy, legacy_target)
    targets = [profile.save_dir.joinpath(*future_target), profile.save_dir.joinpath(*legacy_target)]
    if not original.is_dir():
        raise CampaignProfileError(f"No supported save for {title} and this user exists in {root}.")
    if any(os.path.lexists(path) for path in targets):
        raise CampaignProfileError("The campaign already has a save for this user and game; it was not replaced.")
    target = profile.save_dir.joinpath(*parts)
    _mkdir(target.parent, profile.root)
    _mirror_tree(original, target, profile.root)
    return target


def create_campaign(base: Path, name: str, source: SourceProfile, *,
                    copy_installed_content: bool = False) -> PreparedCampaign:
    """Creates the campaign `name` in `base` as a copy of `source`; fails if it exists."""
    return _prepare(base, name, source, copy_installed_content, False, True)


def prepare_campaign(base: Path, name: str, source: SourceProfile, *, copy_installed_content: bool = False,
                     rebind_source: bool = False) -> PreparedCampaign:
    """Creates the campaign `name` in `base` if needed, else brings it up to date with `source`:
    the program and its DLLs, the user profiles, keys and firmware are copied again where they
    changed, and the storage paths are reset to the campaign. Campaign saves, mods, settings and
    caches are kept. A campaign copied from another profile is refused unless `rebind_source`, as
    it would change its online identity. With `copy_installed_content`, the games, updates and DLC
    installed in the tester's NAND and SD card replace those of the campaign (they can be large).
    Ends with verify_isolation()."""
    return _prepare(base, name, source, copy_installed_content, rebind_source, False)


def _prepare(base: Path, name: str, source: SourceProfile, copy_installed: bool, rebind: bool,
             must_create: bool) -> PreparedCampaign:
    root = campaign_root(base, name, source)
    # Everything that can fail on the tester's side is checked before anything is written.
    identity = read_identity(source.nand_dir)
    program = _inspect_program(source.emulator, _system_directories()) if os.name == "nt" else None
    for running in (source.emulator, root / source.emulator.name) if program is not None else (source.emulator,):
        if _in_use(running):
            raise CampaignProfileError(f"Close the emulator ({running}) first, then try again: it saves its "
                                       f"settings and profiles while it runs and when it exits.")
    manifest = None
    state = "new"
    if os.path.lexists(root):
        info = os.lstat(root)
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise UnsafePathError(f"{root} is not a plain folder.")
        if os.path.lexists(root / CREATING_MARKER):
            state = "incomplete"
        else:
            manifest = _read_manifest(root, name)
            if manifest is not None:
                state = "existing"
            elif _has_entries(root):
                raise UnsafePathError(f"{root} already exists and is not a campaign; choose another name "
                                      f"or folder.")
    if must_create and state == "existing":
        raise CampaignProfileError(f"The campaign {name!r} already exists in {root.parent}.")
    if state == "existing":
        recorded = manifest["source"]
        if not rebind and (_canonical(recorded["user_dir"]) != _canonical(source.user_dir) or
                           _canonical(recorded["config_dir"]) != _canonical(source.config_dir)):
            raise IdentityError(f"The campaign {name!r} was copied from the emulator profile in "
                                f"{recorded['user_dir']}, not {source.user_dir}. Its saves belong to that "
                                f"profile's online identity; rebind it only if this profile should "
                                f"replace it.")
        links = _links_below(root, hard_links=True)
        if links:
            raise IsolationError(f"The campaign profile in {root} is not isolated, so nothing was "
                                 f"changed: {'; '.join(links)}.")
    identities = manifest["identities"] if manifest else _new_identities(identity)
    if set(identities) != {user.uuid for user in identity}:
        raise IdentityError("The source profile's users changed; create a new campaign rather than "
                            "replacing the identities of an existing campaign.")

    created = state != "existing"
    if created:
        Path(os.path.realpath(base)).mkdir(mode=0o700, parents=True, exist_ok=True)
        if campaign_root(base, name, source) != root:
            raise UnsafePathError(f"The campaign folder {base} changed while the campaign was being created.")
        if state == "new":
            try:
                os.mkdir(root, 0o700)
            except FileExistsError:
                if _has_entries(root):
                    raise CampaignProfileError(f"{root} was created by something else meanwhile.") from None
            if os.name == "posix":
                root.chmod(0o700)  # it holds the decryption keys
        else:
            with os.scandir(root) as entries:
                leftovers = [Path(entry.path) for entry in entries]
            for leftover in leftovers:
                _remove_tree(leftover, root)
        _replace_file(root / CREATING_MARKER, root, lambda file: file.write(b"incomplete\n"))

    profile = CampaignProfile(name=name, root=root,
                              executable=root / source.emulator.name if program else source.emulator,
                              source_emulator=source.emulator, source_user_dir=source.user_dir,
                              source_config_dir=source.config_dir)
    try:
        updated: list[str] = []
        warnings: list[str] = []
        previous = list((manifest or {}).get("dependencies", []))
        if manifest and manifest.get("program"):
            previous.append(manifest["program"])
        dependencies: tuple[str, ...] = ()
        if program is not None:
            dependencies = _install_program(program, root, previous, updated)
        text = _populate(profile, source, identities, copy_installed, updated, warnings)
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {"format": FORMAT, "name": name,
                "created": (manifest or {}).get("created", now), "prepared": now,
                "source": {"emulator": str(source.emulator), "user_dir": str(source.user_dir),
                           "config_dir": str(source.config_dir)},
                "program": source.emulator.name if program else None,
                "identities": identities, "dependencies": list(dependencies)}
        _replace_file(root / MANIFEST_NAME, root, lambda file: file.write(json.dumps(data, indent=1).encode()))
        if created:
            _unlink(root / CREATING_MARKER)
    except BaseException:
        if state == "new":
            with contextlib.suppress(OSError, CampaignProfileError):
                _remove_tree(root, root)
        raise
    verify_isolation(profile)
    return PreparedCampaign(
        profile=profile, created=created, identity=identity, current_user=_current_user(text, identity),
        keys=(profile.keys_dir / "prod.keys").is_file(), firmware=_has_entries(profile.firmware_dir),
        dependencies=dependencies, system_dependencies=program.system if program else (),
        updated=tuple(updated), warnings=tuple(warnings))


def _install_identity(profile: CampaignProfile, source: SourceProfile, identities: dict[str, str],
                      updated: list[str]) -> None:
    """Copy profile metadata while replacing both UUID fields and mapping avatar filenames."""
    original = (source.identity_dir / PROFILES_NAME).read_bytes()
    if len(original) < PROFILES_SIZE:
        raise IdentityError("The source profile changed while its identities were being copied.")
    data = bytearray(original)
    found: set[str] = set()
    for slot in range(MAX_USERS):
        offset = 0x10 + slot * PROFILE_RECORD
        source_id = bytes(data[offset:offset + 16]).hex()
        if int(source_id, 16):
            if source_id not in identities or source_id in found:
                raise IdentityError("The source profile changed while its identities were being copied.")
            found.add(source_id)
            target = bytes.fromhex(identities[source_id])
            data[offset:offset + 16] = target
            data[offset + 16:offset + 32] = target
    if found != set(identities):
        raise IdentityError("The source profile changed while its identities were being copied.")
    avatars = {source_id: f"{uuid.UUID(hex=source_id)}.jpg" for source_id in identities}
    _copy_files(source.identity_dir, profile.identity_dir, profile.root, updated,
                exclude=frozenset({PROFILES_NAME, *avatars.values()}))
    for source_id, filename in avatars.items():
        original_avatar = source.identity_dir / filename
        target_avatar = profile.identity_dir / f"{uuid.UUID(hex=identities[source_id])}.jpg"
        if original_avatar.is_file() and _copy_file(original_avatar, target_avatar, profile.root):
            updated.append(target_avatar.relative_to(profile.root).as_posix())
    target = profile.identity_dir / PROFILES_NAME
    if not target.is_file() or target.read_bytes() != data:
        _replace_file(target, profile.root, lambda file: file.write(data))
        updated.append(target.relative_to(profile.root).as_posix())


def _populate(profile: CampaignProfile, source: SourceProfile, identities: dict[str, str],
              copy_installed: bool, updated: list[str], warnings: list[str]) -> str:
    """Copies identity metadata, keys, certificates and firmware; returns the campaign settings text."""
    root = profile.root
    for directory in (profile.config_dir, profile.keys_dir, profile.certs_dir, profile.save_dir,
                      profile.load_dir, profile.sdmc_dir, profile.dump_dir, profile.tas_dir,
                      profile.screenshots_dir, profile.identity_dir, profile.firmware_dir.parent):
        _mkdir(directory, root)

    _install_identity(profile, source, identities, updated)
    _copy_files(source.keys_dir, profile.keys_dir, root, updated, private=True)
    _copy_files(source.certs_dir, profile.certs_dir, root, updated, only_missing=True)
    if _has_entries(source.firmware_dir):
        if _mirror_tree(source.firmware_dir, profile.firmware_dir, root):
            updated.append(profile.firmware_dir.relative_to(root).as_posix() + "/")
    sd_contents = source.sdmc_dir.joinpath(*SD_CONTENTS_PARTS)
    for installed, copy, content in (
            (source.installed_dir, profile.installed_dir, source.installed_dir),
            (sd_contents, profile.sdmc_dir.joinpath(*SD_CONTENTS_PARTS), sd_contents / "registered")):
        if not _has_entries(content):
            continue
        if copy_installed:
            _mkdir(copy.parent, root)
            if _mirror_tree(installed, copy, root):
                updated.append(copy.relative_to(root).as_posix() + "/")
        else:
            warnings.append(f"The games, updates and DLC installed in {content} were not copied, so the "
                            f"campaign does not have them: start the game from files whose updates are in "
                            f"a game folder, or prepare with copy_installed_content=True.")
    seed = source.nand_dir.joinpath(*SD_SEED_PARTS)
    if copy_installed and seed.is_file() and _copy_file(seed, profile.nand_dir.joinpath(*SD_SEED_PARTS), root):
        updated.append(profile.nand_dir.joinpath(*SD_SEED_PARTS).relative_to(root).as_posix())
    if not (profile.keys_dir / "prod.keys").is_file():
        warnings.append(f"There are no decryption keys in {source.keys_dir}, so the campaign has none: "
                        f"install them in the campaign's emulator (Tools > Install Decryption Keys).")
    if not _has_entries(profile.firmware_dir):
        warnings.append(f"There is no firmware in {source.firmware_dir}, so the campaign has none: if the "
                        f"game needs it, install it in the campaign's emulator (Tools > Install Firmware).")

    source_ini = _read_ini(source.config_dir / CONFIG_NAME)
    target = profile.config_dir / CONFIG_NAME
    own = _read_ini(target)
    bom, text = own or source_ini or (b"", "")
    mapping = sorted(((source.user_dir, profile.user_dir), (source.config_dir, profile.config_dir),
                      (source.nand_dir, profile.nand_dir), (source.sdmc_dir, profile.sdmc_dir),
                      (source.load_dir, profile.load_dir), (source.dump_dir, profile.dump_dir),
                      (source.tas_dir, profile.tas_dir), (source.save_dir, profile.nand_dir)),
                     key=lambda pair: len(pair[0].parts), reverse=True)
    text = _remap_paths(text, mapping)
    storage: dict[str, str] = {}
    for key, path in zip(STORAGE_KEYS, (profile.nand_dir, profile.sdmc_dir, profile.load_dir,
                                        profile.dump_dir, profile.tas_dir)):
        storage[f"{key}\\default"] = "false"
        storage[key] = _ini_path(path)
    storage[f"{SAVE_KEY}\\default"] = "true"  # empty: saves stay in the NAND
    storage[SAVE_KEY] = ""
    text = _set_ini_values(text, DATA_STORAGE, storage)
    text = _set_ini_values(text, "UI", {SCREENSHOT_KEY: _ini_path(profile.screenshots_dir)})
    if source_ini is not None:
        # The selected user decides which identity the game plays as.
        selected = {key: value for key in ("current_user\\default", "current_user")
                    if (value := _ini_value(source_ini[1], "System", key)) is not None}
        if "current_user" in selected:
            text = _set_ini_values(text, "System", selected)
    data = bom + text.encode("utf-8")
    try:
        unchanged = target.read_bytes() == data
    except FileNotFoundError:
        unchanged = False
    if not unchanged:
        _replace_file(target, root, lambda file: file.write(data))
        updated.append(target.relative_to(root).as_posix())
    for folder in ("custom", "input"):  # per-game settings and controller profiles, once
        _copy_files(source.config_dir / folder, profile.config_dir / folder, root, updated,
                    only_missing=True, suffix=".ini")
    return text


def install_mod(profile: CampaignProfile, title_id: str, mod_name: str, source: Path, *,
                replace: bool = False) -> Path:
    """Copies the mod in `source` (a folder of exefs, romfs, romfs_ext and cheats folders) into the
    campaign's mod tree for the base title `title_id`, and returns where. Fails if the campaign
    already has a mod of that name, unless `replace`."""
    title = check_title_id(title_id)
    name = _check_name(mod_name, "mod name")
    verify_isolation(profile)
    if _in_use(profile.executable):
        raise CampaignProfileError(f"Close the campaign's emulator ({profile.executable}) first, then try again.")
    source = Path(os.path.abspath(source))
    try:
        info = os.lstat(source)
    except FileNotFoundError:
        raise CampaignProfileError(f"{source} does not exist.") from None
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise CampaignProfileError(f"{source} is not a plain folder.")
    if _overlaps(source, profile.root):
        raise UnsafePathError(f"{source} overlaps the campaign directory {profile.root}.")
    with os.scandir(source) as entries:
        parts = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in entries]
    unexpected = sorted(part for part, is_dir in parts if not is_dir or part.lower() not in MOD_PARTS)
    if not parts or unexpected:
        raise CampaignProfileError(f"{source} is not a mod folder: it may hold only the folders "
                                   f"{', '.join(MOD_PARTS)}" +
                                   (f", not {', '.join(unexpected)}." if unexpected else ", and holds none."))
    links = _links_below(source, hard_links=False)
    if links:
        raise CampaignProfileError(f"{source} contains links ({links[0]}); put the files themselves in it.")
    target = profile.load_dir / title / name
    if os.path.lexists(target) and not replace:
        raise CampaignProfileError(f"The campaign already has the mod {target}; replace it explicitly.")
    _mkdir(target.parent, profile.root)
    _mirror_tree(source, target, profile.root)
    return target
