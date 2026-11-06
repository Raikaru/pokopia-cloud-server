"""Installs the official Eglantine build for this system from its public GitHub releases.

download_emulator(home, check) takes the newest published release, prereleases included, and installs
the build for this system in a new directory, home/emulator/<release tag>. Ask the player first: it
downloads about 70 MB on Windows and 140 MB on Linux. A published release need not have private-server
support, so the executable it contains is inspected with `check` (launcher.check_emulator) before
anything is installed.

The download is refused unless it has exactly the size and SHA-256 digest that GitHub publishes for
the asset. It is unpacked in a staging directory next to the installs, within size limits:
- Windows: the zip, as regular files and directories only, each inside the staging directory.
- Linux: the AppImage, which bundles the Qt and other libraries the plain tar.gz build expects the
  system to provide. Its squashfs is zstd-compressed, which Python cannot read, so the verified
  AppImage unpacks itself (--appimage-extract, which needs no FUSE). The result is used only if it
  holds nothing but directories, regular files and relative symbolic links that stay inside it. The
  installed executable is the program itself (usr/bin/eglantine), which runs without the AppImage
  runtime and which launcher.check_emulator can inspect on every later start.
The staging directory, with the downloaded file, is removed whether the installation succeeds or not.

Nothing that exists is replaced: each release gets a new directory. No portable profile is created,
so the launcher continues to use the player's existing standard emulator profile when available.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import json
import mmap
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import BinaryIO, Callable, Iterator
from urllib.parse import urlsplit

import certifi

if os.name == "nt":
    import msvcrt
else:
    import fcntl

REPOSITORY = "notsapinho/Eglantine"
RELEASES_URL = f"https://github.com/{REPOSITORY}/releases"
# The list includes prereleases, which /releases/latest skips.
RELEASES_API = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=30"
DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
EXE_NAME = "eglantine.exe" if os.name == "nt" else "eglantine"
# The official asset for each system (sys.platform) and machine.
ASSETS = {
    ("win32", "x86_64"): "eglantine-windows-x86_64.zip",
    ("linux", "x86_64"): "eglantine-linux-x86_64.AppImage",
    ("linux", "aarch64"): "eglantine-linux-aarch64.AppImage",
}
MACHINES = {"amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
RELEASE_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SHA256_DIGEST = re.compile(r"sha256:([0-9a-fA-F]{64})")

INSTALL_DIR = "emulator"
STAGING_PREFIX = ".download-"
LOCK_NAME = ".install.lock"
# Where --appimage-extract unpacks, in its working directory.
APPIMAGE_ROOT = "squashfs-root"

# Build 18's Windows zip is 68 MB and expands to 172 MB in 84 entries; its x86_64 AppImage is 141 MB
# with 587 inodes.
MAX_METADATA_BYTES = 8 << 20
MAX_ASSET_BYTES = 256 << 20
MAX_EXPANDED_BYTES = 1 << 30
MAX_MEMBERS = 10000
EXTRACT_TIMEOUT_SECONDS = 600
EXTRACT_POLL_SECONDS = 0.5
CHUNK = 65536
TIMEOUT_SECONDS = 30

WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
WINDOWS_DEVICES = frozenset(["con", "prn", "aux", "nul", "conin$", "conout$",
                             *(f"com{n}" for n in range(1, 10)), *(f"lpt{n}" for n in range(1, 10))])


def download_emulator(home: Path, check: Callable[[Path], None]) -> Path:
    """Installs the official Eglantine build for this system from the newest published release and
    returns its executable. `check` exits (SystemExit) if an executable is not a compatible build; it
    runs before anything is installed. Exits with the reason if no usable compatible build can be
    installed; only home/emulator changes, and never an existing install in it."""
    asset = expected_asset(sys.platform, platform.machine())
    release = latest_release()
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not RELEASE_TAG.fullmatch(tag):
        sys.exit(f"The newest Eglantine release has an unexpected tag ({tag!r}); see {RELEASES_URL}.")
    url, size, sha256 = release_asset(release, tag, asset)

    root = home / INSTALL_DIR
    try:
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.mkdir(exist_ok=True)
    except OSError as exc:
        sys.exit(f"Cannot create {root} for the emulator: {exc}")
    target = root / tag
    with install_lock(root):
        for leftover in list(root.glob(STAGING_PREFIX + "*")):
            remove_tree(leftover)
        if os.path.lexists(target):
            # Installed earlier: the launcher installs a release only after the check accepted it.
            executable = find_executable(target) if target.is_dir() and not target.is_symlink() else None
            if executable is None:
                sys.exit(f"{target} already exists but does not contain one {EXE_NAME}; it was left as it "
                         f"is. Move it elsewhere to install {tag} again.")
            check_release(check, executable, tag, str(executable), f"{target} was left as it is.")
            return executable.resolve()

        try:
            staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=root))
        except OSError as exc:
            sys.exit(f"Cannot create a staging directory in {root}: {exc}")
        try:
            archive = staging / asset
            download(url, size, sha256, archive)
            files = unpack(archive, staging)
            executable = find_executable(files)
            if executable is None:
                sys.exit(f"{asset} of release {tag} does not contain one {EXE_NAME}; nothing was installed. "
                         f"See {RELEASES_URL}.")
            print(f"Checking {EXE_NAME} from {tag}...")
            check_release(check, executable, tag, f"{EXE_NAME} from {asset}", "Nothing was installed.")
            installed = target / executable.relative_to(files)
            try:
                if asset.endswith(".AppImage"):
                    require_glibc(executable, tag)
                if os.path.lexists(target):
                    sys.exit(f"{target} appeared during the installation; it was left as it is.")
                os.rename(files, target)
            except OSError as exc:
                sys.exit(f"Cannot install the emulator in {target}: {exc}")
        finally:
            remove_tree(staging)
    print(f"Installed Eglantine {tag} in {target}.")
    return installed.resolve()


def expected_asset(system: str, machine: str) -> str:
    """The name of the official release asset for `system` (a sys.platform value) and `machine`."""
    normalized = machine.lower()
    asset = ASSETS.get((system, MACHINES.get(normalized, normalized)))
    if asset is None:
        sys.exit(f"Eglantine publishes no build for this system ({system}, {machine or 'unknown machine'}), "
                 f"only for Windows x86_64 and Linux x86_64 and aarch64. If this system can run one of "
                 f"those, download it from {RELEASES_URL} and select its {EXE_NAME}.")
    return asset


# --- GitHub ------------------------------------------------------------------------------------


class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follows redirects (GitHub sends downloads to its storage host) only to HTTPS addresses."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise urllib.error.HTTPError(newurl, code, f"refused a redirect to {newurl}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, accept: str) -> http.client.HTTPResponse:
    """Opens a public GitHub address, without credentials. Certificates are checked against certifi's
    CA bundle, which is packaged with the launcher, as for the portal."""
    context = ssl.create_default_context(cafile=certifi.where())
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), HttpsOnlyRedirects())
    headers = {"Accept": accept, "User-Agent": "PokopiaLauncher"}
    if url.startswith("https://api.github.com/"):
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    return opener.open(urllib.request.Request(url, headers=headers), timeout=TIMEOUT_SECONDS)


def http_failure(exc: urllib.error.HTTPError) -> str:
    if exc.code in (403, 429) and exc.headers.get("X-RateLimit-Remaining") == "0":
        return ("GitHub's limit on requests without an account is used up for this network; try again in "
                "an hour")
    return f"GitHub answered {exc.code} {exc.reason}"


def network_failure(exc: Exception) -> str:
    return str(getattr(exc, "reason", None) or exc)


def latest_release() -> dict:
    """The newest published release, prereleases included."""
    try:
        with _open(RELEASES_API, "application/vnd.github+json") as response:
            body = response.read(MAX_METADATA_BYTES + 1)
    except urllib.error.HTTPError as exc:
        sys.exit(f"Cannot list the Eglantine releases: {http_failure(exc)}. See {RELEASES_URL}.")
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        sys.exit(f"Cannot reach GitHub to list the Eglantine releases: {network_failure(exc)}. Check the "
                 f"internet connection and try again.")
    try:
        if len(body) > MAX_METADATA_BYTES:
            raise ValueError(f"more than {MAX_METADATA_BYTES} bytes")
        releases = json.loads(body)
        if not isinstance(releases, list):
            raise ValueError("not a list")
    except ValueError as exc:
        sys.exit(f"GitHub's list of Eglantine releases is not in the expected format ({exc}).")
    published = [release for release in releases if isinstance(release, dict) and not release.get("draft")
                 and isinstance(release.get("published_at"), str)]
    if not published:
        sys.exit(f"Eglantine has no published release yet; see {RELEASES_URL}.")
    return max(published, key=lambda release: release["published_at"])


def release_asset(release: dict, tag: str, name: str) -> tuple[str, int, str]:
    """The address, size and SHA-256 digest (hex) that GitHub publishes for asset `name` of `release`."""
    listed = release.get("assets")
    assets = [asset for asset in listed if isinstance(asset, dict)] if isinstance(listed, list) else []
    asset = next((asset for asset in assets if asset.get("name") == name), None)
    if asset is None:
        names = ", ".join(sorted(str(asset.get("name")) for asset in assets)) or "none"
        sys.exit(f"The newest Eglantine release, {tag}, has no {name} (its files: {names}). See "
                 f"{RELEASES_URL}.")
    if asset.get("state") != "uploaded":
        sys.exit(f"{name} of the newest Eglantine release, {tag}, is still being uploaded; try again in a few "
                 f"minutes.")
    url, size, digest = asset.get("browser_download_url"), asset.get("size"), asset.get("digest")
    if url != f"{DOWNLOAD_PREFIX}{tag}/{name}":
        sys.exit(f"GitHub lists {name} of release {tag} at an unexpected address ({url!r}); nothing was "
                 f"downloaded.")
    if type(size) is not int or not 0 < size <= MAX_ASSET_BYTES:
        sys.exit(f"GitHub lists {name} of release {tag} with an unexpected size ({size!r} bytes; at most "
                 f"{MAX_ASSET_BYTES} are accepted); nothing was downloaded.")
    match = SHA256_DIGEST.fullmatch(digest) if isinstance(digest, str) else None
    if match is None:
        sys.exit(f"GitHub publishes no SHA-256 digest for {name} of release {tag} ({digest!r}), so a download "
                 f"could not be verified; nothing was downloaded.")
    return url, size, match.group(1).lower()


def download(url: str, size: int, sha256: str, path: Path) -> None:
    """Downloads `url` into the new file `path`; exits unless it is `size` bytes with digest `sha256`."""
    print(f"Downloading {url} ({size / 1e6:.0f} MB)...")
    progress = sys.stdout is not None and sys.stdout.isatty()
    digest = hashlib.sha256()
    received = 0
    try:
        with _open(url, "application/octet-stream") as response, path.open("xb") as file:
            length = response.headers.get("Content-Length")
            if length is not None and length.isdigit() and int(length) != size:
                sys.exit(f"GitHub serves {url} with {length} bytes, but its release lists {size}; nothing was "
                         f"installed. Try again later.")
            while chunk := response.read(CHUNK):
                received += len(chunk)
                if received > size:
                    break
                digest.update(chunk)
                file.write(chunk)
                if progress and (received - len(chunk)) * 10 // size != received * 10 // size:
                    print(f"\r{received * 100 // size:3d}%", end="", flush=True)
    except urllib.error.HTTPError as exc:
        sys.exit(f"Cannot download {url}: {http_failure(exc)}.")
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        sys.exit(f"Cannot download {url}: {network_failure(exc)}. Check the internet connection and the free "
                 f"space in {path.parent.parent}, then try again.")
    finally:
        if progress:
            print()
    if received != size:
        sys.exit(f"The download of {url} {'is larger' if received > size else 'ended early'}: GitHub lists "
                 f"{size} bytes. Nothing was installed; try again.")
    if not hmac.compare_digest(digest.hexdigest(), sha256):
        sys.exit(f"The download of {url} does not have the SHA-256 digest GitHub publishes for it; it was "
                 f"discarded and nothing was installed. Try again; if this persists, report it at "
                 f"{RELEASES_URL}.")


# --- Unpacking ---------------------------------------------------------------------------------


class ArchiveError(Exception):
    """Release contents that cannot be unpacked safely."""


def unpack(archive: Path, staging: Path) -> Path:
    """Unpacks the verified download `archive` in `staging`, then deletes it; returns the directory with
    the release's files."""
    print(f"Unpacking {archive.name}...")
    try:
        if archive.name.endswith(".zip"):
            files = staging / "files"
            files.mkdir()
            unpack_zip(archive, files)
        else:
            files = extract_appimage(archive, staging)
        archive.unlink()
    except OSError as exc:
        sys.exit(f"Cannot unpack {archive.name} in {staging}: {exc}")
    return files


def member_parts(name: str, windows: bool = os.name == "nt") -> tuple[str, ...]:
    """The components of an archive member's path ("" and "." dropped). Refuses names that could leave
    the destination or mean something else on Windows: absolute paths, "..", backslashes, control
    characters and, on Windows, drive letters and other characters it forbids, the trailing dots and
    spaces it drops, and device names such as NUL."""
    if name.startswith("/"):
        raise ArchiveError(f"absolute path {name!r}")
    parts = tuple(part for part in name.rstrip("/").split("/") if part != ".")
    for part in parts:
        if part in ("", "..") or "\\" in part or any(ord(character) < 32 for character in part):
            raise ArchiveError(f"unsafe path {name!r}")
        if windows and (not WINDOWS_FORBIDDEN.isdisjoint(part) or part != part.rstrip(". ")
                        or part.split(".")[0].rstrip(" ").lower() in WINDOWS_DEVICES):
            raise ArchiveError(f"path {name!r} is not valid on Windows")
    return parts


class Extractor:
    """Creates archive members in `root`, a new empty directory: regular files and directories only,
    each path once, at most MAX_MEMBERS entries and MAX_EXPANDED_BYTES of content."""

    def __init__(self, root: Path, windows: bool) -> None:
        self.root = root
        self.windows = windows
        self.files: set[tuple[str, ...]] = set()
        self.directories: set[tuple[str, ...]] = set()
        self.members = 0
        self.budget = MAX_EXPANDED_BYTES

    def claim(self, name: str, directory: bool) -> Path | None:
        self.members += 1
        if self.members > MAX_MEMBERS:
            raise ArchiveError(f"more than {MAX_MEMBERS} entries")
        parts = member_parts(name, self.windows)
        if not parts:
            if directory:
                return None
            raise ArchiveError(f"file without a name ({name!r})")
        key = tuple(part.lower() for part in parts) if self.windows else parts
        if key in self.files or any(key[:n] in self.files for n in range(1, len(key))) or \
                (not directory and key in self.directories):
            raise ArchiveError(f"{name!r} is listed twice or inside a file")
        (self.directories if directory else self.files).add(key)
        self.directories.update(key[:n] for n in range(1, len(key)))
        return self.root.joinpath(*parts)

    def directory(self, name: str) -> None:
        path = self.claim(name, True)
        if path is not None:
            path.mkdir(parents=True, exist_ok=True)

    def file(self, name: str, size: int, source: BinaryIO, executable: bool) -> None:
        path = self.claim(name, False)
        if size > self.budget:
            raise ArchiveError(f"it expands to more than {MAX_EXPANDED_BYTES} bytes")
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL: never write through or over anything that exists.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags, 0o755 if executable else 0o644), "wb") as file:
            while chunk := source.read(CHUNK):
                if len(chunk) > self.budget:
                    raise ArchiveError(f"it expands to more than {MAX_EXPANDED_BYTES} bytes")
                self.budget -= len(chunk)
                file.write(chunk)


def unpack_zip(archive: Path, destination: Path, windows: bool = os.name == "nt") -> None:
    """Unpacks `archive` into the new empty directory `destination`; exits if a member is not a regular
    file or directory with a safe path, or if it expands too far."""
    extractor = Extractor(destination, windows)
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if len(members) > MAX_MEMBERS:
                raise ArchiveError(f"more than {MAX_MEMBERS} entries")
            if sum(member.file_size for member in members) > MAX_EXPANDED_BYTES:
                raise ArchiveError(f"it expands to more than {MAX_EXPANDED_BYTES} bytes")
            for member in members:
                # Only archives made on Unix record the file type; the others hold regular files.
                mode = member.external_attr >> 16 if member.create_system == 3 else 0
                kind = stat.S_IFMT(mode)
                if member.flag_bits & 0x1:
                    raise ArchiveError(f"{member.filename!r} is encrypted")
                if member.is_dir() and kind in (0, stat.S_IFDIR):
                    extractor.directory(member.filename)
                elif not member.is_dir() and kind in (0, stat.S_IFREG):
                    with bundle.open(member) as source:
                        extractor.file(member.filename, member.file_size, source, bool(mode & 0o111))
                else:
                    raise ArchiveError(f"{member.filename!r} is a link or special file")
    except (ArchiveError, zipfile.BadZipFile, EOFError, zlib.error, NotImplementedError) as exc:
        raise SystemExit(f"{archive.name} cannot be installed safely: {exc}. Nothing was installed; see "
                         f"{RELEASES_URL}.") from None


def extract_appimage(appimage: Path, staging: Path) -> Path:
    """Lets the verified `appimage` unpack itself into staging/squashfs-root; returns that directory.
    The extraction is stopped if it grows beyond MAX_MEMBERS entries or MAX_EXPANDED_BYTES, and its
    result is refused unless scan_tree accepts it."""
    files = staging / APPIMAGE_ROOT
    log = staging / "extract.log"
    appimage.chmod(0o700)
    deadline = time.monotonic() + EXTRACT_TIMEOUT_SECONDS
    try:
        with log.open("xb") as errors:
            process = subprocess.Popen([str(appimage), "--appimage-extract"], cwd=staging,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
            try:
                while True:
                    try:
                        code = process.wait(timeout=EXTRACT_POLL_SECONDS)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if time.monotonic() > deadline:
                        raise ArchiveError(f"unpacking took more than {EXTRACT_TIMEOUT_SECONDS} seconds")
                    scan_tree(files, final=False)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        if code != 0:
            detail = log.read_text(errors="replace").strip()[-500:]
            raise ArchiveError(f"it could not unpack itself (exit code {code})"
                               f"{': ' + detail if detail else ''}")
        if files.is_symlink() or not files.is_dir():
            raise ArchiveError(f"unpacking did not create {APPIMAGE_ROOT}")
        scan_tree(files, final=True)
    except ArchiveError as exc:
        raise SystemExit(f"{appimage.name} cannot be installed safely: {exc}. Nothing was installed; see "
                         f"{RELEASES_URL}.") from None
    return files


def scan_tree(root: Path, final: bool) -> None:
    """Raises ArchiveError if `root` holds more than MAX_MEMBERS entries or MAX_EXPANDED_BYTES in files,
    and, once `final`, unless every entry is a directory, a regular file without set-user-ID or
    set-group-ID, or a relative symbolic link that resolves inside `root`. While the extraction runs
    (not `final`), entries that vanish or cannot be read yet are skipped."""
    def fail(exc: OSError) -> None:
        raise exc

    real_root = os.path.realpath(root)
    entries = size = 0
    for folder, folders, files in os.walk(root, onerror=fail if final else None):
        for name in folders + files:
            path = os.path.join(folder, name)
            try:
                info = os.lstat(path)
            except OSError:
                if final:
                    raise
                continue
            entries += 1
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
            if entries > MAX_MEMBERS:
                raise ArchiveError(f"more than {MAX_MEMBERS} entries")
            if size > MAX_EXPANDED_BYTES:
                raise ArchiveError(f"it expands to more than {MAX_EXPANDED_BYTES} bytes")
            if not final or stat.S_ISDIR(info.st_mode):
                continue
            relative = os.path.relpath(path, root)
            if stat.S_ISREG(info.st_mode):
                if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise ArchiveError(f"{relative} is set-user-ID or set-group-ID")
            elif stat.S_ISLNK(info.st_mode):
                link = os.readlink(path)
                resolved = os.path.realpath(path)
                if os.path.isabs(link) or os.path.commonpath([real_root, resolved]) != real_root:
                    raise ArchiveError(f"{relative} links outside the release ({link})")
            else:
                raise ArchiveError(f"{relative} is a special file")


# --- Installation ------------------------------------------------------------------------------


def find_executable(directory: Path) -> Path | None:
    """The one emulator executable in `directory` (a regular file, outside any portable profile), or
    None if there is none or more than one."""
    windows = os.name == "nt"
    found = []
    for folder, folders, files in os.walk(directory):
        folders[:] = [name for name in folders if name != "user"]
        for name in files:
            path = Path(folder, name)
            if (name.lower() if windows else name) == EXE_NAME and not path.is_symlink() and path.is_file() \
                    and (windows or os.access(path, os.X_OK)):
                found.append(path)
    return found[0] if len(found) == 1 else None


def check_release(check: Callable[[Path], None], executable: Path, tag: str, shown_as: str,
                  outcome: str) -> None:
    """Runs `check`; if it refuses the executable, exits saying that the release is not online-capable."""
    try:
        check(executable)
    except SystemExit as exc:
        reason = str(exc.code).replace(str(executable), shown_as) if exc.code is not None else "refused"
        raise SystemExit(f"The newest published Eglantine release, {tag}, is not online-capable: {reason}\n"
                         f"{outcome} Watch {RELEASES_URL} for a release with private-server support, or "
                         f"select a compatible emulator you already have.") from None


def require_glibc(executable: Path, tag: str) -> None:
    """Exits unless this system's glibc is at least the newest version `executable` asks for: the
    AppImage bundles every library except glibc and a few other system libraries."""
    with executable.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as image:
        needed = max(((int(major), int(minor)) for major, minor in re.findall(rb"GLIBC_(\d+)\.(\d+)", image)),
                     default=None)
    if needed is None:
        return
    try:
        current = os.confstr("CS_GNU_LIBC_VERSION") or ""
    except (ValueError, OSError):
        current = ""
    match = re.fullmatch(r"glibc (\d+)\.(\d+)\S*", current)
    have = (int(match.group(1)), int(match.group(2))) if match else None
    if have is None or have < needed:
        found = f"glibc {have[0]}.{have[1]}" if have else "no glibc"
        sys.exit(f"Eglantine {tag} for Linux needs glibc {needed[0]}.{needed[1]} or newer, and this system "
                 f"has {found}. Nothing was installed; update the system or use a build made for it.")


@contextlib.contextmanager
def install_lock(root: Path) -> Iterator[None]:
    """One installation at a time in `root`. The operating system drops the lock with the process, so a
    crash leaves none behind."""
    try:
        fd = os.open(root / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        sys.exit(f"Cannot lock {root} for the installation: {exc}")
    try:
        try:
            if os.name == "nt":
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            sys.exit(f"Another launcher is installing the emulator in {root}; let it finish, then try again.")
        try:
            yield
        finally:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def remove_tree(path: Path) -> None:
    """Removes a staging directory; one that cannot be removed now is removed by the next installation."""
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"Could not remove the temporary directory {path} ({exc}); the next installation removes it, "
              f"or delete it yourself.", file=sys.stderr)
