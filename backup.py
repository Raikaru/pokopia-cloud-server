#!/usr/bin/env python3
r"""Back up the Pokopia VPS into this PC's encrypted rclone remote.

The VPS holds no cloud credentials. This script asks it over SSH for a snapshot: snapshot.py, run
as root there, takes the game server's consistent snapshot, adds the files of the chosen profile,
checks everything and sends a .tar.gz. A snapshot whose state refers to a missing blob fails. The
archive streams straight into the rclone crypt remote, so no plaintext copy is written to this
disk. It is uploaded as <name>.tar.gz.partial, read back through crypt and compared with the bytes
sent, and only then renamed to <name>.tar.gz. A failed run deletes nothing but its own .partial
upload. Old backups are never deleted.

--profile names the deployment the VPS runs, and so what a complete backup of it holds (PROFILES).
It has no default and ends the archive name, so a backup never quietly leaves part of a deployment
out; a listed file that is missing fails the backup, and so does a damaged game blob.
  private-test  the game server alone, reached through an SSH tunnel: its data, its TLS certificate
                and key (server.der, the same certificate, is the trust anchor its clients
                install) and its systemd unit
  portal        the public deployment: the game server's data and unit, plus the account portal's
                database, PKI (which holds the game server's TLS key too), systemd unit and Caddy
                configuration. Every PKI file a restore needs is required; only ingress-ca.key,
                which may be kept offline, is optional.
  public-stage  separate authenticated VPS deployment, including the offline ingress CA key,
                service units, application source and dependency lock, and proxy configuration.

This script's HOST, DESTINATION and PROFILES are specific to one deployment; adapt and review them
before using it elsewhere. It needs Python 3.8 or newer, ssh and rclone on PATH. To run it every
6 hours without a console window, enter this in cmd.exe after replacing PYTHONW and PROJECT_DIR.
The interactive task only runs while this user is logged in; Windows' default power settings also
skip starts on battery and may stop a running backup if the PC switches to battery.
Keep the private-test task and create a separate task with --profile public-stage for the
isolated authenticated deployment.

    schtasks /Create /TN "Pokopia VPS backup" /SC HOURLY /MO 6 /IT /F /TR "\"PYTHONW\" \"PROJECT_DIR\backup.py\" --profile private-test"

Results go to backup.log next to this file. To restore, copy a backup to the VPS without writing it
to this disk, again in cmd.exe, then follow the Backups section of docs/server-operations.md:

    rclone cat gdrive-crypt:Pokopia-Server-Backups/<name>.tar.gz | ssh fates-vps "umask 077 && cat > /root/backup.tar.gz"
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

HOST = 'fates-vps'
SNAPSHOT = ['python3', '/opt/pokopia-server/snapshot.py', '--socket', '/run/pokopia-cloud/snapshot.sock',
            '--file', 'systemd/pokopia-cloud.service=/etc/systemd/system/pokopia-cloud.service']
PUBLIC_SNAPSHOT = ['python3', '/opt/pokopia-public/app/snapshot.py',
                   '--socket', '/run/pokopia-public/snapshot.sock',
                   '--file', 'systemd/pokopia-public.service=/etc/systemd/system/pokopia-public.service']
# What snapshot.py adds for each deployment, besides the game server's data and unit.
PROFILES = {
    'private-test': [
        '--file', 'tls/server.crt=/var/lib/pokopia-cloud/server.crt',
        '--file', 'tls/server.key=/var/lib/pokopia-cloud/server.key',
        '--file', 'tls/server.der=/var/lib/pokopia-cloud/server.der',
    ],
    'portal': [
        '--sqlite', 'portal/auth.db=/var/lib/pokopia-portal/auth.db',
        '--dir', 'portal/pki=/var/lib/pokopia-portal/pki',
        # The PKI a restore cannot do without; ingress-ca.key may be kept offline.
        '--require', 'portal/pki/device-ca.key', '--require', 'portal/pki/device-ca.crt',
        '--require', 'portal/pki/ingress-ca.crt', '--require', 'portal/pki/ingress.crt',
        '--require', 'portal/pki/ingress.key',
        '--file', 'systemd/pokopia-portal.service=/etc/systemd/system/pokopia-portal.service',
        '--file', 'caddy/Caddyfile=/etc/caddy/Caddyfile',
    ],
    'public-stage': [
        '--sqlite', 'portal/auth.db=/var/lib/pokopia-public/portal/auth.db',
        '--dir', 'portal/pki=/var/lib/pokopia-public/portal/pki',
        '--require', 'portal/pki/device-ca.key', '--require', 'portal/pki/device-ca.crt',
        '--require', 'portal/pki/ingress-ca.crt', '--require', 'portal/pki/ingress.crt',
        '--require', 'portal/pki/ingress.key',
        '--file', 'portal/offline-ca/ingress-ca.key=/var/lib/pokopia-public/offline-ca/ingress-ca.key',
        '--file', 'systemd/pokopia-public-portal.service=/etc/systemd/system/pokopia-public-portal.service',
        '--file', 'systemd/pokopia-public-registration.conf=/etc/systemd/system/pokopia-public-portal.service.d/registration.conf',
        '--file', 'systemd/pokopia-discord-proxy.service=/etc/systemd/system/pokopia-discord-proxy.service',
        '--file', 'portal/discord-client-id=/var/lib/pokopia-public/portal/discord-client-id',
        '--file', 'portal/discord-client-secret=/var/lib/pokopia-public/portal/discord-client-secret',
        '--file', 'discord-proxy/tinyproxy=/opt/pokopia-discord-proxy/usr/bin/tinyproxy',
        '--file', 'discord-proxy/tinyproxy.conf=/opt/pokopia-discord-proxy/tinyproxy.conf',
        '--file', 'discord-proxy/allowlist=/opt/pokopia-discord-proxy/allowlist',
        '--file', 'systemd/pokopia-public-proxy.service=/etc/systemd/system/pokopia-public-proxy.service',
        '--file', 'systemd/pokopia-public-relay.conf=/etc/systemd/system/pokopia-public.service.d/relay.conf',
        '--file', 'systemd/pokopia-public-ingress.socket=/etc/systemd/system/pokopia-public-ingress.socket',
        '--file', 'systemd/pokopia-public-ingress.service=/etc/systemd/system/pokopia-public-ingress.service',
        '--file', 'systemd/pokopia-turn.service=/etc/systemd/system/pokopia-turn.service',
        '--file', 'relay/turn.conf=/etc/pokopia-relay/turn.conf',
        '--file', 'relay/secret=/var/lib/pokopia-public/server/relay/secret',
        '--file', 'caddy/Caddyfile=/opt/pokopia-proxy/Caddyfile',
        '--file', 'application/server.py=/opt/pokopia-public/app/server.py',
        '--file', 'application/portal.py=/opt/pokopia-public/app/portal.py',
        '--file', 'application/snapshot.py=/opt/pokopia-public/app/snapshot.py',
        '--file', 'application/requirements.txt=/opt/pokopia-public/app/requirements.txt',
        '--file', 'application/requirements-portal.txt=/opt/pokopia-public/app/requirements-portal.txt',
        '--file', 'application/requirements.lock=/opt/pokopia-public/requirements.lock',
        '--file', 'application/SOURCE=/opt/pokopia-public/app/SOURCE',
    ],
}
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
       '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4']
DESTINATION = 'gdrive-crypt:Pokopia-Server-Backups'
RCLONE = ['rclone', '--contimeout', '15s', '--timeout', '60s']
DEADLINE_SECONDS = 1800  # every child process still running after this is killed
CHUNK_SIZE = 1 << 20
LOG = Path(__file__).with_name('backup.log')
# Keeps ssh and rclone from opening console windows under pythonw.
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


class Run:
    """The child processes of one backup; past the deadline all are killed and no more start."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.children: list[subprocess.Popen] = []
        self.expired = False
        self.timer = threading.Timer(DEADLINE_SECONDS, self.expire)
        self.timer.daemon = True
        self.timer.start()

    def start(self, args: list[str], **kwargs) -> subprocess.Popen:
        with self.lock:
            if self.expired:
                raise RuntimeError(f'the backup ran longer than {DEADLINE_SECONDS} seconds')
            child = subprocess.Popen(args, creationflags=NO_WINDOW, **kwargs)
            self.children.append(child)
            return child

    def expire(self) -> None:
        with self.lock:
            self.expired = True
            self.kill()

    def kill(self) -> None:
        for child in self.children:
            if child.poll() is None:
                child.kill()
        for child in self.children:
            child.wait()

    def finish(self) -> None:
        self.timer.cancel()
        with self.lock:
            self.kill()

    def rclone(self, *args: str) -> None:
        with tempfile.TemporaryFile() as errors:
            child = self.start([*RCLONE, *args], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=errors)
            if child.wait() != 0:
                raise RuntimeError(f'rclone {args[0]} failed: {text(errors)}')

    def upload_snapshot(self, profile: str, target: str) -> tuple[str, int, str]:
        """Streams a snapshot from the VPS into `target`: its SHA-256, size and SSH warnings."""
        command = shlex.join([*(PUBLIC_SNAPSHOT if profile == 'public-stage' else SNAPSHOT),
                              *PROFILES[profile]])
        with tempfile.TemporaryFile() as ssh_errors, tempfile.TemporaryFile() as rclone_errors:
            ssh = self.start([*SSH, HOST, command], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=ssh_errors)
            upload = self.start([*RCLONE, 'rcat', target], stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=rclone_errors)
            digest, size = hashlib.sha256(), 0
            while chunk := ssh.stdout.read(CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
                upload.stdin.write(chunk)
            if ssh.wait() != 0:
                # Raising before rclone sees the end of its input keeps the upload unfinished.
                raise RuntimeError(f'snapshot failed: {text(ssh_errors)}')
            upload.stdin.close()
            if upload.wait() != 0:
                raise RuntimeError(f'upload failed: {text(rclone_errors)}')
            return digest.hexdigest(), size, text(ssh_errors)

    def read_back(self, target: str) -> tuple[str, int]:
        """Reads `target` back through crypt, which decrypts and authenticates it."""
        with tempfile.TemporaryFile() as errors:
            child = self.start([*RCLONE, 'cat', target], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=errors)
            digest, size = hashlib.sha256(), 0
            while chunk := child.stdout.read(CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
            if child.wait() != 0:
                raise RuntimeError(f'read-back failed: {text(errors)}')
            return digest.hexdigest(), size


def text(stream) -> str:
    stream.seek(0)
    return stream.read().decode('utf-8', errors='replace').strip()


def report(stream, message: str) -> None:
    if stream:  # None under pythonw
        print(message, file=stream)


def require_encrypted_destination() -> None:
    """Refuse to stream secrets unless the configured destination is the expected crypt remote."""
    remote = DESTINATION.partition(':')[0]
    prefix = f"RCLONE_CONFIG_{remote.upper().replace('-', '_')}_"
    if any(key.upper().startswith((prefix, 'RCLONE_CRYPT_')) for key in os.environ):
        raise RuntimeError('rclone crypt environment overrides are not allowed for backups')
    result = subprocess.run([*RCLONE, 'config', 'dump'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                            creationflags=NO_WINDOW, check=False)
    if result.returncode:
        raise RuntimeError('cannot read rclone configuration; backup not started')
    try:
        config = json.loads(result.stdout)[remote]
        valid = (config.get('type') == 'crypt'
                 and config.get('filename_encryption', 'standard') == 'standard'
                 and str(config.get('directory_name_encryption', 'true')).lower() == 'true'
                 and bool(config.get('password')) and bool(config.get('remote')))
    except (ValueError, KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise RuntimeError('backup destination is not configured as an encrypted rclone crypt remote')


def main() -> None:
    logging.basicConfig(filename=LOG, level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    parser = argparse.ArgumentParser(description='Back up the Pokopia VPS into the encrypted rclone remote.')
    parser.add_argument('--profile', required=True, choices=PROFILES,
                        help='the deployment on the VPS, which decides what the backup holds')
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        if exc.code:
            logging.error('Backup not started: invalid arguments %s', sys.argv[1:])
        raise
    name = f'{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(6)}-{args.profile}.tar.gz'
    partial, final = f'{DESTINATION}/{name}.partial', f'{DESTINATION}/{name}'
    run = Run()
    upload_started = False
    try:
        require_encrypted_destination()
        run.rclone('mkdir', DESTINATION)
        upload_started = True
        sha256, size, warnings = run.upload_snapshot(args.profile, partial)
        if run.read_back(partial) != (sha256, size):
            raise RuntimeError('the encrypted upload does not read back as the bytes sent')
        run.rclone('moveto', partial, final)
    except BaseException as exc:
        logging.exception('Backup failed')
        run.finish()
        # Only this run's uniquely named .partial object is ever deleted.
        if upload_started:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run([*RCLONE, 'deletefile', partial], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300,
                               creationflags=NO_WINDOW, check=False)
        report(sys.stderr, f'Backup failed: {exc}')
        sys.exit(1)
    run.finish()
    if warnings:
        logging.warning('VPS reported: %s', warnings)
        report(sys.stderr, f'VPS reported: {warnings}')
    logging.info('Verified encrypted backup %s (%d bytes, sha256=%s)', final, size, sha256)
    report(sys.stdout, f'Verified encrypted backup: {final}')


if __name__ == '__main__':
    main()
