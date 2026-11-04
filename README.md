# Pokopia Cloud Server

A self-hosted replacement for the NPLN services used by Pokémon Pokopia's Cloud Islands. It provides matchmaking, island storage, a STUN responder and an optional account portal. It does **not** provide Nintendo's official services, game files, firmware or keys.

**Status:** Experimental. Two game instances have joined the same island on one PC, including through the public service. A successful join across separate networks is not established. The original-story co-op components are unfinished and are not a playable feature.

## Requirements

- Python 3.10 or newer and OpenSSL.
- A compatible [Eglantine Online](https://github.com/Raikaru/Eglantine) build with private-server support.
- Your own game, decryption keys and any required firmware.
- For public hosting: a domain, HTTPS, and the account portal and launcher dependencies.

## Getting started

Install the server dependencies from this directory:

```sh
python -m venv .venv
# Windows: .venv\Scripts\python.exe -m pip install -r requirements.txt
# Linux/macOS: .venv/bin/python -m pip install -r requirements.txt
```

[Generate a server certificate and CA, configure the emulator, and start the server](docs/server-operations.md#setup). That guide also covers [public hosting with accounts and passkeys](docs/server-operations.md#accounts-passkeys-and-the-launcher), [backups and restore](docs/server-operations.md#backups), and [network and relay configuration](docs/server-operations.md#network-exposure).

## Security

- Without client-certificate authentication the server **does not authenticate users**. Keep it on loopback or a trusted network; use client-certificate mode for public hosting.
- Players' IP addresses can be exposed without relay-only mode. See the guide's [relay and security limitations](docs/server-operations.md#security-limitations).
- Keep certificates' private keys, account databases, `data/`, backups and logs private. The data directory contains a signing secret; verbose logs can contain tokens and player information.

## Main files

- `server.py` — game service, storage, matchmaking and STUN.
- `portal.py` — accounts, passkeys and device enrollment.
- `launcher.py` — player-side account linking and local gateway.
- `snapshot.py` and `backup.py` — server snapshots and backup transport. `backup.py` is configured for one deployment; review its host, paths and profiles before reuse.
- `campaign_*.py` — experimental, incomplete story co-op research; the durable campaign API is not wired into the server.
- `test_*.py` — regression tests.

Protocol message layouts follow [kinnay/NPLN-Protocols](https://github.com/kinnay/NPLN-Protocols).

## License

The code in this repository is licensed under the GNU General Public License, version 3 or (at your option) any later version. See [LICENSE](LICENSE). Dependencies have their own licenses. This license does not grant rights to Pokémon, Nintendo, game files, firmware or keys.
