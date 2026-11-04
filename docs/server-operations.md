# Pokopia Cloud Server: operator guide

A local stand-in for the Nintendo NPLN services that Pokémon Pokopia's Cloud Islands feature uses. It is a single Python script (`server.py`) meant to run alongside an Eglantine emulator build that can redirect DNS and trust a custom root CA.

Every TLS port (443 and 8443 by default) serves:

- gRPC over HTTP/2 for `nn.npln.auth.v1.Auth`, `nn.npln.ugcstore.v1.Ugcstore`, `nn.npln.matchmaking.v1.GameSessionService` and `nn.npln.gamesync.v1.Gamesync`. The maintenance and friends subscriptions are only kept alive. Any method without a handler gets an empty response, so the game sees default values.
- Island storage over HTTP/1.1 or HTTP/2. Uploads go to `/upload/<id>` and work like Google Cloud Storage resumable uploads. Downloads come from `/download/<id>`.

A UDP STUN responder (port 3478 by default) is the ICE server that `AllocateIceServerSet` hands out. The game's peer-to-peer (WebRTC) connections use it to gather candidates.

Message layouts follow [kinnay/NPLN-Protocols](https://github.com/kinnay/NPLN-Protocols). The module docstring at the top of `server.py` explains the protocol details.

## Tested setup

This has been tested with two emulator instances on one Windows PC, connecting to a server bound to `127.0.0.1`. The setup used Python 3.10.11, h2 4.4.1 and h11 0.16.0. It has not been tested across a LAN or over the internet. The sections below explain what those setups would need.

## Contents

| File | Purpose |
|---|---|
| `server.py` | The server |
| `portal.py` | Account portal: passkey sign-up and sign-in, and linking launchers. See [Accounts, passkeys and the launcher](#accounts-passkeys-and-the-launcher). |
| `launcher.py` | Player-side launcher for client-certificate mode: links the PC, configures a separate emulator profile, and runs the local gateway between the emulator and the server while the emulator runs. Packaged as `PokopiaLauncher.exe` for testers; see [Packaging the launcher](#packaging-the-launcher). |
| `test_gamesync_isolation.py` | Regression tests that simultaneous game sessions keep their Gamesync state apart and that deferred writes stay within the Gamesync limit and are applied |
| `test_client_auth.py` | Contract tests of client-certificate mode: what one account may do with another's data, and the resource limits |
| `test_launcher.py` | Regression tests that the launcher changes only the emulator settings it needs, only with consent and keeping the previous file, copies keys and firmware without touching their source, and refuses incompatible emulator builds |
| `snapshot.py` | Backup client that writes a consistent, verified snapshot of a running server to stdout (Linux) |
| `backup.py` | Windows bridge that streams a VPS snapshot to the configured encrypted rclone remote |
| `test_backup.py` | Regression tests that reject an unencrypted backup target and crypt configuration overrides |
| `test_snapshot.py` | Regression test that snapshots keep showing one moment while the server changes its data (Linux) |
| `requirements.txt` | Python dependencies (`h2`, `h11`) |
| `requirements-portal.txt` | Dependencies of `portal.py` (`webauthn`, `cryptography`) |
| `requirements-launcher.txt` | Dependencies of `launcher.py` (`certifi`, `cryptography`) |
| `ca.cnf` | OpenSSL config for the root CA |
| `server.cnf` | OpenSSL config for the server certificate and its host names |
| `.gitignore` | Excludes keys, certificates, `data/`, logs, caches, packaging output and `portal.txt` |

## Requirements

- Python 3.10 or newer. The code uses `contextlib.aclosing`, which was added in 3.10.
- The OpenSSL command-line tool, used to generate certificates.
- A compatible [Eglantine Online](https://github.com/Raikaru/Eglantine-Online) build with private-server support; the launcher checks for the required settings. The server alone does not provide the emulator, game files, firmware or keys.
- For client-certificate mode: `requirements-portal.txt` on the server, and on every player's PC either `PokopiaLauncher.exe` (no Python needed) or Python with `requirements-launcher.txt`.

## Setup

Run all commands from this directory. They work the same in PowerShell and in a POSIX shell, apart from the virtual environment paths.

### 1. Install dependencies

```
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

On Linux or macOS, use `python3 -m venv .venv` and `.venv/bin/python -m pip install -r requirements.txt`.

### 2. Generate your own certificates

Everyone who runs a server must create their own CA. Never reuse or share someone else's keys.

```
openssl req -x509 -new -newkey rsa:2048 -nodes -sha256 -days 3650 -config ca.cnf -keyout ca.key -out ca.crt
openssl req -new -newkey rsa:2048 -nodes -sha256 -config server.cnf -keyout server.key -out server.csr
openssl x509 -req -sha256 -days 3650 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile server.cnf -extensions v3_req -out server.crt
openssl x509 -in ca.crt -outform der -out ca.der
```

These commands produce:

- `ca.key` and `ca.crt`: the root CA, `CN=Pokopia Cloud Root CA`, with `CA:TRUE` and the `keyCertSign` and `cRLSign` key usages.
- `server.key` and `server.crt`: the server certificate, signed by that CA. It has `CA:FALSE` and the `serverAuth` and `clientAuth` extended key usages. Its subject alternative names are `*.npln.nintendo.net`, `npln.nintendo.net`, `*.npln.srv.nintendo.net`, `*.t.npln.srv.nintendo.net`, `*.lp1.t.npln.srv.nintendo.net`, `localhost` and `127.0.0.1`.
- `ca.der`: the CA certificate in DER format. This is the only file the emulators need.

By default, `server.py` loads `server.crt` and `server.key` from its own directory. Use `--cert` and `--key` to load them from somewhere else.

`ca.key` is only needed to sign server certificates. You can move it offline after step 2. If you issue a new server certificate from the same CA, clients keep working. If you create a new CA, you must give every client the new `ca.der` and remove the old one.

The module docstring in `server.py` also shows a different approach: one self-signed `CA:TRUE` certificate that serves as its own trust anchor. The tested setup used the CA-signed certificate described here instead.

Wildcards match exactly one DNS label. The server logs `TLS handshake for <name>` for every connection. If a handshake fails right after that line, the client usually rejected the certificate. Check that `<name>` is covered by the names in `server.cnf`.

### 3. Configure each emulator instance

Each instance has its own user directory, for example `%APPDATA%\eden` or a portable `user\` folder next to the executable.

1. Copy `ca.der` into `<user dir>\certs\`. Keep `ca.key` and `server.key` private; never copy them to clients.
2. Close the emulator first. It saves its settings back to the config file while it runs and when it exits. For a local server listening on port 443, set these keys in the `[Services]` section of `<user dir>\config\qt-config.ini`, substituting the absolute path to your `ca.der`:

   ```
   private_server_enabled\default=false
   private_server_enabled=true
   private_server_domains\default=false
   private_server_domains="npln.srv.nintendo.net,npln.nintendo.net"
   private_server_gateway\default=false
   private_server_gateway=127.0.0.1
   private_server_gateway_port\default=false
   private_server_gateway_port=443
   private_server_ca\default=false
   private_server_ca="<absolute path to ca.der>"
   private_server_relay\default=false
   private_server_relay=""
   ```

   Each domain entry matches that name and its subdomains. The gateway is a loopback IPv4 address;
   the configured CA is trusted for every hostname, not just these domains. For authenticated remote
   servers, use the launcher rather than configuring a remote server address as the gateway.
3. Give every instance its own emulator user profile. The id token the emulator sends is unsigned. Its `sub` claim is a hash of the profile's UUID, and the server derives the account from that claim alone. Two instances with copies of the same profile therefore appear to the server as the same account.

### 4. Run the server

```
.\.venv\Scripts\python.exe server.py
```

With no options, the server:

- listens only on `127.0.0.1`, on TCP ports 443 and 8443 (TLS) and UDP port 3478 (STUN);
- tells the game to use the STUN server at `127.0.0.1:3478`;
- stores its data in `data/` next to `server.py`.

Stop it with Ctrl+C.

The game always dials `<tenant>.lp1.t.npln.srv.nintendo.net` on port 443, so the server must listen on 443. Windows has no privileged ports, but another program may already be using 443. On Linux and macOS, ports below 1024 need root or `CAP_NET_BIND_SERVICE`.

| Option | Default | Meaning |
|---|---|---|
| `--bind ADDR` | `127.0.0.1` | Listen address for TLS, plain HTTP and STUN |
| `--port N` | 443 and 8443 | TLS port for gRPC and storage. Repeat it for several ports. The first one is the Gamesync port given to clients. |
| `--http-port N` | off | Also serve storage over plain, unencrypted HTTP |
| `--storage-url URL` | `https://storage.npln.nintendo.net` | Base URL of the upload and download URIs given to clients |
| `--cert PATH` / `--key PATH` | `server.crt` / `server.key` next to `server.py` | TLS certificate and private key |
| `--data-dir PATH` | `data` next to `server.py` | Persistent state |
| `--max-players N` | 4 | Capacity of a game session |
| `--stun HOST:PORT` | built-in responder | STUN server given to clients instead of the built-in one |
| `--stun-port N` | 3478 | UDP port of the built-in STUN responder. `0` disables it. |
| `--client-ca PATH` | off | Client-certificate mode: accept only connections with a certificate from this CA (the portal's `device-ca.crt`) and authorize every call by the account of that device. Needs `--auth-db`. Cannot be combined with `--http-port`. |
| `--auth-db PATH` | off | The portal's account database, opened read-only |
| `--gamesync-port N` | first `--port` | Gamesync port given to clients. Use 443 when clients connect through `launcher.py`. |
| `--insecure-no-auth` | off | Allow a non-loopback `--bind` without `--client-ca`. For a trusted LAN only. |
| `--max-storage-mb N` | 10240 | All Ugcstore documents, attachments and uploads together. See [Resource limits](#resource-limits). |
| `-v`, `--verbose` | off | Log every message payload |
| `--snapshot-socket PATH` | off | Unix socket that serves backup snapshots to root and the server's own user (Linux). See [Backups](#backups). |
| `--turn HOST:PORT` | off | TURN server (UDP) given to clients with credentials that expire with the ICE server set, after one hour. Needs `--turn-secret-file`. See [Relay-only mode](#relay-only-mode). |
| `--turn-secret-file PATH` | off | File holding the TURN server's `static-auth-secret`: one word of at least 16 printable ASCII characters |
| `--relay-only` | off | Deliver Gamesync session descriptions with only relay candidates on the `--turn` server. Needs `--turn` as an IPv4 address and `--turn-relay-ports`. |
| `--turn-relay-ports MIN:MAX` | off | The TURN server's relay port range (coturn `min-port` and `max-port`), the only ports `--relay-only` accepts in relay candidates |

## What is stored

`data/state.json` holds the user records, Ugcstore documents, short aliases, upload sessions and the HMAC secret that signs every token. Uploaded island data is saved as files in `data/blobs/`. Treat the whole `data/` directory as secret: anyone with the secret can create valid tokens for any user. On Linux and macOS the server runs with umask `077` and, at every start, makes `data/` and `data/blobs/` mode `0700` and `state.*` and every blob `0600`. It stops with an error if it cannot, for example because the directory belongs to another user; give it to the server's user.

Changes are written so that a crash or power loss leaves consistent data, as far as the platform promises it:

- A new or replaced file, `state.json` or a blob, is written to a temporary file, flushed to storage and then renamed over the old one, and the rename is made durable. On Linux the flush is `fsync` and the directory is flushed after the rename. On macOS the flush is `F_FULLFSYNC`, because plain `fsync` can leave data in the drive's cache. On Windows the flush is `FlushFileBuffers` and the rename is `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`, which Microsoft documents as not returning "until the file is actually moved on the disk" (a directory cannot be flushed there). A flush or sync that fails, `EIO` for example, fails the change; it is never quietly replaced by a weaker one.
- An upload chunk is flushed before the state that counts it is saved. A whole-object `PUT` writes a new backing blob and saves its ID and size only after the new file is published durably. The old blob remains available until the new state is saved; if publication fails, the prior upload can resume. Existing upload records are assigned their original blob ID at startup. If the platform cannot promise the new file is durable, the whole-object replacement fails instead of publishing a reference to it. Bytes past a resumable upload's count, left by a write whose state was never saved, are dropped when the upload goes on. An upload whose file is shorter than its count, or missing, is discarded (`410`, start again), and a complete upload whose file does not have its size is not imported (`FAILED_PRECONDITION`).
- A blob file is deleted only after `state.json` has been saved without any reference to it, and only if the platform promised that save is on disk. If the server or the machine stops between the two, the file stays behind unreferenced: it takes disk space but is never read, backed up or counted against a quota, and you can delete it by hand. The same happens on Windows when the file cannot be deleted because a download still has it open; a warning is logged.
- Limits: on a filesystem that refuses to flush a directory, or a macOS filesystem without `F_FULLFSYNC`, the server logs a warning and never deletes a blob it no longer needs, so an older state that a power loss brings back does not lose its files to a deletion; those orphans never go away by themselves. Nothing more is promised there: after a power loss, the newest state and the newest blobs it refers to may not both be on disk. Drives or virtual disks that ignore flush requests can lose recent writes on any platform.
- Cost: every save rewrites and flushes the whole `state.json`, on the event loop, so all requests wait for each flush. Saves happen on every Ugcstore commit, user sign-in, upload chunk and upload session; with a slow or busy disk this adds the flush time to each of them.

Backups do not depend on these flushes: snapshots read the files they hold open (see [Backups](#backups)).

Matchmaking sessions, creation tickets and Gamesync documents are kept in memory only. They are lost when the server restarts. Gamesync calls made with a token issued before the restart then fail with `NOT_FOUND`, because the token's user session no longer exists.

## Resource limits

These apply in every mode. The island upload seen from the game (`StageData`) was 2.8 MB.

- A gRPC message may be at most 4 MiB, also after gzip or deflate decompression, which stops as soon as the output passes that size. A unary or server-streaming request must hold exactly one message; a bidirectional call's messages that arrive together may decode to no more than the room left in its 8 MiB queue. A storage request body may be at most 32 MiB, and so may an uploaded object. An upload that would pass a limit is discarded.
- One connection may hold at most 48 MiB of request data, all connections together 256 MiB. A body counts from its first byte until its call is over, including while its response waits for the client. A bidirectional call's data counts from its first byte too, and its messages, as decoded (decompressed), until the call has read them, at most 8 MiB per call; past that the call fails, and it fails with `RESOURCE_EXHAUSTED` when decoding what arrived would take its connection or all connections past their budget. Once a call is over, even one cancelled before it started, its messages are dropped and whatever its client still sends is ignored and the stream reset. A connection may hold at most 8 open bidirectional calls. A connection whose incoming request data would break one of these limits is closed.
  Each queued bidirectional message also counts 64 bytes for its queue entry, including an empty message.
- A parsed protobuf message takes far more memory than its bytes, so every message parsed while a call is handled, the request and what the handler parses from it or from stored data, counts against the same budgets: 512 bytes, its size, and 288 bytes per field (the measured worst case is about 260). It counts until nothing holds it anymore: a subscription's request for as long as the subscription is open, a bidirectional call's latest message for as long as the handler keeps it, and nothing once a call is over or cancelled. A message may have at most 65,536 fields, nested messages each counted on their own; one with more is malformed (`INVALID_ARGUMENT`), and one that would not fit the budgets is refused while it is parsed, with `RESOURCE_EXHAUSTED`. With `--verbose`, payloads are parsed for the log within the same budgets; one that does not fit is logged as its size and first 64 bytes, so logging never changes how a call is answered. The same holds at the default log level for what Gamesync lines describe: `KeepUserSession` requests and responses, user session documents and the session descriptions in committed documents. A description that does not fit is left out of its line (`not described`, `SDP not looked for`), so a committed write is still answered as committed and a `KeepUserSession` call goes on; data that does not decode, a refused authorization, and request data the call itself cannot fit still fail the call.
- Responses wait for the client's flow-control window: at most 48 MiB per connection and 256 MiB in total, and a stream whose client grants no window for 60 seconds is reset (a connection that takes no data for 60 seconds is closed). Downloads are read from disk and sent 64 KiB at a time, at most 4 at once per connection and 256 in total, so a stalled download holds one piece, not the whole object.
- Names of users, documents, short aliases, Gamesync documents, global values, deferred writes and watch targets, and MIME types, may be at most 512 bytes. A game session's properties may be at most 64 KiB. A document field path, in a mask or a transform, may have at most 20 segments, and a Gamesync merge may go at most 20 maps deep; deeper ones fail with `INVALID_ARGUMENT`.
- All persisted data together may take `--max-storage-mb` (default 10240): users, documents and short aliases as they grow `state.json` (names, fields and 128 bytes per record), attachments and uploads. Storage also stops growing while the data disk has less than 1 GiB free. A commit may import an upload once; an imported upload that the commit's final documents do not use is deleted. Deleting a user deletes its documents, short aliases and attachments.
- One game session's Gamesync documents, global values and deferred writes, names included, may take 16 MiB in at most 4096 records. A deferment counts as its encoded bytes, so each empty write still costs the 2 bytes it takes, plus what the aliases in its names stood for when it was stored: tenant, user session and user. None of the storing call's headers are kept. A game session may have at most 64 open transactions of at most 256 documents read each. A user session may keep at most 4 `KeepUserSession` calls open, each with at most 32 watch targets of at most 64 documents. A `KeepUserSession` call whose client stops reading is ended once 32 MiB of responses wait for it.
- A Gamesync commit may copy and produce at most 32 MiB, twice what a game session holds, because it holds its results until it is over and other calls wait while it runs. Each write costs 128 bytes plus its document as staged and, for a masked update, merge or transform, the stored document it decodes. Each field transform adds its result. A nested field, in a transform, an update mask or a merge, adds every map above it that it decodes and encodes again, at its size before the write, so a deep field costs once per level. Every cost is charged before the copy is made. Past 32 MiB the commit fails with `RESOURCE_EXHAUSTED` and changes nothing.
- Deferred writes were counted against the Gamesync limit when they were stored, so they are applied outside the request budgets above. Request data held by other calls, or by the call that is ending, can't make the server drop deferred writes it already accepted. Each deferment is applied as a commit of its own, with the commit's 32 MiB copying budget and a 48 MiB budget of its own for the messages parsed while applying it, the same as one connection. Each field transform is parsed only when it is applied. One deferment is applied per turn of the server's event loop, so other calls wait for at most one at a time, and deferments still waiting count against the Gamesync limit. A deferment that needs more than either budget fails with `RESOURCE_EXHAUSTED` without costing the others anything.
- A Gamesync get, read or list operation has a 32 MiB work budget, shared by its returned documents and nested read-mask paths. The budget estimates copied data and is not a strict process-memory ceiling; operations that exceed it fail with `RESOURCE_EXHAUSTED`.
- The STUN responder answers at most 20 datagrams a second from one address and 1000 in total, and logs at most 60 lines a minute, then a count of what it suppressed and dropped. Once the minute's lines are spent it does not format any more. A line describes at most 16 attributes, with text attributes escaped and cut to 64 characters, and is cut to 1024 characters.

Client-certificate mode adds per-account limits: 16 NPLN users, 64 documents per user, 256 KiB of `state.json` (users, documents and short aliases, as above), 128 MiB of attachments and uploads, 8 unimported upload sessions (the oldest is dropped), 8 short aliases per user and 32 open connections.

## Backups

Don't copy `data/` while the server runs. Such a copy can pair `state.json` with blobs from another moment, or miss a blob that was replaced during the copy. Take snapshots through the server instead. This needs Linux.

The Windows bridge checks that its rclone destination is configured as `crypt` with encrypted
filenames and directories before sending a snapshot. It refuses crypt-related environment overrides.
The rclone configuration must remain unchanged while a backup runs.
The `public-stage` profile backs up the separate authenticated VPS deployment, including its
account database, PKI and offline ingress CA key, relay configuration and secret, Discord OAuth
client credentials and restricted outbound proxy, service units and overrides, source files,
dependency lock and proxy configuration. It uses its own snapshot
socket and does not replace the `private-test` backup task. The Windows tasks run only while the
user is logged in and may be skipped on battery. The account database snapshot is individually
consistent but not atomic with the game snapshot.

1. Start the server with `--snapshot-socket PATH`. Put the socket in a directory that only root and the server's user can enter. With systemd, in the server's unit:

   ```
   [Service]
   RuntimeDirectory=pokopia-cloud
   RuntimeDirectoryMode=0700
   ExecStart=... server.py ... --snapshot-socket /run/pokopia-cloud/snapshot.sock
   ```

2. On the same machine, as root, run `snapshot.py`. It writes a `.tar.gz` to stdout and writes nothing to disk. Add everything else a restore needs, which depends on the mode (see the table below). For client-certificate mode with the paths used in [Running a server](#running-a-server):

   ```
   python3 snapshot.py --socket /run/pokopia-cloud/snapshot.sock \
     --file systemd/pokopia-cloud.service=/etc/systemd/system/pokopia-cloud.service \
     --sqlite portal/auth.db=/var/lib/pokopia-portal/auth.db \
     --dir portal/pki=/var/lib/pokopia-portal/pki \
     --require portal/pki/device-ca.key --require portal/pki/device-ca.crt \
     --require portal/pki/ingress-ca.crt --require portal/pki/ingress.crt --require portal/pki/ingress.key \
     --file systemd/pokopia-portal.service=/etc/systemd/system/pokopia-portal.service \
     --file caddy/Caddyfile=/etc/caddy/Caddyfile > backup.tar.gz
   ```

   In local mode, replace the portal lines, from `--sqlite` to the Caddyfile, with the server's certificate, key and trust anchor, for example `--file tls/server.crt=/var/lib/pokopia-cloud/server.crt --file tls/server.key=/var/lib/pokopia-cloud/server.key --file tls/server.der=/var/lib/pokopia-cloud/server.der`. The restore steps below use these names.

   `--file NAME=PATH` adds a file as `NAME`, `--sqlite NAME=PATH` adds an SQLite database, and `--dir NAME=PATH` adds every file in a directory as `NAME/<file>`. A missing path fails the snapshot, but `--dir` takes whatever files the directory holds, so name every file a restore needs with `--require NAME`; the snapshot fails without it. `ingress-ca.key` is not required because you may keep it offline. All of these options can be repeated. `--sqlite` needs Python 3.11 or newer. A non-zero exit status means the archive is unfinished, so discard it. After `--deadline` seconds (default 1800), `snapshot.py` gives up.

| Mode | Add to the snapshot |
|---|---|
| Both | The server's systemd unit, or wherever its flags are kept |
| Local mode | The `--cert` and `--key` files, and the certificate the clients trust: `ca.der`, or for a self-signed `CA:TRUE` server certificate the certificate itself (`server.der`). Keep `ca.key` safe on its own. Without them, every client must install a new trust anchor. |
| Client-certificate mode | `auth.db` (with `--sqlite`), the whole `--pki-dir` (with `--dir`), the portal's systemd unit and the reverse proxy's configuration. Without the PKI, every launcher must link again; without `auth.db`, every account and passkey is lost and nobody owns the restored game users. |

How a snapshot stays consistent:

- Only the server's event loop thread changes `state.json` and the blobs, and it finishes each change before it awaits anything. When a client connects, the server serializes its state and opens every blob that the state refers to, in one step on that thread. The state and blobs therefore come from one moment. Campaign data is captured separately as described below. The server is never paused or stopped.
- The server sends the files afterwards and keeps serving other requests meanwhile. Whole-object uploads use a new backing blob, leaving the old file intact for snapshots; unfinished uploads only write or truncate past their recorded byte count. An open blob therefore keeps the captured bytes even if it is later replaced or deleted.
- The server sends one snapshot at a time. A second client gets `busy`. Only root and the server's own user are served, which the server checks with `SO_PEERCRED`. A client that takes no data for 5 minutes is dropped, and its blobs are closed. Because a snapshot holds every blob open, the server raises its soft open-file limit to the hard limit.
- `snapshot.py` checks every file against the server's manifest. If the state refers to a blob whose file is missing, or whose size differs from the attachment size or the received byte count that the state records, the snapshot fails: the data needs repair, and the archive would not restore it. An unfinished upload whose file holds more than it has received, which happens when the server stops before saving, is captured up to the received count. SQLite databases are copied with SQLite's backup API in one read transaction. Each copy is consistent, but it is a few moments younger than the server's data.
- `snapshot.py` checks campaign metadata and checkpoint manifests, verifies each referenced payload's size and content hash, and requires the server's separately captured `campaign_inventory` to match the files received. The server includes its campaign registry in snapshots. Campaigns and personal data are captured separately, not at one atomic instant; after restoring an account database, startup replays deletion of accounts still listed as deleted. A legacy snapshot with neither campaign files nor an inventory is still accepted, so the checker cannot distinguish that from a snapshot where both were omitted. The durable campaign API is not yet wired into the server.
- Campaign-aware servers use snapshot protocol 2. Update `snapshot.py` on the server and backup machine together with `server.py`; an older client refuses protocol 2 instead of silently omitting campaigns.

| Archive path | Contents |
|---|---|
| `data/state.json`, `data/blobs/<id>` | The server's `--data-dir`. Only blobs that the state refers to are included. |
| `data/campaigns/…` | Campaign metadata, retained checkpoints and deletion markers. |
| Names given to `--file`, `--sqlite` and `--dir` | The files and databases you added |
| `snapshot.json` | The last entry. It lists the size and SHA-256 of every file and the snapshot times. |

A snapshot contains the token signing secret and every key you added. Store it encrypted.

### Restoring

Restore everything from one archive, and start nothing until every file is back and checked. Stop at the first command that fails. The commands expect the archive at `/root/backup.tar.gz` and use the paths and service users in this guide: the server runs as `pokopia-cloud`, which belongs to the group `pokopia-portal`, and the portal runs as `pokopia-portal`. Skip the portal steps in local mode, and the local-mode steps in client-certificate mode.

1. Stop the services, so nothing writes the files being restored: `systemctl stop pokopia-cloud pokopia-portal`, or only `pokopia-cloud` in local mode.
2. Check the archive and unpack it into a private directory. `--check` fails unless every file matches `snapshot.json` and every name is a plain relative path. Give it the same `--require` options as the snapshot had, so it also fails if a file the restore needs is absent. It prints checksums for checking the unpacked files:

   ```
   install -d -m 0700 /root/restore
   python3 snapshot.py --check /root/backup.tar.gz > /root/restore.sha256
   tar -xzf /root/backup.tar.gz -C /root/restore --no-same-owner
   (cd /root/restore && sha256sum --quiet -c /root/restore.sha256)
   ```

3. Move the current state aside, if there is any, and keep it until the restored services work. Moving the portal's whole directory also moves any `auth.db-journal` aside, which SQLite would otherwise apply to the restored database. The second line is for client-certificate mode:

   ```
   mv /var/lib/pokopia-cloud /var/lib/pokopia-cloud.before-restore
   mv /var/lib/pokopia-portal /var/lib/pokopia-portal.before-restore
   ```

4. Restore the server's data:

   ```
   install -d -o pokopia-cloud -g pokopia-cloud -m 0700 /var/lib/pokopia-cloud
   cp -r /root/restore/data /var/lib/pokopia-cloud/data
   chown -R pokopia-cloud:pokopia-cloud /var/lib/pokopia-cloud/data
   chmod -R u=rwX,go= /var/lib/pokopia-cloud/data
   ```

   In local mode, also restore its certificate and key, here archived as `tls/`:

   ```
   install -o pokopia-cloud -g pokopia-cloud -m 0600 /root/restore/tls/server.key /var/lib/pokopia-cloud/
   install -o pokopia-cloud -g pokopia-cloud -m 0644 /root/restore/tls/server.crt /root/restore/tls/server.der /var/lib/pokopia-cloud/
   ```

5. In client-certificate mode, restore the portal's database and PKI. Never run `portal.py init-pki` in their place: launchers only accept the original ingress CA, and their certificates only chain to the original device CA.

   ```
   install -d -o pokopia-portal -g pokopia-portal -m 0750 /var/lib/pokopia-portal /var/lib/pokopia-portal/pki
   install -o pokopia-portal -g pokopia-portal -m 0640 /root/restore/portal/auth.db /var/lib/pokopia-portal/
   install -o pokopia-portal -g pokopia-portal -m 0644 /root/restore/portal/pki/*.crt /var/lib/pokopia-portal/pki/
   install -o pokopia-portal -g pokopia-portal -m 0640 /root/restore/portal/pki/ingress.key /var/lib/pokopia-portal/pki/
   install -o pokopia-portal -g pokopia-portal -m 0600 /root/restore/portal/pki/device-ca.key /var/lib/pokopia-portal/pki/
   ```

   If the archive holds `ingress-ca.key`, install it like `device-ca.key`, or keep it offline.
6. Compare the archived configuration with the installed one, or install it on a new machine (then `systemctl daemon-reload`). Only the first line applies in local mode. Here a difference does not stop the restore, but the installed files must keep the archived values of these settings: the portal's `--rp-id` and `--origin`, because passkeys are bound to them; `--ingress-host`, `--ingress-port` and `--ingress-name`, because launchers saved them; and the Caddy site name, which DNS must point at this machine.

   ```
   diff /root/restore/systemd/pokopia-cloud.service /etc/systemd/system/pokopia-cloud.service
   diff /root/restore/systemd/pokopia-portal.service /etc/systemd/system/pokopia-portal.service
   diff /root/restore/caddy/Caddyfile /etc/caddy/Caddyfile
   ```

7. Check the restored files, their owners and modes, and that each service user can read what it needs. Every command must succeed, and the last one must print `ok`:

   ```
   diff -r /root/restore/data /var/lib/pokopia-cloud/data
   diff -r /root/restore/portal/pki /var/lib/pokopia-portal/pki
   cmp /root/restore/portal/auth.db /var/lib/pokopia-portal/auth.db
   ls -la /var/lib/pokopia-cloud /var/lib/pokopia-portal /var/lib/pokopia-portal/pki
   runuser -u pokopia-cloud -- cat /var/lib/pokopia-portal/auth.db /var/lib/pokopia-portal/pki/ingress.key > /dev/null
   runuser -u pokopia-portal -- python3 -c "import sqlite3; print(sqlite3.connect('file:/var/lib/pokopia-portal/auth.db?mode=ro', uri=True).execute('PRAGMA integrity_check').fetchone()[0])"
   ```

   In local mode, run only the first line, `ls -la /var/lib/pokopia-cloud`, and `cmp /root/restore/tls/server.key /var/lib/pokopia-cloud/server.key` and the same for `server.crt` and `server.der`.
8. Start the portal, then the server: `systemctl start pokopia-portal`, then `systemctl start pokopia-cloud`. In local mode, start only `pokopia-cloud`. Check `journalctl -u pokopia-portal -u pokopia-cloud`.
9. The restored `auth.db` undoes every account change made after the backup. Repeat the ones that locked someone out, such as `portal.py disable`, `revoke-device` and account deletions.
10. Once the services work, delete the unencrypted copies: `rm -r /root/restore /root/restore.sha256 /root/backup.tar.gz`. Delete the `.before-restore` directories once you no longer need them.

`test_snapshot.py` checks snapshots while the data changes. Run it on Linux with `python3 -m unittest test_snapshot`.

## Several islands at once

Each game session has its own Gamesync documents, global values, transactions and deferred writes, so several islands can be open at the same time. The game names Gamesync documents without their session, for example `docs/__gs/f`. The server therefore takes the session from the user session that the caller's Gamesync token was issued for. That user session must still be in its game session and belong to the token's user.

- Players in the same game session share all of its Gamesync state. Players in other sessions can't read, change or watch it.
- A Gamesync call never falls back to another session. Without a valid Gamesync token it fails with `UNAUTHENTICATED`. Once its user session has left the game session, it fails with `NOT_FOUND`. An open `KeepUserSession` call fails each later request the same way.
- When a player leaves a session that still has other players, their open `KeepUserSession` call ends first. Their deferred writes are then queued, and once they are applied, the documents named after their user session are deleted, even if a deferred write fails. Until then, the remaining players still see those documents.
- A player's deferred writes are also queued when their `KeepUserSession` call ends, however much request data the server holds at the time. Queued deferments are applied in the order their names were first stored, one per turn of the server's event loop, so other calls can run between them. Other players may see the session before a player's deferments are applied, and a later `DefermentOperation` can no longer change or delete them. A deferment that fails is logged and dropped with none of its writes, and the player's other deferments are still applied. It may fail on a malformed write, a failed precondition, a session over its Gamesync limit or either of the budgets above. If the last player leaves before queued deferments are applied, they are dropped with the rest of the session's Gamesync state.
- In Gamesync names, `users/current` stands for the user of the call's gamesync token, so each player of an island names their own documents. Deferred writes resolve `userSessions/current`, `users/current` and the other aliases in their names as they did when they were stored. They still change the same documents after the tokens of the call that stored them expire, 8 hours after they were issued.
- When the last player leaves, all of the session's Gamesync state is deleted.
- `QueryGameSessions` only returns sessions whose properties match the string entries of its filter: an `f_<name>` entry with a string matches property `<name>` with the same string. The game finds an island's session this way, by the `string1` property its host set. Filter entries without a string (`f_sys_lock`, `f_int1` and so on) are not evaluated, because their meaning is unknown.

Several islands at once have not been tested with the game. `test_gamesync_isolation.py` uses simulated clients to check the separation, as well as the limit and application of deferred writes. That includes deferments that fail, that copy too much, that each fit a commit but copy more together, or that need more than their parsing budget. It also covers deferments applied one at a time while still counting against the limit, still queued when the session ends, or applied after their tokens expire. Run it with `.\.venv\Scripts\python.exe -m unittest test_gamesync_isolation`.

## Network exposure

### Same PC (tested, default)

Clients on the same machine can connect, and nothing else can.

### LAN (untested)

What the code requires:

- Run the server with `--bind 0.0.0.0 --insecure-no-auth --stun <server-lan-ip>:3478`. Without `--stun`, a server bound to `0.0.0.0`, `::` or `""` still tells clients to use STUN at `127.0.0.1:3478`, which points each remote client at its own machine. The server refuses a non-loopback `--bind` without `--client-ca` unless `--insecure-no-auth` acknowledges that everyone on the network can then act as any user.
- Alternatively, use `--bind <server-lan-ip> --insecure-no-auth`. The server then tells clients to use that address for STUN, but it stops listening on `127.0.0.1`. An emulator on the server PC must then also redirect to the LAN IP.
- This LAN configuration also requires a compatible per-client loopback gateway: private-server mode does not accept the LAN address as its gateway. The launcher is intended for client-certificate mode; the insecure LAN setup has not been verified with the current emulator build.
- Allow inbound TCP 443 and 8443 and UDP 3478 through the server's firewall.
- Game traffic goes directly between players over UDP, using WebRTC. The server only exchanges session descriptions and answers STUN requests. Without `--turn` it offers no TURN relay, so players' machines must be able to send UDP to each other directly.

### Internet

Use [client-certificate mode](#accounts-passkeys-and-the-launcher). Without it, every endpoint is reachable by anyone and the authentication problems below apply to strangers. Without a TURN relay, players whose NATs block direct UDP between them cannot connect, and players learn each other's addresses; see [Relay-only mode](#relay-only-mode). A game join through the public service has been checked on one PC; a join across separate networks has not.

### Relay-only mode

With `--turn`, `AllocateIceServerSet` also hands out a TURN server (field 3 of the `IceServerSet`: host, port, protocol UDP, username, password). The credentials follow the TURN REST API scheme that coturn checks with `use-auth-secret`: the username is `<expiry>:<id>` and the password is `base64(HMAC-SHA1(secret, username))`. `<expiry>` is the Unix time one hour ahead, when the ICE server set runs out. coturn refuses expired credentials for new allocations but keeps allocations already made with them. In client-certificate mode `<id>` is derived from the account, so the TURN server's log can tie allocations to an account without naming it. In local mode it is random for each set, and anyone who reaches the server gets credentials. The secret is read from `--turn-secret-file` so it stays out of the process list, and is never logged. `-v` does not dump `AllocateIceServerSet` responses, and the INFO line names the username only.

`--relay-only` filters every Gamesync document on its way to a player: `GetDocument`, `ReadDocuments`, `ListDocuments`, the documents a `KeepUserSession` target lists, change notifications, and the values field transforms return. What is stored does not change. Documents without signaling markers (`candidate`, `raddr`, `rport`, `IN IP4`/`IN IP6`, `typ host|srflx|prflx|relay`, `v=<digit>`) are delivered unchanged. In the others, every string or bytes value that starts with an SDP version line is rebuilt line by line:

- A candidate is kept only if it is a UDP `relay` candidate whose address is exactly the `--turn` IPv4 address and whose port is within `--turn-relay-ports`. Its `raddr`/`rport`, the player's own address as the TURN server saw it, become `0.0.0.0`/`0`. Of its extensions only `generation`, `ufrag`, `network-id` and `network-cost` stay. A relay candidate with any other address is dropped too, because a malicious player could name their own machine as a "relay".
- `o=` keeps its session id and version with address `0.0.0.0`, `s=` becomes `-`, `c=` becomes `IN IP4 0.0.0.0`, and `m=` ports become 9 (0 stays 0). `v=`, `t=`, `b=`, empty lines and the attributes `ice-ufrag`, `ice-pwd`, `ice-options`, `ice-lite`, `ice-mismatch`, `setup`, `fingerprint`, `mid`, `group`, `sctp-port`, `max-message-size`, `tls-id`, `end-of-candidates`, `rtcp-mux`, `rtcp-rsize`, `extmap-allow-mixed` and the direction attributes are kept when they parse. Every other line, including `a=rtcp`, `a=remote-candidates`, unknown attributes and `i=`, `u=`, `e=`, `p=`, `z=`, `k=` and `r=`, is dropped.
- A whole description is dropped, and its value becomes null, if it is over 64 KiB or 256 lines, has a control or non-ASCII character, has a second `v=` line, or has an `o=` or `m=` line that does not parse.
- Any other string or bytes value that contains a marker is also replaced with null. This includes a lone `candidate:` line, SDP that does not start with `v=`, and binary payloads that embed candidate text. Null also replaces values that hold a marker but do not have the shape a peer would read the same way: a value with several fields, a map with a repeated key or an entry with extra fields, or a value nested more than 16 maps or arrays deep. A dropped value keeps its map key or array index.

When filtering a changed document runs out of the writer's request budget, the change is sent to no one, and the `KeepUserSession` calls it was for end with `RESOURCE_EXHAUSTED`. In relay-only mode the INFO line for a committed session description counts the candidates written and lists only the ones delivered.

Example (the coturn host's public IPv4 address `203.0.113.10` is a placeholder). The secret file must be readable only by the server's user:

```sh
openssl rand -hex 32 > /etc/pokopia-cloud/turn-secret && chmod 600 /etc/pokopia-cloud/turn-secret
```

`turnserver.conf`. The relay address must be the address clients see, so give coturn no `external-ip` mapping that differs from `--turn`:

```
listening-ip=203.0.113.10
relay-ip=203.0.113.10
listening-port=3478
min-port=49160
max-port=49200
use-auth-secret
static-auth-secret=<the contents of /etc/pokopia-cloud/turn-secret>
realm=pokopia.example.org
fingerprint
no-tcp-relay
no-multicast-peers
no-cli
```

```sh
venv/bin/python server.py --bind 0.0.0.0 --port 8443 --gamesync-port 443 \
  --client-ca /var/lib/pokopia-portal/pki/device-ca.crt --auth-db /var/lib/pokopia-portal/auth.db \
  --cert /var/lib/pokopia-portal/pki/ingress.crt --key /var/lib/pokopia-portal/pki/ingress.key \
  --stun-port 0 \
  --turn 203.0.113.10:3478 --turn-secret-file /etc/pokopia-cloud/turn-secret \
  --relay-only --turn-relay-ports 49160:49200
```

`--stun-port 0` disables the built-in STUN responder. With `--turn`, the game can obtain relay candidates without a separate `--stun` advertisement; the public same-PC game join was tested this way. Open UDP 3478 and the relay port range on the coturn host.

What relay-only mode does not do:

- **It is not complete privacy.** The players' games still gather host and server-reflexive candidates, and send connectivity checks from them to the relay addresses they receive. Those checks reach the TURN server. coturn forwards them only to an allocation that has a permission for the sender's address, which another player would first have to learn some other way.
- Only session descriptions are rewritten, and markers are searched for as plain text. Non-SDP fields are passed on unchanged unless they contain a marker. Addresses that the game or a modified client sends in any other form are not detected, for example base64, compressed, or binary-packed data. Such signaling has not been ruled out.
- Ugcstore documents, game session properties, document names and `KeepUserSession` echoes are not filtered.
- A player can name any relay port in the range, including another player's allocation. coturn drops what it sends there unless that allocation has a permission for its address.
- The server operator still sees players' addresses: TLS connections, STUN and TURN traffic, and the server log. `-v` dumps every request, including unfiltered session descriptions, so don't use it for a public test. TURN over UDP sends the username unencrypted, so an observer on the path can link one account's allocations.
- Any account the server accepts can use the relay for its own traffic, within coturn's limits. Consider coturn's `user-quota`, `total-quota` and `denied-peer-ip` for the host's private ranges.
- Two game instances on one PC joined the same island through the authenticated public service using both the relay-restricted tester build and the generic private-server build; guest movement was visible on the host. A real-game join and IP-privacy verification across separate networks remain untested.

## Accounts, passkeys and the launcher

A public test registered a passkey, linked a launcher, obtained usable TURN credentials through
its mTLS gateway, and joined two game instances on one PC to the same Cloud Island. A join
across separate networks remains unverified.

Client-certificate mode lets strangers play on an internet server. It has three parts:

- `portal.py`, a web page where players create an account with a passkey or, if enabled by the operator, Discord, and link their PCs to it.
- `launcher.py`, which runs on each player's PC (packaged as `PokopiaLauncher.exe`, so players need no Python). Linking creates a key that stays on that PC and gets a certificate for it from the portal. The launcher's gateway listens on `127.0.0.6:443`. The emulator connects to it as it would to a local server, and the gateway relays each connection unchanged to the server over TLS with that certificate.
- `server.py --client-ca ... --auth-db ...`, which refuses connections without a certificate from the portal and authorizes every call by the account behind it.

### Running a server

The example uses `pokopia.example.org`. Passkeys are bound to that name (the WebAuthn RP ID): use a host name you will keep, because changing it makes every passkey unusable. Use a dedicated name, not a domain's apex, so the passkeys belong to this service alone.

1. Point a DNS `A` record for the name at the server.
2. Install the dependencies: `python3 -m venv venv` and `venv/bin/pip install -r requirements.txt -r requirements-portal.txt`.
3. Create the certificates once. `init-pki` never overwrites them:

   ```
   venv/bin/python portal.py init-pki --pki-dir /var/lib/pokopia-portal/pki --ingress-name pokopia.example.org
   ```

   `device-ca.key` signs launcher certificates and stays with the portal. `server.py` needs `device-ca.crt`, `ingress.crt` and `ingress.key`. Launchers trust `ingress-ca.crt`, which the portal hands them while linking. `ingress-ca.key` is only needed to issue a new ingress certificate, so keep it offline.
4. Run the portal. It creates the database on first start:

   ```
   venv/bin/python portal.py serve --db /var/lib/pokopia-portal/auth.db --pki-dir /var/lib/pokopia-portal/pki --rp-id pokopia.example.org --origin https://pokopia.example.org --ingress-host pokopia.example.org --ingress-port 8443
   ```

   It listens on `127.0.0.1:8780` over plain HTTP. Browsers only offer passkeys on HTTPS, so put a reverse proxy with a publicly trusted certificate in front of it. With Caddy, the whole `Caddyfile` is:

   ```
   pokopia.example.org {
   	reverse_proxy 127.0.0.1:8780
   }
   ```

   The portal believes `X-Forwarded-For` only from `--trusted-proxy` addresses (default `127.0.0.1` and `::1`) and rate-limits by that address: 10 sign-ups per hour, 30 sign-ins per 10 minutes and 120 requests per minute. Registration is open, within two caps that hold across all networks: at most `--max-accounts` enabled accounts (default 1000; disabled and deleted accounts do not count) and at most `--max-signups-per-day` new accounts in 24 hours (default 50). An account that has not linked a launcher 7 days after it was created never reached the server, so it is removed and its place freed. `--closed` stops new accounts.

   Optional Discord sign-in is off unless both `--discord-client-id-file PATH` and
   `--discord-client-secret-file PATH` are supplied. Create a Discord application with the sole
   redirect URI `https://pokopia.example.org/auth/discord/callback`. Give the portal user read access
   to the ID file and exclusive access to the secret file (mode `0600` on POSIX); do not put the
   secret in a command line, source repository, or request log. Back up the secret securely along
   with the portal configuration. If outbound access is restricted, allow HTTPS to Discord through
   an appropriately restricted HTTP CONNECT proxy and set `--discord-proxy http://host:port`.
   The inbound reverse proxy must not log OAuth callback query strings.

   The portal requests only Discord's `identify` scope. It retains the numeric Discord ID, not the
   Discord password or OAuth tokens; Discord can also return basic profile fields, which are discarded.
   A Discord identity is never matched to an existing account automatically: sign in with its passkey
   and explicitly link Discord. Keep a backup passkey; losing the only sign-in method locks the
   account out. Discord login relies on the security of the player's Discord account.
   Starting this portal against a version 1 database migrates it to version 2, even when Discord is
   disabled. Back up the account database first. Older portal versions cannot open the migrated
   database; restoring an older backup also rolls back account and device changes made since that backup.

5. Run the server with the ingress certificate and the account database:

   ```
   venv/bin/python server.py --bind 0.0.0.0 --port 8443 --gamesync-port 443 --stun <public-ip>:3478 --cert /var/lib/pokopia-portal/pki/ingress.crt --key /var/lib/pokopia-portal/pki/ingress.key --client-ca /var/lib/pokopia-portal/pki/device-ca.crt --auth-db /var/lib/pokopia-portal/auth.db
   ```

   Run the portal as user and group `pokopia-portal`, and make the server's user a member of that group. The portal runs with umask `027`, so `auth.db` is mode `0640`; `init-pki` makes `pki/` `0750`, `device-ca.key` and `ingress-ca.key` `0600`, and `ingress.key` `0640`, so the server can read the database and its key through the group but not the CA keys. The database uses a rollback journal, so read access is enough for the server.
6. Open TCP 443 (portal), TCP 8443 (server) and UDP 3478 (STUN). STUN answers anyone; consider a firewall rate limit for UDP 3478 too, and cap the journal or log size (for example `SystemMaxUse=` in `journald.conf`).

`portal.py accounts --db ...` lists accounts. `portal.py disable --db ... <account>` and `portal.py revoke-device --db ... <device>` lock out an account or one launcher; the server closes their connections within 30 seconds. `portal.py delete --db ... <account>` removes an account with its passkeys and launchers and leaves a tombstone, from which the server deletes the account's NPLN users, documents, short aliases, attachments and upload sessions within a minute. Deletion cannot be undone except from a backup.

### Playing

A player needs a Windows PC, their own copy of the game and their own decryption keys (and firmware, if the game needs it). They need neither Python nor any manual configuration:

1. Unpack the folder from the operator (see [Packaging the launcher](#packaging-the-launcher)) somewhere you can write to, such as the Desktop. Keep `PokopiaLauncher.exe` and `eglantine.exe` in the same folder.
2. Double-click `PokopiaLauncher.exe`. If Windows says it protected your PC, choose **More info**, then **Run anyway**.
3. The first time, the browser opens the portal. Create an account with a passkey or sign in, check that the fingerprint matches the one in the launcher window, and approve this PC.
4. The launcher sets up the emulator. If you already use Eden, yuzu, citron, suyu or sudachi, it offers to copy your keys and firmware from it. Then it asks once for your game file.
5. The game starts. Keep the launcher window open while you play; it closes when you close the emulator.

Later, double-clicking `PokopiaLauncher.exe` starts the same game straight away. Nothing else may listen on `127.0.0.6:443`.

Without a command, the launcher runs `play`, which does this, in order, and stops with the reason at the first step that fails (the window stays open until you press Enter):

1. It links this PC if it is not linked yet or its certificate has expired. The portal address comes from `--portal`, else from the `portal.txt` packaged with the launcher, else it asks for it.
2. It connects to the server once as this PC. If the server cannot be reached, it stops. If the server refuses the certificate (revoked or expired device, disabled account), it offers to link again.
3. It finds the emulator: `--emulator`, else `eglantine.exe` next to the launcher, else the one used last time, else it asks. It requires the private-server DNS redirect, custom CA, private-server account token and relay-only network restriction. It also refuses to go on while that emulator is running, because the emulator saves its settings when it exits.
4. It uses the `user\` folder next to the emulator as a separate profile, and creates the folder if needed. An emulator with a `user\` folder next to it uses that instead of `%APPDATA%\eden`, so no other profile changes. It copies the gateway CA to `user\certs\pokopia-launcher-gateway-ca.der` and sets `airplane_mode=false`, `private_server_enabled=true`, `private_server_domains="npln.srv.nintendo.net,npln.nintendo.net"`, `private_server_gateway=127.0.0.6`, `private_server_ca` to the CA path, and `private_server_relay` to the operator's relay policy in `[Services]`, each with its `\default=false` line. The relay policy comes from `--relay` or packaged `relay.txt`; a missing or invalid policy stops the launcher. A missing file is created. An existing one is changed only after the launcher lists the changes and you agree; the previous file is kept as `qt-config.ini.before-pokopia-<time>`.
5. If the profile has no `keys\prod.keys` or no firmware, it offers to copy `keys\*.keys` and `nand\system\Contents\registered\` from the first of `%APPDATA%\eden`, `yuzu`, `citron`, `suyu` and `sudachi` that has `keys\prod.keys`. It copies nothing else, such as games, saves or user profiles, and changes nothing in the source. Otherwise it tells you to use the emulator's **Tools > Install Decryption Keys** and **Tools > Install Firmware**. The profile is separate, so a game update installed in another profile is missing here; install it with **File > Install Files to NAND** if the game needs it.
6. It asks for the game file (Cancel opens the emulator without a game) and remembers the emulator and the game in `%LOCALAPPDATA%\PokopiaLauncher\play.json`.
7. It starts the gateway on `127.0.0.6:443`, then `eglantine.exe -g <game>`, and stops the gateway when the emulator exits. If Windows cannot start the emulator because a DLL is missing, it says to install the Microsoft Visual C++ Redistributable (x64).

With Python instead of the packaged launcher: `py -3 -m pip install -r requirements-launcher.txt`, then `py -3 launcher.py play --portal https://pokopia.example.org`. The other commands are `link`, `configure --user-dir <user dir>` (sets up any emulator user directory, such as `%APPDATA%\eden`, as in step 4), `run` (only the gateway) and `status`.

The experimental `campaign_bridge.py` is not connected to this launcher and does not enable shared
story progression. Its mailbox can read the patched game's unique-quest journal, stopping on lost
entries or a foreign read cursor; neither relay sends those events yet. Its Windows `GameProcess`
requires the main address from the **current** emulator process's `user\log\eden_log.txt`. A stale
address can misdirect guest-memory reads; the alignment check rejects some stale addresses, not all.

The launcher checks the portal's certificate against the CA bundle of `certifi`, not the Windows certificate store. That store can hold an expired cross-signed intermediate, such as the ISRG Root X2 one that expired in 2025, which makes Python's OpenSSL 1.1.1 reject a certificate that browsers accept.

The launcher keeps its keys in `%LOCALAPPDATA%\PokopiaLauncher`. On Windows they are encrypted with a passphrase that Windows (DPAPI) protects for the current user; elsewhere the directory is mode `0700`. A certificate is valid for 180 days (`portal.py serve --device-days`). Linking again creates a new device; revoke old ones on the portal. Add a backup passkey on the portal: an account with no remaining sign-in method cannot be recovered.

A browser session lasts 30 minutes and only while the credential it signed in with stays registered. Adding or removing a passkey, changing a Discord link, and approving a launcher need a sign-in within the last 10 minutes. The portal rechecks the session inside the account-change transaction. Linking or unlinking Discord requires a recent passkey sign-in; the last sign-in method cannot be removed. Removing a sign-in method ends sessions and pending launcher approvals that used it, and can also revoke launchers approved with it. The account page shows the sign-in method used to approve each launcher.

### Packaging the launcher

Build `PokopiaLauncher.exe` on Windows, from this directory, in PowerShell. `portal.txt` holds the portal address and `relay.txt` holds the TURN IPv4 address, listener port and allowed allocation port range. These must match the server and coturn configuration; the example address is a placeholder:

```
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-launcher.txt pyinstaller
Set-Content -NoNewline -Encoding ascii portal.txt https://pokopia.example.org
Set-Content -NoNewline -Encoding ascii relay.txt "203.0.113.10:3478,49160-49200"
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onefile --console --name PokopiaLauncher --add-data "portal.txt;." --add-data "relay.txt;." launcher.py
```

The result is `dist\PokopiaLauncher.exe`. PyInstaller also packages Python, `cryptography`, Tk (for the file dialogs) and `certifi`'s CA bundle. The executable is not signed, so Windows SmartScreen warns about it.

For players, put `PokopiaLauncher.exe` in one folder with a compatible `eglantine.exe` and the emulator's license and source notice, and zip it. Never add a `user\` folder, keys, firmware, games or saves. A compatible build has the generic `private_server_*` settings and the private-server account token; the older tester-specific build is not compatible with this launcher. The emulator build needs the Microsoft Visual C++ runtime (`MSVCP140*.dll`, `VCRUNTIME140*.dll`). Players who do not have it installed get a message from the launcher. Alternatively, put the DLLs from Visual Studio's `VC\Redist\MSVC\<version>\x64\Microsoft.VC143.CRT\` next to `eglantine.exe`.

### What the server enforces

- The TLS handshake needs a certificate from the device CA, and that device must be in the database, neither revoked nor expired, with its account enabled.
- Every token the server issues (access, refresh, matchmaking and Gamesync) names the account it was issued to, and only works on that account's connections.
- NPLN users belong to the account that created them, at most 16 per account. `IssuePrearrangedUserToken` and `CreateUser` derive the user from the account and the emulator profile, because the id token's unsigned `sub` only tells apart the profiles of one account. `IssueToken` only serves existing users of the caller's account. Users created in local mode have no account, so they are refused; they are not migrated automatically. Anonymous users are refused.
- Ugcstore: an account reads and writes the documents of its own users (`tenants/<t>/documents/users/<u>/...`). Of other accounts' documents it can read the `public/` ones, `private/SessionIDData` when the request's rule context holds the password from the owner's `private/PasswordData` (the game does this when joining a Cloud Island), and the owner's `private/StageData` and its attachment URI for 10 minutes after that or while it is an island member. An island member is an account with a user in a game session that hosts the island (see Matchmaking), whose game still keeps that session (as long as its user session would not be dropped), and that joined it under the owner's current island password. Every write, other attachment URI and short alias (at most 8 per user), and every other document, is the owner's alone, except for a Cloud Island save (below). These rules follow what the game was seen doing; the real service's rules are not public. They take the account from the connection, not from a bearer token.
- Cloud Island save: any player with the island's address and password may play on it even while its owner is away, and when the owner leaves while others are on it, the game hands hosting to one of them ([Nintendo's Cloud Island guide](https://en-americas-support.nintendo.com/app/answers/detail/a_id/71373)). Whoever hosts saves the island to the owner's documents: one commit updates `private/StageData`, imports the host's own upload as its attachment and updates `public/MetaData`, with the island's `sessionID` and `password` as the commit's rule context (the owner's game sends the same rule context with its own saves). A commit by another account may therefore make exactly these writes, update `private/StageData` and `public/MetaData` and import an upload into `private/StageData`, when the account is an island member and the rule context holds the owner's current island password. These documents need not exist yet, as an island whose owner left before its first save has no `StageData`. The password counts as a guess like any other, once per commit. Deletes, field transforms, direct attachments and every other document, including `PasswordData` and `SessionIDData`, stay the owner's alone. The island's growth counts against the owner's quotas; the imported upload leaves the host's.
- Storage: an upload URI only works for the account that asked for it. An attachment downloads for its document's owner, or, when it is that island's `private/StageData`, for a visitor with a current password grant or an island member. Both are checked again on download; a grant ends on expiry or password change, membership when the user leaves the session or the password changes. Writes are refused beyond the [resource limits](#resource-limits).
- Matchmaking: a request may only name users of the calling account, and creation tickets are only visible to the account that created them. The game finds a Cloud Island's game session by its `string1` property, `:` and the island's `sessionID` from the owner's `private/SessionIDData`, and whoever opens the island, its owner or a visitor while the owner is away, creates the session with it. So a new session hosts the island whose `sessionID` its `string1` names, among those of the creator's own users and those the creator gave the current password of within the last 10 minutes; a session that names none of them is taken to host the creator's island. A game session is only visible, to `QueryGameSessions`, `GetGameSession` and `JoinGameSession`, to an account that has a user in it, that owns the island it hosts, or that gave that island's current password within the last 10 minutes. The password of another member's island does not count. The session's properties hold the island's session id, which otherwise only the password-protected `private/SessionIDData` reveals. `JoinGameSession` also checks the session password for newcomers, and only accounts with a user in a session see its password.
- A grant from a right island password (finding the island's session, reading its `StageData`) and island membership end when the owner changes or removes the password.
- Wrong island and session passwords count against the guessing account (10 per 10 minutes), its network (30 per 10 minutes; an IPv4 address or an IPv6 /64) and the island or session (60 per hour). Once a count is full, further guesses that it covers are refused until its oldest entry is older than its window, so a lockout ends at most one window after the guessing stops. An account that gave the island's or session's current password within the last 30 days does not count against, and is not held back by, that island's or session's count; its account and network counts still apply, and a new password ends this. The game's island password looked like 6 letters and digits; at 60 guesses an hour per island, guessing it takes centuries.

Not yet verified with the game: the gateway relay; hiding sessions and their passwords from accounts without the island password (if the game searches or compares differently, joining fails); the document rules, including Cloud Island saves by a visitor who hosts while the owner is away or after the owner handed hosting over (such commits were seen refused before these rules allowed them, not yet accepted), and that the game never needs to write the owner's `SessionIDData` then; whether the owner's game gives the session password when it joins its own island hosted by a visitor; and that the game sends a bearer token wherever one is required (`ValidateToken`, `ListUsers`, `DeleteUser`, and matchmaking calls that name no user, such as `ListUserSessions` for a game session).

Client-certificate mode does not fix these:

- Password counts and grants are kept in memory, so they start over when the server restarts.
- **Island members can overwrite the island.** Any player who joined a Cloud Island's session with its password may save the island, as the game lets any of them host it, also while the owner is away, so such a player can also replace its `StageData` and `MetaData` with anything. Changing the island password ends this for everyone who joined under the old one; backups are what undo it.
- **Guessing can lock new visitors out of an island.** Anyone who registers several accounts, or uses several networks, can keep an island's count full, and then visitors who have not given its current password in the last 30 days are refused, even with the right password, until the guessing stops. A per-island count is what keeps distributed guessing slow; without it, every new account and network would add guesses. This is a tradeoff of open registration and shared limits, not solved here: the protocol offers no challenge or proof of work to tell people from scripts. Raising or lowering the count only moves the balance.
- **Sign-ups can be used up.** Someone who registers `--max-signups-per-day` accounts, from as many networks as the per-address limit requires, stops sign-ups for that day, and accounts that link a launcher are not pruned, so over time they can fill `--max-accounts` until an operator disables or deletes them. Open registration cannot tell legitimate players from such accounts. For an operator-controlled service, run with `--closed` and open registration only while expected players sign up.
- Game traffic and STUN go directly between players over UDP, so players learn each other's IP addresses, unless [relay-only mode](#relay-only-mode) is used, within the limits listed there.
- Anything that can copy a launcher's key, or connect to its gateway on `127.0.0.6`, acts as that account. This includes malware and other users of the same PC.
- The emulator trusts the gateway CA for every host name, as it does `ca.der`. The launcher discards the gateway CA's private key as soon as it has signed the gateway certificate.

## Security limitations

In local mode, that is without `--client-ca`, the server authenticates nobody. Only expose it to people you trust, or use [client-certificate mode](#accounts-passkeys-and-the-launcher), which addresses the first four points below.

- **Anyone can get a token for any user.** `IssueToken` issues a token for whatever user name the client asks for. `CreateUser` and `IssuePrearrangedUserToken` take the account from the `sub` claim of the client's id token, and that token's signature is never checked, so a client can claim any account. The emulator's own token uses `alg: none`.
- **Documents are open to everyone.** `GetDocument` and `CommitDocuments` don't check who is calling. Any client can read, overwrite or delete any user's island documents by name. `DeleteUser` deletes any user record without a token.
- **Island separation is not access control.** Gamesync keeps each game session's data apart, but matchmaking checks nobody. `JoinGameSession` ignores session passwords and accepts any user name, so anyone who can reach the server can join any session and then read and change its Gamesync documents.
- **Storage URLs work for anyone who has them.** `/upload/<id>` and `/download/<id>` need no authentication. The ids are 20 random characters from a 32-character alphabet, so they can't be guessed, but `IssueAttachmentUri` doesn't check the caller either. Any client can ask it for the download URL of any document's attachment.
- **Resource limits are coarse.** The [resource limits](#resource-limits) bound memory and disk, but in local mode they are shared by everyone, so one client can use up the storage quota or the in-flight budget of all.
- **Logs contain personal data.** They record user names, tenant ids, peer IP addresses and the ICE candidates in session descriptions. `-v` also logs every payload, including tokens. Don't publish logs.
- **The CA is trusted for every host name.** An emulator that trusts `ca.der` accepts any certificate signed by `ca.key`, for any host name, in any title. `ca.cnf` sets no name constraints, and name constraints have not been tested with the game. Keep `ca.key` private, and only install a `ca.der` from someone you trust.
- **Plain HTTP is unencrypted.** `--http-port` serves island storage without TLS.

## Never share or commit

`*.key`, `*.crt`, `*.der`, `*.csr`, `*.srl`, `data/` (including `state.json`, `blobs/` and the signing secret), the portal's account database (`*.db`), snapshot archives (`*.tar.gz`), `*.log` and `__pycache__/`. The included `.gitignore` excludes all of them.

## License

The code in this repository is licensed under the GNU General Public License, version 3 or (at
your option) any later version. See [LICENSE](../LICENSE). Dependencies are distributed under their
own licenses. The repository does not grant rights to Pokémon, Nintendo, game files, firmware or keys.
