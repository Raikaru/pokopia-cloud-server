"""HTTP routes of durable shared story campaigns (campaign_store.CampaignRegistry): creating and
sharing them, and committing and reading their checkpoints, for the portal account behind a
client-certificate connection.

NOT WIRED IN. server.py does not dispatch to CampaignApi, and must not until three integrations
exist; without them a campaign could outlive its owner's deleted account, escape the storage quota,
or come back from a backup without anyone allowed to use it:
  * Backups: server.py's snapshots include the whole registry (CampaignRegistry.capture_backup:
    metadata, every retained checkpoint, tombstones and purge markers), not only state.json and blobs.
  * Quotas: campaign bytes (CampaignStore.usage) count against Storage.room_for's per-account and
    --max-storage-mb limits; the store applies only its own max_campaign_bytes and min_free_bytes.
  * Account deletion: purge_deleted_accounts calls CampaignRegistry.purge_account for every deleted
    account that CampaignRegistry.accounts() names.

Wiring, for server.py once they exist:
  * Dispatch: a request whose target is_campaign_api() goes to `await CampaignApi.handle(method,
    target, headers, body, principal)` instead of Storage.handle, with the connection's Principal
    (None in local mode, which authenticates nobody and is refused everything) and the header dict
    the transports build (lower-case names). The result has server.Response's fields (status,
    headers, body, stream); one with a stream is sent like a blob download (send_file,
    send_file_http1), counted against MAX_DOWNLOADS_PER_CONNECTION and MAX_DOWNLOADS, and whoever
    sends it closes the file (ApiResponse.close() if it is never sent).
  * Bodies: body_limit(method, target), for a target is_campaign_api() accepts, is the most body
    bytes the route takes: MAX_COMMIT_REQUEST_BYTES (server.py's MAX_STORAGE_REQUEST_BYTES, 32 MiB)
    for a commit, 0 for every other route. A transport may refuse a longer Content-Length before
    buffering anything; the transports already refuse bodies over MAX_STORAGE_REQUEST_BYTES and
    count them in MAX_BUFFERED_BYTES until the response is sent.
  * Threads: handle() runs prepare() on the event loop, then execute() in `executor` (None: the
    loop's default executor; a dedicated ThreadPoolExecutor with a few workers bounds how much disk
    and inflate work runs at once). prepare() parses and checks the request without touching the
    disk, and only it calls host_session, the one place that may read server state. execute() calls
    only the registry, with a frozen CampaignRequest of strings, numbers and read-only views of the
    immutable body: it reads and changes no object of the event loop. If handle() is cancelled
    while execute() runs, the work finishes in the worker (a commit lands) and a download's file is
    closed there.
  * host_session(principal, session) -> HostSession | None, called on the event loop for commits
    only, once the request parsed: the connection's principal and the name of the game session
    the commit says it comes from. It answers HostSession(account, session, campaign) only if a
    live game session of that name exists (after Backend.prune_sessions), its creator's user
    session is in it and belongs to principal.account (as CampaignLive.hosts), and the session is
    bound to the durable campaign `campaign` (a CampaignRegistry ID) by a record made explicitly for
    that campaign, never inferred from other state; else None. The commit goes on only if the answer
    is a HostSession of the principal's account, the session the commit names and the campaign of
    its path. Anything else, None, another type, another account, session or campaign, refuses it
    with 403 not_host, and an exception with 503 unavailable, so a missing or broken check fails
    closed. The registry then still requires the account to own or be a member of the campaign,
    checked under the campaign's lock with the commit.

Protocol. Every route needs an authenticated principal whose account is a registry account ID
(401 unauthenticated otherwise). No route takes a query (400), and only a commit has a body (400).
Responses are JSON (application/json, cache-control: no-store) unless named otherwise; a refusal is
{"error": <code>, "message": <text>} plus the fields named below. ETags are strong and quoted: the
SHA-256 hex of a campaign's metadata (CampaignInfo.etag) or of a checkpoint's manifest
(Checkpoint.etag), or of a payload's bytes.

  GET    /campaigns                                    200 {"campaigns": [Campaign]}, by ID
  POST   /campaigns                                    201 Campaign; ETag, Location: /campaigns/<id>
  GET    /campaigns/<id>                               200 Campaign; ETag
  DELETE /campaigns/<id>                   If-Match    204; owner only; every checkpoint goes too
  PUT    /campaigns/<id>/members/<account> If-Match    200 Campaign; ETag; owner only
  DELETE /campaigns/<id>/members/<account> If-Match    200 Campaign; ETag, or 204 if <account> is
                                                       the caller (leaving); the owner removes any
                                                       member, a member only itself
  GET    /campaigns/<id>/checkpoint                    200 {"checkpoint": Checkpoint or null}; ETag
                                                       if there is one
  POST   /campaigns/<id>/checkpoint  If-Match or       201 {"checkpoint": Checkpoint}; ETag; 200 if
                                     If-None-Match: *  the commit changed nothing; host only
  GET    /campaigns/<id>/checkpoints                   200 {"checkpoints": [Checkpoint]}, the
                                                       retained ones, newest first
  GET    /campaigns/<id>/checkpoints/<revision>/story        200 application/octet-stream, the
  GET    /campaigns/<id>/checkpoints/<revision>/unique       payload; ETag "<its SHA-256>",
  GET    /campaigns/<id>/checkpoints/<revision>/stages/<n>   X-Checkpoint-ETag "<checkpoint etag>"

  Campaign   = {"campaign", "role": "owner" | "member", "owner", "members": [account, ...],
                "revision", "etag", "created", "updated"}  (CampaignInfo; times are Unix seconds)
  Checkpoint = {"campaign", "revision", "etag", "parent": etag | null, "created", "author",
                "story": {"sha256", "size"}, "unique": {"sha256", "size"},
                "stages": {"<n>": {"sha256", "size", "raw_size"}, ...}}  (campaign_store.Checkpoint)

Path segments: <id> is ID_LENGTH (26) characters of ID_ALPHABET, the IDs CampaignRegistry.create
draws; <account> an account ID (1 to 512 printable ASCII characters without spaces) percent-encoded
as one segment; <revision> and <n> (a stage number, 0 to 99) are decimal without leading zeros.
Targets have at most MAX_TARGET_CHARS characters (400). A payload's bytes are checked against its
manifest before they are sent; a client checks its SHA-256 against the Checkpoint it fetched.

Preconditions, all explicit (428 precondition_required when missing; 400 when malformed; 412
precondition_failed with the current "etag", null for none, when not current):
  * Adding a member: If-Match with the metadata's etag; If-Match: * is refused, so a stale or
    replayed invitation cannot bring back a member removed since.
  * Deleting a campaign, removing a member: If-Match with the metadata's etag, or If-Match: * to
    take access away whatever changed meanwhile.
  * Committing: If-Match with the newest checkpoint's etag, or If-None-Match: * for a campaign's
    first checkpoint; If-Match: * is refused, so no commit replaces a checkpoint it did not see. The
    412 also has the current "revision".

A commit's body (Content-Type: application/vnd.pokopia.campaign-commit, else 415), as
encode_commit() writes and parse_commit() reads it: the 4-byte big-endian length of a JSON header
of at most MAX_COMMIT_HEADER_BYTES (16 KiB) UTF-8 bytes, the header, then the payloads back to back
with exactly the sizes it declares and nothing after them. The header is
  {"session": <game session name, 1-512 printable ASCII>,
   "story": 9061 | null, "unique": 1024 | null,        both or neither: one common save's story
                                                       block and unique quest history; null keeps
   "stages": {"<n>": <size of STGDATnn.BIN> | null}}   null drops the stage; unnamed stages are kept
with no other key, no key twice and JSON integers only. The payloads follow in the order story,
unique, then the stages with a size by ascending number. The whole body has at most
MAX_COMMIT_REQUEST_BYTES; a stage file at most the store's max_stage_bytes (413 too_large).
campaign_store checks the payloads themselves (400 bad_payload, 413 too_large, 507
quota_exceeded).

Error codes: 400 bad_request, bad_payload; 401 unauthenticated; 403 forbidden (a member asking what
only the owner may, or the owner leaving), not_host, account_purged; 404 not_found; 405
method_not_allowed (with Allow); 409 too_many_campaigns, too_many_members, member_unavailable (a
purged account); 412 precondition_failed; 413 too_large; 415 unsupported_media_type; 428
precondition_required; 500 damaged (stored data fails its checks), storage_error (with "committed":
true, false or null as StorageError.committed; read the campaign to find out), internal; 503 busy
(Retry-After), unavailable; 507 quota_exceeded.

Non-disclosure: 404 not_found has one body for a campaign that does not exist, was deleted, is not
shared with the caller, has an ID of the wrong shape or damaged metadata, for a revision or stage
that is not retained, and for a path under /campaigns that names no route. A damaged checkpoint
(500) or a failing disk (500, 503) is told only to an account that may see the campaign, which a
fresh registry.get decides; anyone else gets 404, or 503 unavailable when that cannot be decided
now. not_host is decided before any lookup, from the caller's own game session alone, so it answers
alike for every well-formed campaign ID; a host whose session is bound to a campaign it may not use
gets 404 like anyone else.

Limits of these protections:
  * The host check is a moment on the event loop before the worker commits: a host that leaves the
    session, or loses its binding, after it still lands that commit. Only the registry's ACL is
    checked under the campaign's lock with the commit. The binding's integrity, who may bind which
    session to which campaign, is the host_session implementation's.
  * Lock waits and 503 busy can show anyone who knows a campaign's ID (a removed member) that it is
    in use. IDs carry 130 random bits and are never reused, so nobody finds one by guessing.
  * Owner and members see the campaign's owner, members and checkpoint authors (account IDs).
    Members are opaque IDs: they are not checked against the portal's accounts, and there is no
    acceptance step, so an owner may list any ID, bounded by max_owned and max_members. Adding a
    purged account tells the owner it was purged (409 member_unavailable).
  * Revocation does not reach back: a download whose files were opened before it finishes.
  * POST /campaigns is not idempotent: a retry after a lost response makes another campaign
    (bounded by max_owned). A commit is: a retry after a lost response is refused 412 if the first
    attempt landed, and the newest checkpoint's author and payload hashes tell whether it was it. A
    commit handed to the worker lands even if its client goes away meanwhile.
  * Every request that names a well-formed campaign ID makes the store keep a lock file for that ID
    (.locks/<id>.lock, empty, kept forever), whether the campaign exists or not, so an authenticated
    account can grow .locks/ by one file per request with a new ID; request rates are server.py's.
  * One request carries a whole commit, so a checkpoint within a few KiB of the store's 32 MiB
    max_checkpoint_bytes cannot be committed here: the frame must fit MAX_COMMIT_REQUEST_BYTES.
  * Transports keep one value per header name, so a precondition given twice is not noticed.
  * Damaged campaign metadata answers 404 even to the owner (fail closed); the store's warnings in
    the log are how an operator finds it.
  * Logs name the method, route, account, status and error code, never bodies, session names or
    member IDs (campaign_store logs IDs of its own changes). A damaged campaign or failing disk is
    logged with the store's message (IDs and paths); an unexpected exception with its type and stack
    only.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
import traceback
import types
from concurrent.futures import Executor
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Mapping, Optional
from urllib.parse import unquote

import campaign_store as cs

log = logging.getLogger("npln.campaign.api")

PREFIX = "/campaigns"
COMMIT_MEDIA_TYPE = "application/vnd.pokopia.campaign-commit"
MAX_COMMIT_REQUEST_BYTES = 32 * 1024 * 1024  # server.py MAX_STORAGE_REQUEST_BYTES: one request body
MAX_COMMIT_HEADER_BYTES = 16 * 1024  # server.py MAX_LIVE_REQUEST_BYTES: a commit's JSON header
COMMIT_LENGTH_BYTES = 4  # the big-endian length of that header, before it
MAX_SESSION_NAME_BYTES = 512  # server.py MAX_NAME_BYTES: game session names
MAX_TARGET_CHARS = 2048  # a percent-encoded account ID takes up to 1536
MAX_PRECONDITION_CHARS = 128  # an If-Match or If-None-Match value
MAX_MESSAGE_CHARS = 300  # of a campaign_store PayloadError message passed on to the client
NOT_FOUND = "no such campaign, or it is not shared with this account"

CAMPAIGN_SEGMENT = re.compile(rf"[{cs.ID_ALPHABET}]{{{cs.ID_LENGTH}}}")
REVISION_SEGMENT = re.compile(r"[1-9][0-9]{0,19}")
STAGE_SEGMENT = re.compile(r"0|[1-9][0-9]?")  # 0 to MAX_STAGE_NUMBER, in paths and commit headers
assert cs.MAX_STAGE_NUMBER == 99
PCHAR_SEGMENT = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+")  # RFC 3986 segment-nz
ETAG = re.compile(r'"([0-9a-f]{64})"')
COMMIT_KEYS = frozenset({"session", "story", "unique", "stages"})

# Route kinds by path shape, the methods each takes, and the route each pair names.
ALLOW = {"campaigns": ("GET", "POST"), "campaign": ("GET", "DELETE"), "member": ("PUT", "DELETE"),
         "checkpoint": ("GET", "POST"), "checkpoints": ("GET",), "payload": ("GET",)}
ROUTES = {("campaigns", "GET"): "list", ("campaigns", "POST"): "create", ("campaign", "GET"): "get",
          ("campaign", "DELETE"): "delete", ("member", "PUT"): "add_member", ("member", "DELETE"): "remove_member",
          ("checkpoint", "GET"): "head", ("checkpoint", "POST"): "commit", ("checkpoints", "GET"): "history",
          ("payload", "GET"): "payload"}
METHODS = frozenset(method for methods in ALLOW.values() for method in methods)
FORBIDDEN = {"delete": "only the campaign's owner deletes it",
             "add_member": "only the campaign's owner adds members",
             "remove_member": "only the campaign's owner removes other members, and it cannot leave, only delete"}


# --- Results -----------------------------------------------------------------------------------


@dataclass
class ApiResponse:
    """server.Response's fields, so that server.py sends it as one, and the error code it logs.
    A response with a `stream` (file, offset, length) has its body in that file; whoever sends it
    closes the file, and close() does so for one that is never sent."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes
    stream: Optional[tuple[BinaryIO, int, int]] = None
    outcome: str = field(default="ok", compare=False)

    def close(self) -> None:
        if self.stream is not None:
            self.stream[0].close()


class ApiError(Exception):
    """A refused request: its HTTP status, the error code a client acts on, a message for people,
    and the further fields of its JSON body and headers."""

    def __init__(self, status: int, code: str, message: str, extra: Mapping[str, object] | None = None,
                 headers: tuple[tuple[str, str], ...] = ()):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = dict(extra or {})
        self.headers = headers

    def response(self) -> ApiResponse:
        return json_response(self.status, {"error": self.code, "message": self.message, **self.extra}, self.headers,
                             outcome=self.code)


def json_response(status: int, payload: dict, headers: tuple[tuple[str, str], ...] = (),
                  outcome: str = "ok") -> ApiResponse:
    body = json.dumps(payload, separators=(",", ":")).encode()
    return ApiResponse(status, [("content-type", "application/json"), ("content-length", str(len(body))),
                                ("cache-control", "no-store"), *headers], body, None, outcome)


def no_content() -> ApiResponse:
    return ApiResponse(204, [("cache-control", "no-store")], b"")


def not_found() -> ApiError:
    return ApiError(404, "not_found", NOT_FOUND)


def quoted(etag: str) -> str:
    return f'"{etag}"'


def campaign_doc(info: cs.CampaignInfo, account: str) -> dict:
    """A campaign's metadata as the routes answer it (Campaign), for `account`."""
    return {"campaign": info.campaign, "role": info.role(account), "owner": info.owner, "members": list(info.members),
            "revision": info.revision, "etag": info.etag, "created": info.created, "updated": info.updated}


def checkpoint_doc(checkpoint: cs.Checkpoint) -> dict:
    """A checkpoint's manifest as the routes answer it (Checkpoint)."""
    return {"campaign": checkpoint.campaign, "revision": checkpoint.revision, "etag": checkpoint.etag,
            "parent": checkpoint.parent, "created": checkpoint.created, "author": checkpoint.author,
            "story": {"sha256": checkpoint.story.sha256, "size": checkpoint.story.size},
            "unique": {"sha256": checkpoint.unique.sha256, "size": checkpoint.unique.size},
            "stages": {str(number): {"sha256": stage.sha256, "size": stage.size, "raw_size": stage.raw_size}
                       for number, stage in sorted(checkpoint.stages.items())}}


# --- Requests ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class HostSession:
    """host_session's answer for a game session that the caller's account hosts right now."""

    account: str  # the account of the session's creator, who hosts it
    session: str  # the game session's name
    campaign: str  # the durable campaign (CampaignRegistry ID) the session is bound to


HostSessionCheck = Callable[[object, str], Optional[HostSession]]


@dataclass(frozen=True)
class CommitFrame:
    """A commit's parsed body: read-only views of the request body, nothing copied."""

    session: str
    story: memoryview | None
    unique: memoryview | None
    stages: Mapping[int, memoryview | None]  # read-only; None drops the stage


@dataclass(frozen=True)
class CampaignRequest:
    """A parsed request that execute() serves, holding nothing of the event loop's."""

    method: str
    route: str  # a value of ROUTES
    account: str  # the principal's
    campaign: str | None = None
    member: str | None = None
    # delete, add_member, remove_member: the metadata's etag, or None for If-Match: *. commit: the
    # newest checkpoint's etag, or None for If-None-Match: * (no checkpoint yet).
    if_match: str | None = None
    revision: int | None = None
    part: str | None = None  # payload: "story", "unique" or "stage"
    stage: int | None = None
    commit: CommitFrame | None = None


def is_campaign_api(target: str) -> bool:
    """Whether an HTTP request target names a campaign route (PREFIX) instead of storage."""
    path = target.partition("?")[0]
    return path == PREFIX or path.startswith(PREFIX + "/")


def body_limit(method: str, target: str) -> int:
    """The most body bytes the campaign route of `target` (is_campaign_api) takes with `method`."""
    found = resolve(target.partition("?")[0])
    return MAX_COMMIT_REQUEST_BYTES if found is not None and found[0] == "checkpoint" and method == "POST" else 0


def resolve(path: str) -> tuple[str, tuple[str, ...]] | None:
    """The route kind of a path, by its shape alone, with its raw variable segments; None if no
    route has that shape."""
    if path == PREFIX:
        return "campaigns", ()
    if not path.startswith(PREFIX + "/"):
        return None
    segments = path[len(PREFIX) + 1:].split("/")
    count = len(segments)
    if count == 1:
        return "campaign", (segments[0],)
    if count == 2 and segments[1] in ("checkpoint", "checkpoints"):
        return segments[1], (segments[0],)
    if count == 3 and segments[1] == "members":
        return "member", (segments[0], segments[2])
    if count == 4 and segments[1] == "checkpoints" and segments[3] in ("story", "unique"):
        return "payload", (segments[0], segments[2], segments[3], "")
    if count == 5 and segments[1] == "checkpoints" and segments[3] == "stages":
        return "payload", (segments[0], segments[2], "stage", segments[4])
    return None


def campaign_segment(segment: str) -> str:
    if not CAMPAIGN_SEGMENT.fullmatch(segment):
        raise not_found()
    return segment


def revision_segment(segment: str) -> int:
    if not REVISION_SEGMENT.fullmatch(segment) or int(segment) > cs.MAX_REVISION:
        raise not_found()
    return int(segment)


def stage_segment(segment: str) -> int:
    if not STAGE_SEGMENT.fullmatch(segment):
        raise not_found()
    return int(segment)


def account_segment(segment: str) -> str:
    """A member's account ID from its percent-encoded path segment."""
    account = None
    if PCHAR_SEGMENT.fullmatch(segment):
        try:
            account = unquote(segment, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
    if account is None or not cs.ACCOUNT_ID.fullmatch(account):
        raise ApiError(400, "bad_request", f"a member is an account ID of 1 to {cs.MAX_ACCOUNT_BYTES} printable ASCII "
                                           "characters without spaces, percent-encoded as one path segment")
    return account


def precondition(headers: Mapping[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is None:
        return None
    value = value.strip()
    if len(value) > MAX_PRECONDITION_CHARS:
        raise ApiError(400, "bad_request", f"{name} is one quoted ETag")
    return value


def strong_etag(value: str, name: str) -> str:
    match = ETAG.fullmatch(value)
    if match is None:
        raise ApiError(400, "bad_request", f"{name} is one strong ETag, as a response gave it")
    return match.group(1)


def if_match(headers: Mapping[str, str], *, any_allowed: bool) -> str | None:
    """The metadata etag a change of the campaign requires; None for If-Match: * (if allowed)."""
    value = precondition(headers, "if-match")
    if value is None:
        raise ApiError(428, "precondition_required", "this change needs If-Match with the campaign's ETag"
                       + (", or *" if any_allowed else ""))
    if value == "*":
        if not any_allowed:
            raise ApiError(400, "bad_request", "adding a member needs If-Match with the campaign's ETag, not *")
        return None
    return strong_etag(value, "if-match")


def commit_precondition(headers: Mapping[str, str]) -> str | None:
    """The etag of the checkpoint a commit replaces; None for If-None-Match: * (no checkpoint yet)."""
    match, none_match = precondition(headers, "if-match"), precondition(headers, "if-none-match")
    if match is not None and none_match is not None:
        raise ApiError(400, "bad_request", "a commit has If-Match or If-None-Match, not both")
    if match is not None:
        if match == "*":
            raise ApiError(400, "bad_request", "a commit names the checkpoint it replaces: If-Match: * is refused")
        return strong_etag(match, "if-match")
    if none_match is not None:
        if none_match != "*":
            raise ApiError(400, "bad_request", "If-None-Match: * is a campaign's first commit; others use If-Match")
        return None
    raise ApiError(428, "precondition_required", "a commit needs If-Match with the newest checkpoint's ETag, or "
                                                 "If-None-Match: * for the first checkpoint")


def media_type(headers: Mapping[str, str]) -> str:
    return headers.get("content-type", "").partition(";")[0].strip().lower()


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    """json.loads object_pairs_hook: an object that names a key twice is refused, not trimmed."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("an object names a key twice")
    return result


def no_constant(name: str) -> object:
    """json.loads parse_constant: NaN and the infinities are refused."""
    raise ValueError(f"{name} is not a number")


def session_name(value: object) -> str:
    if not (isinstance(value, str) and 0 < len(value) <= MAX_SESSION_NAME_BYTES and value.isascii()
            and value.isprintable()):
        raise ApiError(400, "bad_request", f"session is the name of a game session, 1 to {MAX_SESSION_NAME_BYTES} "
                                           "printable ASCII characters")
    return value


def parse_commit(body: bytes, *, max_stage_bytes: int = cs.MAX_STAGE_BYTES) -> CommitFrame:
    """A commit's body (COMMIT_MEDIA_TYPE; see the module's description), framed but not yet
    checked as payloads, which campaign_store does. Raises ApiError: 400 bad_request or bad_payload,
    413 too_large."""
    if type(body) is not bytes:
        body = bytes(body)  # the views must not change under the worker
    if len(body) > MAX_COMMIT_REQUEST_BYTES:
        raise ApiError(413, "too_large", f"a commit's body has at most {MAX_COMMIT_REQUEST_BYTES} bytes")
    if len(body) < COMMIT_LENGTH_BYTES:
        raise ApiError(400, "bad_request", "a commit starts with the 4-byte length of its JSON header")
    size = int.from_bytes(body[:COMMIT_LENGTH_BYTES], "big")
    if size > MAX_COMMIT_HEADER_BYTES:
        raise ApiError(413, "too_large", f"a commit's JSON header has at most {MAX_COMMIT_HEADER_BYTES} bytes")
    start = COMMIT_LENGTH_BYTES + size
    if size == 0 or len(body) < start:
        raise ApiError(400, "bad_request", "a commit's JSON header is cut short")
    try:
        head = json.loads(body[COMMIT_LENGTH_BYTES:start].decode("utf-8"), object_pairs_hook=unique_keys,
                          parse_constant=no_constant)
    except (ValueError, RecursionError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise ApiError(400, "bad_request", "a commit's header is not JSON") from None
    if type(head) is not dict or head.keys() != COMMIT_KEYS:
        raise ApiError(400, "bad_request", "a commit's header is an object of session, story, unique and stages")
    session = session_name(head["session"])
    story, unique = head["story"], head["unique"]
    if story is None and unique is None:
        common = ()
    elif (type(story) is int and story == cs.STORY_BLOCK_SIZE and type(unique) is int
          and unique == cs.UNIQUE_SIZE):
        common = (story, unique)
    else:
        raise ApiError(400, "bad_payload", f"story and unique are {cs.STORY_BLOCK_SIZE} and {cs.UNIQUE_SIZE}, one "
                                           "common save's story block and unique quest history, or both null")
    if type(head["stages"]) is not dict:
        raise ApiError(400, "bad_request", "stages is an object of stage numbers")
    sizes: dict[int, int | None] = {}
    for key, value in head["stages"].items():
        if not STAGE_SEGMENT.fullmatch(key):
            raise ApiError(400, "bad_request", "stage numbers are 0 to 99, in decimal without leading zeros")
        if value is not None and (type(value) is not int or value < 1):
            raise ApiError(400, "bad_request", "a stage is the size of its file, or null to drop it")
        if value is not None and value > max_stage_bytes:
            raise ApiError(413, "too_large", f"stage {key}: a stage file has at most {max_stage_bytes} bytes")
        sizes[int(key)] = value
    numbers = sorted(number for number, value in sizes.items() if value is not None)
    lengths = [*common, *(sizes[number] for number in numbers)]
    if start + sum(lengths) != len(body):
        raise ApiError(400, "bad_request", "the payloads after a commit's header are not the sizes it declares")
    view = memoryview(body)
    parts = []
    for length in lengths:
        parts.append(view[start:start + length])
        start += length
    stages: dict[int, memoryview | None] = {number: None for number, value in sizes.items() if value is None}
    stages.update(zip(numbers, parts[len(common):]))
    story_view, unique_view = parts[:2] if common else (None, None)
    return CommitFrame(session, story_view, unique_view, types.MappingProxyType(stages))


def encode_commit(session: str, *, story: bytes | None = None, unique: bytes | None = None,
                  stages: Mapping[int, bytes | None] | None = None) -> bytes:
    """A commit's body (COMMIT_MEDIA_TYPE) as parse_commit reads it, for clients and tests. `stages`
    maps stage numbers to STGDATnn.BIN bytes, or to None to drop the stage."""
    stages = dict(stages or {})
    numbers = sorted(stages)
    header = json.dumps({"session": session, "story": None if story is None else len(story),
                         "unique": None if unique is None else len(unique),
                         "stages": {str(number): None if stages[number] is None else len(stages[number])
                                    for number in numbers}}, separators=(",", ":")).encode()
    payloads = [bytes(data) for data in (story, unique, *(stages[number] for number in numbers)) if data is not None]
    return b"".join([len(header).to_bytes(COMMIT_LENGTH_BYTES, "big"), header, *payloads])


def open_payload(captured: cs.CapturedObject, checkpoint: cs.Checkpoint) -> BinaryIO:
    """A file of its own over a payload that an OpenCheckpoint holds, read through once and checked
    against the manifest: it outlives the OpenCheckpoint, and payload files are never rewritten."""
    where = f"campaign {checkpoint.campaign} revision {checkpoint.revision}: {captured.path}"
    try:
        fd = os.dup(captured.fd)
    except OSError as exc:
        raise cs.StorageError(f"{where}: {exc}") from exc
    try:
        file = os.fdopen(fd, "rb")
    except OSError as exc:
        os.close(fd)
        raise cs.StorageError(f"{where}: {exc}") from exc
    try:
        digest = hashlib.sha256()
        remaining = captured.size
        file.seek(0)
        while remaining:
            chunk = file.read(min(cs.READ_CHUNK, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        file.close()
        raise cs.StorageError(f"{where}: {exc}") from exc
    except BaseException:
        file.close()
        raise
    if remaining or digest.hexdigest() != captured.sha256:
        file.close()
        raise cs.IntegrityError(f"{where} does not match its manifest")
    return file


def log_bug(what: str, exc: BaseException) -> None:
    """Logs an unexpected exception by its type and stack, not its message, which could quote request data."""
    log.error("campaign api %s failed with %s:\n%s", what, type(exc).__name__,
              "".join(traceback.format_tb(exc.__traceback__)).rstrip())


def internal() -> ApiResponse:
    return ApiError(500, "internal", "the server failed; nothing is known about what took effect").response()


class Handoff:
    """Hands execute()'s response from the worker to handle(), and closes a download's file that
    nobody will send because handle() was cancelled meanwhile."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.abandoned = False
        self.result: ApiResponse | None = None

    def run(self, execute: Callable[[CampaignRequest], ApiResponse], request: CampaignRequest) -> ApiResponse:
        result = execute(request)
        with self.lock:
            if not self.abandoned:
                self.result = result
                return result
        result.close()
        return result

    def abandon(self) -> None:
        with self.lock:
            self.abandoned = True
            result, self.result = self.result, None
        if result is not None:
            result.close()


# --- Routes ------------------------------------------------------------------------------------


class CampaignApi:
    """The campaign routes over `registry` (see the module's description). host_session is the
    host check of commits; `executor` runs execute() (None: the event loop's default executor)."""

    def __init__(self, registry: cs.CampaignRegistry, host_session: HostSessionCheck, *,
                 executor: Executor | None = None):
        if not callable(host_session):
            raise TypeError("host_session must be callable; commits have no host check without it")
        self.registry = registry
        self.host_session = host_session
        self.executor = executor

    async def handle(self, method: str, target: str, headers: Mapping[str, str], body: bytes,
                     principal: object | None) -> ApiResponse:
        """Serves one request: prepare() here on the event loop, execute() in the executor."""
        prepared = self.prepare(method, target, headers, body, principal)
        if isinstance(prepared, CampaignRequest):
            handoff = Handoff()
            try:
                result = await asyncio.get_running_loop().run_in_executor(self.executor, handoff.run, self.execute,
                                                                          prepared)
            except asyncio.CancelledError:
                handoff.abandon()
                raise
            except Exception as exc:  # the executor refused the work, for example once shut down
                log_bug("scheduling a request", exc)
                result = internal()
        else:
            result = prepared
        self.log_request(method, principal, prepared, result)
        return result

    def serve(self, method: str, target: str, headers: Mapping[str, str], body: bytes,
              principal: object | None) -> ApiResponse:
        """prepare() and execute() on this thread, for tests and tools without an event loop."""
        prepared = self.prepare(method, target, headers, body, principal)
        result = self.execute(prepared) if isinstance(prepared, CampaignRequest) else prepared
        self.log_request(method, principal, prepared, result)
        return result

    def prepare(self, method: str, target: str, headers: Mapping[str, str], body: bytes,
                principal: object | None) -> CampaignRequest | ApiResponse:
        """The request parsed and checked, and for a commit its host checked (host_session), on the
        event loop and without disk I/O; or the response that refuses it."""
        try:
            return self._prepare(method, target, headers or {}, body if body is not None else b"", principal)
        except ApiError as exc:
            return exc.response()
        except Exception as exc:
            log_bug("preparing a request", exc)
            return internal()

    def execute(self, request: CampaignRequest) -> ApiResponse:
        """Serves a prepared request through the registry; blocks on disk I/O, so it runs in a worker
        and touches nothing of the event loop."""
        try:
            return self._execute(request)
        except ApiError as exc:
            return exc.response()
        except cs.CampaignError as exc:
            return self._refusal(request, exc)
        except Exception as exc:
            log_bug(request.route, exc)
            return internal()

    @staticmethod
    def log_request(method: str, principal: object | None, prepared: CampaignRequest | ApiResponse,
                    result: ApiResponse) -> None:
        account = getattr(principal, "account", None)
        log.info("campaign api %s %s from account %s -> %d %s", method if method in METHODS else "(other)",
                 prepared.route if isinstance(prepared, CampaignRequest) else "-",
                 account if isinstance(account, str) and cs.ACCOUNT_ID.fullmatch(account) else "-",
                 result.status, result.outcome)

    # --- Internals ---

    def _prepare(self, method: str, target: str, headers: Mapping[str, str], body: bytes,
                 principal: object | None) -> CampaignRequest:
        account = getattr(principal, "account", None) if principal is not None else None
        if not (isinstance(account, str) and cs.ACCOUNT_ID.fullmatch(account)):
            raise ApiError(401, "unauthenticated", "campaigns need a device certificate")
        if type(body) is not bytes:
            body = bytes(body)  # the worker reads views of it: it must not change
        if not isinstance(target, str) or len(target) > MAX_TARGET_CHARS:
            raise ApiError(400, "bad_request", f"a request target has at most {MAX_TARGET_CHARS} characters")
        path, query_mark, _ = target.partition("?")
        found = resolve(path)
        if found is None:
            raise not_found()
        kind, raw = found
        allowed = ALLOW[kind]
        if method not in allowed:
            raise ApiError(405, "method_not_allowed", f"this campaign route takes {', '.join(allowed)}",
                           headers=(("allow", ", ".join(allowed)),))
        if query_mark:
            raise ApiError(400, "bad_request", "campaign routes take no query")
        route = ROUTES[kind, method]
        if route != "commit" and body:
            raise ApiError(400, "bad_request", "only a commit has a body")
        campaign = campaign_segment(raw[0]) if raw else None
        if route in ("list", "create", "get", "head", "history"):
            return CampaignRequest(method, route, account, campaign)
        if route == "delete":
            return CampaignRequest(method, route, account, campaign, if_match=if_match(headers, any_allowed=True))
        if route in ("add_member", "remove_member"):
            member = account_segment(raw[1])
            return CampaignRequest(method, route, account, campaign, member=member,
                                   if_match=if_match(headers, any_allowed=route == "remove_member"))
        if route == "payload":
            return CampaignRequest(method, route, account, campaign, revision=revision_segment(raw[1]), part=raw[2],
                                   stage=stage_segment(raw[3]) if raw[2] == "stage" else None)
        if media_type(headers) != COMMIT_MEDIA_TYPE:
            raise ApiError(415, "unsupported_media_type", f"a commit's body is {COMMIT_MEDIA_TYPE}")
        if len(body) > MAX_COMMIT_REQUEST_BYTES:
            raise ApiError(413, "too_large", f"a commit's body has at most {MAX_COMMIT_REQUEST_BYTES} bytes")
        expected = commit_precondition(headers)
        frame = parse_commit(body, max_stage_bytes=self.registry.store.max_stage_bytes)
        self._check_host(principal, account, campaign, frame.session)
        return CampaignRequest(method, route, account, campaign, if_match=expected, commit=frame)

    def _check_host(self, principal: object, account: str, campaign: str, session: str) -> None:
        """Refuses the commit unless host_session says the account hosts `session` now, and that the
        session is bound to `campaign`. Fails closed."""
        try:
            host = self.host_session(principal, session)
        except Exception as exc:
            log.warning("campaign api: host_session failed with %s; the commit is refused", type(exc).__name__)
            raise ApiError(503, "unavailable", "the game session could not be checked; try again") from None
        if not (type(host) is HostSession and host.account == account and host.session == session
                and host.campaign == campaign):
            raise ApiError(403, "not_host", "only the host of a live game session bound to this campaign commits "
                                            "its checkpoints")

    def _execute(self, request: CampaignRequest) -> ApiResponse:
        registry, account, campaign, route = self.registry, request.account, request.campaign, request.route
        if route == "list":
            infos = registry.campaigns_of(account)
            return json_response(200, {"campaigns": [campaign_doc(info, account) for info in infos]})
        if route == "create":
            info = registry.create(account)
            return json_response(201, campaign_doc(info, account),
                                 (("etag", quoted(info.etag)), ("location", f"{PREFIX}/{info.campaign}")))
        if route == "get":
            return self._campaign(registry.get(campaign, account), account)
        if route == "delete":
            registry.delete(campaign, account, if_match=request.if_match)
            return no_content()
        if route == "add_member":
            return self._campaign(registry.add_member(campaign, account, request.member, if_match=request.if_match),
                                  account)
        if route == "remove_member":
            info = registry.remove_member(campaign, account, request.member, if_match=request.if_match)
            return no_content() if request.member == account else self._campaign(info, account)
        if route == "head":
            checkpoint = registry.head(campaign, account)
            if checkpoint is None:
                return json_response(200, {"checkpoint": None})
            return json_response(200, {"checkpoint": checkpoint_doc(checkpoint)}, (("etag", quoted(checkpoint.etag)),))
        if route == "history":
            return json_response(200, {"checkpoints": [checkpoint_doc(checkpoint)
                                                       for checkpoint in registry.history(campaign, account)]})
        if route == "commit":
            frame = request.commit
            checkpoint = registry.commit(campaign, account, request.if_match, story=frame.story, unique=frame.unique,
                                         stages=dict(frame.stages) or None)
            return json_response(200 if checkpoint.etag == request.if_match else 201,
                                 {"checkpoint": checkpoint_doc(checkpoint)}, (("etag", quoted(checkpoint.etag)),))
        if route == "payload":
            return self._payload(request)
        raise AssertionError(f"no route {route!r}")

    @staticmethod
    def _campaign(info: cs.CampaignInfo, account: str) -> ApiResponse:
        return json_response(200, campaign_doc(info, account), (("etag", quoted(info.etag)),))

    def _payload(self, request: CampaignRequest) -> ApiResponse:
        with self.registry.open(request.campaign, request.account, request.revision) as opened:
            checkpoint = opened.checkpoint
            if request.part == "story":
                wanted = checkpoint.story.sha256
            elif request.part == "unique":
                wanted = checkpoint.unique.sha256
            else:
                stage = checkpoint.stages.get(request.stage)
                if stage is None:
                    raise not_found()
                wanted = stage.sha256
            captured = {captured.sha256: captured for captured in opened.objects}[wanted]
            file = open_payload(captured, checkpoint)
        return ApiResponse(200, [("content-type", "application/octet-stream"), ("content-length", str(captured.size)),
                                 ("cache-control", "no-store"), ("etag", quoted(captured.sha256)),
                                 ("x-checkpoint-etag", quoted(checkpoint.etag))], b"", (file, 0, captured.size))

    def _visible(self, request: CampaignRequest) -> bool | None:
        """Whether the account may see the campaign now, which decides whether a failure may be told
        to it: False also for damaged metadata, None if it cannot be decided now."""
        try:
            self.registry.get(request.campaign, request.account)
        except (cs.CampaignNotFound, cs.InvalidCampaignId, cs.IntegrityError, cs.InvalidAccount):
            return False
        except cs.CampaignError:  # busy, or failing storage
            return None
        return True

    def _refusal(self, request: CampaignRequest, exc: cs.CampaignError) -> ApiResponse:
        route = request.route
        if isinstance(exc, (cs.CampaignNotFound, cs.InvalidCampaignId)):
            return not_found().response()
        if isinstance(exc, cs.AccessDenied):
            return ApiError(403, "forbidden", FORBIDDEN.get(route, "only the campaign's owner may do this")).response()
        if isinstance(exc, cs.MetadataConflict):
            return ApiError(412, "precondition_failed", "the campaign changed since that ETag",
                            {"etag": exc.current.etag}).response()
        if isinstance(exc, cs.RevisionConflict):
            current = exc.current
            return ApiError(412, "precondition_failed", "the campaign's newest checkpoint is another one",
                            {"etag": current.etag if current else None,
                             "revision": current.revision if current else None}).response()
        if isinstance(exc, cs.PayloadTooLarge):
            return ApiError(413, "too_large", str(exc)[:MAX_MESSAGE_CHARS]).response()
        if isinstance(exc, cs.PayloadError):
            return ApiError(400, "bad_payload", str(exc)[:MAX_MESSAGE_CHARS]).response()
        if isinstance(exc, cs.QuotaExceeded):
            if route == "create":
                return ApiError(409, "too_many_campaigns", "this account owns as many campaigns as it may").response()
            if route == "add_member":
                return ApiError(409, "too_many_members", "the campaign is shared with as many accounts as it may"
                                ).response()
            return ApiError(507, "quota_exceeded", "the campaign, or the server's disk, has no room for this "
                                                   "checkpoint").response()
        if isinstance(exc, cs.AccountPurged):
            if route == "add_member":
                return ApiError(409, "member_unavailable", "that account no longer exists").response()
            return ApiError(403, "account_purged", "this account no longer exists").response()
        if isinstance(exc, cs.CampaignBusy):
            return ApiError(503, "busy", "the campaign is busy; try again", headers=(("retry-after", "1"),)).response()
        if isinstance(exc, cs.InvalidAccount):
            return ApiError(400, "bad_request", "that is not an account ID").response()
        if isinstance(exc, (cs.IntegrityError, cs.StorageError)):
            if request.campaign is not None:
                visible = self._visible(request)
                if visible is False:
                    return not_found().response()
                if visible is None:
                    return ApiError(503, "unavailable", "the campaign cannot be served now; try again").response()
            log.warning("campaign api %s from account %s failed: %s", route, request.account, exc)
            if isinstance(exc, cs.IntegrityError):
                return ApiError(500, "damaged", "the campaign's stored data is damaged").response()
            return ApiError(500, "storage_error", "the server's storage failed", {"committed": exc.committed}).response()
        log_bug(route, exc)
        return internal()
