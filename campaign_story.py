"""Read and replace the campaign-story portion of a Pokopia 2.0.1 common save.

The bytes outside the story block remain local to the player. Only use rewritten saves in an
isolated campaign profile, never while the emulator is running. Replacing this block alone does
not synchronize a campaign: unique-request history, a matching world save, and the game's quest
effects also matter. In a multiplayer test, matching story quests alone left a guest's request stale.
"""
from __future__ import annotations

import struct
import zlib

MAGIC = 0x31227687
VERSION = 0x0200017D
HEADER_SIZE = 0x130
RAW_SIZE = 0x470CED
STORY_START = 0x220F04
STORY_SIZE = 0x2365
MAX_SAVE_SIZE = 32 * 1024 * 1024


class InvalidSave(ValueError):
    """The save or story block is not a supported complete Pokopia 2.0.1 save."""


def decode_common(save: bytes) -> bytes:
    """Return the validated uncompressed common-save stream."""
    if not HEADER_SIZE < len(save) <= MAX_SAVE_SIZE:
        raise InvalidSave("common save has an invalid size")
    magic, version = struct.unpack_from('<II', save)
    if magic != MAGIC or version != VERSION or not save[0x0a] & 4:
        raise InvalidSave("not a compressed Pokopia 2.0.1 common save")
    end = struct.unpack_from('<i', save, 0x10)[0]
    if not HEADER_SIZE < end <= len(save):
        raise InvalidSave("common save has an invalid compressed length")
    stream = zlib.decompressobj()
    try:
        raw = stream.decompress(save[HEADER_SIZE:end], RAW_SIZE + 1)
    except zlib.error as exc:
        raise InvalidSave(f"common save cannot be decompressed: {exc}") from exc
    if not stream.eof or stream.unused_data or stream.unconsumed_tail or len(raw) != RAW_SIZE:
        raise InvalidSave("common save does not contain one complete, correctly sized stream")
    return raw


def extract_story(save: bytes) -> bytes:
    """Return only the serialized story block, not the rest of the common save."""
    raw = decode_common(save)
    return raw[STORY_START:STORY_START + STORY_SIZE]


def replace_story(save: bytes, story: bytes) -> bytes:
    """Return a new save with only its story block changed; never write the input file."""
    if not isinstance(story, bytes) or len(story) != STORY_SIZE:
        raise InvalidSave(f"story block must be exactly {STORY_SIZE} bytes")
    raw = decode_common(save)
    changed = raw[:STORY_START] + story + raw[STORY_START + STORY_SIZE:]
    compressed = zlib.compress(changed, 9)
    end = HEADER_SIZE + len(compressed)
    if end > MAX_SAVE_SIZE:
        raise InvalidSave("rewritten common save exceeds the size limit")
    result = bytearray(max(end, len(save)))
    result[:HEADER_SIZE] = save[:HEADER_SIZE]
    struct.pack_into('<i', result, 0x10, end)
    result[HEADER_SIZE:end] = compressed
    return bytes(result)
