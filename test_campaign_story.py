"""Behavioral checks for isolated Pokopia campaign story saves."""
import struct
import unittest
import zlib

import campaign_story as story


def common(raw):
    header = bytearray(story.HEADER_SIZE)
    struct.pack_into('<II', header, 0, story.MAGIC, story.VERSION)
    header[0x0a] = 4
    compressed = zlib.compress(raw)
    struct.pack_into('<i', header, 0x10, len(header) + len(compressed))
    return bytes(header) + compressed


class CampaignStoryTest(unittest.TestCase):
    def test_replaces_only_story_and_round_trips(self):
        raw = bytearray(story.RAW_SIZE)
        raw[story.STORY_START - 1] = 7
        raw[story.STORY_START + story.STORY_SIZE] = 9
        original = common(raw)
        replacement = b'\x5a' * story.STORY_SIZE
        updated = story.replace_story(original, replacement)
        self.assertEqual(story.extract_story(updated), replacement)
        after = story.decode_common(updated)
        self.assertEqual(after[:story.STORY_START], raw[:story.STORY_START])
        self.assertEqual(after[story.STORY_START + story.STORY_SIZE:], raw[story.STORY_START + story.STORY_SIZE:])
        self.assertEqual(story.extract_story(original), bytes(story.STORY_SIZE))

    def test_rejects_wrong_version_truncated_stream_and_wrong_story_size(self):
        valid = common(bytes(story.RAW_SIZE))
        wrong_version = bytearray(valid)
        struct.pack_into('<I', wrong_version, 4, story.VERSION + 1)
        for broken in (bytes(wrong_version), valid[:-1]):
            with self.subTest(length=len(broken)), self.assertRaises(story.InvalidSave):
                story.extract_story(broken)
        with self.assertRaises(story.InvalidSave):
            story.replace_story(valid, b'wrong length')


if __name__ == '__main__':
    unittest.main()
