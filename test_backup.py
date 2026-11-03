"""Regression tests for the backup destination's encryption requirement."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import backup


@unittest.skipUnless(shutil.which('rclone'), 'rclone is needed to inspect a real configuration')
class BackupDestinationTest(unittest.TestCase):
    def test_plain_remote_is_rejected_before_upload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'rclone.conf'
            config.write_text('[gdrive-crypt]\ntype = local\n', encoding='utf-8')
            env = {key: value for key, value in os.environ.items() if not key.upper().startswith('RCLONE_')}
            env['RCLONE_CONFIG'] = str(config)
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(RuntimeError, 'not configured as an encrypted'):
                    backup.require_encrypted_destination()

    def test_environment_override_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {'RCLONE_CONFIG_GDRIVE_CRYPT_TYPE': 'local'}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'environment overrides'):
                backup.require_encrypted_destination()


if __name__ == '__main__':
    unittest.main()
