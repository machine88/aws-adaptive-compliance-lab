"""Synthetic encryption-output tests for acknowledgment only after filesystem synchronization."""
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from research.aws_reader import EncryptedArchive


def archive_fixture(root):
    """Construct a writer fixture without credentials, real evidence or cryptographic keys.

    Inputs:
        root: Temporary parent directory for a synthetic exclusive output directory.
    Outputs:
        EncryptedArchive: Test-only instance with fake public-recipient and executable paths.
            Creates a local directory; encryption subprocess output must be mocked by tests.
    """
    archive = EncryptedArchive.__new__(EncryptedArchive)
    archive.root = Path(root) / "archive"
    archive.root.mkdir(mode=0o700)
    archive.cert = archive.root / "synthetic-public.pem"
    archive.binary = "synthetic-openssl"
    archive.timeout_seconds = 1
    archive.receipts = []
    return archive


class ArchiveDurabilityTests(unittest.TestCase):
    """Keep a failed persistence operation from producing a usable success receipt."""

    def test_receipt_requires_file_and_directory_synchronization(self):
        """Observe acknowledgment ordering while performing real temporary-file synchronization.

        Inputs:
            self: Test instance; uses synthetic ciphertext from a mocked encryption subprocess.
        Outputs:
            None; verifies no receipt exists before both synchronization points finish.
        """
        with tempfile.TemporaryDirectory() as directory:
            archive = archive_fixture(directory)
            stages = []
            original = os.fsync

            def observe(descriptor):
                """Inspect the synchronization stage before delegating to the real OS operation.

                Inputs:
                    descriptor: Open file or directory descriptor passed by the writer.
                Outputs:
                    None: Records stage, checks unacknowledged state and calls real fsync.
                """
                stages.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
                self.assertEqual(archive.receipts, [])
                original(descriptor)

            with patch("research.aws_reader.subprocess.run", return_value=SimpleNamespace(stdout=b"synthetic-ciphertext")), patch("research.aws_reader.os.fsync", side_effect=observe):
                receipt = archive.write({"synthetic": True})
            self.assertEqual(stages, ["file", "directory"])
            self.assertEqual(archive.receipts, [receipt])
            self.assertEqual((archive.root / receipt["file"]).read_bytes(), b"synthetic-ciphertext")

    def test_failed_sync_keeps_ciphertext_without_acknowledgment(self):
        """Preserve partial ciphertext and reject overwrite after either synchronization fails.

        Inputs:
            self: Test instance injecting file-stage and directory-stage persistence errors.
        Outputs:
            None; verifies errors propagate, no receipt appears, and retry cannot overwrite.
        """
        for failure_stage in ("file", "directory"):
            with self.subTest(stage=failure_stage), tempfile.TemporaryDirectory() as directory:
                archive = archive_fixture(directory)

                def fail_selected_stage(descriptor):
                    """Raise a synthetic persistence failure at the selected descriptor type.

                    Inputs:
                        descriptor: Open file or directory descriptor supplied to fsync.
                    Outputs:
                        None: Raises OSError at the selected stage; otherwise changes nothing.
                    """
                    stage = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
                    if stage == failure_stage:
                        raise OSError("synthetic persistence failure")

                with patch("research.aws_reader.subprocess.run", return_value=SimpleNamespace(stdout=b"synthetic-ciphertext")), patch("research.aws_reader.os.fsync", side_effect=fail_selected_stage):
                    with self.assertRaises(OSError):
                        archive.write({"synthetic": True})
                    self.assertEqual(archive.receipts, [])
                    self.assertEqual((archive.root / "record-00000.cms").read_bytes(), b"synthetic-ciphertext")
                    with self.assertRaises(FileExistsError):
                        archive.write({"synthetic": True})
