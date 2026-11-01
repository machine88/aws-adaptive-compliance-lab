"""Synthetic recovery-intent binding, encryption and fail-closed retention tests; no AWS IO."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from research.catalog import canonical_sha256
from tests.crypto_fixtures import synthetic_recipient
from research.recovery_intent import build_recovery_intent, retain_recovery_intent, verify_recovery_intent
from research.scenario_lock import acquire_sandbox_lock, release_sandbox_lock
from tests.test_sandbox_emptiness import fixture as listing_fixture
from tests.test_sandbox_readiness import fixture as metadata_fixture

RUN = "a" * 32
REVIEW = "b" * 64
SOURCE = "c" * 64


class RecoveryIntentTests(unittest.TestCase):
    """Use a temporary synthetic encryption recipient, never the real Keychain item."""

    @classmethod
    def setUpClass(cls):
        """Create one synthetic test-only RSA recipient for actual CMS roundtrip checks.

        Inputs:
            cls: Test class receiving temporary certificate/key paths and a public fingerprint.
        Outputs:
            None: Creates temporary local test files; no real credentials, AWS or Keychain access.
        """
        cls.temporary = tempfile.TemporaryDirectory()
        cls.parent = Path(cls.temporary.name).resolve()
        cls.binary, cls.cert, cls.key, cls.recipient = synthetic_recipient(cls.parent)

    @classmethod
    def tearDownClass(cls):
        """Remove only the class's disposable synthetic recipient and temporary files.

        Inputs:
            cls: Test class owning the temporary directory created by setUpClass.
        Outputs:
            None: Cleans temporary synthetic files; does not touch real keys or run artifacts.
        """
        cls.temporary.cleanup()

    def test_record_binds_fixed_actions_and_copies_prestate(self):
        """Keep raw pre-state separate from later caller changes and preserve closed gates.

        Inputs:
            self: Test instance using synthetic protection/listing responses and external pins.
        Outputs:
            None: Asserts exact fixed actions, no input mutation and successful offline verification.
        """
        metadata, listings = metadata_fixture(), listing_fixture()
        original = copy.deepcopy(metadata)
        record = build_recovery_intent(RUN, metadata, listings, REVIEW, SOURCE, self.recipient)
        self.assertEqual(metadata, original)
        self.assertEqual(record["requests"]["proposed_mutation"]["params"]["VersioningConfiguration"], {"Status": "Suspended"})
        self.assertEqual(record["requests"]["restoration"]["params"]["VersioningConfiguration"], {"Status": "Enabled"})
        metadata["get_bucket_versioning"]["Status"] = "Suspended"
        self.assertEqual(record["prestate"]["metadata"], original)
        for field in ("live_execution_allowed", "restoration_verified", "recovery_credentials_verified"):
            self.assertIs(record[field], False)
        self.assertEqual(verify_recovery_intent(record, RUN, REVIEW, SOURCE, self.recipient), canonical_sha256(record))

    def test_altered_scope_actions_phase_and_pins_rejected(self):
        """Reject relabeling, widened schemas, false-like gates and changed retained content pins.

        Inputs:
            self: Test instance applying independent changes to a valid synthetic private record.
        Outputs:
            None: Every changed contract fails offline verification rather than granting execution.
        """
        original = build_recovery_intent(RUN, metadata_fixture(), listing_fixture(), REVIEW, SOURCE, self.recipient)
        for field, value in (("phase", "pilot"), ("bucket", "unrelated"), ("run_id", "d" * 32),
                             ("live_execution_allowed", True), ("live_execution_allowed", 0), ("extra", "field")):
            record = copy.deepcopy(original)
            record[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify_recovery_intent(record, RUN, REVIEW, SOURCE, self.recipient)
        record = copy.deepcopy(original)
        record["requests"]["restoration"]["params"]["VersioningConfiguration"]["Status"] = "Suspended"
        with self.assertRaises(ValueError):
            verify_recovery_intent(record, RUN, REVIEW, SOURCE, self.recipient)
        with self.assertRaises(ValueError):
            verify_recovery_intent(original, RUN, "d" * 64, SOURCE, self.recipient)
        metadata = metadata_fixture()
        metadata["get_bucket_versioning"]["MFADelete"] = "Enabled"
        with self.assertRaises(ValueError):
            build_recovery_intent(RUN, metadata, listing_fixture(), REVIEW, SOURCE, self.recipient)

    def test_real_encrypted_intent_roundtrip_and_lock_retention(self):
        """Retain ciphertext under the matching lock and verify it using only a synthetic key.

        Inputs:
            self: Test instance with a temporary owner lock and test-only encryption recipient.
        Outputs:
            None: Asserts private modes, encrypted raw evidence, exact reconstruction and blocked reuse.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lock = acquire_sandbox_lock(root, RUN)
            commitment = retain_recovery_intent(root, RUN, metadata_fixture(), listing_fixture(), REVIEW,
                                                SOURCE, self.recipient, self.cert, self.binary, 5)
            archive = lock / "recovery-intent"
            cipher = (archive / commitment["ciphertext"]["file"]).read_bytes()
            self.assertNotIn(b"RequireTLS", cipher)
            plaintext = subprocess.run([self.binary, "cms", "-decrypt", "-binary", "-inform", "DER",
                                        "-recip", str(self.cert), "-inkey", str(self.key)], input=cipher,
                                       check=True, capture_output=True, timeout=5).stdout
            record = json.loads(plaintext)
            self.assertEqual(verify_recovery_intent(record, RUN, REVIEW, SOURCE, self.recipient), commitment["intent_sha256"])
            self.assertEqual(json.loads((archive / "commitment.json").read_text()), commitment)
            for file in archive.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertIs(commitment["live_execution_allowed"], False)
            with self.assertRaises(ValueError):
                release_sandbox_lock(root, RUN)
            with self.assertRaises(FileExistsError):
                acquire_sandbox_lock(root, RUN)
            with self.assertRaises(ValueError):
                retain_recovery_intent(root, RUN, metadata_fixture(), listing_fixture(), REVIEW,
                                       SOURCE, self.recipient, self.cert, self.binary, 5)

    def test_wrong_run_and_recipient_fail_without_success(self):
        """Keep foreign run ownership and recipient mismatches from producing a commitment.

        Inputs:
            self: Test instance creating independent synthetic lock states for each mismatch.
        Outputs:
            None: Asserts ownership failure creates nothing and recipient failure leaves a blocked archive.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lock = acquire_sandbox_lock(root, RUN)
            with self.assertRaises(ValueError):
                retain_recovery_intent(root, "d" * 32, metadata_fixture(), listing_fixture(), REVIEW,
                                       SOURCE, self.recipient, self.cert, self.binary, 5)
            self.assertEqual({file.name for file in lock.iterdir()}, {"owner.json"})
            with self.assertRaises(ValueError):
                retain_recovery_intent(root, RUN, metadata_fixture(), listing_fixture(), REVIEW,
                                       SOURCE, "d" * 64, self.cert, self.binary, 5)
            self.assertFalse((lock / "recovery-intent" / "commitment.json").exists())
            with self.assertRaises(ValueError):
                release_sandbox_lock(root, RUN)

    def test_encryption_or_commitment_sync_failure_preserves_blocked_lock(self):
        """Retain partial recovery material without returning success after persistence fails.

        Inputs:
            self: Test instance injecting encryption-write and final-directory-sync failures.
        Outputs:
            None: Asserts errors propagate and neither failed attempt releases the local lock.
        """
        for target in ("research.recovery_intent.EncryptedArchive.write", "research.recovery_intent.sync_archive_directory"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                acquire_sandbox_lock(root, RUN)
                with patch(target, side_effect=OSError("synthetic retention failure")), self.assertRaises(OSError):
                    retain_recovery_intent(root, RUN, metadata_fixture(), listing_fixture(), REVIEW,
                                           SOURCE, self.recipient, self.cert, self.binary, 5)
                with self.assertRaises(ValueError):
                    release_sandbox_lock(root, RUN)
                with self.assertRaises(FileExistsError):
                    acquire_sandbox_lock(root, RUN)
