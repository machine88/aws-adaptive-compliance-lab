"""Offline private-reader, corruption, resource-limit and restoration-candidate tests."""
import copy
import json
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from research.catalog import canonical_sha256
from research.recovery_intent import retain_recovery_intent
from research.recovery_review import MAX_BYTES, build_restoration_candidate, read_recovery_intent, retain_restoration_candidate, read_restoration_candidate
from research.scenario_lock import acquire_sandbox_lock, release_sandbox_lock
from tests.crypto_fixtures import synthetic_recipient
from tests.test_sandbox_emptiness import fixture as listing_fixture
from tests.test_sandbox_readiness import fixture as metadata_fixture

RUN, REVIEW, SOURCE = "a" * 32, "b" * 64, "c" * 64


class RecoveryReviewTests(unittest.TestCase):
    """Exercise actual CMS with a disposable recipient and entirely synthetic cloud responses."""

    @classmethod
    def setUpClass(cls):
        """Create a test-only encryption recipient shared by this class's offline cases.

        Inputs:
            cls: Test class owning temporary public/private synthetic recipient files.
        Outputs:
            None: Creates disposable files; no real key, Keychain or AWS access occurs.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.recipient = synthetic_recipient(Path(cls.keys.name))

    @classmethod
    def tearDownClass(cls):
        """Remove the class's disposable synthetic recipient.

        Inputs:
            cls: Test class owning its temporary recipient directory.
        Outputs:
            None: Removes only synthetic test files.
        """
        cls.keys.cleanup()

    def setUp(self):
        """Retain a new synthetic recovery intent under an independent private lock.

        Inputs:
            self: Test instance receiving temporary paths and an external commitment pin.
        Outputs:
            None: Creates temporary encrypted fixtures and registers their cleanup.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "locks"
        self.root.mkdir(mode=0o700)
        self.lock = acquire_sandbox_lock(self.root, RUN)
        self.commitment = retain_recovery_intent(self.root, RUN, metadata_fixture(), listing_fixture(),
            REVIEW, SOURCE, self.recipient, self.cert, self.binary, 5)
        self.pin = canonical_sha256(self.commitment)
        self.archive = self.lock / "recovery-intent"

    def decrypt(self, ciphertext):
        """Authenticate and decrypt only synthetic test ciphertext with the disposable private key.

        Inputs:
            self: Test instance holding the synthetic recipient paths and executable.
            ciphertext: Bounded CMS bytes supplied by the reader.
        Outputs:
            bytes: In-memory authenticated plaintext; no plaintext file or real key access.
        """
        return subprocess.run([self.binary, "cms", "-decrypt", "-binary", "-inform", "DER",
            "-recip", str(self.cert), "-inkey", str(self.key)], input=ciphertext,
            check=True, capture_output=True, timeout=5).stdout

    def read(self, decryptor=None, pin=None, max_bytes=MAX_BYTES):
        """Invoke the private reader with independently retained synthetic scope pins.

        Inputs:
            self: Test instance containing the encrypted fixture.
            decryptor: Optional trusted test callback; defaults to real synthetic CMS decryption.
            pin: Optional replacement external commitment identity for negative cases.
            max_bytes: Explicit reader budget used by resource-boundary tests.
        Outputs:
            dict: Private reader result or a propagated expected test error; no AWS calls.
        """
        return read_recovery_intent(self.root, RUN, decryptor or self.decrypt, REVIEW, SOURCE,
                                    self.recipient, self.pin if pin is None else pin, max_bytes)

    def test_real_reader_roundtrip_preserves_closed_execution(self):
        """Load an authenticated synthetic record and preserve its external identity and closed gates.

        Inputs:
            self: Test instance with a complete private archive.
        Outputs:
            None: Asserts identity consistency, development-only scope and no lock release.
        """
        result = self.read()
        self.assertEqual(result["commitment"], self.commitment)
        self.assertEqual(result["intent_sha256"], self.commitment["intent_sha256"])
        self.assertIs(result["live_execution_allowed"], False)
        self.assertEqual(result["record"]["research_trials"], 0)
        self.assertTrue(self.lock.exists())

    def test_external_pin_and_ciphertext_fail_before_decryption(self):
        """Reject an untrusted commitment or changed ciphertext without crossing the decryptor boundary.

        Inputs:
            self: Test instance changing only fixture content or an external pin.
        Outputs:
            None: Asserts the trusted callback is never called for either mismatch.
        """
        decryptor = Mock(side_effect=AssertionError("Must not decrypt changed evidence"))
        with self.assertRaises(ValueError):
            self.read(decryptor, "d" * 64)
        path = self.archive / "record-00000.cms"
        path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            self.read(decryptor)
        decryptor.assert_not_called()

    def test_extra_files_and_duplicate_commitment_keys_rejected(self):
        """Reject incomplete schemas and JSON ambiguity before private evidence is decrypted.

        Inputs:
            self: Test instance adding a foreign file then a duplicate commitment field.
        Outputs:
            None: Asserts both forms of archive ambiguity fail closed.
        """
        extra = self.archive / "unexpected"
        extra.write_text("synthetic")
        with self.assertRaises(ValueError):
            self.read()
        extra.unlink()
        path = self.archive / "commitment.json"
        path.write_text(path.read_text().replace('"run_id":', '"run_id": "wrong", "run_id":'))
        with self.assertRaises(ValueError):
            self.read()

    def test_private_modes_hardlinks_and_symlinks_rejected(self):
        """Reject exposed archives and aliasing of private files.

        Inputs:
            self: Test instance varying temporary directory modes and file link types.
        Outputs:
            None: Asserts unsafe permissions and links cannot enter the recovery reader.
        """
        self.archive.chmod(0o755)
        with self.assertRaises(ValueError):
            self.read()
        self.archive.chmod(0o700)
        cipher = self.archive / "record-00000.cms"
        alias = self.base / "alias"
        alias.hardlink_to(cipher)
        with self.assertRaises(ValueError):
            self.read()
        alias.unlink()
        commitment = self.archive / "commitment.json"
        target = self.base / "synthetic-commitment"
        commitment.rename(target)
        commitment.symlink_to(target)
        with self.assertRaises(OSError):
            self.read()

    def test_changed_owner_during_decryption_rejected(self):
        """Catch a lock owner change made while a trusted callback is executing.

        Inputs:
            self: Test instance changing its own synthetic owner marker during callback execution.
        Outputs:
            None: Asserts post-callback consistency checks reject the changed lock.
        """
        def change_owner(ciphertext):
            """Decrypt the test record then deliberately alter the synthetic owner marker.

            Inputs:
                ciphertext: Test-only encrypted recovery record.
            Outputs:
                bytes: Authentic test plaintext; also rewrites the disposable owner marker.
            """
            plaintext = self.decrypt(ciphertext)
            (self.lock / "owner.json").write_text("{}")
            return plaintext
        with self.assertRaises(ValueError):
            self.read(change_owner)

    def test_replaced_root_during_decryption_rejected(self):
        """Reject a detached valid archive when its named root has been replaced.

        Inputs:
            self: Test instance renaming only its disposable lock root.
        Outputs:
            None: Asserts descriptor identity checks detect replacement despite valid old contents.
        """
        def replace_root(ciphertext):
            """Decrypt the fixture and replace the path to the original private lock root.

            Inputs:
                ciphertext: Test-only encrypted recovery record.
            Outputs:
                bytes: Valid synthetic plaintext; renames and recreates temporary directories.
            """
            plaintext = self.decrypt(ciphertext)
            self.root.rename(self.base / "original-root")
            self.root.mkdir(mode=0o700)
            return plaintext
        with self.assertRaises(ValueError):
            self.read(replace_root)

    def test_byte_limits_and_invalid_plaintext_rejected(self):
        """Reject invalid limits, excessive decrypted output and duplicate plaintext keys.

        Inputs:
            self: Test instance supplying bounded synthetic failure callbacks.
        Outputs:
            None: Asserts ingestion cannot exceed its declared budget or accept ambiguous JSON.
        """
        for limit in (True, 0, MAX_BYTES + 1, 100):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.read(max_bytes=limit)
        with self.assertRaises(ValueError):
            self.read(Mock(return_value=b"x" * MAX_BYTES))
        with self.assertRaises(ValueError):
            self.read(Mock(return_value=b'{"phase":"pilot","phase":"development"}'))

    def test_restoration_candidate_rejects_weakened_poststate(self):
        """Require the full protected empty baseline while leaving actual restoration unverified.

        Inputs:
            self: Test instance with valid intent and deliberately weakened post-state copies.
        Outputs:
            None: Asserts technical consistency, immutable inputs and rejection of weakened evidence.
        """
        record = self.read()["record"]
        metadata, listings = metadata_fixture(), listing_fixture()
        original = copy.deepcopy(metadata)
        candidate = build_restoration_candidate(record, RUN, metadata, listings, REVIEW, SOURCE, self.recipient)
        self.assertEqual(metadata, original)
        self.assertIs(candidate["supplied_restoration_matches_baseline"], True)
        self.assertIs(candidate["restoration_verified"], False)
        metadata["get_bucket_versioning"]["Status"] = "Suspended"
        with self.assertRaises(ValueError):
            build_restoration_candidate(record, RUN, metadata, listings, REVIEW, SOURCE, self.recipient)
        listings["list_object_versions"]["response"]["DeleteMarkers"] = [{"Key": "synthetic"}]
        with self.assertRaises(ValueError):
            build_restoration_candidate(record, RUN, original, listings, REVIEW, SOURCE, self.recipient)

    def test_retained_candidate_roundtrip_does_not_release_lock(self):
        """Save a linked encrypted candidate without declaring closure or removing any evidence.

        Inputs:
            self: Test instance using actual CMS with supplied synthetic restoration metadata.
        Outputs:
            None: Asserts linkage, privacy and held-lock behavior, including repeated-write rejection.
        """
        receipt = retain_restoration_candidate(self.root, RUN, self.decrypt, metadata_fixture(), listing_fixture(),
            REVIEW, SOURCE, self.recipient, self.pin, self.binary, 5)
        archive = self.lock / "recovery-closure"
        candidate = json.loads(self.decrypt((archive / "record-00000.cms").read_bytes()))
        self.assertEqual(canonical_sha256(candidate), receipt["candidate_sha256"])
        self.assertEqual(receipt["intent_commitment_sha256"], self.pin)
        self.assertIs(candidate["restoration_verified"], False)
        verified = read_restoration_candidate(self.root, RUN, self.decrypt, REVIEW, SOURCE,
            self.recipient, self.pin, canonical_sha256(receipt))
        self.assertTrue(verified["retained_candidate_consistent"] and verified["lock_held"])
        self.assertFalse(verified["restoration_verified"] or verified["live_execution_allowed"])
        self.assertNotIn("poststate", verified)
        self.assertEqual(self.read()["commitment"], self.commitment)
        with self.assertRaises(ValueError):
            release_sandbox_lock(self.root, RUN)
        with self.assertRaises(FileExistsError):
            retain_restoration_candidate(self.root, RUN, self.decrypt, metadata_fixture(), listing_fixture(),
                REVIEW, SOURCE, self.recipient, self.pin, self.binary, 5)

    def test_candidate_sync_failure_retains_existing_intent_and_lock(self):
        """Propagate a final candidate synchronization error while preserving original recovery data.

        Inputs:
            self: Test instance injecting only the new candidate's final directory synchronization failure.
        Outputs:
            None: Asserts no automatic unlock and continued readability of the original intent.
        """
        with patch("research.recovery_review.sync_archive_directory", side_effect=OSError("synthetic sync failure")):
            with self.assertRaises(OSError):
                retain_restoration_candidate(self.root, RUN, self.decrypt, metadata_fixture(), listing_fixture(),
                    REVIEW, SOURCE, self.recipient, self.pin, self.binary, 5)
        self.assertEqual(self.read()["commitment"], self.commitment)
        with self.assertRaises(ValueError):
            release_sandbox_lock(self.root, RUN)


    def test_candidate_reader_rejects_pins_bytes_and_changes_during_decryption(self):
        """Reject corrupted, excessive or replaced candidate/intent evidence without releasing exclusion.

        Inputs:
            self: Test instance retaining disposable CMS intent and candidate archives only.
        Outputs:
            None: Asserts closed failure for bad pins, budgets, plaintext, intent and directory changes.
        """
        receipt = retain_restoration_candidate(self.root, RUN, self.decrypt, metadata_fixture(), listing_fixture(),
            REVIEW, SOURCE, self.recipient, self.pin, self.binary, 5)
        candidate_pin = canonical_sha256(receipt)
        archive = self.lock / "recovery-closure"
        ciphertext = (archive / "record-00000.cms").read_bytes()
        intent_ciphertext = (self.archive / "record-00000.cms").read_bytes()
        for case in ("pin", "budget", "ciphertext", "plaintext", "oversized", "intent_changed", "directory"):
            with self.subTest(case=case):
                calls = 0

                def decrypt_candidate(data):
                    """Inject one candidate-stage failure while authenticating all other synthetic records.

                    Inputs:
                        data: Synthetic CMS bytes supplied by the maintained reader.
                    Outputs:
                        bytes: Authenticated disposable plaintext or one deliberate malformed payload;
                            selected cases replace only temporary test files/directories.
                    """
                    nonlocal calls
                    calls += 1
                    plain = self.decrypt(data)
                    if calls == 2:
                        if case == "plaintext":
                            changed = json.loads(plain)
                            changed["restoration_verified"] = True
                            return json.dumps(changed).encode()
                        if case == "oversized":
                            return b"x" * MAX_BYTES
                        if case == "intent_changed":
                            (self.archive / "record-00000.cms").write_bytes(b"changed-synthetic-intent")
                        if case == "directory":
                            archive.rename(self.base / "saved-closure")
                            shutil.copytree(self.base / "saved-closure", archive)
                    return plain

                if case == "ciphertext":
                    (archive / "record-00000.cms").write_bytes(b"changed-synthetic-candidate")
                try:
                    with self.assertRaises((ValueError, subprocess.SubprocessError)):
                        read_restoration_candidate(self.root, RUN, decrypt_candidate, REVIEW, SOURCE,
                            self.recipient, self.pin, "0" * 64 if case == "pin" else candidate_pin,
                            max_bytes=32 if case == "budget" else MAX_BYTES)
                    if case in {"pin", "ciphertext"}:
                        self.assertEqual(calls, 1)
                    with self.assertRaises(ValueError):
                        release_sandbox_lock(self.root, RUN)
                finally:
                    if (self.base / "saved-closure").exists():
                        shutil.rmtree(archive)
                        (self.base / "saved-closure").rename(archive)
                    (archive / "record-00000.cms").write_bytes(ciphertext)
                    (self.archive / "record-00000.cms").write_bytes(intent_ciphertext)
