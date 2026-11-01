"""Preview-first operator integration tests; native helper execution is always mocked."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from research.catalog import canonical_sha256
from research.recovery_intent import retain_recovery_intent
from research.recovery_operator import VERSION, operator_source_sha256, preview_recovery_scope, verify_with_keychain
from research.recovery_review import MAX_BYTES
from research.scenario_lock import acquire_sandbox_lock
from scripts.review_recovery import main
from tests.crypto_fixtures import synthetic_recipient
from tests.test_sandbox_emptiness import fixture as listing_fixture
from tests.test_sandbox_readiness import fixture as metadata_fixture

RUN, REVIEW, SOURCE = "a" * 32, "b" * 64, "c" * 64


class RecoveryOperatorTests(unittest.TestCase):
    """Compose the real bridge and reader with disposable data and a fake native subprocess."""

    @classmethod
    def setUpClass(cls):
        """Prepare one disposable CMS recipient, never a real Keychain item.

        Inputs:
            cls: Test class receiving only temporary synthetic encryption paths.
        Outputs:
            None: Creates test files that tearDownClass removes.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))

    @classmethod
    def tearDownClass(cls):
        """Remove only the class's disposable synthetic recipient.

        Inputs:
            cls: Test class owning the temporary key directory.
        Outputs:
            None: Removes synthetic test files; no real credential access.
        """
        cls.keys.cleanup()

    def setUp(self):
        """Create private dummy helper paths, a retained synthetic intent and local review scope.

        Inputs:
            self: Test instance receiving private disposable paths and scope pins.
        Outputs:
            None: Creates test fixtures and registers cleanup; no native helper or AWS call.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.locks, self.recipient, self.scratch = [self.base / name for name in ("locks", "recipient", "scratch")]
        for directory in (self.locks, self.recipient, self.scratch):
            directory.mkdir(mode=0o700)
        self.helper = self.base / "dummy-helper"
        self.helper.write_bytes(b"synthetic-helper-never-executed")
        self.helper.chmod(0o700)
        for name in ("recipient-public.pem", "private-key.encrypted.pem", "recipient-metadata.json"):
            file = self.recipient / name
            file.write_bytes(self.cert.read_bytes() if name == "recipient-public.pem" else b"synthetic-placeholder-not-key-material")
            file.chmod(0o600)
        acquire_sandbox_lock(self.locks, RUN)
        commitment = retain_recovery_intent(self.locks, RUN, metadata_fixture(), listing_fixture(), REVIEW,
            SOURCE, self.pin, self.cert, self.binary, 5)
        self.scope = {"version": VERSION, "phase": "development", "run_id": RUN,
            "lock_root": str(self.locks), "review_manifest_sha256": REVIEW, "source_sha256": SOURCE,
            "recipient_sha256": self.pin, "commitment_sha256": canonical_sha256(commitment),
            "helper": str(self.helper), "helper_sha256": hashlib.sha256(self.helper.read_bytes()).hexdigest(),
            "recipient": str(self.recipient), "scratch": str(self.scratch),
            "operator_source_sha256": operator_source_sha256(), "max_bytes": MAX_BYTES}
        self.scope_path = self.base / "scope.json"
        self.scope_path.write_text(json.dumps(self.scope))
        self.scope_path.chmod(0o600)

    def test_default_preview_does_not_construct_keychain_callback(self):
        """Keep default CLI mode read-only and free of native helper construction or decrypted output.

        Inputs:
            self: Test instance with a valid private scope and captured CLI output.
        Outputs:
            None: Asserts preview success, no Keychain construction and no private path output.
        """
        output = io.StringIO()
        with patch("research.recovery_operator.MacKeychainDecryptor", side_effect=AssertionError("No callback in preview")) as factory, contextlib.redirect_stdout(output):
            self.assertEqual(main(["--scope", str(self.scope_path)]), 0)
        factory.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual(result["mode"], "preview")
        self.assertIs(result["keychain_invoked"], False)
        self.assertNotIn(str(self.helper), output.getvalue())
        self.assertNotIn("prestate", output.getvalue())

    def test_scope_and_source_pin_mismatches_stop_before_callback(self):
        """Reject mismatched approval/source fingerprints before native bridge construction.

        Inputs:
            self: Test instance using independent negative scope/source pin cases.
        Outputs:
            None: Asserts neither mismatch opens a callback or sensitive target.
        """
        with patch("research.recovery_operator.MacKeychainDecryptor") as factory:
            with self.assertRaises(ValueError):
                verify_with_keychain(self.scope, "d" * 64)
            changed = copy.deepcopy(self.scope)
            changed["operator_source_sha256"] = "d" * 64
            with self.assertRaises(ValueError):
                verify_with_keychain(changed, canonical_sha256(changed))
            factory.assert_not_called()

    def test_invalid_development_scope_and_cli_execution_pair_rejected(self):
        """Reject widened phase/schema, unbounded limits, relative paths and missing execute approval.

        Inputs:
            self: Test instance varying declared local scope and CLI flag combinations.
        Outputs:
            None: Asserts validation failure before helper invocation.
        """
        for field, value in (("phase", "pilot"), ("max_bytes", True), ("max_bytes", MAX_BYTES + 1),
                             ("helper", "relative-helper"), ("lock_root", "/tmp/../other"), ("extra", "field")):
            changed = copy.deepcopy(self.scope)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                preview_recovery_scope(changed)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(["--scope", str(self.scope_path), "--execute"])
            with self.assertRaises(SystemExit):
                main(["--scope", str(self.scope_path), "--approved-scope-sha256", canonical_sha256(self.scope)])

    def test_real_bridge_reader_composition_with_mocked_native_helper(self):
        """Exercise captured bridge pipes and actual CMS parsing without accessing any Keychain.

        Inputs:
            self: Test instance using disposable recipient data and a mocked native helper process.
        Outputs:
            None: Asserts one callback, clean ciphertext scratch, minimal summary and closed gates.
        """
        actual_run = subprocess.run

        def fake_helper(args, capture_output, check, timeout):
            """Authenticate the supplied synthetic ciphertext instead of launching the native helper.

            Inputs:
                args: Existing bridge argv, including the temporary ciphertext file path.
                capture_output: Must retain native output privately in the parent pipe.
                check: Must reject nonzero helper exit status.
                timeout: Existing bounded native helper deadline.
            Outputs:
                CompletedProcess: Actual synthetic CMS plaintext bytes; never calls Keychain.
            """
            self.assertTrue(capture_output and check)
            self.assertEqual(timeout, 60)
            ciphertext = Path(args[2]).read_bytes()
            plaintext = actual_run([self.binary, "cms", "-decrypt", "-binary", "-inform", "DER",
                "-recip", str(self.cert), "-inkey", str(self.key)], input=ciphertext,
                check=True, capture_output=True, timeout=5).stdout
            return subprocess.CompletedProcess(args, 0, stdout=plaintext, stderr=b"")

        output = io.StringIO()
        with patch("research.keychain_decryption.platform.system", return_value="Darwin"), patch("research.keychain_decryption.subprocess.run", side_effect=fake_helper) as native, contextlib.redirect_stdout(output):
            self.assertEqual(main(["--scope", str(self.scope_path), "--execute",
                                   "--approved-scope-sha256", canonical_sha256(self.scope)]), 0)
        self.assertEqual(native.call_count, 1)
        result = json.loads(output.getvalue())
        self.assertTrue(result["local_intent_consistency"])
        self.assertIs(result["live_execution_allowed"], False)
        self.assertIs(result["restoration_verified"], False)
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertNotIn("prestate", output.getvalue())
        self.assertNotIn(str(self.recipient), output.getvalue())

    def test_helper_failure_has_generic_output_and_cleans_scratch(self):
        """Prevent a failed helper's private captured bytes from leaking through the CLI.

        Inputs:
            self: Test instance injecting a native error containing synthetic sensitive markers.
        Outputs:
            None: Asserts generic failure, no success output, no leaked marker and clean scratch.
        """
        output, error = io.StringIO(), io.StringIO()
        failure = subprocess.CalledProcessError(1, ["helper"], output=b"private-marker", stderr=b"private-marker")
        with patch("research.keychain_decryption.platform.system", return_value="Darwin"), patch("research.keychain_decryption.subprocess.run", side_effect=failure), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(main(["--scope", str(self.scope_path), "--execute",
                                   "--approved-scope-sha256", canonical_sha256(self.scope)]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("private-marker", error.getvalue())
        self.assertEqual(json.loads(error.getvalue())["status"], "local_verification_failed")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_unsafe_scope_files_fail_before_callback(self):
        """Reject broad permissions and duplicate scope fields at the private input boundary.

        Inputs:
            self: Test instance modifying only its disposable scope file.
        Outputs:
            None: Asserts CLI failure without Keychain construction.
        """
        with patch("research.recovery_operator.MacKeychainDecryptor") as factory, contextlib.redirect_stderr(io.StringIO()):
            self.scope_path.chmod(0o644)
            self.assertEqual(main(["--scope", str(self.scope_path)]), 1)
            self.scope_path.chmod(0o600)
            self.scope_path.write_text(self.scope_path.read_text().replace('"phase":', '"phase": "pilot", "phase":'))
            self.assertEqual(main(["--scope", str(self.scope_path)]), 1)
            factory.assert_not_called()
