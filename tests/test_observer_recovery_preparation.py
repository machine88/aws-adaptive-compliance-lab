"""Offline lock/capture/intent integration; actual CMS and SDK stubs, no AWS or Keychain."""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from functools import partial
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from research.catalog import canonical_sha256
from research.observer_recovery_preparation import prepare_recovery_from_observer, retain_preparation_manifest
from research.recovery_review import read_recovery_intent
from research.sandbox_operator import build_sandbox_scope, run_sandbox_operator
from research.sandbox_readiness import BUCKET
from research.scenario_lock import acquire_sandbox_lock, inspect_sandbox_lock, release_sandbox_lock
from scripts.sandbox_capture_worker import run_worker
from tests.crypto_fixtures import synthetic_recipient, synthetic_decrypt
from tests.test_sandbox_capture import stubbed_session
from tests.test_sandbox_observer import observation
from tests.test_sandbox_operator import configure_profile

REVIEW = "c" * 64


class ObserverRecoveryPreparationTests(unittest.TestCase):
    """Preserve lock ownership and evidence links across successful and interrupted preparation."""

    @classmethod
    def setUpClass(cls):
        """Create one disposable encryption recipient for these composed offline tests.

        Inputs:
            cls: Test class receiving temporary public/test-private paths and fingerprint.
        Outputs:
            None: Creates only synthetic key material; no real recipient or credentials.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))
        cls.binary, cls.cert = str(Path(cls.binary).resolve()), cls.cert.resolve()

    @classmethod
    def tearDownClass(cls):
        """Remove the class-owned disposable recipient after all test cases.

        Inputs:
            cls: Test class owning the temporary synthetic files.
        Outputs:
            None: Deletes only test fixtures; no operational lock or evidence is touched.
        """
        cls.keys.cleanup()

    def setUp(self):
        """Reserve an isolated private test parent and authenticated synthetic decryptor.

        Inputs:
            self: Test instance receiving disposable paths and callback configuration.
        Outputs:
            None: Registers cleanup and a test-only in-memory decryptor; no external calls.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.decrypt = partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key)

    def case(self, name):
        """Build one unused output scope and separate private lock/binding roots.

        Inputs:
            self: Test instance owning a temporary parent and synthetic certificate.
            name: Fixed test label used only beneath that temporary parent.
        Outputs:
            tuple: Lock root, binding root and current scope; creates no capture or lock.
        """
        parent = self.base / name
        parent.mkdir(mode=0o700)
        locks, bindings = parent / "locks", parent / "bindings"
        locks.mkdir(mode=0o700)
        bindings.mkdir(mode=0o700)
        scope = build_sandbox_scope(self.cert, parent / "capture", self.binary, "a" * 32)
        self.current_locks = locks
        return locks, bindings, scope

    def capture(self, scope, approved_scope_sha256):
        """Run the real observer/worker flow after asserting the caller already owns its lock.

        Inputs:
            self: Test instance with isolated lock root and disposable recipient.
            scope: Current synthetic observer scope supplied by the preparation controller.
            approved_scope_sha256: Synthetic reviewed scope hash used only for this test.
        Outputs:
            dict: Actual operator summary from SDK-stubbed capture and real CMS retention.
                Creates private test ciphertext, never invokes AWS or real credential resolution.
        """
        inspect_sandbox_lock(self.current_locks, scope["run_id"])
        identity, receipts = observation()
        session, stubbers, clients = stubbed_session(receipts, identity)
        configure_profile(session)
        for stubber in stubbers.values():
            self.addCleanup(stubber.deactivate)

        def worker(command, descriptor, timeout_seconds):
            """Replace only the process boundary while exercising the maintained worker body.

            Inputs:
                command: Trusted worker argv; not executed in this offline test.
                descriptor: Reviewed scope and hash passed by the real operator.
                timeout_seconds: Declared worker limit retained by the operator.
            Outputs:
                str: Success after the worker finishes with SDK stubs and synthetic encryption.
            """
            run_worker(descriptor["scope"], descriptor["approved_scope_sha256"], Mock(return_value=session))
            return "success"

        with patch("research.sandbox_operator.bounded_worker", side_effect=worker):
            result = run_sandbox_operator(scope, approved_scope_sha256)
        for stubber in stubbers.values():
            stubber.assert_no_pending_responses()
        return result

    def test_preparation_links_capture_manifest_and_existing_recovery_reader(self):
        """Retain a readable encrypted intent only after a new scoped pass under the held lock.

        Inputs:
            self: Test instance composing actual capture/reader/writer code with SDK stubs.
        Outputs:
            None: Asserts one callback, exact manifest linkage, closed gates and blocked reuse.
        """
        locks, bindings, scope = self.case("success")
        callback = Mock(side_effect=self.capture)
        result = prepare_recovery_from_observer(locks, bindings, scope, canonical_sha256(scope), REVIEW, callback, self.decrypt)
        callback.assert_called_once()
        self.assertTrue(result["lock_held"] and result["intent_retained"])
        self.assertFalse(result["live_execution_allowed"] or result["source_freshness_verified"])
        manifest = json.loads((bindings / (scope["run_id"] + ".json")).read_text())
        self.assertEqual(canonical_sha256(manifest), result["preparation_manifest_sha256"])
        self.assertEqual(manifest["human_review_sha256"], REVIEW)
        self.assertEqual(manifest["ciphertext_fingerprint"], result["ciphertext_fingerprint"])
        self.assertNotIn("metadata", manifest)
        read = read_recovery_intent(locks, scope["run_id"], self.decrypt,
            result["preparation_manifest_sha256"], scope["capture"]["source_sha256"], self.pin,
            result["intent_commitment_sha256"])
        self.assertEqual(read["intent_sha256"], result["intent_sha256"])
        self.assertEqual(read["record"]["review_manifest_sha256"], result["preparation_manifest_sha256"])
        with self.assertRaises(ValueError):
            release_sandbox_lock(locks, scope["run_id"])
        with self.assertRaises(FileExistsError):
            acquire_sandbox_lock(locks, scope["run_id"])

    def test_existing_output_binding_and_lock_stop_before_observation(self):
        """Reject history/reuse and contention before a callback can acquire observations.

        Inputs:
            self: Test instance varying existing output, manifest and held lock boundaries.
        Outputs:
            None: Asserts no callback on any admission failure and no automatic lock removal.
        """
        for case in ("output", "binding", "binding_symlink", "lock"):
            with self.subTest(case=case):
                locks, bindings, scope = self.case(case)
                if case == "output":
                    Path(scope["output_root"]).mkdir(mode=0o700)
                elif case == "binding":
                    (bindings / (scope["run_id"] + ".json")).write_text("{}")
                elif case == "binding_symlink":
                    (bindings / (scope["run_id"] + ".json")).symlink_to(bindings / "absent-target")
                else:
                    acquire_sandbox_lock(locks, scope["run_id"])
                callback = Mock()
                with self.assertRaises((ValueError, FileExistsError)):
                    prepare_recovery_from_observer(locks, bindings, scope, canonical_sha256(scope), REVIEW, callback, self.decrypt)
                callback.assert_not_called()
                self.assertEqual((locks / (BUCKET + ".lock")).exists(), case == "lock")

        locks, bindings, scope = self.case("unsafe_manifest_name")
        with self.assertRaises(ValueError):
            retain_preparation_manifest(bindings, {"run_id": "../escape"})
        self.assertFalse((bindings.parent / "escape.json").exists())

    def test_callback_clock_lock_and_retention_failures_preserve_exclusion(self):
        """Stop after one attempt on callback, timing, lock replacement or persistence failure.

        Inputs:
            self: Test instance using synthetic captures and independent failure variants.
        Outputs:
            None: Asserts the lock remains held, no automatic retry/mutation occurs and partial
                metadata is retained only in the appropriate persistence-failure case.
        """
        for case in ("callback", "deadline", "wall_rollback", "wall_jump", "monotonic_rollback", "old_receipts", "replaced_lock", "permissions", "owner", "retention"):
            with self.subTest(case=case):
                locks, bindings, scope = self.case(case)
                options = {}
                if case == "deadline":
                    options["monotonic_ns"] = Mock(side_effect=[0, 301_000_000_000])
                if case == "monotonic_rollback":
                    options["monotonic_ns"] = Mock(side_effect=[0, 500_000_000, 400_000_000, 700_000_000])
                if case in ("wall_rollback", "wall_jump"):
                    now = datetime.now(timezone.utc)
                    changed = now + timedelta(seconds=-1 if case == "wall_rollback" else 10)
                    options["clock"] = Mock(side_effect=[now.isoformat().replace("+00:00", "Z"), changed.isoformat().replace("+00:00", "Z")])
                    options["monotonic_ns"] = Mock(side_effect=[0, 1_000_000_000])
                if case == "old_receipts":
                    future = datetime.now(timezone.utc) + timedelta(days=1)
                    options["clock"] = Mock(side_effect=[(future + timedelta(seconds=i)).isoformat().replace("+00:00", "Z") for i in range(3)])
                    options["monotonic_ns"] = Mock(side_effect=[0, 1_000_000_000, 2_000_000_000])

                def observe(current_scope, reviewed_hash):
                    """Supply one independently varied synthetic observer outcome.

                    Inputs:
                        current_scope: Scope passed after preparation acquired its local lock.
                        reviewed_hash: Independent scope identity passed to the callback.
                    Outputs:
                        dict: Real SDK-stubbed capture summary, or deliberate callback error;
                            the lock-replacement variant renames only disposable test directories.
                    """
                    if case == "callback":
                        raise RuntimeError("synthetic callback failure")
                    result = self.capture(current_scope, reviewed_hash)
                    if case == "replaced_lock":
                        (locks / (BUCKET + ".lock")).rename(locks / "original-held-lock")
                        acquire_sandbox_lock(locks, current_scope["run_id"])
                    if case == "permissions":
                        (locks / (BUCKET + ".lock")).chmod(0o755)
                    if case == "owner":
                        (locks / (BUCKET + ".lock") / "owner.json").write_text("{}")
                    return result

                callback = Mock(side_effect=observe)
                with patch("research.observer_recovery_preparation.retain_recovery_intent", side_effect=OSError("synthetic persistence failure")) if case == "retention" else nullcontext():
                    with self.assertRaises((ValueError, RuntimeError, OSError)):
                        prepare_recovery_from_observer(locks, bindings, scope, canonical_sha256(scope), REVIEW, callback, self.decrypt, **options)
                callback.assert_called_once()
                self.assertTrue((locks / (BUCKET + ".lock")).exists())
                self.assertFalse((locks / (BUCKET + ".lock") / "recovery-intent").exists())
                self.assertEqual((bindings / (scope["run_id"] + ".json")).exists(), case == "retention")
