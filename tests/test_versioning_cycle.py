"""Synthetic change/observe/restore integration and real disposable encrypted journal checks."""
from asyncio import CancelledError
import copy
from functools import partial
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from research.archive_ingestion import read_archive_records
from research.aws_reader import EncryptedArchive
from research.catalog import canonical_sha256
from research.recovery_intent import build_recovery_intent
from research.versioning_cycle import VERSION, cycle_source_sha256, run_offline_versioning_cycle
from tests.crypto_fixtures import synthetic_recipient, synthetic_decrypt
from tests.test_sandbox_emptiness import fixture as listing_fixture
from tests.test_sandbox_readiness import fixture as metadata_fixture


class VersioningCycleTests(unittest.TestCase):
    """Check callback order, pre-change durability, ambiguity/cancellation and bounded recovery."""

    @classmethod
    def setUpClass(cls):
        """Create one disposable encryption recipient for this offline integration class.

        Inputs:
            cls: Test class receiving temporary test-only certificate/private-key paths.
        Outputs:
            None: Creates synthetic crypto only; no real credentials, Keychain or account access.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))

    @classmethod
    def tearDownClass(cls):
        """Remove disposable class encryption material.

        Inputs:
            cls: Test class owning temporary fixture files.
        Outputs:
            None: Deletes only synthetic test files.
        """
        cls.keys.cleanup()

    def fixture(self):
        """Construct a synthetic intent, fixed driver scope, fake clock and explicitly fake callbacks.

        Inputs:
            self: Test instance receiving assertion access inside disposable callbacks.
        Outputs:
            tuple: Scope, callbacks, clock, ordered invocation labels and copied journal events;
                acknowledgment hashes are test stubs, not claims of encryption outside the CMS test.
        """
        run, review, source = "a" * 32, "b" * 64, "c" * 64
        intent = build_recovery_intent(run, metadata_fixture(), listing_fixture(), review, source, self.pin)
        scope = {"version": VERSION, "phase": "development", "mode": "synthetic_only", "run_id": run,
            "source_sha256": cycle_source_sha256(), "intent_sha256": canonical_sha256(intent),
            "intent_review_sha256": review, "intent_source_sha256": source, "recipient_sha256": self.pin,
            "horizon_seconds": 1800, "max_mutation_callbacks": 1, "max_restoration_callbacks": 3}
        clock, events, records = {"ns": 0}, [], []

        def admit():
            """Supply the explicit synthetic intent, not an actual read-only preparation result.

            Inputs:
                No arguments; uses this test's disposable in-memory intent.
            Outputs:
                dict: Synthetic admission frame and copied intent; no AWS state assertion.
            """
            events.append("admit")
            return {"kind": "synthetic_development_admission", "intent": copy.deepcopy(intent)}

        def suspend(request):
            """Assert pending intent was acknowledged before the simulated change callback.

            Inputs:
                request: Fixed intent-derived Suspended request description; never sent to AWS.
            Outputs:
                None: Records synthetic invocation and validates exact fixed request.
            """
            self.assertEqual(records[1]["event"], "change_pending")
            self.assertEqual(request, intent["requests"]["proposed_mutation"])
            events.append("suspend")

        def suspended():
            """Simulate independent confirmation before opening a fixed observation window.

            Inputs:
                No arguments; advances only the disposable local clock.
            Outputs:
                bool: True for this synthetic fixture, not actual source proof.
            """
            events.append("verify_suspended")
            clock["ns"] += 10
            return True

        def observe(deadline_ns):
            """Simulate completion at the single supplied cutoff without waiting in real time.

            Inputs:
                deadline_ns: Absolute synthetic cutoff; must equal trigger plus 1,800 seconds.
            Outputs:
                dict: Exact closed-window acknowledgment and an advanced fake clock.
            """
            self.assertEqual(deadline_ns, 10 + 1800 * 1_000_000_000)
            events.append("observe")
            clock["ns"] = deadline_ns
            return {"deadline_ns": deadline_ns, "window_closed": True}

        def restore(request):
            """Record the exact intent-derived Enabled request without any SDK.

            Inputs:
                request: Fixed restoration description, never sent to an AWS endpoint.
            Outputs:
                None: Validates scope and records one synthetic restoration invocation.
            """
            self.assertEqual(request, intent["requests"]["restoration"])
            events.append("restore")

        def enabled():
            """Simulate independent Enabled confirmation, not a successful writer response.

            Inputs:
                No arguments; records a synthetic verification event.
            Outputs:
                bool: True only in this fixture; no cloud restoration claim.
            """
            events.append("verify_enabled")
            return True

        def retain(record):
            """Supply an ordered stub acknowledgment for failure-injection tests.

            Inputs:
                record: Maintained synthetic journal event, with no raw provider data.
            Outputs:
                dict: Test-only receipt; the CMS integration test replaces this with real encryption.
            """
            receipt = {"file": f"record-{len(records):05d}.cms", "ciphertext_sha256": canonical_sha256(record)}
            records.append(copy.deepcopy(record))
            return receipt

        callbacks = {"admit": admit, "suspend": suspend, "verify_suspended": suspended, "observe_until": observe,
                     "restore": restore, "verify_enabled": enabled, "retain": retain}
        return scope, callbacks, clock, events, records

    def run_cycle(self, scope, callbacks, clock):
        """Invoke the maintained offline driver with the fixture's independent scope pin and clock.

        Inputs:
            self: Test instance orchestrating only synthetic callbacks.
            scope: Current fixed offline scope with retained intent/source pins.
            callbacks: Disposable test callback map.
            clock: Mutable test-only nanosecond counter, not the host clock.
        Outputs:
            dict: Synthetic driver summary; no real time sleep, AWS request or operational lock.
        """
        return run_offline_versioning_cycle(scope, canonical_sha256(scope), callbacks, lambda: clock["ns"])

    def test_normal_cycle_with_actual_encrypted_journal(self):
        """Compose fixed ordering with actual encrypted retention and authenticated disposable readback.

        Inputs:
            self: Test instance using its disposable recipient and fake 1,800-second clock.
        Outputs:
            None: Asserts pre-change durability, fixed cutoff, retained terminal state and closed live gates.
        """
        scope, callbacks, clock, events, records = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            archive = EncryptedArchive(Path(directory).resolve() / "journal", self.cert, self.binary, 5)

            def encrypt(record):
                """Replace the test stub with the real existing CMS archive writer.

                Inputs:
                    record: Synthetic driver event requiring durable encrypted retention.
                Outputs:
                    dict: Real ordered ciphertext receipt after local synchronization.
                """
                receipt = archive.write(record)
                records.append(copy.deepcopy(record))
                return receipt

            callbacks["retain"] = encrypt
            result = self.run_cycle(scope, callbacks, clock)
            decrypt = partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key)
            decoded, receipts = read_archive_records(archive.root, decrypt, self.pin, max_records=20, max_bytes=1048576)
            self.assertEqual(decoded, records)
            self.assertEqual(events, ["admit", "suspend", "verify_suspended", "observe", "restore", "verify_enabled"])
            self.assertEqual((result["mutation_callbacks"], result["restoration_callbacks"]), (1, 1))
            self.assertTrue(result["window_completed"] and result["restored_in_simulation"] and result["durable_journal_complete"])
            self.assertFalse(result["live_execution_allowed"] or result["lock_release_allowed"] or result["restoration_verified"])
            self.assertEqual(decoded[-1]["event"], "cycle_terminal")
            self.assertFalse(any(path.suffix == ".json" for path in archive.root.iterdir()))

    def test_admission_scope_and_prechange_journal_failures_never_call_change(self):
        """Reject real-preparation promotion, changed scope/intent and missing durable pre-change records.

        Inputs:
            self: Test instance injecting admission or pre-change retention failures.
        Outputs:
            None: Asserts no mutation, observation or restoration callback on rejected admission.
        """
        for case in ("mode", "intent", "real_preparation", "admission_error", "first_record", "pending_record"):
            scope, callbacks, clock, events, records = self.fixture()
            if case == "mode":
                scope["mode"] = "live"
            if case == "intent":
                scope["intent_sha256"] = "0" * 64
            if case == "admission_error":
                callbacks["admit"] = Mock(side_effect=OSError("synthetic private provider text"))
            if case == "real_preparation":
                callbacks["admit"] = Mock(return_value={"phase": "development", "lock_held": True, "intent_retained": True})
            if case in {"first_record", "pending_record"}:
                normal = callbacks["retain"]

                def fail(record):
                    """Refuse the selected pre-change record without acknowledging it.

                    Inputs:
                        record: Disposable synthetic journal event.
                    Outputs:
                        dict: Prior acknowledgments only; selected event raises a synthetic failure.
                    """
                    if case == "first_record" or record["event"] == "change_pending":
                        raise OSError("synthetic private provider text")
                    return normal(record)

                callbacks["retain"] = fail
            with self.subTest(case=case), self.assertRaises(ValueError) as raised:
                self.run_cycle(scope, callbacks, clock)
            self.assertNotIn("synthetic private provider text", str(raised.exception))
            self.assertNotIn("suspend", events)
            self.assertNotIn("restore", events)

    def test_change_observation_and_cancellation_errors_restore_without_mutation_retry(self):
        """Route ambiguous changes, unverified triggers, bad windows and cancellation into recovery.

        Inputs:
            self: Test instance varying only explicitly synthetic callback outcomes.
        Outputs:
            None: Asserts one change at most, independent verification and immediate bounded recovery.
        """
        for case in ("write_error", "unverified", "verify_error", "early_window", "clock_rollback", "cancel"):
            scope, callbacks, clock, events, records = self.fixture()
            if case == "write_error":
                callbacks["suspend"] = Mock(side_effect=TimeoutError("private callback error"))
            if case == "unverified":
                callbacks["verify_suspended"] = Mock(return_value=False)
            if case == "verify_error":
                callbacks["verify_suspended"] = Mock(side_effect=ValueError("private callback error"))
            if case in {"early_window", "clock_rollback", "cancel"}:
                def observe(deadline_ns):
                    """Return early, roll the clock back, or cancel the synthetic observation callback.

                    Inputs:
                        deadline_ns: Original fixed cutoff, never changed by the test.
                    Outputs:
                        dict: Deliberately incomplete window or propagated synthetic cancellation.
                    """
                    if case == "cancel":
                        raise CancelledError()
                    if case == "clock_rollback":
                        clock["ns"] = 0
                    return {"deadline_ns": deadline_ns, "window_closed": True}
                callbacks["observe_until"] = observe
            with self.subTest(case=case):
                result = self.run_cycle(scope, callbacks, clock)
            self.assertEqual((result["mutation_callbacks"], result["restoration_callbacks"]), (1, 1))
            self.assertTrue(result["restored_in_simulation"])
            self.assertFalse(result["window_completed"])
            self.assertNotIn("private callback error", json.dumps(result))
            if case in {"unverified", "verify_error", "write_error"}:
                self.assertNotIn("observe", events)

    def test_restore_bounds_ambiguous_writes_and_journal_outage(self):
        """Require independent Enabled confirmation; bound failed/cancelled recovery and preserve review gates.

        Inputs:
            self: Test instance injecting only synthetic restoration and post-change retention faults.
        Outputs:
            None: Asserts at most three restoration requests, one after cancellation and no release authority.
        """
        for case in ("failed", "ambiguous_verified", "restore_cancel", "verify_cancel", "journal_outage"):
            scope, callbacks, clock, events, records = self.fixture()
            if case == "failed":
                callbacks["verify_enabled"] = Mock(return_value=False)
            if case == "ambiguous_verified":
                callbacks["restore"] = Mock(side_effect=TimeoutError("private callback error"))
            if case == "restore_cancel":
                callbacks["restore"] = Mock(side_effect=KeyboardInterrupt())
                callbacks["verify_enabled"] = Mock(return_value=False)
            if case == "verify_cancel":
                callbacks["verify_enabled"] = Mock(side_effect=CancelledError())
            if case == "journal_outage":
                normal = callbacks["retain"]

                def outage(record):
                    """Keep only the two mandatory records, then simulate an unavailable journal.

                    Inputs:
                        record: Maintained synthetic event; recovery calls must still proceed.
                    Outputs:
                        dict: Initial stub receipts only; later events raise a synthetic storage failure.
                    """
                    if len(records) >= 2:
                        raise OSError("synthetic journal unavailable")
                    return normal(record)
                callbacks["retain"] = outage
            with self.subTest(case=case):
                result = self.run_cycle(scope, callbacks, clock)
            self.assertEqual(result["mutation_callbacks"], 1)
            self.assertEqual(result["restoration_callbacks"], 3 if case == "failed" else 1)
            self.assertEqual(result["restored_in_simulation"], case in {"ambiguous_verified", "journal_outage"})
            self.assertEqual(result["manual_review_required"], case != "ambiguous_verified")
            self.assertEqual(result["durable_journal_complete"], case != "journal_outage")
            self.assertFalse(result["lock_release_allowed"] or result["live_execution_allowed"])
