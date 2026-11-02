"""Offline preparation command integration with disposable crypto, SDK stubs and no real Keychain."""
import contextlib
import copy
from functools import partial
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from research.catalog import canonical_sha256
from research.preparation_operator import (ROOT, VERSION, preparation_source_sha256,
    run_preparation_operator, run_preparation_worker, validate_preparation_scope, read_preparation_result)
from research.sandbox_operator import build_sandbox_scope
from research.sandbox_readiness import BUCKET
from research.scenario_lock import acquire_sandbox_lock, inspect_sandbox_lock
from scripts.prepare_sandbox import main
from scripts.sandbox_capture_worker import run_worker
from tests.crypto_fixtures import synthetic_recipient, synthetic_decrypt
from tests.test_sandbox_capture import stubbed_session
from tests.test_sandbox_observer import observation
from tests.test_sandbox_operator import configure_profile


class PreparationOperatorTests(unittest.TestCase):
    """Verify preview gates, composed encrypted preparation and interrupted-run preservation."""

    @classmethod
    def setUpClass(cls):
        """Create disposable test-only encryption material.

        Inputs:
            cls: Test class receiving temporary synthetic certificate/key paths.
        Outputs:
            None: Creates no real recipient, credentials, AWS session or Keychain item.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))
        cls.binary = str(Path(cls.binary).resolve())

    @classmethod
    def tearDownClass(cls):
        """Remove the disposable class recipient.

        Inputs:
            cls: Test class owning temporary synthetic crypto files.
        Outputs:
            None: Deletes only disposable test files.
        """
        cls.keys.cleanup()

    def setUp(self):
        """Prepare a current scope with disjoint private temporary paths and test-only bridge pins.

        Inputs:
            self: Test instance receiving isolated fixture directories and reviewed test scope.
        Outputs:
            None: Creates synthetic metadata and ciphertext placeholder, not a real Keychain item.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        for name in ("locks", "bindings", "scratch", "recipient"):
            (self.base / name).mkdir(mode=0o700)
        recipient = self.base / "recipient"
        for name, data in (("recipient-public.pem", self.cert.read_bytes()),
                           ("private-key.encrypted.pem", b"synthetic-encrypted-placeholder"),
                           ("recipient-metadata.json", b'{}')):
            (recipient / name).write_bytes(data)
            (recipient / name).chmod(0o600)
        helper = self.base / "synthetic-never-executed-helper"
        helper.write_bytes(b"synthetic helper, never executed")
        helper.chmod(0o700)
        observer = build_sandbox_scope(recipient / "recipient-public.pem", self.base / "capture", self.binary, "a" * 32)
        self.scope = {"version": VERSION, "phase": "development", "observer": observer,
            "observer_scope_sha256": canonical_sha256(observer), "human_review_sha256": "c" * 64,
            "lock_root": str(self.base / "locks"), "binding_root": str(self.base / "bindings"),
            "operator_root": str(self.base / "operator"), "source_sha256": preparation_source_sha256(),
            "worker_timeout_seconds": 330, "bridge": {"helper": str(helper),
                "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(), "recipient": str(recipient),
                "scratch": str(self.base / "scratch"),
                "recipient_metadata_sha256": hashlib.sha256((recipient / "recipient-metadata.json").read_bytes()).hexdigest(),
                "encrypted_private_key_sha256": hashlib.sha256((recipient / "private-key.encrypted.pem").read_bytes()).hexdigest(),
                "helper_source_sha256": hashlib.sha256((ROOT / "scripts/macos_decrypt_record.swift").read_bytes()).hexdigest()}}
        self.path = self.base / "scope.json"
        self.path.write_text(json.dumps(self.scope))
        self.path.chmod(0o600)
        self.decrypt = partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key)

    def test_preview_and_changed_dependencies_fail_before_execution(self):
        """Keep preview free of side effects and reject changed scope/dependencies before worker start.

        Inputs:
            self: Test instance with a synthetic reviewed preparation scope.
        Outputs:
            None: Asserts no worker/helper calls, no output reservation and strict execution flags.
        """
        with patch("research.preparation_operator.bounded_worker") as worker, \
                patch("research.preparation_operator.MacKeychainDecryptor") as decrypt, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--scope", str(self.path)]), 0)
        worker.assert_not_called()
        decrypt.assert_not_called()
        self.assertNotIn(str(self.base), output.getvalue())
        self.assertFalse((self.base / "operator").exists())
        with contextlib.redirect_stderr(io.StringIO()):
            for extra in (["--execute"], ["--approved-scope-sha256", "b" * 64]):
                with self.assertRaises(SystemExit):
                    main(["--scope", str(self.path)] + extra)
        for case in ("source", "helper", "metadata", "key", "review", "overlap"):
            changed = copy.deepcopy(self.scope)
            if case == "source":
                changed["source_sha256"] = "0" * 64
            elif case == "review":
                changed["human_review_sha256"] = "0" * 64
            elif case == "overlap":
                changed["operator_root"] = changed["lock_root"]
            else:
                name = {"helper": "helper_sha256", "metadata": "recipient_metadata_sha256",
                        "key": "encrypted_private_key_sha256"}[case]
                changed["bridge"][name] = "0" * 64
            with self.subTest(case=case), patch("research.preparation_operator.bounded_worker") as worker:
                with self.assertRaises(ValueError):
                    run_preparation_operator(changed, canonical_sha256(self.scope) if case == "review" else canonical_sha256(changed))
                worker.assert_not_called()
            self.assertFalse((self.base / "operator").exists())
        acquire_sandbox_lock(self.scope["lock_root"], self.scope["observer"]["run_id"])
        with self.assertRaises(ValueError):
            validate_preparation_scope(self.scope, canonical_sha256(self.scope))

    def test_supervised_worker_composes_capture_and_verifies_retained_intent(self):
        """Exercise real capture/crypto/intent readers through both mocked process boundaries.

        Inputs:
            self: Test instance using SDK stubs and a disposable in-memory authenticated decryptor.
        Outputs:
            None: Asserts one capture, nested group ownership, verified intent, minimal result and held lock.
        """
        identity, receipts = observation()
        session, stubbers, clients = stubbed_session(receipts, identity)
        configure_profile(session)
        for stubber in stubbers.values():
            self.addCleanup(stubber.deactivate)

        def capture_worker(command, descriptor, timeout_seconds, **options):
            """Replace only nested process launch with the real SDK-stubbed observer worker.

            Inputs:
                command: Maintained worker argv, never launched in this offline test.
                descriptor: Reviewed observer scope and independent pin.
                timeout_seconds: Expected existing observer timeout.
                options: Must declare inherited outer-supervisor group ownership.
            Outputs:
                str: Success after real encrypted capture; no live AWS call.
            """
            self.assertEqual(options, {"inherit_supervisor_group": True})
            self.assertEqual(timeout_seconds, 150)
            inspect_sandbox_lock(self.scope["lock_root"], self.scope["observer"]["run_id"])
            run_worker(descriptor["scope"], descriptor["approved_scope_sha256"], Mock(return_value=session))
            return "success"

        def preparation_worker(command, descriptor, timeout_seconds, **options):
            """Run the actual preparation body with a disposable decryptor and isolated-leader metadata.

            Inputs:
                command: Fixed outer worker argv; not launched by this offline test.
                descriptor: Reviewed preparation scope and independent pin.
                timeout_seconds: Fixed outer deadline.
                options: Must request group-wide cleanup on normal exit as well as timeout.
            Outputs:
                str: Success only after actual ciphertext/intent consistency verification.
            """
            self.assertEqual(options, {"terminate_group_on_exit": True})
            self.assertEqual(timeout_seconds, 330)
            with patch("research.preparation_operator.os.getsid", return_value=os.getpid()), \
                    patch("research.preparation_operator.os.getpgrp", return_value=os.getpid()), \
                    patch("research.preparation_operator.MacKeychainDecryptor", return_value=self.decrypt), \
                    patch("research.sandbox_operator.bounded_worker", side_effect=capture_worker) as capture:
                run_preparation_worker(descriptor["scope"], descriptor["approved_scope_sha256"])
            capture.assert_called_once()
            return "success"

        with patch("research.preparation_operator.bounded_worker", side_effect=preparation_worker) as outer:
            result = run_preparation_operator(self.scope, canonical_sha256(self.scope))
        outer.assert_called_once()
        self.assertEqual(result["worker_status"], "success")
        self.assertFalse(result["worker_report_verified"] or result["live_execution_allowed"])
        retained = json.loads((self.base / "operator/result.json").read_text())
        self.assertEqual(canonical_sha256(retained), result["result_sha256"])
        self.assertTrue(retained["retained_intent_consistency_verified"])
        self.assertFalse(retained["source_freshness_verified"])
        self.assertNotIn("metadata", retained)
        self.assertEqual(set((self.base / "locks" / (BUCKET + ".lock")).iterdir()),
            {self.base / "locks" / (BUCKET + ".lock") / name for name in ("owner.json", "recovery-intent")})
        # Result admission must reject scientific gate promotion and unexpected raw-data fields.
        for case in ("gate", "extra"):
            changed = copy.deepcopy(retained)
            changed["source_freshness_verified" if case == "gate" else "metadata"] = True
            (self.base / "operator/result.json").write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                read_preparation_result(self.base / "operator", self.scope, canonical_sha256(self.scope))
        for stubber in stubbers.values():
            stubber.assert_no_pending_responses()
        with self.assertRaises(ValueError):
            run_preparation_operator(self.scope, canonical_sha256(self.scope))

    def test_timeout_and_false_success_preserve_partial_work_without_retry(self):
        """Retain exclusion on timeout and refuse success without the worker's exact result.

        Inputs:
            self: Test instance using synthetic process outcomes only.
        Outputs:
            None: Asserts one invocation, preserved owner lock, retained status and blocked reuse.
        """
        def interrupted(command, descriptor, timeout_seconds, **options):
            """Simulate outer interruption after worker acquired the persistent lock.

            Inputs:
                command: Fixed worker argv, never executed.
                descriptor: Reviewed scope and approval pin.
                timeout_seconds: Outer deadline retained by the operator.
                options: Supervisor cleanup options, not used to launch a process here.
            Outputs:
                str: Timeout after creating only the synthetic owner lock.
            """
            acquire_sandbox_lock(self.scope["lock_root"], self.scope["observer"]["run_id"])
            return "timeout"
        with patch("research.preparation_operator.bounded_worker", side_effect=interrupted) as worker:
            result = run_preparation_operator(self.scope, canonical_sha256(self.scope))
        worker.assert_called_once()
        self.assertEqual(result["worker_status"], "timeout")
        inspect_sandbox_lock(self.scope["lock_root"], self.scope["observer"]["run_id"])
        self.assertIsNone(result["result_sha256"])
        # A worker exit without a retained result must never produce a successful status file.
        scope = copy.deepcopy(self.scope)
        scope["operator_root"] = str(self.base / "other-operator")
        scope["lock_root"] = str(self.base / "other-locks")
        Path(scope["lock_root"]).mkdir(mode=0o700)
        with patch("research.preparation_operator.bounded_worker", return_value="success"):
            with self.assertRaises(FileNotFoundError):
                run_preparation_operator(scope, canonical_sha256(scope))
        self.assertFalse((self.base / "other-operator/status.json").exists())
