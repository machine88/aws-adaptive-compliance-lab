"""Offline operator/worker composition tests; no real profiles, credentials or AWS calls."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from research.catalog import canonical_sha256
from research.sandbox_operator import PROFILE, build_sandbox_scope, run_sandbox_operator
from scripts.capture_sandbox import main
from scripts.sandbox_capture_worker import run_worker, validate_observer_profile
from tests.crypto_fixtures import synthetic_recipient
from tests.test_sandbox_capture import decrypt_records, stubbed_session
from tests.test_sandbox_observer import observation


def configure_profile(session):
    """Supply only synthetic SDK profile metadata for the exact permitted role chain.

    Inputs:
        session: Mock session receiving local configuration stubs, never credentials.
    Outputs:
        None: Sets in-memory configuration responses; performs no IO or SDK calls.
    """
    session._session.get_scoped_config.return_value = {
        "role_arn": "arn:aws:iam::653464153304:role/dissertation-sandbox-observer",
        "source_profile": "dissertation", "role_session_name": "dissertation-sandbox-observer",
        "duration_seconds": "900", "region": "us-east-2"}
    session._session.full_config = {"profiles": {"dissertation": {
        "login_session": "synthetic-local-login", "region": "us-east-2", "output": "json"}}}


class SandboxOperatorTests(unittest.TestCase):
    """Verify consent gates, SDK/CMS composition and preservation of timeout outcomes."""

    @classmethod
    def setUpClass(cls):
        """Create one disposable encryption recipient for offline integration tests.

        Inputs:
            cls: Test class receiving disposable test-only paths.
        Outputs:
            None: Creates synthetic keys/certificate; never accesses real keys or Keychain.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))
        cls.binary, cls.cert = str(Path(cls.binary).resolve()), cls.cert.resolve()

    @classmethod
    def tearDownClass(cls):
        """Remove the class-owned disposable test recipient.

        Inputs:
            cls: Test class owning synthetic files.
        Outputs:
            None: Deletes only temporary test files.
        """
        cls.keys.cleanup()

    def setUp(self):
        """Build a current local scope without creating a capture or touching a profile.

        Inputs:
            self: Test instance receiving a private temporary parent and review scope.
        Outputs:
            None: Writes one private synthetic scope JSON and registers automatic cleanup.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.scope = build_sandbox_scope(self.cert, self.root / "run", self.binary, "a" * 32)
        self.scope_path = self.root / "scope.json"
        self.scope_path.write_text(json.dumps(self.scope))
        self.scope_path.chmod(0o600)

    def test_preview_and_flag_gates_never_start_worker(self):
        """Keep default preview credential-free and reject partial execution flags.

        Inputs:
            self: Test instance with a private synthetic scope.
        Outputs:
            None: Asserts no worker/output creation and no private paths in displayed summaries.
        """
        output = io.StringIO()
        with patch("research.sandbox_operator.bounded_worker") as worker, contextlib.redirect_stdout(output):
            self.assertEqual(main(["--scope", str(self.scope_path)]), 0)
            worker.assert_not_called()
        self.assertFalse((self.root / "run").exists())
        self.assertNotIn(str(self.root), output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            for extra in (["--execute"], ["--approved-scope-sha256", "b" * 64]):
                with self.assertRaises(SystemExit):
                    main(["--scope", str(self.scope_path)] + extra)

    def test_changed_review_bindings_fail_before_output(self):
        """Reject stale review hashes and changed runtime/source pins before starting a worker.

        Inputs:
            self: Test instance varying independent binding boundaries.
        Outputs:
            None: Asserts every mismatch leaves the future capture path uncreated.
        """
        changed = copy.deepcopy(self.scope)
        changed["runtime_versions"]["boto3"] += "-changed"
        source = copy.deepcopy(self.scope)
        source["capture"]["source_sha256"] = "b" * 64
        with patch("research.sandbox_operator.bounded_worker") as worker:
            for scope, digest in ((self.scope, "b" * 64), (changed, canonical_sha256(changed)),
                                  (source, canonical_sha256(source))):
                with self.assertRaises(ValueError):
                    run_sandbox_operator(scope, digest)
            worker.assert_not_called()
        self.assertFalse((self.root / "run").exists())

    def test_operator_worker_sdk_and_encryption_compose(self):
        """Connect the real worker/collector to modeled SDK stubs and real disposable CMS output.

        Inputs:
            self: Test instance with real local bindings, synthetic SDK responses and recipient.
        Outputs:
            None: Asserts the supervised descriptor, role profile, ciphertext journals and no
            automatic rerun. The subprocess boundary alone is mocked; existing supervisor
            tests cover actual process-group timeout/reaping behavior.
        """
        identity, receipts = observation()
        session, stubbers, clients = stubbed_session(receipts, identity)
        configure_profile(session)
        for stubber in stubbers.values():
            self.addCleanup(stubber.deactivate)
        factory = Mock(return_value=session)

        def worker(command, descriptor, timeout_seconds):
            """Execute the real silent worker body against explicit offline SDK stubs.

            Inputs:
                command: Trusted argv expected to name isolated Python and the fixed worker.
                descriptor: Bound scope and independently supplied approval fingerprint.
                timeout_seconds: Fixed supervisor deadline passed by the operator.
            Outputs:
                str: Synthetic supervisor success after the real worker body returns.
                    Does not spawn a process or perform AWS IO.
            """
            self.assertEqual(command[1], "-I")
            self.assertTrue(command[2].endswith("scripts/sandbox_capture_worker.py"))
            self.assertEqual(timeout_seconds, 150)
            run_worker(descriptor["scope"], descriptor["approved_scope_sha256"], factory)
            return "success"

        with patch("research.sandbox_operator.bounded_worker", side_effect=worker) as supervised:
            result = run_sandbox_operator(self.scope, canonical_sha256(self.scope))
            self.assertEqual(result["worker_status"], "success")
            self.assertFalse(result["capture_completion_independently_verified"])
            with self.assertRaises(FileExistsError):
                run_sandbox_operator(self.scope, canonical_sha256(self.scope))
            self.assertEqual(supervised.call_count, 1)
        factory.assert_called_once_with(profile_name=PROFILE, region_name="us-east-2")
        for stubber in stubbers.values():
            stubber.assert_no_pending_responses()
        root = self.root / "run"
        records = decrypt_records(root / "capture", self.binary, self.cert, self.key)
        self.assertEqual(records[-1]["kind"], "sandbox_capture_completion")
        self.assertEqual(records[0]["operator_scope_sha256"], canonical_sha256(self.scope))
        journal = decrypt_records(root / "journal", self.binary, self.cert, self.key)
        self.assertEqual(journal[-1]["worker_status"], "success")
        self.assertEqual(journal[-1]["ciphertext_fingerprint"], result["ciphertext_fingerprint"])
        self.assertEqual(len(result["ciphertext_fingerprint"]), 64)
        self.assertEqual(journal[0]["scope_sha256"], canonical_sha256(self.scope))

    def test_timeout_and_profile_failures_remain_closed(self):
        """Preserve failed worker status and reject credential-process or wrong-role profiles.

        Inputs:
            self: Test instance using a mocked timeout and synthetic profile configurations.
        Outputs:
            None: Asserts encrypted timeout outcome, no completion claim and profile rejection
            without resolving credentials or issuing a service request.
        """
        with patch("research.sandbox_operator.bounded_worker", return_value="timeout"):
            result = run_sandbox_operator(self.scope, canonical_sha256(self.scope))
        self.assertEqual(result["worker_status"], "timeout")
        self.assertFalse(result["live_execution_allowed"])
        journal = decrypt_records(self.root / "run/journal", self.binary, self.cert, self.key)
        self.assertEqual(journal[-1]["worker_status"], "timeout")
        self.assertFalse((self.root / "run/capture").exists())
        for field, value in (("role_arn", "arn:aws:iam::653464153304:role/other"),
                             ("credential_process", "never-executed")):
            session = Mock()
            configure_profile(session)
            session._session.get_scoped_config.return_value[field] = value
            with self.assertRaises(ValueError):
                validate_observer_profile(session)
            session.client.assert_not_called()
        session = Mock()
        configure_profile(session)
        session._session.full_config["profiles"]["dissertation"]["credential_process"] = "never-executed"
        with self.assertRaises(ValueError):
            validate_observer_profile(session)
        session.client.assert_not_called()
