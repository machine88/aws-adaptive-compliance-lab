"""Real SDK stub and CMS integration coverage for bounded sandbox observation; no AWS IO."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber

from research.aws_reader import EncryptedArchive
from research.catalog import canonical_sha256
from research.sandbox_capture import SendBudget, capture_sandbox, capture_scope, capture_source_sha256, invoke_sandbox_read
from tests.crypto_fixtures import synthetic_recipient
from tests.test_sandbox_observer import observation


def stubbed_session(receipts, identity, error_operation=None):
    """Prepare real SDK clients with deterministic modeled responses and no network access.

    Inputs:
        receipts: Synthetic ordered S3 receipt fixtures; only responses and request params are used.
        identity: Synthetic STS response whose identity may intentionally be invalid.
        error_operation: Optional operation receiving AccessDenied and stopping later stubs.
    Outputs:
        tuple: Mock session, real stubbers and clients. Starts stubs; caller must stop them.
            Uses only explicit dummy credentials and performs no credential discovery or AWS IO.
    """
    sdk = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-2")
    clients = {service: sdk.client(service) for service in ("sts", "s3")}
    stubbers = {service: Stubber(client) for service, client in clients.items()}
    identity = copy.deepcopy(identity)
    identity.update(UserId="synthetic-observer-id", ResponseMetadata={"HTTPStatusCode": 200, "RequestId": "synthetic-sts"})
    stubbers["sts"].add_response("get_caller_identity", identity, {})
    for receipt in receipts:
        operation = receipt["operation"]
        if operation == error_operation:
            stubbers["s3"].add_client_error(operation, service_error_code="AccessDenied",
                service_message="synthetic-private-error", http_status_code=403, expected_params=receipt["request"])
            break
        stubbers["s3"].add_response(operation, receipt["response"], receipt["request"])
    for stubber in stubbers.values():
        stubber.activate()
    session = Mock()
    session.client.side_effect = [clients["sts"], clients["s3"]]
    return session, stubbers, clients


def decrypt_records(root, binary, certificate, key):
    """Decrypt disposable test ciphertext directly into captured memory.

    Inputs:
        root: Synthetic capture directory containing CMS files.
        binary: Local OpenSSL 3 executable.
        certificate: Disposable public recipient certificate path.
        key: Disposable test-only private key path, never a real user key.
    Outputs:
        list: Parsed plaintext records in memory; no plaintext disk files or printed contents.
    """
    records = []
    for file in sorted(root.glob("record-*.cms")):
        raw = subprocess.run([binary, "cms", "-decrypt", "-binary", "-inform", "DER",
            "-in", str(file), "-recip", str(certificate), "-inkey", str(key)],
            check=True, capture_output=True, timeout=5).stdout
        records.append(json.loads(raw))
    return records


class SandboxCaptureTests(unittest.TestCase):
    """Validate encrypted success, early failure, consent-pin and wire-attempt boundaries."""

    def test_sdk_to_ciphertext_success_and_failure_boundaries(self):
        """Exercise complete capture and fail-closed identity, scope, provider and deadline paths.

        Inputs:
            self: Test instance with modeled SDK stubs and disposable synthetic recipient.
        Outputs:
            None; verifies ciphertext contents only in memory, exact calls and no later reads
            after failures. Does not access AWS, Keychain or real evidence.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, certificate, key, recipient = synthetic_recipient(root)
            for case in ("success", "identity", "tags", "provider", "deadline", "approval", "recipient"):
                with self.subTest(case=case):
                    identity, receipts = observation()
                    if case == "identity":
                        identity["Arn"] = "arn:aws:iam::653464153304:root"
                    if case == "tags":
                        receipts[1]["response"]["TagSet"] = []
                    session, stubbers, clients = stubbed_session(receipts, identity,
                        "get_bucket_tagging" if case == "provider" else None)
                    self.addCleanup(stubbers["sts"].deactivate)
                    self.addCleanup(stubbers["s3"].deactivate)
                    archive = EncryptedArchive(root / case, certificate, binary, timeout_seconds=5)
                    scope = capture_scope(capture_source_sha256(), "0" * 64 if case == "recipient" else recipient)
                    digest = "0" * 64 if case == "approval" else canonical_sha256(scope)
                    ticks = Mock(return_value=0)
                    if case == "deadline":
                        ticks.side_effect = [0, 0, 0, 121_000_000_000, 121_000_000_000, 121_000_000_000]
                    if case == "success":
                        result = capture_sandbox(session, archive, scope, digest, ticks)
                        self.assertTrue(result["complete"])
                        self.assertFalse(result["live_execution_allowed"])
                        for stubber in stubbers.values():
                            stubber.assert_no_pending_responses()
                        records = decrypt_records(archive.root, binary, certificate, key)
                        self.assertEqual(len(records), 15)
                        self.assertEqual(records[-2]["record"]["listings"]["list_object_versions"]["response"]["IsTruncated"], False)
                        self.assertEqual(records[-1]["kind"], "sandbox_capture_completion")
                        for call in session.client.call_args_list:
                            config = call.kwargs["config"]
                            self.assertEqual(config.retries["total_max_attempts"], 1)
                            self.assertTrue(config.ignore_configured_endpoint_urls)
                            self.assertTrue(call.kwargs["verify"])
                    else:
                        with self.assertRaises(ValueError) as failure:
                            capture_sandbox(session, archive, scope, digest, ticks)
                        self.assertNotIn("synthetic-private-error", str(failure.exception))
                        if case in ("approval", "recipient"):
                            session.client.assert_not_called()
                            self.assertEqual(archive.receipts, [])
                        else:
                            records = decrypt_records(archive.root, binary, certificate, key)
                            self.assertEqual(records[-1]["kind"], "sandbox_capture_failure")
                            self.assertFalse(any(record["kind"] == "sandbox_capture_completion" for record in records))
                            expected = {"identity": 1, "tags": 3, "provider": 2, "deadline": 1}[case]
                            self.assertEqual(sum(record["kind"] == "sandbox_observer_receipt" for record in records), expected)
                            if case == "provider":
                                self.assertEqual(records[-1]["response"]["Error"]["Code"], "AccessDenied")
                    self.assertFalse(any(file.suffix in (".json", ".txt") for file in archive.root.iterdir()))

    def test_wire_and_operation_guards_reject_widening(self):
        """Prevent extra wire attempts and reject mutations or object-body reads.

        Inputs:
            self: Test instance invoking the registered guard contract without a network.
        Outputs:
            None; asserts sends require an active unexpired one-attempt budget, and dispatch never
            invokes a client for operations outside the reviewed metadata/listing set.
        """
        clock = Mock(return_value=0)
        client = Mock()
        for operation in ("get_object", "put_bucket_versioning", "delete_object"):
            with self.assertRaises(ValueError):
                invoke_sandbox_read(client, operation, {})
        self.assertEqual(client.mock_calls, [])
        guard = SendBudget(100, clock)
        with self.assertRaises(ValueError):
            guard.before_send(None)
        guard.active = True
        guard.before_send(None)
        with self.assertRaises(ValueError):
            guard.before_send(None)
        guard.sent = 0
        clock.return_value = 100
        with self.assertRaises(ValueError):
            guard.before_send(None)
