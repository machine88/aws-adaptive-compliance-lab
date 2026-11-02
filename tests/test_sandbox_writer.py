"""Offline writer transport tests with real disposable CMS and SDK stubs, never live credentials."""
import copy
from functools import partial
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
from botocore.stub import Stubber

from research.archive_ingestion import read_archive_records
from research.aws_reader import EncryptedArchive
from research.catalog import canonical_sha256
from research.recovery_intent import build_recovery_intent
from research.sandbox_emptiness import ACCOUNT, BUCKET, REGION
from research.sandbox_writer import BoundedVersioningWriter, PROFILE, ROLE, writer_scope
from tests.crypto_fixtures import synthetic_recipient, synthetic_decrypt
from tests.test_sandbox_emptiness import fixture as listing_fixture
from tests.test_sandbox_readiness import fixture as metadata_fixture


class SandboxWriterTests(unittest.TestCase):
    """Enforce fixed scope, independent role identity, durable pending requests and finite attempts."""

    @classmethod
    def setUpClass(cls):
        """Create one disposable recipient for actual CMS transport-evidence roundtrips.

        Inputs:
            cls: Test class receiving temporary synthetic certificate/private-key paths.
        Outputs:
            None: Creates no real recipient, Keychain item, profile or cloud resource.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))

    @classmethod
    def tearDownClass(cls):
        """Delete disposable class crypto fixtures only.

        Inputs:
            cls: Test class owning its temporary synthetic recipient directory.
        Outputs:
            None: Removes temporary test files, never operational evidence.
        """
        cls.keys.cleanup()

    def fixture(self, statuses=(), wrong_identity=False, wrong_profile=False, mode="change_and_restore"):
        """Build exact SDK stub expectations with a fake profile and disposable encrypted archive.

        Inputs:
            self: Test instance registering temporary cleanup and stub deactivation.
            statuses: Ordered fake PutBucketVersioning responses; ERROR yields a ClientError.
            wrong_identity: Return an unrelated role in the synthetic STS response.
            wrong_profile: Add an unapproved credential_process key without executing it.
            mode: Explicit bounded writer mode, including recovery_only for dedicated tests.
        Outputs:
            tuple: Scope, intent, archive, factory, session, clients, stubbers and fake clock.
                Synthetic SDK credentials are provided directly so no real lookup/network occurs.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        archive = EncryptedArchive(Path(temporary.name).resolve() / "journal", self.cert, self.binary, 5)
        intent = build_recovery_intent("a" * 32, metadata_fixture(), listing_fixture(), "b" * 64, "c" * 64, self.pin)
        scope = writer_scope("a" * 32, self.pin, canonical_sha256(intent), "b" * 64, "c" * 64,
                             enable_writes=True, mode=mode)
        session = boto3.Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name=REGION)
        config = Config(retries={"total_max_attempts": 1, "mode": "standard"}, connect_timeout=3, read_timeout=10)
        clients = {name: session.client(name, region_name=REGION, endpoint_url=f"https://{name}.{REGION}.amazonaws.com", config=config)
                   for name in ("sts", "s3")}
        stubbers = {name: Stubber(client) for name, client in clients.items()}
        identity = {"Account": ACCOUNT, "UserId": "synthetic-role-id:session",
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{'unrelated' if wrong_identity else ROLE}/{ROLE}",
            "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "synthetic-identity"}}
        stubbers["sts"].add_response("get_caller_identity", identity, {})
        for status in statuses:
            expected_status = "Suspended" if status == "ERROR" else status
            params = {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT, "VersioningConfiguration": {"Status": expected_status}}
            if status == "ERROR":
                stubbers["s3"].add_client_error("put_bucket_versioning", service_error_code="AccessDenied",
                    service_message="synthetic-private-provider-error", http_status_code=403, expected_params=params)
            else:
                stubbers["s3"].add_response("put_bucket_versioning",
                    {"ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "synthetic-write"}}, params)
        for stubber in stubbers.values():
            stubber.activate()
            self.addCleanup(stubber.deactivate)
        # Keep real pre-stubbed clients, but use a separate explicit profile/session test double.
        session = Mock()
        profile = {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE}", "source_profile": "dissertation",
                   "role_session_name": ROLE, "duration_seconds": "3600", "region": REGION}
        if wrong_profile:
            profile["credential_process"] = "never-executed"
        session._session.get_scoped_config = Mock(return_value=profile)
        session._session.full_config = {"profiles": {"dissertation": {"login_session": "synthetic-only", "region": REGION}}}

        def client(service, **options):
            """Inspect real transport constructor options but return pre-stubbed local SDK clients.

            Inputs:
                service: Maintained sts or s3 service name.
                options: Explicit region, TLS endpoint and Config selected by the writer.
            Outputs:
                object: SDK client with activated Stubber; no network or credential resolution.
            """
            self.assertEqual(options["endpoint_url"], f"https://{service}.{REGION}.amazonaws.com")
            self.assertTrue(options["verify"] and options["use_ssl"])
            self.assertEqual(options["region_name"], REGION)
            self.assertEqual(options["config"].retries["total_max_attempts"], 1)
            self.assertEqual(options["config"].proxies, {})
            self.assertTrue(options["config"].ignore_configured_endpoint_urls)
            return clients[service]

        session.client = Mock(side_effect=client)
        factory = Mock(return_value=session)
        return scope, intent, archive, factory, session, clients, stubbers, {"ns": 100}

    def writer(self, case):
        """Construct the maintained writer through an explicit offline-test session factory.

        Inputs:
            self: Test instance registering socket/handler cleanup for successful writers.
            case: Tuple returned by the independent SDK fixture builder.
        Outputs:
            object: Real writer using disposable encrypted retention and stubbed SDK responses.
        """
        scope, intent, archive, factory, session, clients, stubbers, clock = case
        writer = BoundedVersioningWriter(scope, canonical_sha256(scope), intent, archive, factory,
                                        monotonic_ns=lambda: clock["ns"])
        self.addCleanup(writer.close)
        return writer

    def test_default_scope_and_changed_bindings_stop_before_session_creation(self):
        """Reject disabled/default, changed targets, intent and independent hashes before credentials.

        Inputs:
            self: Test instance varying only synthetic current scopes and intent copies.
        Outputs:
            None: Asserts no session/client request or encrypted output record on rejected admission.
        """
        case = self.fixture()
        scope, intent, archive, factory, session, clients, stubbers, clock = case
        for field, value in (("enable_writes", False), ("bucket", "unrelated"), ("region", "us-west-2"),
                             ("source_sha256", "0" * 64), ("max_suspensions", 2)):
            changed = copy.deepcopy(scope)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                BoundedVersioningWriter(changed, canonical_sha256(changed), intent, archive, factory)
        default = writer_scope(scope["run_id"], self.pin, scope["intent_sha256"], "b" * 64, "c" * 64)
        self.assertFalse(default["enable_writes"])
        with self.assertRaises(ValueError):
            BoundedVersioningWriter(scope, "0" * 64, intent, archive, factory)
        changed_intent = copy.deepcopy(intent)
        changed_intent["requests"]["proposed_mutation"]["params"]["Bucket"] = "unrelated"
        with self.assertRaises(ValueError):
            BoundedVersioningWriter(scope, canonical_sha256(scope), changed_intent, archive, factory)
        factory.assert_not_called()
        self.assertEqual(archive.receipts, [])

    def test_fixed_requests_encrypted_roundtrip_and_finite_restore_calls(self):
        """Retain exact requests privately and consume one suspension/three recovery attempts only.

        Inputs:
            self: Test instance using actual disposable CMS and exact SDK stub parameters.
        Outputs:
            None: Asserts ordered encrypted evidence, no MFA/object API, role/config checks and closed gates.
        """
        case = self.fixture(("Suspended", "Enabled", "Enabled", "Enabled"))
        scope, intent, archive, factory, session, clients, stubbers, clock = case
        writer = self.writer(case)
        factory.assert_called_once_with(profile_name=PROFILE, region_name=REGION)
        with self.assertRaises(ValueError):
            writer.restore_enabled()
        intent["requests"]["proposed_mutation"]["params"]["Bucket"] = "changed-original-input"
        response = writer.suspend_once()
        self.assertEqual(response["status"], "write_response_only")
        with self.assertRaises(ValueError):
            writer.suspend_once()
        for _ in range(3):
            writer.restore_enabled()
        with self.assertRaises(ValueError):
            writer.restore_enabled()
        decrypt = partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key)
        records, receipts = read_archive_records(archive.root, decrypt, self.pin, max_records=20, max_bytes=1048576)
        pending = [record for record in records if record["kind"] == "versioning_pending"]
        self.assertEqual([record["request"]["params"]["VersioningConfiguration"]["Status"] for record in pending],
                         ["Suspended", "Enabled", "Enabled", "Enabled"])
        self.assertEqual(len(records), 10)
        self.assertTrue(writer.summary()["identity_verified"] and writer.summary()["journal_complete"])
        self.assertFalse(writer.summary()["credential_coverage_verified"] or writer.summary()["restoration_verified"])
        for stubber in stubbers.values():
            stubber.assert_no_pending_responses()
        writer.close()
        with self.assertRaises(ValueError):
            writer.restore_enabled()

    def test_wrong_identity_or_profile_never_constructs_s3_client(self):
        """Retain safe failure evidence and reject wrong role or credential providers before S3 setup.

        Inputs:
            self: Test instance with one synthetic wrong-role or unapproved-profile case.
        Outputs:
            None: Asserts no S3 client construction/write and no raw errors exposed.
        """
        for identity, profile in ((True, False), (False, True)):
            case = self.fixture(wrong_identity=identity, wrong_profile=profile)
            with self.subTest(wrong_identity=identity), self.assertRaises(ValueError) as raised:
                self.writer(case)
            session = case[4]
            self.assertNotIn("unrelated", str(raised.exception))
            self.assertNotIn("s3", [call.args[0] for call in session.client.call_args_list])

    def test_ambiguous_write_and_postchange_retention_failure_preserve_recovery(self):
        """Consume ambiguous attempts once and allow bounded recovery despite missing journal acknowledgments.

        Inputs:
            self: Test instance using synthetic AccessDenied and ciphertext-retention failures.
        Outputs:
            None: Asserts no suspension retry, private provider errors and three-attempt recovery bound.
        """
        for outage in (False, True):
            case = self.fixture(("Suspended" if outage else "ERROR", "Enabled", "Enabled", "Enabled"))
            writer = self.writer(case)
            archive = case[2]
            if outage:
                original = archive.write

                def write(record):
                    """Keep the mandatory pending-change receipt then fail all later storage operations.

                    Inputs:
                        record: Private synthetic transport event destined for real disposable CMS.
                    Outputs:
                        dict: Initial real receipts only; later writes raise a synthetic storage failure.
                    """
                    if len(archive.receipts) >= 3:
                        raise OSError("synthetic-private-provider-error")
                    return original(record)
                archive.write = write
            with self.assertRaises(ValueError) as raised:
                writer.suspend_once()
            self.assertNotIn("synthetic-private-provider-error", str(raised.exception))
            with self.assertRaises(ValueError):
                writer.suspend_once()
            for _ in range(3):
                if outage:
                    with self.assertRaises(ValueError):
                        writer.restore_enabled()
                else:
                    writer.restore_enabled()
            self.assertEqual(writer.summary()["suspensions"], 1)
            self.assertEqual(writer.summary()["restorations"], 3)
            self.assertEqual(writer.summary()["journal_complete"], not outage)
            with self.assertRaises(ValueError):
                writer.restore_enabled()
            for stubber in case[6].values():
                stubber.assert_no_pending_responses()
            if not outage:
                decrypt = partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key)
                records, _ = read_archive_records(archive.root, decrypt, self.pin, max_records=25, max_bytes=1048576)
                error = next(record for record in records if record["kind"] == "versioning_attempt_uncertain")
                self.assertEqual(error["provider_response"]["Error"]["Message"], "synthetic-private-provider-error")

    def test_recovery_only_deadline_thread_and_wire_guards(self):
        """Block fresh suspension in recovery mode, late/wrong-thread calls and duplicate wire sends.

        Inputs:
            self: Test instance with fake monotonic time and real SDK event emitters; no HTTP sends.
        Outputs:
            None: Asserts deadlines/affinity/SendBudget operate before any extra stubbed S3 request.
        """
        recovery = self.fixture(("Enabled",), mode="recovery_only")
        writer = self.writer(recovery)
        with self.assertRaises(ValueError):
            writer.suspend_once()
        writer.restore_enabled()
        recovery[6]["s3"].assert_no_pending_responses()
        case = self.fixture()
        writer = self.writer(case)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaises(ValueError):
                pool.submit(writer.suspend_once).result()
        self.assertEqual(writer.summary()["suspensions"], 0)
        s3, guard = writer._s3, writer._guard
        with self.assertRaises(ValueError):
            s3.meta.events.emit("before-send.s3.PutBucketVersioning", request=object())
        guard.active, guard.sent = True, 0
        s3.meta.events.emit("before-send.s3.PutBucketVersioning", request=object())
        with self.assertRaises(ValueError):
            s3.meta.events.emit("before-send.s3.PutBucketVersioning", request=object())
        guard.active = False
        case[7]["ns"] += 2400_000_000_000
        with self.assertRaises(ValueError):
            writer.suspend_once()
        self.assertEqual(writer.summary()["suspensions"], 0)

        late = self.fixture()
        writer = self.writer(late)
        dispatch = Mock()
        writer._s3.put_bucket_versioning = dispatch
        original = late[2].write

        def delayed_pending(record):
            """Advance the fake clock during mandatory pending retention to exhaust wire admission.

            Inputs:
                record: Disposable private transport record passed to the real test archive.
            Outputs:
                dict: Real encrypted receipt; only fake time advances, never host time or AWS state.
            """
            if record["kind"] == "versioning_pending":
                late[7]["ns"] += 2400_000_000_000
            return original(record)

        late[2].write = delayed_pending
        with self.assertRaises(ValueError):
            writer.suspend_once()
        dispatch.assert_not_called()
