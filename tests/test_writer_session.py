"""SDK-stub and disposable-CMS tests for exact temporary-session/expiration evidence binding."""
import json
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber

from research.archive_ingestion import read_archive_records
from research.aws_reader import EncryptedArchive
from research.catalog import canonical_sha256
from research.writer_session import BoundWriterSession, ROLE, ROLE_ARN, SOURCE_ARN, TARGET_ARN, writer_session_scope
from tests.crypto_fixtures import synthetic_recipient, synthetic_decrypt


class WriterSessionTests(unittest.TestCase):
    """Use synthetic credentials/responses only; no real profile, Keychain or network access."""

    @classmethod
    def setUpClass(cls):
        """Create disposable encryption material for actual retained-metadata roundtrips.

        Inputs:
            cls: Test class owning temporary synthetic certificate/private-key paths.
        Outputs:
            None: Creates only disposable local crypto material.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))

    @classmethod
    def tearDownClass(cls):
        """Remove only disposable test keys.

        Inputs:
            cls: Test class owning temporary crypto fixture directory.
        Outputs:
            None: Removes no operational evidence or real credential files.
        """
        cls.keys.cleanup()

    def fixture(self, wrong_source=False, wrong_role=False, wrong_bound=False, short=False, bad_date=False, denied=False):
        """Prepare exact SDK request expectations and a same-session static client factory.

        Inputs:
            self: Test instance owning cleanup and assertions.
            wrong_source: Supply an unrelated source IAM user.
            wrong_role: Supply an unrelated returned assumed-role ARN.
            wrong_bound: Supply an unrelated identity for the session created from returned credentials.
            short: Return insufficient actual expiration despite a requested one-hour session.
            bad_date: Return a service Date far from the local receipt clock.
            denied: Simulate a private provider failure containing a sentinel that must not escape.
        Outputs:
            tuple: Enabled scope, archive, factory, mutable fake clock, stubbers and factory call list.
                All clients use synthetic static credentials; no live provider lookup occurs.
        """
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        archive = EncryptedArchive(Path(folder.name).resolve() / 'archive', self.cert, self.binary, 5)
        scope = writer_session_scope('a' * 32, self.pin, enable_session=True)
        clock = {'ns': 5_000_000_000, 'wall': datetime(2026, 11, 2, tzinfo=timezone.utc)}
        credentials = {'AccessKeyId': 'ASIA' + 'A' * 16, 'SecretAccessKey': 'synthetic-secret-sentinel',
                       'SessionToken': 'synthetic-token-sentinel',
                       'Expiration': clock['wall'] + timedelta(seconds=2400 if short else 3600)}
        identity_id = 'synthetic-role-id:' + ROLE
        source_sdk = boto3.Session(aws_access_key_id='synthetic', aws_secret_access_key='synthetic', region_name='us-east-2')
        source_client = source_sdk.client('sts', endpoint_url='https://sts.us-east-2.amazonaws.com')
        bound_sdk = boto3.Session(aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'],
                                 aws_session_token=credentials['SessionToken'], region_name='us-east-2')
        bound_client = bound_sdk.client('sts', endpoint_url='https://sts.us-east-2.amazonaws.com')
        source_stub, bound_stub = Stubber(source_client), Stubber(bound_client)
        metadata = {'HTTPStatusCode': 200, 'RequestId': 'synthetic-request',
                    'HTTPHeaders': {'date': format_datetime(clock['wall'] + timedelta(seconds=20 if bad_date else 0), usegmt=True)}}
        source_stub.add_response('get_caller_identity', {'Account': '653464153304', 'Arn': SOURCE_ARN + ('-other' if wrong_source else ''),
                                                       'UserId': 'synthetic-source', 'ResponseMetadata': metadata}, {})
        if not wrong_source:
            params = {'RoleArn': TARGET_ARN, 'RoleSessionName': ROLE, 'DurationSeconds': 3600}
            if denied:
                source_stub.add_client_error('assume_role', service_error_code='AccessDenied', service_message='synthetic-private-error-sentinel', expected_params=params)
            else:
                source_stub.add_response('assume_role', {'Credentials': credentials,
                    'AssumedRoleUser': {'Arn': ROLE_ARN + ('-other' if wrong_role else ''), 'AssumedRoleId': identity_id},
                    'ResponseMetadata': metadata}, params)
        if not any((wrong_source, wrong_role, short, bad_date, denied)):
            bound_stub.add_response('get_caller_identity', {'Account': '653464153304', 'Arn': ROLE_ARN,
                'UserId': identity_id + ('-other' if wrong_bound else ''), 'ResponseMetadata': metadata}, {})
        for stub in (source_stub, bound_stub):
            stub.activate()
            self.addCleanup(stub.deactivate)
        # The constructor sees profile metadata for the source only; returned credentials are explicit.
        source = Mock()
        source._session.get_scoped_config.return_value = {'login_session': 'synthetic-only', 'region': 'us-east-2'}
        source.client.return_value = source_client
        bound_sdk.client = Mock(return_value=bound_client)
        calls = []

        def factory(**options):
            """Assert exact returned credentials select the only allowed bound SDK session.

            Inputs:
                options: SDK constructor arguments selected by the maintained broker.
            Outputs:
                object: Synthetic source or bound session; never looks up real credentials.
            """
            calls.append(set(options))
            if 'profile_name' in options:
                self.assertEqual(options, {'profile_name': 'dissertation', 'region_name': 'us-east-2'})
                return source
            self.assertEqual(options, {'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'], 'aws_session_token': credentials['SessionToken'],
                'region_name': 'us-east-2'})
            return bound_sdk

        return scope, archive, factory, clock, (source_stub, bound_stub), calls

    def open(self, fixture):
        """Connect an explicitly synthetic fixture to the broker without network access.

        Inputs:
            self: Test instance; no external session state.
            fixture: Tuple created by fixture(), containing clocks and stub-only session constructor.
        Outputs:
            BoundWriterSession: Initialized test broker with no live writer admission.
        """
        scope, archive, factory, clock, _, _ = fixture
        return BoundWriterSession(scope, canonical_sha256(scope), archive, factory,
                                  clock=lambda: clock['wall'].isoformat(), monotonic_ns=lambda: clock['ns'])

    def test_disabled_changed_or_unretained_scope_never_resolves_credentials(self):
        """Stop disabled/tampered scopes and initial retention failure before SDK construction.

        Inputs:
            self: Test instance with disposable archive and factory invocation list.
        Outputs:
            None: Assertions verify no source identity or role assumption occurs.
        """
        f = self.fixture()
        for scope in (dict(f[0], enable_session=False), dict(f[0], duration_seconds=7200), dict(f[0], region='us-west-2')):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                BoundWriterSession(scope, canonical_sha256(scope), f[1], f[2])
        self.assertEqual(f[5], [])
        logger = logging.getLogger('botocore.endpoint')
        previous_level = logger.level
        try:
            logger.setLevel(logging.DEBUG)
            with self.assertRaisesRegex(ValueError, 'SDK debug logging must remain disabled'):
                self.open(f)
        finally:
            logger.setLevel(previous_level)
        self.assertEqual(f[5], [])
        f[1].write = Mock(side_effect=OSError('synthetic-retention-failure'))
        with self.assertRaisesRegex(ValueError, '^Writer session setup failed; no live admission$'):
            self.open(f)
        self.assertEqual(f[5], [])

    def test_bound_identity_expiration_and_nonsecret_cms_roundtrip(self):
        """Bind exact SDK credentials/identity and encrypt only allowlisted nonsecret session metadata.

        Inputs:
            self: Test instance with disposable CMS keys and fixed fake same-domain clocks.
        Outputs:
            None: Assertions verify exact API calls, metadata privacy and unchanged live gates.
        """
        root = Path(__file__).resolve().parents[1]
        inventory = json.loads((root / 'protocol/writer-session-policy-inventory.json').read_text())
        self.assertEqual(inventory['source_sha256'], {'research/writer_session.py': hashlib.sha256((root / 'research/writer_session.py').read_bytes()).hexdigest()})
        self.assertEqual(canonical_sha256(inventory['analysis']), inventory['analysis_canonical_sha256'])
        self.assertTrue(inventory['review_inventory_only'])
        self.assertFalse(inventory['policy_attachment_approved'] or inventory['aws_applied'])
        f = self.fixture()
        broker = self.open(f)
        self.addCleanup(broker.close)
        options = broker._session.client.call_args.kwargs
        self.assertEqual(options['endpoint_url'], 'https://sts.us-east-2.amazonaws.com')
        self.assertEqual(options['region_name'], 'us-east-2')
        self.assertTrue(options['verify'] and options['use_ssl'])
        self.assertEqual(options['config'].retries['total_max_attempts'], 1)
        for stub in f[4]:stub.assert_no_pending_responses()
        self.assertEqual(len(f[5]), 2)
        assessment = broker.assess_budget()
        self.assertTrue(assessment['declared_budget_sufficient'])
        self.assertFalse(assessment['credential_coverage_verified'] or assessment['live_execution_allowed'])
        records, receipts = read_archive_records(f[1].root,
            lambda data: synthetic_decrypt(data, self.binary, self.cert, self.key), self.pin, max_records=4, max_bytes=1048576)
        encoded = json.dumps(records)
        for value in ('synthetic-secret-sentinel', 'synthetic-token-sentinel', 'ASIA' + 'A' * 16, 'Credentials', 'SecretAccessKey'):
            self.assertNotIn(value, encoded)
        self.assertEqual(len(records), 4)
        with self.assertRaises(ValueError):broker.client('iam')
        # Returning a client never grants permission to widen operations or bypass the writer.
        f[3]['ns'] += 1_000_000_000
        f[3]['wall'] += timedelta(seconds=1)
        self.assertTrue(broker.assess_budget()['declared_budget_sufficient'])
        broker.close()
        with self.assertRaises(ValueError):broker.client('sts')

    def test_identity_provider_and_short_expiration_fail_closed(self):
        """Reject source/role/session mismatches, service clock skew and insufficient returned lifetime.

        Inputs:
            self: Test instance with isolated synthetic response variants.
        Outputs:
            None: Assertions verify no session handoff or raw provider error escape.
        """
        for option in ('wrong_source', 'wrong_role', 'wrong_bound', 'short', 'bad_date', 'denied'):
            f = self.fixture(**{option: True})
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, '^Writer session setup failed; no live admission$'):
                self.open(f)
            self.assertLessEqual(len(f[5]), 2 if option == 'wrong_bound' else 1)

    def test_time_expiry_and_setup_retention_delays_prevent_handoff(self):
        """Reject clock drift, lifetime exhaustion and slow durable scope retention before dispatch.

        Inputs:
            self: Test instance with explicitly advanced synthetic wall/monotonic clocks.
        Outputs:
            None: Assertions verify conservative wire expiry and zero refresh/retry/session reset.
        """
        f = self.fixture()
        broker = self.open(f)
        self.addCleanup(broker.close)
        with ThreadPoolExecutor(max_workers=1) as worker:
            with self.assertRaises(ValueError):worker.submit(broker.assess_budget).result()
        f[3]['ns'] += 2_000_000_000
        with self.assertRaises(ValueError):broker.assess_budget()
        with self.assertRaises(ValueError):broker._before_send(None)
        f[3]['wall'] += timedelta(seconds=2)
        f[3]['ns'] += 3593_000_000_000
        f[3]['wall'] += timedelta(seconds=3593)
        with self.assertRaises(ValueError):broker._before_send(None)
        with self.assertRaises(ValueError):broker.assess_budget()
        late = self.fixture()
        retain = late[1].write

        def delayed(record):
            """Advance setup clocks during mandatory scope retention without real sleeping.

            Inputs:
                record: Maintained nonsecret metadata frame to encrypt with disposable recipient.
            Outputs:
                dict: Real CMS receipt after fake setup deadline has expired.
            """
            receipt = retain(record)
            late[3]['ns'] += 120_000_000_000
            late[3]['wall'] += timedelta(seconds=120)
            return receipt

        late[1].write = delayed
        with self.assertRaises(ValueError):self.open(late)
        self.assertEqual(len(late[5]), 0)
