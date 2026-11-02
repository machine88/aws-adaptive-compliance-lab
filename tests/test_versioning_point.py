"""SDK-stub/CMS checks for independent versioning point evidence and historical readback integrity."""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from functools import partial
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber

from research.archive_ingestion import read_archive_records
from research.aws_reader import EncryptedArchive
from research.catalog import canonical_sha256
from research.versioning_point import capture_versioning_point, versioning_point_scope, verify_versioning_point
from tests.crypto_fixtures import synthetic_recipient, synthetic_decrypt


class VersioningPointTests(unittest.TestCase):
    """Exercise exact owner/role reads and encrypted receipt reconstruction without live AWS."""

    @classmethod
    def setUpClass(cls):
        """Create disposable certificate material for real CMS evidence checks.

        Inputs:
            cls: Test class receiving temporary crypto fixture references.
        Outputs:
            None: Creates only synthetic local keys/certificate, no real recipient or profile.
        """
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))

    @classmethod
    def tearDownClass(cls):
        """Remove disposable crypto fixture storage.

        Inputs:
            cls: Test class owning its temporary synthetic recipient.
        Outputs:
            None: Removes no operational evidence or credentials.
        """
        cls.keys.cleanup()

    def fixture(self, status='Suspended', wrong_identity=False, stale=False, wall=None):
        """Construct exact dedicated-profile metadata, static synthetic clients and API stubs.

        Inputs:
            self: Test instance owning stub deactivation and temporary archive cleanup.
            status: Synthetic versioning status, with None representing missing required state.
            wrong_identity: Return an unrelated observer role and expect no S3 request.
            stale: Return a service Date outside the retained local request interval.
            wall: Optional synthetic aware service clock; None uses the fixed fixture date.
        Outputs:
            tuple: Session, archive, scope, clock and stubbers; no profile lookup or network occurs.
        """
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        archive = EncryptedArchive(Path(folder.name).resolve() / 'point', self.cert, self.binary, 5)
        scope = versioning_point_scope('a' * 32, 'trigger', self.pin, enable_capture=True)
        wall = wall or datetime(2026, 11, 2, tzinfo=timezone.utc)
        meta = {'HTTPStatusCode': 200, 'RequestId': 'synthetic-request',
                'HTTPHeaders': {'date': format_datetime(wall - timedelta(seconds=60 if stale else 0), usegmt=True)}}
        sdk = boto3.Session(aws_access_key_id='synthetic', aws_secret_access_key='synthetic', region_name='us-east-2')
        clients = {service: sdk.client(service, endpoint_url=f'https://{service}.us-east-2.amazonaws.com') for service in ('sts', 's3')}
        stubs = {service: Stubber(client) for service, client in clients.items()}
        role = 'other' if wrong_identity else 'dissertation-sandbox-observer'
        stubs['sts'].add_response('get_caller_identity', {'Account': '653464153304', 'UserId': 'synthetic-id',
            'Arn': f'arn:aws:sts::653464153304:assumed-role/{role}/dissertation-sandbox-observer', 'ResponseMetadata': meta}, {})
        if not wrong_identity and not stale:
            response = {'ResponseMetadata': meta}
            if status is not None:response['Status'] = status
            stubs['s3'].add_response('get_bucket_versioning', response,
                {'Bucket': 'dissertation-sandbox-653464153304-us-east-2-s3-01', 'ExpectedBucketOwner': '653464153304'})
        for stub in stubs.values():
            stub.activate()
            self.addCleanup(stub.deactivate)
        session = Mock()
        session._session.get_scoped_config.return_value = {'role_arn': 'arn:aws:iam::653464153304:role/dissertation-sandbox-observer',
            'source_profile': 'dissertation', 'role_session_name': 'dissertation-sandbox-observer', 'duration_seconds': '900', 'region': 'us-east-2'}
        session._session.full_config = {'profiles': {'dissertation': {'login_session': 'synthetic-only', 'region': 'us-east-2'}}}

        def client(service, **options):
            """Inspect fixed transport options and return only pre-stubbed clients.

            Inputs:
                service: Maintained literal sts or s3.
                options: Fixed region, HTTPS endpoint, TLS flags and SDK Config.
            Outputs:
                object: Synthetic SDK client; no credential lookup or actual network request.
            """
            self.assertEqual(options['endpoint_url'], f'https://{service}.us-east-2.amazonaws.com')
            self.assertTrue(options['use_ssl'] and options['verify'])
            self.assertEqual(options['config'].retries['total_max_attempts'], 1)
            return clients[service]

        session.client.side_effect = client
        return session, archive, scope, wall, stubs

    def capture(self, case):
        """Run one point against static synthetic clocks and stubbed SDK clients.

        Inputs:
            self: Test instance with no operational session state.
            case: Fixture tuple containing independent observer metadata and disposable archive.
        Outputs:
            dict: Point report and ciphertext fingerprint; never actual AWS evidence.
        """
        session, archive, scope, wall, _ = case
        return capture_versioning_point(session, archive, scope, canonical_sha256(scope),
                                        clock=lambda: wall.isoformat(), monotonic_ns=lambda: 0)

    def test_exact_read_and_cms_reconstruction_reject_tampering(self):
        """Verify independently pinned raw receipt readback and reject altered status/phase/chains.

        Inputs:
            self: Test instance using real disposable CMS and synthetic point evidence.
        Outputs:
            None: Assertions preserve observed-state meaning without interval/comparative claims.
        """
        root = Path(__file__).resolve().parents[1]
        inventory = json.loads((root / 'protocol/versioning-point-policy-provenance.json').read_text())
        self.assertEqual(inventory['source_sha256'], {'research/versioning_point.py': hashlib.sha256((root / 'research/versioning_point.py').read_bytes()).hexdigest()})
        self.assertRegex(inventory['analysis_canonical_sha256'], r'^[0-9a-f]{64}$')
        self.assertTrue(inventory['analysis_retained_privately'] and inventory['review_only'])
        self.assertNotIn('analysis', inventory)
        self.assertFalse(inventory['policy_attachment_approved'] or inventory['aws_applied'])
        case = self.fixture()
        report = self.capture(case)
        for stub in case[4].values():stub.assert_no_pending_responses()
        records, receipts = read_archive_records(case[1].root,
            partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key), self.pin,
            max_records=4, max_bytes=1048576)
        self.assertEqual(verify_versioning_point(case[2], canonical_sha256(case[2]), records, receipts,
                                              report['ciphertext_fingerprint']), report)
        self.assertEqual(report['observed_status'], 'Suspended')
        self.assertFalse(report['interval_state_verified'] or report['formal_trial_authorized'])
        changed = copy.deepcopy(records)
        changed[2]['response']['Status'] = 'Enabled'
        with self.assertRaises(ValueError):
            verify_versioning_point(case[2], canonical_sha256(case[2]), changed, receipts, report['ciphertext_fingerprint'])
        with self.assertRaises(ValueError):
            verify_versioning_point(case[2], canonical_sha256(case[2]), records, receipts, 'f' * 64)
        scope = dict(case[2], phase='pilot')
        with self.assertRaises(ValueError):
            verify_versioning_point(scope, canonical_sha256(scope), records, receipts, report['ciphertext_fingerprint'])

    def test_bad_identity_date_and_missing_state_fail_closed(self):
        """Reject unrelated/stale identity before S3 and missing versioning after attributed read.

        Inputs:
            self: Test instance iterating meaningful source/evidence failure variants.
        Outputs:
            None: Assertions prevent an unsupported status or stale receipt becoming a trigger.
        """
        for options in ({'wrong_identity': True}, {'stale': True}, {'status': None}):
            with self.subTest(options=options):
                case = self.fixture(**options)
                with self.assertRaisesRegex(ValueError, '^Versioning point capture failed; partial ciphertext retained$'):
                    self.capture(case)
                self.assertEqual(case[0].client.call_count, 2 if 'status' in options else 1)
                for stub in case[4].values():stub.assert_no_pending_responses()

    def test_disabled_or_widened_scope_stops_before_client_construction(self):
        """Keep default capture disabled and reject target/source tampering before AWS setup.

        Inputs:
            self: Test instance supplying only synthetic session metadata and archive.
        Outputs:
            None: Asserts no SDK client or archive record is created by rejected scopes.
        """
        case = self.fixture()
        for scope in (versioning_point_scope('a' * 32, 'trigger', self.pin),
                      dict(case[2], bucket='other-bucket'), dict(case[2], source_sha256='f' * 64)):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                capture_versioning_point(case[0], case[1], scope, canonical_sha256(scope))
        self.assertFalse(case[0].client.called)
        self.assertEqual(case[1].receipts, [])
