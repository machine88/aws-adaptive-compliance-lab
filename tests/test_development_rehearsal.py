"""Full development-case offline composition with SDK stubs, disposable CMS and no real Keychain."""
from datetime import datetime, timedelta, timezone
import contextlib
import io
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import boto3
from botocore.stub import Stubber

from research.catalog import canonical_sha256
from research.development_case import run_development_actions
from research.development_rehearsal import build_rehearsal_scope, run_rehearsal_operator, run_rehearsal_worker
from research.sandbox_capture import capture_sandbox
from research.sandbox_operator import build_sandbox_scope
from research.sandbox_readiness import BUCKET
from research.writer_session import BoundWriterSession, ROLE_ARN, ROLE
from research.versioning_point import capture_versioning_point
from scripts.sandbox_capture_worker import run_worker
from scripts.run_development_case import main as case_main
from tests.crypto_fixtures import synthetic_recipient
from tests import test_preparation_operator as prep_tests
from tests.test_sandbox_capture import stubbed_session
from tests.test_sandbox_observer import observation
from tests.test_sandbox_operator import configure_profile
from tests import test_writer_session as broker_tests
from tests import test_versioning_point as point_tests


class DevelopmentRehearsalTests(unittest.TestCase):
    """Exercise the composed runtime and preserve exact approval, recovery and evidence boundaries."""

    @classmethod
    def setUpClass(cls):
        """Create one disposable recipient used by all actual encryption in this class.

        Inputs:
            cls: Test class owning synthetic certificate and temporary key references.
        Outputs:
            None: Creates no real recipient, credential, Keychain item or AWS resource.
        """
        import tempfile
        cls.keys = tempfile.TemporaryDirectory()
        cls.binary, cls.cert, cls.key, cls.pin = synthetic_recipient(Path(cls.keys.name))
        cls.binary = str(Path(cls.binary).resolve())

    @classmethod
    def tearDownClass(cls):
        """Remove only disposable class crypto fixtures.

        Inputs:
            cls: Test class owning synthetic fixture storage.
        Outputs:
            None: No operational evidence or real key is touched.
        """
        cls.keys.cleanup()

    def case(self, enabled=True):
        """Reuse the maintained private preparation fixture and compose a separate post/case scope.

        Inputs:
            self: Test instance owning private temporary paths and synthetic helper metadata.
            enabled: Explicit case enable boolean; tests can exercise the safe default.
        Outputs:
            dict: Current source-bound test case declaration with disjoint unused outputs.
        """
        prep_tests.PreparationOperatorTests.setUp(self)
        post = build_sandbox_scope(self.scope['observer']['certificate'], self.base / 'post', self.binary, 'a' * 32)
        return build_rehearsal_scope(self.scope, post, self.base / 'case', enabled)

    def test_disabled_changed_and_consumed_scope_never_launches_worker(self):
        """Reject unapproved execution, widened protocol and changed code bindings before reservation.

        Inputs:
            self: Test instance with real local scope validation and synthetic private bindings.
        Outputs:
            None: Asserts zero process/cloud/Keychain launches and no case output on rejection.
        """
        scope = self.case()
        for selected in (False, True):
            declaration = dict(scope, enable_experiment=selected)
            path = self.base / ('case-' + str(selected) + '.json')
            path.write_text(json.dumps(declaration))
            path.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()), patch('research.development_rehearsal.bounded_worker') as worker:
                self.assertEqual(case_main(['--scope', str(path), '--scope-sha256', canonical_sha256(declaration)]), 0)
                worker.assert_not_called()
        for changed in (dict(scope, enable_experiment=False), dict(scope, horizon_seconds=1),
                        dict(scope, max_service_calls=999), dict(scope, source_sha256='f' * 64)):
            with self.subTest(changed=changed), patch('research.development_rehearsal.bounded_worker') as worker:
                with self.assertRaises(ValueError):run_rehearsal_operator(changed, canonical_sha256(changed))
                worker.assert_not_called()
                self.assertFalse((self.base / 'case').exists())

    def test_full_composition_and_stale_admission_preserve_actual_outcome(self):
        """Exercise complete state cycle, full post-state and closure; reject stale pre-change evidence.

        Inputs:
            self: Test instance using SDK stubs, disposable CMS and accelerated same-domain clocks.
        Outputs:
            None: Verifies a positive engineering case and a retained negative case without actual
                AWS, real waiting, Keychain use, formal-trial promotion or automatic lock release.
        """
        real_mono = time.monotonic_ns
        for stale in (False, True):
            with self.subTest(stale=stale):
                scope = self.case()
                offset, stubs = {'ns': 0}, []

                def mono():
                    """Keep real monotonic progression plus explicitly simulated observation time.

                    Inputs:
                        No arguments; reads the original clock and test-only offset.
                    Outputs:
                        int: Same-domain synthetic nanoseconds, no blocking or AWS access.
                    """
                    return real_mono() + offset['ns']

                def wall():
                    """Advance wall time consistently with the synthetic observation offset.

                    Inputs:
                        No arguments; reads actual UTC plus test-only elapsed offset.
                    Outputs:
                        str: Aware UTC receipt timestamp for synthetic producer envelopes.
                    """
                    return (datetime.now(timezone.utc) + timedelta(microseconds=offset['ns'] // 1000)).isoformat().replace('+00:00', 'Z')

                def sleep(seconds):
                    """Simulate the fixed thirty-minute horizon without real waiting.

                    Inputs:
                        seconds: Positive bounded wait requested by the maintained action loop.
                    Outputs:
                        None: Advances only the shared synthetic offset.
                    """
                    offset['ns'] += int(seconds * 1_000_000_000)

                role_case = broker_tests.WriterSessionTests.fixture(self, wall=datetime.now(timezone.utc))
                role_session, role_sts = role_case[6]
                role_case[4][1].add_response('get_caller_identity', {'Account': '653464153304', 'Arn': ROLE_ARN,
                    'UserId': 'synthetic-role-id:' + ROLE,
                    'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': 'writer-identity'}}, {})
                s3 = boto3.Session.client(role_session, 's3', region_name='us-east-2', endpoint_url='https://s3.us-east-2.amazonaws.com')
                writes = Stubber(s3)
                for status in ([] if stale else ['Suspended', 'Enabled']):
                    writes.add_response('put_bucket_versioning',
                        {'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': 'synthetic-versioning'}},
                        {'Bucket': BUCKET, 'ExpectedBucketOwner': '653464153304', 'VersioningConfiguration': {'Status': status}})
                writes.activate()
                self.addCleanup(writes.deactivate)

                def role_client(service, **options):
                    """Return only real stubbed clients belonging to the same explicit role session.

                    Inputs:
                        service: Fixed sts or s3 name selected by the maintained broker.
                        options: Fixed HTTPS/TLS/Config options already verified in focused tests.
                    Outputs:
                        object: Real SDK stub client; no network or profile lookup.
                    """
                    return role_sts if service == 'sts' else s3

                role_session.client.side_effect = role_client

                def broker(declaration, pin, archive, **options):
                    """Use the actual broker with synthetic source/role SDK responses.

                    Inputs:
                        declaration: Reviewed broker sub-scope from the composed case.
                        pin: Independent sub-scope fingerprint.
                        archive: Real disposable encrypted session archive reserved by the runtime.
                        options: Shared wall and monotonic clocks supplied by the runtime.
                    Outputs:
                        BoundWriterSession: Actual broker with no real credential lookup or AWS call.
                    """
                    return BoundWriterSession(declaration, pin, archive, session_factory=role_case[2], **options)

                def point(session, archive, declaration, pin, **options):
                    """Exercise real independent point capture with fresh synthetic role/API responses.

                    Inputs:
                        session: Unused observer sentinel; no real profile was opened.
                        archive: Real disposable point archive from the maintained runtime.
                        declaration: Fixed slot/run/source scope for this point.
                        pin: Independent point fingerprint.
                        options: Shared wall and monotonic clocks supplied by the runtime.
                    Outputs:
                        dict: Actual point producer result, later decrypted/verified by the runtime.
                    """
                    status = 'Enabled' if declaration['point'] == 'admission' or declaration['point'].startswith('restoration-') else 'Suspended'
                    fixture = point_tests.VersioningPointTests.fixture(self, status=status, wall=datetime.fromisoformat(wall()))
                    stubs.extend(fixture[4].values())
                    report = capture_versioning_point(fixture[0], archive, declaration, pin, **options)
                    if stale and declaration['point'] == 'admission':offset['ns'] += 61_000_000_000
                    return report

                def capture(session, archive, declaration, pin, **options):
                    """Keep full pre/post captures in the same synthetic receipt clock domain.

                    Inputs:
                        session: Actual SDK-stubbed full observer session.
                        archive: Real disposable CMS capture archive.
                        declaration: Fixed complete metadata/listing capture scope.
                        pin: Independent capture fingerprint.
                        options: Maintained enclosing operator binding.
                    Outputs:
                        dict: Real encrypted full capture result; no live AWS requests.
                    """
                    return capture_sandbox(session, archive, declaration, pin, clock=wall, monotonic_ns=mono, **options)

                def capture_worker(command, descriptor, timeout_seconds, **options):
                    """Replace only nested process launch with the real full observer SDK/CMS worker.

                    Inputs:
                        command: Maintained child argv, not executed by this offline test.
                        descriptor: Current full observer declaration and fingerprint.
                        timeout_seconds: Fixed nested capture timeout.
                        options: Must retain outer experiment process-group ownership.
                    Outputs:
                        str: Success after actual full capture using synthetic SDK responses.
                    """
                    self.assertEqual(timeout_seconds, 150)
                    self.assertEqual(options, {'inherit_supervisor_group': True})
                    identity, receipts = observation()
                    session, responses, _ = stubbed_session(receipts, identity)
                    configure_profile(session)
                    stubs.extend(responses.values())
                    for response in responses.values():self.addCleanup(response.deactivate)
                    with patch('scripts.sandbox_capture_worker.capture_sandbox', side_effect=capture):
                        run_worker(descriptor['scope'], descriptor['approved_scope_sha256'], Mock(return_value=session))
                    return 'success'

                def actions(run_id, writer, observe, guard, retain):
                    """Use the actual action/recovery loop with accelerated coherent clocks only.

                    Inputs:
                        run_id: Reviewed development run identifier.
                        writer: Actual fixed-target writer using SDK stubs and the actual broker.
                        observe: Actual runtime point capture/readback adapter.
                        guard: Actual original-lock/fresh-evidence admission check.
                        retain: Actual encrypted action-journal callback.
                    Outputs:
                        dict: Actual development result from synthetic AWS observations, no real wait.
                    """
                    return run_development_actions(run_id, writer, observe, guard, retain, monotonic_ns=mono, sleep=sleep)

                def outer_worker(command, descriptor, timeout_seconds, **options):
                    """Replace only outer process launch while keeping the real composed runtime.

                    Inputs:
                        command: Maintained outer argv, not launched by this offline test.
                        descriptor: Current reviewed case and independent fingerprint.
                        timeout_seconds: Fixed 3,000-second hard supervisor limit.
                        options: Must request whole-group cleanup including normal exit.
                    Outputs:
                        str: Success when an actual positive or negative result is retained.
                    """
                    self.assertEqual(timeout_seconds, 3000)
                    self.assertEqual(options, {'terminate_group_on_exit': True})
                    with patch('research.development_rehearsal.os.getsid', return_value=os.getpid()), \
                            patch('research.development_rehearsal.os.getpgrp', return_value=os.getpid()), \
                            patch('research.development_rehearsal.signal.alarm'), \
                            patch('research.development_rehearsal.utc_now', side_effect=wall), \
                            patch('research.development_rehearsal.time.monotonic_ns', side_effect=mono), \
                            patch('research.development_rehearsal.BoundWriterSession', side_effect=broker), \
                            patch('research.development_rehearsal.capture_versioning_point', side_effect=point), \
                            patch('research.development_rehearsal.run_development_actions', side_effect=actions), \
                            patch('research.development_rehearsal.MacKeychainDecryptor', return_value=self.decrypt), \
                            patch('research.preparation_operator.MacKeychainDecryptor', return_value=self.decrypt), \
                            patch('research.sandbox_operator.bounded_worker', side_effect=capture_worker), \
                            patch('research.development_rehearsal.boto3', SimpleNamespace(Session=Mock(return_value=object()))):
                        run_rehearsal_worker(descriptor['scope'], descriptor['approved_scope_sha256'])
                    return 'success'

                with patch('research.development_rehearsal.bounded_worker', side_effect=outer_worker) as process:
                    summary = run_rehearsal_operator(scope, canonical_sha256(scope))
                process.assert_called_once()
                self.assertEqual(summary['worker_status'], 'success')
                result = json.loads((self.base / 'case/result.json').read_text())
                self.assertEqual(canonical_sha256(result), summary['result_sha256'])
                self.assertEqual(result['engineering_cycle_completed'], not stale)
                self.assertEqual(result['actions']['mutation_calls'], 0 if stale else 1)
                self.assertFalse(result['formal_trial_authorized'] or result['ai_model_evaluation_performed'])
                self.assertEqual(result['research_trials'], 0)
                lock = self.base / 'locks' / (BUCKET + '.lock')
                self.assertTrue((lock / 'recovery-intent').is_dir())
                self.assertEqual((lock / 'recovery-closure').is_dir(), not stale)
                with self.assertRaises(ValueError):run_rehearsal_operator(scope, canonical_sha256(scope))
                writes.assert_no_pending_responses()
                for response in list(role_case[4]) + stubs:response.assert_no_pending_responses()
