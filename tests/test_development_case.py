"""Development-case sequencing and recovery tests with trusted synthetic adapters, no live trial."""
import unittest

from research.catalog import canonical_sha256
from research.development_case import run_development_actions
from research.versioning_point import VERSION


class DevelopmentCaseTests(unittest.TestCase):
    """Check actual action ordering, frozen horizon and bounded recovery across meaningful failures."""

    def fixture(self, failure=None):
        """Build a synthetic writer, receipt adapter, retained journal and advancing test clock.

        Inputs:
            self: Test instance with ordering assertions and no real credentials.
            failure: Optional prechange, pending, mutation, trigger, retention, cancel or restore_cancel fault.
        Outputs:
            tuple: Writer, point/admission/retention callbacks, clock/sleep and recorded event list.
                These trusted test callbacks are not authenticated cloud observations.
        """
        clock, events, sequence = {'ns': 0}, [], {'value': 0}

        class Writer:
            """Minimal trusted test writer counting requests without any SDK session."""
            mutations = restores = 0

            def summary(writer):
                """Expose only the fixed run identity expected by the orchestration.

                Inputs:
                    writer: Synthetic writer holding in-memory counters only.
                Outputs:
                    dict: Fixed development run ID; no actual AWS identity claim.
                """
                return {'run_id': 'a' * 32}

            def suspend_once(writer):
                """Simulate a single possible change after a durable pending record.

                Inputs:
                    writer: Synthetic writer incrementing its request counter.
                Outputs:
                    None: Records call and optionally raises an ambiguous synthetic failure.
                """
                self.assertEqual(events[-1], 'change_pending')
                writer.mutations += 1
                if failure == 'mutation':raise ValueError('Synthetic ambiguous write')

            def restore_enabled(writer):
                """Simulate bounded restoration without turning a response into state proof.

                Inputs:
                    writer: Synthetic writer incrementing its recovery counter.
                Outputs:
                    None: Records call or simulates cancellation during restoration.
                """
                writer.restores += 1
                if failure == 'restore_cancel':raise KeyboardInterrupt()

        def point(slot):
            """Supply fixed-phase synthetic reports from the same fake clock domain.

            Inputs:
                slot: Maintained observation slot selected by the development orchestrator.
            Outputs:
                dict: Minimal synthetic report; not actual readback or interval proof.
            """
            clock['ns'] += 1
            status = 'Enabled' if slot == 'admission' or slot.startswith('restoration-') else 'Suspended'
            if failure == 'trigger' and slot == 'trigger':status = 'Enabled'
            if failure in ('retention', 'restore_cancel') and slot.startswith('restoration-'):status = 'Suspended'
            return {'version': VERSION, 'phase': 'development', 'run_id': 'a' * 32, 'point': slot,
                'observed_status': status, 'finished_at': '2026-11-02T00:00:00Z', 'finished_monotonic_ns': clock['ns'],
                'receipts_sha256': 'b' * 64, 'request_receipt_clock_consistent': True,
                'interval_state_verified': False, 'formal_trial_authorized': False, 'research_trials': 0,
                'ciphertext_fingerprint': 'c' * 64}

        def admit():
            """Simulate the maintained lock/freshness admission checker.

            Inputs:
                No arguments; reads only this test's selected fault.
            Outputs:
                None: Raises before possible mutation when synthetic admission fails.
            """
            if failure == 'prechange':raise ValueError('Synthetic invalid prestate')

        def retain(record):
            """Acknowledge ordered journal events or inject a pre/post-change retention outage.

            Inputs:
                record: Maintained development action frame containing only minimal metadata.
            Outputs:
                dict: Synthetic ciphertext-shaped acknowledgment; no actual encryption in this test.
            """
            event = record['event']
            events.append(event)
            if failure == 'pending' and event == 'change_pending' or failure == 'retention' and event in ('trigger_observed', 'restore_pending', 'terminal'):
                raise OSError('Synthetic retention outage')
            receipt = {'file': f"record-{sequence['value']:05d}.cms", 'ciphertext_sha256': canonical_sha256(record)}
            sequence['value'] += 1
            return receipt

        def sleep(seconds):
            """Advance synthetic time by bounded waits and optionally simulate user cancellation.

            Inputs:
                seconds: Positive wait of at most five seconds, never a real blocking sleep.
            Outputs:
                None: Advances fake clock or raises synthetic KeyboardInterrupt during observation.
            """
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 5)
            if failure == 'cancel':raise KeyboardInterrupt()
            clock['ns'] += int(seconds * 1_000_000_000)

        return Writer(), point, admit, retain, clock, sleep, events

    def run_case(self, fixture):
        """Execute one case using fixed development identity and disposable in-memory adapters.

        Inputs:
            self: Test instance with no external runtime state.
            fixture: Tuple returned by fixture() containing trusted synthetic callbacks.
        Outputs:
            dict: Development-only action result; no AWS operation or trial.
        """
        writer, point, admit, retain, clock, sleep, _ = fixture
        return run_development_actions('a' * 32, writer, point, admit, retain,
                                       monotonic_ns=lambda: clock['ns'], sleep=sleep)

    def test_fixed_window_and_recovery_follow_verified_point_order(self):
        """Preserve one mutation, one fixed cutoff and independent Enabled readback after restore.

        Inputs:
            self: Test instance with exact same-domain synthetic readback reports.
        Outputs:
            None: Asserts full development sequence while every formal-study/release gate stays false.
        """
        case = self.fixture()
        result = self.run_case(case)
        self.assertEqual((case[0].mutations, case[0].restores), (1, 1))
        self.assertEqual(result['cutoff_monotonic_ns'], 2 + 1800_000_000_000)
        self.assertTrue(result['window_completed'] and result['enabled_readback_observed'] and result['journal_complete'])
        self.assertFalse(result['formal_trial_authorized'] or result['lock_release_allowed'])
        self.assertEqual(result['research_trials'], 0)
        self.assertEqual(set(result['point_fingerprints']), {'admission', 'trigger', 'window_end', 'restoration-1'})

    def test_prechange_failures_never_request_mutation_or_restore(self):
        """Fail closed before the first possible change when admission or durable pending retention fails.

        Inputs:
            self: Test instance selecting pre-change safety failures.
        Outputs:
            None: Asserts no write/recovery callback and no successful window are fabricated.
        """
        for failure in ('prechange', 'pending'):
            with self.subTest(failure=failure):
                case = self.fixture(failure)
                result = self.run_case(case)
                self.assertEqual((case[0].mutations, case[0].restores), (0, 0))
                self.assertFalse(result['window_completed'] or result['enabled_readback_observed'])

    def test_ambiguity_cancellation_and_journal_outage_keep_recovery_bounded(self):
        """Recover after possible change, preserve negative results and cap uncertain restoration.

        Inputs:
            self: Test instance injecting post-change response, trigger, journal and cancellation faults.
        Outputs:
            None: Verifies one mutation, one/three bounded restores and no false window completion.
        """
        for failure in ('mutation', 'trigger', 'retention', 'cancel', 'restore_cancel'):
            with self.subTest(failure=failure):
                case = self.fixture(failure)
                result = self.run_case(case)
                self.assertEqual(case[0].mutations, 1)
                self.assertEqual(case[0].restores, 3 if failure == 'retention' else 1)
                if failure != 'restore_cancel':self.assertFalse(result['window_completed'])
                if failure in ('retention', 'restore_cancel'):
                    self.assertFalse(result['enabled_readback_observed'])
                else:
                    self.assertTrue(result['enabled_readback_observed'])
                if failure == 'retention':self.assertFalse(result['journal_complete'])
