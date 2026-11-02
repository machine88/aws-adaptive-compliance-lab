"""Offline safety tests for session timing replay, clock changes and recovery budget exhaustion."""
import copy
import unittest
from datetime import datetime, timedelta, timezone

from research.catalog import canonical_sha256
from research.writer_coverage import ROLE_ARN, VERSION, assess_writer_session_budget


class WriterCoverageTests(unittest.TestCase):
    """Exercise fixed timing and independent-binding boundaries using synthetic metadata only."""

    def frame(self, lifetime=3600):
        """Build nonsecret synthetic writer metadata without consulting real credentials.

        Inputs:
            self: Test instance; owns no cloud session or operational evidence.
            lifetime: Synthetic seconds between sample time and declared expiration.
        Outputs:
            dict: Fresh independently fingerprintable development metadata fixture.
        """
        start = datetime(2026, 11, 2, tzinfo=timezone.utc)
        return {"version": VERSION, "phase": "development", "run_id": "a" * 32,
                "role_arn": ROLE_ARN, "sampled_at": start.isoformat(),
                "expires_at": (start + timedelta(seconds=lifetime)).isoformat(),
                "sample_monotonic_ns": 5_000_000_000, "source_record_sha256": "b" * 64}

    def test_binding_schema_and_role_replay_are_rejected(self):
        """Reject altered samples, cross-run reuse, alternate roles and accidental secret fields.

        Inputs:
            self: Test instance supplying synthetic metadata and independent expected pins.
        Outputs:
            None: Assertions verify rejection; no credential lookup, file or AWS access.
        """
        sample = self.frame()
        pin = canonical_sha256(sample)
        for key, value in (("run_id", "c" * 32), ("role_arn", ROLE_ARN + "-other"),
                           ("phase", "pilot"), ("AccessKeyId", "synthetic-forbidden-field")):
            changed = copy.deepcopy(sample)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                assess_writer_session_budget(changed, canonical_sha256(changed), "a" * 32,
                                             sample["sampled_at"], 5_000_000_000)
        changed = dict(sample, source_record_sha256="c" * 64)
        with self.assertRaises(ValueError):
            assess_writer_session_budget(changed, pin, "a" * 32, sample["sampled_at"], 5_000_000_000)

    def test_age_and_clock_inversions_fail_before_admission(self):
        """Reject stale, future, naive, malformed and inconsistent wall/monotonic samples.

        Inputs:
            self: Test instance with a fixed synthetic same-domain clock anchor.
        Outputs:
            None: Assertions preserve closed live gates across clock/replay failures.
        """
        sample = self.frame()
        cases = [("2026-11-02T00:00:31Z", 36_000_000_000),
                 ("2026-11-02T00:00:00Z", 36_000_000_000),
                 ("2026-11-02T00:00:03Z", 5_000_000_000),
                 ("2026-11-01T23:59:59Z", 5_000_000_000),
                 ("2026-11-02T00:00:00", 5_000_000_000),
                 ("2026-11-02T00:00:00Z", 4_000_000_000),
                 ("2026-11-02T00:00:00Z", True)]
        for wall, mono in cases:
            with self.subTest(wall=wall, mono=mono), self.assertRaises(ValueError):
                assess_writer_session_budget(sample, canonical_sha256(sample), "a" * 32, wall, mono)

    def test_budget_reserves_recovery_skew_and_elapsed_time(self):
        """Require the entire transport lifetime plus recovery reserve and conservative clock charge.

        Inputs:
            self: Test instance evaluating synthetic expiration boundaries without real waiting.
        Outputs:
            None: Assertions check exact admission boundary, late reevaluation and false proof gates.
        """
        for lifetime in (-1, 0, 1800, 2400, 2520, 3601):
            sample = self.frame(lifetime)
            with self.subTest(lifetime=lifetime), self.assertRaises(ValueError):
                assess_writer_session_budget(sample, canonical_sha256(sample), "a" * 32,
                                             sample["sampled_at"], 5_000_000_000)
        sample = self.frame(2521)
        original = copy.deepcopy(sample)
        result = assess_writer_session_budget(sample, canonical_sha256(sample), "a" * 32,
                                              sample["sampled_at"], 5_000_000_000)
        self.assertTrue(result["declared_budget_sufficient"])
        self.assertEqual(sample, original)
        self.assertFalse(any(result[key] for key in ("provider_provenance_verified",
                         "credential_coverage_verified", "live_execution_allowed", "restoration_verified")))
        self.assertEqual(result["research_trials"], 0)
        # A prior sufficient result cannot be reused as a later sample or hide elapsed time.
        with self.assertRaises(ValueError):
            assess_writer_session_budget(sample, canonical_sha256(sample), "a" * 32,
                                         "2026-11-02T00:00:00.000001Z", 5_000_001_000)
        sample = self.frame(2522)
        with self.assertRaises(ValueError):
            assess_writer_session_budget(sample, canonical_sha256(sample), "a" * 32,
                                         "2026-11-02T00:00:00.5Z", 6_100_000_000)
        with self.assertRaises(ValueError):
            assess_writer_session_budget(result, canonical_sha256(result), "a" * 32,
                                         "2026-11-02T00:00:01Z", 6_000_000_000)
