"""Offline session-metadata timing checks; never resolve credentials or authorize a live writer."""
from datetime import timedelta

from research.catalog import canonical_sha256
from research.scenario_lock import validate_run_id
from research.timing import require_sha256, utc_timestamp

# Inputs: retained nonsecret metadata only. Output: fixed development timing assessment.
VERSION = "writer-session-budget-v0.1"
TRANSPORT_SECONDS = 2400
RECOVERY_MARGIN_SECONDS = 120
MAX_SAMPLE_AGE_SECONDS = 30
CLOCK_TOLERANCE_NS = 1_000_000_000
ROLE_ARN = ("arn:aws:sts::653464153304:assumed-role/"
            "dissertation-sandbox-versioning/dissertation-sandbox-versioning")
SAMPLE_KEYS = {"version", "phase", "run_id", "role_arn", "expires_at", "sampled_at",
               "sample_monotonic_ns", "source_record_sha256"}


def assess_writer_session_budget(sample, expected_sample_sha256, run_id, assessed_at, monotonic_ns):
    """Reject insufficient or stale declared session timing without reading a credential provider.

    Inputs:
        sample: Exact nonsecret metadata frame from a future trusted session-evidence adapter;
            contains expiration, local sample clocks and retained source-record fingerprint only.
        expected_sample_sha256: Independently retained fingerprint of the entire metadata frame;
            matching proves consistency only, not authentic provider provenance or user approval.
        run_id: Independently selected development run identifier that must match the sample.
        assessed_at: Explicit timezone-aware current wall-clock string, supplied by the caller.
        monotonic_ns: Current nonnegative integer monotonic sample in the same process/clock domain.
    Outputs:
        dict: Fixed-budget planning assessment with every live/credential/restoration gate false;
            raises ValueError on bad binding, schema, clock, age or insufficient declared lifetime.
            No credential, SDK, AWS, evidence-file, environment or operational-lock access occurs.
    """
    validate_run_id(run_id)
    require_sha256(expected_sample_sha256)
    # Closed metadata schema excludes access keys, tokens and arbitrary provider response fields.
    if not isinstance(sample, dict) or set(sample) != SAMPLE_KEYS:
        raise ValueError("Exact nonsecret session timing metadata required")
    if sample["version"] != VERSION or sample["phase"] != "development" or sample["run_id"] != run_id or sample["role_arn"] != ROLE_ARN:
        raise ValueError("Exact development run and writer role required")
    require_sha256(sample["source_record_sha256"])
    if canonical_sha256(sample) != expected_sample_sha256:
        raise ValueError("Session timing metadata differs from independent fingerprint")
    sampled_ns = sample["sample_monotonic_ns"]
    if type(sampled_ns) is not int or type(monotonic_ns) is not int or sampled_ns < 0 or monotonic_ns < sampled_ns:
        raise ValueError("Same-domain monotonic progression required")
    sampled, assessed, expires = (utc_timestamp(value) for value in
                                  (sample["sampled_at"], assessed_at, sample["expires_at"]))
    wall_elapsed = assessed - sampled
    mono_elapsed_ns = monotonic_ns - sampled_ns
    wall_elapsed_ns = ((wall_elapsed.days * 86400 + wall_elapsed.seconds) * 1_000_000
                       + wall_elapsed.microseconds) * 1000
    # Both clocks must progress consistently; neither may hide a stale or backdated frame.
    if wall_elapsed_ns < 0 or abs(wall_elapsed_ns - mono_elapsed_ns) > CLOCK_TOLERANCE_NS:
        raise ValueError("Session sampling clocks are inconsistent")
    if max(wall_elapsed_ns, mono_elapsed_ns) > MAX_SAMPLE_AGE_SECONDS * 1_000_000_000:
        raise ValueError("Fresh session timing sample required")
    if expires > sampled + timedelta(seconds=3600):
        raise ValueError("Declared expiration exceeds the deployed role maximum")
    required_seconds = TRANSPORT_SECONDS + RECOVERY_MARGIN_SECONDS
    # Charge the greater elapsed clock, then reserve skew tolerance in addition to recovery time.
    charged_elapsed_ns = max(wall_elapsed_ns, mono_elapsed_ns)
    remaining = expires - sampled
    remaining_ns = ((remaining.days * 86400 + remaining.seconds) * 1_000_000
                    + remaining.microseconds) * 1000 - charged_elapsed_ns
    if remaining_ns < required_seconds * 1_000_000_000 + CLOCK_TOLERANCE_NS:
        raise ValueError("Insufficient declared session lifetime for transport and recovery reserve")
    return {"version": VERSION, "phase": "development", "run_id": run_id,
            "sample_sha256": expected_sample_sha256, "assessed_at": assessed_at,
            "assessed_monotonic_ns": monotonic_ns, "declared_budget_sufficient": True,
            "transport_seconds": TRANSPORT_SECONDS, "recovery_margin_seconds": RECOVERY_MARGIN_SECONDS,
            "clock_tolerance_ns": CLOCK_TOLERANCE_NS, "max_sample_age_seconds": MAX_SAMPLE_AGE_SECONDS,
            "provider_provenance_verified": False, "credential_coverage_verified": False,
            "live_execution_allowed": False, "restoration_verified": False, "research_trials": 0}
