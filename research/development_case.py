"""Development-only versioning action orchestration; trusted adapters, no formal trial or ML metrics."""
from asyncio import CancelledError
import time

from research.catalog import canonical_sha256
from research.scenario_lock import validate_run_id
from research.timing import require_sha256
from research.versioning_point import VERSION as POINT_VERSION

HORIZON_SECONDS = 1800
POINT_KEYS = {"version", "phase", "run_id", "point", "observed_status", "finished_at", "finished_monotonic_ns",
              "receipts_sha256", "request_receipt_clock_consistent", "interval_state_verified",
              "formal_trial_authorized", "research_trials", "ciphertext_fingerprint"}


def run_development_actions(run_id, writer, observe_point, prechange_check, retain,
                            monotonic_ns=time.monotonic_ns, sleep=time.sleep):
    """Perform one fixed change/window and bounded recovery with maintained trusted adapters.

    Inputs:
        run_id: Independent approved development run identifier matching writer and readback scopes.
        writer: Initialized fixed-target BoundedVersioningWriter; scope/intent/session checks external.
        observe_point: Trusted maintained adapter accepting one fixed slot name; must capture and
            independently decrypt/verify its raw receipts before returning the exact minimal report.
        prechange_check: Trusted no-argument lock/fresh-prestate/admission checker, raises on failure.
        retain: Trusted encrypted-journal callback receiving maintained metadata-only event frames;
            returns an ordered ciphertext receipt. Matching callback shapes do not authenticate code.
        monotonic_ns: Same-process nonnegative integer clock shared with the point observer.
        sleep: Trusted bounded wait callback; tests advance synthetic time without real waiting.
    Outputs:
        dict: Development action result only, with formal/research/release gates false. No SDK is
            created here; the separately reviewed runtime binds actual maintained adapters.
            One possible suspension, a fixed 1,800-second horizon from verified point finish,
            and at most three Enabled calls; no mutation retry, automatic restart or lock release.
            Post-change failures attempt bounded recovery even when journaling fails. Callbacks
            are cooperative; process kill, host/network loss and arbitrary injected code remain
            outside this orchestration's guarantees. A write response never proves restoration.
    """
    validate_run_id(run_id)
    if writer.summary().get("run_id") != run_id or any(not callable(callback) for callback in (observe_point, prechange_check, retain, monotonic_ns, sleep)):
        raise ValueError("Matching writer and trusted development adapters required")
    sequence, last_ns, possible_change = 0, None, False
    journal_complete, window_completed, restoration_observed = True, False, False
    mutation_calls = restoration_calls = 0
    cause, deadline = "none", None
    points = {}

    def now():
        """Reject invalid or backward local clocks before the next orchestration decision.

        Inputs:
            No arguments; invokes supplied same-process monotonic_ns callback.
        Outputs:
            int: Nonnegative clock or generic failure; no timestamp is backdated.
        """
        nonlocal last_ns
        value = monotonic_ns()
        if type(value) is not int or value < 0 or last_ns is not None and value < last_ns:
            raise ValueError("Invalid development monotonic clock")
        last_ns = value
        return value

    def journal(event, details, required=False):
        """Require ordered durable evidence before change; preserve recovery after later outages.

        Inputs:
            event: Maintained action label, not provider exception text.
            details: Minimal event details containing counts, hashes and point summaries only.
            required: Whether retention failure must prevent the first possible mutation.
        Outputs:
            bool: True for acknowledged retention; False marks incomplete evidence. Required
                failure raises a generic error. No raw SDK response is returned or printed here.
        """
        nonlocal sequence, journal_complete
        try:
            receipt = retain({"kind": "development_case_event", "phase": "development", "run_id": run_id,
                              "sequence": sequence, "event": event, "details": details, "research_trials": 0})
            if not isinstance(receipt, dict) or set(receipt) != {"file", "ciphertext_sha256"} or receipt["file"] != f"record-{sequence:05d}.cms":
                raise ValueError("Ordered encrypted case journal required")
            require_sha256(receipt["ciphertext_sha256"])
            sequence += 1
            return True
        except BaseException:
            journal_complete = False
            if required:
                raise ValueError("Required pre-change retention failed") from None
            return False

    def point(slot):
        """Accept one exact source-bound report within its same-process acquisition interval.

        Inputs:
            slot: Fixed admission, trigger, window_end or numbered restoration slot, used once.
        Outputs:
            dict: Minimal independently readback-verified report from the trusted runtime adapter.
                Rejects replay, changed phase/run, mismatched clocks or fabricated research gates.
                This shape check alone cannot authenticate an arbitrary Python callback.
        """
        if slot in points:
            raise ValueError("Development point slot already consumed")
        before = now()
        report = observe_point(slot)
        after = now()
        if not isinstance(report, dict) or set(report) != POINT_KEYS or report["version"] != POINT_VERSION or report["phase"] != "development" or report["run_id"] != run_id or report["point"] != slot:
            raise ValueError("Exact development point report required")
        for key in ("receipts_sha256", "ciphertext_fingerprint"):
            require_sha256(report[key])
        finished = report["finished_monotonic_ns"]
        if type(finished) is not int or not before <= finished <= after or report["observed_status"] not in {"Enabled", "Suspended"}:
            raise ValueError("Current same-domain point receipt required")
        if report["request_receipt_clock_consistent"] is not True or report["interval_state_verified"] is not False or report["formal_trial_authorized"] is not False or type(report["research_trials"]) is not int or report["research_trials"] != 0:
            raise ValueError("Development-only point gates required")
        points[slot] = report
        return report

    try:
        journal("scope", {"horizon_seconds": HORIZON_SECONDS, "max_mutations": 1, "max_restorations": 3}, required=True)
        admission = point("admission")
        if admission["observed_status"] != "Enabled":
            raise ValueError("Enabled independent admission required")
        prechange_check()
        journal("change_pending", {"admission_sha256": canonical_sha256(admission)}, required=True)
        # Mark uncertainty before the call, including a guard/transport error with no response.
        possible_change, mutation_calls = True, 1
        writer.suspend_once()
        trigger = point("trigger")
        if trigger["observed_status"] != "Suspended":
            cause = "suspension_not_observed"
            raise ValueError("Suspended trigger not observed")
        deadline = trigger["finished_monotonic_ns"] + HORIZON_SECONDS * 1_000_000_000
        if not journal("trigger_observed", {"point_sha256": canonical_sha256(trigger), "cutoff_monotonic_ns": deadline}):
            cause = "evidence_retention_failed"
            raise ValueError("Incomplete trigger journal")
        while True:
            current = now()
            if current >= deadline:
                break
            sleep(min(5, (deadline - current) / 1_000_000_000))
        end = point("window_end")
        if end["observed_status"] != "Suspended":
            cause = "end_state_changed"
            raise ValueError("Window end differs from expected development state")
        window_completed = True
        journal("window_closed", {"point_sha256": canonical_sha256(end), "cutoff_monotonic_ns": deadline})
    except BaseException as error:
        if cause == "none":
            cause = "cancelled" if isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError)) else "development_action_failed"
        journal("action_failed", {"cause": cause, "possible_change": possible_change})
    finally:
        if possible_change:
            for number in range(1, 4):
                restoration_calls += 1
                journal("restore_pending", {"attempt": number})
                cancelled = False
                try:
                    writer.restore_enabled()
                except BaseException as error:
                    cancelled = isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError))
                    journal("restore_response_uncertain", {"attempt": number})
                try:
                    restored = point(f"restoration-{number}")
                    restoration_observed = restored["observed_status"] == "Enabled"
                except BaseException as error:
                    cancelled = cancelled or isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError))
                if cancelled and cause == "none":
                    cause = "cancelled"
                if restoration_observed or cancelled:
                    break
    if possible_change and not restoration_observed and cause == "none":
        cause = "restoration_not_observed"
    result = {"phase": "development", "run_id": run_id, "mutation_calls": mutation_calls,
              "restoration_calls": restoration_calls, "window_completed": window_completed,
              "enabled_readback_observed": restoration_observed, "journal_complete": journal_complete,
              "cause": cause, "point_fingerprints": {slot: report["ciphertext_fingerprint"] for slot, report in points.items()},
              "cutoff_monotonic_ns": deadline, "formal_trial_authorized": False,
              "lock_release_allowed": False, "research_trials": 0}
    journal("terminal", {"cause": cause, "window_completed": window_completed, "enabled_readback_observed": restoration_observed})
    result["journal_complete"] = journal_complete
    if not journal_complete and result["cause"] == "none":
        result["cause"] = "evidence_retention_failed"
    return result
