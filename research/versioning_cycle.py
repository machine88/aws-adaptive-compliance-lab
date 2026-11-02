"""Offline callback executor for the fixed change/observe/restore protocol; no AWS adapter or CLI."""
from asyncio import CancelledError
import copy
from dataclasses import asdict
import hashlib
from pathlib import Path
import time

from research.catalog import canonical_sha256
from research.recovery_intent import verify_recovery_intent
from research.scenario_lock import validate_run_id
from research.scenario_recovery import RecoveryState, next_recovery_action
from research.timing import require_sha256

VERSION = "offline-versioning-cycle-v0.1"
KEYS = {"version", "phase", "mode", "run_id", "source_sha256", "intent_sha256",
        "intent_review_sha256", "intent_source_sha256", "recipient_sha256", "horizon_seconds",
        "max_mutation_callbacks", "max_restoration_callbacks"}
CALLBACKS = {"admit", "suspend", "verify_suspended", "observe_until", "restore", "verify_enabled", "retain"}


def cycle_source_sha256():
    """Bind maintained offline driver dependencies without opening credentials or evidence.

    Inputs:
        No arguments; reads regular research Python source files only.
    Outputs:
        str: Canonical path/content hash; no AWS, SDK session, filesystem mutation or decryption.
    """
    root = Path(__file__).resolve().parent
    files = sorted(root.glob("*.py"))
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Regular offline driver source required")
    return canonical_sha256({path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files})


def validate_cycle_scope(scope, approved_scope_sha256):
    """Require the exact synthetic-only protocol and independently retained scope/source pins.

    Inputs:
        scope: Development-only offline contract with independent retained-intent provenance pins.
        approved_scope_sha256: Independent scope fingerprint used by the offline integration test/operator.
    Outputs:
        None: Local source reads only; rejects changed/widened scopes before any callback.
            Hash matching never authorizes a live mutation or authenticates supplied callbacks.
    """
    require_sha256(approved_scope_sha256)
    if not isinstance(scope, dict) or set(scope) != KEYS or scope["version"] != VERSION or scope["phase"] != "development" or scope["mode"] != "synthetic_only":
        raise ValueError("Exact synthetic-only driver contract required")
    validate_run_id(scope["run_id"])
    for name in ("source_sha256", "intent_sha256", "intent_review_sha256", "intent_source_sha256", "recipient_sha256"):
        require_sha256(scope[name])
    for name, value in (("horizon_seconds", 1800), ("max_mutation_callbacks", 1), ("max_restoration_callbacks", 3)):
        if type(scope[name]) is not int or scope[name] != value:
            raise ValueError("Fixed offline timing and request bounds required")
    if canonical_sha256(scope) != approved_scope_sha256 or cycle_source_sha256() != scope["source_sha256"]:
        raise ValueError("Offline scope or maintained source changed")


def run_offline_versioning_cycle(scope, approved_scope_sha256, callbacks, monotonic_ns=time.monotonic_ns):
    """Exercise one change, fixed-window observation and bounded restoration with synthetic callbacks.

    Inputs:
        scope: Exact independently pinned synthetic-only development contract; never live approval.
        approved_scope_sha256: Retained offline scope fingerprint, not authorization for AWS.
        callbacks: Exact trusted callable map: admit() returns synthetic intent admission;
            suspend(request) simulates one fixed change; verify_suspended() returns exactly True
            only for independent synthetic confirmation; observe_until(deadline_ns) returns
            {deadline_ns, window_closed: True}; restore(request) simulates Enabled restoration;
            verify_enabled() returns exactly True only for independent synthetic confirmation;
            retain(record) durably retains an encrypted event and returns its ordered CMS receipt.
            Use disposable test adapters only; Python callables are not a security sandbox.
        monotonic_ns: Injectable integer nanosecond clock; tests advance it without sleeping.
    Outputs:
        dict: Minimal synthetic state/counters with every live/research/release gate closed.
            Calls no SDK itself, prints no callback result/error and never releases a lock.
            Requires durable admission/pending-change records before change. After possible
            change, journal failures do not prevent bounded best-effort restoration; they force
            review. Ambiguous writes never retry the mutation; restore requests are at most three.
            Cooperative callbacks cannot guarantee recovery after process kill, host/network loss
            or a hung callback. No live adapter, runtime supervisor or credential proof is provided.
    """
    scope = copy.deepcopy(scope)
    validate_cycle_scope(scope, approved_scope_sha256)
    if not isinstance(callbacks, dict) or set(callbacks) != CALLBACKS or any(not callable(value) for value in callbacks.values()):
        raise ValueError("Exact trusted synthetic callback set required")
    state = RecoveryState()
    sequence = 0
    journal_ok = True
    mutation_calls = restoration_calls = 0
    window_completed = False
    cause = "none"
    last_clock = None

    def clock():
        """Reject malformed/rolling-back local timing in the synthetic driver.

        Inputs:
            No arguments; invokes the explicitly supplied monotonic_ns callback.
        Outputs:
            int: Nonnegative monotonic timestamp or a generic error; no timestamp is backdated.
        """
        nonlocal last_clock
        try:
            value = monotonic_ns()
        except BaseException:
            raise ValueError("Offline clock unavailable") from None
        if type(value) is not int or value < 0 or (last_clock is not None and value < last_clock):
            raise ValueError("Invalid offline monotonic clock")
        last_clock = value
        return value

    def retain(event, action, required=False):
        """Require ordered ciphertext acknowledgments without logging raw callback data/errors.

        Inputs:
            event: Maintained event label; never raw exception text or detector output.
            action: Maintained next-action description.
            required: Whether failure must stop before the first possible change callback.
        Outputs:
            bool: True for a well-formed ordered receipt; False marks uncertain/incomplete journal.
                Required failure raises only a generic ValueError. No plaintext file is written here.
        """
        nonlocal sequence, journal_ok
        record = {"version": VERSION, "phase": "development", "synthetic_only": True, "run_id": scope["run_id"],
                  "scope_sha256": approved_scope_sha256, "sequence": sequence,
                  "state": asdict(state), "event": event, "action": action,
                  "live_execution_allowed": False, "research_trials": 0}
        try:
            receipt = callbacks["retain"](record)
            if not isinstance(receipt, dict) or set(receipt) != {"file", "ciphertext_sha256"} or receipt["file"] != f"record-{sequence:05d}.cms":
                raise ValueError("Ordered encrypted acknowledgment required")
            require_sha256(receipt["ciphertext_sha256"])
            sequence += 1
            return True
        except BaseException:
            journal_ok = False
            if required:
                raise ValueError("Durable offline pre-change evidence required") from None
            return False

    def summary(phase):
        """Return only engineering counters and permanently closed live/scientific gates.

        Inputs:
            phase: Maintained terminal state label, not a provider or detector response.
        Outputs:
            dict: Synthetic outcome with no raw evidence, comparative result or credential value.
        """
        return {"version": VERSION, "synthetic_only": True, "phase": phase, "run_id": scope["run_id"],
                "mutation_callbacks": mutation_calls, "restoration_callbacks": restoration_calls,
                "window_completed": window_completed, "restored_in_simulation": state.phase == "recovered",
                "durable_journal_complete": journal_ok, "cause": cause,
                "manual_review_required": state.phase != "recovered" or not journal_ok,
                "restoration_verified": False, "lock_release_allowed": False,
                "live_execution_allowed": False, "research_trials": 0}

    # A completed real read-only preparation is not admission to this synthetic write exercise.
    try:
        admission = callbacks["admit"]()
    except BaseException:
        raise ValueError("Synthetic admission unavailable; no change attempted") from None
    if not isinstance(admission, dict) or set(admission) != {"kind", "intent"} or admission["kind"] != "synthetic_development_admission":
        raise ValueError("Explicit synthetic admission required")
    intent = copy.deepcopy(admission["intent"])
    intent_pin = verify_recovery_intent(intent, scope["run_id"], scope["intent_review_sha256"],
                                       scope["intent_source_sha256"], scope["recipient_sha256"])
    if intent_pin != scope["intent_sha256"]:
        raise ValueError("Synthetic intent differs from independently retained pin")
    clock()
    retain("admission_retained", "prepare_change", required=True)
    state, action = next_recovery_action(state, "preflight_retained")
    retain("change_pending", action, required=True)
    event = "write_response_only"
    try:
        mutation_calls += 1
        callbacks["suspend"](copy.deepcopy(intent["requests"]["proposed_mutation"]))
        # Write success alone cannot open the observation window.
        if callbacks["verify_suspended"]() is True:
            state, action = next_recovery_action(state, "independent_suspended_receipt")
            trigger = clock()
            deadline = trigger + scope["horizon_seconds"] * 1_000_000_000
            if retain("suspension_confirmed", action):
                observed = callbacks["observe_until"](deadline)
                expected = {"deadline_ns": deadline, "window_closed": True}
                if canonical_sha256(observed) != canonical_sha256(expected) or clock() < deadline:
                    raise ValueError("Fixed offline observation window did not complete")
                window_completed = True
                event = "window_closed"
            else:
                cause, event = "journal_failure", "error"
        else:
            cause = "unverified_change"
    except BaseException as error:
        cancelled = isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError))
        cause, event = ("cancelled", "cancel") if cancelled else ("change_or_observation_error", "error")
    state, action = next_recovery_action(state, event)
    # Recovery continues even if optional post-change journal acknowledgment is unavailable.
    retain(event, action)
    while state.phase == "restoring":
        retain("restore_pending", action)
        cancelled = False
        restoration_calls += 1
        try:
            callbacks["restore"](copy.deepcopy(intent["requests"]["restoration"]))
        except BaseException as error:
            cancelled = isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError))
        verified = False
        try:
            verified = callbacks["verify_enabled"]() is True
        except BaseException as error:
            cancelled = cancelled or isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError))
        event = "restoration_verified" if verified else "cancel" if cancelled else "restoration_ambiguous"
        state, action = next_recovery_action(state, event)
        retain(event, action)
    retain("cycle_terminal", "keep_lock_for_review")
    if cause == "none" and state.phase != "recovered":
        cause = "restoration_unverified"
    if cause == "none" and not journal_ok:
        cause = "journal_failure"
    return summary(state.phase)
