"""Callback-based locked development preparation; no built-in AWS adapter or mutation path."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import time

from research.archive_ingestion import private_bytes
from research.aws_reader import sync_archive_directory
from research.catalog import canonical_sha256
from research.recovery_intent import retain_recovery_intent
from research.recovery_review import private_directory
from research.sandbox_capture import utc_now
from research.sandbox_observer import utc_clock
from research.sandbox_operator import validate_sandbox_scope
from research.sandbox_readiness import BUCKET
from research.sandbox_verification import read_verified_sandbox_prestate
from research.scenario_lock import acquire_sandbox_lock, inspect_sandbox_lock, private_lock_root, validate_run_id
from research.timing import require_sha256

VERSION = "observer-recovery-preparation-v0.1"
MAX_PREPARATION_NS = 300_000_000_000
CLOCK_TOLERANCE_NS = 1_000_000_000


def check_local_interval(started, finished, monotonic_start, monotonic_finish):
    """Reject rollback, excessive local duration or large host-clock discontinuity.

    Inputs:
        started: Aware UTC host time at the beginning of the local preparation interval.
        finished: Aware UTC host time at its current end.
        monotonic_start: Integer nanosecond counter captured at the beginning.
        monotonic_finish: Integer nanosecond counter captured at the current end.
    Outputs:
        int: Elapsed monotonic nanoseconds; ValueError rejects malformed counters, rollback,
            intervals of 300 seconds or more, or wall/monotonic disagreement over one second.
            No clock reads or IO. These are engineering consistency limits, not time attestation.
    """
    if type(monotonic_start) is not int or type(monotonic_finish) is not int:
        raise ValueError("Integer monotonic counters required")
    elapsed = monotonic_finish - monotonic_start
    wall_ns = int((finished - started).total_seconds() * 1_000_000_000)
    if not 0 <= elapsed < MAX_PREPARATION_NS or wall_ns < 0 or abs(wall_ns - elapsed) > CLOCK_TOLERANCE_NS:
        raise ValueError("Local preparation clocks or deadline inconsistent")
    return elapsed


def retain_preparation_manifest(root, manifest):
    """Synchronize one metadata-only preparation manifest outside the execution lock.

    Inputs:
        root: Existing canonical private binding directory, validated again before creation.
        manifest: Maintained JSON-compatible preparation metadata; contains hashes/clocks, no raw responses.
    Outputs:
        str: Canonical content hash after exclusive mode-600 file creation and file/directory fsync.
            Partial failures remain for review; no overwrite, plaintext evidence or AWS call occurs.
    """
    validate_run_id(manifest["run_id"])
    root = private_lock_root(root)
    path = root / (manifest["run_id"] + ".json")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(json.dumps(manifest, sort_keys=True, allow_nan=False).encode())
        stream.flush()
        os.fsync(stream.fileno())
    sync_archive_directory(root)
    return canonical_sha256(manifest)



def check_lock_binding(lock_root, root_descriptor, lock_descriptor, run_id, intent_retained=False):
    """Keep the same named root, lock directory and private owner marker throughout preparation.

    Inputs:
        lock_root: Canonical named root used when the descriptors were acquired.
        root_descriptor: Open original root descriptor, kept alive across callback/retention.
        lock_descriptor: Open original sandbox lock descriptor, kept alive across the same work.
        run_id: Expected retained owner identifier.
        intent_retained: Whether only owner plus recovery-intent, rather than owner alone, is allowed.
    Outputs:
        None: Reads bounded owner bytes and checks directory identities/inventory; raises on
            replacement, changed ownership or partial layout. Performs no deletion or AWS IO.
    """
    for current, original in ((os.stat(lock_root, follow_symlinks=False), os.fstat(root_descriptor)),
            (os.stat(BUCKET + ".lock", dir_fd=root_descriptor, follow_symlinks=False), os.fstat(lock_descriptor))):
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700:
            raise ValueError("Preparation directories lost private ownership or permissions")
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError("Preparation lock or root was replaced")
    expected = json.dumps({"version": "sandbox-local-lock-v0.1", "bucket": BUCKET, "run_id": run_id}, sort_keys=True).encode()
    if private_bytes(lock_descriptor, "owner.json", 4096) != expected:
        raise ValueError("Preparation lock owner changed")
    names = {"owner.json", "recovery-intent"} if intent_retained else {"owner.json"}
    if set(os.listdir(lock_descriptor)) != names:
        raise ValueError("Preparation lock inventory changed")


def prepare_recovery_from_observer(lock_root, binding_root, scope, approved_scope_sha256,
                                   human_review_sha256, capture_callback, decrypt_record,
                                   clock=utc_now, monotonic_ns=time.monotonic_ns):
    """Acquire the local lock, obtain a new observation and retain its bound encrypted intent.

    Inputs:
        lock_root: Existing canonical private directory shared by cooperating sandbox runners.
        binding_root: Existing canonical private directory for exclusive metadata-only manifests.
        scope: Current explicitly reviewed observer scope with a new run ID and absent output path.
        approved_scope_sha256: Independently retained hash of that approved observer scope.
        human_review_sha256: Independent original human review-manifest hash, not proof of approval.
        capture_callback: Trusted separately authorized callable receiving scope and approved hash;
            must run one new observer pass and return the maintained operator success summary.
            There is no built-in live adapter; offline tests use SDK stubs only.
        decrypt_record: Existing trusted authenticated callback returning evidence bytes in memory.
        clock: Injectable UTC string clock used around acquisition, verification and retention.
        monotonic_ns: Injectable integer monotonic nanosecond clock for local duration consistency.
    Outputs:
        dict: Minimal preparation/commitment pins with all execution/scientific gates closed.
            Creates one persistent local lock, calls the observer once, reads its bounded encrypted
            archives, writes a private metadata manifest and retains the existing encrypted intent.
            Has no AWS mutation adapter, emits no planner event and never releases a lock or retries. The supplied
            observer callback can perform reads only after its separate reviewed authorization.
            Any post-acquisition failure leaves the lock and partial artifacts held for review.
            Limits are cooperative checks, not a hard callback/fsync process deadline or proof of
            independent source freshness/concurrency. No raw response or private pre-state escapes.
    """
    require_sha256(human_review_sha256)
    scope = copy.deepcopy(scope)
    validate_sandbox_scope(scope, approved_scope_sha256)
    lock_root, binding_root = private_lock_root(lock_root), private_lock_root(binding_root)
    run_id = scope["run_id"]
    lock_path = lock_root / (BUCKET + ".lock")
    output = Path(scope["output_root"])
    if output.exists() or output.is_relative_to(lock_path) or binding_root.is_relative_to(lock_path):
        raise ValueError("New capture output outside the lock required")
    binding_path = binding_root / (run_id + ".json")
    if binding_path.exists() or binding_path.is_symlink() or not callable(capture_callback) or not callable(decrypt_record):
        raise ValueError("Unused binding path and trusted callbacks required")
    # Reserve ownership before any callback can observe AWS. No exception path removes this lock.
    with ExitStack() as descriptors:
        root_descriptor = private_directory(lock_root)
        descriptors.callback(os.close, root_descriptor)
        acquire_sandbox_lock(lock_root, run_id)
        lock_descriptor = private_directory(BUCKET + ".lock", root_descriptor)
        descriptors.callback(os.close, lock_descriptor)
        inspect_sandbox_lock(lock_root, run_id)
        check_lock_binding(lock_root, root_descriptor, lock_descriptor, run_id)
        started = utc_clock(clock())
        start_ns = monotonic_ns()
        result = copy.deepcopy(capture_callback(copy.deepcopy(scope), approved_scope_sha256))
        returned_ns, returned = monotonic_ns(), utc_clock(clock())
        check_local_interval(started, returned, start_ns, returned_ns)
        if not isinstance(result, dict):
            raise ValueError("Exact observer success summary required")
        fingerprint = result.get("ciphertext_fingerprint")
        require_sha256(fingerprint)
        expected = {"phase": "development", "run_id": run_id, "worker_status": "success",
                    "scope_sha256": approved_scope_sha256, "capture_completion_independently_verified": False,
                    "ciphertext_fingerprint": fingerprint, "live_execution_allowed": False, "research_trials": 0}
        if canonical_sha256(result) != canonical_sha256(expected):
            raise ValueError("Observer result differs from the approved new pass")
        check_lock_binding(lock_root, root_descriptor, lock_descriptor, run_id)
        read = read_verified_sandbox_prestate(output, scope, approved_scope_sha256, fingerprint, decrypt_record)
        verified_ns, verified = monotonic_ns(), utc_clock(clock())
        elapsed = check_local_interval(started, verified, start_ns, verified_ns)
        check_local_interval(returned, verified, returned_ns, verified_ns)
        # Require every receipt to fit this callback interval; old archives cannot be admitted by age alone.
        for receipt in [read["identity_receipt"]] + read["prestate"]["receipts"]:
            if utc_clock(receipt["started_at"]) < started or utc_clock(receipt["finished_at"]) > returned:
                raise ValueError("Receipt lies outside this locked acquisition interval")
        check_lock_binding(lock_root, root_descriptor, lock_descriptor, run_id)
        manifest = {"version": VERSION, "phase": "development", "run_id": run_id,
                    "human_review_sha256": human_review_sha256, "observer_scope_sha256": approved_scope_sha256,
                    "ciphertext_fingerprint": fingerprint, "source_sha256": scope["capture"]["source_sha256"],
                    "recipient_sha256": scope["capture"]["recipient_sha256"],
                    "capture_started_at": started.isoformat(), "capture_returned_at": returned.isoformat(),
                    "verified_at": verified.isoformat(), "local_elapsed_ns": elapsed,
                    "local_lock_identity": {"root_device": os.fstat(root_descriptor).st_dev,
                        "root_inode": os.fstat(root_descriptor).st_ino,
                        "lock_device": os.fstat(lock_descriptor).st_dev, "lock_inode": os.fstat(lock_descriptor).st_ino},
                    "verification_report_sha256": canonical_sha256(read["report"]),
                    "private_prestate_sha256": canonical_sha256(read["prestate"]),
                    "local_receipt_window_consistent": True, "source_freshness_verified": False,
                    "concurrent_writes_excluded": False, "live_execution_allowed": False, "research_trials": 0}
        manifest_sha256 = retain_preparation_manifest(binding_root, manifest)
        # The effective manifest links the original review, capture and clocks without changing intent schema.
        commitment = retain_recovery_intent(lock_root, run_id, read["prestate"]["metadata"],
            read["prestate"]["listings"], manifest_sha256, scope["capture"]["source_sha256"],
            scope["capture"]["recipient_sha256"], scope["certificate"], scope["openssl"], 5)
        finished_ns, finished = monotonic_ns(), utc_clock(clock())
        check_local_interval(started, finished, start_ns, finished_ns)
        check_local_interval(verified, finished, verified_ns, finished_ns)
        check_lock_binding(lock_root, root_descriptor, lock_descriptor, run_id, intent_retained=True)
        return {"version": VERSION, "phase": "development", "run_id": run_id,
                "preparation_manifest_sha256": manifest_sha256, "human_review_sha256": human_review_sha256,
                "observer_scope_sha256": approved_scope_sha256, "ciphertext_fingerprint": fingerprint,
                "intent_commitment_sha256": canonical_sha256(commitment), "intent_sha256": commitment["intent_sha256"],
                "local_receipt_window_consistent": True, "lock_held": True, "intent_retained": True,
                "source_freshness_verified": False, "concurrent_writes_excluded": False,
                "recovery_credentials_verified": False, "live_execution_allowed": False, "research_trials": 0}
