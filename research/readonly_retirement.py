"""Reviewed local retirement of a completed read-only preparation; never certifies cloud restoration."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path

from research.archive_ingestion import private_bytes
from research.catalog import canonical_sha256
from research.preparation_operator import preview_preparation_scope, read_preparation_result
from research.recovery_review import private_directory, strict_object
from research.sandbox_readiness import BUCKET
from research.scenario_lock import RETIREMENT_GUARD, private_lock_root
from research.timing import require_sha256

ROOT = Path(__file__).resolve().parents[1]
VERSION = "readonly-preparation-retirement-v0.1"
KEYS = {"version", "phase", "kind", "preparation", "preparation_scope_sha256",
        "preparation_result_sha256", "lock_inventory_sha256", "archive_root", "source_sha256"}


def retirement_source_sha256():
    """Fingerprint maintained retirement dependencies and its fixed CLI entry point.

    Inputs:
        No arguments; reads regular research Python sources and the retirement CLI only.
    Outputs:
        str: Canonical content fingerprint, no private artifact, credential or AWS access.
    """
    files = list((ROOT / "research").glob("*.py")) + [ROOT / name for name in (
        "scripts/retire_readonly_preparation.py", "scripts/review_recovery.py")]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Regular maintained retirement source required")
    return canonical_sha256({str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in sorted(files)})


def preview_retirement(scope):
    """Check declared read-only retirement boundaries without opening evidence or changing locks.

    Inputs:
        scope: Exact historical preparation, independent pins and proposed private archive root.
    Outputs:
        dict: Minimal scope fingerprint and closed research/restoration gates; no IO or consent.
    """
    if not isinstance(scope, dict) or set(scope) != KEYS or scope["version"] != VERSION or scope["phase"] != "development" or scope["kind"] != "retire_completed_readonly_preparation":
        raise ValueError("Exact read-only development retirement scope required")
    prep = preview_preparation_scope(scope["preparation"])
    for name in ("preparation_scope_sha256", "preparation_result_sha256", "lock_inventory_sha256", "source_sha256"):
        require_sha256(scope[name])
    if prep["scope_sha256"] != scope["preparation_scope_sha256"]:
        raise ValueError("Historical preparation differs from independently retained scope")
    value = scope["archive_root"]
    if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
        raise ValueError("Absolute non-traversing archive root required")
    archive = Path(value)
    preparation = scope["preparation"]
    for path in [Path(preparation[name]) for name in ("lock_root", "binding_root", "operator_root")] + [Path(preparation["observer"]["output_root"])]:
        if archive.is_relative_to(path) or path.is_relative_to(archive):
            raise ValueError("Disjoint archive root required")
    if len(json.dumps(scope).encode()) > 65536:
        raise ValueError("Bounded retirement descriptor required")
    return {"version": VERSION, "mode": "preview", "run_id": prep["run_id"],
            "scope_sha256": canonical_sha256(scope), "aws_called": False, "lock_changed": False,
            "restoration_verified": False, "live_execution_allowed": False, "research_trials": 0}


def read_private_json(root, name):
    """Read one bounded private metadata object with duplicate/nonfinite field rejection.

    Inputs:
        root: Existing private canonical metadata directory.
        name: Fixed single-child filename chosen by maintained code.
    Outputs:
        dict: Parsed metadata after at most 64 KiB; no raw encrypted evidence is decrypted.
    """
    descriptor = private_directory(root)
    try:
        return strict_object(private_bytes(descriptor, name, 65536))
    finally:
        os.close(descriptor)


def readonly_lock_inventory(lock_descriptor, preparation, result):
    """Bind the exact owner/intent-only lock to an independently retained completed preparation.

    Inputs:
        lock_descriptor: Anchored private lock descriptor held through inspection or retirement.
        preparation: Historical reviewed preparation; current producer-source matching is unnecessary.
        result: Exact verified metadata-only preparation result with independent content pin.
    Outputs:
        str: Canonical fingerprint of every retained lock file; reads at most 4 MiB, no decryption.
            Any closure, extra file, wrong owner, altered commitment/ciphertext/recipient fails.
    """
    if set(os.listdir(lock_descriptor)) != {"owner.json", "recovery-intent"}:
        raise ValueError("Only a completed read-only intent lock may be retired")
    owner = private_bytes(lock_descriptor, "owner.json", 4096)
    expected = {"version": "sandbox-local-lock-v0.1", "bucket": BUCKET, "run_id": result["run_id"]}
    if canonical_sha256(strict_object(owner)) != canonical_sha256(expected):
        raise ValueError("Retirement owner differs from reviewed run")
    descriptor = private_directory("recovery-intent", lock_descriptor)
    try:
        names = {"recipient-public.pem", "record-00000.cms", "commitment.json"}
        if set(os.listdir(descriptor)) != names:
            raise ValueError("Complete exclusive intent archive required")
        contents = {}
        remaining = 4 * 1024 * 1024 - len(owner)
        for name in sorted(names):
            contents[name] = private_bytes(descriptor, name, remaining)
            remaining -= len(contents[name])
        commitment = strict_object(contents["commitment.json"])
        if canonical_sha256(commitment) != result["intent_commitment_sha256"] or commitment["intent_sha256"] != result["intent_sha256"]:
            raise ValueError("Intent differs from the independently retained preparation result")
        recipient = preparation["observer"]["capture"]["recipient_sha256"]
        if hashlib.sha256(contents["recipient-public.pem"]).hexdigest() != recipient:
            raise ValueError("Retained intent recipient changed")
        receipt = {"file": "record-00000.cms", "ciphertext_sha256": hashlib.sha256(contents["record-00000.cms"]).hexdigest()}
        if commitment["ciphertext"] != receipt:
            raise ValueError("Retained intent ciphertext changed")
        files = {"owner.json": hashlib.sha256(owner).hexdigest()}
        files.update({"recovery-intent/" + name: hashlib.sha256(data).hexdigest() for name, data in contents.items()})
        return canonical_sha256(files)
    finally:
        os.close(descriptor)


def completed_preparation(preparation, scope_pin, result_pin):
    """Check historical successful preparation metadata without replaying its consumed capture.

    Inputs:
        preparation: Historical exact preparation scope with retained local metadata paths.
        scope_pin: Independently retained historical preparation scope fingerprint.
        result_pin: Independently retained successful result content fingerprint.
    Outputs:
        tuple: Minimal result and manifest after scope/status/result/manifest linkage validation.
            No current-runtime/source requirement, SDK, decryption, output creation or cloud claim.
    """
    if preview_preparation_scope(preparation)["scope_sha256"] != scope_pin:
        raise ValueError("Historical preparation changed")
    root = private_lock_root(preparation["operator_root"])
    if read_preparation_result(root, preparation, scope_pin) != result_pin:
        raise ValueError("Historical result differs from independent pin")
    result = read_private_json(root, "result.json")
    expected_status = {"version": "preparation-operator-v0.1", "phase": "development", "run_id": result["run_id"],
        "scope_sha256": scope_pin, "worker_status": "success", "worker_report_verified": False,
        "live_execution_allowed": False, "research_trials": 0, "result_sha256": result_pin}
    if canonical_sha256(read_private_json(root, "status.json")) != canonical_sha256(expected_status):
        raise ValueError("Completed read-only supervisor status required")
    if canonical_sha256(read_private_json(root, "scope.json")) != scope_pin:
        raise ValueError("Retained historical scope changed")
    manifest = read_private_json(private_lock_root(preparation["binding_root"]), result["run_id"] + ".json")
    if canonical_sha256(manifest) != result["preparation_manifest_sha256"] or manifest["human_review_sha256"] != preparation["human_review_sha256"]:
        raise ValueError("Preparation binding manifest changed")
    return result, manifest


def require_directory_identity(path, descriptor):
    """Ensure a private named directory still refers to its held descriptor.

    Inputs:
        path: Canonical directory path expected to remain named throughout retirement.
        descriptor: Open original directory descriptor.
    Outputs:
        None: Rejects replacement, symlinks or changed private ownership/permissions; no mutation.
    """
    private_lock_root(path)
    current, original = os.stat(path, follow_symlinks=False), os.fstat(descriptor)
    if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
        raise ValueError("Retirement directory identity changed")


def write_retirement_record(descriptor, name, record):
    """Synchronize one exclusive private metadata record through an anchored directory.

    Inputs:
        descriptor: Held private directory descriptor owned by the retirement operation.
        name: Fixed maintained filename, never caller-selected path text.
        record: Maintained metadata-only scope or archival commitment.
    Outputs:
        None: Creates mode-600 file, fsyncs file/directory; partial work remains on failure.
    """
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
    with os.fdopen(output, "wb") as stream:
        stream.write(json.dumps(record, sort_keys=True, allow_nan=False).encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(descriptor)


def retire_readonly_preparation(scope, approved_scope_sha256):
    """Archive a completed read-only lock intact under separate explicit retirement approval.

    Inputs:
        scope: Exact separately reviewed retirement scope with historical result and lock pins.
        approved_scope_sha256: Independently retained approved retirement fingerprint; not consent proof.
    Outputs:
        dict: Minimal successful retirement summary, with no restoration/research authority.
            Reserves a persistent acquisition guard, renames the entire lock into a new same-device
            private archive, verifies/syncs preservation, then removes only its own guard last.
            No AWS, Keychain, retry, recursive deletion or live evidence overwrite. Partial work
            is never rolled back automatically. Exceptions require inspecting guard/archive state;
            failure after final guard removal can mean committed retirement with uncertain fsync.
    """
    if os.name != "posix":
        raise ValueError("POSIX evidence retirement required")
    require_sha256(approved_scope_sha256)
    if preview_retirement(scope)["scope_sha256"] != approved_scope_sha256 or retirement_source_sha256() != scope["source_sha256"]:
        raise ValueError("Retirement scope or maintained source differs from approval")
    preparation = scope["preparation"]
    result, manifest = completed_preparation(preparation, scope["preparation_scope_sha256"], scope["preparation_result_sha256"])
    lock_root, archive_root = private_lock_root(preparation["lock_root"]), private_lock_root(scope["archive_root"])
    run_id = result["run_id"]
    with ExitStack() as descriptors:
        root = private_directory(lock_root)
        descriptors.callback(os.close, root)
        archive = private_directory(archive_root)
        descriptors.callback(os.close, archive)
        lock = private_directory(BUCKET + ".lock", root)
        descriptors.callback(os.close, lock)
        original = manifest["local_lock_identity"]
        if {"root_device": os.fstat(root).st_dev, "root_inode": os.fstat(root).st_ino,
                "lock_device": os.fstat(lock).st_dev, "lock_inode": os.fstat(lock).st_ino} != original:
            raise ValueError("Original preparation lock identity required")
        if os.fstat(root).st_dev != os.fstat(archive).st_dev:
            raise ValueError("Atomic same-device archival required")
        if readonly_lock_inventory(lock, preparation, result) != scope["lock_inventory_sha256"]:
            raise ValueError("Retained lock differs from independent review pin")
        target = archive_root / run_id
        if target.exists() or target.is_symlink():
            raise ValueError("Unused retirement destination required")
        # This guard keeps cooperating acquisitions blocked even after the fixed lock name moves.
        os.mkdir(RETIREMENT_GUARD, mode=0o700, dir_fd=root)
        guard = private_directory(RETIREMENT_GUARD, root)
        descriptors.callback(os.close, guard)
        guard_record = {"version": VERSION, "run_id": run_id, "scope_sha256": approved_scope_sha256,
                        "lock_inventory_sha256": scope["lock_inventory_sha256"]}
        write_retirement_record(guard, "scope.json", guard_record)
        os.fsync(root)
        os.mkdir(run_id, mode=0o700, dir_fd=archive)
        retired = private_directory(run_id, archive)
        descriptors.callback(os.close, retired)
        write_retirement_record(retired, "scope.json", scope)
        os.fsync(archive)
        for path, descriptor in ((lock_root, root), (archive_root, archive), (target, retired),
                                  (lock_root / (BUCKET + ".lock"), lock)):
            require_directory_identity(path, descriptor)
        if readonly_lock_inventory(lock, preparation, result) != scope["lock_inventory_sha256"]:
            raise ValueError("Retained lock changed before archival")
        # The destination parent is exclusively reserved; no existing evidence is overwritten.
        os.rename(BUCKET + ".lock", BUCKET + ".lock", src_dir_fd=root, dst_dir_fd=retired)
        os.fsync(retired)
        os.fsync(root)
        require_directory_identity(target / (BUCKET + ".lock"), lock)
        if readonly_lock_inventory(lock, preparation, result) != scope["lock_inventory_sha256"]:
            raise ValueError("Archived lock differs from reviewed bytes")
        receipt = {"version": VERSION, "phase": "development", "run_id": run_id,
            "scope_sha256": approved_scope_sha256, "lock_inventory_sha256": scope["lock_inventory_sha256"],
            "archive_committed": True, "restoration_verified": False, "source_freshness_verified": False,
            "live_execution_allowed": False, "research_trials": 0}
        write_retirement_record(retired, "retirement.json", receipt)
        os.fsync(archive)
        for path, descriptor in ((lock_root, root), (archive_root, archive), (target, retired),
                                  (target / (BUCKET + ".lock"), lock), (lock_root / RETIREMENT_GUARD, guard)):
            require_directory_identity(path, descriptor)
        if (lock_root / (BUCKET + ".lock")).exists() or (lock_root / (BUCKET + ".lock")).is_symlink():
            raise ValueError("Unexpected new lock requires manual retirement review")
        if set(os.listdir(guard)) != {"scope.json"} or set(os.listdir(retired)) != {"scope.json", BUCKET + ".lock", "retirement.json"}:
            raise ValueError("Retirement inventory changed")
        for descriptor, name, expected in ((guard, "scope.json", guard_record),
                (retired, "scope.json", scope), (retired, "retirement.json", receipt)):
            if canonical_sha256(strict_object(private_bytes(descriptor, name, 65536))) != canonical_sha256(expected):
                raise ValueError("Retirement metadata changed before guard removal")
        if readonly_lock_inventory(lock, preparation, result) != scope["lock_inventory_sha256"]:
            raise ValueError("Archived evidence changed before guard removal")
        completed_preparation(preparation, scope["preparation_scope_sha256"], scope["preparation_result_sha256"])
        # All original recovery bytes and archival commitment are durable before reuse is possible.
        os.unlink("scope.json", dir_fd=guard)
        os.rmdir(RETIREMENT_GUARD, dir_fd=root)
        os.fsync(root)
        return dict(receipt, lock_retired=True, cooperative_acquisition_unblocked=True)
