"""Preview-first supervised observer-to-intent preparation; no mutation or lock-release path."""
import copy
from functools import partial
import hashlib
import json
import os
from pathlib import Path

from research.archive_ingestion import private_bytes
from research.aws_reader import sync_archive_directory
from research.catalog import canonical_sha256
from research.keychain_decryption import MacKeychainDecryptor, require_private_path
from research.native_capture import bounded_worker
from research.observer_recovery_preparation import VERSION as INTENT_PREPARATION_VERSION, prepare_recovery_from_observer
from research.recovery_review import private_directory, read_recovery_intent, strict_object
from research.sandbox_operator import preview_sandbox_scope, validate_sandbox_scope, run_sandbox_operator
from research.sandbox_readiness import BUCKET
from research.scenario_lock import private_lock_root
from research.timing import require_sha256

ROOT = Path(__file__).resolve().parents[1]
VERSION = "preparation-operator-v0.1"
KEYS = {"version", "phase", "observer", "observer_scope_sha256", "human_review_sha256",
        "lock_root", "binding_root", "operator_root", "bridge", "source_sha256", "worker_timeout_seconds"}
BRIDGE_KEYS = {"helper", "helper_sha256", "recipient", "scratch", "recipient_metadata_sha256",
               "encrypted_private_key_sha256", "helper_source_sha256"}


def preparation_source_sha256():
    """Bind maintained preparation code and its fixed worker/CLI/helper entry points.

    Inputs:
        No arguments; reads regular maintained source files only.
    Outputs:
        str: Canonical source fingerprint; no AWS, Keychain or private evidence access.
    """
    files = list((ROOT / "research").glob("*.py")) + [ROOT / name for name in (
        "requirements-aws.txt", "scripts/prepare_sandbox.py", "scripts/sandbox_preparation_worker.py",
        "scripts/sandbox_capture_worker.py", "scripts/macos_decrypt_record.swift")]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Regular maintained preparation source required")
    return canonical_sha256({str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in sorted(files)})


def preview_preparation_scope(scope):
    """Check the declared preparation boundaries without opening paths or invoking a helper.

    Inputs:
        scope: Exact development scope containing the observer, local paths and independent pins.
    Outputs:
        dict: Minimal review fingerprint with closed execution gates; no IO or approval granted.
    """
    if not isinstance(scope, dict) or set(scope) != KEYS or scope["version"] != VERSION or scope["phase"] != "development":
        raise ValueError("Exact development preparation scope required")
    observer = preview_sandbox_scope(scope["observer"])
    if scope["observer_scope_sha256"] != observer["scope_sha256"]:
        raise ValueError("Observer scope pin mismatch")
    for name in ("human_review_sha256", "source_sha256"):
        require_sha256(scope[name])
    if type(scope["worker_timeout_seconds"]) is not int or scope["worker_timeout_seconds"] != 330:
        raise ValueError("Fixed outer preparation timeout required")
    bridge = scope["bridge"]
    if not isinstance(bridge, dict) or set(bridge) != BRIDGE_KEYS:
        raise ValueError("Exact independently pinned local bridge required")
    for name in BRIDGE_KEYS - {"helper", "recipient", "scratch"}:
        require_sha256(bridge[name])
    paths = [scope[name] for name in ("lock_root", "binding_root", "operator_root")]
    paths += [bridge[name] for name in ("helper", "recipient", "scratch")]
    if any(not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts for value in paths):
        raise ValueError("Absolute non-traversing preparation paths required")
    if str(Path(bridge["recipient"]) / "recipient-public.pem") != scope["observer"]["certificate"]:
        raise ValueError("Observer and bridge must use the same recipient")
    # Separate output, exclusion, bindings and scratch so partial work cannot replace dependencies.
    writes = [Path(scope[name]) for name in ("lock_root", "binding_root", "operator_root")]
    writes += [Path(scope["observer"]["output_root"]), Path(bridge["scratch"])]
    for index, path in enumerate(writes):
        for other in writes[index + 1:]:
            if path.is_relative_to(other) or other.is_relative_to(path):
                raise ValueError("Disjoint preparation write directories required")
        if any(Path(bridge[name]).is_relative_to(path) for name in ("helper", "recipient")):
            raise ValueError("Bridge dependencies must be outside preparation write directories")
    if len(json.dumps({"scope": scope, "approved_scope_sha256": "0" * 64}).encode()) > 65536:
        raise ValueError("Bounded preparation descriptor required")
    return {"version": VERSION, "mode": "preview", "phase": "development", "run_id": observer["run_id"],
            "scope_sha256": canonical_sha256(scope), "aws_called": False, "keychain_invoked": False,
            "live_execution_allowed": False, "research_trials": 0}


def pinned_private_file(path, expected_sha256):
    """Check a bounded owner-only file against a separately retained content fingerprint.

    Inputs:
        path: Existing canonical private regular file, never a plaintext private key.
        expected_sha256: Independently retained expected fingerprint.
    Outputs:
        None: Reads at most 64 KiB; rejects links, unsafe metadata and changed bytes without logging.
    """
    path = Path(path)
    if path.resolve() != path:
        raise ValueError("Canonical private dependency required")
    descriptor = private_directory(path.parent)
    try:
        raw = private_bytes(descriptor, path.name, 65536)
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Private dependency pin changed")


def validate_preparation_scope(scope, approved_scope_sha256, *, reserved=False):
    """Recompute source/runtime/bridge pins and require unused outputs before any execution.

    Inputs:
        scope: Exact previously reviewed preparation scope.
        approved_scope_sha256: Independently retained hash; matching is not proof of human consent.
        reserved: Internal worker mode requiring exactly the parent-retained scope in its directory.
    Outputs:
        None: Local bounded metadata/source reads only; no Keychain, AWS or output creation.
            Rejects changed dependencies, existing locks and consumed/partial outputs.
    """
    if os.name != "posix":
        raise ValueError("POSIX preparation supervision required")
    require_sha256(approved_scope_sha256)
    if preview_preparation_scope(scope)["scope_sha256"] != approved_scope_sha256:
        raise ValueError("Preparation scope differs from review")
    if preparation_source_sha256() != scope["source_sha256"]:
        raise ValueError("Preparation source changed")
    validate_sandbox_scope(scope["observer"], scope["observer_scope_sha256"])
    for name in ("lock_root", "binding_root"):
        private_lock_root(scope[name])
    operator = Path(scope["operator_root"])
    private_lock_root(operator.parent)
    if operator.resolve() != operator:
        raise ValueError("Canonical operator output required")
    absent = [Path(scope["observer"]["output_root"]),
              Path(scope["lock_root"]) / (BUCKET + ".lock"),
              Path(scope["binding_root"]) / (scope["observer"]["run_id"] + ".json")]
    if type(reserved) is not bool:
        raise ValueError("Explicit reservation mode required")
    if reserved:
        private_lock_root(operator)
        descriptor = private_directory(operator)
        try:
            if set(os.listdir(descriptor)) != {"scope.json"} or strict_object(private_bytes(descriptor, "scope.json", 65536)) != scope:
                raise ValueError("Exact parent scope reservation required")
        finally:
            os.close(descriptor)
    else:
        absent.append(operator)
    if any(path.exists() or path.is_symlink() for path in absent):
        raise ValueError("Preparation requires unused outputs and an unheld lock")
    bridge = scope["bridge"]
    for name in ("recipient", "scratch"):
        private_lock_root(bridge[name])
    helper = require_private_path(bridge["helper"])
    if helper.resolve() != helper or not os.access(helper, os.X_OK):
        raise ValueError("Canonical private executable helper required")
    # Only encrypted key bytes are hashed; no private key is decrypted or exported here.
    if hashlib.sha256(helper.read_bytes()).hexdigest() != bridge["helper_sha256"]:
        raise ValueError("Compiled bridge changed")
    for name, pin in (("recipient-metadata.json", "recipient_metadata_sha256"),
                      ("private-key.encrypted.pem", "encrypted_private_key_sha256")):
        pinned_private_file(Path(bridge["recipient"]) / name, bridge[pin])
    pinned_private_file(scope["observer"]["certificate"], scope["observer"]["capture"]["recipient_sha256"])
    if hashlib.sha256((ROOT / "scripts/macos_decrypt_record.swift").read_bytes()).hexdigest() != bridge["helper_source_sha256"]:
        raise ValueError("Reviewed helper source changed")


def write_preparation_json(path, record):
    """Retain one exclusive private metadata-only preparation record and synchronize it.

    Inputs:
        path: New filename in an existing canonical private operator directory.
        record: Maintained minimal scope/result/status metadata; never raw decrypted evidence.
    Outputs:
        None: Creates a mode-600 file and fsyncs file/directory; partial failure remains retained.
    """
    path = Path(path)
    private_lock_root(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(json.dumps(record, sort_keys=True, allow_nan=False).encode())
        stream.flush()
        os.fsync(stream.fileno())
    sync_archive_directory(path.parent)


def run_preparation_worker(scope, approved_scope_sha256):
    """Compose observation, archive verification and readable encrypted intent under one lock.

    Inputs:
        scope: Exact approved development preparation scope, validated before output reservation.
        approved_scope_sha256: Independent preparation scope hash retained by the operator.
    Outputs:
        None: In an isolated outer worker only, runs one observer pass and the trusted local
            decryptor; retains intent and a minimal result. Never mutates AWS, retries or unlocks.
            Verifies the newly written intent through the existing bounded reader before success.
    """
    if os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid():
        raise ValueError("Isolated preparation session required")
    # Revalidate the exact parent reservation before constructing the trusted decryptor.
    validate_preparation_scope(scope, approved_scope_sha256, reserved=True)
    bridge = scope["bridge"]
    decrypt = MacKeychainDecryptor(bridge["helper"], bridge["helper_sha256"], bridge["recipient"],
                                  scope["observer"]["capture"]["recipient_sha256"], bridge["scratch"])
    capture = partial(run_sandbox_operator, inherit_supervisor_group=True)
    result = prepare_recovery_from_observer(scope["lock_root"], scope["binding_root"], scope["observer"],
        scope["observer_scope_sha256"], scope["human_review_sha256"], capture, decrypt)
    # Verify actual retained intent, not merely the writer's return status, before worker completion.
    retained = read_recovery_intent(scope["lock_root"], result["run_id"], decrypt,
        result["preparation_manifest_sha256"], scope["observer"]["capture"]["source_sha256"],
        scope["observer"]["capture"]["recipient_sha256"], result["intent_commitment_sha256"])
    if retained["intent_sha256"] != result["intent_sha256"]:
        raise ValueError("Retained intent differs from preparation result")
    result.update(preparation_scope_sha256=approved_scope_sha256, retained_intent_consistency_verified=True)
    write_preparation_json(Path(scope["operator_root"]) / "result.json", result)


def read_preparation_result(root, scope, approved_scope_sha256):
    """Check the worker's metadata-only result against this operation before reporting success.

    Inputs:
        root: Existing private operator directory containing the worker result.
        scope: Reviewed scope defining the run, observer and human review pins.
        approved_scope_sha256: Independent preparation scope fingerprint.
    Outputs:
        str: Result content hash after exact schema/pin/gate checks; no decrypted evidence or
            independent source authentication is claimed. Missing/partial/malformed result fails.
    """
    descriptor = private_directory(root)
    try:
        result = strict_object(private_bytes(descriptor, "result.json", 65536))
    finally:
        os.close(descriptor)
    pins = {"preparation_manifest_sha256", "ciphertext_fingerprint", "intent_commitment_sha256", "intent_sha256"}
    expected = {"version": INTENT_PREPARATION_VERSION, "phase": "development",
                "run_id": scope["observer"]["run_id"], "human_review_sha256": scope["human_review_sha256"],
                "observer_scope_sha256": scope["observer_scope_sha256"],
                "preparation_scope_sha256": approved_scope_sha256,
                "local_receipt_window_consistent": True, "lock_held": True, "intent_retained": True,
                "retained_intent_consistency_verified": True, "source_freshness_verified": False,
                "concurrent_writes_excluded": False, "recovery_credentials_verified": False,
                "live_execution_allowed": False, "research_trials": 0}
    if set(result) != set(expected) | pins:
        raise ValueError("Exact minimal worker result required")
    for name in pins:
        require_sha256(result[name])
        expected[name] = result[name]
    if canonical_sha256(result) != canonical_sha256(expected):
        raise ValueError("Worker result differs from approved preparation")
    return canonical_sha256(result)


def run_preparation_operator(scope, approved_scope_sha256):
    """Reserve and supervise one explicitly approved read-only preparation operation.

    Inputs:
        scope: Reviewed current development preparation scope, including observer and local pins.
        approved_scope_sha256: Independently retained approved scope hash; no implicit approval.
    Outputs:
        dict: Minimal supervisor status with no plaintext evidence; creates private scope/status
            metadata and runs one silent worker. Timeout/cancellation stops its shared group,
            preserving any lock and partial evidence. No automatic retry, release or AWS mutation.
    """
    scope = copy.deepcopy(scope)
    validate_preparation_scope(scope, approved_scope_sha256)
    root = Path(scope["operator_root"])
    root.mkdir(mode=0o700)
    sync_archive_directory(root.parent)
    write_preparation_json(root / "scope.json", scope)
    status = bounded_worker([scope["observer"]["python_executable"], "-I",
                             str(ROOT / "scripts/sandbox_preparation_worker.py")],
                            {"scope": scope, "approved_scope_sha256": approved_scope_sha256}, 330,
                            terminate_group_on_exit=True)
    summary = {"version": VERSION, "phase": "development", "run_id": scope["observer"]["run_id"],
               "scope_sha256": approved_scope_sha256, "worker_status": status,
               "worker_report_verified": False, "live_execution_allowed": False, "research_trials": 0}
    summary["result_sha256"] = read_preparation_result(root, scope, approved_scope_sha256) if status == "success" else None
    write_preparation_json(root / "status.json", summary)
    return summary
