"""Reviewed local recovery verification using the existing Keychain callback; no AWS or unlock path."""
import hashlib
from pathlib import Path

from research.catalog import canonical_sha256
from research.keychain_decryption import MacKeychainDecryptor
from research.recovery_review import MAX_BYTES, read_recovery_intent
from research.scenario_lock import validate_run_id
from research.timing import require_sha256

VERSION = "recovery-operator-v0.1"
REPOSITORY = Path(__file__).resolve().parents[1]
SCOPE_KEYS = {"version", "phase", "run_id", "lock_root", "review_manifest_sha256", "source_sha256",
              "recipient_sha256", "commitment_sha256", "helper", "helper_sha256", "recipient", "scratch",
              "operator_source_sha256", "max_bytes"}


def operator_source_sha256():
    """Fingerprint maintained recovery Python, helper source and pinned requirement declarations.

    Inputs:
        None: Reads maintained regular source files under this repository; never recipient files.
    Outputs:
        str: Canonical hash of relative paths and file-content hashes. Rejects source symlinks;
            performs no Keychain/cloud call and creates nothing. Not runtime authentication.
    """
    files = list((REPOSITORY / "research").glob("*.py")) + [REPOSITORY / name for name in (
        "scripts/review_recovery.py", "scripts/macos_decrypt_record.swift", "requirements-aws.txt", "requirements-ml.txt")]
    if any(file.is_symlink() or not file.is_file() for file in files):
        raise ValueError("Maintained operator source must be regular files")
    return canonical_sha256({str(file.relative_to(REPOSITORY)): hashlib.sha256(file.read_bytes()).hexdigest()
                             for file in sorted(files)})


def preview_recovery_scope(scope):
    """Validate a development-only local verification scope without opening sensitive paths.

    Inputs:
        scope: Exact local scope containing run, path, provenance and byte-budget declarations.
    Outputs:
        dict: Scope identity and closed execution/restoration gates. Does not read helper,
            recipient, lock or scratch files, construct a Keychain callback or create output.
            Hash validity and canonical-looking paths do not prove review or availability.
    """
    if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS or scope["version"] != VERSION or scope["phase"] != "development":
        raise ValueError("Exact development recovery-operator scope required")
    validate_run_id(scope["run_id"])
    for name in ("review_manifest_sha256", "source_sha256", "recipient_sha256", "commitment_sha256",
                 "helper_sha256", "operator_source_sha256"):
        require_sha256(scope[name])
    if type(scope["max_bytes"]) is not int or not 1 <= scope["max_bytes"] <= MAX_BYTES:
        raise ValueError("Bounded recovery byte budget required")
    for name in ("lock_root", "helper", "recipient", "scratch"):
        value = scope[name]
        if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
            raise ValueError("Absolute non-traversing local scope paths required")
    return {"version": VERSION, "scope_sha256": canonical_sha256(scope), "run_id": scope["run_id"],
            "mode": "preview", "keychain_invoked": False, "live_execution_allowed": False,
            "restoration_verified": False, "research_trials": 0}


def verify_with_keychain(scope, approved_scope_sha256):
    """Verify one already-retained intent through the existing pinned local Keychain bridge.

    Inputs:
        scope: Exact independently reviewed local verification scope; no cloud/write operations.
        approved_scope_sha256: Independently trusted hash of the reviewed scope. Matching a
            supplied hash is not evidence of human consent; the operator must hold approval.
    Outputs:
        dict: Minimal local-consistency summary with no raw record/private paths. Calls the
            existing Keychain helper once through a captured authenticated boundary, using
            temporary ciphertext scratch only. Never changes the lock or AWS. Errors propagate;
            no retries, replacement capture, permission widening or success report on failure.
    """
    preview = preview_recovery_scope(scope)
    require_sha256(approved_scope_sha256)
    if preview["scope_sha256"] != approved_scope_sha256:
        raise ValueError("Recovery scope differs from the independent approved pin")
    if operator_source_sha256() != scope["operator_source_sha256"]:
        raise ValueError("Recovery operator source differs from the reviewed pin")
    # Construction validates the helper and public recipient; actual key access occurs only on read.
    decryptor = MacKeychainDecryptor(scope["helper"], scope["helper_sha256"], scope["recipient"],
                                     scope["recipient_sha256"], scope["scratch"])
    result = read_recovery_intent(scope["lock_root"], scope["run_id"], decryptor,
        scope["review_manifest_sha256"], scope["source_sha256"], scope["recipient_sha256"],
        scope["commitment_sha256"], scope["max_bytes"])
    return {"version": VERSION, "scope_sha256": preview["scope_sha256"], "run_id": scope["run_id"],
            "mode": "local_verification", "local_intent_consistency": True,
            "intent_sha256": result["intent_sha256"], "commitment_sha256": result["commitment_sha256"],
            "live_execution_allowed": False, "restoration_verified": False, "research_trials": 0}
