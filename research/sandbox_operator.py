"""Preview-first supervised sandbox capture; explicit approval remains an external requirement."""
import hashlib
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys

from research.aws_reader import EncryptedArchive, sync_archive_directory
from research.catalog import canonical_sha256
from research.native_capture import bounded_worker, snapshot_fingerprint
from research.sandbox_capture import capture_scope, capture_source_sha256
from research.scenario_lock import private_lock_root, validate_run_id
from research.timing import require_sha256

VERSION = "sandbox-operator-v0.1"
PROFILE = "dissertation-sandbox-observer"
ROOT = Path(__file__).resolve().parents[1]
KEYS = {"version", "phase", "run_id", "profile", "certificate", "output_root", "openssl",
        "openssl_sha256", "python_executable", "python_sha256", "runtime_versions",
        "worker_timeout_seconds", "capture"}


def preview_sandbox_scope(scope):
    """Validate declared operator boundaries without opening paths or creating SDK sessions.

    Inputs:
        scope: Exact operator scope containing declared paths, runtime pins and capture manifest.
    Outputs:
        dict: Minimal preview summary and scope fingerprint; no IO or live authorization.
            Malformed or widened scope raises ValueError before any target is opened.
    """
    if not isinstance(scope, dict) or set(scope) != KEYS or scope["version"] != VERSION or scope["phase"] != "development" or scope["profile"] != PROFILE:
        raise ValueError("Exact development sandbox operator scope required")
    validate_run_id(scope["run_id"])
    if type(scope["worker_timeout_seconds"]) is not int or scope["worker_timeout_seconds"] != 150:
        raise ValueError("Fixed supervised worker timeout required")
    for name in ("certificate", "output_root", "openssl", "python_executable"):
        value = scope[name]
        if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
            raise ValueError("Absolute non-traversing operator paths required")
    for name in ("openssl_sha256", "python_sha256"):
        require_sha256(scope[name])
    versions = scope["runtime_versions"]
    if not isinstance(versions, dict) or set(versions) != {"boto3", "botocore", "awscrt"} or any(not isinstance(value, str) or not value for value in versions.values()):
        raise ValueError("Explicit AWS runtime version pins required")
    capture = scope["capture"]
    if not isinstance(capture, dict) or canonical_sha256(capture) != canonical_sha256(capture_scope(capture.get("source_sha256"), capture.get("recipient_sha256"))):
        raise ValueError("Fixed capture manifest required")
    return {"mode": "preview", "phase": "development", "run_id": scope["run_id"],
            "scope_sha256": canonical_sha256(scope), "aws_called": False,
            "live_execution_allowed": False, "research_trials": 0}


def build_sandbox_scope(certificate, output_root, openssl, run_id):
    """Bind local software and a public recipient without credential access or output creation.

    Inputs:
        certificate: Canonical absolute public recipient certificate path; at most 64 KiB.
        output_root: Canonical absolute future capture directory in an existing private parent.
        openssl: Canonical absolute OpenSSL executable path used for bounded normalization.
        run_id: Independently retained 32-character lowercase hexadecimal development identifier.
    Outputs:
        dict: Reviewable scope with source, runtime, recipient and path bindings. Reads local
            public/source files and runs certificate normalization; no SDK session or AWS IO.
            Does not attest to installed package contents, profile availability or human approval.
    """
    validate_run_id(run_id)
    certificate, output, binary = Path(certificate), Path(output_root), Path(openssl)
    for path in (certificate, output, binary):
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError("Canonical absolute scope paths required")
    private_lock_root(output.parent)
    if not certificate.is_file() or not binary.is_file():
        raise ValueError("Existing public certificate and executable required")
    with certificate.open("rb") as stream:
        public = stream.read(65537)
    if len(public) > 65536 or b"PRIVATE KEY" in public:
        raise ValueError("Bounded public certificate only")
    public = subprocess.run([str(binary), "x509", "-outform", "PEM"], input=public,
                            check=True, capture_output=True, timeout=5).stdout
    scope = {"version": VERSION, "phase": "development", "run_id": run_id, "profile": PROFILE,
             "certificate": str(certificate), "output_root": str(output), "openssl": str(binary),
             "openssl_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
             "python_executable": sys.executable, "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
             "runtime_versions": {name: importlib.metadata.version(name) for name in ("boto3", "botocore", "awscrt")},
             "worker_timeout_seconds": 150,
             "capture": capture_scope(capture_source_sha256(), hashlib.sha256(public).hexdigest())}
    preview_sandbox_scope(scope)
    return scope


def validate_sandbox_scope(scope, approved_scope_sha256):
    """Recompute local bindings before starting a worker or creating output.

    Inputs:
        scope: Exact reviewed operator scope.
        approved_scope_sha256: Independently retained hash of the explicitly approved scope.
    Outputs:
        None: Raises ValueError on changed source, runtime, recipient, paths or review hash.
            Reads local files only; hash matching does not itself establish human approval.
    """
    preview = preview_sandbox_scope(scope)
    require_sha256(approved_scope_sha256)
    if preview["scope_sha256"] != approved_scope_sha256:
        raise ValueError("Reviewed operator scope hash mismatch")
    expected = build_sandbox_scope(scope["certificate"], scope["output_root"], scope["openssl"], scope["run_id"])
    if canonical_sha256(expected) != approved_scope_sha256:
        raise ValueError("Local operator bindings changed")


def run_sandbox_operator(scope, approved_scope_sha256):
    """Reserve one private run and supervise its silent read-only worker after review.

    Inputs:
        scope: Exact operator scope already explicitly approved for live development collection.
        approved_scope_sha256: Independently retained scope hash; not a substitute for approval.
    Outputs:
        dict: Minimal worker status, closed scenario-execution gate and zero research trials.
            Creates an exclusive private run with encrypted operator journal and capture output.
            A worker timeout kills/reaps its process group through the existing supervisor;
            partial output is preserved. Local preparation/fsync and process reaping are not
            subject to an absolute end-to-end deadline. No automatic retry or lock release.
    """
    if os.name != "posix":
        raise ValueError("POSIX process supervision required")
    validate_sandbox_scope(scope, approved_scope_sha256)
    root = Path(scope["output_root"])
    root.mkdir(mode=0o700)
    sync_archive_directory(root.parent)
    journal = EncryptedArchive(root / "journal", scope["certificate"], scope["openssl"], timeout_seconds=5)
    journal.write({"kind": "sandbox_operator_scope", "scope": scope, "scope_sha256": approved_scope_sha256})
    descriptor = {"scope": scope, "approved_scope_sha256": approved_scope_sha256}
    status = bounded_worker([scope["python_executable"], "-I", str(ROOT / "scripts/sandbox_capture_worker.py")],
                            descriptor, scope["worker_timeout_seconds"])
    # Worker exit success is not independent authentication of its encrypted completion record.
    fingerprint = snapshot_fingerprint(root / "capture", scope["capture"]["recipient_sha256"]) if status == "success" else None
    journal.write({"kind": "sandbox_operator_status", "worker_status": status,
                   "ciphertext_fingerprint": fingerprint,
                   "scope_sha256": approved_scope_sha256, "capture_completion_independently_verified": False,
                   "live_execution_allowed": False, "research_trials": 0})
    return {"phase": "development", "run_id": scope["run_id"], "worker_status": status,
            "scope_sha256": approved_scope_sha256, "capture_completion_independently_verified": False,
            "ciphertext_fingerprint": fingerprint, "live_execution_allowed": False, "research_trials": 0}
