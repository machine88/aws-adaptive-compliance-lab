"""Scoped native snapshot callbacks with encrypted journaling and POSIX worker timeouts."""
import copy
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from research.archive_ingestion import private_bytes
from research.aws_reader import ACCOUNT, REGION, EncryptedArchive, read_plan
from research.catalog import canonical_sha256
from research.prospective_runner import CollectorAbort, DevelopmentSamplingRunner
from research.timing import require_sha256
from research.trials import safe_id

REPOSITORY = Path(__file__).resolve().parents[1]
READER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/dissertation-evidence-reader"


def utc_now():
    """Read timezone-aware UTC wall time for an explicitly invoked native run.

    Inputs:
        No arguments; reads the local system clock without contacting AWS.
    Outputs:
        datetime: Aware UTC timestamp; does not verify a cloud trigger or synchronize clocks.
    """
    return datetime.now(timezone.utc)


def run_native_capture(plan, approved_plan_sha256, scope, approved_scope_sha256, certificate,
                        wall_clock=None, monotonic_clock=None, sleeper=None):
    """Execute a separately approved native development capture with exact plan/scope matching.

    Inputs:
        plan: Independently reviewed development runner plan, including collector scope fingerprint.
        approved_plan_sha256: Trusted fingerprint of that explicitly approved capture plan.
        scope: Native scope produced and reviewed before execution.
        approved_scope_sha256: Trusted fingerprint of the exact approved native scope.
        certificate: Public recipient certificate matching the scope; never a private key.
        wall_clock: Optional injected aware clock; None uses actual UTC wall time.
        monotonic_clock: Optional injected elapsed clock; None uses time.monotonic.
        sleeper: Optional injected wait callback; None uses real sleeps of at most 60 seconds.
    Outputs:
        dict: Closed runner report and encrypted native-report receipt after the full window.
            Creates private ciphertext outputs and starts bounded read-only workers only on call.
            Invalid plans/scopes fail before output reservation; failures preserve partial output
            without a native completion report. Hash matching alone is not human approval proof.
    """
    native = None

    def collect(sample_id):
        """Delegate collection only after the private native context has been opened.

        Inputs:
            sample_id: Reviewed scheduled identifier.
        Outputs:
            dict: Native status/evidence hash; an unopened context aborts instead of reading AWS.
        """
        if native is None:
            raise CollectorAbort("Native context is not open")
        return native.collect(sample_id)

    def persist(record):
        """Delegate encrypted journal writes after native scope validation.

        Inputs:
            record: Runner metadata to retain privately.
        Outputs:
            str: Ciphertext receipt hash; an unopened context aborts.
        """
        if native is None:
            raise CollectorAbort("Native context is not open")
        return native.persist(record)

    runner = DevelopmentSamplingRunner(plan, approved_plan_sha256, collect, persist,
                                       utc_now if wall_clock is None else wall_clock,
                                       time.monotonic if monotonic_clock is None else monotonic_clock,
                                       time.sleep if sleeper is None else sleeper)
    if plan["collector_scope_sha256"] != approved_scope_sha256 or len(plan["sampling"]["samples"]) != scope["max_snapshots"]:
        raise ValueError("Runner scope/invocation count differs from approved native scope")
    native = NativeSnapshotCallbacks(scope, approved_scope_sha256, certificate)
    report = runner.run()
    receipt = native.persist({"kind": "native_run_report", "phase": "development", "report": report,
                               "prior_ciphertext_receipts": list(native.journal.receipts)})
    return {"report": report, "native_report_receipt": receipt}


def native_scope(bucket, certificate, output_root, openssl, timeout_seconds, max_items, max_pages, max_snapshots):
    """Build a local reviewable binding without credentials, AWS calls or output creation.

    Inputs:
        bucket: Maintained research bucket; its exact read plan is hashed.
        certificate: Public recipient certificate path, never a private key.
        output_root: Absolute future private run directory; parent must exist for execution.
        openssl: Explicit OpenSSL executable used for certificate normalization/encryption.
        timeout_seconds: Integer worker deadline from one through 300 seconds.
        max_items: Per-query item cap from one through 1,000.
        max_pages: Per-query page cap from one through 20.
        max_snapshots: Total distinct collector invocations from one through 1,000.
    Outputs:
        dict: Reviewable scope, executable/code/runtime/public-recipient pins and read bounds.
            Reads local files and normalizes a public certificate; makes no AWS call or file write.
    """
    for value, upper in [(timeout_seconds, 300), (max_items, 1000), (max_pages, 20), (max_snapshots, 1000)]:
        if type(value) is not int or not 1 <= value <= upper:
            raise ValueError("Explicit bounded native capture settings required")
    root = Path(output_root)
    if not root.is_absolute() or root != root.resolve():
        raise ValueError("Canonical absolute output root required")
    binary = str(Path(openssl).resolve(strict=True))
    with Path(certificate).open("rb") as stream:
        public = stream.read(65537)
    if len(public) > 65536:
        raise ValueError("Public certificate input exceeds local bound")
    if b"PRIVATE KEY" in public:
        raise ValueError("Only a public recipient certificate is allowed")
    public = subprocess.run([binary, "x509", "-outform", "PEM"], input=public, capture_output=True, check=True, timeout=30).stdout
    files = list((REPOSITORY / "research").glob("*.py")) + [REPOSITORY / name for name in (
        "scripts/collect_snapshot.py", "scripts/prospective_snapshot_worker.py", "requirements-aws.txt", "requirements-ml.txt")]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Maintained source files must be regular files")
    return {"phase": "development", "account_id": ACCOUNT, "region": REGION, "bucket": bucket,
            "source_profile": "dissertation", "reader_role_arn": READER_ROLE,
            "recipient_sha256": hashlib.sha256(public).hexdigest(), "output_root": str(root),
            "snapshot_requests_sha256": canonical_sha256(read_plan(bucket)),
            "code_sha256": {str(path.relative_to(REPOSITORY)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in sorted(files)},
            "runtime_versions": {name: importlib.metadata.version(name) for name in ("boto3", "botocore", "awscrt")},
            "python_version": platform.python_version(), "python_executable": sys.executable,
            "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            "openssl_executable": binary, "openssl_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            "timeout_seconds": timeout_seconds, "max_items": max_items, "max_pages": max_pages,
            "local_crypto_timeout_seconds": min(timeout_seconds, 30),
            "max_snapshots": max_snapshots,
            "logical_service_calls_per_snapshot_excluding_auth_refresh": 3 + sum(max_pages if r["paginated"] else 1 for r in read_plan(bucket))}


def validate_native_scope(scope, approved_scope_sha256, certificate):
    """Recompute every local binding rather than trusting a caller's reviewed-scope declaration.

    Inputs:
        scope: Exact native scope produced by native_scope in the reviewed environment.
        approved_scope_sha256: Independently trusted hash from the explicitly approved capture review.
        certificate: Public certificate whose normalized bytes must match the scope.
    Outputs:
        None: Raises ValueError on mismatched scope/code/runtime/certificate; performs no AWS call.
    """
    require_sha256(approved_scope_sha256)
    if not isinstance(scope, dict) or canonical_sha256(scope) != approved_scope_sha256:
        raise ValueError("Native scope differs from independently reviewed hash")
    expected = native_scope(scope["bucket"], certificate, scope["output_root"], scope["openssl_executable"],
                            scope["timeout_seconds"], scope["max_items"], scope["max_pages"], scope["max_snapshots"])
    if expected != scope:
        raise ValueError("Native collector binding changed since review")


def worker_environment():
    """Remove inherited credential/endpoint/Python overrides from the snapshot subprocess.

    Inputs:
        No arguments; reads process environment without logging its values.
    Outputs:
        dict: Child environment using default local login files, pinned code and regional SDK settings.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith(("AWS_", "PYTHON", "DYLD_", "LD_"))}
    env.update(AWS_EC2_METADATA_DISABLED="true", AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_MAX_ATTEMPTS="3", AWS_RETRY_MODE="standard")
    return env


def bounded_worker(command, descriptor, timeout_seconds, *, inherit_supervisor_group=False, terminate_group_on_exit=False):
    """Run a silent isolated worker and kill its process group on timeout or cancellation.

    Inputs:
        command: Trusted explicit argv for the pinned Python/worker, never shell text.
        descriptor: JSON-compatible private scope/output descriptor passed through stdin only.
        timeout_seconds: Reviewed bounded subprocess runtime.
        inherit_supervisor_group: Keep a nested child in this process group only when this
            caller is already its isolated session/group leader; default creates a new session.
        terminate_group_on_exit: Kill remaining members of a new worker group even after normal
            worker exit; required for the outer preparation supervisor, incompatible with nesting.
    Outputs:
        str: success, failed, fatal or timeout; reaps the child and discards stdout/stderr.
            Default cancellation kills the worker group then propagates. Nested mode kills only
            its immediate child; the outer supervisor owns group-wide termination. No raw output
            is retained. This mode never targets the invoking application's process group.
    """
    if type(terminate_group_on_exit) is not bool or (terminate_group_on_exit and inherit_supervisor_group):
        raise ValueError("Group cleanup requires an explicit standalone supervisor mode")
    if type(inherit_supervisor_group) is not bool:
        raise ValueError("Explicit boolean process-group mode required")
    if inherit_supervisor_group and (os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid()):
        raise ValueError("Nested workers require an isolated session/group leader")
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=not inherit_supervisor_group, env=worker_environment())
    try:
        process.communicate(json.dumps(descriptor, allow_nan=False).encode(), timeout=timeout_seconds)
    except BaseException as error:
        try:
            if inherit_supervisor_group:
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        if isinstance(error, subprocess.TimeoutExpired):
            return "timeout"
        raise
    if terminate_group_on_exit:
        # A failed helper may leave descendants even when the immediate worker has exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return "success" if process.returncode == 0 else "fatal" if process.returncode == 2 else "failed"


def snapshot_fingerprint(root, recipient_sha256):
    """Hash bounded private ciphertext files without decrypting or asserting completion contents.

    Inputs:
        root: Worker snapshot directory expected to contain only public certificate and CMS records.
        recipient_sha256: Independently pinned normalized public certificate hash.
    Outputs:
        str: Archive-compatible fingerprint; bad permissions, links, gaps or excessive size fail.
            Does not authenticate the writer or inspect encrypted completion/source records.
    """
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Private owned snapshot directory required")
        names = os.listdir(descriptor)
        records = sorted((name for name in names if re.fullmatch(r"record-\d{5}\.cms", name)))
        if len(records) < 2 or len(records) > 10000 or records != [f"record-{i:05d}.cms" for i in range(len(records))] or set(names) != set(records) | {"recipient-public.pem"}:
            raise ValueError("Unexpected or incomplete ciphertext file inventory")
        remaining = 67108864
        public = private_bytes(descriptor, "recipient-public.pem", remaining)
        if hashlib.sha256(public).hexdigest() != recipient_sha256:
            raise ValueError("Snapshot public recipient changed")
        remaining -= len(public)
        receipts = []
        for name in records:
            content = private_bytes(descriptor, name, remaining)
            remaining -= len(content)
            receipts.append({"file": name, "ciphertext_sha256": hashlib.sha256(content).hexdigest()})
        if set(os.listdir(descriptor)) != set(names):
            raise ValueError("Snapshot inventory changed during fingerprinting")
        return canonical_sha256({"recipient_sha256": recipient_sha256, "receipts": receipts})
    finally:
        os.close(descriptor)


class NativeSnapshotCallbacks:
    """Bind the development runner to scoped subprocess snapshots and a CMS journal."""

    def __init__(self, scope, approved_scope_sha256, certificate):
        """Validate local scope, reserve exclusive private output and validate encryption first.

        Inputs:
            scope: Reviewed local scope including output root and invocation/read/time bounds.
            approved_scope_sha256: Independently trusted approved scope fingerprint.
            certificate: Public recipient certificate; no decryption key is accessed.
        Outputs:
            None: Creates private root/samples/journal directories and encrypted scope record.
                Performs no credential lookup or AWS call; existing roots are never reused.
        """
        if os.name != "posix":
            raise ValueError("Native process-group and private-file safeguards require POSIX")
        validate_native_scope(scope, approved_scope_sha256, certificate)
        self.scope, self.scope_sha256 = copy.deepcopy(scope), approved_scope_sha256
        root = Path(scope["output_root"])
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("Run parent must be private and owned")
            os.mkdir(root.name, mode=0o700, dir_fd=parent)
        finally:
            os.close(parent)
        self.root = root
        self.samples = root / "samples"
        self.samples.mkdir(mode=0o700)
        self.journal = EncryptedArchive(root / "journal", certificate, scope["openssl_executable"],
                                         timeout_seconds=scope["local_crypto_timeout_seconds"])
        self.seen = set()
        self.persist({"kind": "native_scope", "phase": "development", "scope": self.scope,
                      "scope_sha256": approved_scope_sha256})

    def persist(self, record):
        """Encrypt one runner event through the existing exclusive CMS archive writer.

        Inputs:
            record: Label-free run metadata; never printed or written as plaintext.
        Outputs:
            str: Ciphertext receipt hash; encryption/persistence failures propagate.
        """
        return self.journal.write(record)["ciphertext_sha256"]

    def collect(self, sample_id):
        """Execute one scoped snapshot under a bounded silent worker without reading log bodies.

        Inputs:
            sample_id: Unique safe identifier from the independently reviewed runner schedule.
        Outputs:
            dict: status/evidence_sha256 only; successful exit yields an unverified ciphertext
                fingerprint, failures yield encrypted error metadata and preserve partial files.
                Fatal scope/identity failures abort the schedule; no automatic retry is performed.
        """
        safe_id(sample_id)
        if sample_id in self.seen or len(self.seen) >= self.scope["max_snapshots"]:
            raise CollectorAbort("Snapshot replay or invocation cap reached")
        self.seen.add(sample_id)
        try:
            validate_native_scope(self.scope, self.scope_sha256, self.journal.cert)
        except Exception:
            raise CollectorAbort("Native scope integrity check failed") from None
        output = self.samples / sample_id
        descriptor = {"scope": self.scope, "approved_scope_sha256": self.scope_sha256,
                      "certificate": str(self.journal.cert), "sample_id": sample_id}
        outcome = bounded_worker([self.scope["python_executable"], "-I", str(REPOSITORY / "scripts/prospective_snapshot_worker.py")],
                                 descriptor, self.scope["timeout_seconds"])
        if outcome == "fatal":
            raise CollectorAbort("Worker scope or source identity validation failed")
        if outcome == "success":
            try:
                validate_native_scope(self.scope, self.scope_sha256, self.journal.cert)
                digest = snapshot_fingerprint(output, self.scope["recipient_sha256"])
            except Exception:
                raise CollectorAbort("Post-worker source or ciphertext inventory check failed") from None
            return {"status": "success", "evidence_sha256": digest}
        digest = self.persist({"kind": "snapshot_worker_failed", "sample_id": sample_id, "reason": outcome,
                               "partial_output_retained": output.exists()})
        return {"status": "error", "evidence_sha256": digest}
