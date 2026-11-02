"""Opt-in fixed-bucket readback receipts for development; no mutation or compliance prediction."""
import copy
from datetime import timedelta
from email.utils import parsedate_to_datetime
import hashlib
import logging
from pathlib import Path
import time

from botocore.config import Config

from research.catalog import canonical_sha256
from research.sandbox_capture import SendBudget, utc_now
from research.sandbox_emptiness import ACCOUNT, BUCKET, REGION
from research.scenario_lock import validate_run_id
from research.timing import require_sha256, utc_timestamp
from scripts.sandbox_capture_worker import validate_observer_profile

VERSION = "development-versioning-point-v0.1"
PROFILE = ROLE = "dissertation-sandbox-observer"
POINTS = {"admission", "trigger", "window_end", "restoration-1", "restoration-2", "restoration-3"}


def point_source_sha256():
    """Fingerprint maintained readback dependencies without opening credentials.

    Inputs:
        No arguments; reads regular research Python sources, AWS requirements and profile validator.
    Outputs:
        str: Canonical maintained source fingerprint; no AWS, profile or private evidence access.
    """
    root = Path(__file__).resolve().parents[1]
    files = sorted(list((root / "research").glob("*.py")) + [root / "requirements-aws.txt",
                   root / "scripts/sandbox_capture_worker.py"])
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Regular point-observer sources required")
    return canonical_sha256({str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files})


def versioning_point_scope(run_id, point, recipient_sha256, enable_capture=False):
    """Declare one of the six fixed experiment readback slots with execution off by default.

    Inputs:
        run_id: Independent hexadecimal development run identifier.
        point: admission, trigger, window_end or restoration-1 through restoration-3.
        recipient_sha256: Independently retained public-recipient fingerprint.
        enable_capture: Explicit boolean for separately reviewed live read authorization.
    Outputs:
        dict: Fixed two-call, sixty-second metadata-only read scope; no SDK or output creation.
            The enclosing reviewed experiment, not this function, enforces the six-slot run limit.
    """
    return declared_point_scope(run_id, point, recipient_sha256, point_source_sha256(), enable_capture)


def declared_point_scope(run_id, point, recipient_sha256, source_sha256, enable_capture):
    """Reconstruct fixed point metadata without substituting current source for historical pins.

    Inputs:
        run_id: Independent development run identifier.
        point: One fixed observation slot.
        recipient_sha256: Independent public-recipient fingerprint.
        source_sha256: Independently retained historical maintained-source fingerprint.
        enable_capture: Explicit boolean in the reviewed declaration.
    Outputs:
        dict: Exact closed-schema fixed-target metadata; no filesystem, profile or AWS access.
    """
    validate_run_id(run_id)
    require_sha256(recipient_sha256)
    require_sha256(source_sha256)
    if point not in POINTS or type(enable_capture) is not bool:
        raise ValueError("Fixed point and explicit capture boolean required")
    return {"version": VERSION, "phase": "development", "run_id": run_id, "point": point,
            "account": ACCOUNT, "region": REGION, "bucket": BUCKET, "profile": PROFILE,
            "source_sha256": source_sha256, "recipient_sha256": recipient_sha256,
            "max_sdk_calls": 2, "deadline_seconds": 60, "enable_capture": enable_capture}


def check_point_receipt(receipt, operation, previous=None):
    """Validate one fixed operation envelope before any subsequent service request.

    Inputs:
        receipt: Supplied raw identity or versioning envelope retained privately by the producer.
        operation: Maintained literal get_caller_identity or get_bucket_versioning.
        previous: Prior validated finish timestamp, or None for the first receipt.
    Outputs:
        datetime: Validated current finish timestamp; errors reject malformed/old/unattributed data.
            No IO or source authentication occurs in this consistency predicate.
    """
    if operation not in {"get_caller_identity", "get_bucket_versioning"}:
        raise ValueError("Fixed point operation required")
    if not isinstance(receipt, dict) or set(receipt) != {"kind", "operation", "request", "response", "started_at", "finished_at", "finished_monotonic_ns", "elapsed_ns"}:
        raise ValueError("Exact point receipt schema required")
    request = {} if operation == "get_caller_identity" else {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}
    if receipt["kind"] != "versioning_point_receipt" or receipt["operation"] != operation or receipt["request"] != request:
        raise ValueError("Fixed point operation and owner required")
    started, finished = utc_timestamp(receipt["started_at"]), utc_timestamp(receipt["finished_at"])
    elapsed = receipt["elapsed_ns"]
    finished_ns = receipt["finished_monotonic_ns"]
    if type(finished_ns) is not int or finished_ns < 0 or type(elapsed) is not int or finished_ns < elapsed:
        raise ValueError("Same-domain point finish counter required")
    if type(elapsed) is not int or not 0 <= elapsed < 60_000_000_000 or finished < started or previous is not None and started < previous:
        raise ValueError("Ordered bounded point receipt clocks required")
    if abs((finished - started).total_seconds() * 1_000_000_000 - elapsed) > 1_000_000_000:
        raise ValueError("Point wall and monotonic clocks disagree")
    response = receipt["response"]
    metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
    if not isinstance(metadata, dict) or metadata.get("HTTPStatusCode") != 200 or "Error" in response or not isinstance(metadata.get("RequestId"), str) or not metadata["RequestId"].strip():
        raise ValueError("Successful attributed point response required")
    headers = metadata.get("HTTPHeaders", {})
    if not isinstance(headers, dict):
        raise ValueError("Point HTTP metadata required")
    server = parsedate_to_datetime(headers.get("date", ""))
    if server.tzinfo is None or not started - timedelta(seconds=5) <= server <= finished + timedelta(seconds=5):
        raise ValueError("Point service date differs from the local request interval")
    return finished


def check_point_receipts(scope, receipts):
    """Validate supplied attributed identity/readback envelopes and local/service clock consistency.

    Inputs:
        scope: Retained fixed development point scope, independently bound by the archive verifier.
        receipts: Exactly one STS identity and one S3 versioning envelope, ordered and copied.
    Outputs:
        dict: Minimal observed point status and receipt fingerprint; no raw response returned.
            Consistency only: no cloud authentication, interval-wide state or research trial proof.
    """
    if not isinstance(receipts, list) or len(receipts) != 2:
        raise ValueError("Exact identity and versioning receipts required")
    previous = None
    for index, operation in enumerate(("get_caller_identity", "get_bucket_versioning")):
        previous = check_point_receipt(receipts[index], operation, previous)
    if previous - utc_timestamp(receipts[0]["started_at"]) >= timedelta(seconds=60):
        raise ValueError("Point request interval exceeds its budget")
    identity, state = (receipt["response"] for receipt in receipts)
    if identity.get("Account") != ACCOUNT or identity.get("Arn") != f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/{ROLE}":
        raise ValueError("Exact independent observer identity required")
    if state.get("Status") not in {"Enabled", "Suspended"} or state.get("MFADelete", "Disabled") != "Disabled":
        raise ValueError("Explicit supported versioning/MFA state required")
    return {"version": VERSION, "phase": "development", "run_id": scope["run_id"], "point": scope["point"],
            "observed_status": state["Status"], "finished_at": receipts[-1]["finished_at"],
            "finished_monotonic_ns": receipts[-1]["finished_monotonic_ns"],
            "receipts_sha256": canonical_sha256(receipts), "request_receipt_clock_consistent": True,
            "interval_state_verified": False, "formal_trial_authorized": False, "research_trials": 0}


def capture_versioning_point(session, archive, scope, approved_scope_sha256, clock=utc_now,
                             monotonic_ns=time.monotonic_ns):
    """Retain one independently scoped observer identity and versioning read in ciphertext.

    Inputs:
        session: Explicit dedicated observer-profile SDK session, validated before client creation.
        archive: New empty pinned-recipient EncryptedArchive with five-second crypto timeout.
        scope: Current source-bound point scope, explicitly enabled after separate live approval.
        approved_scope_sha256: Independently retained scope fingerprint; not consent itself.
        clock: Local timezone-aware receipt clock callback.
        monotonic_ns: Same-process integer nanosecond clock for deadlines and wire starts.
    Outputs:
        dict: Minimal observed status/report plus ciphertext receipt fingerprint; no raw responses.
            Makes at most one identity and one fixed-owner versioning request, no mutation/retry.
            Any error preserves partial ciphertext, closes clients and raises a generic failure.
    """
    scope = copy.deepcopy(scope)
    require_sha256(approved_scope_sha256)
    expected = versioning_point_scope(scope["run_id"], scope["point"], scope["recipient_sha256"], scope["enable_capture"])
    if canonical_sha256(scope) != canonical_sha256(expected) or canonical_sha256(scope) != approved_scope_sha256 or scope["enable_capture"] is not True:
        raise ValueError("Current reviewed enabled point scope required")
    if archive.receipts or archive.timeout_seconds != 5 or hashlib.sha256(Path(archive.cert).read_bytes()).hexdigest() != scope["recipient_sha256"]:
        raise ValueError("Fresh pinned-recipient point archive required")
    validate_observer_profile(session)
    clients, guards, records, last_ns = [], [], [], None

    def now():
        """Reject clock rollback and enabled SDK debug logging before client/request work.

        Inputs:
            No arguments; reads injected monotonic clock and known SDK logger configuration.
        Outputs:
            int: Nonnegative increasing clock or generic failure; no request/credential logging.
        """
        nonlocal last_ns
        namespaces = ("botocore", "boto3", "urllib3", "awscrt")
        loggers = [logging.getLogger(name) for name in namespaces]
        loggers += [logger for name, logger in list(logging.Logger.manager.loggerDict.items())
                    if isinstance(logger, logging.Logger) and name.startswith(tuple(namespace + "." for namespace in namespaces))]
        value = monotonic_ns()
        if any(logger.isEnabledFor(logging.DEBUG) for logger in loggers) or type(value) is not int or value < 0 or last_ns is not None and value < last_ns:
            raise ValueError("Quiet SDK logging and valid point clock required")
        last_ns = value
        return value

    def retain(record):
        """Check ordered encrypted acknowledgments before accepting the next point operation.

        Inputs:
            record: Maintained private metadata or raw identity/versioning receipt, never printed.
        Outputs:
            None: Retains ciphertext durably or fails before proceeding; no plaintext export.
        """
        receipt = archive.write(record)
        if not isinstance(receipt, dict) or set(receipt) != {"file", "ciphertext_sha256"} or receipt["file"] != f"record-{len(records):05d}.cms":
            raise ValueError("Ordered point ciphertext receipt required")
        require_sha256(receipt["ciphertext_sha256"])
        records.append(copy.deepcopy(record))

    deadline = now() + 60_000_000_000
    try:
        retain({"kind": "versioning_point_scope", "scope": scope, "scope_sha256": approved_scope_sha256})
        for service in ("sts", "s3"):
            if now() >= deadline:
                raise ValueError("Point deadline elapsed")
            client = session.client(service, region_name=REGION, endpoint_url=f"https://{service}.{REGION}.amazonaws.com",
                config=Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1, "mode": "standard"},
                    ignore_configured_endpoint_urls=True, proxies={}, use_fips_endpoint=False, use_dualstack_endpoint=False,
                    s3={"use_accelerate_endpoint": False}), use_ssl=True, verify=True)
            clients.append(client)
            guard = SendBudget(deadline, now)
            guards.append((service, client, guard))
            client.meta.events.register_first(f"before-send.{service}", guard.before_send)
            before, started = now(), clock()
            if before >= deadline:
                raise ValueError("Point deadline elapsed before request")
            guard.active = True
            try:
                if service == "sts":
                    response = client.get_caller_identity()
                    operation, request = "get_caller_identity", {}
                else:
                    response = client.get_bucket_versioning(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT)
                    operation, request = "get_bucket_versioning", {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}
            finally:
                guard.active = False
            finished, elapsed = clock(), now() - before
            retain({"kind": "versioning_point_receipt", "operation": operation, "request": request,
                    "response": response, "started_at": started, "finished_at": finished,
                    "finished_monotonic_ns": before + elapsed, "elapsed_ns": elapsed})
            check_point_receipt(records[-1], operation, None if service == "sts" else utc_timestamp(records[-2]["finished_at"]))
            # Identity must pass before even constructing the S3 client.
            if service == "sts" and (response.get("Account") != ACCOUNT or response.get("Arn") != f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/{ROLE}"):
                raise ValueError("Wrong independent observer identity")
        report = check_point_receipts(scope, records[1:])
        if now() >= deadline:
            raise ValueError("Point completion deadline elapsed")
        retain({"kind": "versioning_point_completion", "report": report, "receipts": copy.deepcopy(archive.receipts)})
        if now() >= deadline:
            raise ValueError("Point retention exceeded its deadline")
        return {**report, "ciphertext_fingerprint": canonical_sha256(archive.receipts)}
    except BaseException:
        raise ValueError("Versioning point capture failed; partial ciphertext retained") from None
    finally:
        for service, client, guard in guards:
            guard.active = False
            try:
                client.meta.events.unregister(f"before-send.{service}", guard.before_send)
                client.close()
            except Exception:
                pass


def verify_versioning_point(scope, approved_scope_sha256, records, receipts, expected_fingerprint):
    """Reconstruct an encrypted point archive against independent scope and ciphertext pins.

    Inputs:
        scope: Independently retained historical point scope; no current-source substitution.
        approved_scope_sha256: Independent exact scope fingerprint.
        records: Four bounded authenticated in-memory plaintext records from the generic archive reader.
        receipts: Four ordered ciphertext acknowledgments from that same reader.
        expected_fingerprint: Independently retained ciphertext-receipt inventory fingerprint.
    Outputs:
        dict: Minimal observed status/report after consistency checks; no raw responses returned.
            No AWS, decryption, formal trial promotion or continuous-state proof occurs here.
    """
    require_sha256(approved_scope_sha256)
    require_sha256(expected_fingerprint)
    if not isinstance(scope, dict):
        raise ValueError("Exact retained point scope required")
    expected = declared_point_scope(scope["run_id"], scope["point"], scope["recipient_sha256"], scope["source_sha256"], scope["enable_capture"])
    if canonical_sha256(expected) != canonical_sha256(scope) or scope["enable_capture"] is not True:
        raise ValueError("Exact enabled historical development point required")
    if canonical_sha256(scope) != approved_scope_sha256 or not isinstance(records, list) or len(records) != 4 or len(receipts) != 4 or canonical_sha256(receipts) != expected_fingerprint:
        raise ValueError("Complete independently pinned point archive required")
    if records[0] != {"kind": "versioning_point_scope", "scope": scope, "scope_sha256": approved_scope_sha256}:
        raise ValueError("Retained point scope differs from review")
    report = check_point_receipts(scope, records[1:3])
    if records[3] != {"kind": "versioning_point_completion", "report": report, "receipts": receipts[:3]}:
        raise ValueError("Point completion or ciphertext chain differs")
    return {**report, "ciphertext_fingerprint": expected_fingerprint}
