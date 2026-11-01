"""Reviewed development-only sandbox capture engine; no command or automatic live execution."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from research.catalog import canonical_sha256
from research.sandbox_observer import ACCOUNT, REGION, ROLE, assemble_observer_prestate, observer_requests
from research.sandbox_readiness import TAGS
from research.timing import require_sha256

VERSION = "sandbox-capture-v0.1"


def capture_source_sha256():
    """Fingerprint maintained capture dependencies for an independently reviewed scope.

    Inputs:
        None: Reads regular research Python files, capture/operator scripts and AWS dependencies.
    Outputs:
        str: Canonical path/content hash; rejects symlinks and performs no AWS or credential IO.
            Does not authenticate installed libraries, Python, the OS or human approval.
    """
    root = Path(__file__).resolve().parents[1]
    files = list((root / "research").glob("*.py")) + [root / name for name in (
        "requirements-aws.txt", "scripts/capture_sandbox.py", "scripts/sandbox_capture_worker.py", "scripts/review_recovery.py")]
    if any(file.is_symlink() or not file.is_file() for file in files):
        raise ValueError("Regular maintained capture source required")
    return canonical_sha256({str(file.relative_to(root)): hashlib.sha256(file.read_bytes()).hexdigest()
                             for file in sorted(files)})


def capture_scope(source_sha256, recipient_sha256):
    """Describe a fixed capture budget and pinned recipient without opening a session.

    Inputs:
        source_sha256: Independently retained maintained-source hash, not proof of approval.
        recipient_sha256: SHA-256 of normalized public recipient PEM, never a private key.
    Outputs:
        dict: Development-only scope for one STS call and eleven S3 operations, with no IO.
            Invalid hash syntax raises ValueError. No execution or permissions are granted.
    """
    require_sha256(source_sha256)
    require_sha256(recipient_sha256)
    return {"version": VERSION, "phase": "development", "account": ACCOUNT, "region": REGION,
            "role": ROLE, "source_sha256": source_sha256, "recipient_sha256": recipient_sha256,
            "requests": observer_requests(), "max_sdk_calls": 12, "deadline_seconds": 120,
            "connect_timeout_seconds": 3, "read_timeout_seconds": 10, "crypto_timeout_seconds": 5,
            "total_max_attempts": 1, "research_trials": 0}


def utc_now():
    """Read a UTC receipt clock without claiming synchronization accuracy.

    Inputs:
        None: Uses the host clock.
    Outputs:
        str: UTC ISO timestamp ending in Z; no file or AWS IO.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SendBudget:
    """Block a second wire attempt, including SDK redirects, within one planned invocation."""

    def __init__(self, deadline_ns, monotonic_ns):
        """Initialize an inactive per-client wire guard.

        Inputs:
            self: New budget instance.
            deadline_ns: Absolute monotonic deadline for starting wire attempts.
            monotonic_ns: Injectable monotonic clock shared with the collector.
        Outputs:
            None: Initializes in-memory counters; no IO.
        """
        self.active = False
        self.sent = 0
        self.deadline_ns = deadline_ns
        self.monotonic_ns = monotonic_ns

    def before_send(self, request, **kwargs):
        """Reject retries or sends outside the currently planned operation.

        Inputs:
            self: Per-client budget instance.
            request: SDK prepared request; deliberately never inspected or logged.
            kwargs: Additional SDK event context; unused and never logged.
        Outputs:
            None: Counts the first attempt; raises ValueError before any subsequent send.
        """
        if not self.active or self.sent >= 1 or self.monotonic_ns() >= self.deadline_ns:
            raise ValueError("Observer wire-attempt budget exceeded")
        self.sent += 1



def invoke_sandbox_read(client, operation, request):
    """Dispatch only the eleven declared metadata/listing operations using explicit SDK calls.

    Inputs:
        client: Scoped S3 SDK client configured by capture_sandbox.
        operation: One operation from the fixed sandbox observation manifest.
        request: Exact parameters already supplied by that manifest.
    Outputs:
        dict: SDK response; errors propagate for encrypted capture-level retention. Explicit calls
            support deterministic IAM analysis and reject all mutation/body-read operations.
    """
    if operation == "get_bucket_location":
        return client.get_bucket_location(**request)
    if operation == "get_bucket_tagging":
        return client.get_bucket_tagging(**request)
    if operation == "get_bucket_encryption":
        return client.get_bucket_encryption(**request)
    if operation == "get_bucket_ownership_controls":
        return client.get_bucket_ownership_controls(**request)
    if operation == "get_bucket_versioning":
        return client.get_bucket_versioning(**request)
    if operation == "get_bucket_policy":
        return client.get_bucket_policy(**request)
    if operation == "get_bucket_policy_status":
        return client.get_bucket_policy_status(**request)
    if operation == "get_public_access_block":
        return client.get_public_access_block(**request)
    if operation == "list_objects_v2":
        return client.list_objects_v2(**request)
    if operation == "list_object_versions":
        return client.list_object_versions(**request)
    if operation == "list_multipart_uploads":
        return client.list_multipart_uploads(**request)
    raise ValueError("Operation outside sandbox read manifest")


def capture_sandbox(session, archive, scope, approved_scope_sha256, monotonic_ns=time.monotonic_ns, clock=utc_now, operator_scope_sha256=None):
    """Retain one bounded encrypted observation using already-approved development scope.

    Inputs:
        session: Explicit SDK session resolving only the separately reviewed observer profile.
            Credential-provider activity is outside this operation budget and needs review.
        archive: New EncryptedArchive with a public certificate and five-second crypto timeout.
        scope: Exact capture_scope result; source and recipient must match actual local inputs.
        approved_scope_sha256: Independently reviewed scope hash; supplying it is not human approval.
        monotonic_ns: Injectable monotonic nanosecond clock for between-operation deadline checks.
        clock: Injectable UTC string clock for supplied receipt envelopes.
        operator_scope_sha256: Optional independently reviewed enclosing operator fingerprint,
            retained inside the encrypted capture scope to bind receipts to that run.
    Outputs:
        dict: Minimal completion summary after encrypted receipts, pre-state and completion record.
            Creates only ciphertext through archive; performs at most twelve planned SDK calls.
            Failed requests/preconditions stop collection, retain encrypted failure when possible,
            and raise a generic ValueError. Interrupts propagate after best-effort retention.
            No mutation, retries, pagination, research classification or automatic recovery occurs.
    """
    # Reject stale or edited scope and recipient before constructing any SDK clients.
    require_sha256(approved_scope_sha256)
    if operator_scope_sha256 is not None:
        require_sha256(operator_scope_sha256)
    if not isinstance(scope, dict) or canonical_sha256(scope) != canonical_sha256(capture_scope(capture_source_sha256(), scope.get("recipient_sha256"))) or canonical_sha256(scope) != approved_scope_sha256:
        raise ValueError("Exact reviewed capture scope and current source required")
    if archive.timeout_seconds != 5 or hashlib.sha256(archive.cert.read_bytes()).hexdigest() != scope["recipient_sha256"] or archive.receipts:
        raise ValueError("Fresh bounded archive for the pinned recipient required")
    start = monotonic_ns()
    active_request, identity, receipts = None, None, []
    attempted, started, before = False, None, None
    guards = []
    try:
        archive.write({"kind": "sandbox_capture_scope", "scope": scope, "scope_sha256": approved_scope_sha256,
                       "operator_scope_sha256": operator_scope_sha256})
        config = Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1, "mode": "standard"},
                        ignore_configured_endpoint_urls=True, proxies={}, use_fips_endpoint=False,
                        use_dualstack_endpoint=False, s3={"use_accelerate_endpoint": False})
        clients = {}
        for service in ("sts", "s3"):
            clients[service] = session.client(service, region_name=REGION, config=config,
                endpoint_url=f"https://{service}.{REGION}.amazonaws.com", use_ssl=True, verify=True)
            guard = SendBudget(start + 120_000_000_000, monotonic_ns)
            clients[service].meta.events.register_first(f"before-send.{service}", guard.before_send)
            guards.append((clients[service], service, guard))
        plan = [{"service": "sts", "operation": "get_caller_identity", "region": REGION, "request": {}}] + observer_requests()
        for active_request in plan:
            attempted, started, before = False, None, None
            if monotonic_ns() - start >= 120_000_000_000:
                raise ValueError("Observer deadline elapsed")
            client = clients[active_request["service"]]
            guard = guards[0 if active_request["service"] == "sts" else 1][2]
            guard.active, guard.sent = True, 0
            started, before = clock(), monotonic_ns()
            try:
                attempted = True
                response = client.get_caller_identity() if active_request["service"] == "sts" else invoke_sandbox_read(client, active_request["operation"], active_request["request"])
            finally:
                guard.active = False
            receipt = {**active_request, "started_at": started, "finished_at": clock(),
                       "elapsed_ns": monotonic_ns() - before, "response": response}
            # Persist raw response before interpreting it; failures remain part of the archive.
            archive.write({"kind": "sandbox_observer_receipt", "phase": "development", "receipt": receipt})
            if monotonic_ns() - start >= 120_000_000_000:
                raise ValueError("Observer deadline elapsed")
            status = response.get("ResponseMetadata", {})
            if type(status.get("HTTPStatusCode")) is not int or status["HTTPStatusCode"] != 200 or not isinstance(status.get("RequestId"), str) or not status["RequestId"].strip() or "Error" in response:
                raise ValueError("Successful attributed service response required")
            if active_request["operation"] == "get_bucket_location" and response.get("LocationConstraint") != REGION:
                raise ValueError("Sandbox region guard failed")
            if active_request["operation"] == "get_bucket_tagging":
                tags = response.get("TagSet")
                if not isinstance(tags, list) or len(tags) != len(TAGS) or any(not isinstance(tag, dict) or set(tag) != {"Key", "Value"} or not isinstance(tag["Key"], str) for tag in tags) or {tag["Key"]: tag["Value"] for tag in tags} != TAGS:
                    raise ValueError("Sandbox project tags guard failed")
            if active_request["service"] == "sts":
                identity = response
                prefix = f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/"
                arn = identity.get("Arn", "")
                if identity.get("Account") != ACCOUNT or not isinstance(arn, str) or not arn.startswith(prefix) or not arn[len(prefix):] or "/" in arn[len(prefix):]:
                    raise ValueError("Dedicated sandbox observer identity required")
            else:
                receipts.append(receipt)
        prestate = assemble_observer_prestate(identity, receipts)
        archive.write({"kind": "sandbox_observer_prestate", "record": prestate})
        if monotonic_ns() - start >= 120_000_000_000:
            raise ValueError("Observer deadline elapsed")
        archive.write({"kind": "sandbox_capture_completion", "phase": "development", "complete": True,
                       "scope_sha256": approved_scope_sha256, "receipts": list(archive.receipts),
                       "live_execution_allowed": False, "research_trials": 0})
        return {"phase": "development", "complete": True, "encrypted_records": len(archive.receipts),
                "scope_sha256": approved_scope_sha256, "live_execution_allowed": False, "research_trials": 0}
    except BaseException as error:
        # Avoid secret-bearing exception strings; provider errors stay inside ciphertext only.
        failure = {"kind": "sandbox_capture_failure", "phase": "development", "complete": False,
                   "request": active_request, "request_attempted": attempted,
                   "started_at": started, "finished_at": clock(),
                   "elapsed_ns": None if before is None else monotonic_ns() - before,
                   "error_type": type(error).__name__,
                   "scope_sha256": approved_scope_sha256, "research_trials": 0}
        if isinstance(error, ClientError):
            failure["response"] = error.response
        try:
            archive.write(failure)
        except Exception:
            pass  # Preserve partial ciphertext; there is no completion acknowledgement.
        if not isinstance(error, Exception):
            raise
        raise ValueError("Observer capture stopped; retained ciphertext may be incomplete") from None
    finally:
        # Remove handlers from caller-owned clients even when collection or encryption fails.
        for client, service, guard in guards:
            client.meta.events.unregister(f"before-send.{service}", guard.before_send)
