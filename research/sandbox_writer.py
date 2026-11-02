"""Disabled-by-default fixed-bucket SDK transport for a future reviewed versioning/recovery runner."""
from asyncio import CancelledError
import copy
import hashlib
from pathlib import Path
import threading
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from research.catalog import canonical_sha256
from research.recovery_intent import verify_recovery_intent
from research.sandbox_capture import SendBudget, utc_now
from research.sandbox_emptiness import ACCOUNT, BUCKET, REGION
from research.scenario_lock import validate_run_id
from research.timing import require_sha256
from research.writer_session import BoundWriterSession

VERSION = "sandbox-versioning-writer-v0.2"
ROLE = PROFILE = "dissertation-sandbox-versioning"
KEYS = {"version", "phase", "account", "region", "bucket", "profile", "run_id", "source_sha256",
        "recipient_sha256", "intent_sha256", "intent_review_sha256", "intent_source_sha256",
        "enable_writes", "mode", "session_mode", "lifetime_seconds", "max_suspensions", "max_restorations"}


def writer_source_sha256():
    """Bind maintained writer dependencies and exact AWS package declarations.

    Inputs:
        No arguments; reads regular maintained Python and requirement files only.
    Outputs:
        str: Canonical path/content hash; no profile, private artifact, SDK session or AWS access.
    """
    root = Path(__file__).resolve().parents[1]
    files = list((root / "research").glob("*.py")) + [root / "requirements-aws.txt"]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Regular maintained writer source required")
    return canonical_sha256({str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(files)})


def writer_scope(run_id, recipient_sha256, intent_sha256, intent_review_sha256, intent_source_sha256,
                 enable_writes=False, mode="change_and_restore", session_mode="profile"):
    """Build a reviewable fixed-target scope with execution disabled unless explicitly selected.

    Inputs:
        run_id: New retained 32-character hexadecimal development identifier.
        recipient_sha256: Independent normalized public recipient fingerprint.
        intent_sha256: Independent verified protected-intent content fingerprint.
        intent_review_sha256: Independent intent preparation-manifest fingerprint.
        intent_source_sha256: Independent historical intent source fingerprint.
        enable_writes: Explicit boolean; False is the safe default and cannot initialize a writer.
        mode: change_and_restore or separately reviewed recovery_only; neither is consent proof.
        session_mode: profile by default, or independently reviewed bound_session; never inferred.
    Outputs:
        dict: Current source-bound fixed account/bucket/role scope; no SDK session or output creation.
    """
    scope = {"version": VERSION, "phase": "development", "account": ACCOUNT, "region": REGION,
        "bucket": BUCKET, "profile": PROFILE, "run_id": run_id, "source_sha256": writer_source_sha256(),
        "recipient_sha256": recipient_sha256, "intent_sha256": intent_sha256,
        "intent_review_sha256": intent_review_sha256, "intent_source_sha256": intent_source_sha256,
        "enable_writes": enable_writes, "mode": mode, "session_mode": session_mode, "lifetime_seconds": 2400,
        "max_suspensions": 1, "max_restorations": 3}
    preview_writer_scope(scope)
    return scope


def preview_writer_scope(scope):
    """Validate declared fixed transport boundaries without reading profiles or creating SDK clients.

    Inputs:
        scope: Exact fixed-target development writer contract.
    Outputs:
        dict: Scope fingerprint and closed runner/research gates; no AWS or execution authority.
    """
    fixed = {"version": VERSION, "phase": "development", "account": ACCOUNT, "region": REGION,
             "bucket": BUCKET, "profile": PROFILE}
    if not isinstance(scope, dict) or set(scope) != KEYS or any(scope[name] != value for name, value in fixed.items()):
        raise ValueError("Exact fixed-target writer scope required")
    validate_run_id(scope["run_id"])
    for name in ("source_sha256", "recipient_sha256", "intent_sha256", "intent_review_sha256", "intent_source_sha256"):
        require_sha256(scope[name])
    if type(scope["enable_writes"]) is not bool or scope["mode"] not in {"change_and_restore", "recovery_only"} or scope["session_mode"] not in {"profile", "bound_session"}:
        raise ValueError("Explicit writer enable flag and bounded mode required")
    for name, value in (("lifetime_seconds", 2400), ("max_suspensions", 1), ("max_restorations", 3)):
        if type(scope[name]) is not int or scope[name] != value:
            raise ValueError("Fixed writer lifetime and attempt bounds required")
    return {"version": VERSION, "scope_sha256": canonical_sha256(scope), "writes_enabled": scope["enable_writes"],
            "mode": "preview", "aws_called": False, "live_execution_allowed": False, "research_trials": 0}


def validate_writer_profile(session):
    """Reject broader credentials/providers before constructing identity or write clients.

    Inputs:
        session: Explicit SDK session configured for the proposed dedicated writer profile.
    Outputs:
        None: Validates configuration only; does not resolve or export credentials or call AWS.
            Requested session duration is not proof of remaining credential lifetime.
    """
    expected = {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE}", "source_profile": "dissertation",
                "role_session_name": ROLE, "duration_seconds": "3600", "region": REGION}
    if session._session.get_scoped_config() != expected:
        raise ValueError("Exact dedicated writer profile required")
    source = session._session.full_config["profiles"].get("dissertation", {})
    if set(source) - {"login_session", "region", "output"} or not isinstance(source.get("login_session"), str) or not source["login_session"] or source.get("region") != REGION:
        raise ValueError("Existing local-login source profile required")


class BoundedVersioningWriter:
    """Single-thread transport only; does not provide live admission, rollback or source attestation."""

    def __init__(self, scope, approved_scope_sha256, intent, archive, session_factory=None,
                 monotonic_ns=time.monotonic_ns, clock=utc_now, bound_session=None, prechange_check=None):
        """Validate opt-in, intent and fresh encryption before checking the dedicated writer identity.

        Inputs:
            scope: Explicitly enabled fixed-target scope approved separately before any real use.
            approved_scope_sha256: Independent scope fingerprint; matching alone is not consent.
            intent: Protected intent already authenticated/bound by the independent upstream reader.
            archive: New empty EncryptedArchive with the pinned recipient and five-second crypto limit.
            session_factory: Optional offline-test constructor; None uses the exact named boto3 profile.
            monotonic_ns: Integer local nanosecond clock; guards cooperative lifetime and wire starts.
            clock: UTC timestamp callback for encrypted transport receipts only.
            bound_session: Exact initialized BoundWriterSession for explicitly scoped bound_session
                mode only; profile mode refuses it. A separate session factory cannot be mixed in.
            prechange_check: Trusted no-argument admission checker required for bound-session
                change_and_restore mode. Must raise on stale evidence/changed lock; its return
                value is ignored. This callable is not an independent attestation or consent.
        Outputs:
            None: With explicit opt-in only, creates fixed regional clients, makes one identity call
                and retains its encrypted response. No S3 write occurs during construction. Wrong
                identity/profile, disabled scope or retention failure stops before S3 client setup.
                Credential-provider activity is outside the one identity/four write API budget.
        """
        require_sha256(approved_scope_sha256)
        preview = preview_writer_scope(scope)
        if preview["scope_sha256"] != approved_scope_sha256 or writer_source_sha256() != scope["source_sha256"] or scope["enable_writes"] is not True:
            raise ValueError("Current independently reviewed enabled writer scope required")
        if scope["session_mode"] == "bound_session":
            if type(bound_session) is not BoundWriterSession or session_factory is not None or (scope["mode"] == "change_and_restore" and not callable(prechange_check)):
                raise ValueError("Exact bound session without alternate factory required")
        elif bound_session is not None:
            raise ValueError("Profile mode cannot accept a bound session")
        intent = copy.deepcopy(intent)
        if verify_recovery_intent(intent, scope["run_id"], scope["intent_review_sha256"], scope["intent_source_sha256"], scope["recipient_sha256"]) != scope["intent_sha256"]:
            raise ValueError("Authenticated retained intent differs from independent pin")
        if archive.receipts or archive.timeout_seconds != 5 or hashlib.sha256(Path(archive.cert).read_bytes()).hexdigest() != scope["recipient_sha256"]:
            raise ValueError("Fresh bounded encrypted archive with reviewed recipient required")
        self._scope, self._intent, self._archive = copy.deepcopy(scope), intent, archive
        self._prechange_check = prechange_check
        self._clock, self._monotonic = clock, monotonic_ns
        self._thread, self._busy, self._closed = threading.get_ident(), False, False
        self._clients, self._sequence, self._last_time = {}, 0, None
        self._suspensions = self._restorations = 0
        self._active_status = None
        self._journal_complete, self._identity_verified = True, False
        self._deadline = self._now() + 2400_000_000_000
        self._identity_deadline = self._last_time + 120_000_000_000
        try:
            self._retain({"kind": "writer_scope", "scope": self._scope, "scope_sha256": approved_scope_sha256}, required=True)
            if self._scope["session_mode"] == "bound_session":
                self._session = bound_session
                claim = bound_session.claim_writer(self._scope["run_id"], self._scope["recipient_sha256"])
                self._retain(claim, required=True)
            else:
                factory = boto3.Session if session_factory is None else session_factory
                self._session = factory(profile_name=PROFILE, region_name=REGION)
                validate_writer_profile(self._session)
            sts, guard = self._client("sts", self._identity_deadline)
            guard.active, guard.sent = True, 0
            try:
                identity = sts.get_caller_identity()
            finally:
                guard.active = False
            self._retain({"kind": "writer_identity", "response": identity}, required=True)
            self._success(identity)
            if self._now() >= self._identity_deadline or identity.get("Account") != ACCOUNT or identity.get("Arn") != f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/{ROLE}":
                raise ValueError("Exact actual writer role/account identity required")
            self._identity_verified = True
            self._s3, self._guard = self._client("s3", self._deadline)
        except BaseException as error:
            failure = {"kind": "writer_initialization_failed", "error_type": type(error).__name__}
            if isinstance(error, ClientError):
                failure["provider_response"] = error.response
            self._retain(failure)
            self.close()
            raise ValueError("Writer initialization failed; inspect retained evidence") from None

    def _now(self):
        """Validate local monotonic progression without claiming independent source freshness.

        Inputs:
            self: Writer owning its injected local clock and previous counter.
        Outputs:
            int: Nonnegative counter; malformed values or rollback raise before request admission.
        """
        value = self._monotonic()
        if type(value) is not int or value < 0 or (self._last_time is not None and value < self._last_time):
            raise ValueError("Invalid writer monotonic clock")
        self._last_time = value
        return value

    def _client(self, service, deadline):
        """Configure one fixed HTTPS regional client with SDK retry and wire-attempt limits.

        Inputs:
            self: Writer with an already validated explicit profile.
            service: Maintained literal sts or s3, never a caller-selected service.
            deadline: Absolute latest local monotonic start time for a wire attempt.
        Outputs:
            tuple: Client and inactive shared SendBudget; credential resolution may occur here.
                Records references for deterministic handler/socket cleanup.
        """
        config = Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1, "mode": "standard"},
            ignore_configured_endpoint_urls=True, proxies={}, use_fips_endpoint=False, use_dualstack_endpoint=False,
            s3={"use_accelerate_endpoint": False})
        if self._scope["session_mode"] == "bound_session":
            # The exact broker owns fixed endpoints/configuration and its independent expiry guard.
            client = self._session.client(service)
        else:
            client = self._session.client(service, region_name=REGION, config=config,
                endpoint_url=f"https://{service}.{REGION}.amazonaws.com", use_ssl=True, verify=True)
        guard = SendBudget(deadline, self._now)
        client.meta.events.register_first(f"before-send.{service}", guard.before_send)
        if service == "s3" and self._scope["session_mode"] == "bound_session":
            client.meta.events.register_first("before-send.s3", self._prechange_wire_budget)
        self._clients[service] = (client, guard)
        return client, guard

    def _prechange_wire_budget(self, request, **kwargs):
        """Recheck the same session's full budget at the actual suspension wire boundary.

        Inputs:
            self: Bound-session writer owning one currently active fixed status request.
            request: Prepared SDK request; never inspected or retained by this guard.
            kwargs: Unused SDK event metadata; never logged.
        Outputs:
            None: Rejects insufficient budget before a Suspended send. Enabled recovery remains
                constrained by the broker expiry guard, not a new full observation-horizon budget.
        """
        if self._active_status == "Suspended":
            self._session.check_writer_budget(self._scope["run_id"])
            self._prechange_check()
            self._session.check_writer_budget(self._scope["run_id"])

    def _retain(self, record, required=False):
        """Check ordered encrypted acknowledgments and retain uncertainty on any storage failure.

        Inputs:
            self: Writer owning the dedicated new encrypted archive and receipt sequence.
            record: Private transport scope, pending request, response or error; never printed.
            required: Whether failure must stop before identity or initial mutation dispatch.
        Outputs:
            bool: True for acknowledged retention; False marks incomplete evidence. Required failure
                raises a generic error. Recovery attempts may continue best-effort after journal failure.
        """
        try:
            receipt = self._archive.write({"phase": "development", "run_id": self._scope["run_id"], **copy.deepcopy(record)})
            if not isinstance(receipt, dict) or set(receipt) != {"file", "ciphertext_sha256"} or receipt["file"] != f"record-{self._sequence:05d}.cms":
                raise ValueError("Ordered ciphertext acknowledgment required")
            require_sha256(receipt["ciphertext_sha256"])
            self._sequence += 1
            return True
        except BaseException:
            self._journal_complete = False
            if required:
                raise ValueError("Writer evidence retention failed before request") from None
            return False

    def _success(self, response):
        """Check attributed HTTP success without interpreting it as configuration-state proof.

        Inputs:
            self: Writer retaining the response before validation.
            response: Raw SDK result already passed through the encrypted boundary.
        Outputs:
            None: Raises generically on error/malformed response; no raw provider data escapes.
        """
        metadata = response.get("ResponseMetadata", {})
        if type(metadata.get("HTTPStatusCode")) is not int or metadata["HTTPStatusCode"] != 200 or not isinstance(metadata.get("RequestId"), str) or not metadata["RequestId"].strip() or "Error" in response:
            raise ValueError("Attributed successful SDK response required")

    def suspend_once(self):
        """Request the fixed Suspended transition at most once in this writer instance.

        Inputs:
            self: Initialized explicitly approved writer; caller must separately verify live admission.
        Outputs:
            dict: Minimal write-response-only summary, never a verified trigger or trial result.
        """
        return self._write("Suspended")

    def restore_enabled(self):
        """Request fixed Enabled recovery at most three times, never verify restoration from a write.

        Inputs:
            self: Writer after a possible change, or a separately reviewed recovery-only scope.
        Outputs:
            dict: Minimal transport acknowledgment; independent scoped readback remains mandatory.
        """
        return self._write("Enabled")

    def _write(self, status):
        """Consume a bounded attempt, retain pending action and dispatch only fixed PutBucketVersioning.

        Inputs:
            self: Single-thread writer with validated actual identity and private intent.
            status: Maintained literal Suspended or Enabled selected by public fixed methods.
        Outputs:
            dict: Write acknowledgment with all restoration/runner/research gates closed.
                Ambiguous responses/errors consume their attempt and raise a generic error. After
                possible mutation, bounded Enabled requests can proceed despite journal outage.
        """
        if self._closed or self._busy or threading.get_ident() != self._thread or not self._identity_verified or self._now() >= self._deadline:
            raise ValueError("Writer closed, busy, wrong-thread or outside reviewed lifetime")
        if status == "Suspended":
            if self._scope["mode"] != "change_and_restore" or self._suspensions or self._restorations:
                raise ValueError("Suspension unavailable or already consumed")
            self._suspensions += 1
        elif status == "Enabled":
            if self._restorations >= 3 or (not self._suspensions and self._scope["mode"] != "recovery_only"):
                raise ValueError("Recovery-only admission or prior possible mutation required")
            self._restorations += 1
        else:
            raise ValueError("Fixed versioning statuses only")
        self._busy = True
        request = copy.deepcopy(self._intent["requests"]["proposed_mutation" if status == "Suspended" else "restoration"])
        try:
            self._retain({"kind": "versioning_pending", "request": request,
                "suspensions": self._suspensions, "restorations": self._restorations}, required=status == "Suspended")
            if status == "Suspended" and self._scope["session_mode"] == "bound_session":
                self._retain({"kind": "prechange_session_budget", "assessment":
                    self._session.check_writer_budget(self._scope["run_id"])}, required=True)
                self._prechange_check()
                # Retention/admission can consume time; recheck before activating the wire guard.
                self._session.check_writer_budget(self._scope["run_id"])
            started, before = self._clock(), self._now()
            if before >= self._deadline:
                raise ValueError("Writer lifetime elapsed before wire admission")
            self._active_status = status
            self._guard.active, self._guard.sent = True, 0
            try:
                # Explicit SDK call supports deterministic IAM analysis; no caller parameters or MFA.
                response = self._s3.put_bucket_versioning(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT,
                    VersioningConfiguration={"Status": status})
            finally:
                self._guard.active = False
                self._active_status = None
            if not self._retain({"kind": "versioning_response", "request": request, "response": response,
                    "started_at": started, "finished_at": self._clock(), "elapsed_ns": self._now() - before}):
                raise ValueError("Versioning response retention incomplete")
            self._success(response)
            return {"phase": "development", "status": "write_response_only", "requested_status": status,
                    "restoration_verified": False, "live_execution_allowed": False, "research_trials": 0}
        except BaseException as error:
            record = {"kind": "versioning_attempt_uncertain", "request": request, "error_type": type(error).__name__}
            if isinstance(error, ClientError):
                record["provider_response"] = error.response
            self._retain(record)
            if isinstance(error, (KeyboardInterrupt, SystemExit, CancelledError)):
                raise KeyboardInterrupt("Versioning attempt interrupted; independent recovery review required") from None
            raise ValueError("Versioning attempt uncertain; inspect encrypted evidence and verify state") from None
        finally:
            self._guard.active, self._busy = False, False
            self._active_status = None

    def summary(self):
        """Expose minimal transport counters while leaving independent live admission gates closed.

        Inputs:
            self: Initialized or closed writer; no provider response is exposed.
        Outputs:
            dict: Attempt counts and journal status only; no source/credential/restoration proof.
        """
        return {"run_id": self._scope["run_id"], "suspensions": self._suspensions, "restorations": self._restorations,
                "identity_verified": self._identity_verified, "journal_complete": self._journal_complete,
                "credential_coverage_verified": False, "restoration_verified": False,
                "live_execution_allowed": False, "research_trials": 0}

    def close(self):
        """Disable sends and release SDK handlers/sockets without making a recovery request.

        Inputs:
            self: Possibly partially initialized writer owning client/guard references.
        Outputs:
            None: Marks closed, unregisters handlers and closes clients best-effort. No AWS call,
                automatic rollback, restoration claim or lock release occurs.
        """
        self._closed = True
        for service, (client, guard) in self._clients.items():
            guard.active = False
            try:
                client.meta.events.unregister(f"before-send.{service}", guard.before_send)
                if service == "s3" and self._scope["session_mode"] == "bound_session":
                    client.meta.events.unregister("before-send.s3", self._prechange_wire_budget)
                client.close()
            except Exception:
                pass
