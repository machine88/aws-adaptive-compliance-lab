"""Opt-in temporary writer session broker; credentials stay in memory, never in retained evidence."""
import copy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import logging
from pathlib import Path
import threading
import time

import boto3
from botocore.config import Config

from research.catalog import canonical_sha256
from research.sandbox_capture import SendBudget, utc_now
from research.scenario_lock import validate_run_id
from research.timing import require_sha256, utc_timestamp
from research.writer_coverage import ROLE_ARN, VERSION as BUDGET_VERSION, assess_writer_session_budget

VERSION = "bound-writer-session-v0.1"
ACCOUNT, REGION = "653464153304", "us-east-2"
ROLE = "dissertation-sandbox-versioning"
SOURCE_ARN = f"arn:aws:iam::{ACCOUNT}:user/martin-morales-personal"
TARGET_ARN = f"arn:aws:iam::{ACCOUNT}:role/{ROLE}"


def session_source_sha256():
    """Fingerprint maintained session dependencies without resolving credentials.

    Inputs:
        No arguments; reads regular research Python sources and AWS package declarations.
    Outputs:
        str: Canonical source hash; no private evidence, profile, SDK or AWS access.
    """
    root = Path(__file__).resolve().parents[1]
    files = sorted(list((root / "research").glob("*.py")) + [root / "requirements-aws.txt"])
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Regular maintained session sources required")
    return canonical_sha256({str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in files})


def writer_session_scope(run_id, recipient_sha256, enable_session=False):
    """Declare a fixed authentication-only scope with actual execution disabled by default.

    Inputs:
        run_id: Independent 32-character hexadecimal development identifier.
        recipient_sha256: Independent public encryption-recipient fingerprint.
        enable_session: Explicit boolean for a separately approved authentication pass.
    Outputs:
        dict: Fixed source/profile/role/recipient scope; creates no session or evidence files.
    """
    validate_run_id(run_id)
    require_sha256(recipient_sha256)
    if type(enable_session) is not bool:
        raise ValueError("Explicit session enable boolean required")
    return {"version": VERSION, "phase": "development", "run_id": run_id,
            "source_sha256": session_source_sha256(), "recipient_sha256": recipient_sha256,
            "account": ACCOUNT, "region": REGION, "source_profile": "dissertation",
            "source_arn": SOURCE_ARN, "role_arn": TARGET_ARN, "role_session_name": ROLE,
            "duration_seconds": 3600, "setup_seconds": 120, "max_setup_calls": 3,
            "enable_session": enable_session}


class BoundWriterSession:
    """Trusted same-process session binding; no live writer integration or mutation method."""

    def __init__(self, scope, approved_scope_sha256, archive, session_factory=None,
                 clock=utc_now, monotonic_ns=time.monotonic_ns):
        """Verify source, assume one fixed role and verify identity using those exact returned credentials.

        Inputs:
            self: New single-thread session broker.
            scope: Current independently reviewed, explicitly enabled authentication-only scope.
            approved_scope_sha256: Independently retained exact scope hash; not human consent itself.
            archive: New empty pinned-recipient EncryptedArchive with a five-second crypto limit.
            session_factory: Optional trusted SDK-stub constructor; None uses boto3.Session.
            clock: Local UTC receipt clock; never asserts independent clock synchronization.
            monotonic_ns: Same-process nonnegative nanosecond clock for setup and expiry guards.
        Outputs:
            None: Opt-in only, source identity/one AssumeRole/bound identity calls and encrypted
                nonsecret evidence. Temporary key/token values stay solely in SDK/process memory.
                No bucket write, profile installation, credential file, refresh or fallback occurs.
                Any failure closes clients and returns a generic error without provider details.
        """
        require_sha256(approved_scope_sha256)
        if not isinstance(scope, dict) or type(scope.get("enable_session")) is not bool:
            raise ValueError("Exact reviewed session scope required")
        expected = writer_session_scope(scope.get("run_id"), scope.get("recipient_sha256"), scope["enable_session"])
        if canonical_sha256(scope) != canonical_sha256(expected) or canonical_sha256(scope) != approved_scope_sha256 or scope["enable_session"] is not True:
            raise ValueError("Current independently reviewed enabled session scope required")
        if archive.receipts or archive.timeout_seconds != 5 or hashlib.sha256(Path(archive.cert).read_bytes()).hexdigest() != scope["recipient_sha256"]:
            raise ValueError("New bounded pinned-recipient archive required")
        self._scope, self._archive = copy.deepcopy(scope), archive
        self._clock, self._monotonic = clock, monotonic_ns
        self._thread, self._closed, self._sequence = threading.get_ident(), False, 0
        self._clients, self._session = {}, None
        self._ready, self._writer_claimed = False, False
        self._last_ns = self._now()
        self._setup_deadline = self._last_ns + 120_000_000_000
        self._expires_ns = self._expires_at = self._anchor_wall = self._anchor_ns = None
        factory = boto3.Session if session_factory is None else session_factory
        try:
            self._retain({"kind": "session_scope", "scope": self._scope})
            self._before_setup()
            source = factory(profile_name="dissertation", region_name=REGION)
            profile = source._session.get_scoped_config()
            if set(profile) - {"login_session", "region", "output"} or not isinstance(profile.get("login_session"), str) or not profile["login_session"] or profile.get("region") != REGION:
                raise ValueError("Exact login-session source profile required")
            source_sts = source.client("sts", region_name=REGION, endpoint_url=f"https://sts.{REGION}.amazonaws.com",
                                       config=self._config(), use_ssl=True, verify=True)
            self._clients["source"] = source_sts
            budget = SendBudget(self._setup_deadline, self._now)
            source_sts.meta.events.register_first("before-send.sts", budget.before_send)
            budget.active, budget.sent = True, 0
            self._before_setup()
            identity = source_sts.get_caller_identity()
            budget.active = False
            self._success(identity)
            if identity.get("Account") != ACCOUNT or identity.get("Arn") != SOURCE_ARN:
                raise ValueError("Exact non-root source identity required")
            self._retain({"kind": "source_identity", "account": ACCOUNT, "arn": SOURCE_ARN,
                          "request_id": identity["ResponseMetadata"]["RequestId"]})
            self._before_setup()
            budget.active, budget.sent = True, 0
            response = source_sts.assume_role(RoleArn=TARGET_ARN, RoleSessionName=ROLE, DurationSeconds=3600)
            budget.active = False
            self._success(response)
            self._before_setup()
            received_wall, received_ns = utc_timestamp(self._clock()), self._now()
            server = parsedate_to_datetime(response["ResponseMetadata"]["HTTPHeaders"]["date"])
            if server.tzinfo is None or abs((received_wall - server).total_seconds()) > 5:
                raise ValueError("Session service/local receipt clocks disagree")
            assumed, credentials = response["AssumedRoleUser"], response["Credentials"]
            if assumed.get("Arn") != ROLE_ARN or not isinstance(assumed.get("AssumedRoleId"), str) or not assumed["AssumedRoleId"].endswith(":" + ROLE):
                raise ValueError("Exact returned assumed role required")
            expiration = credentials["Expiration"]
            if not isinstance(expiration, datetime) or expiration.tzinfo is None:
                raise ValueError("Explicit provider expiration required")
            self._expires_at = expiration.astimezone(timezone.utc).isoformat()
            self._anchor_wall, self._anchor_ns = received_wall, received_ns
            # Reserve service/local tolerance before admitting any later wire start.
            self._expires_ns = received_ns + int((expiration - received_wall).total_seconds() * 1_000_000_000) - 5_000_000_000
            record = {"kind": "assumed_session_metadata", "run_id": scope["run_id"], "role_arn": ROLE_ARN,
                      "assumed_role_id": assumed["AssumedRoleId"], "expires_at": self._expires_at,
                      "received_at": received_wall.isoformat(), "received_monotonic_ns": received_ns,
                      "server_date": server.astimezone(timezone.utc).isoformat(),
                      "request_id": response["ResponseMetadata"]["RequestId"]}
            self._source_record_sha256 = canonical_sha256(record)
            self._retain(record)
            self.assess_budget()
            self._before_setup()
            # Public SDK constructor binds every later client to exactly this non-refreshing session.
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                if not isinstance(credentials.get(key), str) or not credentials[key]:
                    raise ValueError("Complete temporary credential response required")
            self._session = factory(aws_access_key_id=credentials["AccessKeyId"],
                                    aws_secret_access_key=credentials["SecretAccessKey"],
                                    aws_session_token=credentials["SessionToken"], region_name=REGION)
            del credentials, response
            bound = self.client("sts")
            bound_budget = SendBudget(self._setup_deadline, self._now)
            bound.meta.events.register_first("before-send.sts", bound_budget.before_send)
            try:
                bound_budget.active = True
                actual = bound.get_caller_identity()
            finally:
                bound_budget.active = False
                bound.meta.events.unregister("before-send.sts", bound_budget.before_send)
            self._success(actual)
            if actual.get("Account") != ACCOUNT or actual.get("Arn") != ROLE_ARN or actual.get("UserId") != assumed["AssumedRoleId"]:
                raise ValueError("Bound session actual identity differs from returned session")
            self._retain({"kind": "bound_identity", "account": ACCOUNT, "arn": ROLE_ARN,
                          "user_id": actual["UserId"], "request_id": actual["ResponseMetadata"]["RequestId"]})
            self._before_setup()
            self.assess_budget()
            source_sts.close()
            del self._clients["source"]
            self._ready = True
        except BaseException:
            self.close()
            raise ValueError("Writer session setup failed; no live admission") from None

    def evidence_binding(self):
        """Expose only the metadata pins needed for independent encrypted-record readback.

        Inputs:
            self: Fully initialized active broker with verified actual bound identity.
        Outputs:
            dict: Run, scope and retained nonsecret source-record fingerprints. No keys, tokens,
                raw provider response, write permission or formal-trial authority are returned.
        """
        self._now()
        if not self._ready:
            raise ValueError("Initialized bound session required")
        return {"run_id": self._scope["run_id"], "session_scope_sha256": canonical_sha256(self._scope),
                "source_record_sha256": self._source_record_sha256}

    def claim_writer(self, run_id, recipient_sha256):
        """Bind this initialized session to at most one writer with matching run and recipient.

        Inputs:
            self: Fully initialized broker; no refresh or replacement session is created.
            run_id: Independently reviewed writer run identifier.
            recipient_sha256: Independently reviewed writer public-recipient fingerprint.
        Outputs:
            dict: Nonsecret session/evidence linkage plus fresh timing assessment. Consumes the
                one-writer claim before assessment so failed setup cannot silently reset a run.
                No cloud call, write authorization or independent source-state proof is supplied.
        """
        self._now()
        if not self._ready or self._writer_claimed or run_id != self._scope["run_id"] or recipient_sha256 != self._scope["recipient_sha256"] or self._scope["source_sha256"] != session_source_sha256():
            raise ValueError("Unused matching bound writer session required")
        self._writer_claimed = True
        assessment = self.check_writer_budget(run_id)
        return {"kind": "bound_writer_session_claim", "run_id": run_id,
                "session_scope_sha256": canonical_sha256(self._scope),
                "source_record_sha256": self._source_record_sha256,
                "budget_assessment": assessment, "live_execution_allowed": False, "research_trials": 0}

    def check_writer_budget(self, run_id):
        """Recheck full pre-change time coverage for the single claimed writer.

        Inputs:
            self: Initialized broker already claimed by exactly one writer.
            run_id: Independent writer run identifier, required to match the original session scope.
        Outputs:
            dict: Fresh conservative assessment from the same non-refreshing session; no AWS IO.
                Intended before suspension only, never as a full-horizon prerequisite for recovery.
        """
        if not self._ready or not self._writer_claimed or run_id != self._scope["run_id"]:
            raise ValueError("Matching claimed writer required")
        return self.assess_budget()

    def _now(self):
        """Reject malformed, backward or cross-thread monotonic use.

        Inputs:
            self: Broker owning the clock and thread; initial invocation may precede last timestamp.
        Outputs:
            int: Current monotonic timestamp, or generic ValueError before another request.
        """
        # SDK debug records can include raw STS responses or signed request tokens.
        namespaces = ("boto3", "botocore", "urllib3", "awscrt")
        loggers = [logging.getLogger(name) for name in namespaces]
        loggers += [logger for name, logger in list(logging.Logger.manager.loggerDict.items())
                    if isinstance(logger, logging.Logger) and name.startswith(tuple(name + "." for name in namespaces))]
        if any(logger.isEnabledFor(logging.DEBUG) for logger in loggers):
            raise ValueError("SDK debug logging must remain disabled")
        value = self._monotonic()
        if threading.get_ident() != self._thread or self._closed or type(value) is not int or value < 0 or value < getattr(self, "_last_ns", 0):
            raise ValueError("Active same-thread monotonic session required")
        self._last_ns = value
        return value

    def _before_setup(self):
        """Enforce setup deadline even when the SDK is stubbed or encrypted retention was slow.

        Inputs:
            self: Active broker with fixed setup deadline.
        Outputs:
            None: Raises before proceeding after the deadline; no IO.
        """
        if self._now() >= self._setup_deadline:
            raise ValueError("Session setup deadline exceeded")

    def _config(self):
        """Construct fixed HTTPS client behavior without provider retries or endpoint overrides.

        Inputs:
            self: Broker; configuration construction reads no credential values.
        Outputs:
            Config: Fixed regional no-proxy, one-attempt SDK configuration.
        """
        return Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1, "mode": "standard"},
                      ignore_configured_endpoint_urls=True, proxies={}, use_fips_endpoint=False,
                      use_dualstack_endpoint=False, s3={"use_accelerate_endpoint": False})

    def _success(self, response):
        """Require attributed successful SDK metadata without retaining arbitrary response contents.

        Inputs:
            self: Broker interpreting a response inside its fixed setup sequence.
            response: In-memory SDK response; may contain secrets and must never be logged.
        Outputs:
            None: Rejects HTTP errors, error frames and missing request attribution.
        """
        metadata = response.get("ResponseMetadata", {})
        if response.get("Error") or metadata.get("HTTPStatusCode") != 200 or not isinstance(metadata.get("RequestId"), str) or not metadata["RequestId"]:
            raise ValueError("Attributed successful session response required")

    def _retain(self, record):
        """Require durable ordered encrypted acknowledgments for allowlisted nonsecret records.

        Inputs:
            self: Broker with new private encrypted archive and sequence counter.
            record: Maintained metadata-only frame; no raw STS response or credential fields.
        Outputs:
            None: Writes encrypted metadata; failure prevents session handoff.
        """
        receipt = self._archive.write({"phase": "development", **copy.deepcopy(record)})
        if not isinstance(receipt, dict) or set(receipt) != {"file", "ciphertext_sha256"} or receipt["file"] != f"record-{self._sequence:05d}.cms":
            raise ValueError("Ordered encrypted session receipt required")
        require_sha256(receipt["ciphertext_sha256"])
        self._sequence += 1

    def assess_budget(self):
        """Reevaluate expiration from the bound response and continuously checked process clocks.

        Inputs:
            self: Broker owning returned session expiration and original local clock anchor.
        Outputs:
            dict: Conservative metadata assessment with all live/provider-proof gates false;
                no SDK refresh, provider lookup or evidence mutation. Not a reusable permit.
        """
        now_ns, wall = self._now(), utc_timestamp(self._clock())
        if self._anchor_ns is None or abs((wall - self._anchor_wall).total_seconds() * 1_000_000_000 - (now_ns - self._anchor_ns)) > 1_000_000_000:
            raise ValueError("Bound session clocks are inconsistent")
        # Charge five extra seconds for the accepted service/local clock disagreement.
        sample = {"version": BUDGET_VERSION, "phase": "development", "run_id": self._scope["run_id"],
                  "role_arn": ROLE_ARN, "expires_at": (utc_timestamp(self._expires_at) - timedelta(seconds=5)).isoformat(),
                  "sampled_at": wall.isoformat(), "sample_monotonic_ns": now_ns,
                  "source_record_sha256": self._source_record_sha256}
        return assess_writer_session_budget(sample, canonical_sha256(sample), self._scope["run_id"], wall.isoformat(), now_ns)

    def _before_send(self, request, **kwargs):
        """Block sends after closure, expiration reserve or local clock inconsistency.

        Inputs:
            self: Broker owning session expiry and process clocks.
            request: Prepared SDK request; never inspected, copied or logged.
            kwargs: Unused SDK event metadata; never retained.
        Outputs:
            None: Rejects wire starts at/after conservative expiry; does not retry or refresh.
        """
        now_ns, wall = self._now(), utc_timestamp(self._clock())
        if now_ns >= self._expires_ns or abs((wall - self._anchor_wall).total_seconds() * 1_000_000_000 - (now_ns - self._anchor_ns)) > 1_000_000_000:
            raise ValueError("Bound session expired or clock inconsistent")

    def client(self, service):
        """Create/cache only fixed STS or S3 clients from the same in-memory static session.

        Inputs:
            self: Broker with complete returned temporary credentials; no fallback profile.
            service: Literal sts or s3, restricted for future reviewed writer integration.
        Outputs:
            object: Cached SDK client with a broker lifetime wire guard; calls no service method.
                Trusted callers still need writer attempt limits and explicit live approval.
        """
        self._before_send(None)
        if service not in {"sts", "s3"} or self._session is None:
            raise ValueError("Bound STS/S3 session required")
        if service not in self._clients:
            client = self._session.client(service, region_name=REGION, endpoint_url=f"https://{service}.{REGION}.amazonaws.com",
                                           config=self._config(), use_ssl=True, verify=True)
            self._clients[service] = client
            client.meta.events.register_first(f"before-send.{service}", self._before_send)
        return self._clients[service]

    def close(self):
        """Close owned sockets and disable future broker use without refreshing or revoking STS.

        Inputs:
            self: Broker; safe after partial setup or previous closure.
        Outputs:
            None: Closes clients and drops local session reference. Python cannot guarantee memory
                zeroization; AWS credentials are not revoked and previously held raw clients remain
                trusted application objects, not an adversarial isolation boundary.
        """
        self._closed = True
        for client in self._clients.values():
            client.close()
        self._clients.clear()
        self._session = None
