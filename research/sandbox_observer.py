"""Offline request manifest and receipt adapter for a future sandbox observer; no AWS IO."""
import copy
from datetime import datetime

from research.sandbox_emptiness import ACCOUNT, BUCKET, LISTINGS, REGION, verify_sandbox_prestate
from research.sandbox_readiness import OPERATIONS

ROLE = "dissertation-sandbox-observer"


def observer_requests():
    """Describe the complete fixed read-only S3 observation without creating clients.

    Inputs:
        None: Uses the dedicated development bucket, expected owner and Ohio region.
    Outputs:
        list: Eleven fresh request descriptions; no IO, credentials or AWS calls.
    """
    requests = []
    # Current objects serve both predicates; do not issue that listing twice.
    for operation in ["get_bucket_location", "get_bucket_tagging"] + sorted((OPERATIONS | set(LISTINGS)) - {"get_bucket_location", "get_bucket_tagging"}):
        params = {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}
        if operation in LISTINGS:
            params[LISTINGS[operation][0]] = 1000
        requests.append({"service": "s3", "operation": operation, "region": REGION,
                         "request": params})
    return requests


def utc_clock(value):
    """Parse a retained explicit UTC clock without inferring local time.

    Inputs:
        value: ISO 8601 timestamp string ending in Z.
    Outputs:
        datetime: Parsed timezone-aware clock; malformed or non-UTC input raises ValueError.
            No IO or clock reads occur.
    """
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Explicit UTC receipt clock required")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("Malformed receipt clock") from error


def assemble_observer_prestate(identity, receipts):
    """Bind supplied ordered request receipts to the fixed observer and existing predicates.

    Inputs:
        identity: Supplied STS response for the dedicated assumed observer role in this account.
        receipts: Eleven ordered envelopes matching observer_requests, each additionally holding
            response, started_at, finished_at and elapsed_ns. Clocks are supplied, not trusted.
    Outputs:
        dict: Copied private raw receipts, metadata/listings usable by recovery-intent preparation,
            and administrative checks. No IO, AWS calls, approval or source authentication.
            Invalid identity, requests, clocks, failed responses or pre-state raises ValueError.
    """
    prefix = f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/"
    if not isinstance(identity, dict) or identity.get("Account") != ACCOUNT:
        raise ValueError("Expected observer account required")
    arn = identity.get("Arn")
    if not isinstance(arn, str) or not arn.startswith(prefix) or not arn[len(prefix):] or "/" in arn[len(prefix):]:
        raise ValueError("Dedicated assumed observer role required")
    requests = observer_requests()
    if not isinstance(receipts, list) or len(receipts) != len(requests):
        raise ValueError("Complete bounded observation required")
    metadata, listings = {}, {}
    previous_finish = None
    for expected, receipt in zip(requests, receipts):
        if not isinstance(receipt, dict) or set(receipt) != set(expected) | {"response", "started_at", "finished_at", "elapsed_ns"}:
            raise ValueError("Exact observer receipt envelope required")
        if any(receipt[key] != value for key, value in expected.items()):
            raise ValueError("Observer request differs from fixed scope")
        # JSON equality alone treats booleans as integers; page limits must be actual integers.
        operation = expected["operation"]
        if operation in LISTINGS and type(receipt["request"][LISTINGS[operation][0]]) is not int:
            raise ValueError("Integer page ceiling required")
        started, finished = utc_clock(receipt["started_at"]), utc_clock(receipt["finished_at"])
        if finished < started or previous_finish is not None and started < previous_finish:
            raise ValueError("Ordered nonoverlapping receipt clocks required")
        if type(receipt["elapsed_ns"]) is not int or receipt["elapsed_ns"] < 0:
            raise ValueError("Nonnegative monotonic duration required")
        previous_finish = finished
        response = receipt["response"]
        status = response.get("ResponseMetadata") if isinstance(response, dict) else None
        if not isinstance(status, dict) or type(status.get("HTTPStatusCode")) is not int or status["HTTPStatusCode"] != 200 or "Error" in response:
            raise ValueError("Successful retained SDK response required")
        if not isinstance(status.get("RequestId"), str) or not status["RequestId"].strip():
            raise ValueError("Retained service request identifier required")
        if operation in OPERATIONS:
            metadata[operation] = copy.deepcopy(response)
        if operation in LISTINGS:
            listings[operation] = copy.deepcopy({"region": REGION, "request": receipt["request"], "response": response})
    report = verify_sandbox_prestate(metadata, listings)
    # Internal consistency does not authenticate the provider, clocks or absence of concurrent writes.
    return {"version": "sandbox-observer-prestate-v0.1", "phase": "development",
            "identity": copy.deepcopy(identity), "receipts": copy.deepcopy(receipts),
            "metadata": metadata, "listings": listings, "administrative_report": report,
            "source_identity_verified": False, "source_freshness_verified": False,
            "live_execution_allowed": False, "research_trials": 0}
