"""Development recovery-intent preparation; retains encrypted pre-state and never calls AWS."""
import copy
import hashlib
import json
import os

from research.aws_reader import EncryptedArchive, sync_archive_directory
from research.catalog import canonical_sha256
from research.contracts import PROPOSAL_SHA256
from research.sandbox_emptiness import ACCOUNT, BUCKET, REGION, verify_sandbox_prestate
from research.scenario_lock import inspect_sandbox_lock, validate_run_id
from research.timing import require_sha256

VERSION = "sandbox-recovery-intent-v0.1"


def build_recovery_intent(run_id, metadata, listings, review_manifest_sha256, source_sha256, recipient_sha256):
    """Build an exact development-only recovery record from supplied administrative evidence.

    Inputs:
        run_id: Retained 32-character lowercase hexadecimal local run identifier.
        metadata: Nine-operation protection response map for the fixed Enabled sandbox.
        listings: Three unfiltered full-bucket empty listing receipts for that same sandbox.
        review_manifest_sha256: External review-manifest content hash; syntax is not approval.
        source_sha256: Externally pinned source-bundle content hash; not verified by this function.
        recipient_sha256: External normalized public PEM recipient fingerprint.
    Outputs:
        dict: Private JSON-compatible record containing copied raw pre-state, fixed proposed
            mutation/restoration request descriptions and closed execution/scientific gates.
            No IO or AWS calls. Invalid scope/pre-state/hash arguments raise ValueError.
    """
    validate_run_id(run_id)
    for digest in (review_manifest_sha256, source_sha256, recipient_sha256):
        require_sha256(digest)
    prestate = verify_sandbox_prestate(metadata, listings)
    if metadata["get_bucket_versioning"].get("MFADelete", "Disabled") != "Disabled":
        raise ValueError("MFA Delete enabled or unknown is outside this proposed transition")
    # Deep copies keep later caller edits from rewriting the proposed recovery configuration.
    evidence = copy.deepcopy({"metadata": metadata, "listings": listings})
    requests = {}
    for label, status in (("proposed_mutation", "Suspended"), ("restoration", "Enabled")):
        requests[label] = {"service": "s3", "operation": "PutBucketVersioning", "region": REGION,
                           "params": {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT,
                                      "VersioningConfiguration": {"Status": status}}}
    return {"kind": "sandbox_recovery_intent", "version": VERSION, "phase": "development",
            "proposal_sha256": PROPOSAL_SHA256, "run_id": run_id, "account": ACCOUNT, "region": REGION, "bucket": BUCKET,
            "review_manifest_sha256": review_manifest_sha256, "source_sha256": source_sha256,
            "recipient_sha256": recipient_sha256, "prestate": evidence,
            "prestate_sha256": canonical_sha256(evidence), "administrative_report": prestate,
            "requests": requests, "live_execution_allowed": False,
            "recovery_credentials_verified": False, "restoration_verified": False,
            "research_trials": 0}


def verify_recovery_intent(record, run_id, review_manifest_sha256, source_sha256, recipient_sha256):
    """Validate decrypted intent against independently retained run and provenance pins.

    Inputs:
        record: Already-decrypted private JSON record; decryption and authentication are external.
        run_id: Expected local run identifier from a trusted retained run record.
        review_manifest_sha256: Independently retained review-manifest fingerprint.
        source_sha256: Independently retained source-bundle fingerprint.
        recipient_sha256: Independently retained normalized public PEM fingerprint.
    Outputs:
        str: Canonical intent SHA-256 after exact reconstruction. No IO or AWS calls; rejects
            altered scope/actions/gates/extra fields. Does not authenticate caller-supplied data.
    """
    if not isinstance(record, dict) or not isinstance(record.get("prestate"), dict) or set(record["prestate"]) != {"metadata", "listings"}:
        raise ValueError("Complete decrypted recovery intent required")
    expected = build_recovery_intent(run_id, record["prestate"]["metadata"],
                                    record["prestate"]["listings"], review_manifest_sha256,
                                    source_sha256, recipient_sha256)
    # Canonical hashes distinguish false from 0 and reject nonfinite JSON values.
    if canonical_sha256(record) != canonical_sha256(expected):
        raise ValueError("Recovery intent differs from the fixed scope or retained pins")
    return canonical_sha256(expected)


def retain_recovery_intent(lock_root, run_id, metadata, listings, review_manifest_sha256,
                           source_sha256, recipient_sha256, certificate, openssl, timeout_seconds):
    """Persist one encrypted intent beneath an intact matching lock, retaining failures.

    Inputs:
        lock_root: Canonical private directory containing the fixed sandbox's owner-only lock.
        run_id: Matching retained local run identifier.
        metadata: Supplied Enabled sandbox protection response map.
        listings: Supplied full-empty listing receipts.
        review_manifest_sha256: External manifest content pin; not proof of human approval.
        source_sha256: External source content pin; not authenticated here.
        recipient_sha256: Expected fingerprint of the normalized public recipient certificate.
        certificate: Existing public RSA certificate path; never a private key or password.
        openssl: Explicit OpenSSL 3 executable path used by the existing archive writer.
        timeout_seconds: Integer 1..300 deadline for each local cryptographic subprocess.
    Outputs:
        dict: Private commitment after synchronized encrypted retention and commitment write.
            Creates recovery-intent/ inside the lock; failure retains partial files and blocks
            owner-only release/reuse. No AWS calls, automatic lock release or execution event.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("Bounded integer crypto timeout required")
    record = build_recovery_intent(run_id, metadata, listings, review_manifest_sha256,
                                   source_sha256, recipient_sha256)
    lock = inspect_sandbox_lock(lock_root, run_id)
    archive = EncryptedArchive(lock / "recovery-intent", certificate, openssl, timeout_seconds)
    actual_recipient = hashlib.sha256(archive.cert.read_bytes()).hexdigest()
    if actual_recipient != recipient_sha256:
        raise ValueError("Normalized recipient differs from the external fingerprint")
    # Persist only ciphertext for raw evidence; public commitments carry hashes and identifiers.
    receipt = archive.write(record)
    commitment = {"version": VERSION, "run_id": run_id, "recipient_sha256": recipient_sha256,
                  "intent_sha256": canonical_sha256(record), "ciphertext": receipt,
                  "live_execution_allowed": False}
    path = archive.root / "commitment.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(json.dumps(commitment, sort_keys=True, allow_nan=False).encode())
        handle.flush()
        os.fsync(handle.fileno())
    sync_archive_directory(archive.root)
    return commitment
