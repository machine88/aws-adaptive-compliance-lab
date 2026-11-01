"""Bounded offline recovery reading and encrypted restoration candidates; never unlocks or calls AWS."""
import copy
import hashlib
import json
import os

from research.archive_ingestion import private_bytes, reject_constant, unique_object
from research.aws_reader import EncryptedArchive, sync_archive_directory
from research.catalog import canonical_sha256
from research.recovery_intent import VERSION, build_recovery_intent, verify_recovery_intent
from research.sandbox_emptiness import BUCKET
from research.scenario_lock import private_lock_root, validate_run_id
from research.timing import require_sha256

MAX_BYTES = 4 * 1024 * 1024
AUDIT_VERSION = "sandbox-restoration-candidate-v0.1"


def private_directory(name, parent=None):
    """Open an owned private directory without following a final-component symlink.

    Inputs:
        name: Directory path or single child name when parent is supplied.
        parent: Optional already-open parent directory descriptor.
    Outputs:
        int: Open directory descriptor owned by the caller; raises on unsafe permissions.
            Caller must close it. Opens metadata only, with no cloud or credential access.
    """
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(descriptor)
        raise ValueError("Owned private recovery directory required")
    return descriptor


def strict_object(raw):
    """Decode a finite private JSON object without accepting duplicate field names.

    Inputs:
        raw: Bounded in-memory UTF-8 JSON bytes supplied by the private reader or decryptor.
    Outputs:
        dict: Decoded object; malformed, duplicate, nonfinite or non-object JSON raises.
            Does not print or persist plaintext.
    """
    value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("Private recovery JSON object required")
    return value


def read_recovery_intent(lock_root, run_id, decrypt_record, review_manifest_sha256,
                         source_sha256, recipient_sha256, commitment_sha256, max_bytes=MAX_BYTES):
    """Read and verify one retained intent through a caller-owned authenticated decryptor.

    Inputs:
        lock_root: Canonical private local root containing the fixed sandbox lock.
        run_id: Independently retained expected run identifier.
        decrypt_record: Trusted bounded callback accepting ciphertext bytes and returning plaintext bytes.
        review_manifest_sha256: Independent review-manifest content pin; not human approval proof.
        source_sha256: Independent source-bundle content pin.
        recipient_sha256: Independent normalized public PEM fingerprint.
        commitment_sha256: Independently retained canonical hash of the returned preparation commitment.
        max_bytes: Integer 1..4 MiB cumulative file/plaintext budget including rereads.
    Outputs:
        dict: Private in-memory record/commitment and their hashes, with execution disallowed.
            Never writes plaintext, calls AWS, opens private keys or releases a lock. Rejects
            partial/unsafe/changed files and mismatched external pins before accepting data.
    """
    validate_run_id(run_id)
    for pin in (review_manifest_sha256, source_sha256, recipient_sha256, commitment_sha256):
        require_sha256(pin)
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES:
        raise ValueError("Bounded recovery ingestion byte budget required")
    root_path = private_lock_root(lock_root)
    descriptors = []
    try:
        root = private_directory(root_path)
        descriptors.append(root)
        lock = private_directory(BUCKET + ".lock", root)
        descriptors.append(lock)
        lock_names = set(os.listdir(lock))
        if lock_names not in ({"owner.json", "recovery-intent"}, {"owner.json", "recovery-intent", "recovery-closure"}):
            raise ValueError("Unexpected or incomplete recovery lock contents")
        owner = private_bytes(lock, "owner.json", max_bytes)
        expected_owner = {"version": "sandbox-local-lock-v0.1", "bucket": BUCKET, "run_id": run_id}
        if canonical_sha256(strict_object(owner)) != canonical_sha256(expected_owner):
            raise ValueError("Recovery lock belongs to a different run")
        archive = private_directory("recovery-intent", lock)
        descriptors.append(archive)
        names = {"recipient-public.pem", "record-00000.cms", "commitment.json"}
        if set(os.listdir(archive)) != names:
            raise ValueError("Exact complete recovery archive required")
        used = len(owner)
        initial = {}
        for name in sorted(names):
            initial[name] = private_bytes(archive, name, max_bytes - used)
            used += len(initial[name])
        cert = initial["recipient-public.pem"]
        if b"PRIVATE KEY" in cert or hashlib.sha256(cert).hexdigest() != recipient_sha256:
            raise ValueError("Recovery public recipient differs from the trusted pin")
        commitment = strict_object(initial["commitment.json"])
        expected_keys = {"version", "run_id", "recipient_sha256", "intent_sha256", "ciphertext", "live_execution_allowed"}
        if (set(commitment) != expected_keys or commitment.get("version") != VERSION
                or commitment.get("run_id") != run_id or commitment.get("recipient_sha256") != recipient_sha256
                or commitment.get("live_execution_allowed") is not False
                or canonical_sha256(commitment) != commitment_sha256):
            raise ValueError("Recovery commitment differs from the retained external identity")
        require_sha256(commitment["intent_sha256"])
        ciphertext = initial["record-00000.cms"]
        expected_receipt = {"file": "record-00000.cms", "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest()}
        if commitment["ciphertext"] != expected_receipt:
            raise ValueError("Recovery ciphertext differs from its committed receipt")
        # Decryption stays behind the existing trusted boundary; no plaintext file is created.
        plaintext = decrypt_record(ciphertext)
        if not isinstance(plaintext, bytes) or len(plaintext) > max_bytes - used:
            raise ValueError("Invalid or excessive recovery plaintext")
        used += len(plaintext)
        record = strict_object(plaintext)
        intent_hash = verify_recovery_intent(record, run_id, review_manifest_sha256, source_sha256, recipient_sha256)
        if intent_hash != commitment["intent_sha256"]:
            raise ValueError("Decrypted recovery intent differs from its committed content")
        # Recheck contents after the callback so replacement during decryption fails closed.
        for name in sorted(names):
            content = private_bytes(archive, name, max_bytes - used)
            used += len(content)
            if content != initial[name]:
                raise ValueError("Recovery archive changed while being read")
        final_owner = private_bytes(lock, "owner.json", max_bytes - used)
        if final_owner != owner or set(os.listdir(lock)) != lock_names or set(os.listdir(archive)) != names:
            raise ValueError("Recovery lock changed while being read")
        # Named directory entries must still refer to the descriptors held throughout ingestion.
        for parent, name, opened in ((root, BUCKET + ".lock", lock), (lock, "recovery-intent", archive)):
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            original = os.fstat(opened)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError("Recovery directory was replaced during ingestion")
        current_root, original_root = os.stat(root_path, follow_symlinks=False), os.fstat(root)
        if (current_root.st_dev, current_root.st_ino) != (original_root.st_dev, original_root.st_ino):
            raise ValueError("Recovery root was replaced during ingestion")
        return {"record": record, "commitment": commitment, "intent_sha256": intent_hash,
                "commitment_sha256": commitment_sha256, "live_execution_allowed": False}
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def build_restoration_candidate(record, run_id, metadata, listings, review_manifest_sha256,
                                 source_sha256, recipient_sha256):
    """Compare supplied restoration metadata to the fixed protected baseline without certifying AWS.

    Inputs:
        record: Decrypted intent already bound to an independently retained commitment by the reader.
        run_id: Independent expected local run identifier.
        metadata: Supplied post-restoration nine-operation protection response map.
        listings: Supplied full-empty current/version/upload listing receipts.
        review_manifest_sha256: Independent review-manifest fingerprint.
        source_sha256: Independent source-bundle fingerprint.
        recipient_sha256: Independent normalized public PEM fingerprint.
    Outputs:
        dict: Private restoration candidate with copied post-state and hashes. No IO or AWS calls.
            Supplied technical consistency is true; actual restoration, freshness and execution
            remain unverified. Invalid intent or post-state raises rather than closing a run.
    """
    intent_hash = verify_recovery_intent(record, run_id, review_manifest_sha256, source_sha256, recipient_sha256)
    # Reuse the same exact protection, emptiness and MFA boundary as intent preparation.
    checked = build_recovery_intent(run_id, metadata, listings, review_manifest_sha256, source_sha256, recipient_sha256)
    return {"kind": "sandbox_restoration_candidate", "version": AUDIT_VERSION, "phase": "development",
            "run_id": run_id, "bucket": BUCKET, "intent_sha256": intent_hash,
            "poststate": copy.deepcopy(checked["prestate"]), "poststate_sha256": checked["prestate_sha256"],
            "administrative_report": checked["administrative_report"],
            "supplied_restoration_matches_baseline": True, "restoration_verified": False,
            "live_execution_allowed": False, "research_trials": 0}


def retain_restoration_candidate(lock_root, run_id, decrypt_record, metadata, listings,
                                  review_manifest_sha256, source_sha256, recipient_sha256,
                                  commitment_sha256, openssl, timeout_seconds):
    """Retain one encrypted restoration candidate linked to the independently pinned intent.

    Inputs:
        lock_root: Canonical private root containing the retained recovery intent and held lock.
        run_id: Independent expected run identifier.
        decrypt_record: Trusted bounded authenticated ciphertext-to-plaintext callback.
        metadata: Supplied post-restoration protection metadata, not a verified live source.
        listings: Supplied full-empty post-restoration listing receipts.
        review_manifest_sha256: Independent manifest content pin.
        source_sha256: Independent source-bundle content pin.
        recipient_sha256: Independent normalized public PEM fingerprint.
        commitment_sha256: Independent canonical preparation-commitment hash.
        openssl: Existing OpenSSL 3 executable path for the original public recipient.
        timeout_seconds: Integer 1..300 local cryptographic subprocess deadline.
    Outputs:
        dict: Private candidate commitment after synchronized encrypted retention. Creates an
            exclusive recovery-closure archive and retains partial failures. Never deletes old
            evidence, releases the lock, declares actual restoration or authorizes a live action.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("Bounded integer crypto timeout required")
    read = read_recovery_intent(lock_root, run_id, decrypt_record, review_manifest_sha256,
                               source_sha256, recipient_sha256, commitment_sha256)
    candidate = build_restoration_candidate(read["record"], run_id, metadata, listings,
                                            review_manifest_sha256, source_sha256, recipient_sha256)
    lock = private_lock_root(lock_root) / (BUCKET + ".lock")
    certificate = lock / "recovery-intent" / "recipient-public.pem"
    archive = EncryptedArchive(lock / "recovery-closure", certificate, openssl, timeout_seconds)
    if hashlib.sha256(archive.cert.read_bytes()).hexdigest() != recipient_sha256:
        raise ValueError("Restoration recipient differs from the independent pin")
    receipt = archive.write(candidate)
    commitment = {"version": AUDIT_VERSION, "run_id": run_id, "intent_sha256": read["intent_sha256"],
                  "intent_commitment_sha256": commitment_sha256, "candidate_sha256": canonical_sha256(candidate),
                  "ciphertext": receipt, "restoration_verified": False, "live_execution_allowed": False}
    descriptor = os.open(archive.root / "commitment.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(json.dumps(commitment, sort_keys=True, allow_nan=False).encode())
        handle.flush()
        os.fsync(handle.fileno())
    sync_archive_directory(archive.root)
    return commitment
