"""Offline verification of bounded observer archives; plaintext stays in caller-owned memory."""
import copy
from pathlib import Path

from research.archive_ingestion import read_archive_records
from research.catalog import canonical_sha256
from research.native_capture import snapshot_fingerprint
from research.sandbox_observer import assemble_observer_prestate, observer_requests, utc_clock
from research.sandbox_operator import preview_sandbox_scope
from research.scenario_lock import private_lock_root
from research.timing import require_sha256


def require_receipts(receipts, count):
    """Require canonical contiguous ciphertext receipts for a known successful archive shape.

    Inputs:
        receipts: Ordered filename/hash dictionaries from the bounded authenticated reader.
        count: Exact expected record count for this archive.
    Outputs:
        None: Rejects changed counts, schemas, filenames or digest syntax; performs no IO.
    """
    if not isinstance(receipts, list) or len(receipts) != count:
        raise ValueError("Exact observer ciphertext receipt count required")
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict) or set(receipt) != {"file", "ciphertext_sha256"} or receipt["file"] != f"record-{index:05d}.cms":
            raise ValueError("Canonical observer ciphertext sequence required")
        require_sha256(receipt["ciphertext_sha256"])


def verify_sandbox_records(scope, approved_scope_sha256, fingerprint, journal, journal_receipts, capture, capture_receipts):
    """Cross-check decrypted archives against independent scope/inventory pins and pre-state rules.

    Inputs:
        scope: Independently retained approved historical operator scope, never inferred from data.
        approved_scope_sha256: Trusted hash of that approved scope; not proof of human approval.
        fingerprint: Independently retained capture ciphertext inventory fingerprint.
        journal: Two authenticated decoded operator records, retained in memory only.
        journal_receipts: Their two ordered ciphertext receipts from the bounded reader.
        capture: Fifteen authenticated decoded capture records, retained in memory only.
        capture_receipts: Their fifteen ordered ciphertext receipts from the bounded reader.
    Outputs:
        dict: Minimal consistency report with source/freshness/execution/scientific gates closed.
            No IO, plaintext export or input mutation. Rejects substituted records, phases,
            requests, timing, pre-state or completion chains. Does not authenticate the sender,
            attest host clocks, establish atomic emptiness or validate a research trial.
    """
    preview = preview_sandbox_scope(scope)
    require_sha256(approved_scope_sha256)
    require_sha256(fingerprint)
    if preview["scope_sha256"] != approved_scope_sha256:
        raise ValueError("Approved observer scope mismatch")
    require_receipts(journal_receipts, 2)
    require_receipts(capture_receipts, 15)
    if not isinstance(journal, list) or len(journal) != 2 or not isinstance(capture, list) or len(capture) != 15:
        raise ValueError("Complete successful observer archives required")
    calculated = canonical_sha256({"recipient_sha256": scope["capture"]["recipient_sha256"], "receipts": capture_receipts})
    if calculated != fingerprint:
        raise ValueError("Capture differs from retained inventory pin")
    expected_journal = [
        {"kind": "sandbox_operator_scope", "scope": scope, "scope_sha256": approved_scope_sha256},
        {"kind": "sandbox_operator_status", "worker_status": "success", "ciphertext_fingerprint": fingerprint,
         "scope_sha256": approved_scope_sha256, "capture_completion_independently_verified": False,
         "live_execution_allowed": False, "research_trials": 0}]
    if canonical_sha256(journal) != canonical_sha256(expected_journal):
        raise ValueError("Operator journal binding or success status mismatch")
    opening = {"kind": "sandbox_capture_scope", "scope": scope["capture"],
               "scope_sha256": canonical_sha256(scope["capture"]), "operator_scope_sha256": approved_scope_sha256}
    if canonical_sha256(capture[0]) != canonical_sha256(opening):
        raise ValueError("Capture opening differs from approved operator")
    plan = [{"service": "sts", "operation": "get_caller_identity", "region": "us-east-2", "request": {}}] + observer_requests()
    receipts, previous_finish, elapsed = [], None, 0
    for record, expected in zip(capture[1:13], plan):
        if not isinstance(record, dict) or set(record) != {"kind", "phase", "receipt"} or record["kind"] != "sandbox_observer_receipt" or record["phase"] != "development":
            raise ValueError("Exact development receipt record required")
        receipt = record["receipt"]
        if not isinstance(receipt, dict) or set(receipt) != set(expected) | {"started_at", "finished_at", "elapsed_ns", "response"} or any(receipt[key] != value for key, value in expected.items()):
            raise ValueError("Observer receipt request mismatch")
        started, finished = utc_clock(receipt["started_at"]), utc_clock(receipt["finished_at"])
        if finished < started or previous_finish is not None and started < previous_finish or type(receipt["elapsed_ns"]) is not int or receipt["elapsed_ns"] < 0:
            raise ValueError("Ordered observer receipt clocks required")
        elapsed += receipt["elapsed_ns"]
        previous_finish = finished
        receipts.append(receipt)
    if elapsed >= 120_000_000_000:
        raise ValueError("SDK durations exceed successful capture deadline")
    identity = receipts[0]["response"]
    status = identity.get("ResponseMetadata", {}) if isinstance(identity, dict) else {}
    if not isinstance(status, dict) or type(status.get("HTTPStatusCode")) is not int or status["HTTPStatusCode"] != 200 or not isinstance(status.get("RequestId"), str) or not status["RequestId"].strip() or "Error" in identity:
        raise ValueError("Successful attributed observer identity receipt required")
    prestate = assemble_observer_prestate(identity, receipts[1:])
    if canonical_sha256(capture[13]) != canonical_sha256({"kind": "sandbox_observer_prestate", "record": prestate}):
        raise ValueError("Retained pre-state differs from reconstructed receipts")
    completion = {"kind": "sandbox_capture_completion", "phase": "development", "complete": True,
                  "scope_sha256": canonical_sha256(scope["capture"]), "receipts": capture_receipts[:-1],
                  "live_execution_allowed": False, "research_trials": 0}
    if canonical_sha256(capture[14]) != canonical_sha256(completion):
        raise ValueError("Capture completion chain or phase mismatch")
    return {"version": "sandbox-capture-verification-v0.1", "phase": "development", "run_id": scope["run_id"],
            "scope_sha256": approved_scope_sha256, "ciphertext_fingerprint": fingerprint,
            "capture_records": 15, "journal_records": 2, "receipts_consistent": True,
            "bucket_protections_match_deployment": True, "supplied_full_bucket_listings_empty": True,
            "source_identity_independently_attested": False, "source_freshness_verified": False,
            "concurrent_writes_excluded": False, "trigger_verified": False, "ml_ready": False,
            "formal_trial_authorized": False, "live_execution_allowed": False, "research_trials": 0}


def read_verified_sandbox_prestate(root, scope, approved_scope_sha256, fingerprint, decrypt_record):
    """Read and verify private archives, returning raw pre-state only to a trusted in-memory caller.

    Inputs:
        root: Canonical private operator output directory, equal to the approved declared path.
        scope: Independently retained approved historical operator scope.
        approved_scope_sha256: Trusted scope hash retained outside the capture.
        fingerprint: Trusted capture ciphertext inventory fingerprint retained outside the archives.
        decrypt_record: Existing trusted callback returning authenticated plaintext bytes in memory.
    Outputs:
        dict: Private report/prestate/identity-receipt bundle; never print or serialize its raw
            fields as plaintext. No plaintext files, AWS calls or input changes.
            Reads at most two journal records with 1 MiB and fifteen capture records with 4 MiB
            cumulative ciphertext/plaintext budgets respectively. Snapshot inventory reads use
            the existing 64 MiB ceiling. Rejects inventory changes before/after decryption.
            Current capture source need not equal historical source; no live execution is allowed.
    """
    preview = preview_sandbox_scope(scope)
    if preview["scope_sha256"] != approved_scope_sha256:
        raise ValueError("Trusted observer scope required before decryption")
    require_sha256(fingerprint)
    root = private_lock_root(root)
    if root != Path(scope["output_root"]):
        raise ValueError("Observer archive path differs from approved scope")
    recipient = scope["capture"]["recipient_sha256"]
    before_capture = snapshot_fingerprint(root / "capture", recipient)
    before_journal = snapshot_fingerprint(root / "journal", recipient)
    if before_capture != fingerprint:
        raise ValueError("Observer inventory pin differs before decryption")
    journal, journal_receipts = read_archive_records(root / "journal", decrypt_record, recipient, 2, 1048576)
    capture, capture_receipts = read_archive_records(root / "capture", decrypt_record, recipient, 15, 4194304)
    result = verify_sandbox_records(scope, approved_scope_sha256, fingerprint, journal, journal_receipts, capture, capture_receipts)
    if snapshot_fingerprint(root / "capture", recipient) != before_capture or snapshot_fingerprint(root / "journal", recipient) != before_journal:
        raise ValueError("Observer inventories changed during verification")
    return {"report": result, "prestate": copy.deepcopy(capture[13]["record"]),
            "identity_receipt": copy.deepcopy(capture[1]["receipt"])}


def verify_sandbox_archive(root, scope, approved_scope_sha256, fingerprint, decrypt_record):
    """Return only a minimal report from the shared bounded private pre-state reader.

    Inputs:
        root: Canonical private output directory equal to the approved scope path.
        scope: Independently retained approved historical operator scope.
        approved_scope_sha256: Trusted scope fingerprint retained outside the archive.
        fingerprint: Trusted capture inventory fingerprint retained outside the archive.
        decrypt_record: Existing authenticated callback returning plaintext bytes privately in memory.
    Outputs:
        dict: Minimal consistency report with scientific/execution gates closed. Uses the same
            two-record/1 MiB journal and fifteen-record/4 MiB capture limits as the private reader.
            No raw pre-state is returned, no plaintext file is written and no AWS call occurs.
    """
    return read_verified_sandbox_prestate(root, scope, approved_scope_sha256, fingerprint, decrypt_record)["report"]
