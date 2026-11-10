"""Offline native journal/source verification with independently pinned execution receipts."""
import copy
import math
import os
import stat
from datetime import timedelta
from pathlib import Path
from research.archive_ingestion import read_archive_records, verify_archive
from research.aws_reader import ACCOUNT, REGION, read_plan
from research.catalog import canonical_sha256
from research.prospective_runner import validate_runner_plan
from research.sampling import audit_sampling
from research.timing import require_sha256, utc_timestamp

# Exact event schemas prevent hidden scores, labels or replacement clocks entering this audit.
COMMON = {"kind", "phase", "run_id"}
EVENT_KEYS = {
    "run_opened": COMMON | {"plan_sha256", "collector_scope_sha256", "monotonic_seconds", "recorded_at", "trigger_verified"},
    "sample_due": COMMON | {"sample_id", "scheduled_at", "recorded_at", "monotonic_seconds"},
    "sample_skipped": COMMON | {"sample_id", "reason", "recorded_at", "monotonic_seconds"},
    "collector_failed": COMMON | {"sample_id", "recorded_at", "reason"},
    "sample_returned": COMMON | {"receipt", "invocation_started_monotonic_seconds", "invocation_recorded_monotonic_seconds"},
    "run_closed": COMMON | {"recorded_at", "plan_sha256", "audit_sha256", "monotonic_seconds", "prior_journal_receipts", "acquisition_schedule_met"},
    "snapshot_worker_failed": {"kind", "sample_id", "reason", "partial_output_retained"},
}


def verify_journal_sequence(records, receipts, plan, report):
    """Check scheduled event order and recorded wall/monotonic coordinates without trusting flags.

    Inputs:
        records: Authenticated decoded journal envelopes with native scope/report endpoints.
        receipts: Ordered ciphertext filename/hash receipts from the shared private reader.
        plan: Independently approved development plan already schema-validated.
        report: Exact runner report from the final native envelope.
    Outputs:
        list: Error sample identifiers; malformed/missing/extra/reordered events or clocks fail.
            Performs no IO, classification, trigger attestation or scientific exclusion decision.
    """
    for event in records[1:-1]:
        if event.get("kind") not in EVENT_KEYS or set(event) != EVENT_KEYS[event["kind"]]:
            raise ValueError("Exact native journal event schema required")
    first, last = records[1], records[-2]
    if first.get("kind") != "run_opened" or last.get("kind") != "run_closed":
        raise ValueError("Opened and closed runner journal required")
    plan_hash = canonical_sha256(plan)
    if first.get("plan_sha256") != plan_hash or last.get("plan_sha256") != plan_hash or first.get("collector_scope_sha256") != plan["collector_scope_sha256"] or first.get("trigger_verified") is not False:
        raise ValueError("Runner opening/closure differs from reviewed plan")
    origin_wall = utc_timestamp(first["recorded_at"])
    origin_mono = first["monotonic_seconds"]
    points = [(origin_wall, origin_mono)]
    position, returned, skipped, failures, engine_hashes = 2, [], [], [], [receipts[1]["ciphertext_sha256"]]

    def take(kind):
        """Consume exactly the next expected event, binding runner events to the run identity.

        Inputs:
            kind: Required event type at the current declared schedule position.
        Outputs:
            tuple: Event and ciphertext hash; advances the cursor or raises ValueError.
        """
        nonlocal position
        if position >= len(records)-1 or records[position].get("kind") != kind:
            raise ValueError("Native journal event order differs from reviewed schedule")
        event, digest = records[position], receipts[position]["ciphertext_sha256"]
        position += 1
        if kind != "snapshot_worker_failed":
            if event.get("phase") != "development" or event.get("run_id") != plan["run_id"]:
                raise ValueError("Runner event has wrong phase/run identity")
            engine_hashes.append(digest)
        return event, digest

    start = utc_timestamp(plan["sampling"]["trigger_at"])
    end = start + timedelta(seconds=1800)
    for sample in plan["sampling"]["samples"]:
        identifier = sample["sample_id"]
        target = start + timedelta(seconds=sample["offset_seconds"])
        due, _ = take("sample_due")
        due_wall = utc_timestamp(due["recorded_at"])
        if due.get("sample_id") != identifier or utc_timestamp(due["scheduled_at"]) != target or due_wall < target:
            raise ValueError("Sample due event differs from scheduled target")
        points.append((due_wall, due["monotonic_seconds"]))
        deadline = min(target+timedelta(seconds=plan["sampling"]["max_start_lateness_seconds"]), end)
        if records[position].get("kind") == "sample_skipped":
            event, _ = take("sample_skipped")
            when = utc_timestamp(event["recorded_at"])
            if event.get("sample_id") != identifier or event.get("reason") != "start_deadline_missed" or when < due_wall:
                raise ValueError("Invalid skipped-sample event")
            if not (when > deadline or (sample["offset_seconds"] < 0 and when >= start)):
                raise ValueError("Skipped target was not outside its reviewed start boundary")
            points.append((when, event["monotonic_seconds"]))
            skipped.append(identifier)
            continue
        failure, failure_hash = None, None
        if records[position].get("kind") in {"snapshot_worker_failed", "collector_failed"}:
            failure, failure_hash = take(records[position]["kind"])
            if failure.get("sample_id") != identifier:
                raise ValueError("Failure evidence belongs to another sample")
            if failure["kind"] == "snapshot_worker_failed":
                if set(failure) != {"kind", "sample_id", "reason", "partial_output_retained"} or failure["reason"] not in {"timeout", "failed"} or type(failure["partial_output_retained"]) is not bool:
                    raise ValueError("Unsupported native worker failure record")
            elif failure.get("reason") != "collector_exception":
                raise ValueError("Unsupported collector failure record")
        event, _ = take("sample_returned")
        receipt = event["receipt"]
        requested, recorded = utc_timestamp(receipt["request_started_at"]), utc_timestamp(receipt["recorded_at"])
        if receipt["sample_id"] != identifier or requested < due_wall or requested > deadline or (sample["offset_seconds"] < 0 and requested >= start):
            raise ValueError("Returned invocation violates its scheduled start boundary")
        points.extend([(requested, event["invocation_started_monotonic_seconds"]),
                       (recorded, event["invocation_recorded_monotonic_seconds"])])
        if receipt["status"] == "error":
            if failure is None or failure_hash != receipt["evidence_sha256"]:
                raise ValueError("Error receipt lacks its retained encrypted failure evidence")
            if failure["kind"] == "collector_failed" and utc_timestamp(failure["recorded_at"]) != recorded:
                raise ValueError("Collector failure clock differs from invocation receipt")
            failures.append(identifier)
        elif failure is not None:
            raise ValueError("Failure record cannot become a successful invocation")
        returned.append(receipt)
    if position != len(records)-2:
        raise ValueError("Extra native journal events after the planned samples")
    last, _ = take("run_closed")
    closed = utc_timestamp(last["recorded_at"])
    points.append((closed, last["monotonic_seconds"]))
    if first.get("phase") != "development" or first.get("run_id") != plan["run_id"]:
        raise ValueError("Run opening has wrong identity")
    previous_mono = None
    for wall, mono in points:
        if type(mono) not in (int, float) or not math.isfinite(mono) or (previous_mono is not None and mono < previous_mono):
            raise ValueError("Invalid/backward recorded monotonic clock")
        if abs((wall-origin_wall).total_seconds()-(mono-origin_mono)) > plan["max_clock_skew_seconds"]:
            raise ValueError("Recorded wall/monotonic drift exceeds reviewed bound")
        previous_mono = mono
    if closed < utc_timestamp(plan["sampling"]["closed_at"]) or utc_timestamp(report["actual_closed_at"]) != closed:
        raise ValueError("Native report closes before planned/recorded closure")
    if report["receipts"] != returned or report["skipped_samples"] != skipped or report["journal_receipts"] != engine_hashes:
        raise ValueError("Runner report does not reproduce the recorded event sequence")
    if last["prior_journal_receipts"] != engine_hashes[:-1]:
        raise ValueError("Runner closure ciphertext receipt chain mismatch")
    audit_plan = copy.deepcopy(plan["sampling"])
    audit_plan["closed_at"] = report["actual_closed_at"]
    audit = audit_sampling(audit_plan, returned)
    if canonical_sha256(audit) != canonical_sha256(report["sampling_audit"]) or last["audit_sha256"] != canonical_sha256(audit) or last["acquisition_schedule_met"] is not audit["acquisition_schedule_met"]:
        raise ValueError("Native timing audit differs from recomputed receipts")
    return failures


def audit_native_clocks(statuses, anchor_at, cutoff_at):
    """Classify source rows by their recorded clocks without producing a baseline decision.

    Inputs:
        statuses: Scoped source_statuses rows returned by the snapshot normalizer.
        anchor_at: Declared development window start.
        cutoff_at: End of the observation window, inclusive for receipt times.
    Outputs:
        list[dict]: Original scoped rows with a clock disposition. Performs no AWS
            calls, writes, fusion, or first-detection inference.
    """
    start = utc_timestamp(anchor_at)
    end = utc_timestamp(cutoff_at)
    if end <= start:
        raise ValueError("Native clock audit requires a positive window")

    audited = []
    for row in statuses:
        require_sha256(row["evidence_sha256"])
        if row["source"] == "config":
            source_clock = "detected_at"
        elif row["source"] == "securityhub_cspm":
            source_clock = "provider_updated_at"
        else:
            raise ValueError("Unsupported native source")

        # CSPM update time is a provider clock. It does not establish first detection.
        clocks = [row.get(field) for field in ("source_observed_at", source_clock, "recorded_at")]
        if any(value is None for value in clocks):
            disposition = "missing_clock"
        else:
            try:
                observed, provider, received = (utc_timestamp(value) for value in clocks)
            except (TypeError, ValueError):
                disposition = "invalid_clock"
            else:
                if not observed <= provider <= received:
                    disposition = "inconsistent_clocks"
                elif observed < start:
                    disposition = "source_before_window"
                elif received > end:
                    disposition = "late_receipt"
                else:
                    disposition = "within_window"
        audited.append({**row, "clock_disposition": disposition})
    return audited


def verify_native_run(root, decrypt_record, recipient_sha256, native_report_sha256, plan, scope):
    """Verify a completed native journal and every successful source snapshot without cloud access.

    Inputs:
        root: Original private native run root containing only journal and samples directories.
        decrypt_record: Trusted authenticated CMS decryption callback; never prints plaintext/keys.
        recipient_sha256: Independently trusted normalized public certificate fingerprint.
        native_report_sha256: Independently retained final ciphertext receipt returned by execution.
        plan: Independently reviewed exact development runner plan, not loaded from the run itself.
        scope: Independently reviewed native scope, not trusted solely because the journal repeats it.
    Outputs:
        dict: Hash-bound timing/normalized-source summaries with false research/ML/authentication gates.
            Reads private encrypted files and decrypts in memory; no writes, AWS calls or labels.
            Missing/fatal/partial completion, altered pins/events/clocks or source mismatches fail.
    """
    plan_hash, scope_hash = canonical_sha256(plan), canonical_sha256(scope)
    validate_runner_plan(plan, plan_hash)
    require_sha256(native_report_sha256)
    if scope.get("phase") != "development" or scope.get("account_id") != ACCOUNT or scope.get("region") != REGION or scope.get("recipient_sha256") != recipient_sha256:
        raise ValueError("Native scope differs from expected development account/recipient")
    if plan["collector_scope_sha256"] != scope_hash or len(plan["sampling"]["samples"]) != scope["max_snapshots"] or scope["snapshot_requests_sha256"] != canonical_sha256(read_plan(scope["bucket"])):
        raise ValueError("Reviewed plan/scope/read-plan binding differs")
    root = Path(root)
    if str(root.resolve()) != scope["output_root"] or root.is_symlink():
        raise ValueError("Native root differs from reviewed location")
    for directory in (root, root / "samples"):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Private owned native directories required")
    if set(os.listdir(root)) != {"journal", "samples"}:
        raise ValueError("Unexpected files in native root")
    records, receipts = read_archive_records(root / "journal", decrypt_record, recipient_sha256)
    if receipts[-1]["ciphertext_sha256"] != native_report_sha256:
        raise ValueError("Native final ciphertext differs from independently retained receipt")
    if len(records) < 8 or records[0] != {"kind": "native_scope", "phase": "development", "scope": scope, "scope_sha256": scope_hash}:
        raise ValueError("Native scope envelope differs from independent review")
    terminal = records[-1]
    if set(terminal) != {"kind", "phase", "report", "prior_ciphertext_receipts"} or terminal["kind"] != "native_run_report" or terminal["phase"] != "development" or terminal["prior_ciphertext_receipts"] != receipts[:-1]:
        raise ValueError("Native final report/receipt chain mismatch")
    report = terminal["report"]
    flags = {"trigger_verified", "provider_delivery_verified", "source_freshness_verified", "paired_monitoring_validated",
             "sender_authenticated", "ml_ready", "formal_trial_authorized"}
    keys = flags | {"version", "phase", "plan_sha256", "collector_scope_sha256", "planned_closed_at", "actual_closed_at",
                    "receipts", "skipped_samples", "sampling_audit", "journal_receipts"}
    if set(report) != keys or report["version"] != "development-sampling-runner-v0.1" or report["phase"] != "development" or any(report[key] is not False for key in flags):
        raise ValueError("Unsupported or promoted native readiness report")
    if report["plan_sha256"] != plan_hash or report["collector_scope_sha256"] != scope_hash or utc_timestamp(report["planned_closed_at"]) != utc_timestamp(plan["sampling"]["closed_at"]):
        raise ValueError("Native report has wrong reviewed plan/scope/closure")
    failed = verify_journal_sequence(records, receipts, plan, report)
    allowed_samples = {receipt["sample_id"] for receipt in report["receipts"]}
    if not set(os.listdir(root / "samples")) <= allowed_samples:
        raise ValueError("Unscheduled sample output present")
    for event in records:
        if event.get("kind") == "snapshot_worker_failed":
            partial = root / "samples" / event["sample_id"]
            if partial.exists() != event["partial_output_retained"] or partial.is_symlink():
                raise ValueError("Recorded partial-output retention differs from disk")
            if partial.exists():
                info = partial.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError("Private owned partial output directory required")
    verified_sources = []
    for receipt in report["receipts"]:
        if receipt["status"] != "success":
            continue
        verified = verify_archive(root / "samples" / receipt["sample_id"], decrypt_record, recipient_sha256, scope["bucket"])
        if verified["capture_kind"] != "snapshot" or verified["archive_sha256"] != receipt["evidence_sha256"]:
            raise ValueError("Successful source differs from recorded snapshot receipt")
        first, last = utc_timestamp(receipt["request_started_at"]), utc_timestamp(receipt["recorded_at"])
        queries = {}
        results = {"get_compliance_details_by_config_rule": "EvaluationResults", "get_enabled_standards": "StandardsSubscriptions", "get_findings": "Findings"}
        for record in verified["records"]:
            if record["kind"] not in {"response", "absent"}:
                continue
            recorded = utc_timestamp(record["collector_recorded_at"])
            request = record["request"]
            if not first <= recorded <= last:
                raise ValueError("Source receipt lies outside its recorded collector invocation")
            if not request["paginated"] and not first <= utc_timestamp(record["request_started_at"]) <= recorded:
                raise ValueError("Source request clock lies outside collector invocation")
            key = canonical_sha256(request)
            pages, items = queries.get(key, (0, 0))
            if request["paginated"]:
                values = record["response"].get(results[request["operation"]], [])
                if not isinstance(values, list):
                    raise ValueError("Malformed paginated source list")
                items += len(values)
            pages += 1
            if pages > (scope["max_pages"] if request["paginated"] else 1) or items > scope["max_items"]:
                raise ValueError("Snapshot source exceeds reviewed page/item caps")
            queries[key] = pages, items
        normalized = verified["normalized"]
        clock_audit = audit_native_clocks(normalized["source_statuses"], plan["sampling"]["trigger_at"],
                                          report["sampling_audit"]["cutoff_at"])
        verified_sources.append({"sample_id": receipt["sample_id"], "archive_sha256": verified["archive_sha256"],
                                 "normalized": normalized, "source_clock_audit": clock_audit})
    return {"version": "development-native-verification-v0.1", "phase": "development",
            "plan_sha256": plan_hash, "scope_sha256": scope_hash, "native_report_sha256": native_report_sha256,
            "sampling_audit": report["sampling_audit"], "verified_snapshots": verified_sources,
            "failed_samples": failed, "skipped_samples": report["skipped_samples"],
            "sender_authenticated": False, "trigger_verified": False, "provider_delivery_verified": False,
            "source_freshness_verified": False, "ml_ready": False, "formal_trial_authorized": False}
