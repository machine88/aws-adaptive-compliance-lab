"""Reviewed development-only S3 case operator; ciphertext evidence, fixed scope and no study metrics."""
from contextlib import ExitStack
import copy
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import signal
import time

import boto3

from research.archive_ingestion import private_bytes, read_archive_records
from research.aws_reader import EncryptedArchive, sync_archive_directory
from research.catalog import canonical_sha256
from research.development_case import run_development_actions
from research.keychain_decryption import MacKeychainDecryptor
from research.native_capture import bounded_worker
from research.observer_recovery_preparation import check_lock_binding
from research.preparation_operator import (preview_preparation_scope, validate_preparation_scope,
    run_preparation_worker, read_preparation_result, write_preparation_json)
from research.recovery_review import (private_directory, strict_object, read_recovery_intent,
    retain_restoration_candidate, read_restoration_candidate)
from research.sandbox_capture import utc_now
from research.sandbox_operator import preview_sandbox_scope, validate_sandbox_scope, run_sandbox_operator
from research.sandbox_readiness import BUCKET
from research.sandbox_verification import read_verified_sandbox_prestate
from research.sandbox_writer import BoundedVersioningWriter, writer_scope
from research.scenario_lock import private_lock_root
from research.timing import require_sha256, utc_timestamp
from research.versioning_point import versioning_point_scope, capture_versioning_point, verify_versioning_point, POINTS
from research.writer_session import BoundWriterSession, writer_session_scope, SOURCE_ARN, ROLE_ARN

ROOT = Path(__file__).resolve().parents[1]
VERSION = "development-versioning-operator-v0.1"
KEYS = {"version", "phase", "preparation", "preparation_sha256", "post_observer", "post_observer_sha256",
        "session", "points", "output_root", "source_sha256", "protocol_sha256", "enable_experiment",
        "worker_timeout_seconds", "horizon_seconds", "max_service_calls", "automatic_lock_release"}


def rehearsal_source_sha256():
    """Bind maintained experiment, helper and supervisor entry points before live approval.

    Inputs:
        No arguments; reads regular maintained sources and the development protocol only.
    Outputs:
        str: Canonical content fingerprint; no profile, Keychain or AWS access.
    """
    files = list((ROOT / 'research').glob('*.py')) + [ROOT / name for name in (
        'requirements-aws.txt', 'scripts/run_development_case.py', 'scripts/development_case_worker.py',
        'scripts/sandbox_preparation_worker.py', 'scripts/sandbox_capture_worker.py', 'scripts/capture_sandbox.py',
        'scripts/prepare_sandbox.py', 'scripts/review_recovery.py', 'scripts/macos_decrypt_record.swift',
        'protocol/development-versioning-case.json')]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError('Regular maintained experiment sources required')
    return canonical_sha256({str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(files)})


def build_rehearsal_scope(preparation, post_observer, output_root, enable_experiment=False):
    """Compose one closed development case from independently reviewable fixed subscopes.

    Inputs:
        preparation: Current new locked observer-to-intent scope and pinned local decryptor binding.
        post_observer: Current new full metadata capture scope for post-restoration verification.
        output_root: Canonical absolute unused private case directory under an existing private parent.
        enable_experiment: Explicit boolean; False is the default and cannot run the operator.
    Outputs:
        dict: Source/protocol-bound case scope with fixed run, six point slots and bounded actions.
            Reads maintained source only; makes no AWS/Keychain call or output reservation.
    """
    prep = preview_preparation_scope(preparation)
    post = preview_sandbox_scope(post_observer)
    if type(enable_experiment) is not bool or prep['run_id'] != post['run_id']:
        raise ValueError('One development run and explicit execution boolean required')
    recipient = preparation['observer']['capture']['recipient_sha256']
    if post_observer['capture']['recipient_sha256'] != recipient or post_observer['certificate'] != preparation['observer']['certificate']:
        raise ValueError('Same reviewed recipient required across the case')
    return {'version': VERSION, 'phase': 'development', 'preparation': preparation,
        'preparation_sha256': prep['scope_sha256'], 'post_observer': post_observer,
        'post_observer_sha256': post['scope_sha256'],
        'session': writer_session_scope(prep['run_id'], recipient, enable_session=True),
        'points': {slot: versioning_point_scope(prep['run_id'], slot, recipient, enable_capture=True) for slot in sorted(POINTS)},
        'output_root': str(output_root), 'source_sha256': rehearsal_source_sha256(),
        'protocol_sha256': hashlib.sha256((ROOT / 'protocol/development-versioning-case.json').read_bytes()).hexdigest(),
        'enable_experiment': enable_experiment, 'worker_timeout_seconds': 3000, 'horizon_seconds': 1800,
        'max_service_calls': 44, 'automatic_lock_release': False}


def preview_rehearsal_scope(scope):
    """Check a declared current case without credentials, helper invocation or output reservation.

    Inputs:
        scope: Exact development declaration, including the default disabled execution choice.
    Outputs:
        dict: Independent review fingerprint and closed execution/scientific gates. Reads maintained
            source only; actual private runtime/path bindings are checked by execution validation.
    """
    if not isinstance(scope, dict) or set(scope) != KEYS or type(scope.get('enable_experiment')) is not bool:
        raise ValueError('Exact development case declaration required')
    expected = build_rehearsal_scope(scope['preparation'], scope['post_observer'], scope['output_root'], scope['enable_experiment'])
    if canonical_sha256(expected) != canonical_sha256(scope):
        raise ValueError('Current experiment declaration/source/protocol changed')
    return {'version': VERSION, 'mode': 'preview', 'phase': 'development',
            'scope_sha256': canonical_sha256(scope), 'execution_selected': scope['enable_experiment'],
            'aws_called': False, 'live_execution_allowed': False, 'research_trials': 0}


def validate_rehearsal_scope(scope, approved_scope_sha256, reserved=False):
    """Reject disabled/changed scopes, consumed outputs and overlapping or unsafe private paths.

    Inputs:
        scope: Exact current reviewed development case scope; independently approved externally.
        approved_scope_sha256: Independent full scope fingerprint; matching alone is not consent.
        reserved: Internal worker mode requiring only the parent's exact scope reservation.
    Outputs:
        None: Local source/binding/path checks only; no credentials, Keychain or AWS access.
    """
    require_sha256(approved_scope_sha256)
    preview = preview_rehearsal_scope(scope)
    if scope.get('enable_experiment') is not True or type(reserved) is not bool:
        raise ValueError('Exact explicitly enabled reviewed development scope required')
    if preview['scope_sha256'] != approved_scope_sha256:
        raise ValueError('Current experiment source/protocol/scope differs from review')
    validate_preparation_scope(scope['preparation'], scope['preparation_sha256'])
    validate_sandbox_scope(scope['post_observer'], scope['post_observer_sha256'])
    root, post = Path(scope['output_root']), Path(scope['post_observer']['output_root'])
    if not root.is_absolute() or '..' in root.parts or root.resolve() != root or post.resolve() != post:
        raise ValueError('Canonical absolute experiment output required')
    private_lock_root(root.parent)
    private_lock_root(post.parent)
    prep = scope['preparation']
    writes = [root, post, Path(prep['operator_root']), Path(prep['observer']['output_root']),
              Path(prep['lock_root']), Path(prep['binding_root']), Path(prep['bridge']['scratch'])]
    for index, path in enumerate(writes):
        for other in writes[index + 1:]:
            if path.is_relative_to(other) or other.is_relative_to(path):
                raise ValueError('Disjoint experiment write locations required')
    if post.exists() or post.is_symlink():
        raise ValueError('Unused post-restoration capture required')
    if reserved:
        descriptor = private_directory(root)
        try:
            if set(os.listdir(descriptor)) != {'scope.json'} or strict_object(private_bytes(descriptor, 'scope.json', 65536)) != scope:
                raise ValueError('Exact parent experiment reservation required')
        finally:
            os.close(descriptor)
    elif root.exists() or root.is_symlink():
        raise ValueError('Unused experiment output required; no automatic rerun')
    if len(json.dumps({'scope': scope, 'approved_scope_sha256': approved_scope_sha256}).encode()) > 65536:
        raise ValueError('Bounded experiment descriptor required')


def private_json(root, name):
    """Read one bounded owned private metadata record without following filesystem links.

    Inputs:
        root: Existing canonical private directory.
        name: Maintained fixed metadata filename beneath that root.
    Outputs:
        dict: Strict in-memory JSON object; no plaintext evidence export or cloud operation.
    """
    descriptor = private_directory(root)
    try:
        return strict_object(private_bytes(descriptor, name, 65536))
    finally:
        os.close(descriptor)


def watchdog(signum, frame):
    """Interrupt cooperative preparation/observation early enough for bounded recovery.

    Inputs:
        signum: POSIX alarm signal supplied by the worker process.
        frame: Interrupted Python frame; never inspected or logged.
    Outputs:
        None: Raises TimeoutError. Hard kill, host loss and hung native work remain unguaranteed.
    """
    raise TimeoutError('Development worker cooperative deadline')


def run_rehearsal_worker(scope, approved_scope_sha256):
    """Execute one approved fixed development case inside an isolated silent supervisor worker.

    Inputs:
        scope: Exact source-bound enabled development scope with unused private outputs.
        approved_scope_sha256: Independently retained explicitly approved full scope hash.
    Outputs:
        None: Performs fixed scoped AWS reads, at most one suspension and three restores;
            retains ciphertext, intent/candidate and minimal private result. No model, baseline
            comparison, formal trial, automatic retry, lock release or evidence deletion occurs.
            On process kill or unverified recovery, keep the lock and request separate recovery
            review; this function cannot guarantee recovery from host/network/process loss.
    """
    if os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid():
        raise ValueError('Isolated development session/group leader required')
    validate_rehearsal_scope(scope, approved_scope_sha256, reserved=True)
    root, prep = Path(scope['output_root']), scope['preparation']
    observer = prep['observer']
    run_id, recipient = observer['run_id'], observer['capture']['recipient_sha256']
    cert, openssl = observer['certificate'], observer['openssl']
    bridge = prep['bridge']
    decrypt = MacKeychainDecryptor(bridge['helper'], bridge['helper_sha256'], bridge['recipient'], recipient, bridge['scratch'])
    audit = EncryptedArchive(root / 'audit', cert, openssl, 5)
    actions_archive = EncryptedArchive(root / 'actions', cert, openssl, 5)
    (root / 'points').mkdir(mode=0o700)
    sync_archive_directory(root)
    private_lock_root(root / 'points')
    started_wall, started_ns = utc_timestamp(utc_now()), time.monotonic_ns()
    old_handler = signal.signal(signal.SIGALRM, watchdog)
    broker = writer = None
    try:
        audit.write({'kind': 'development_case_scope', 'scope_sha256': approved_scope_sha256, 'protocol_sha256': scope['protocol_sha256']})
        # Open the fixed session once; its remaining lifetime is rechecked after preparation.
        session_archive = EncryptedArchive(root / 'session', cert, openssl, 5)
        broker = BoundWriterSession(scope['session'], canonical_sha256(scope['session']), session_archive, clock=utc_now, monotonic_ns=time.monotonic_ns)
        session_records, _ = read_archive_records(session_archive.root, decrypt, recipient, max_records=4, max_bytes=1048576)
        binding = broker.evidence_binding()
        if len(session_records) != 4 or session_records[0] != {'phase': 'development', 'kind': 'session_scope', 'scope': scope['session']} or canonical_sha256({key: value for key, value in session_records[2].items() if key != 'phase'}) != binding['source_record_sha256']:
            raise ValueError('Encrypted session metadata differs from the bound runtime')
        if session_records[1].get('arn') != SOURCE_ARN or session_records[3].get('arn') != ROLE_ARN or session_records[3].get('user_id') != session_records[2].get('assumed_role_id'):
            raise ValueError('Retained source/bound session identity mismatch')
        # Reuse the existing locked, encrypted and readback-verified preparation exactly once.
        preparation_root = Path(prep['operator_root'])
        preparation_root.mkdir(mode=0o700)
        sync_archive_directory(preparation_root.parent)
        write_preparation_json(preparation_root / 'scope.json', prep)
        signal.alarm(330)
        run_preparation_worker(prep, scope['preparation_sha256'])
        signal.alarm(0)
        preparation_result_sha = read_preparation_result(preparation_root, prep, scope['preparation_sha256'])
        prepared = private_json(preparation_root, 'result.json')
        if canonical_sha256(prepared) != preparation_result_sha:
            raise ValueError('Preparation result changed')
        manifest = private_json(prep['binding_root'], run_id + '.json')
        if canonical_sha256(manifest) != prepared['preparation_manifest_sha256']:
            raise ValueError('Retained preparation manifest changed')
        retained = read_recovery_intent(prep['lock_root'], run_id, decrypt, prepared['preparation_manifest_sha256'],
            observer['capture']['source_sha256'], recipient, prepared['intent_commitment_sha256'])
        if retained['intent_sha256'] != prepared['intent_sha256']:
            raise ValueError('Retained intent changed')
        observer_session = boto3.Session(profile_name='dissertation-sandbox-observer', region_name='us-east-2')
        observed_points = {}
        with ExitStack() as stack:
            root_fd = private_directory(prep['lock_root'])
            stack.callback(os.close, root_fd)
            lock_fd = private_directory(BUCKET + '.lock', root_fd)
            stack.callback(os.close, lock_fd)
            identity = manifest['local_lock_identity']
            if (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino, os.fstat(lock_fd).st_dev, os.fstat(lock_fd).st_ino) != (identity['root_device'], identity['root_inode'], identity['lock_device'], identity['lock_inode']):
                raise ValueError('Preparation lock identity changed')

            def guard():
                """Require the original held intent/lock and fresh full/point pre-state at change.

                Inputs:
                    No arguments; uses anchored original descriptors and verified current-run evidence.
                Outputs:
                    None: Metadata/clock checks only; raises before suspension on stale or changed inputs.
                """
                check_lock_binding(prep['lock_root'], root_fd, lock_fd, run_id, intent_retained=True)
                now_wall, now_ns = utc_timestamp(utc_now()), time.monotonic_ns()
                if abs((now_wall - started_wall).total_seconds() * 1_000_000_000 - (now_ns - started_ns)) > 1_000_000_000:
                    raise ValueError('Experiment wall/monotonic clocks differ')
                age = (now_wall - utc_timestamp(manifest['capture_started_at'])).total_seconds()
                admission = observed_points.get('admission')
                if not 0 <= age <= 60 or not admission or admission['observed_status'] != 'Enabled' or not 0 <= now_ns - admission['finished_monotonic_ns'] <= 30_000_000_000:
                    raise ValueError('Fresh protected-empty pre-state and Enabled admission required')

            def point(slot):
                """Capture and independently decrypt/verify one predeclared observer slot.

                Inputs:
                    slot: One fixed case slot, consumed once with an exclusive encrypted archive.
                Outputs:
                    dict: Minimal same-run readback report after independent receipt-chain validation.
                        No raw response leaves local worker memory; no repeated slot is permitted.
                """
                if slot in observed_points:
                    raise ValueError('Point slot already consumed')
                declaration = scope['points'][slot]
                archive = EncryptedArchive(root / 'points' / slot, cert, openssl, 5)
                report = capture_versioning_point(observer_session, archive, declaration, canonical_sha256(declaration), clock=utc_now, monotonic_ns=time.monotonic_ns)
                records, receipts = read_archive_records(archive.root, decrypt, recipient, max_records=4, max_bytes=1048576)
                verified = verify_versioning_point(declaration, canonical_sha256(declaration), records, receipts, report['ciphertext_fingerprint'])
                if verified != report:
                    raise ValueError('Point readback differs from runtime report')
                observed_points[slot] = report
                return report

            write_scope = writer_scope(run_id, recipient, prepared['intent_sha256'], prepared['preparation_manifest_sha256'],
                observer['capture']['source_sha256'], enable_writes=True, session_mode='bound_session')
            writer_archive = EncryptedArchive(root / 'writer', cert, openssl, 5)
            writer = BoundedVersioningWriter(write_scope, canonical_sha256(write_scope), retained['record'], writer_archive,
                                             bound_session=broker, prechange_check=guard, clock=utc_now, monotonic_ns=time.monotonic_ns)
            writer_records, _ = read_archive_records(writer_archive.root, decrypt, recipient, max_records=3, max_bytes=1048576)
            if len(writer_records) != 3 or writer_records[0] != {'phase': 'development', 'run_id': run_id, 'kind': 'writer_scope', 'scope': write_scope, 'scope_sha256': canonical_sha256(write_scope)} or writer_records[1].get('source_record_sha256') != binding['source_record_sha256'] or writer_records[1].get('session_scope_sha256') != binding['session_scope_sha256']:
                raise ValueError('Writer/session encrypted linkage differs')
            identity = writer_records[2].get('response', {})
            if writer_records[2].get('kind') != 'writer_identity' or identity.get('Account') != '653464153304' or identity.get('Arn') != ROLE_ARN or identity.get('UserId') != session_records[3].get('user_id'):
                raise ValueError('Encrypted writer identity differs from the bound session')
            write_preparation_json(root / 'runtime-pins.json', {'phase': 'development', 'run_id': run_id,
                'scope_sha256': approved_scope_sha256, 'preparation_result_sha256': preparation_result_sha,
                'preparation_manifest_sha256': prepared['preparation_manifest_sha256'], 'intent_sha256': prepared['intent_sha256'],
                'intent_commitment_sha256': prepared['intent_commitment_sha256'], 'intent_source_sha256': observer['capture']['source_sha256'],
                'recipient_sha256': recipient, 'writer_scope_sha256': canonical_sha256(write_scope), 'lock_release_allowed': False})
            # Cooperative observation alarm is cancelled before bounded recovery inside the action adapter.
            signal.alarm(2100)

            def retain_action(record):
                """Retain action evidence and leave recovery time after observation ends/fails.

                Inputs:
                    record: Maintained metadata-only case event from run_development_actions.
                Outputs:
                    dict: Durable ciphertext receipt; cancels observation alarm before restoration and
                        retains one metadata-only window cutoff file after trigger acknowledgment.
                """
                if record['event'] == 'restore_pending':signal.alarm(0)
                receipt = actions_archive.write(record)
                if record['event'] == 'trigger_observed':
                    write_preparation_json(root / 'window.json', {'phase': 'development', 'run_id': run_id,
                        'scope_sha256': approved_scope_sha256, 'stage': 'observing', 'horizon_seconds': 1800,
                        'cutoff_monotonic_ns': record['details']['cutoff_monotonic_ns'], 'research_trials': 0})
                return receipt

            actions = run_development_actions(run_id, writer, point, guard, retain_action)
            signal.alarm(0)
            protected_poststate = candidate_verified = False
            candidate_pin = post_fingerprint = None
            if actions['enabled_readback_observed']:
                check_lock_binding(prep['lock_root'], root_fd, lock_fd, run_id, intent_retained=True)
                post_started = utc_timestamp(utc_now())
                post = run_sandbox_operator(scope['post_observer'], scope['post_observer_sha256'], inherit_supervisor_group=True)
                post_returned = utc_timestamp(utc_now())
                if post['worker_status'] != 'success':raise ValueError('Full post-restoration capture failed')
                post_fingerprint = post['ciphertext_fingerprint']
                read = read_verified_sandbox_prestate(scope['post_observer']['output_root'], scope['post_observer'],
                    scope['post_observer_sha256'], post_fingerprint, decrypt)
                for receipt in [read['identity_receipt']] + read['prestate']['receipts']:
                    if not post_started <= utc_timestamp(receipt['started_at']) <= utc_timestamp(receipt['finished_at']) <= post_returned:
                        raise ValueError('Post-state receipts outside this run interval')
                protected_poststate = True
                commitment = retain_restoration_candidate(prep['lock_root'], run_id, decrypt, read['prestate']['metadata'],
                    read['prestate']['listings'], prepared['preparation_manifest_sha256'], observer['capture']['source_sha256'],
                    recipient, prepared['intent_commitment_sha256'], openssl, 5)
                candidate_pin = canonical_sha256(commitment)
                closure = read_restoration_candidate(prep['lock_root'], run_id, decrypt, prepared['preparation_manifest_sha256'],
                    observer['capture']['source_sha256'], recipient, prepared['intent_commitment_sha256'], candidate_pin)
                candidate_verified = closure['retained_candidate_consistent']
            success = (actions['mutation_calls'] == 1 and actions['window_completed'] and actions['enabled_readback_observed']
                       and actions['journal_complete'] and actions['cause'] == 'none' and protected_poststate and candidate_verified)
            result = {'version': VERSION, 'phase': 'development', 'run_id': run_id, 'scope_sha256': approved_scope_sha256,
                'protocol_sha256': scope['protocol_sha256'], 'engineering_cycle_completed': bool(success), 'actions': actions,
                'protected_empty_poststate_observed': protected_poststate, 'restoration_candidate_readback_consistent': candidate_verified,
                'post_capture_fingerprint': post_fingerprint, 'candidate_commitment_sha256': candidate_pin,
                'lock_held_for_review': True, 'formal_trial_authorized': False, 'research_trials': 0,
                'native_baseline_comparison_performed': False, 'ai_model_evaluation_performed': False}
            audit.write({'kind': 'development_case_result', 'result': result})
            write_preparation_json(root / 'result.json', result)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        if writer is not None:writer.close()
        if broker is not None:broker.close()


def run_rehearsal_operator(scope, approved_scope_sha256):
    """Reserve and supervise exactly one explicitly approved development case; never auto-retry.

    Inputs:
        scope: Source-bound enabled current case scope with unused outputs and unheld lock.
        approved_scope_sha256: Independent full scope fingerprint approved separately by the user.
    Outputs:
        dict: Minimal worker status and case-result fingerprint. Reserves private metadata and runs
            a silent isolated worker for at most 3,000 seconds; hard timeout/cancellation kills its
            process group and preserves any held lock/evidence for manual recovery review.
            Success means a returned worker result, not a positive experiment; inspect its outcome.
    """
    scope = copy.deepcopy(scope)
    validate_rehearsal_scope(scope, approved_scope_sha256)
    root = Path(scope['output_root'])
    root.mkdir(mode=0o700)
    sync_archive_directory(root.parent)
    write_preparation_json(root / 'scope.json', scope)
    status = bounded_worker([scope['preparation']['observer']['python_executable'], '-I',
        str(ROOT / 'scripts/development_case_worker.py')], {'scope': scope, 'approved_scope_sha256': approved_scope_sha256},
        3000, terminate_group_on_exit=True)
    result_pin = None
    if status == 'success':
        result = private_json(root, 'result.json')
        if result.get('version') != VERSION or result.get('phase') != 'development' or result.get('run_id') != scope['preparation']['observer']['run_id'] or result.get('scope_sha256') != approved_scope_sha256 or result.get('formal_trial_authorized') is not False or result.get('research_trials') != 0:
            raise ValueError('Worker result differs from the approved development case')
        result_pin = canonical_sha256(result)
    summary = {'version': VERSION, 'phase': 'development', 'run_id': scope['preparation']['observer']['run_id'],
        'scope_sha256': approved_scope_sha256, 'worker_status': status, 'result_sha256': result_pin,
        'independent_review_pending': True, 'lock_release_allowed': False, 'research_trials': 0}
    write_preparation_json(root / 'status.json', summary)
    return summary
