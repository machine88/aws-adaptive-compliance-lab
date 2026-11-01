"""Persistent local sandbox exclusion; interrupted runs require explicit recovery review."""
import json
import os
from pathlib import Path
import re
import stat

from research.sandbox_readiness import BUCKET


def private_lock_root(root):
    """Validate the canonical existing private directory used by cooperating local runners.

    Inputs:
        root: Existing absolute canonical directory path owned by the current OS user.
    Outputs:
        Path: Validated directory; raises ValueError for links, broad permissions or bad paths.
            Reads filesystem metadata only; creates nothing.
    """
    path = Path(root)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Canonical absolute lock directory required")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Existing user-owned 0700 lock directory required")
    return path


def validate_run_id(run_id):
    """Require a non-path identifier for the future run's exclusive ownership record.

    Inputs:
        run_id: Caller-selected 32-character lowercase hexadecimal development identifier.
    Outputs:
        None: Raises ValueError for malformed identifiers; no IO or state changes.
    """
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise ValueError("A 32-character lowercase hexadecimal run identifier is required")


def acquire_sandbox_lock(root, run_id):
    """Atomically reserve the fixed sandbox under a shared private local lock directory.

    Inputs:
        root: Existing canonical private directory shared by all cooperating local runners.
        run_id: Unique development run identifier retained with the run's audit records.
    Outputs:
        Path: Created fixed lock directory containing a private owner.json marker. Existing
            locks raise FileExistsError regardless of age/PID. Any partial creation failure
            leaves the lock in place for manual recovery. No AWS or credential access occurs.
    """
    validate_run_id(run_id)
    parent = private_lock_root(root)
    lock = parent / (BUCKET + ".lock")
    # mkdir is the exclusion boundary; never delete another run's lock or infer staleness.
    lock.mkdir(mode=0o700)
    payload = json.dumps({"version": "sandbox-local-lock-v0.1", "bucket": BUCKET,
                          "run_id": run_id}, sort_keys=True).encode("utf-8")
    descriptor = os.open(lock / "owner.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    # Persist both directory entries before a future caller could issue a mutation.
    for directory in (lock, parent):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return lock


def inspect_sandbox_lock(root, run_id):
    """Validate an intact owner-only local lock before preparing recovery material.

    Inputs:
        root: Existing canonical private lock root shared by cooperating local runners.
        run_id: Exact retained owner identifier for the fixed sandbox lock.
    Outputs:
        Path: Matching lock directory. Reads bounded owner metadata only; changes nothing.
            Missing, partial, expanded, symlinked or mismatched locks raise before return.
    """
    validate_run_id(run_id)
    parent = private_lock_root(root)
    lock = parent / (BUCKET + ".lock")
    private_lock_root(lock)
    if {entry.name for entry in lock.iterdir()} != {"owner.json"}:
        raise ValueError("Partial or unexpected lock contents require manual recovery")
    descriptor = os.open(lock / "owner.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Private regular lock owner record required")
        expected = json.dumps({"version": "sandbox-local-lock-v0.1", "bucket": BUCKET,
                               "run_id": run_id}, sort_keys=True).encode("utf-8")
        if handle.read(len(expected) + 1) != expected:
            raise ValueError("Lock ownership differs from the retained run identifier")
    return lock


def release_sandbox_lock(root, run_id):
    """Explicitly release an intact matching local lock after independent recovery review.

    Inputs:
        root: Same canonical private lock directory used at acquisition.
        run_id: Exact retained owner identifier; a different identifier cannot release the lock.
    Outputs:
        None: Removes owner.json and the empty lock directory after strict metadata/content
            checks. Raises on missing, replaced, partial or extra files. This filesystem action
            does not verify cloud restoration or authorize execution; the caller must do so.
    """
    lock = inspect_sandbox_lock(root, run_id)
    # Do not use recursive cleanup: unexpected files must keep reuse blocked.
    (lock / "owner.json").unlink()
    lock.rmdir()
