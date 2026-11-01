"""Preview or explicitly verify an existing private recovery intent; never prints decrypted evidence."""
import argparse
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.archive_ingestion import private_bytes
from research.recovery_operator import operator_source_sha256, preview_recovery_scope, verify_with_keychain
from research.recovery_review import private_directory, strict_object
from research.scenario_lock import private_lock_root


def read_private_scope(path):
    """Load a bounded private scope file without following its final symlink.

    Inputs:
        path: Canonical absolute file path in an existing owned private directory.
    Outputs:
        dict: Strict JSON object read within a 64 KiB cap. Creates nothing and rejects unsafe
            file ownership, modes, links or JSON before any recipient or Keychain access.
    """
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Canonical absolute private scope path required")
    parent = private_lock_root(path.parent)
    descriptor = private_directory(parent)
    try:
        return strict_object(private_bytes(descriptor, path.name, 65536))
    finally:
        os.close(descriptor)


def main(argv=None):
    """Default to a credential-free preview; require explicit reviewed scope for local verification.

    Inputs:
        argv: Optional argument list; None reads the operator's command-line arguments.
    Outputs:
        int: Zero on preview/verification success, one on a secret-safe operational failure.
            Prints only source/scope identities or a minimal summary. Execute mode may invoke
            the dedicated local Keychain helper. Never prints raw decrypted data or tracebacks.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", help="Canonical absolute path to a private reviewed JSON scope")
    parser.add_argument("--print-source-pin", action="store_true", help="Print the current maintained-source hash only")
    parser.add_argument("--execute", action="store_true", help="Explicitly verify retained local evidence with the Keychain bridge")
    parser.add_argument("--approved-scope-sha256", help="Independent fingerprint of the approved local verification scope")
    args = parser.parse_args(argv)
    if args.print_source_pin:
        if args.scope or args.execute or args.approved_scope_sha256:
            parser.error("Source-pin inspection cannot be combined with verification arguments")
    elif not args.scope or args.execute != bool(args.approved_scope_sha256):
        parser.error("Supply --scope; execution requires both --execute and --approved-scope-sha256")
    try:
        if args.print_source_pin:
            result = {"operator_source_sha256": operator_source_sha256(), "keychain_invoked": False}
        else:
            scope = read_private_scope(args.scope)
            result = verify_with_keychain(scope, args.approved_scope_sha256) if args.execute else preview_recovery_scope(scope)
    except Exception:
        # Provider errors can contain sensitive captured bytes; keep stdout/stderr failure output generic.
        print(json.dumps({"status": "local_verification_failed", "live_execution_allowed": False,
                          "restoration_verified": False}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


# Merely importing the CLI cannot inspect a scope or invoke a Keychain helper.
if __name__ == "__main__":
    raise SystemExit(main())
