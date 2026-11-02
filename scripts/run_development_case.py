"""Preview a private reviewed development scope; --execute additionally needs explicit user approval."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.keychain_decryption import require_private_path
from research.development_rehearsal import run_rehearsal_operator, preview_rehearsal_scope
from research.recovery_review import strict_object


def main(argv=None):
    """Validate a bounded private scope and optionally invoke its separately approved operator.

    Inputs:
        argv: Optional CLI argument list, defaulting to process arguments.
    Outputs:
        int: Zero for valid preview or worker success, one for generic operational failure.
            Prints only a minimal status; no raw evidence, provider error, credentials or tokens.
            Default preview performs local validation only and never starts AWS/Keychain work.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', required=True)
    parser.add_argument('--scope-sha256', required=True)
    parser.add_argument('--execute', action='store_true', help='Use only after explicit approval of this reviewed scope')
    args = parser.parse_args(argv)
    try:
        with require_private_path(args.scope).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:raise ValueError('Scope too large')
        scope = strict_object(raw)
        if preview_rehearsal_scope(scope)['scope_sha256'] != args.scope_sha256:
            raise ValueError('Independent scope fingerprint differs')
        if not args.execute:
            print('Development declaration valid; preview only. No AWS or Keychain call.')
            return 0
        result = run_rehearsal_operator(scope, args.scope_sha256)
        print('Development worker ' + result['worker_status'] + '; private result requires review; lock remains held.')
        return 0 if result['worker_status'] == 'success' else 1
    except BaseException:
        print('Development case stopped; inspect private artifacts and any held lock. No automatic retry.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
