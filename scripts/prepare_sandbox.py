"""Preview or explicitly run one reviewed read-only observer-to-intent preparation."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.preparation_operator import preview_preparation_scope, run_preparation_operator
from scripts.review_recovery import read_private_scope


def main(argv=None):
    """Default to pure preview; require both execution flags for supervised preparation.

    Inputs:
        argv: Optional argument list; None reads process arguments.
    Outputs:
        int: Zero for preview or successful worker exit, one for generic operational failure.
            Prints only a minimal summary; execution may perform approved AWS reads and dedicated
            Keychain decryption. Never prints paths, decrypted records or raw exception details.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Private reviewed preparation scope JSON")
    parser.add_argument("--execute", action="store_true", help="Run the separately approved preparation")
    parser.add_argument("--approved-scope-sha256", help="Independently retained approved preparation pin")
    args = parser.parse_args(argv)
    if args.execute != bool(args.approved_scope_sha256):
        parser.error("Execution requires both --execute and --approved-scope-sha256")
    try:
        scope = read_private_scope(args.scope)
        result = run_preparation_operator(scope, args.approved_scope_sha256) if args.execute else preview_preparation_scope(scope)
        code = 0 if not args.execute or result["worker_status"] == "success" else 1
    except Exception:
        print(json.dumps({"status": "preparation_failed", "live_execution_allowed": False,
                          "research_trials": 0}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return code


# Importing the command cannot reserve a lock, read AWS or invoke the Keychain helper.
if __name__ == "__main__":
    raise SystemExit(main())
