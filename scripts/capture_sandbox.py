"""Preview a private sandbox operator scope; live reads require explicit reviewed execution."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from research.sandbox_operator import preview_sandbox_scope, run_sandbox_operator
from scripts.review_recovery import read_private_scope


def main(argv=None):
    """Default to preview and require paired execution/review flags before starting a worker.

    Inputs:
        argv: Optional operator arguments; None uses process command-line arguments.
    Outputs:
        int: Zero for preview or successful worker exit, one for a failed/timeout worker or
            generic operational error. Prints minimal status only, never scope paths or evidence.
            Malformed arguments exit with argparse status two. No automatic live execution.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Canonical absolute private reviewed scope JSON")
    parser.add_argument("--execute", action="store_true", help="Run the explicitly approved development capture")
    parser.add_argument("--approved-scope-sha256", help="Independent hash of the explicitly approved scope")
    args = parser.parse_args(argv)
    if args.execute != bool(args.approved_scope_sha256):
        parser.error("Execution requires both --execute and --approved-scope-sha256")
    try:
        scope = read_private_scope(args.scope)
        result = run_sandbox_operator(scope, args.approved_scope_sha256) if args.execute else preview_sandbox_scope(scope)
    except Exception:
        print(json.dumps({"status": "sandbox_operator_failed", "live_execution_allowed": False,
                          "research_trials": 0}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if not args.execute or result["worker_status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
