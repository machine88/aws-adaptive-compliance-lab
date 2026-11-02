"""Preview or explicitly archive one completed read-only preparation lock without deleting evidence."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.readonly_retirement import preview_retirement, retire_readonly_preparation
from scripts.review_recovery import read_private_scope


def main(argv=None):
    """Require separate explicit reviewed approval for local retirement; default to pure preview.

    Inputs:
        argv: Optional argument list; None reads process CLI arguments.
    Outputs:
        int: Zero on preview or committed retirement, one on a generic failure requiring state review.
            Prints minimal metadata only. No AWS or Keychain call; no automatic retry or rollback.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Private retirement scope JSON")
    parser.add_argument("--execute", action="store_true", help="Run separately approved local retirement")
    parser.add_argument("--approved-scope-sha256", help="Independent approved retirement fingerprint")
    args = parser.parse_args(argv)
    if args.execute != bool(args.approved_scope_sha256):
        parser.error("Retirement requires both --execute and --approved-scope-sha256")
    try:
        scope = read_private_scope(args.scope)
        result = retire_readonly_preparation(scope, args.approved_scope_sha256) if args.execute else preview_retirement(scope)
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"status": "retirement_failed_or_incomplete", "state_requires_review": True,
                          "restoration_verified": False, "live_execution_allowed": False}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
