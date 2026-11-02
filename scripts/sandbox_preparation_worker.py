"""Silent internal preparation worker; explicit reviewed authorization is held by its operator."""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.native_capture import worker_environment
from research.preparation_operator import run_preparation_worker
from research.recovery_review import strict_object


def main(argv=None, input_stream=None):
    """Accept one bounded parent descriptor and keep all operational output silent.

    Inputs:
        argv: Optional argument list; only an empty list is allowed for this internal worker.
        input_stream: Optional binary stream for offline tests; None uses process stdin.
    Outputs:
        int: Zero on complete retained-intent verification, one on operational failure, two on
            malformed input/environment. No raw errors, plaintext records or credentials printed.
    """
    try:
        if (sys.argv[1:] if argv is None else argv):
            return 2
        expected = worker_environment()
        keys = {key for key in expected if key.startswith("AWS_")}
        if {key for key in os.environ if key.startswith("AWS_")} != keys or any(os.environ[key] != expected[key] for key in keys):
            return 2
        stream = sys.stdin.buffer if input_stream is None else input_stream
        raw = stream.read(65537)
        if len(raw) > 65536:
            return 2
        descriptor = strict_object(raw)
        if set(descriptor) != {"scope", "approved_scope_sha256"}:
            return 2
    except Exception:
        return 2
    try:
        run_preparation_worker(descriptor["scope"], descriptor["approved_scope_sha256"])
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
