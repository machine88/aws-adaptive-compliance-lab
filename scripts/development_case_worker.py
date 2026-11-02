"""Silent internal development experiment worker; no implicit live approval or direct shell use."""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.development_rehearsal import run_rehearsal_worker
from research.native_capture import worker_environment
from research.recovery_review import strict_object


def main(argv=None, input_stream=None):
    """Accept one bounded reviewed descriptor and suppress all operational/credential output.

    Inputs:
        argv: Optional argument list; only an empty list is allowed for this internal worker.
        input_stream: Optional test byte stream; None reads process stdin.
    Outputs:
        int: Zero for a retained result, one for operation failure, two for invalid descriptor or
            environment. No raw error, decrypted evidence, key or token is printed.
    """
    try:
        if (sys.argv[1:] if argv is None else argv):
            return 2
        expected = worker_environment()
        keys = {key for key in expected if key.startswith('AWS_')}
        if {key for key in os.environ if key.startswith('AWS_')} != keys or any(os.environ[key] != expected[key] for key in keys):
            return 2
        raw = (sys.stdin.buffer if input_stream is None else input_stream).read(65537)
        if len(raw) > 65536:return 2
        descriptor = strict_object(raw)
        if set(descriptor) != {'scope', 'approved_scope_sha256'}:return 2
    except Exception:
        return 2
    try:
        run_rehearsal_worker(descriptor['scope'], descriptor['approved_scope_sha256'])
    except BaseException:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
