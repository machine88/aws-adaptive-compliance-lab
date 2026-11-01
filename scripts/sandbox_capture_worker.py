"""Silent internal sandbox capture worker; never invoke without reviewed live-capture approval."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from research.aws_reader import ACCOUNT, REGION, EncryptedArchive
from research.native_capture import worker_environment
from research.recovery_review import strict_object
from research.sandbox_capture import capture_sandbox
from research.sandbox_operator import PROFILE, validate_sandbox_scope
from research.scenario_lock import private_lock_root
from research.catalog import canonical_sha256


def validate_observer_profile(session):
    """Require a dedicated role profile sourced only from the existing local login profile.

    Inputs:
        session: Explicit SDK session configured for dissertation-sandbox-observer.
    Outputs:
        None: Reads SDK profile configuration in memory and rejects unexpected credential chains.
            Does not resolve credentials, issue AWS calls or return/log configuration values.
            Actual source identity and deployed role trust still need independent review.
    """
    profile = session._session.get_scoped_config()
    allowed = {"role_arn", "source_profile", "role_session_name", "duration_seconds", "region"}
    if set(profile) != allowed or profile["role_arn"] != f"arn:aws:iam::{ACCOUNT}:role/dissertation-sandbox-observer" or profile["source_profile"] != "dissertation" or profile["role_session_name"] != "dissertation-sandbox-observer" or profile["duration_seconds"] != "900" or profile["region"] != REGION:
        raise ValueError("Exact dedicated observer role profile required")
    source = session._session.full_config["profiles"].get("dissertation", {})
    if set(source) - {"login_session", "region", "output"} or not isinstance(source.get("login_session"), str) or not source["login_session"] or source.get("region") != REGION:
        raise ValueError("Existing local-login source profile required")


def run_worker(scope, approved_scope_sha256, session_factory=None):
    """Validate local bindings and encryption before constructing the explicit observer session.

    Inputs:
        scope: Reviewed operator scope read from the bounded supervisor descriptor.
        approved_scope_sha256: Independently reviewed operator scope hash.
        session_factory: Optional offline-test SDK constructor; None uses boto3.Session.
    Outputs:
        None: Creates only a new ciphertext capture archive and performs the fixed development
            reads on explicit invocation. Failures propagate to the silent main handler.
            No permission deployment, mutation, cleanup or credential persistence occurs.
    """
    import boto3
    validate_sandbox_scope(scope, approved_scope_sha256)
    root = private_lock_root(scope["output_root"])
    private_lock_root(root / "journal")
    archive = EncryptedArchive(root / "capture", scope["certificate"], scope["openssl"], timeout_seconds=5)
    factory = boto3.Session if session_factory is None else session_factory
    session = factory(profile_name=PROFILE, region_name=REGION)
    validate_observer_profile(session)
    capture_sandbox(session, archive, scope["capture"], canonical_sha256(scope["capture"]),
                    operator_scope_sha256=approved_scope_sha256)


def main(argv=None, input_stream=None):
    """Accept only the supervisor's bounded descriptor and suppress operational error output.

    Inputs:
        argv: Optional CLI arguments; only an empty list is allowed for this internal worker.
        input_stream: Optional binary stdin for offline tests; None uses process stdin.
    Outputs:
        int: Zero for worker success, one for capture failure, two for invalid input/environment.
            Prints nothing; the supervisor also discards stdout/stderr. Timeout can leave partial
            ciphertext without an encrypted completion/failure marker.
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
        validate_sandbox_scope(descriptor["scope"], descriptor["approved_scope_sha256"])
    except Exception:
        return 2
    try:
        run_worker(descriptor["scope"], descriptor["approved_scope_sha256"])
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
