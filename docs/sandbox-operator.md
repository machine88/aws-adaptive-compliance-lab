# Supervised sandbox observation operator

Status: implemented and tested offline; the separately approved observer role is deployed and its local short-lived profile identity verified. **The actual single-pass scope is prepared and previewed, but live collection is not yet approved and has not run.** Access deployment and collection have separate approval gates.

The POSIX operator connects the fixed read-only [capture engine](sandbox-observer.md) to the existing silent process-group supervisor. This is development evidence only. It does not mutate the sandbox, run a scenario, train ML, release a lock or create pilot/confirmatory trials.

## Review and execution flow

```text
Local public certificate + maintained code/runtime + proposed private output
                         ↓
               Build and review exact scope
                         ↓
             Default CLI preview: no AWS calls
                         ↓
        Explicit approval + execute flag + matching scope hash
                         ↓
    Exclusive private run → encrypted journal → supervised worker
                         ↓
       Observer identity → fixed S3 reads → encrypted receipts
                         ↓
     Retain worker status; independently verify evidence later
```

`build_sandbox_scope(certificate, output_root, openssl, run_id)` reads local public/software files and normalizes the public certificate with a five-second subprocess timeout. Inputs must use canonical absolute paths; the future output's parent must already be user-owned mode 0700. The run identifier is 32 lowercase hexadecimal characters. No output or SDK session is created. Retain the returned JSON privately as mode 0600 in a mode 0700 directory and independently review its canonical hash. Building a scope does not approve it.

The scope fixes account/region/role requests, the declared `dissertation-sandbox-observer` profile, certificate and output paths, normalized public-recipient fingerprint, maintained-source fingerprint, Python/OpenSSL executable hashes, AWS package versions, twelve planned SDK calls, the engine's 120-second cooperative deadline and a 150-second worker timeout. Changes require a new scope/review. Package version pins do not hash installed package contents, and these checks do not attest to host security or authenticate the reviewer.

From the repository root, default preview uses:

```sh
python scripts/capture_sandbox.py --scope /ABSOLUTE/PRIVATE/approved-scope.json
```

It reads only the bounded private scope file and validates declared fields. It opens no certificate/output targets, invokes no worker and makes no AWS call. The displayed result contains scope/run identities and closed execution gates, not private paths or responses.

Only after explicit live approval may the same command include **both** `--execute` and `--approved-scope-sha256` with the independently reviewed hash. A supplied hash alone is not authorization. This document supplies no approval and no executable ready-made scope.

## Credential and output boundaries

The silent worker strips inherited AWS/Python overrides through the existing supervisor, uses isolated Python, and requires the dedicated observer role profile to contain exactly the expected role ARN, source profile `dissertation`, role-session name `dissertation-sandbox-observer`, duration `900` and region `us-east-2`. The source profile must contain a nonempty local `login_session`, Ohio region and optionally output format, with no other keys. Unexpected credential-process, static-key, web-identity or other configuration is rejected before creating service clients. Nothing writes or exports credentials. Profile availability, actual source identity and deployed role trust still require independent review; a configuration shape is not identity proof. The engine verifies the assumed observer identity before S3.

SDK credential-provider activity, including role assumption/refresh, is outside the twelve planned observation calls and needs its own review. The inherited supervisor environment declares the existing three-attempt default; the observation clients override it with their explicit one-attempt configuration and wire guard. No role assumption is attempted by this change's tests.

Execution exclusively reserves the private output root. `journal/` contains encrypted operator scope/status records; `capture/` contains the engine's public certificate and encrypted receipts. Its encrypted scope record includes the enclosing operator-scope fingerprint. After worker success, the journal also retains a bounded ciphertext inventory fingerprint using the existing private-file checks; it does not decrypt or authenticate completion contents. Existing output is never reused, overwritten or deleted. If preparation, journaling or worker execution fails, partial output remains. An interruption may leave only the initial journal record. No automatic retry occurs.

On timeout or cancellation, the reused supervisor kills and reaps the worker process group, including child encryption processes in that group. This is a supervised worker timeout, not an absolute end-to-end wall-clock promise: parent certificate checks, local writes/fsync, scheduling and reaping may outlast it. A killed worker can leave partial ciphertext with no final marker. Worker exit `success` is recorded as process status only; `capture_completion_independently_verified` remains false until separately reviewed ciphertext verification exists. Freshness, simultaneous emptiness, interference exclusion and research readiness are not established by process success.

## Validation

Focused tests compose the real operator, worker, SDK stubs and CMS writer with disposable recipients. They cover default preview, paired execution flags, stale review/source/runtime rejection before output, exact profile constraints, encrypted successful receipts, exclusive output reuse and encrypted timeout status. Existing supervisor tests verify actual process-group termination/reaping; that machinery is reused. Tests access no real AWS profile, Keychain or study evidence.
