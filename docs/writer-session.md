# Bound temporary writer session

Status: disabled-by-default broker implemented and tested with SDK stubs and
real disposable CMS encryption. No actual role session was opened with this
component. It is not connected to the SDK writer, live admission or a scenario
runner. No new grants, capture, versioning transition or trial occurred.

## Why the same session matters

The [timing evaluator](writer-session-budget.md) can reject insufficient declared
expiration, but cannot authenticate who supplied it. `research/writer_session.py`
now supplies a fixed, opt-in session construction path:

```text
Source profile dissertation
    -> exact non-root source identity
    -> one fixed AssumeRole request, duration 3,600 seconds
    -> returned expiration and temporary credentials in memory
    -> one non-refreshing SDK session from those exact credentials
    -> actual identity checked against returned role ARN and role/session ID
    -> future STS/S3 clients from that same session
```

The [STS AssumeRole API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
returns temporary credentials and expiration. The public
[Boto3 Session constructor](https://docs.aws.amazon.com/boto3/latest/reference/core/session.html)
accepts explicit temporary credentials. The broker uses those interfaces instead
of inferring expiration from configured duration or botocore private credential
expiry attributes. Identity alone cannot distinguish two separately issued
sessions using the same role/session name; binding relies on the trusted SDK
constructor receiving the exact response credentials, not just matching ARNs.

## Inputs and outputs

`writer_session_scope(run_id, recipient_sha256, enable_session=False)` makes a
fixed development scope without opening profiles, clients or evidence. It binds
all maintained research sources and AWS dependency declarations, exact account,
Ohio endpoints, source profile/user, target role/session, public recipient,
120-second setup deadline, 3,600-second request and three planned SDK setup calls.

`BoundWriterSession(scope, approved_scope_sha256, archive, session_factory=None,
clock=utc_now, monotonic_ns=...)` requires the current exact scope, an independent
fingerprint, explicit enablement and a new empty five-second encrypted archive.
The source profile must be an existing `login_session` in Ohio with only the
expected optional output setting. Source identity must be the exact existing IAM
user, never root. No fallback profile, static source key, credential process or
new login is installed or selected by this broker.

The constructor performs source identity, one AssumeRole request and bound
identity only. It requests no tags, source identity, context, session policy, MFA
fields or alternate role. Before-send guards reject duplicate setup sends,
including SDK retry/redirect attempts. Clients use fixed verified regional HTTPS,
no configured endpoint overrides or proxies, 3/10-second connect/read limits and
one total SDK attempt. Mandatory retention and setup deadlines are rechecked
before source dispatch and before successful handoff. Credential-provider
refresh for the existing source login is outside those three service calls.

Public methods:

| Method | Inputs | Output/side effect |
| --- | --- | --- |
| `assess_budget()` | None | Fresh conservative timing assessment from the retained expiration and continuously compared local wall/monotonic anchors; no provider refresh |
| `client(service)` | Exactly `sts` or `s3` | Cached fixed-region client from the bound static SDK session, with expiration/clock wire guard; invokes no service operation itself |
| `close()` | None | Disable broker and close owned clients; no automatic refresh, rollback, revocation, unlock or evidence deletion |

The service Date must be within five seconds of the local receipt clock. This is
a consistency check, not independent clock synchronization. Five seconds are
subtracted from usable expiration before the timing evaluator reserves its
2,521-second budget. The local monotonic/wall elapsed difference must remain
within one second. Wire starts at or after the conservative expiration deadline
are blocked; this does not guarantee requests finish before expiry or survive
network loss. Setup is cooperative and still needs an outer process supervisor.
A runtime budget assessment does not authorize a write or verify restoration.

## Credential and evidence boundary

Temporary keys/tokens go directly from the in-memory STS response into the public
SDK constructor. No credential value is returned, logged, printed, encrypted into
an evidence record, written to a profile or exported to an environment variable.
Only four allowlisted metadata records are encrypted: scope, source identity,
assumed-session metadata (expiration, role/session ID, service/local clocks,
request ID), and bound identity. Raw STS responses and raw provider errors are
not retained. Failure returns a generic setup error and closes owned clients;
partial encrypted metadata is preserved. Python/SDK memory cannot be guaranteed
to be zeroized, and close does not revoke credentials at AWS.

The class is for trusted same-process application code. Python private attributes,
injected factories and returned clients are not an adversarial security sandbox.
Future writer integration must enforce its own one-change/three-restoration
budget. This broker currently fails the writer's profile-only validator and is
not passed into that writer; no fake profile metadata is used to bypass it. The
standalone budget result deliberately keeps provider/credential/live proof gates
false until an integrated, independently reviewed admission contract exists.

The toolkit secret-safety guidance applies to stored-secret resolution. This
broker performs no Secrets Manager lookup and uses no stored secret identifier;
new STS credentials stay inside runtime memory. No secret or credential values
are requested from chat.

## Generated permission inventory

The upstream source-analysis command is:

```sh
uvx iam-policy-autopilot@latest generate-policies \
  /absolute/repository/research/writer_session.py \
  --tf-dir /absolute/repository/infra/writer \
  --region us-east-2 --account 653464153304 --service-hints sts --pretty
```

The retained run used cached pinned 0.3.0, disabled telemetry and no upload flag.
`protocol/writer-session-policy-inventory.json` preserves the unedited analysis,
its canonical hash and exact source fingerprint. It is **review inventory only**,
not a grant or deployable policy. The analyzer includes broad AssumeRole resource
patterns and SetContext, SetSourceIdentity and TagSession alongside identity;
this broker does not request those optional fields. Do not attach that output to
the writer or source user. Existing writer grants remain unchanged, and its
boundary continues to deny role chaining. No new policy was attached, deployed
or simulated as part of this offline component.

## Validation and next integration

Four focused methods cover disabled/tampered scope and retention failures before
credential resolution; exact SDK constructor/session identity; CMS roundtrip with
credential/error sentinels excluded; source/returned/bound identity mismatches;
short expiration despite a one-hour request; service/local and wall/monotonic
clock disagreement; setup delays, wrong thread, closure and conservative expiry.
They use synthetic SDK credentials and disposable recipients only.

Next: integrate this broker with the writer without weakening the existing
profile-only path, bind retained session evidence to a held intent/lock and fresh
observer receipts, and enforce pre-change budget and process/recovery deadlines.
Then review independent restoration, mutating-run closure and the exact live
rehearsal scope. A new real authentication pass or capture needs its own approval;
merging this code does not authorize one. Pilot/confirmatory evidence remains
separate and no study model has been trained.
