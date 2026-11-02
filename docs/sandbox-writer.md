# Bounded sandbox versioning transport and deployed access

Status: the separately approved saved access plan was applied and independently
verified on November 2, 2026. It created the dedicated role, generated policy,
mandatory boundary, attachment and Terraform guard: five creates, zero updates
and zero deletes. Actual IAM reads matched the reviewed trust, 3,600-second role
maximum, boundary and policy documents, one managed attachment and zero inline
policies. The isolated state contains five managed instances; a follow-up plan
reported no changes and the backend lock was absent afterward.

The source root still defaults off; approved active inputs are retained privately
and must remain enabled for future maintenance plans. Setting the source default
to false is not a pause operation for deployed resources. No writer profile was
installed, versioning change executed, new capture made or rehearsal run. Existing
observer access remains read-only. Saved plans, state and raw verification remain private.

## Transport contract

`research/sandbox_writer.py` exposes `writer_scope`, pure `preview_writer_scope`
and `BoundedVersioningWriter`. Scope creation defaults to `enable_writes=false`;
disabled scopes fail before session construction. There is no live CLI or driver
connection that automatically invokes this library.

An explicitly enabled, independently reviewed scope binds the current source,
run identifier, recipient and authenticated intent review/source/content pins.
The writer requires a new empty encrypted archive, a five-second crypto limit,
and the exact proposed `dissertation-sandbox-versioning` role profile in account
653464153304, Ohio. Its existing local-login source profile must have only the
expected configuration. No password, access key, role credential or token is
accepted as a function input, printed, persisted or exported by this adapter.

Construction retains the scope before constructing clients, checks the actual
STS identity against the exact role/session, and retains the attributed response
before interpretation. Wrong role/account/profile or retention failure prevents
S3 client setup. Credential acquisition/refresh may make separate authentication
requests outside the one identity plus four versioning-call budget.

Public methods have fixed inputs and bounded outputs:

| Method | Input | Output and behavior |
| --- | --- | --- |
| `suspend_once()` | No caller-selected parameters | One possible Suspended attempt; exact bucket/owner and no MFA fields |
| `restore_enabled()` | No caller-selected parameters | At most three Enabled attempts after possible change, or in separately reviewed recovery-only mode |
| `summary()` | None | Attempt/identity/journal counters, with credential coverage/restoration/research gates false |
| `close()` | None | Disable this transport and close handlers/sockets; no rollback, AWS request or unlock |

The SDK dispatch is explicitly `put_bucket_versioning` with the fixed sandbox,
`ExpectedBucketOwner=653464153304` and only `VersioningConfiguration.Status`.
AWS documents both statuses, owner mismatch rejection and an empty HTTP 200
response in its [API contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html).
HTTP success is never treated as an independently observed trigger/restoration.

Clients use verified regional HTTPS endpoints, ignored configured endpoint
URLs, no proxies, no FIPS/dualstack/acceleration override, connect/read limits
of 3/10 seconds and one total SDK attempt. The existing before-send guard rejects
retries/redirect resends and sends outside the active invocation. Local monotonic
rollback, wrong-thread/reentrant calls and requests beginning after the fixed
2,400-second transport lifetime are rejected. Identity setup has a 120-second
limit. These engineering limits are not formal measurement horizons or hard
end-to-end process deadlines; the study's common horizon remains 1,800 seconds.

Pending suspension requires acknowledged encrypted retention before dispatch.
Attempt counters are consumed before retention/network IO, including ambiguous
failures. Raw SDK responses and ClientError details stay inside ciphertext; callers
receive generic uncertainty only. After a possible change, bounded Enabled
attempts may continue despite journal outage, but remain uncertain if response
retention fails. This prioritizes best-effort recovery without fabricating a
complete audit. There is no mutation retry, automatic restart or profile fallback.

## Deployed IAM access

`infra/writer` creates no IAM resources by default. Enabling it additionally needs
a valid independent review-manifest reference, exact non-root provisioning user
and default workspace. A matching hash is provenance, not user approval.

The deployed resources are one dedicated role, one generated managed policy,
one mandatory boundary and one policy attachment, plus a Terraform identity guard.
Trust names only the existing IAM user. The role maximum session is 3,600 seconds;
no local profile or credential is created by Terraform. Destruction is guarded.

The backend uses its own protected key:

```text
dissertation/653464153304/us-east-2/versioning-access/terraform.tfstate
```

The candidate identity policy was generated from actual SDK calls using IAM
Policy Autopilot. Its S3 bucket pattern remains broad and must **never** be
attached without the boundary. The boundary permits only `s3:PutBucketVersioning`
on the exact sandbox in Ohio and `sts:GetCallerIdentity`; explicit denials exclude
other actions, other S3 resources, other S3 regions and insecure S3 transport.
There is no object read/write/delete, bucket-policy/public-access/encryption change,
IAM administration or role-chaining grant.

IAM's published [S3 action condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html)
do not list a requested versioning-status key. Do not claim the role policy itself
enforces Suspended/Enabled ordering, application attempt counts, omission of MFA
fields or rollback. The reviewed application and independent recovery procedures
must enforce those restrictions; arbitrary Python code/compromised credentials
are outside this library's protection.

## Deterministic policy generation

The upstream generation command for a reviewed new tool installation is:

```sh
uvx iam-policy-autopilot@latest generate-policies \
  /absolute/repository/research/sandbox_writer.py \
  --tf-dir /absolute/repository/infra/sandbox \
  --region us-east-2 --account 653464153304 --service-hints s3 sts --pretty
```

The actual retained analysis used cached **0.3.0**, with telemetry disabled and no
policy-upload flag. Its generated baseline is unedited. The companion
`protocol/writer-policy-generation.json` records tool/version, account/region,
exact runtime source hashes, Terraform context, canonical policy hash, mandatory
boundary location and closed standalone/deployment snapshot flags. Source/policy
changes require regeneration and review, not hand-editing the generated policy.
Those snapshot flags describe generation, not later live deployment status.

AWS Access Analyzer validation returned no findings for both candidate documents.
Six IAM custom-policy simulations produced 16 expected resource/action decisions:
two allowed and fourteen explicitly denied, without missing context. These are
administrative candidate-policy checks, not study findings or proof that a live
assumed session will succeed. Raw responses and all future saved plans remain
private. Trust/session policies, resource policies, organizational constraints,
service conditions and later drift still require deployment verification.

## Validation and remaining gates

Five focused SDK-stub tests use disposable CMS recipients to check disabled and
changed scopes, exact requests and finite attempts, private provider errors,
wrong identity/profile, journal outage, recovery-only mode, thread/wire guards
and deadline expiry during pending retention. Five mocked Terraform cases check
zero default grants, boundary/trust, missing review, root and wrong account.
Existing provenance coverage now also checks the writer source/generated output.
CI validates seven roots with no AWS credentials or deployment authority.

The real private saved Terraform plan, backend/collision checks and explicit user
approval preceded IAM creation. The exact saved plan was applied with normal
backend locking after renewed non-root identity and artifact checks. Actual IAM
verification and a no-change follow-up plan passed. Approval of role deployment does not
authorize any versioning change, capture or rehearsal. No compute, new bucket,
monitoring activation, KMS key or paid ML service is requested by this access root;
existing state/log request/storage usage remains a cost dimension. The $100
account alerts are unchanged and are not a spending cap.

Before live integration, independently validate the lock/pre-state, source clocks
and freshness, remaining credential coverage, process supervision, restoration
readback, crash/network recovery and evidence-preserving mutating-run release.
Requested session duration is not proof of remaining lifetime; that gate remains
false. Attempt bounds are per writer instance, not IAM rate limits across a
restart. No unreviewed new instance may reset a consumed mutation attempt.

The offline cycle stays synthetic-only; this transport is not wired into it to
turn synthetic booleans into live admission. Versioning remains outside the two
currently deployed baseline control candidates. No control is added, case dropped
or compliance label inferred from this development transport. Monitoring validity,
independent catalog/ground truth, real model training, R power design and formal
pilot/confirmatory gates remain open.
