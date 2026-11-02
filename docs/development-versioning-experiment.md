# First development experiment: controlled S3 versioning cycle

Status: executable package implemented and exercised offline with SDK stubs and
real disposable encryption. **No live case has run.** Execution needs explicit
approval of its concrete private scope after checks pass. It uses the existing
dedicated sandbox and roles; it deploys no infrastructure or new permissions.

This case supports a dissertation progress report by testing necessary injection,
observation, evidence and recovery machinery. It is development instrument
validation, separate from pilot and confirmatory evidence. A positive engineering
result does not answer whether AI improves compliance monitoring. No baseline
comparison, trained study-model result, detection metric or statistical inference
is produced by this case.

## Predeclared design and expected sequence

`protocol/development-versioning-case.json` fixes the engineering expectations
before live collection. The expected states are independent of any AI prediction:

```text
New protected-empty Enabled pre-state + held lock + readable encrypted intent
                                |
Bound writer session, expiration and identity evidence verified from ciphertext
                                |
Fresh Enabled admission + original lock checked at actual suspension wire boundary
                                |
                   One Suspended request, never retried
                                |
             Independent observer reads Suspended with attributed receipt
                                |
        One fixed 1,800-second cutoff from that read's monotonic finish
                                |
                   Independent window-end Suspended read
                                |
            At most three Enabled requests with independent readback
                                |
     New complete protected-empty post-state + linked candidate readback
                                |
                  Keep recovery lock/evidence for review
```

The target is only `dissertation-sandbox-653464153304-us-east-2-s3-01` in
`us-east-2`, account `653464153304`. The baseline has no current objects, versions,
delete markers or incomplete uploads, and requires all existing public-access,
TLS, ownership and encryption protections. No data upload/deletion, public access,
bucket policy, encryption, other resource or region is changed.

## What constitutes a successful engineering result

All of the following must hold: a newly captured locked protected-empty baseline;
readable bound-session metadata and encrypted intent; fresh independent Enabled
admission; one successful suspension response plus a separate Suspended read;
the single 1,800-second window and Suspended endpoint; independent Enabled
restoration readback; a new complete protected-empty post-state; linked encrypted
restoration-candidate readback; and a complete action journal. Failures and
uncertainty are retained, never rerun automatically or relabeled as success.
A successful worker exit can contain a **negative** experiment result.

The first read and window-end read are point observations. They do not prove that
no intervening external change occurred or establish continuous state. The local
lock coordinates cooperating runs on this host; console users, other hosts and
unmodified Terraform commands remain outside its exclusion. Keep this dedicated
bucket and its IAM/SDK configuration unused by other actors during the case.
CloudTrail attribution and native/AI monitoring validity remain formal-study work.

Versioning is outside the two currently selected baseline control candidates.
The case therefore makes no control-compliance or NIST-mapping claim. It does not
replace the six-service catalog, independent ground truth review, learning-group
separation, baseline validation, power analysis, randomized/counterbalanced
comparison, pilot or confirmatory protocol. It exercises proposal traceability
requirements M09 and M13 at the engineering level only.

## Implementation and review boundaries

- `research/development_rehearsal.py`: source/protocol-bound scope builder,
  declaration preview, actual private binding validation, isolated worker and
  one-pass supervisor.
- `research/development_case.py`: fixed action order and bounded recovery using
  trusted maintained adapters; arbitrary Python callbacks are not authenticated
  sources or a security sandbox.
- `research/versioning_point.py`: two fixed calls per slot, dedicated observer
  identity, exact-owner versioning read following the [S3 API contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html), encrypted raw receipts and independent
  in-memory archive reconstruction.
- `research/sandbox_writer.py`: explicit `bound_session` mode in v0.2, one-use
  broker claim and required pre-change checker; the original profile mode stays
  the default and is not bypassed with fabricated profile configuration.
- `scripts/run_development_case.py`: private scope preview by default;
  `--execute` requires a separately approved, enabled current scope.

The concrete scope fixes the source, protocol, Python/OpenSSL/package versions,
public recipient/helper bindings, existing login profile, new run ID and private
paths. The broker role and readback profile are fixed. Intent and writer hashes
are derived only from that run's newly verified retained preparation using the
reviewed derivation; they cannot select a different bucket/action. No credentials,
passwords, private key or token are accepted from chat or retained in records.
All raw responses, approvals, scopes, hashes, inventory, ciphertext and results
remain private. `runtime-pins.json` is written before possible change for recovery
review; it contains metadata fingerprints, never credentials. `window.json`
reports only the planned local cutoff after acknowledged trigger journaling.

The observer's service Date must fit each request interval within five seconds;
wall/monotonic elapsed clocks must agree within one second. The entire point is
bounded to sixty seconds. Full pre-state acquisition must be at most sixty
seconds old and admission at most thirty seconds old at suspension admission.
The exact bound session is checked for the conservative full timing budget
immediately before suspension, including the actual before-send hook. That full
observation budget is not required again for Enabled recovery. Session expiry,
writer lifetime and attempt limits still apply. These are engineering clock
consistency policies, not independent time attestation or a formal protocol freeze.

## Operation budget, costs and interruption

At most **44 planned service calls**: two full captures (12 each), three broker
setup calls, one writer identity call, one suspension plus three possible restores,
and six independent two-call point slots. Normal success uses fewer slots.
Existing profile authentication/credential refresh may make additional provider
calls; these are explicitly outside that service-operation count. SDK operation
retries/redirect resends are blocked in their per-invocation guards.

The run creates no compute, bucket, KMS key, paid ML endpoint or monitoring
activation. Existing request, telemetry and storage charges remain applicable.
The $100 account alerts remain alerts rather than an automatic spending cap.
No price or total-spend guarantee is implied.

The worker has a 3,000-second hard group limit. Cooperative preparation and
observation alarms leave recovery time when Python can handle the interruption.
The 30-minute observation is part of that limit; setup/verification add elapsed
time. Local IO and process reaping are not absolute wall-clock guarantees.
Hard kill, host loss, blocked native code, network/credential failure or a broken
clock can prevent recovery. No code can promise recovery in those conditions.

On interruption, failure or unverified restoration:

1. Preserve the run directory, any recovery lock, intent and all partial evidence.
2. Do not restart the case, acquire a new writer to reset attempts, or use the
   read-only retirement command to close a case that might have mutated AWS.
3. Review `runtime-pins.json`, encrypted pending/response records and known attempt
   counts. If the process was killed, treat unknown attempts as consumed.
4. Prepare a separately reviewed readback/recovery-only scope if needed. It may
   request only Enabled on the same bucket and must independently verify the
   protected-empty post-state before any later reuse. Do not delete unexpected data.

There is no automatic lock release even after positive readbacks. This first case
keeps its verified encrypted closure under the held lock for human review.

## Validation and permission provenance

Focused tests cover one fixed cutoff, durable pre-change ordering, ambiguous
writes, trigger failures, cancellation and evidence outages with bounded recovery;
wrong identity/stale Date/missing state; point ciphertext/hash/phase tampering;
writer/broker one-use run/recipient binding and late-budget recovery; and a complete
SDK-stub/CMS pre-state-to-closure case plus a stale-admission negative case.
All tests use synthetic credentials/observations and disposable recipients.

Runtime SDK source changes are reanalyzed with pinned IAM Policy Autopilot. The
writer's generated effective candidate remains unchanged; no IAM grant is widened.
The full unedited source analyses stay private for review; public provenance
contains only source/tool/analysis fingerprints and closed approval flags. The
point calls are already in the observer's version-controlled baseline and
boundary, and no generated review analysis is attached. Actual identities,
roles/policies, private inputs and source/runtime fingerprints must be checked
again before the approved live pass.

## Using the result for the overdue assignment

The assignment asks for work performed, whether results succeeded and any justified
plan refinements. After this case runs, report its actual outcome and limitations:
methods, expected/observed state sequence, retained evidence and clock policy,
recovery outcome, technical failures and next plan. Distinguish component test
success from measured research findings. State explicitly that AI-versus-baseline
research questions remain unanswered and pilot/confirmatory trials remain zero.
Preserve negative or incomplete runs and use them to justify engineering plan
refinement rather than changing the research question or excluding poor outcomes
without advisor review. The paper should follow the approved proposal and any
actual advisor feedback, not infer a positive AI result from this engineering case.

The upstream point-source inventory command is:

```sh
uvx iam-policy-autopilot@latest generate-policies \
  /absolute/repository/research/versioning_point.py \
  --tf-dir /absolute/repository/infra/sandbox \
  --region us-east-2 --account 653464153304 --service-hints s3 sts --pretty
```

The retained run used cached pinned 0.3.0 with telemetry disabled and no upload
flag. `protocol/versioning-point-policy-provenance.json` records only public source,
tool and analysis fingerprints with all attachment/application flags false. Full
account-specific unedited output is retained privately.
