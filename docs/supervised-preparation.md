# Supervised development preparation command

Status: one separately approved live development preparation completed, after
renewed sign-in and verification of the expected account/observer identity. It
retained fifteen encrypted capture records, two journal records and one recovery
intent; authenticated intent readback and post-run metadata/ciphertext linkage
checks passed. No AWS configuration changed, no retry ran and no plaintext was
exported. The lock remains held. Offline tests additionally use SDK stubs and
disposable recipients. The consumed approval authorizes no further run.

This command connects the previously separate components:

```text
Private reviewed scope + independent approval pin
                       |
              Outer supervisor (330 s)
                       |
      Revalidate software, recipient and helper pins
                       |
              Acquire persistent safety lock
                       |
        One read-only observer (150 s worker limit)
                       |
       Verify encrypted capture and receipt window
                       |
       Retain manifest + encrypted recovery intent
                       |
         Read back and verify the retained intent
                       |
      Metadata-only result; lock remains held
```

## Review and execution

`research/preparation_operator.py` defines the exact scope. Its version is
`preparation-operator-v0.1`, phase is `development`, and worker timeout is fixed
at 330 seconds. The nested observer keeps its existing twelve-operation budget:
one STS identity call and eleven fixed S3 metadata/list operations on the
existing sandbox. Credential acquisition/refresh activity is outside that
observation budget. No configuration write or scenario transition is exposed.

The private scope contains:

| Input | Meaning |
| --- | --- |
| `observer`, `observer_scope_sha256` | New current observer scope and independent content pin; exact account, role, bucket, runtime, source, recipient and unused output |
| `human_review_sha256` | Independently retained original review-manifest fingerprint; a hash alone is not consent |
| `lock_root`, `binding_root` | Existing disjoint owner-only directories for shared exclusion and metadata manifests |
| `operator_root` | New operator output directory in an existing private parent |
| `source_sha256` | `preparation_source_sha256()` over maintained research modules, fixed entry points, AWS requirements and native-helper source |
| `bridge.helper`, `helper_sha256` | Existing private executable and independently retained binary pin |
| `bridge.recipient`, `recipient_metadata_sha256`, `encrypted_private_key_sha256` | Existing recipient directory and independent metadata/encrypted-key pins; no plaintext key is read |
| `bridge.helper_source_sha256` | Fingerprint of the previously reviewed native-helper source |
| `bridge.scratch` | Existing disjoint owner-only temporary ciphertext directory |

The observer certificate must be that recipient's `recipient-public.pem`.
Write directories cannot overlap one another or contain bridge dependencies.
All scopes, pins, helper paths and metadata remain private under ignored evidence
storage. Current source and runtime must be used to construct a new scope after
any implementation change; do not reuse a historical capture's approval.

Default preview opens only the bounded private scope file; it does not open
recipient/helper paths, construct a decryptor, create output or contact AWS:

```sh
python scripts/prepare_sandbox.py --scope /absolute/private/preparation-scope.json
```

Only after reviewing and explicitly approving that exact preparation operation:

```sh
python scripts/prepare_sandbox.py --scope /absolute/private/preparation-scope.json \
  --execute --approved-scope-sha256 APPROVED_PREPARATION_SHA256
```

Use the pinned runtime declared in the observer scope. Do not replace placeholders
with passwords, private keys or temporary credentials. Complete sign-in on AWS's
page if required. The command validates existing local profile boundaries through
the maintained observer worker and checks actual assumed-role identity before S3.

## Supervision, outputs and recovery boundary

The parent exclusively reserves `operator_root`, writes private `scope.json`,
and launches the silent worker in its own POSIX session/process group. The
observer explicitly inherits that group. Timeout or cancellation kills the group;
normal parent-worker exit also terminates remaining group members. Native
OpenSSL/Keychain helper children inherit the group. This does not control a
process that deliberately detaches into another session, nor guarantee immediate
return from an uninterruptible kernel IO or process-reaping operation.

The inner preparation checks still require less than 300 seconds and consistent
local wall/monotonic progression. The 330-second outer deadline also covers
retained-intent readback. These are engineering limits, not statistical endpoints,
independent clock proof, source freshness or distributed concurrency exclusion.

`result.json` contains only maintained preparation hashes, closed scientific and
execution gates, and `retained_intent_consistency_verified=true`. It is created
only after bounded authenticated readback of the intent. The parent requires its
exact schema, run and scope pins before reporting worker success. `status.json`
contains worker status and result hash. The parent's `worker_report_verified=false`
is deliberate: schema/content linkage is not independent source authentication.
No raw evidence or decrypted pre-state appears in these files or console output.

Any existing lock, output or manifest blocks reuse. Post-acquisition failure leaves
the lock and all partial ciphertext/metadata in place. There is no automatic retry,
lock release, scenario write, recovery planner event, monitoring activation or
permission deployment. A successful command leaves the sandbox unchanged and
locked. A [separate read-only retirement command](readonly-retirement.md) is now offline-tested; actual retirement still requires its own reviewed scope and approval. Mutating scenarios need independently verified restoration and their own closure process;
do not delete the lock to run again. Pilot and confirmatory trials remain zero.

Three focused integration tests cover pure preview/approval gates, changed pins,
held locks, composed SDK-stubbed capture/CMS/intent readback, timeout preservation
and refusal of success without the exact retained result. Existing real-process
tests cover nested timeout termination and descendant cleanup after normal exit.
