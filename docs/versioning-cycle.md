# Offline change, observe and restore driver

Status: implemented and tested with synthetic adapters and a disposable encrypted
journal. **No AWS change, restoration or live rehearsal has run.** There is no SDK
write adapter, deployment or live CLI in this component.

`research/versioning_cycle.py` turns the existing recovery decision table into an
ordered callback executor. It is the offline integration layer needed before a
separately reviewed real adapter can coordinate a scenario change and recovery.

```text
Synthetic-only scope + independently pinned synthetic intent
                              |
                 Durable admission and pending-change records
                              |
                      One Suspended callback
                              |
               Independent synthetic Suspended confirmation
                              |
                One fixed 1,800-second observation cutoff
                              |
               Enabled restoration + independent confirmation
                        (at most 3 requests)
                              |
              Terminal encrypted audit; no release authority
```

## Inputs and outputs

`run_offline_versioning_cycle(scope, approved_scope_sha256, callbacks,
monotonic_ns=...)` accepts the exact `offline-versioning-cycle-v0.1` contract,
phase `development`, mode `synthetic_only`. Its horizon is fixed at 1,800 seconds,
with one mutation callback and at most three restoration callbacks. Independent
intent review/source/recipient/content pins must reconstruct the fixed protected
sandbox intent. Current maintained driver dependencies must match the reviewed
source fingerprint. A fingerprint is not permission to perform an AWS write.

The callable map is exact:

| Callback | Input | Output/contract |
| --- | --- | --- |
| `admit` | None | Explicit `synthetic_development_admission` containing the synthetic intent |
| `suspend` | Copied fixed Suspended request description | Simulated write result is ignored; success alone is not a trigger |
| `verify_suspended` | None | Exactly `True` only for independent simulated confirmation |
| `observe_until` | One absolute monotonic cutoff | Exact cutoff plus `window_closed=true`, with clock at or beyond cutoff |
| `restore` | Copied fixed Enabled request description | Simulated write result is ignored; ambiguity still requires verification |
| `verify_enabled` | None | Exactly `True` only for independent simulated restoration confirmation |
| `retain` | Maintained metadata-only event | Ordered CMS filename/ciphertext receipt after durable encrypted retention |

The injected clock lets tests exercise the full horizon without sleeping. The
cutoff is computed once from simulated confirmation; it is not reset after a
late return. The callback must enforce that cutoff on its own collection. This
cooperative executor cannot interrupt a hung callback or prove that it avoided
post-cutoff samples. Future real collection needs bounded workers and independent
source/clock/receipt validation, not a boolean supplied by this test interface.

The result contains synthetic state, request counts, window completion, journal
status and a fixed error category. `restored_in_simulation=true` never changes
`restoration_verified=false`, `lock_release_allowed=false` or
`live_execution_allowed=false`. Research trials remain zero. No raw errors,
provider responses, findings, expected labels or comparative monitor outputs are
returned or added to these journal events.

## Failure and retention behavior

Admission and the pending-change event require valid durable ordered encrypted
acknowledgments **before** the change callback. A failure there prevents change,
observation and restoration callbacks. Existing actual read-only preparation
results are not accepted as synthetic admission or promoted into write authority.

Once a change might have occurred, errors, cancellation, unverified suspension,
incomplete windows and clock rollback route to restoration. The mutation is
never retried. Journal failure after possible change is marked incomplete but
does not prevent the bounded best-effort restoration callbacks. A failed writer
response can still be followed by an independently confirmed Enabled state.
Failed/ambiguous restoration is capped at three requests; cancellation during
restoration stops further retries when confirmation is unavailable. Terminal
state and journal status retain the need for review.

Acknowledgment structure/ordering is checked, but an arbitrary Python callback
can lie or perform other work. This API is for trusted **synthetic test adapters**,
not a security sandbox or a live source attestation. It opens no SDK session,
private key or operational lock. It cannot guarantee recovery after SIGKILL,
host/network loss, process death or a hung adapter. Existing encrypted intent
and independent recovery procedures remain essential for the future live path.

## Validation and next boundary

Four focused test methods cover real disposable CMS journaling/readback,
pre-change approval/admission/retention failures, ambiguous writes, unverified
triggers, incomplete windows, clock rollback, cancellation, three-request recovery
limits and post-change journal outage. They never contact AWS or use the real
recipient. The fixed 1,800-second contract preserves proposal requirement M13;
synthetic completion is not a validated research timing result.

The [disabled SDK transport and generated access root](sandbox-writer.md) are now
implemented separately and tested with SDK stubs; they have not been deployed or
connected to this synthetic executor. Next: review the saved access plan, validate live
credentials/fresh source receipts and process recovery, integrate the lock and
both monitor collectors, then review the exact live rehearsal plan. No role,
policy, monitoring activation or cloud mutation is authorized by merging this code.
The separate read-only retirement path cannot close a future mutating cycle.
