# Locked observer-to-recovery preparation

Status: callback-based integration implemented and tested offline; one separately approved supervised live preparation has now completed with verified encrypted intent readback. No AWS mutation ran, and its local lock remains held. The earlier standalone observer pass remains separate historical development evidence. The separate [supervised preparation command](supervised-preparation.md) now supplies a reviewed live adapter; this callback module itself has no mutation command.

`research/observer_recovery_preparation.py` connects the existing local exclusion lock, observer operator, bounded archive reader and encrypted recovery-intent writer. This is preparation for a future reviewed development rehearsal; it grants no research or scenario-execution authority.

```text
Reviewed current scope + unused output + private lock/binding roots
                              ↓
                  Acquire persistent local lock
                              ↓
             One separately authorized observer callback
                              ↓
       Verify archives and local acquisition-window consistency
                              ↓
       Persist metadata-only preparation manifest, then encrypted intent
                              ↓
        Return pins with lock held and execution disallowed
```

## Inputs and outputs

`prepare_recovery_from_observer` accepts private lock/binding roots, an independently reviewed current observer scope/hash, an original human review-manifest hash, a trusted one-pass observer callback and an authenticated decryptor. Optional wall/monotonic clocks support deterministic offline tests. A callback is not itself proof of approval or provider authenticity; a future live wrapper must enforce its own reviewed scope and supervision before invoking this API.

The observer callback receives a copied scope and approved hash, after the lock is acquired, and returns the exact maintained operator summary. It must not change AWS configuration. The controller requires a new, absent output path outside the lock; an existing output, preparation manifest (including a broken link) or held lock blocks observation. Manifest names require the validated run identifier and cannot traverse paths. It never retries, releases a lock or emits the recovery planner's `preflight_retained` event.

The result contains only run/manifest/intent/inventory pins, local consistency status and closed execution/scientific gates. The API does not return or write plaintext responses. The shared private pre-state reader supplies raw data only in caller-owned memory; the existing recovery writer encrypts metadata/listings before retention. The separately written preparation manifest contains hashes, local times and lock inode linkage, not raw AWS data.

## Local timing and lock checks

Open root/lock directory descriptors stay anchored across observation, verification and retention. Named directory identities, private owner/mode, exact owner marker and permitted inventory are checked at each stage. Lock replacement, permission changes, owner changes or partial/extra files fail closed. Success preserves `owner.json` plus the existing `recovery-intent` layout, so the established recovery reader remains compatible. No recursive cleanup, PID/age-based stale-lock deletion or automatic release is added.

Every identity and S3 receipt must fall between the host wall clocks bracketing that new callback. Host wall and monotonic time must progress in order through acquisition, verification and retention, with less than 300 seconds total and no more than one second of wall/monotonic disagreement per checked interval. These are provisional **engineering consistency limits**, not statistical thresholds, synchronized-clock proof or AWS freshness attestation. They do not authorize later mutation from an aging retained observation.

The checks are cooperative and cannot interrupt a stuck callback or filesystem sync. A future live wrapper needs reviewed process supervision around the entire flow. On any failure after acquisition, the function closes only its descriptors: lock, capture and partial manifest/intent remain for manual review. A trusted external callback or a different host/root/console can bypass cooperative exclusion; this is not a distributed lock or protection against a hostile local owner.

## Existing intent schema and review linkage

The metadata manifest links the original human review hash to the approved observer scope, ciphertext fingerprint, source/recipient pins, raw private-frame hash, verification report hash and local acquisition/verification window. It is exclusively created as an owner-only file and synchronized before intent retention.

The manifest's canonical hash becomes the existing intent's `review_manifest_sha256`. The original human review hash remains inside that manifest. The intent and recovery-reader schemas are unchanged: downstream readers must use the **returned preparation-manifest pin**, source/recipient pins and returned intent-commitment pin. They must not substitute the original human review hash or derive a trusted pin solely from decrypted data. Hash syntax/content consistency does not establish human authorization.

The manifest's private-frame hash includes identity and ordered receipts. The intent's own pre-state hash covers its reduced metadata/listing payload. These hashes intentionally describe different scopes. Both remain linked to the retained observer inventory and original review.

## Validation and remaining gates

Three focused test methods compose the real operator, worker, SDK stubs, CMS archive reader/writer and existing recovery reader using disposable recipients. They cover successful linkage, existing-output/binding/lock admission failures, callback errors, deadline/clock rollback or jumps, out-of-window receipts, lock replacement/owner/permission changes and persistence failure. They verify one callback, held exclusion and no implicit release/retry. No real AWS profile, Keychain item, historical capture or operational lock is used.

The first integrated pass used its own reviewed scope and explicit approval. That approval is consumed and cannot authorize another run. Independent source/clock validation, recovery credentials, restoration/closure proof, safe release, the change/observe/restore driver, monitoring validation and the separately approved rehearsal remain open. Pilot and confirmatory data stay separate, and research trials remain zero.


## Nested process supervision prerequisite

The shared worker supervisor and observer operator now offer an explicit
`inherit_supervisor_group=True` mode used by the outer preparation worker.
It is accepted only when the invoking process is already both its own session
leader and process-group leader, before reserving observer output. Standalone
calls retain their existing separate-session behavior.

This prevents a nested observer from detaching into a new session beyond the
outer timeout's reach. In nested mode an inner timeout kills/reaps its immediate
child; the outer supervisor remains responsible for terminating the entire
shared group. The mode does not itself create an outer supervisor, stop arbitrary
descendants that deliberately detach, or impose a deadline on filesystem sync.
The separate supervised preparation command now uses this nested mode; live execution still needs its own approval.

Offline regression tests launch a real isolated outer supervisor and nested
sleeping child, then verify that the outer deadline stops the descendant. They
also reject nested mode outside an isolated leader before spawning a process.
