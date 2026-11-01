# Encrypted development recovery intent

`research/recovery_intent.py` connects the offline protection/emptiness predicates, local lock inspection and synchronized CMS archive writer. It prepares recovery material only; it makes no AWS calls and never signals the recovery planner to execute.

## Contents and scope

`build_recovery_intent` requires a valid local run identifier, supplied Enabled sandbox protection metadata, three whole-bucket empty listings, and externally retained review-manifest, source-bundle and normalized public-recipient fingerprints. The fixed proposal fingerprint remains attached. Input evidence is copied, hashed and retained in the private record. Caller edits cannot change an already built record.

The record contains exact proposed S3 `PutBucketVersioning` descriptions: one Suspended mutation and an Enabled restoration, both restricted to the dedicated sandbox, Ohio and expected account owner. They are data, not executed SDK calls or a grant of permissions. No object, encryption, TLS, ownership or public-access change is described. MFA Delete enabled or unknown is rejected; no MFA settings or tokens are requested. See AWS's [PutBucketVersioning contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html).

The administrative reports remain intact, with identity, freshness and concurrency gates closed. A valid hash is not proof of review or human approval. Recovery credentials, restoration and live execution remain explicitly unverified. No scenario labels or predictions are added, and the phase is fixed to development with zero research trials.

## Retention sequence

1. Validate the supplied pre-state and provenance-pin syntax.
2. Inspect the existing private owner-only sandbox lock and require its exact run identifier.
3. Create an exclusive `recovery-intent/` archive beneath that lock using the existing public recipient certificate and a bounded local crypto timeout.
4. Compare the normalized public PEM fingerprint against the external pin.
5. Encrypt and synchronize the private record using the existing CMS writer.
6. Write and synchronize a private `commitment.json` containing the run identifier, recipient/content/ciphertext hashes and closed execution gate.

The record holds raw administrative evidence only inside ciphertext. The public certificate and private commitment file contain no private key. No new recipient is created, no real Keychain item is opened, and no plaintext source evidence is written to disk.

## Interrupted and failed attempts

Failures propagate instead of returning a success commitment. Any partial archive remains under the lock. Repeated preparation and the original owner-only release function reject a lock containing recovery material; they cannot silently replace or remove it. Even successful preparation deliberately leaves the lock held.

An on-disk commitment left after an interrupted final synchronization is not proof that the function returned success. There is no automatic restart, stale-lock takeover, archive cleanup or recovery-aware lock-release procedure in this change. The future reviewed driver must verify actual restoration, retain its audit and explicitly resolve recovery material before allowing reuse. Do not manually remove the lock simply because its owner process exited.

## Offline verification and remaining work

`verify_recovery_intent` consumes an already-decrypted private record and independently retained run/manifest/source/recipient pins. It reconstructs the exact contract and returns the canonical intent hash; the caller must compare that hash to a trusted commitment and independently verify ciphertext identity/decryption provenance. Extra fields, changed phases/actions/targets, changed pins and false-like substituted gate values are rejected. This is consistency checking, not authentication against a same-user writer who can replace files and hashes.

No source clocks, observation horizon, deadline coverage, actual AWS roles, recovery-key availability, live mutation permission or independently observed trigger are established here. A [bounded offline recovery reader and encrypted restoration-candidate writer](recovery-review.md) are now implemented. Operational decryption wiring, verified live source/restoration and recovery-aware closure/release remain unimplemented. The local lock still cannot exclude other hosts, arbitrary Terraform commands or console writers. Those boundaries, source validity and explicit bounded-run approval must be resolved before the first live rehearsal. Pilot and confirmatory paths remain disabled.

Synthetic tests use a temporary test-only RSA recipient to verify actual encryption/decryption, immutable evidence binding, exact recovery actions, wrong-owner/recipient rejection and failure retention. They never use the real recipient, account, private Keychain item or AWS APIs. Historical capture archives are unchanged.
