# Preview-first local recovery operator

`scripts/review_recovery.py` now connects the retained-intent reader to the existing `MacKeychainDecryptor`. This is a local verification entry point, not an AWS scenario runner or a lock-release command. No new key-handling mechanism, recipient, permissions or cloud connection is created.

## Prepare a reviewable scope

The valid-JSON [example](../protocol/recovery-operator-scope.example.json) deliberately contains invalid placeholders. It must fail until an operator fills every value using independently trusted retained records. Do not copy fingerprints from untrusted files simply to make verification pass.

The scope binds a development run, lock root, original manifest/source/recipient/commitment identities, existing helper executable and its fingerprint, prepared recipient directory, private ciphertext scratch directory, maintained operator-source fingerprint and byte ceiling. It contains no password, private-key value or AWS credential. Store actual scopes privately, never in Git or chat.

`operator_source_sha256` hashes maintained research Python, this CLI, the native helper source and pinned dependency declarations. It detects changed declared source, not compromised hosts, arbitrary in-memory changes or whether installed dependencies match their declarations. A source change requires renewed scope review. The helper's independent compiled-executable pin remains required.

From the repository root, inspect the current source identity without opening a recipient or Keychain:

```sh
# Only maintained source is read; no private scope or native helper is opened.
.venv/bin/python scripts/review_recovery.py --print-source-pin
```

Prepare an actual scope in an owned 0700 directory, with the JSON file mode 0600. Helper, recipient, lock and scratch paths must identify the already reviewed local artifacts. Preview accepts declared absolute non-traversing paths without opening those targets; it does not prove their availability, permissions or authenticity.

## Default preview

```sh
# Read a bounded private scope; construct no Keychain callback and create no output.
.venv/bin/python scripts/review_recovery.py --scope /absolute/private/review/scope.json
```

Preview returns a minimal scope fingerprint, run ID and closed gates, without private paths or decrypted content. The scope file must be private, canonical, owned, regular, singly linked and at most 64 KiB; duplicate fields and nonfinite JSON are rejected. The retained-intent byte budget must be an integer from 1 through 4 MiB.

## Explicit local verification

Only after separate review and authorization, an operator may use both `--execute` and `--approved-scope-sha256` with the exact independently retained preview hash. A matching supplied hash is not proof of human consent. The command checks that reviewed scope and maintained source match before constructing the existing pinned Keychain callback.

Execution can cause a macOS prompt for the dedicated recipient item; the user must complete it locally. Existing persistent authorization may avoid another prompt. Keep passwords and codes out of chat. This implementation neither grants access nor broadens the helper's fixed recipient service.

The reader invokes the callback once for the committed ciphertext. The existing bridge checks private helper/recipient paths and fingerprints, uses temporary ciphertext scratch, captures authenticated plaintext privately and cleans scratch on success/failure/timeout. The operator prints only a minimal local-consistency summary and content hashes. Failures produce a generic JSON error without provider output, decrypted data or tracebacks. There are no automatic retries or replacement captures.

No verification report archive is created by this entry point; retain approved administrative verification evidence through the reviewed evidence procedure. Successful local reading does not verify actual AWS restoration, freshness, source clocks, credentials for recovery writes, or human approval of a live run. The lock stays held. Live execution and restoration flags remain false, with zero research trials.

## Validation boundary

Six portable tests cover preview without callback construction, scope/source mismatch rejection, explicit execution flags, private scope files, secret-safe helper failure and actual bridge/reader composition using a mocked native helper and disposable CMS recipient. They never access the real Keychain or account. The standalone entry point has not been used on actual retained artifacts. Its shared intent reader and dedicated Keychain helper have now verified an actual intent during the separately approved [supervised preparation](supervised-preparation.md); that pass leaves AWS-restoration and release gates closed.
