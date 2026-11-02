# Reviewed retirement of a completed read-only preparation

Status: implemented and tested offline; **the live preparation lock has not been
retired**. Its previous approval explicitly retained the lock. This command needs
its own reviewed scope and approval before use.

This path applies only to a successfully completed `preparation-operator-v0.1`
read-only development operation. It preserves the entire encrypted intent lock
and its original owner marker. It is not the closure path for a scenario that
attempted an AWS write, and it does not certify restoration, independent source
freshness, concurrency exclusion or research readiness. The reviewer must confirm
the exact historical producer/approval was read-only; file hashes alone do not
establish that fact or human authorization.

```text
Reviewed historical scope + result + original lock inventory
                            |
                 Validate completed read-only run
                            |
                  Create persistent retirement guard
                            |
             Reserve a new private archive directory
                            |
           Atomically move the entire original lock intact
                            |
          Recheck bytes and synchronize archival commitment
                            |
              Remove only this operation's guard last
                            |
      A new run may acquire a new lock; old evidence stays archived
```

## Inputs and approval

`research/readonly_retirement.py` defines the exact `readonly-preparation-retirement-v0.1`
scope, phase `development`, kind `retire_completed_readonly_preparation`:

| Field | Required meaning |
| --- | --- |
| `preparation` | Exact historical reviewed preparation scope; it is never executed again |
| `preparation_scope_sha256` | Independently retained historical scope fingerprint |
| `preparation_result_sha256` | Independently retained successful worker-result fingerprint |
| `lock_inventory_sha256` | Independently reviewed fingerprint of every owner/intent file |
| `archive_root` | Existing private canonical directory, disjoint from preparation write directories |
| `source_sha256` | `retirement_source_sha256()` of current maintained retirement dependencies and CLI |

The command rechecks exact completed worker status, retained scope, minimal result,
preparation manifest, original root/lock inode identity, commitment, recipient and
ciphertext receipt. It refuses failed/partial preparations, changed evidence,
existing archive destinations and any expanded lock containing a restoration
candidate or other files. It does not decrypt data or validate a cloud post-state.

Use the existing pinned local runtime. Default preview opens only the bounded
private scope file, with no evidence inspection, output creation or lock change:

```sh
python scripts/retire_readonly_preparation.py --scope /absolute/private/retirement-scope.json
```

Only after separately reviewing and approving this exact local archival operation:

```sh
python scripts/retire_readonly_preparation.py --scope /absolute/private/retirement-scope.json \
  --execute --approved-scope-sha256 APPROVED_RETIREMENT_SHA256
```

Retirement makes no AWS or Keychain call and incurs no new AWS usage. No IAM
policy, infrastructure, monitoring state or research gate changes. Keep private
scopes, paths, fingerprints and original evidence outside Git.

## Preservation and interruption behavior

Before moving anything, the command creates a private fixed retirement guard
beside the operational lock. Current cooperating acquisition code checks for
that guard before reservation, after creating the lock directory and after
synchronization. A guard appearing during acquisition leaves a partial or held
lock for review rather than allowing the caller to start observation.

The destination `<archive_root>/<run_id>/` is reserved exclusively on the same
filesystem. The entire original `<bucket>.lock/` moves into it using anchored
POSIX directory descriptors. There is no recursive deletion, ciphertext rewrite,
copy-and-delete fallback, stale-lock inference or automatic retry. The archive
also retains the reviewed retirement scope and an archival commitment. Original
capture, journal, binding and operator files stay in their original locations.

The archival layout remains compatible with `read_recovery_intent`: its lock root
becomes `<archive_root>/<run_id>/`, with the original run/source/manifest/recipient
and commitment pins. The archived owner and encrypted intent retain identical
bytes. This is preservation, not a new success claim about AWS state.

The guard stays present through archival synchronization and final checks of
metadata, ciphertext and directory identities. A failure before guard removal
blocks new cooperative acquisition even if the original lock name has moved.
Partial guard/archive state requires manual review; never delete it automatically.

After the synchronized archival commitment and all checks, the command removes
only its own guard and synchronizes the operational root. An error or interruption
**after guard removal** can leave a valid committed archive and reuse already
unblocked, with uncertain reported completion. The CLI deliberately reports
`retirement_failed_or_incomplete` and `state_requires_review=true`; it never claims
that every failure leaves the operational lock held. Inspect preserved state
before deciding what occurred. There is no automatic rollback or retry.

This is cooperative local coordination. Older programs ignoring the guard,
already-active writers, another host, arbitrary Terraform/console actions or a
hostile local owner are not excluded. Retirement requires a quiescent completed
read-only run and use of the current acquisition code. Future mutating runners
need their own independently verified restoration and release contract.

Three focused tests use synthetic completed metadata and actual disposable CMS.
They verify pure preview/approval flags, byte-for-byte archival, existing-reader
compatibility, new-lock acquisition only after commitment, changed pins/artifacts,
existing destinations/guards, guards appearing during acquisition, interrupted
rename/commitment/guard removal, changed archival metadata and uncertain final sync.
No operational lock, actual capture, AWS credential or real Keychain item is used.
