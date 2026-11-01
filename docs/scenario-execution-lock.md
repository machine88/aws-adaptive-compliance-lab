# Persistent local sandbox execution lock

`research/scenario_lock.py` adds a local filesystem exclusion primitive for a future scenario driver. It performs no AWS, credential, encryption or model operations. No live driver or Terraform command uses it yet.

## Acquisition and recovery

The operator supplies one existing canonical absolute, user-owned `0700` directory on a local filesystem. Every cooperating runner must use this same directory. The sandbox-specific lock name is fixed, so changing the run identifier cannot create a second lock for the same bucket. Acquisition uses atomic directory creation and exclusively writes a `0600` owner record; the record and parent entries are flushed before success is returned. Run identifiers are exactly 32 lowercase hexadecimal characters and cannot contain path components.

An existing lock always blocks acquisition. Age, PID disappearance, process exit and timeouts never establish that AWS was restored, so there is no automatic stale-lock cleanup. Partial creation, an exception, cancellation or process death leaves the directory in place. A future runner must retain recovery instructions before mutation and preserve this lock on unverified recovery.

Release is an explicit operation requiring the matching run identifier and an intact private regular owner file. Extra files, symlinked records, missing metadata and ownership mismatches fail without recursive cleanup. The caller must independently verify cloud restoration and retain its audit before release; the function verifies filesystem ownership, not AWS restoration or human approval. A matching identifier alone is not proof of either.

## Scope and limitations

This is a cooperative single-host filesystem lock, not a distributed AWS lease or an access-control boundary against the same OS user. Another directory, machine, unmodified Terraform process or AWS console session can bypass it. The future live plan must pin the shared lock root and require Terraform and scenario entry points to acquire the same lock. It also needs permissions and operating procedures excluding unrelated writers; this primitive does not supply them. Network filesystem semantics and hostile same-user path replacement are not supported. No scientific freshness, clock, trigger, completeness or authorization gate is opened.

A residual lock requires inspecting the retained run and actual AWS state under an approved recovery procedure. Do not delete it merely because a process exited. No live recovery command is supplied or authorized by this implementation.

## Verification

Synthetic tests cover duplicate acquisition, matching release/reacquisition, private file modes, persistence after a child process exits, wrong-owner release, partial/extra records, broad directory permissions, path-like identifiers and symlinked record rejection. Tests create only temporary local files. Every function documents purpose, inputs, outputs and side effects. No research trial or paid cloud operation occurs.

The [recovery-intent preparer](recovery-intent.md) now uses read-only `inspect_sandbox_lock(root, run_id)` before creating an exclusive archive beneath the lock. Inspection shares the original release checks. A lock containing that archive deliberately fails owner-only inspection/release; a future reviewed recovery-aware closure procedure is still required.
