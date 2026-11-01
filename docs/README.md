# Documentation guide

AWS Adaptive Compliance Lab is an experimental comparison of native AWS monitoring and adaptive anomaly detection. Start with the main [project overview](../README.md), then choose the path that matches your task.

## Learn the system

| Question | Start here |
| --- | --- |
| What is built and what remains? | [Progress map](project-status.md), [implementation plan](implementation-plan.md) |
| Where does AI/ML fit? | [Research pipeline](../research/README.md), [ML design](ai-ml-pipeline.md) |
| What is deployed versus paused? | [Prospective instrument review](prospective-instrument-review.md) |
| How is infrastructure isolated? | [Infrastructure guide](../infra/README.md) |
| What governs the study? | [Proposal traceability](proposal-traceability.md), [software design](research-software-design.md) |

## Evidence and timing

- [Read-only collectors](read-only-collectors.md) and [event-history collector](event-history-collector.md): bounded source access and encrypted retention.
- [Native capture](native-capture.md) and [native verification](native-verification.md): acquisition, closure and independent replay.
- [Sampling contract](sampling-contract.md) and [timing/censoring](timing-and-censoring.md): distinguish scheduled, requested, received, missing and late evidence.
- [Archive durability](archive-durability.md): acknowledge encrypted records only after local file/directory synchronization.
- [Archive ingestion](archive-ingestion.md), [state frames](state-frames.md) and [feature bundles](feature-bundle.md): offline transformation boundaries.
- [Keychain ingestion](keychain-ingestion.md): local evidence decryption protections, not an AWS credential store.

## Scenario safety

Read these in order before proposing a live workflow:

1. [Sandbox design and review](scenario-sandbox-review.md).
2. [Administrative protection checks](sandbox-administrative-readiness.md).
3. [Full-bucket empty-listing contract](sandbox-empty-listings.md).
4. [Recovery decision planner](scenario-recovery-planner.md).
5. [Persistent local execution lock](scenario-execution-lock.md).
6. [Encrypted recovery intent](recovery-intent.md).
7. [Offline recovery reading and restoration review](recovery-review.md).
8. [Preview-first local recovery operator](recovery-operator.md).
9. [Sandbox observer](sandbox-observer.md), [supervised capture operator](sandbox-operator.md), and [observer access preparation](sandbox-observer-access-preparation.md).

These documents describe components and review requirements. They do not grant live-run approval. The lock is local and cooperative; a future driver and Terraform entry points still need integration.

## Deployment history and approvals

[Phase 2 review](phase2-deployment-review.md), [bounded access review](sandbox-access-review.md), [evidence-reader review](evidence-reader-review.md), [state migration](state-migration-completed.md) and [staged activation](staged-activation.md) describe their own historical scopes. Do not treat an old approved plan as permission for a new action.

Some historical documents use the original dissertation project name. Existing AWS identifiers and private retained evidence keep their original names for traceability. Raw approvals, state, account responses, captures and the source proposal remain private.
