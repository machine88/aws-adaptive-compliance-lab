# Research pipeline

This package contains the offline research contracts and development instrument for AWS Adaptive Compliance Lab. It combines an actual local Isolation Forest implementation with fixed technical predicates; it does not use a language model to decide compliance.

## How a future comparison works

```text
Equivalent retained AWS evidence
    ├── Native baseline adapter ───────────────────┐
    └── Numeric features → Isolation Forest       │
            + observed technical facts            │
            → deterministic mapping ──────────────┤
                                                  ↓
                                      Save both predictions
                                                  ↓
Separate ground truth ──────────────────→ Later evaluation
```

The diagram is the intended paired design. Live feature release, baseline fusion and the formal controller remain incomplete. An anomaly score indicates unusualness, not proof of a control violation. The mapper preserves unknown/instrumentation-failure outcomes when evidence is insufficient.

## Components and boundaries

| Component | Purpose | Boundary |
| --- | --- | --- |
| `ml.py` | Isolation Forest fitting/scoring, independent anchor calibration and bounded adaptation | Offline prototype; no study model trained |
| `controller.py` | Bind declared learning assignments, persist paired predictions, join answers later | Completed-observation development controller; not a cloud scheduler |
| `aws_reader.py` | Scoped plans and synchronized encrypted local archives | Local persistence only; no live-run authorization |
| `native_capture.py` | Bounded worker calls and encrypted journal integration | Requires separately reviewed scope and live approval |
| `sandbox_readiness.py` | Validate supplied bucket protection metadata | Cannot authenticate identity or freshness |
| `sandbox_emptiness.py` | Require whole-bucket empty current/version/upload listings | Offline predicate; no live emptiness proof or concurrent-writer exclusion |
| `scenario_recovery.py` | One suspension attempt and bounded restoration decisions | Consumes event names, not authenticated cloud receipts |
| `recovery_operator.py` | Review a private scope and explicitly connect the existing Keychain callback | Preview default; actual retained-artifact verification and live restoration still pending |
| `recovery_review.py` | Bounded private intent reading and encrypted restoration candidates | Supplied consistency only; no verified live restoration or automatic unlock |
| `recovery_intent.py` | Retain encrypted pre-state and fixed recovery actions under a matching lock | Preparation only; no verified live identity, execution or recovery-aware release |
| `development_rehearsal.py` | Preview-first source-bound development case, full encrypted preparation/restoration and supervisor | Needs explicit live approval; no formal trial or automatic unlock |
| `development_case.py` | One change, fixed window and bounded recovery orchestration | Maintained trusted adapters; negative results preserved |
| `versioning_point.py` | Independent attributed versioning read and encrypted archive reconstruction | Point observations, no continuous-state/compliance claim |
| `writer_session.py` | Fixed opt-in role request, static SDK session and retained nonsecret expiration/identity metadata | Explicit bound-writer integration tested offline; no live run or automatic refresh |
| `writer_coverage.py` | Reject insufficient or stale supplied session timing metadata | Offline planning only; no provider proof or live admission |
| `scenario_lock.py` | Persistent exclusion for cooperating local runs | Not distributed; no live/Terraform integration yet |

## Model and evaluation safeguards

Training, anchor calibration, adaptation and held-out assignments must respect independent overlap groups. The current real catalog has insufficient independent groups; synthetic test groups cannot solve that limitation. Predictions are saved before adaptation, and held-out observations cannot update the model. Ground-truth values reach only the later evaluation boundary.

Bounded adaptation limits candidate batch/pool sizes and threshold movement, preserves anchors and supports rejected-update rollback. Passing these software checks is not evidence that adaptation improves study outcomes. Read the [ML protocol explanation](../docs/ai-ml-pipeline.md) and [development controller](../docs/development-controller.md) for the precise contracts.

## Run locally

Use the dependency setup in the [main README](../README.md#try-it-without-an-aws-account). From the repository root:

```sh
# Check research contracts with synthetic fixtures; no AWS credentials required.
.venv/bin/python -m unittest discover -s tests -v

# Write a new synthetic run with fitted artifacts and explicitly unknown baseline outputs.
.venv/bin/python scripts/controller_smoke.py --output evidence/new-synthetic-controller-run
```

The second command requires a new path and writes private local development artifacts. No AWS calls or research trials occur. The [roadmap](../docs/implementation-plan.md) tracks the six-service catalog, instrument validation, R power simulations, pilot and separate confirmatory study still required.
