# First development experiment: controlled versioning cycle

**One explicitly approved live development case completed and passed independent local evidence review.** The implementation was merged in PR #63 after required checks passed. This page reports aggregate engineering findings only; account-specific configuration, raw evidence and review records remain private.

## Predeclared procedure and observed outcome

The case tested whether the instrument could perform and document one controlled configuration deviation, preserve a fixed 1,800-second observation window, and restore the protected baseline.

| Stage | Expected state | Independently observed state |
| --- | --- | --- |
| Admission | Enabled | Enabled |
| Trigger | Suspended | Suspended |
| Window end | Suspended | Suspended |
| Restoration | Enabled | Enabled |

One suspension request and one restoration request were used. The window-end request began after the fixed cutoff. A full post-state check matched the protected baseline, and independent local review verified 72 encrypted records across the case and its recovery evidence. These records are audit artifacts from one development case, not additional experimental units.

```text
Verify baseline → one change → independent trigger → fixed window
                                                       ↓
Review retained evidence ← verify protected state ← restore
```

## Interpretation and limits

The case met its predeclared engineering criteria. It supports the feasibility of the injection, observation, evidence and recovery instrument. Endpoint readings do not establish uninterrupted state throughout the interval. Versioning was an engineering test, outside the two selected S3 baseline controls; it is not reported as a NIST compliance finding.

No native-versus-AI predictions or trained study-model evaluation occurred. This is development evidence, separate from pilot and confirmatory collection. Both research-trial counts remain zero. The approval was consumed once, and this outcome grants no rerun or further collection authority.

## Validation and next work

Before the live case, required CI passed 250 Python tests and checks across seven Terraform roots. The complete synthetic composition and stale-admission case were included; test success is separate from the live engineering result.

The progress assignment can now report the work performed, this verified outcome, its limitations and the refined next steps. Monitoring validation, independent catalog expansion, real-feature validation, R power design, pilot and confirmatory work remain. A positive engineering result does not answer whether AI improves compliance monitoring. See [project status](project-status.md) for the remaining work.
