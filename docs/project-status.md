# Project status and remaining work

The protected AWS foundation, dedicated sandbox, local ML prototype and evidence plumbing are implemented. Development logging/capture observations exist; no pilot or confirmatory research trials exist. New local development uses the non-iCloud checkout at `~/Developer/aws-adaptive-compliance-lab`; the original checkout and private evidence remain preserved.

## Eight major work packages remain open

These packages are not equal in size, strictly sequential, or a percentage-complete estimate. Completing a component advances a package without automatically closing it.

| Work package | Built or established | Needed to close it |
| --- | --- | --- |
| 1. Safe experiment runner | Sandbox; pre-state checks; lock; encrypted intent; bounded recovery reader; encrypted restoration candidates; preview-first Keychain operator; offline observer request/receipt adapter; encrypted capture engine; preview-first supervised observer operator; deployed and independently verified bounded observer access; verified short-lived profile; prepared single-pass capture scope | Separate live-capture approval and retained evidence verification; actual reviewed local verification; independent live receipts/clocks; recovery-aware release; integrated change/observe/restore driver; approved rehearsal |
| 2. Validated monitoring and telemetry | CloudTrail logging and service-reported delivery; encrypted development collection | Reviewed Config/CSPM activation; applicable control validation; attribution, availability, freshness and completeness checks |
| 3. Independent scenario catalog and protocol | Twelve draft S3 cases; separate expected answers and design checks | Six-service coverage; authoritative mappings; viable independent learning groups; review and protocol freeze |
| 4. Study ML pipeline | Executable Isolation Forest, bounded adaptation, mapping and synthetic paired controller | Valid real features, training/anchor inputs, held-out partitions and retained study-model provenance |
| 5. Statistical design and analysis code | Proposal requirements and paired/timing contracts traced | Locked R environment; paired/clustered power simulation; justified sample size; five-outcome analysis verification |
| 6. Pilot validation | Development engineering checks only | Approved pilot, instrument validation and protocol revisions; keep pilot evidence separate |
| 7. Confirmatory experiments and inference | No confirmatory collection | Freeze final protocol/design, obtain approval, collect paired evidence and run prespecified analyses |
| 8. Dissertation results and reporting | Implementation/proposal traceability and documentation | Write from retained findings; verify claims/citations, limitations and reproducibility materials |

Current focus is package 1. Substantial research work remains after the engineering foundation: validated experiments, analysis and results writing have not been completed. A defensible calendar estimate needs the live rehearsal, instrument/pilot findings, catalog review and power-design results; those are not known yet.

## How each completion update is reported

Each work update should state what changed and passed validation, how that advances the study, the next concrete step, and the remaining open packages or gates. Report deployment and research status separately from software tests. Do not turn tests, synthetic demonstrations or development captures into empirical performance claims or invented completion percentages.

The [implementation plan](implementation-plan.md) retains methodological details, exact scientific requirements and approval boundaries. This page is a learning-oriented progress map, not deployment or data-collection authorization.

The [sandbox observer](sandbox-observer.md) now has its own approved and deployed access role. Actual AWS reads verified trust, mandatory boundary, exact policy documents, one generated attachment and no inline policies; the follow-up Terraform plan reported no changes. The local short-lived role profile passed its configured-scope validator and an actual STS identity check. Private approved active inputs preserve the deployed access without changing source defaults.

A single-pass encrypted development-capture scope has been prepared and previewed using the existing public recipient. It remains unapproved, and no sandbox observation or research trial has run. The next gate is approval of that concrete capture, followed by bounded evidence verification; this does not close the integrated runner, instrument-validation or research packages. Ground truth, pilot and confirmatory evidence remain separate.
