# Contributing to AWS Adaptive Compliance Lab

Contributions should improve reproducibility, evidence integrity or a clearly scoped research capability. Open an issue describing the problem before a substantial design change. Never paste credentials, raw inventories, private approvals, research captures, model artifacts or private reviewer information into issues or pull requests.

## Local workflow

Follow the offline setup in the [README](README.md#try-it-without-an-aws-account). Make a focused branch, keep generated artifacts under ignored `evidence/`, and run the relevant tests. Python changes must also pass the function documentation checker; infrastructure changes need mocked Terraform validation. GitHub Actions validates source only and cannot deploy AWS resources.

Every function and method, including test helpers, must explain its purpose and include `Inputs:` and `Outputs:` sections. Describe every named argument, return value, side effect and meaningful failure boundary. State explicitly when there are no arguments or no return value. Add concise intent comments to logical blocks. Keep JSON valid and explain its schema in companion documentation.

## Research boundaries

- Keep development fixtures, pilot evidence and confirmatory observations separate.
- Preserve unknowns, missing/late evidence, failed calls and nondetections.
- Keep expected answers out of model features and prediction generation.
- Respect group-safe learning assignments and score-before-adapt protections.
- Do not change thresholds, exclusions, timing or analysis rules after inspecting confirmatory comparisons.
- Do not describe tests or synthetic demonstrations as empirical performance results.

Explain the problem, behavior change, validation and limitations in a pull request. A merge does not authorize deployment, broader IAM access, live collection, scenario injection or research protocol release. Actual cloud plans and captures require separate explicit approval.

## License status

No software license has been selected yet. Public visibility is not an open-source reuse grant. Resolve licensing with the maintainer before incorporating this code into another project or assuming contribution licensing terms.
