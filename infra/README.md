# Infrastructure guide

Terraform defines AWS Adaptive Compliance Lab's research foundation. The checked-in configuration is bound to a specific research account and Ohio region; it is not a generic one-command deployment template.

## Terraform roots

| Root | Purpose |
| --- | --- |
| `bootstrap/` | Private, encrypted, versioned S3 remote state with native lockfiles |
| `access/` | Bounded deployment roles, permissions boundaries and sandbox access |
| `baseline/` | Telemetry S3, CloudTrail, AWS Config, Security Hub CSPM and budget notifications |
| `reader/` | Scoped read-only evidence access |
| `observer/` | Disabled-by-default sandbox observation role, generated baseline and mandatory boundary |
| `sandbox/` | Dedicated private, encrypted, versioned development S3 bucket |

Separate protected state keys isolate roots. Private backend settings and approved active inputs remain outside Git. The public GitHub name does not change deployed `dissertation-*` identifiers or backend keys.

## Validate without deploying

Use Terraform **1.15.0** and the committed provider lockfiles. From the repository root:

```sh
# Check formatting, then validate and test each root without remote state access.
terraform fmt -check -recursive infra
for root in bootstrap access baseline reader sandbox observer; do
  terraform -chdir="infra/$root" init -backend=false -input=false || exit 1
  terraform -chdir="infra/$root" validate || exit 1
  terraform -chdir="infra/$root" test || exit 1
done
```

Provider downloads require network access. These test suites use mocked providers and need no AWS deployment credentials. CI performs the same source-validation role and has no AWS deployment permissions.

## Current retained deployment status

The foundation and dedicated sandbox are deployed. CloudTrail logging is enabled; Config recording is paused; Security Hub CSPM has no enabled standards. The $100 monthly account-wide budget sends configured alerts rather than imposing a spending cap. These statements summarize retained deployment records, not a fresh live inventory.

The existing evidence reader does not cover the sandbox. A separate observer role is deployed with its mandatory boundary, exact trust and one generated attachment verified; the follow-up plan reported no changes. Its active input remains private and must stay enabled in future plans. Offline empty-state checks and the local lock do not prevent other writers. One separately approved development metadata pass has completed; additional captures or scenario changes still require their own reviewed approval. No automatic deployment workflow exists.

## Before any live plan

Verify the actual non-root identity, account and region. Review the exact target resources and state keys, bounded roles, resource disposition, request/storage costs, recovery and evidence retention. Generate and review a saved plan, obtain approval, then apply only that approved plan under the reviewed role. Do not bypass an access failure with the provisioning user.

Creation and activation defaults are off in source; those defaults are not pause switches for deployed resources. Preserve explicit approved active inputs in later plans. Do not rename or recreate state buckets, roles or telemetry resources just to match the new project branding.

Start with the [deployment review](../docs/phase2-deployment-review.md), [sandbox review](../docs/scenario-sandbox-review.md), [bounded access review](../docs/sandbox-access-review.md) and [roadmap](../docs/implementation-plan.md). Cloud changes, captures and scenario runs have separate approval gates.
