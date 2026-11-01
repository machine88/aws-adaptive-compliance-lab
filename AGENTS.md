# Dissertation project safeguards

- Use AWS profile `dissertation`, expected account `653464153304`, default research region `us-east-2`.
- Verify identity before AWS work. Do not use root sessions.
- Do not deploy or incur research infrastructure charges without explicit user approval of a reviewed plan.
- Use version-controlled Terraform for this study. Preserve existing account resources and isolate state.
- The final dissertation proposal is the methodological source of truth; do not substitute chat summaries.
- Keep development, pilot and confirmatory evidence separate. Do not invent research results.

## Code documentation

- Document every function and method, including test helpers, with its purpose, an `Inputs:` section describing every named argument, and an `Outputs:` section describing the return value and side effects. Explicitly state when there are no arguments or no return value.
- Add brief intent comments to logical code blocks and explain configuration inputs/outputs. Keep the explanations useful for a reader learning the system. JSON files must remain valid JSON; document them in a companion reference instead of adding invalid comments.
- Add short file or module descriptions and comments for configuration blocks or non-obvious code where they help explain purpose, safeguards or research assumptions.
- Keep comments plain and concise. Explain intent without narrating obvious operations; update descriptions whenever behavior changes.
- Apply this convention to both new code and existing code touched during implementation.

<!-- BEGIN AWS Agent Toolkit rules -->
# AWS Guidance

- Where these AWS rules conflict with the project's own instructions, the
  project's instructions take precedence.
- Prefer the AWS MCP Server for AWS interactions — it provides sandboxed
  execution, observability, and audit logging. If unavailable, use the
  AWS CLI directly.
- Before starting a task, check whether a relevant AWS skill is available.
  Load the skill with `retrieve_skill` and prefer its guidance over
  general knowledge.
- When uncertain about specific AWS details (API parameters, permissions,
  limits, error codes), verify against documentation rather than guessing.
  State uncertainty explicitly if you cannot confirm.
- When creating infrastructure, prefer infrastructure-as-code (AWS CDK or
  CloudFormation) over direct CLI commands.
- When working with infrastructure, follow AWS Well-Architected Framework
  principles.
- Do not use em dashes in AWS resource names or descriptions. Use
  hyphens instead.

## Secret Safety

- MUST load the `aws-secrets-manager` skill first for any secret,
  credential, API key, token, or password task. MUST NOT call
  `secretsmanager get-secret-value` or `batch-get-secret-value`, and MUST
  NOT hit the Secrets Manager Agent daemon directly. MUST use
  `{{resolve:secretsmanager:secret-id:SecretString:json-key}}` with
  `asm-exec` so the secret resolves at runtime without entering context.
<!-- END AWS Agent Toolkit rules -->

## Learning support

- Include occasional simple diagrams at major milestones so the user can learn the architecture and workflow.
- Clearly label what is deployed, planned, paused, and awaiting approval; explain new terms in plain language.

## Cost preference

- Use a $100 monthly account-wide alert budget, with early warnings and no automatic spending cutoff. Prioritize completing the dissertation while avoiding unnecessary AWS spend.

## Continuation preference

- After a code PR passes required checks, merge it and continue the next useful implementation step without asking for routine merge confirmation.
- Report completed milestones and keep progressing; do not stop merely because a PR merged.
- Preserve explicit approval of reviewed AWS deployment plans and live research/development capture. Routine continuation does not waive those gates.

## Completion updates

- End each completed work update with what was done and tested, how it helps the study, the next concrete step, and how much remains using verified milestones/open gates.
- Maintain `docs/project-status.md` alongside behavior and milestone changes. Avoid unsupported completion percentages or calendar promises; distinguish engineering progress from research readiness.

## Test scope

- Add tests only for meaningful safety, evidence-integrity, integration or regression behavior. Reuse existing coverage and extend focused cases where possible. Do not add tests merely to mirror implementation, check trivial display output or increase test counts.
