# Observer access review preparation

Status: **disabled-by-default Terraform prepared and tested offline; no saved live plan or deployment approval yet**. The existing evidence-reader excludes the sandbox. Its permissions remain unchanged. The intended new role is `dissertation-sandbox-observer` for the exact bucket `dissertation-sandbox-653464153304-us-east-2-s3-01` in Ohio, with no object-body access or mutations.

## Reproducible source analysis

IAM Policy Autopilot 0.3.0 was available in the local cache. Python/boto3 support and command flags were verified through its help. The original dynamic dispatcher produced `Policies: []`, which was rejected as incomplete. The maintained collector now uses explicit, allowlisted SDK read calls. Its existing SDK integration checks exercise every declared read.

The reviewed analysis command, which uploads/applies nothing, is:

```sh
DISABLE_IAM_POLICY_AUTOPILOT_TELEMETRY=true uvx --offline iam-policy-autopilot==0.3.0 generate-policies \
  /Users/martinmmorales/Developer/aws-adaptive-compliance-lab/research/sandbox_capture.py \
  /Users/martinmmorales/Developer/aws-adaptive-compliance-lab/scripts/sandbox_capture_worker.py \
  --region us-east-2 --account 653464153304 --service-hints s3 sts \
  --tf-dir /Users/martinmmorales/Developer/aws-adaptive-compliance-lab/infra/sandbox --pretty
```

The installed `@latest` cache resolved to 0.3.0 during the actual analysis. The pinned command above documents that version for reproduction. `--offline` constrains uv's package resolution; it does not guarantee that the analyzer itself will make no documentation/network requests. It is not a Terraform planning/apply command, and it uses no `--upload-policies` option.

## Broad candidate rejected for standalone use

The explicit source produced a candidate containing the eleven expected S3 bucket-level action names:

- `s3:GetBucketLocation`, `s3:GetBucketOwnershipControls`, `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`.
- `s3:GetBucketPublicAccessBlock`, `s3:GetBucketTagging`, `s3:GetBucketVersioning`, `s3:GetEncryptionConfiguration`.
- `s3:ListBucket`, `s3:ListBucketVersions`, `s3:ListBucketMultipartUploads`.

It also included wildcard bucket/access-point resources, `s3:GetObjectAcl`, two `s3-object-lambda` actions, and an unscoped `sts:GetCallerIdentity` statement. The candidate is **not accepted for standalone attachment**. Its unedited policy is now retained under `infra/observer/generated-observer-policy.json` only alongside a mandatory restrictive boundary. A tool-generated action list does not establish least privilege or actual runtime necessity. Nothing was uploaded or attached.

## Work needed before approval

1. Verify operation/action/resource/dependent-permission mappings against current authoritative AWS references for this general-purpose bucket. Resolve the analyzer's extra actions and wildcard resources explicitly; an incomplete candidate must not be repaired by granting broad access.
2. Prepare a dedicated Terraform role, exact existing non-root trust principal, a boundary and narrowly scoped runtime policy. Bind access to the fixed sandbox and Ohio; exclude object bodies, writes, unrelated buckets and discovery. Separately review any source principal permission to assume that exact role.
3. Isolate access state under a new reviewed backend key. Produce a saved plan and check that only the new observer access is affected, with no baseline activation, bucket replacement or widened old reader.
4. Obtain approval of that concrete access plan before applying. Separately review the actual local profile/source identity and public-recipient/operator scope before requesting live-capture approval. Keep raw plan/config/account responses private.
5. Record request-cost assumptions with the reviewed capture. The account's $100 alert remains a notification, not an automatic cutoff. This change creates no resources or AWS request charges.

The [operator documentation](sandbox-operator.md) describes the software now ready for that local review. No successful live observation, IAM simulation or actual profile validation is claimed.

## Prepared Terraform scope

`infra/observer` uses its own `observer-access/terraform.tfstate` backend key under the existing account/region state prefix. It does not manage state buckets, the sandbox bucket, the older evidence reader, monitoring activation or any compute. `enable_observer_access` defaults to false. Enabling it proposes two managed policies, one role, one role-policy attachment and a local Terraform identity guard; the generated policy is never attached without the boundary already on the role. No user policy or local AWS profile is changed by this root.

The custom boundary allows the eleven bucket actions only on the exact sandbox in Ohio plus caller identity. Explicit denials block other actions, S3 resources outside the bucket, other S3 request regions and insecure transport. Generated object-ACL/Object Lambda extras are outside the action ceiling. There is no object-content, mutation, role-chaining, backend-state or unrelated-bucket permission. Trust names only the existing non-root IAM user. IAM role maximum session duration is one hour; the operator requests 900-second sessions through its separately reviewed profile.

The boundary is intentionally authored as a permissions ceiling; the identity baseline remains unedited generated output. [AWS boundary semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) explain the intersection and explicit-deny behavior, including the risks of resource-based session grants. The explicit cross-resource/action denials avoid relying solely on implicit boundary denials. This is not proof of live authorization: SCPs, bucket policies and other applicable controls can still deny a request.

[AWS documents](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html#mpuAndPermissions) `s3:ListBucketMultipartUploads` for in-progress upload listing; [version listing](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html) requires `s3:ListBucketVersions`. The collector uses neither object ACL reads nor Object Lambda endpoints. If live checks show a permission mismatch, stop and review it rather than relaxing the ceiling.

All managed resources have `prevent_destroy`. Returning the enabled input to false after deployment is not a pause operation; it will be blocked as removal and requires explicit disposition review. Schema validation and three mock-provider runs cover disabled defaults, exact trust/ceiling/resource guards and root rejection. A source/policy provenance regression binds the unedited candidate to the two analyzed files; `protocol/observer-policy-generation.json` documents these inputs/outputs and closed approval gates. These checks do not call the AWS IAM simulator or constitute a saved live plan.

Next: verify actual non-root identity and live name/state conflicts read-only, establish the source principal's exact role-assumption rights, generate a private saved plan and inspect every proposed change. Obtain explicit approval before applying it. Live collection requires its own scope review and approval afterward. Backend request/storage costs belong in that review; no request charges or new resources were incurred by the offline tests.
