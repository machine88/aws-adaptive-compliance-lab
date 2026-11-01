# Observer access review preparation

Status: **analysis only; no deployable access plan or approved policy yet**. The existing evidence-reader excludes the sandbox. Its permissions remain unchanged. The intended new role is `dissertation-sandbox-observer` for the exact bucket `dissertation-sandbox-653464153304-us-east-2-s3-01` in Ohio, with no object-body access or mutations.

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

## Candidate rejected for deployment

The explicit source produced a candidate containing the eleven expected S3 bucket-level action names:

- `s3:GetBucketLocation`, `s3:GetBucketOwnershipControls`, `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`.
- `s3:GetBucketPublicAccessBlock`, `s3:GetBucketTagging`, `s3:GetBucketVersioning`, `s3:GetEncryptionConfiguration`.
- `s3:ListBucket`, `s3:ListBucketVersions`, `s3:ListBucketMultipartUploads`.

It also included wildcard bucket/access-point resources, `s3:GetObjectAcl`, two `s3-object-lambda` actions, and an unscoped `sts:GetCallerIdentity` statement. The candidate is **not accepted for attachment or deployment**. A tool-generated action list does not establish least privilege or actual runtime necessity. No broad candidate was committed as a ready-to-use infrastructure policy, uploaded or attached.

## Work needed before approval

1. Verify operation/action/resource/dependent-permission mappings against current authoritative AWS references for this general-purpose bucket. Resolve the analyzer's extra actions and wildcard resources explicitly; an incomplete candidate must not be repaired by granting broad access.
2. Prepare a dedicated Terraform role, exact existing non-root trust principal, a boundary and narrowly scoped runtime policy. Bind access to the fixed sandbox and Ohio; exclude object bodies, writes, unrelated buckets and discovery. Separately review any source principal permission to assume that exact role.
3. Isolate access state under a new reviewed backend key. Produce a saved plan and check that only the new observer access is affected, with no baseline activation, bucket replacement or widened old reader.
4. Obtain approval of that concrete access plan before applying. Separately review the actual local profile/source identity and public-recipient/operator scope before requesting live-capture approval. Keep raw plan/config/account responses private.
5. Record request-cost assumptions with the reviewed capture. The account's $100 alert remains a notification, not an automatic cutoff. This change creates no resources or AWS request charges.

The [operator documentation](sandbox-operator.md) describes the software now ready for that local review. No successful live observation, IAM simulation or actual profile validation is claimed.
