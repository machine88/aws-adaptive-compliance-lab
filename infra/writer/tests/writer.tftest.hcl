# Inputs: synthetic IAM attributes. Outputs: offline default, boundary, trust and review-gate checks.
mock_provider "aws" {
  mock_resource "aws_iam_policy" { defaults = { arn = "arn:aws:iam::653464153304:policy/synthetic-versioning" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "653464153304", arn = "arn:aws:iam::653464153304:user/martin-morales-personal" } }
}
# Input: source defaults. Output: no access or backend interaction is requested by mocked planning.
run "disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role.writer) == 0 && length(aws_iam_policy.boundary) == 0 && length(aws_iam_policy.generated) == 0 && length(aws_iam_role_policy_attachment.generated) == 0
    error_message = "Default must create no writer access."
  }
}
# Input: enabled access with a synthetic review pin. Output: exact trust and explicit deny ceiling.
run "bounded_versioning" {
  command = apply
  variables {
    enable_versioning_access = true
    review_manifest_sha256   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  assert {
    condition     = aws_iam_role.writer[0].permissions_boundary == aws_iam_policy.boundary[0].arn && aws_iam_role.writer[0].max_session_duration == 3600 && jsondecode(aws_iam_role.writer[0].assume_role_policy).Statement[0].Principal.AWS == "arn:aws:iam::653464153304:user/martin-morales-personal"
    error_message = "Exact non-root trust, temporary role and mandatory boundary required."
  }
  assert {
    condition     = local.maximum_actions == ["s3:PutBucketVersioning", "sts:GetCallerIdentity"] && local.boundary.Statement[0].Effect == "Deny" && local.boundary.Statement[0].NotAction == local.maximum_actions && local.boundary.Statement[1].NotResource == local.bucket && local.boundary.Statement[2].Condition.StringNotEquals["aws:RequestedRegion"] == "us-east-2" && local.boundary.Statement[3].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Boundary must explicitly deny other actions, buckets, regions and insecure S3 transport."
  }
  assert {
    condition     = local.bucket == "arn:aws:s3:::dissertation-sandbox-653464153304-us-east-2-s3-01" && local.boundary.Statement[5].Action == ["s3:PutBucketVersioning"] && local.boundary.Statement[5].Resource == local.bucket && alltrue([for action in local.maximum_actions : contains(flatten([for statement in local.generated.Statement : statement.Action]), action)]) && length(jsonencode(local.generated)) <= 6144 && length(jsonencode(local.boundary)) <= 6144
    error_message = "Generated baseline must cover only the exact reviewed ceiling within policy limits."
  }
}
# Input: absent review reference. Output: no enabled grant can bypass review provenance.
run "reject_missing_review" {
  command = plan
  variables { enable_versioning_access = true }
  expect_failures = [terraform_data.identity_guard[0]]
}
# Input: root session fixture. Output: refusal before role/policy creation.
run "reject_root" {
  command = plan
  variables {
    enable_versioning_access = true
    review_manifest_sha256   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  override_data {
    target = data.aws_caller_identity.current[0]
    values = { account_id = "653464153304", arn = "arn:aws:iam::653464153304:root" }
  }
  expect_failures = [terraform_data.identity_guard[0]]
}
# Input: alternate account fixture. Output: refusal before role/policy creation.
run "reject_wrong_account" {
  command = plan
  variables {
    enable_versioning_access = true
    review_manifest_sha256   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  override_data {
    target = data.aws_caller_identity.current[0]
    values = { account_id = "000000000000", arn = "arn:aws:iam::000000000000:user/not-reviewed" }
  }
  expect_failures = [terraform_data.identity_guard[0]]
}
