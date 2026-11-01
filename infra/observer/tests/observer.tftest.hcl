# Inputs: synthetic provider responses only. Outputs: offline default, boundary and trust checks.
mock_provider "aws" {
  mock_resource "aws_iam_policy" { defaults = { arn = "arn:aws:iam::653464153304:policy/synthetic-observer" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "653464153304", arn = "arn:aws:iam::653464153304:user/martin-morales-personal" } }
}
# Input: source defaults. Output: no observer access exists until deliberately enabled.
run "disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role.observer) == 0 && length(aws_iam_policy.boundary) == 0 && length(aws_iam_policy.generated) == 0 && length(aws_iam_role_policy_attachment.generated) == 0
    error_message = "Default configuration must create no observer access."
  }
}
# Input: mocked enabled access. Output: mandatory trust/boundary and exact resource/action ceiling.
run "bounded_observer" {
  command = apply
  variables { enable_observer_access = true }
  assert {
    condition     = aws_iam_role.observer[0].permissions_boundary == aws_iam_policy.boundary[0].arn && jsondecode(aws_iam_role.observer[0].assume_role_policy).Statement[0].Principal.AWS == "arn:aws:iam::653464153304:user/martin-morales-personal"
    error_message = "Exact non-root trust and mandatory boundary required."
  }
  assert {
    condition     = alltrue([for action in local.maximum_actions : contains(flatten([for statement in local.generated.Statement : statement.Action]), action)]) && length(jsonencode(local.boundary)) <= 6144 && length(jsonencode(local.generated)) <= 6144 && local.boundary.Statement[3].Effect == "Deny" && local.boundary.Statement[3].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Generated baseline must cover the ceiling, fit policy limits and retain transport denial."
  }
  assert {
    condition     = length(local.bucket_actions) == 11 && local.boundary.Statement[0].NotAction == local.maximum_actions && local.boundary.Statement[0].Effect == "Deny" && alltrue([for action in ["s3:GetObject", "s3:GetObjectAcl", "s3:PutBucketVersioning", "s3:PutObject", "s3:DeleteObject", "sts:AssumeRole", "s3-object-lambda:ListBucket"] : !contains(local.maximum_actions, action)])
    error_message = "Extra generated privileges must remain explicitly denied."
  }
  assert {
    condition     = local.boundary.Statement[1].NotResource == "arn:aws:s3:::dissertation-sandbox-653464153304-us-east-2-s3-01" && local.boundary.Statement[1].Effect == "Deny" && local.boundary.Statement[2].Condition.StringNotEquals["aws:RequestedRegion"] == "us-east-2" && local.boundary.Statement[5].Resource == local.bucket && local.boundary.Statement[5].Action == local.bucket_actions
    error_message = "Only exact sandbox metadata in Ohio may escape explicit denials."
  }
}
# Input: root fixture. Output: provisioning is rejected before any IAM resource.
run "reject_root" {
  command = plan
  variables { enable_observer_access = true }
  override_data {
    target = data.aws_caller_identity.current[0]
    values = { account_id = "653464153304", arn = "arn:aws:iam::653464153304:root" }
  }
  expect_failures = [terraform_data.identity_guard[0]]
}
