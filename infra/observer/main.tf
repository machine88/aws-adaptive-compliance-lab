# Inputs: explicit provisioning profile and isolated backend key. Output: observer-access state only.
terraform {
  required_version = "~> 1.15.0"
  backend "s3" {
    bucket               = "dissertation-653464153304-us-east-2-state"
    key                  = "dissertation/653464153304/us-east-2/observer-access/terraform.tfstate"
    region               = "us-east-2"
    profile              = "dissertation"
    allowed_account_ids  = ["653464153304"]
    encrypt              = true
    use_lockfile         = true
    workspace_key_prefix = "dissertation/653464153304/us-east-2/observer-access/workspaces"
  }
  required_providers {
    aws = { source = "hashicorp/aws", version = "6.36.0" }
  }
}
# Input: explicit existing non-root profile. Output: guarded Ohio provider.
provider "aws" {
  profile             = "dissertation"
  region              = "us-east-2"
  allowed_account_ids = ["653464153304"]
  default_tags { tags = { Project = "aws-ai-compliance-dissertation", Purpose = "sandbox-observation", Phase = "development" } }
}
# Input: separately reviewed access deployment choice. Output: no IAM resources by default.
variable "enable_observer_access" {
  type        = bool
  default     = false
  description = "Enable only after explicit approval of the saved observer-access plan."
}
# Input: selected session when enabled. Output: current identity; no unrelated discovery.
data "aws_caller_identity" "current" { count = var.enable_observer_access ? 1 : 0 }
# Input: identity/workspace. Output: refusal of root, alternate principals and workspaces.
resource "terraform_data" "identity_guard" {
  count = var.enable_observer_access ? 1 : 0
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current[0].arn == "arn:aws:iam::653464153304:user/martin-morales-personal" && terraform.workspace == "default"
      error_message = "Use the reviewed non-root IAM user and default workspace."
    }
  }
}
# Inputs: unedited generated candidate plus reviewed maximum. Output: explicit deny ceiling.
locals {
  bucket    = "arn:aws:s3:::dissertation-sandbox-653464153304-us-east-2-s3-01"
  generated = jsondecode(file("${path.module}/generated-observer-policy.json"))
  bucket_actions = [
    "s3:GetBucketLocation", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging",
    "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:ListBucket",
    "s3:ListBucketMultipartUploads", "s3:ListBucketVersions"
  ]
  maximum_actions = concat(local.bucket_actions, ["sts:GetCallerIdentity"])
  boundary = {
    Version = "2012-10-17"
    Statement = [
      # Explicit denials also constrain resource-based grants to role sessions.
      { Sid = "DenyOtherActions", Effect = "Deny", NotAction = local.maximum_actions, Resource = "*" },
      { Sid = "DenyOtherStorage", Effect = "Deny", Action = "s3:*", NotResource = local.bucket },
      { Sid = "DenyOtherRegions", Effect = "Deny", Action = "s3:*", Resource = "*", Condition = { StringNotEquals = { "aws:RequestedRegion" = "us-east-2" } } },
      { Sid = "DenyInsecureTransport", Effect = "Deny", Action = "s3:*", Resource = "*", Condition = { Bool = { "aws:SecureTransport" = "false" } } },
      { Sid = "ObserverIdentity", Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
      { Sid = "SandboxMetadata", Effect = "Allow", Action = local.bucket_actions, Resource = local.bucket, Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-2" } } }
    ]
  }
}
# Input: reviewed ceiling. Output: boundary created before the role; destruction requires review.
resource "aws_iam_policy" "boundary" {
  count  = var.enable_observer_access ? 1 : 0
  name   = "dissertation-sandbox-observer-boundary"
  policy = jsonencode(local.boundary)
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.identity_guard]
}
# Input: unedited static-analysis policy. Output: baseline unusable without the boundary.
resource "aws_iam_policy" "generated" {
  count  = var.enable_observer_access ? 1 : 0
  name   = "dissertation-sandbox-observer-generated"
  policy = jsonencode(local.generated)
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.identity_guard]
}
# Input: exact human principal and mandatory boundary. Output: dedicated temporary observer role.
resource "aws_iam_role" "observer" {
  count                = var.enable_observer_access ? 1 : 0
  name                 = "dissertation-sandbox-observer"
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.boundary[0].arn
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = "arn:aws:iam::653464153304:user/martin-morales-personal" } }]
  })
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.identity_guard]
}
# Input: role, baseline and attached boundary. Output: effective intersection, never broad candidate alone.
resource "aws_iam_role_policy_attachment" "generated" {
  count      = var.enable_observer_access ? 1 : 0
  role       = aws_iam_role.observer[0].name
  policy_arn = aws_iam_policy.generated[0].arn
  lifecycle { prevent_destroy = true }
}
# Input: optional created role. Output: ARN or null; no local profile or credentials are written.
output "observer_role_arn" { value = try(aws_iam_role.observer[0].arn, null) }
