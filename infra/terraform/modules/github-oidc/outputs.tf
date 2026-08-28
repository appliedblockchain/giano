output "role_arn" {
  value       = aws_iam_role.deploy.arn
  description = "Pass to aws-actions/configure-aws-credentials as role-to-assume."
}

output "oidc_provider_arn" {
  value = local.provider_arn
}
