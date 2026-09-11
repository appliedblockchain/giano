output "gha_deploy_role_arn" {
  value = module.iam-role-gha-deploy.role_arn
}

output "github_oidc_provider_arn" {
  value = data.aws_iam_openid_connect_provider.github.arn
}
