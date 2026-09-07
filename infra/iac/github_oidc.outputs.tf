output "GHA_DEPLOY" {
  description = "what the two workflows need: the role each assumes, the cluster to roll, and the repositories to push to"
  value = {
    role_arn           = module.gha-deploy-role.arn
    terraform_role_arn = module.gha-terraform-role.arn
    aws_region         = var.aws_region[terraform.workspace]
    cluster            = aws_ecs_cluster.ecs.name
    repository_urls    = { for k, m in module.ecr : k => m.repository_url }
    allowed_refs       = var.gha_allowed_refs[terraform.workspace]
  }
}
