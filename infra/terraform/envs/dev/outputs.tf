# ── runbook step 2 ─────────────────────────────────────────────────────────────────────────

output "name_servers" {
  value       = module.dns.name_servers
  description = "Add as an NS record for the child zone in the parent zone. ACM validation blocks until this resolves."
}

output "delegate_zone" {
  value       = local.domain
  description = "The child zone the name_servers above belong to."
}

# ── the environment ────────────────────────────────────────────────────────────────────────

output "urls" {
  value = {
    wallet    = "https://${local.hosts.wallet}"
    api       = "https://${local.hosts.api}"
    app       = "https://${local.hosts.app}"
    paymaster = "https://${local.hosts.paymaster}"
  }
}

output "rp_id" {
  value       = local.hosts.wallet
  description = "IRREVERSIBLE. Every passkey binds to this; renaming the host orphans them all."
}

output "alb_dns_name" {
  value = module.alb.dns_name
}

# ── CI ─────────────────────────────────────────────────────────────────────────────────────

output "github_deploy_role_arn" {
  value       = module.github_oidc.role_arn
  description = "role-to-assume for aws-actions/configure-aws-credentials."
}

output "ecr_repository_urls" {
  value = module.ecr.repository_urls
}

output "cluster_name" {
  value = module.cluster.cluster_name
}

output "service_names" {
  value = local.service_names
}

output "migrate_task_definition" {
  value = aws_ecs_task_definition.migrate.family
}

# `aws ecs run-task` needs this verbatim. awsvpc + public IP is the D8 consequence: a one-shot
# task has the same no-NAT problem as a service.
output "run_task_network_config" {
  value = "awsvpcConfiguration={subnets=[${join(",", module.network.public_subnet_ids)}],securityGroups=[${module.network.tasks_security_group_id}],assignPublicIp=ENABLED}"
}

# ── operations ─────────────────────────────────────────────────────────────────────────────

output "ssm_parameters" {
  value       = [for p in aws_ssm_parameter.placeholder : p.name]
  description = "Written by hand before the first apply that starts services. Runbook step 4."
}

output "tenant_admin_key" {
  value       = random_password.tenant_admin_key.result
  sensitive   = true
  description = "The dev tenant's admin key. `terraform output -raw tenant_admin_key` to read it."
}

output "metrics_bearer_token" {
  value     = random_password.metrics_token.result
  sensitive = true
}

output "database_endpoint" {
  value       = module.rds.address
  description = "Private. Reach it with `aws ecs execute-command` into a running task."
}

output "estimated_monthly_cost_usd" {
  value = var.enable_schedule ? "~77 (scheduled, weekdays 07:00-19:00 UTC)" : "~139 (always on)"
}
