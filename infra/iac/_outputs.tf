# Giano — the aggregate outputs an operator consumes. specs/INFRASTRUCTURE.md §4.7.
# No output ever returns a secret value.

output "DEBUG" {
  description = "identity and naming, for confirming which account and environment is targeted"
  value = {
    aws_profile  = var.profile[terraform.workspace]
    account_id   = data.aws_caller_identity.current.account_id
    caller_arn   = data.aws_caller_identity.current.arn
    default_tags = local.default_tags
    name_prefix  = local.name_prefix
  }
}

output "ENDPOINTS" {
  description = "public hostnames and the ALB they resolve to"
  value = {
    alb_dns_name = aws_lb.alb.dns_name
    wallet       = local.hosts.wallet
    api          = local.hosts.api
    paymaster    = local.hosts.paymaster
    tenants      = local.tenant_hosts
  }
}

output "RUN_TASK_NETWORK" {
  description = "network configuration for `aws ecs run-task` (provision-sponsorship)"
  value = {
    subnets          = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
    security_groups  = [aws_security_group.tasks-sg.id]
    assign_public_ip = "DISABLED"
  }
}

# Flat string outputs, so a runbook command can read one inline with
# `terraform output -raw <name>` — see §18.
output "name_prefix" { value = local.name_prefix }
output "cluster_name" { value = aws_ecs_cluster.ecs.name }
output "aws_profile" { value = var.profile[terraform.workspace] }
output "aws_region" { value = var.aws_region[terraform.workspace] }
output "op_vault" { value = local.op_vault }
output "op_item" { value = local.op_item }

output "wallet_host" { value = local.hosts.wallet }
output "api_host" { value = local.hosts.api }
output "paymaster_host" { value = local.hosts.paymaster }

# { example = { dapp = "example.dev.giano…", wallet = "wallet.example.dev.giano…" }, byoui = {…} }
output "tenant_hosts" {
  description = "per-tenant dApp and wallet hostnames, keyed by tenant slug"
  value       = local.tenant_hosts
}
