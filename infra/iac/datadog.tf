# §17.3.5 — five monitors. Three close risks this document carries as open items: R5 (task
# count), R17 (silent Agent death — deliberately NOT Agent-derived, see below), R2 (funded
# account balance) and R10 (certificate expiry).

locals {
  # every service name that actually exists in this workspace — drives the two per-service
  # monitors below.
  ecs_services = toset(concat(
    ["wallet-api", "wallet-web", "custom-example", "paymaster-admin", "bundler"],
    var.byo_wallet_enabled[terraform.workspace] ? ["custom-example-byoui", "wallet-byo"] : [],
  ))
}

# ── Service task count below desired — R5 ───────────────────────────────────────────────────
# Deliberately NOT Agent-derived: both metrics come from the AWS/ECS control-plane namespace
# via the Datadog AWS integration, so this still fires even when the Agent in that task is
# dead (§9.1).
module "datadog_monitor_service_task_count" {
  for_each = var.datadog_monitors_enabled[terraform.workspace] ? local.ecs_services : toset([])
  source   = "./modules/datadog/monitor"

  name = "ECS: ${each.key} is running fewer tasks than desired on ${local.name_prefix}"
  query = join("", [
    "min(last_10m):",
    "avg:aws.ecs.service.running{clustername:${local.name_prefix}-ecs,servicename:${local.name_prefix}-${each.key}} - ",
    "avg:aws.ecs.service.desired{clustername:${local.name_prefix}-ecs,servicename:${local.name_prefix}-${each.key}} < 0",
  ])

  monitor_thresholds   = { critical = 0 }
  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}

# ── Service reporting no metrics — R17 ──────────────────────────────────────────────────────
# The point is the ABSENCE of data, not the value — the threshold is unreachable on purpose,
# so it only ever alerts by going silent.
module "datadog_monitor_service_no_metrics" {
  for_each = var.datadog_monitors_enabled[terraform.workspace] ? local.ecs_services : toset([])
  source   = "./modules/datadog/monitor"

  name  = "Datadog: no metrics from ${each.key} on ${local.name_prefix} — Agent may be down"
  query = "avg(last_15m):avg:ecs.fargate.cpu.user{env:${terraform.workspace},service:${each.key}} < 0"

  notify_no_data    = true
  no_data_timeframe = 15

  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}

# ── wallet-api health check failing ─────────────────────────────────────────────────────────
module "datadog_monitor_wallet_api_health" {
  count  = var.datadog_monitors_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/datadog/monitor"

  name  = "ALB: wallet-api target group has no healthy hosts on ${local.name_prefix}"
  query = "avg(last_5m):avg:aws.applicationelb.healthy_host_count{targetgroup:${module.svc-wallet-api.target_group_arn}} < 1"

  monitor_thresholds   = { critical = 1 }
  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}

# ── Funded-account balance floor — R2 ───────────────────────────────────────────────────────
# Half-closed until §16.6 lands: nothing emits giano.chain.balance yet, so this is declared and
# does not fire until the repository change ships.
module "datadog_monitor_chain_balance_executor" {
  count  = var.datadog_monitors_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/datadog/monitor"

  name  = "Chain: the Alto executor balance is running low on ${local.name_prefix} — R2"
  query = "avg(last_1h):avg:giano.chain.balance{env:${terraform.workspace},account:executor,chain_id:${var.chain_id}} < 0.05"

  monitor_thresholds   = { critical = 0.05 }
  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}

module "datadog_monitor_chain_balance_paymaster" {
  count  = var.datadog_monitors_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/datadog/monitor"

  name  = "Chain: the paymaster deposit balance is running low on ${local.name_prefix} — R2"
  query = "avg(last_1h):avg:giano.chain.balance{env:${terraform.workspace},account:paymaster,chain_id:${var.chain_id}} < 0.05"

  monitor_thresholds   = { critical = 0.05 }
  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}

# ── Certificate expiry — R10 ────────────────────────────────────────────────────────────────
# Needs the Datadog AWS integration enabled on the account for aws.acm.days_to_expiry to
# resolve. Closes R10 for every certificate this account owns (the wildcard and both tenant
# wallet-host certs) — does not apply to a foreign tenant's own certificate (e.g. Acme's).
module "datadog_monitor_cert_expiry" {
  count  = var.datadog_monitors_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/datadog/monitor"

  name  = "ACM: a certificate on ${local.name_prefix} is within ${var.datadog_cert_expiry_threshold_days} days of expiry — R10"
  query = "min(last_1h):min:aws.acm.days_to_expiry{env:${terraform.workspace}} < ${var.datadog_cert_expiry_threshold_days}"

  monitor_thresholds   = { critical = var.datadog_cert_expiry_threshold_days }
  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}
