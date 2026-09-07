<<<<<<< HEAD
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
=======
# Five monitors. §17.3.5
#
# Three of them close risks this deployment otherwise carries, and which
# column each draws from is the point:
#
#   the Agent covers what happens INSIDE a task;
#   the AWS integration covers whether the task EXISTS.
#
# So the task-count monitor is deliberately not Agent-derived — it compares
# two control-plane figures and still fires when the Agent in that task is
# dead. An Agent-sourced task count cannot tell "the service is down" from
# "the Agent is down", which is why the no-data check is a separate monitor
# rather than folded into the first. R17, §9.1
#
# THE DATADOG AWS INTEGRATION IS A PREREQUISITE FOR THREE OF THE FIVE. It is
# configured once per AWS account in the Datadog UI, not here, and until it
# exists aws.ecs.service.*, aws.applicationelb.* and aws.acm.* do not resolve
# — the monitors are created and silently never fire.

locals {
  datadog_monitors = {
    additional_notifiers = var.datadog_monitor_additional_notifiers
  }

  # Out of hours the scheduler takes every service to zero, so the first two
  # monitors need a Datadog-side downtime covering the same window in dev or
  # they page every evening at 19:00. That downtime is Datadog-side
  # configuration, not Terraform. §17.3.5
  datadog_monitored_services = var.datadog_monitors_enabled[terraform.workspace] ? local.enabled_ecs_services : {}
}

module "datadog_monitor_service_task_count" {
  for_each = local.datadog_monitored_services
>>>>>>> main
  source   = "./modules/datadog/monitor"

  name = "ECS: ${each.key} is running fewer tasks than desired on ${local.name_prefix}"
  query = join("", [
    "min(last_10m):",
    "avg:aws.ecs.service.running{clustername:${local.name_prefix}-ecs,servicename:${local.name_prefix}-${each.key}} - ",
    "avg:aws.ecs.service.desired{clustername:${local.name_prefix}-ecs,servicename:${local.name_prefix}-${each.key}} < 0",
  ])

<<<<<<< HEAD
  monitor_thresholds   = { critical = 0 }
  additional_tags      = local.default_tags
  additional_notifiers = var.datadog_monitor_additional_notifiers
}

# ── Service reporting no metrics — R17 ──────────────────────────────────────────────────────
# The point is the ABSENCE of data, not the value — the threshold is unreachable on purpose,
# so it only ever alerts by going silent.
module "datadog_monitor_service_no_metrics" {
  for_each = var.datadog_monitors_enabled[terraform.workspace] ? local.ecs_services : toset([])
=======
  message = "Fewer tasks running than desired for ${each.key} on ${local.name_prefix}. Control-plane figures from the AWS integration, so this fires whether or not the Agent in the task is alive."

  monitor_thresholds = { critical = 0 }

  # CloudWatch-sourced metrics arrive late; evaluating immediately produces
  # false alerts on every scrape gap.
  evaluation_delay = 600

  additional_tags      = local.default_tags
  additional_notifiers = local.datadog_monitors["additional_notifiers"]
}

module "datadog_monitor_service_no_metrics" {
  for_each = local.datadog_monitored_services
>>>>>>> main
  source   = "./modules/datadog/monitor"

  name  = "Datadog: no metrics from ${each.key} on ${local.name_prefix} — Agent may be down"
  query = "avg(last_15m):avg:ecs.fargate.cpu.user{env:${terraform.workspace},service:${each.key}} < 0"

<<<<<<< HEAD
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
=======
  message = "No Agent metrics from ${each.key} on ${local.name_prefix} for 15 minutes. The Agent is essential = false, so the task may be serving traffic and reporting nothing."

  # The point of this monitor is the ABSENCE of data, not the value: the
  # threshold is unreachable on purpose, so it only ever alerts by going
  # silent.
  notify_no_data     = true
  no_data_timeframe  = 15
  monitor_thresholds = { critical = 0 }

  additional_tags      = local.default_tags
  additional_notifiers = local.datadog_monitors["additional_notifiers"]
}

module "datadog_monitor_wallet_api_healthy_hosts" {
  count  = var.datadog_monitors_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/datadog/monitor"

  name = "ALB: wallet-api has no healthy targets on ${local.name_prefix}"
  query = join("", [
    "min(last_5m):",
    "min:aws.applicationelb.healthy_host_count{",
    "loadbalancer:${aws_lb.alb.arn_suffix},targetgroup:${module.svc-wallet-api.target_group_arn_suffix}",
    "} < 1",
  ])

  message = "wallet-api has no healthy targets behind ${local.name_prefix}-alb. If this coincides with a deploy, suspect the migrate init container first (R21)."

  monitor_thresholds = { critical = 1 }
  evaluation_delay   = 600

  additional_tags      = local.default_tags
  additional_notifiers = local.datadog_monitors["additional_notifiers"]
}

# R2 — the failure most likely to make this environment look broken for a
# non-obvious reason. HALF-CLOSED: the monitor is declared here, but nothing
# emits giano.chain.balance yet. §16.6 is the repository change that does —
# the paymaster watcher already holds a viem client and runs on a timer, so it
# is a DogStatsD call to 127.0.0.1:8125 and nothing more. Until it lands this
# monitor is created and never fires.
module "datadog_monitor_chain_balance" {
  for_each = var.datadog_monitors_enabled[terraform.workspace] ? var.chain_balance_floors : {}
  source   = "./modules/datadog/monitor"

  name = "Chain: ${each.key} balance below floor on ${local.name_prefix}"
  query = join("", [
    "min(last_15m):",
    "min:giano.chain.balance{env:${terraform.workspace},account:${each.key},chain_id:${local.chain_id}}",
    " < ${each.value}",
  ])

  message = "The ${each.key} account is below its floor on ${local.name_prefix}. An empty executor or paymaster deposit presents as 'transactions stopped working' with no other symptom. Top it up from a faucet (§13.2)."

  monitor_thresholds = { critical = each.value }

  notify_no_data    = true
  no_data_timeframe = 60

  additional_tags      = local.default_tags
  additional_notifiers = local.datadog_monitors["additional_notifiers"]
}

# R10 — closed for a tenant hosting its wallet origin in its own DNS: ACM
# renews only while the validation CNAME still resolves there, and this
# catches it 30 days out.
module "datadog_monitor_certificate_expiry" {
  count  = var.datadog_monitors_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/datadog/monitor"

  name  = "ACM: a certificate on ${local.name_prefix} expires within 30 days"
  query = "min(last_1d):min:aws.acm.days_to_expiry{region:${var.aws_region[terraform.workspace]}} by {certificatearn} < 30"

  message = "A certificate is within 30 days of expiry. For a tenant wallet host in the tenant's own DNS, this means their validation CNAME has been removed — ACM stops renewing without it (§6.6 step 2)."

  monitor_thresholds = { critical = 30, warning = 45 }
  evaluation_delay   = 3600

  additional_tags      = local.default_tags
  additional_notifiers = local.datadog_monitors["additional_notifiers"]
>>>>>>> main
}
