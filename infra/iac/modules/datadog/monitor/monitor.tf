<<<<<<< HEAD
# wraps datadog_monitor with thresholds and a notifier list — §17.3.5
#
# Child modules do not inherit a provider's SOURCE ADDRESS from the root, only its
# configuration — the datadog/datadog provider is outside the default hashicorp/ namespace,
# so this module must repeat the source here or Terraform assumes hashicorp/datadog and fails
# to resolve it.
terraform {
  required_providers {
    datadog = { source = "DataDog/datadog" }
  }
}

resource "datadog_monitor" "this" {
  name    = var.name
  type    = var.monitor_type
  query   = var.query
  message = local.full_message
  tags    = local.tags_list

  monitor_thresholds {
    critical = try(var.monitor_thresholds.critical, null)
    warning  = try(var.monitor_thresholds.warning, null)
    ok       = try(var.monitor_thresholds.ok, null)
  }

  notify_no_data    = var.notify_no_data
  no_data_timeframe = var.no_data_timeframe

  include_tags = true
=======
# One Datadog monitor, with thresholds and a notifier list. §17.3.5
#
# The provider source has to be declared here too: `datadog` is not a
# hashicorp/* provider, so a module that uses it without saying so resolves to
# hashicorp/datadog, which does not exist.

terraform {
  required_providers {
    datadog = { source = "DataDog/datadog", version = "~> 3.60" }
  }
}

resource "datadog_monitor" "monitor" {
  name    = var.name
  type    = var.type
  query   = var.query
  message = local.message

  monitor_thresholds {
    critical = var.monitor_thresholds.critical
    warning  = var.monitor_thresholds.warning
  }

  notify_no_data    = var.notify_no_data
  no_data_timeframe = var.notify_no_data ? var.no_data_timeframe : null

  evaluation_delay  = var.evaluation_delay
  renotify_interval = var.renotify_interval
  priority          = var.priority

  # An alert that recovers on its own should say so rather than waiting for
  # someone to close it.
  notify_audit        = false
  include_tags        = true
  require_full_window = false

  tags = local.tags
>>>>>>> main
}
